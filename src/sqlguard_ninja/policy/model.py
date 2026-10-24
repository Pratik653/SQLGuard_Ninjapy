"""Versioned, validated policy schema.

A policy describes *what exists* (the catalog and its classification labels) and *who may
see what* (roles). It is loaded from YAML or JSON and validated eagerly so that a typo in a
role grant fails at start-up instead of silently allowing or denying queries.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from sqlguard_ninja.core.findings import Action


class PolicyError(ValueError):
    """Raised when a policy file is malformed or internally inconsistent."""


class Access(StrEnum):
    """How a role may use a column or a label."""

    ALLOW = "allow"
    AGGREGATE_ONLY = "aggregate_only"
    REVIEW = "review"
    DENY = "deny"


class Sensitivity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _lower_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k).lower(): v for k, v in value.items()}
    return value


def _lower_list(value: Any) -> Any:
    if isinstance(value, list):
        return [str(v).lower() for v in value]
    return value


class LabelDef(_Model):
    """A classification label such as ``contact`` or ``financial``."""

    description: str = ""
    sensitivity: Sensitivity = Sensitivity.MEDIUM
    masking: str | None = Field(
        default=None, description="Recommended masking or minimisation technique."
    )
    special_category: bool = Field(
        default=False, description="GDPR Art. 9 special-category data, when so configured."
    )


class ColumnDef(_Model):
    """Metadata for one column. Labels are configuration, never inferred from the name."""

    type: str = "text"
    labels: tuple[str, ...] = ()
    identifying: bool = Field(
        default=False,
        description="Uniquely identifies a person/entity. Used for small-cohort checks.",
    )
    alternatives: tuple[str, ...] = Field(
        default=(), description="Less sensitive columns of the same table that may suffice."
    )
    json_fields: dict[str, tuple[str, ...]] = Field(
        default_factory=dict,
        description="Labels for paths inside a JSON column, keyed by dotted path.",
    )

    _norm_labels = field_validator("labels", "alternatives", mode="before")(_lower_list)

    @field_validator("json_fields", mode="before")
    @classmethod
    def _norm_json(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k).lower(): _lower_list(list(v)) for k, v in value.items()}
        return value

    def effective_labels(self, json_path: tuple[str, ...] | None = None) -> set[str]:
        """Labels revealed by reading this column, or one JSON path inside it.

        Reading the whole column reveals every nested field, so its labels are the union of
        the column's own labels and all JSON field labels. Reading a path reveals the
        column's labels plus labels of that path, its ancestors and its descendants.
        """
        labels = set(self.labels)
        if json_path is None:
            for field_labels in self.json_fields.values():
                labels.update(field_labels)
            return labels
        requested = ".".join(p.lower() for p in json_path)
        for path, field_labels in self.json_fields.items():
            if (
                path == requested
                or path.startswith(requested + ".")
                or requested.startswith(path + ".")
            ):
                labels.update(field_labels)
        return labels


class TableDef(_Model):
    description: str = ""
    columns: dict[str, ColumnDef]
    tenant_column: str | None = None
    estimated_rows: int | None = Field(default=None, ge=0)

    @field_validator("columns", mode="before")
    @classmethod
    def _norm_columns(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        out: dict[str, Any] = {}
        for name, spec in value.items():
            if spec is None:
                spec = {}
            elif isinstance(spec, str):
                spec = {"type": spec}
            elif isinstance(spec, list):
                spec = {"labels": spec}
            out[str(name).lower()] = spec
        return out

    @field_validator("tenant_column", mode="before")
    @classmethod
    def _norm_tenant(cls, value: Any) -> Any:
        return value.lower() if isinstance(value, str) else value

    @model_validator(mode="after")
    def _check(self) -> TableDef:
        if self.tenant_column and self.tenant_column not in self.columns:
            raise ValueError(f"tenant_column '{self.tenant_column}' is not a declared column")
        for name, col in self.columns.items():
            for alt in col.alternatives:
                if alt not in self.columns:
                    raise ValueError(f"column '{name}' lists unknown alternative '{alt}'")
        return self


class Catalog(_Model):
    default_schema: str | None = Field(
        default=None,
        description="Schema that unqualified names resolve to (e.g. 'public' or 'main').",
    )
    tables: dict[str, TableDef]

    _norm = field_validator("tables", mode="before")(_lower_keys)

    @field_validator("default_schema", mode="before")
    @classmethod
    def _norm_schema(cls, value: Any) -> Any:
        return value.lower() if isinstance(value, str) else value

    def sqlglot_schema(self) -> dict[str, dict[str, str]]:
        return {
            name: {col: spec.type for col, spec in table.columns.items()}
            for name, table in self.tables.items()
        }


class TableGrant(_Model):
    """Which columns of a table a role may reference."""

    columns: Literal["*"] | tuple[str, ...] = "*"
    deny_columns: tuple[str, ...] = ()
    column_access: dict[str, Access] = Field(
        default_factory=dict, description="Per-column overrides; most specific rule wins."
    )

    @field_validator("columns", mode="before")
    @classmethod
    def _norm_cols(cls, value: Any) -> Any:
        return _lower_list(value) if isinstance(value, list) else value

    _norm_deny = field_validator("deny_columns", mode="before")(_lower_list)
    _norm_access = field_validator("column_access", mode="before")(_lower_keys)


class Limits(_Model):
    max_sql_length: int = Field(default=20_000, gt=0)
    max_ast_nodes: int = Field(default=5_000, gt=0)
    max_joins: int | None = Field(default=8, ge=0)
    max_subquery_depth: int | None = Field(default=5, ge=0)
    max_limit: int | None = Field(default=None, gt=0)
    require_limit: bool = False


class Role(_Model):
    description: str = ""
    extends: tuple[str, ...] = Field(
        default=(),
        description="Parent roles. Permissions are inherited; explicit denies cannot be relaxed.",
    )
    tables: dict[str, TableGrant] = Field(default_factory=dict)
    labels: dict[str, Access] = Field(
        default_factory=dict, description="Access per classification label."
    )
    unlisted_label_access: Access = Field(
        default=Access.DENY,
        description="Access for labelled columns whose label the role does not mention.",
    )
    tenant_scoped: bool = True
    limits: Limits | None = None

    _norm_labels = field_validator("labels", mode="before")(_lower_keys)

    @field_validator("tables", mode="before")
    @classmethod
    def _grant_shorthand(cls, value: Any) -> Any:
        # Allow `tables: {orders: "*"}` and `tables: {orders: [id, status]}`.
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for name, grant in value.items():
                if grant is None or grant == "*":
                    grant = {"columns": "*"}
                elif isinstance(grant, list):
                    grant = {"columns": grant}
                out[str(name).lower()] = grant
            return out
        return value


class FunctionPolicy(_Model):
    mode: Literal["denylist", "allowlist"] = "denylist"
    deny: tuple[str, ...] = ()
    allow: tuple[str, ...] = Field(
        default=(),
        description="In allowlist mode: the permitted functions. In denylist mode: "
        "exceptions removed from the built-in deny list.",
    )
    review: tuple[str, ...] = ()
    unknown_function_action: Action = Field(
        default=Action.WARN,
        description="Action for functions sqlglot does not recognise (possible UDFs).",
    )

    _norm = field_validator("deny", "allow", "review", mode="before")(_lower_list)


class TenantConfig(_Model):
    context_key: str = "tenant_id"
    parameter_names: tuple[str, ...] = Field(
        default=("tenant_id",),
        description="Bind-parameter names that the application fills with the trusted tenant.",
    )


class Defaults(_Model):
    unknown_table_action: Action = Action.DENY
    unresolved_column_action: Action = Action.DENY
    unexpandable_star_action: Action = Action.DENY
    catalog_access_action: Action = Action.DENY
    minimization_action: Action = Action.WARN
    small_cohort_action: Action = Action.REVIEW


class CostThresholds(_Model):
    """Static and planner thresholds; see :mod:`sqlguard_ninja.query_cost`."""

    enabled: bool = True
    review_score: int = Field(default=50, ge=0, le=100)
    deny_score: int = Field(default=80, ge=0, le=100)
    large_table_rows: int = Field(default=1_000_000, ge=0)
    max_plan_total_cost: float | None = None
    max_plan_rows: float | None = None


class Disclosure(StrEnum):
    """How much schema detail agent-facing messages may contain."""

    NAMES = "names"
    GENERIC = "generic"


class PolicyMetadata(_Model):
    """Audit metadata for a policy document (policy-as-code)."""

    revision: str = Field(
        default="unversioned",
        description="Human-assigned revision, e.g. '2026.10.1'. Recorded in every decision.",
    )
    owner: str | None = None
    change_ticket: str | None = None
    description: str = ""


class Policy(_Model):
    """Top-level policy document (``version: 1``)."""

    version: Literal[1] = 1
    name: str
    description: str = ""
    metadata: PolicyMetadata = Field(default_factory=PolicyMetadata)
    dialect: str = "postgres"
    catalog: Catalog
    labels: dict[str, LabelDef] = Field(default_factory=dict)
    roles: dict[str, Role] = Field(default_factory=dict)
    default_role: str | None = None
    tenant: TenantConfig = Field(default_factory=TenantConfig)
    functions: FunctionPolicy = Field(default_factory=FunctionPolicy)
    limits: Limits = Field(default_factory=Limits)
    defaults: Defaults = Field(default_factory=Defaults)
    cost: CostThresholds = Field(default_factory=CostThresholds)
    disclosure: Disclosure = Disclosure.NAMES

    _norm_labels = field_validator("labels", mode="before")(_lower_keys)
    _resolved: dict[str, Role] = PrivateAttr(default_factory=dict)
    _fingerprint: str = PrivateAttr(default="")

    @model_validator(mode="after")
    def _check_references(self) -> Policy:
        from sqlguard_ninja.policy.inheritance import (  # noqa: PLC0415 - avoids an import cycle
            InheritanceError,
            resolve_roles,
        )

        errors: list[str] = []
        try:
            self._resolved = resolve_roles(self.roles)
        except InheritanceError as exc:
            raise ValueError(str(exc)) from exc
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        self._fingerprint = hashlib.sha256(canonical.encode()).hexdigest()[:16]
        for tname, table in self.catalog.tables.items():
            for cname, col in table.columns.items():
                for label in col.effective_labels():
                    if label not in self.labels:
                        errors.append(f"{tname}.{cname}: unknown label '{label}'")
        for rname, role in self._resolved.items():
            for label in role.labels:
                if label not in self.labels:
                    errors.append(f"role '{rname}': unknown label '{label}'")
            for tname, grant in role.tables.items():
                tdef = self.catalog.tables.get(tname)
                if tdef is None:
                    errors.append(f"role '{rname}': grant on unknown table '{tname}'")
                    continue
                named = [
                    *(grant.columns if grant.columns != "*" else ()),
                    *grant.deny_columns,
                    *grant.column_access,
                ]
                for cname in named:
                    if cname not in tdef.columns:
                        errors.append(f"role '{rname}': unknown column '{tname}.{cname}'")
        if self.default_role and self.default_role not in self.roles:
            errors.append(f"default_role '{self.default_role}' is not defined")
        if self.cost.review_score > self.cost.deny_score:
            errors.append("cost.review_score must not exceed cost.deny_score")
        if errors:
            raise ValueError("; ".join(errors))
        return self

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        try:
            return cls.model_validate(data)
        except ValueError as exc:  # pydantic.ValidationError subclasses ValueError
            raise PolicyError(f"invalid policy: {exc}") from exc

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        """Load a policy from ``.yaml``/``.yml`` or ``.json``."""
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {p}: {exc}") from exc
        data = json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text)
        if not isinstance(data, dict):
            raise PolicyError(f"policy file {p} must contain a mapping at the top level")
        return cls.from_dict(data)

    def role(self, name: str | None) -> tuple[str | None, Role | None]:
        """Resolve a role name (falling back to ``default_role``)."""
        key = name or self.default_role
        if key is None:
            return None, None
        return key, self._resolved.get(key)

    @property
    def fingerprint(self) -> str:
        """Content hash of the policy (16 hex chars); changes with any semantic change."""
        return self._fingerprint

    @property
    def revision(self) -> str:
        return self.metadata.revision

    def effective_role(self, name: str) -> Role | None:
        """The role after inheritance (as enforced)."""
        return self._resolved.get(name)

    def effective_limits(self, role: Role | None) -> Limits:
        return role.limits if role is not None and role.limits is not None else self.limits
