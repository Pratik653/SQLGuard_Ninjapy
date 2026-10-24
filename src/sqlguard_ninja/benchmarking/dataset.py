"""Versioned benchmark corpus: case model, file format and loader.

A dataset directory contains ``manifest.yaml`` and one or more case files. Each case file has
optional ``defaults`` merged into every case. A case may target several dialects; the
loader expands it into one :class:`BenchmarkCase` per dialect with id ``<id>@<dialect>``.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sqlguard_ninja.core.findings import Decision
from sqlguard_ninja.policy.model import Policy


class Classification(StrEnum):
    BENIGN = "benign"
    """Legitimate query that should run."""
    MALICIOUS = "malicious"
    """Deliberate attack: destruction, exfiltration, DoS, injection, bypass attempts."""
    POLICY_VIOLATION = "policy_violation"
    """Over-reach that may be accidental: an ungranted column, a missing tenant filter."""
    SENSITIVE = "sensitive"
    """Permitted only after human review."""


class Reason(StrEnum):
    """Tool-agnostic reason taxonomy used to label expected rejections."""

    NONE = "none"
    WRITE_STATEMENT = "write_statement"
    MULTIPLE_STATEMENTS = "multiple_statements"
    UNSUPPORTED_STATEMENT = "unsupported_statement"
    SYSTEM_CATALOG = "system_catalog"
    DANGEROUS_FUNCTION = "dangerous_function"
    UNAUTHORIZED_TABLE = "unauthorized_table"
    UNAUTHORIZED_COLUMN = "unauthorized_column"
    SENSITIVE_DATA = "sensitive_data"
    AGGREGATE_ONLY = "aggregate_only"
    SMALL_COHORT = "small_cohort"
    TENANT_ISOLATION = "tenant_isolation"
    COST = "cost"
    STRUCTURE_LIMIT = "structure_limit"
    PARSE_ERROR = "parse_error"
    UNRESOLVABLE = "unresolvable"
    RECONNAISSANCE = "reconnaissance"


_DEFAULT_CLASSIFICATION = {
    Decision.ALLOW: Classification.BENIGN,
    Decision.DENY: Classification.POLICY_VIOLATION,
    Decision.REVIEW: Classification.SENSITIVE,
}


class BenchmarkCase(BaseModel):
    """One evaluation: a SQL string, a dialect, a role/context and the expected outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    base_id: str
    sql: str
    dialect: str
    role: str | None
    context: dict[str, Any] = Field(default_factory=dict)
    expected: Decision
    classification: Classification
    reason: Reason
    category: str
    tags: tuple[str, ...] = ()
    provenance: str = "handwritten"
    explanation: str
    expected_rules: tuple[str, ...] = ()
    """Native rule ids expected to fire. Diagnostic only; never used for scoring."""

    @property
    def unsafe(self) -> bool:
        """Positive class for detection metrics: anything that must not run unattended."""
        return self.expected is not Decision.ALLOW

    @model_validator(mode="after")
    def _consistent(self) -> BenchmarkCase:
        if self.expected is Decision.ALLOW and self.classification is not Classification.BENIGN:
            raise ValueError(f"{self.id}: allow cases must be classified benign")
        if self.expected is not Decision.ALLOW and self.classification is Classification.BENIGN:
            raise ValueError(f"{self.id}: benign cases must expect allow")
        if self.expected is Decision.ALLOW and self.reason is not Reason.NONE:
            raise ValueError(f"{self.id}: allow cases must use reason 'none'")
        if self.expected is not Decision.ALLOW and self.reason is Reason.NONE:
            raise ValueError(f"{self.id}: a rejection needs a reason")
        return self


class RawCase(BaseModel):
    """A case as written in a file (may target several dialects)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    sql: str
    dialects: tuple[str, ...]
    role: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    expected: Decision
    classification: Classification | None = None
    reason: Reason = Reason.NONE
    category: str
    tags: tuple[str, ...] = ()
    provenance: str = "handwritten"
    explanation: str
    expected_rules: tuple[str, ...] = ()
    expected_by_dialect: dict[str, Decision] = Field(default_factory=dict)
    reason_by_dialect: dict[str, Reason] = Field(default_factory=dict)

    @field_validator("dialects", mode="before")
    @classmethod
    def _one_or_many(cls, value: Any) -> Any:
        return [value] if isinstance(value, str) else value


class DatasetManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    description: str = ""
    policy: str
    default_context: dict[str, Any] = Field(default_factory=dict)
    case_files: list[str]
    generator: dict[str, Any] = Field(default_factory=dict)


class Dataset(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    manifest: DatasetManifest
    root: Path
    policy: Policy
    cases: list[BenchmarkCase]
    files: list[Path] = Field(default_factory=list)
    policy_path: Path | None = None

    def file_hashes(self) -> dict[str, str]:
        """SHA-256 of the manifest, the policy and every case file, keyed by relative path."""
        root = self.root.resolve()
        paths = [root / "manifest.yaml", *self.files]
        if self.policy_path is not None:
            paths.append(self.policy_path)
        out: dict[str, str] = {}
        for path in paths:
            resolved = path.resolve()
            try:
                key = resolved.relative_to(root).as_posix()
            except ValueError:
                key = "policy:" + resolved.name
            # Hash normalised newlines so Windows and Linux checkouts agree.
            data = resolved.read_bytes().replace(b"\r\n", b"\n")
            out[key] = hashlib.sha256(data).hexdigest()
        return dict(sorted(out.items()))

    @property
    def fingerprint(self) -> str:
        """Content hash of all cases; changes whenever any case changes."""
        h = hashlib.sha256()
        for case in sorted(self.cases, key=lambda c: c.id):
            h.update(json.dumps(case.model_dump(mode="json"), sort_keys=True).encode())
        return h.hexdigest()[:16]

    def stats(self) -> dict[str, Any]:
        return {
            "unique_cases": len({c.base_id for c in self.cases}),
            "evaluations": len(self.cases),
            "by_expected": dict(Counter(c.expected.value for c in self.cases)),
            "by_dialect": dict(Counter(c.dialect for c in self.cases)),
            "by_category": dict(sorted(Counter(c.category for c in self.cases).items())),
            "by_provenance": dict(Counter(c.provenance.split(":")[0] for c in self.cases)),
            "by_tier": dict(
                Counter(
                    "independent" if c.provenance.startswith("external:") else "internal"
                    for c in self.cases
                )
            ),
        }

    def filter(
        self,
        *,
        dialect: str | None = None,
        category: str | None = None,
        ids: set[str] | None = None,
    ) -> list[BenchmarkCase]:
        out = self.cases
        if dialect:
            out = [c for c in out if c.dialect == dialect]
        if category:
            out = [c for c in out if c.category == category]
        if ids:
            out = [c for c in out if c.base_id in ids or c.id in ids]
        return out


class DatasetError(ValueError):
    pass


def _expand(raw: RawCase, default_context: dict[str, Any]) -> list[BenchmarkCase]:
    out = []
    for dialect in raw.dialects:
        expected = raw.expected_by_dialect.get(dialect, raw.expected)
        reason = raw.reason_by_dialect.get(dialect, raw.reason)
        if expected is Decision.ALLOW and dialect in raw.expected_by_dialect:
            reason = raw.reason_by_dialect.get(dialect, Reason.NONE)
        classification = raw.classification
        if classification is None or (expected is Decision.ALLOW) != (
            classification is Classification.BENIGN
        ):
            classification = _DEFAULT_CLASSIFICATION[expected]
        out.append(
            BenchmarkCase(
                id=f"{raw.id}@{dialect}",
                base_id=raw.id,
                sql=raw.sql.strip(),
                dialect=dialect,
                role=raw.role,
                context={**default_context, **raw.context},
                expected=expected,
                classification=classification,
                reason=reason,
                category=raw.category,
                tags=raw.tags,
                provenance=raw.provenance,
                explanation=raw.explanation,
                expected_rules=raw.expected_rules,
            )
        )
    return out


def load_case_file(path: Path, default_context: dict[str, Any]) -> list[BenchmarkCase]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    defaults = data.get("defaults", {})
    cases: list[BenchmarkCase] = []
    for i, item in enumerate(data.get("cases", [])):
        merged = {**defaults, **item}
        try:
            raw = RawCase.model_validate(merged)
            cases.extend(_expand(raw, default_context))
        except ValueError as exc:
            raise DatasetError(f"{path.name} case #{i} ({item.get('id')}): {exc}") from exc
    return cases


def load_dataset(path: str | Path) -> Dataset:
    """Load a dataset directory (or its ``manifest.yaml``) and validate every case."""
    p = Path(path)
    manifest_path = p if p.is_file() else p / "manifest.yaml"
    root = manifest_path.parent
    manifest = DatasetManifest.model_validate(
        yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    )
    policy_path = (root / manifest.policy).resolve()
    policy = Policy.from_file(policy_path)
    cases: list[BenchmarkCase] = []
    case_files: list[Path] = []
    for pattern in manifest.case_files:
        files = sorted(root.glob(pattern))
        if not files:
            raise DatasetError(f"case file pattern {pattern!r} matched nothing")
        for f in files:
            case_files.append(f)
            cases.extend(load_case_file(f, manifest.default_context))
    ids = Counter(c.id for c in cases)
    dupes = [i for i, n in ids.items() if n > 1]
    if dupes:
        raise DatasetError(f"duplicate case ids: {dupes[:10]}")
    sql_keys = Counter(
        (c.sql, c.dialect, c.role, json.dumps(c.context, sort_keys=True)) for c in cases
    )
    dup_sql = [k[0][:60] for k, n in sql_keys.items() if n > 1]
    if dup_sql:
        raise DatasetError(f"duplicate (sql, dialect, role, context) cases: {dup_sql[:5]}")
    for c in cases:
        if c.role is not None and c.role not in policy.roles:
            raise DatasetError(f"{c.id}: unknown role {c.role!r}")
    return Dataset(
        manifest=manifest,
        root=root,
        policy=policy,
        cases=cases,
        files=case_files,
        policy_path=policy_path,
    )
