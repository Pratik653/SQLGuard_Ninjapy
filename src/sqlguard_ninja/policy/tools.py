"""Policy-as-code tooling: diff, simulate, explain and templates.

These help a reviewer answer "what does this policy change actually do?" before it is
activated. A *relaxation* is any change that can only make more queries allowed. A diff with
relaxations deserves security review; ``sqlninja policy diff --fail-on-relaxation`` makes CI
enforce that review.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from sqlguard_ninja.core.findings import Action, ValidationResult
from sqlguard_ninja.core.guard import Guard
from sqlguard_ninja.policy.model import Access, Policy, Role, TableGrant

_ACCESS_RANK = {Access.ALLOW: 0, Access.REVIEW: 1, Access.AGGREGATE_ONLY: 2, Access.DENY: 3}
_ACTION_RANK = {Action.WARN: 0, Action.REVIEW: 1, Action.DENY: 2}


class Effect(StrEnum):
    RELAXES = "relaxes"
    RESTRICTS = "restricts"
    NEUTRAL = "neutral"


@dataclass(frozen=True)
class Change:
    path: str
    before: Any
    after: Any
    effect: Effect


@dataclass
class PolicyDiff:
    old_fingerprint: str
    new_fingerprint: str
    old_revision: str
    new_revision: str
    changes: list[Change] = field(default_factory=list)

    @property
    def relaxations(self) -> list[Change]:
        return [c for c in self.changes if c.effect is Effect.RELAXES]

    def as_dict(self) -> dict[str, Any]:
        return {
            "old": {"revision": self.old_revision, "fingerprint": self.old_fingerprint},
            "new": {"revision": self.new_revision, "fingerprint": self.new_fingerprint},
            "relaxations": len(self.relaxations),
            "changes": [{**asdict(c), "effect": c.effect.value} for c in self.changes],
        }


def _rank_effect(before: int, after: int) -> Effect:
    if after < before:
        return Effect.RELAXES
    if after > before:
        return Effect.RESTRICTS
    return Effect.NEUTRAL


def _limit_effect(before: int | None, after: int | None) -> Effect:
    """For caps where None means 'no cap'."""
    if before == after:
        return Effect.NEUTRAL
    if after is None or (before is not None and after > before):
        return Effect.RELAXES
    return Effect.RESTRICTS


def _cols(grant: TableGrant) -> set[str] | None:
    return None if grant.columns == "*" else set(grant.columns)


def _diff_grant(path: str, a: TableGrant, b: TableGrant, out: list[Change]) -> None:
    ca, cb = _cols(a), _cols(b)
    if ca != cb:
        if ca is None or cb is None:
            effect = Effect.RELAXES if cb is None else Effect.RESTRICTS
            out.append(Change(f"{path}.columns", a.columns, b.columns, effect))
        else:
            if cb - ca:
                out.append(Change(f"{path}.columns", None, sorted(cb - ca), Effect.RELAXES))
            if ca - cb:
                out.append(Change(f"{path}.columns", sorted(ca - cb), None, Effect.RESTRICTS))
    removed, added = (
        set(a.deny_columns) - set(b.deny_columns),
        set(b.deny_columns) - set(a.deny_columns),
    )
    if removed:
        out.append(Change(f"{path}.deny_columns", sorted(removed), None, Effect.RELAXES))
    if added:
        out.append(Change(f"{path}.deny_columns", None, sorted(added), Effect.RESTRICTS))
    for col in sorted(set(a.column_access) | set(b.column_access)):
        va, vb = a.column_access.get(col), b.column_access.get(col)
        if va != vb:
            ra = _ACCESS_RANK[va] if va else -1
            rb = _ACCESS_RANK[vb] if vb else -1
            out.append(Change(f"{path}.column_access.{col}", va, vb, _rank_effect(ra, rb)))


def _diff_role(name: str, a: Role, b: Role, out: list[Change]) -> None:
    base = f"roles.{name}"
    for t in sorted(set(a.tables) - set(b.tables)):
        out.append(Change(f"{base}.tables.{t}", "granted", None, Effect.RESTRICTS))
    for t in sorted(set(b.tables) - set(a.tables)):
        out.append(Change(f"{base}.tables.{t}", None, "granted", Effect.RELAXES))
    for t in sorted(set(a.tables) & set(b.tables)):
        _diff_grant(f"{base}.tables.{t}", a.tables[t], b.tables[t], out)
    for label in sorted(set(a.labels) | set(b.labels)):
        va = a.labels.get(label, a.unlisted_label_access)
        vb = b.labels.get(label, b.unlisted_label_access)
        if va != vb:
            out.append(
                Change(
                    f"{base}.labels.{label}",
                    va,
                    vb,
                    _rank_effect(_ACCESS_RANK[va], _ACCESS_RANK[vb]),
                )
            )
    if a.unlisted_label_access != b.unlisted_label_access:
        out.append(
            Change(
                f"{base}.unlisted_label_access",
                a.unlisted_label_access,
                b.unlisted_label_access,
                _rank_effect(
                    _ACCESS_RANK[a.unlisted_label_access], _ACCESS_RANK[b.unlisted_label_access]
                ),
            )
        )
    if a.tenant_scoped != b.tenant_scoped:
        effect = Effect.RELAXES if not b.tenant_scoped else Effect.RESTRICTS
        out.append(Change(f"{base}.tenant_scoped", a.tenant_scoped, b.tenant_scoped, effect))
    if a.limits != b.limits:
        out.append(Change(f"{base}.limits", a.limits, b.limits, Effect.NEUTRAL))


def diff_policies(old: Policy, new: Policy) -> PolicyDiff:
    """Semantic diff on the *effective* (inherited) policy, with security effect per change."""
    out: list[Change] = []
    old_roles = {n: old.effective_role(n) for n in old.roles}
    new_roles = {n: new.effective_role(n) for n in new.roles}
    for n in sorted(set(old_roles) - set(new_roles)):
        out.append(Change(f"roles.{n}", "defined", None, Effect.RESTRICTS))
    for n in sorted(set(new_roles) - set(old_roles)):
        out.append(Change(f"roles.{n}", None, "defined", Effect.RELAXES))
    for n in sorted(set(old_roles) & set(new_roles)):
        a, b = old_roles[n], new_roles[n]
        assert a is not None and b is not None
        _diff_role(n, a, b, out)

    for tname in sorted(set(old.catalog.tables) | set(new.catalog.tables)):
        ta, tb = old.catalog.tables.get(tname), new.catalog.tables.get(tname)
        if ta is None or tb is None:
            out.append(
                Change(f"catalog.{tname}", ta and "defined", tb and "defined", Effect.NEUTRAL)
            )
            continue
        if ta.tenant_column != tb.tenant_column:
            effect = Effect.RELAXES if tb.tenant_column is None else Effect.RESTRICTS
            out.append(
                Change(f"catalog.{tname}.tenant_column", ta.tenant_column, tb.tenant_column, effect)
            )
        for col in sorted(set(ta.columns) | set(tb.columns)):
            la = ta.columns[col].effective_labels() if col in ta.columns else set()
            lb = tb.columns[col].effective_labels() if col in tb.columns else set()
            if la - lb:
                out.append(
                    Change(f"catalog.{tname}.{col}.labels", sorted(la - lb), None, Effect.RELAXES)
                )
            if lb - la:
                out.append(
                    Change(f"catalog.{tname}.{col}.labels", None, sorted(lb - la), Effect.RESTRICTS)
                )

    fa, fb = old.functions, new.functions
    if fa.mode != fb.mode:
        effect = Effect.RELAXES if fb.mode == "denylist" else Effect.RESTRICTS
        out.append(Change("functions.mode", fa.mode, fb.mode, effect))
    if set(fa.deny) - set(fb.deny):
        out.append(
            Change("functions.deny", sorted(set(fa.deny) - set(fb.deny)), None, Effect.RELAXES)
        )
    if set(fb.deny) - set(fa.deny):
        out.append(
            Change("functions.deny", None, sorted(set(fb.deny) - set(fa.deny)), Effect.RESTRICTS)
        )
    if set(fa.allow) != set(fb.allow):
        grew = bool(set(fb.allow) - set(fa.allow))
        out.append(
            Change(
                "functions.allow",
                sorted(fa.allow),
                sorted(fb.allow),
                Effect.RELAXES if grew else Effect.RESTRICTS,
            )
        )

    for key in ("max_joins", "max_subquery_depth", "max_limit", "max_sql_length", "max_ast_nodes"):
        va, vb = getattr(old.limits, key), getattr(new.limits, key)
        if va != vb:
            out.append(Change(f"limits.{key}", va, vb, _limit_effect(va, vb)))
    if old.limits.require_limit != new.limits.require_limit:
        out.append(
            Change(
                "limits.require_limit",
                old.limits.require_limit,
                new.limits.require_limit,
                Effect.RELAXES if not new.limits.require_limit else Effect.RESTRICTS,
            )
        )
    for key, va in old.defaults.model_dump().items():
        vb = getattr(new.defaults, key)
        if va != vb:
            out.append(
                Change(f"defaults.{key}", va, vb, _rank_effect(_ACTION_RANK[va], _ACTION_RANK[vb]))
            )
    for key in ("review_score", "deny_score"):
        va, vb = getattr(old.cost, key), getattr(new.cost, key)
        if va != vb:
            out.append(
                Change(f"cost.{key}", va, vb, Effect.RELAXES if vb > va else Effect.RESTRICTS)
            )
    if old.cost.enabled != new.cost.enabled:
        out.append(
            Change(
                "cost.enabled",
                old.cost.enabled,
                new.cost.enabled,
                Effect.RELAXES if not new.cost.enabled else Effect.RESTRICTS,
            )
        )
    if old.disclosure != new.disclosure:
        out.append(Change("disclosure", old.disclosure, new.disclosure, Effect.NEUTRAL))
    return PolicyDiff(old.fingerprint, new.fingerprint, old.revision, new.revision, out)


# ------------------------------------------------------------------------------- simulate
@dataclass(frozen=True)
class SimCase:
    sql: str
    role: str | None
    context: Mapping[str, Any]
    dialect: str | None = None
    expect: str | None = None
    id: str = ""


def load_sim_cases(path: str | Path) -> list[SimCase]:
    """A YAML list (or ``cases:`` mapping) of ``{id, sql, role, context, dialect, expect}``."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    items = data.get("cases", []) if isinstance(data, dict) else data
    out = []
    for i, item in enumerate(items):
        if "sql" not in item:
            raise ValueError(f"case #{i} has no 'sql'")
        out.append(
            SimCase(
                sql=str(item["sql"]),
                role=item.get("role"),
                context=item.get("context") or {},
                dialect=item.get("dialect"),
                expect=item.get("expect"),
                id=str(item.get("id", i + 1)),
            )
        )
    return out


def simulate(
    policy: Policy, cases: Iterable[SimCase], against: Policy | None = None
) -> list[dict[str, Any]]:
    """Evaluate cases under ``policy`` (and optionally a candidate policy) without executing."""
    current = Guard(policy)
    candidate = Guard(against) if against is not None else None
    rows = []
    for case in cases:
        r = current.validate(case.sql, role=case.role, dialect=case.dialect, context=case.context)
        row: dict[str, Any] = {
            "id": case.id,
            "role": case.role,
            "decision": r.decision.value,
            "rules": [f.rule_id for f in r.blocking_findings],
            "expect": case.expect,
            "matches_expectation": None if case.expect is None else r.decision.value == case.expect,
        }
        if candidate is not None:
            c = candidate.validate(
                case.sql, role=case.role, dialect=case.dialect, context=case.context
            )
            row["candidate_decision"] = c.decision.value
            row["changed"] = c.decision != r.decision
            row["candidate_matches_expectation"] = (
                None if case.expect is None else c.decision.value == case.expect
            )
        rows.append(row)
    return rows


# -------------------------------------------------------------------------------- explain
def _setting_source(policy: Policy, role: str, getter: Any) -> str | None:
    """Nearest role in the inheritance chain (child first) that sets a value."""
    seen: set[str] = set()
    queue = [role]
    while queue:
        name = queue.pop(0)
        if name in seen or name not in policy.roles:
            continue
        seen.add(name)
        raw = policy.roles[name]
        if getter(raw):
            return name
        queue.extend(raw.extends)
    return None


def explain_column(policy: Policy, role: str, table: str, column: str) -> dict[str, Any]:
    """How the effective access of ``role`` to ``table.column`` is derived (for reviewers)."""
    from sqlguard_ninja.privacy.rules import resolve_column_access  # noqa: PLC0415

    effective = policy.effective_role(role)
    if effective is None:
        raise KeyError(f"unknown role {role!r}")
    tdef = policy.catalog.tables.get(table)
    if tdef is None or column not in tdef.columns:
        raise KeyError(f"unknown column {table}.{column}")
    grant = effective.tables.get(table)
    granted = grant is not None and (grant.columns == "*" or column in grant.columns)
    denied_col = grant is not None and column in grant.deny_columns
    decision = resolve_column_access(policy, effective, table, column)
    labels = []
    for label in sorted(decision.labels):
        access = effective.labels.get(label, effective.unlisted_label_access)
        source = _setting_source(policy, role, lambda r, lb=label: lb in r.labels)
        labels.append(
            {
                "label": label,
                "access": access.value,
                "set_by_role": source or "(unlisted_label_access)",
            }
        )
    return {
        "role": role,
        "inherits": list(effective.extends),
        "table_granted": grant is not None,
        "table_grant_from": _setting_source(policy, role, lambda r: table in r.tables),
        "column_granted": granted and not denied_col,
        "column_in_deny_columns": denied_col,
        "labels": labels,
        "effective_access": decision.strongest.value if granted and not denied_col else "deny",
        "tenant_scoped": effective.tenant_scoped,
        "tenant_column": tdef.tenant_column,
        "policy_revision": policy.revision,
        "policy_fingerprint": policy.fingerprint,
    }


def explain_result(result: ValidationResult) -> dict[str, Any]:
    """Structured decision explanation (includes internal detail: for operators, not agents)."""
    return {
        "decision": result.decision.value,
        "decision_id": result.decision_id,
        "policy": {
            "name": result.policy_name,
            "revision": result.policy_revision,
            "fingerprint": result.policy_fingerprint,
        },
        "role": result.role,
        "tables": list(result.tables),
        "columns": list(result.columns),
        "findings": [
            {
                "rule_id": f.rule_id,
                "category": f.category.value,
                "action": f.action.value,
                "severity": f.severity.value,
                "message": f.message,
                "detail": f.detail,
                "table": f.table,
                "column": f.column,
                "labels": list(f.labels),
                "remediation": f.remediation,
                "lineage": f.metadata.get("lineage"),
            }
            for f in result.findings
        ],
    }


# ------------------------------------------------------------------------------ templates
TEMPLATES = ("minimal", "multi_tenant_saas", "analytics_readonly")


def template_text(kind: str) -> str:
    if kind not in TEMPLATES:
        raise KeyError(f"unknown template {kind!r}; choose from {list(TEMPLATES)}")
    return (resources.files("sqlguard_ninja.policy") / "templates" / f"{kind}.yaml").read_text(
        encoding="utf-8"
    )
