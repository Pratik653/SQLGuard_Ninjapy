"""Opt-in, AST-based tenant-filter enforcement.

:func:`apply_tenant_filters` adds ``<alias>.<tenant_column> = <tenant bind parameter>`` to
every scope that reads a tenant-scoped table without a pin, then **re-validates the rewritten
SQL**. It returns that SQL only if the guard ALLOWs it. That rewritten string is what must be
executed (ADR-011 refines ADR-005: the validated string and the executed string are the same).

It refuses (:class:`TenantRewriteRefused`) whenever safe enforcement cannot be established:

* the original query has any blocking finding other than a missing tenant pin (a rewrite cannot
  fix a forbidden column or a write, and must not mask a query naming another tenant; a cost
  finding is tolerated because the added filters may resolve it, and re-validation decides);
* the unpinned table is the preserved side of a RIGHT or FULL join (ownership is ambiguous);
* the rewritten SQL does not pass validation.

The predicate is built as an AST node with a bind parameter, never by string concatenation,
and the tenant value is never inlined. Database row-level security remains the authoritative
control; this is defence in depth for application-side enforcement.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from sqlglot import exp

from sqlguard_ninja.core.analysis import analyse
from sqlguard_ninja.core.findings import ValidationResult
from sqlguard_ninja.core.guard import Guard
from sqlguard_ninja.core.lineage import consumers_pin
from sqlguard_ninja.core.rules.tenant import _pin_status

TENANT_RULE = "tenant.missing_predicate"
# A missing tenant filter also inflates the static cost score (unfiltered large tables). Such
# findings may be resolved by the rewrite; the re-validation of the rewritten SQL decides.
REWRITE_CAN_RESOLVE = frozenset({TENANT_RULE, "cost.static_score"})


class TenantRewriteRefused(PermissionError):
    def __init__(self, reason: str, result: ValidationResult | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.result = result


@dataclass(frozen=True)
class RewriteResult:
    sql: str
    """The SQL to execute (identical to the input when no rewrite was needed)."""
    original_sql: str
    applied: list[str] = field(default_factory=list)
    """``alias.column`` predicates that were added."""
    result: ValidationResult | None = None

    @property
    def rewritten(self) -> bool:
        return bool(self.applied)


def _join_of(select: exp.Select, alias: str) -> exp.Join | None:
    joins: list[exp.Join] = list(select.args.get("joins") or [])
    return next((j for j in joins if j.alias_or_name == alias), None)


def _right_or_full_preserved(select: exp.Select, alias: str) -> bool:
    """True if ``alias`` is on the preserved side of a RIGHT or FULL join."""
    joins = list(select.args.get("joins") or [])
    from_ = select.args.get("from_") or select.args.get("from")
    base_alias = from_.this.alias_or_name if from_ is not None and from_.this is not None else None
    for join in joins:
        side = (join.side or "").upper()
        if side == "FULL" and (alias in (join.alias_or_name, base_alias)):
            return True
        if side == "RIGHT" and base_alias == alias:
            return True
    return False


def apply_tenant_filters(
    guard: Guard,
    sql: str,
    *,
    role: str | None,
    context: Mapping[str, Any],
    dialect: str | None = None,
    parameter: str | None = None,
) -> RewriteResult:
    """Return SQL that pins every tenant-scoped read, or raise :class:`TenantRewriteRefused`."""
    policy = guard.policy
    dialect = (dialect or policy.dialect).lower()
    cfg = policy.tenant
    param = parameter or (cfg.parameter_names[0] if cfg.parameter_names else None)
    if param is None or param.lower() not in {p.lower() for p in cfg.parameter_names}:
        raise TenantRewriteRefused("the policy declares no approved tenant bind parameter")
    if context.get(cfg.context_key) is None:
        raise TenantRewriteRefused("the request has no trusted tenant context")

    first = guard.validate(sql, role=role, dialect=dialect, context=context)
    if first.allowed:
        return RewriteResult(sql, sql, [], first)
    blocking = first.blocking_findings
    if not any(f.rule_id == TENANT_RULE for f in blocking) or any(
        f.rule_id not in REWRITE_CAN_RESOLVE for f in blocking
    ):
        raise TenantRewriteRefused(
            "the query has problems other than a missing tenant filter", first
        )

    limits = policy.effective_limits(policy.role(role)[1])
    analysis = analyse(sql, dialect, policy.catalog, max_nodes=limits.max_ast_nodes)
    if analysis.qualified is None:
        raise TenantRewriteRefused("the query could not be analysed", first)
    expected = str(context[cfg.context_key])
    params = {p.lower() for p in cfg.parameter_names}

    def pinned_in(facts: Any, alias: str, column: str) -> bool:
        if not isinstance(facts.expression, exp.Select):
            return False
        ok, _others, multi = _pin_status(facts.expression, alias, column, expected, params)
        return ok and not multi

    applied: list[str] = []
    for facts in analysis.scopes:
        select = facts.expression
        if not isinstance(select, exp.Select):
            continue
        for ref in facts.tables:
            tdef = policy.catalog.tables.get(ref.name)
            if ref.is_function or tdef is None or tdef.tenant_column is None:
                continue
            column = tdef.tenant_column
            if pinned_in(facts, ref.alias, column) or consumers_pin(
                analysis, facts, ref.alias, column, pinned_in
            ):
                continue
            if _right_or_full_preserved(select, ref.alias):
                raise TenantRewriteRefused(
                    "a tenant table is on the preserved side of a RIGHT/FULL join", first
                )
            predicate = exp.EQ(
                this=exp.column(column, table=ref.alias),
                expression=exp.Placeholder(this=param),
            )
            join = _join_of(select, ref.alias)
            if join is not None and (join.side or "").upper() == "LEFT":
                on = join.args.get("on")
                join.set("on", exp.and_(on, predicate) if on is not None else predicate)
            else:
                select.where(predicate, append=True, copy=False)
            applied.append(f"{ref.alias}.{column}")

    if not applied:
        raise TenantRewriteRefused("no safe place to add the tenant filter was found", first)
    rewritten = analysis.qualified.sql(dialect=dialect)
    final = guard.validate(rewritten, role=role, dialect=dialect, context=context)
    if not final.allowed:
        raise TenantRewriteRefused("the rewritten query did not pass validation", final)
    return RewriteResult(rewritten, sql, applied, final)
