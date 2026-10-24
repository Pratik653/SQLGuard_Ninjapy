"""Tenant isolation: every read of a tenant-scoped table must be pinned to the caller's tenant.

Semantics (fail closed):

* The tenant value comes only from the trusted request context, never from the query.
* A table reference is *pinned* when, within the scope that reads it, its tenant column is
  connected through ``=`` equalities to the context tenant value (as a literal or an
  approved bind parameter). Only top-level ``AND`` conjuncts of ``WHERE`` and of
  ``INNER JOIN ... ON`` count, plus the ``ON`` clause of the ``LEFT JOIN`` that introduces
  the reference. Anything under ``OR``/``NOT`` is ignored, so ``tenant_id = 1 OR 1 = 1``
  does not pin anything.
* A filter applied in an *outer* scope pins a table read in an inner scope (CTE or derived
  table) only when lineage proves it: the inner scope projects the tenant column unmodified,
  does not aggregate, window, limit or offset rows, and *every* consumer pins that projection
  (see :mod:`sqlguard_ninja.core.lineage`). Otherwise the inner read is unpinned.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from sqlglot import exp

from sqlguard_ninja.core.analysis import ScopeFacts
from sqlguard_ninja.core.findings import Action, Category, Finding, Severity
from sqlguard_ninja.core.lineage import consumers_pin
from sqlguard_ninja.core.rules.base import RuleContext

Term = tuple[str, ...]


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[Term, Term] = {}

    def find(self, x: Term) -> Term:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: Term, b: Term) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb

    def members(self, x: Term) -> list[Term]:
        root = self.find(x)
        return [t for t in list(self.parent) if self.find(t) == root]


def _conjuncts(node: exp.Expr | None) -> list[exp.Expr]:
    if node is None:
        return []
    if isinstance(node, (exp.Where, exp.Having)):
        node = node.this
    while isinstance(node, exp.Paren):
        node = node.this
    if isinstance(node, exp.And):
        return _conjuncts(node.left) + _conjuncts(node.right)
    return [node]


def _term(node: exp.Expr) -> Term | None:
    while isinstance(node, exp.Paren):
        node = node.this
    if isinstance(node, exp.Column) and node.table and not isinstance(node.this, exp.Star):
        return ("col", node.table, node.name)
    # Casts are unwrapped only around constants. A cast of the *column* can be lossy
    # (e.g. text ids '1' and '01' both cast to 1), so it never counts as a pin.
    while isinstance(node, (exp.Paren, exp.Cast, exp.TryCast)):
        node = node.this
    if isinstance(node, exp.Literal):
        return ("const", str(node.this))
    if isinstance(node, exp.Neg) and isinstance(node.this, exp.Literal):
        return ("const", "-" + str(node.this.this))
    if isinstance(node, exp.Placeholder):
        return ("param", str(node.name or node.this or "?").lower())
    if isinstance(node, exp.Parameter):
        return ("param", str(node.name).lower())
    return None


def _add_equalities(uf: _UnionFind, preds: list[exp.Expr]) -> None:
    for pred in preds:
        if isinstance(pred, exp.EQ):
            left, right = _term(pred.left), _term(pred.right)
            if left and right:
                uf.union(left, right)
        elif isinstance(pred, exp.In) and not pred.args.get("query"):
            values = pred.expressions
            left = _term(pred.this)
            if left and len(values) == 1:
                right = _term(values[0])
                if right:
                    uf.union(left, right)
            elif left and len(values) > 1:
                # Several tenants requested: record each so the rule can explain it.
                for value in values:
                    t = _term(value)
                    if t:
                        uf.union(left, ("multi", *t))


def _scope_predicates(
    select: exp.Select,
) -> tuple[list[exp.Expr], dict[str, list[exp.Expr]]]:
    """Top-level WHERE and INNER JOIN conjuncts, plus each LEFT JOIN's own ON conjuncts."""
    joins: list[exp.Join] = list(select.args.get("joins") or [])
    global_preds = _conjuncts(select.args.get("where"))
    left_join_on: dict[str, list[exp.Expr]] = {}
    for join in joins:
        side = (join.side or "").upper()
        kind = (join.kind or "").upper()
        on_preds = _conjuncts(join.args.get("on"))
        if not side and kind in ("", "INNER"):
            global_preds += on_preds
        elif side == "LEFT":
            left_join_on[join.alias_or_name] = on_preds
    return global_preds, left_join_on


def _pin_status(
    select: exp.Select, alias: str, column: str, expected: str, params: set[str]
) -> tuple[bool, list[str], bool]:
    """(pinned to the context tenant, other tenant values seen, multi-value IN)."""
    global_preds, left_join_on = _scope_predicates(select)
    uf = _UnionFind()
    _add_equalities(uf, global_preds + left_join_on.get(alias, []))
    members = uf.members(("col", alias, column))
    pinned = any(m == ("const", expected) or (m[0] == "param" and m[1] in params) for m in members)
    others = sorted({m[-1] for m in members if m[0] in ("const", "multi") and m[-1] != expected})
    multi = any(m[0] == "multi" for m in members)
    return pinned, others, multi


class TenantIsolationRule:
    rule_ids = ("tenant.context_missing", "tenant.missing_predicate", "tenant.wrong_value")

    def check(self, ctx: RuleContext) -> Iterator[Finding]:
        if ctx.role is not None and not ctx.role.tenant_scoped:
            return
        catalog = ctx.policy.catalog
        cfg = ctx.policy.tenant
        tenant_value: Any = ctx.context.get(cfg.context_key)
        params = {p.lower() for p in cfg.parameter_names}
        reported_missing_ctx = False

        for facts in ctx.analysis.scopes:
            scoped = [
                ref
                for ref in facts.tables
                if not ref.is_function
                and ref.name in catalog.tables
                and catalog.tables[ref.name].tenant_column
            ]
            if not scoped or not isinstance(facts.expression, exp.Select):
                continue
            if tenant_value is None:
                if not reported_missing_ctx:
                    reported_missing_ctx = True
                    yield Finding(
                        rule_id="tenant.context_missing",
                        category=Category.TENANT,
                        severity=Severity.CRITICAL,
                        action=Action.DENY,
                        message="The request has no tenant context; tenant-scoped data is "
                        "unavailable.",
                        detail=f"context key {cfg.context_key!r} not supplied by the application",
                    )
                continue
            select = facts.expression

            expected = str(tenant_value)

            def pinned_in(
                scope_facts: ScopeFacts, alias: str, column: str, expected: str = expected
            ) -> bool:
                if not isinstance(scope_facts.expression, exp.Select):
                    return False
                ok, _others, multi_ = _pin_status(
                    scope_facts.expression, alias, column, expected, params
                )
                return ok and not multi_

            for ref in scoped:
                tenant_col = catalog.tables[ref.name].tenant_column
                assert tenant_col is not None
                pinned, others, multi = _pin_status(select, ref.alias, tenant_col, expected, params)
                table_txt = ctx.name("table", ref.name)
                if pinned and not multi:
                    continue
                if (
                    not others
                    and not multi
                    and consumers_pin(ctx.analysis, facts, ref.alias, tenant_col, pinned_in)
                ):
                    continue
                if others or multi:
                    yield Finding(
                        rule_id="tenant.wrong_value",
                        category=Category.TENANT,
                        severity=Severity.CRITICAL,
                        action=Action.DENY,
                        message=f"The query filters {table_txt} by a tenant other than the "
                        "caller's own.",
                        detail=f"{ref.alias}.{tenant_col} compared with {others}",
                        table=ref.name,
                        column=tenant_col,
                    )
                else:
                    yield Finding(
                        rule_id="tenant.missing_predicate",
                        category=Category.TENANT,
                        severity=Severity.CRITICAL,
                        action=Action.DENY,
                        message=f"Every read of {table_txt} must filter on the caller's tenant.",
                        detail=f"no top-level equality on {ref.alias}.{tenant_col} in its scope",
                        table=ref.name,
                        column=tenant_col,
                        remediation=f"Add `{ref.alias}.{tenant_col} = :{cfg.parameter_names[0]}`"
                        " to the WHERE clause of the scope that reads this table."
                        if cfg.parameter_names
                        else None,
                    )
