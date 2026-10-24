"""Column lineage across CTEs and derived tables.

Used to relax two deliberately strict, scope-local checks *only* when the data flow can be
proven, and to explain decisions. Anything unproven returns False, so callers keep their
fail-closed default.

* :func:`aggregated_downstream` — a raw projection of a column in an inner scope is acceptable
  for ``aggregate_only`` access when every consumer of that output aggregates it statistically
  (directly, or through further raw projections that are themselves aggregated downstream).
* :func:`consumers_pin` — a tenant pin applied by every consumer of an unmodified projection
  of the tenant column is equivalent to a pin inside the inner scope, provided the inner
  scope does not aggregate, window, limit or offset rows.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlglot import exp

from sqlguard_ninja.core.analysis import (
    AggregateKind,
    Clause,
    QueryAnalysis,
    ScopeFacts,
    _aggregate_of,
    _clause_of,
)

MAX_DEPTH = 8


def consumers(analysis: QueryAnalysis, facts: ScopeFacts) -> list[tuple[ScopeFacts, str]]:
    """Scopes that select from ``facts`` (CTE or derived table), with the alias they use."""
    out: list[tuple[ScopeFacts, str]] = []
    for other in analysis.scopes:
        if other.scope is None or other is facts:
            continue
        for alias, (_node, source) in other.scope.selected_sources.items():
            if source is facts.scope:
                out.append((other, alias))
    return out


def projection_output(select: exp.Expr, node: exp.Expr) -> str | None:
    """Output name of the select-list item containing ``node``, if it is a plain projection."""
    if not isinstance(select, exp.Select):
        return None
    current: exp.Expr | None = node
    while current is not None and current.parent is not select:
        if isinstance(current, exp.Window):
            return None
        current = current.parent
    if current is None or current.arg_key != "expressions":
        return None
    name = current.alias_or_name
    return name.lower() if name else None


def _references(facts: ScopeFacts, alias: str, column: str) -> list[exp.Column]:
    assert facts.scope is not None
    return [
        c for c in facts.scope.find_all(exp.Column) if c.table == alias and c.name.lower() == column
    ]


def _whole_row_reference(facts: ScopeFacts, alias: str) -> bool:
    assert facts.scope is not None
    return any(n.name == alias for n in facts.scope.find_all(exp.TableColumn))


def aggregated_downstream(
    analysis: QueryAnalysis, facts: ScopeFacts, node: exp.Expr, depth: int = 0
) -> bool:
    """True if the value projected by ``node`` only ever reaches statistical aggregates."""
    if depth > MAX_DEPTH or facts.scope is None:
        return False
    output = projection_output(facts.expression, node)
    if output is None:
        return False
    users = consumers(analysis, facts)
    if not users:
        return False  # the root (or a scalar subquery): the raw value is returned directly
    for consumer, alias in users:
        if _whole_row_reference(consumer, alias):
            return False
        for ref in _references(consumer, alias, output):
            kind = _aggregate_of(ref, consumer.expression)
            if kind is AggregateKind.STATISTICAL:
                continue
            if (
                kind is AggregateKind.NONE
                and _clause_of(ref, consumer.expression) is Clause.SELECT
                and aggregated_downstream(analysis, consumer, ref, depth + 1)
            ):
                continue
            return False
    return True


def resolve_base(
    analysis: QueryAnalysis, facts: ScopeFacts, column: exp.Column, depth: int = 0
) -> tuple[str, str] | None:
    """Base ``(table, column)`` behind ``column`` through *unmodified* projections, if any."""
    if depth > MAX_DEPTH or facts.scope is None:
        return None
    alias = column.table
    if alias in facts.alias_to_table:
        ref = facts.alias_to_table[alias]
        return None if ref.is_function else (ref.name, column.name.lower())
    selected = facts.scope.selected_sources.get(alias)
    if selected is None:
        return None
    source = selected[1]
    inner = next((s for s in analysis.scopes if s.scope is source), None)
    if inner is None or not isinstance(inner.expression, exp.Select):
        return None
    for projection in inner.expression.expressions:
        if projection.alias_or_name.lower() != column.name.lower():
            continue
        value = projection.this if isinstance(projection, exp.Alias) else projection
        if isinstance(value, exp.Column):
            return resolve_base(analysis, inner, value, depth + 1)
        return None
    return None


def derived_references(
    analysis: QueryAnalysis, clauses: tuple[Clause, ...]
) -> list[tuple[ScopeFacts, exp.Column, tuple[str, str]]]:
    """Columns in ``clauses`` that reach a base column only through a CTE or derived table."""
    out = []
    for facts in analysis.scopes:
        if facts.scope is None:
            continue
        for column in facts.scope.find_all(exp.Column):
            if not column.table or column.table in facts.alias_to_table:
                continue  # direct base references are already in analysis.columns
            if _clause_of(column, facts.expression) not in clauses:
                continue
            base = resolve_base(analysis, facts, column)
            if base is not None:
                out.append((facts, column, base))
    return out


def pushdown_eligible(facts: ScopeFacts) -> bool:
    """A scope whose rows map one-to-one onto filtered base rows (no aggregation or limits)."""
    select = facts.expression
    if not isinstance(select, exp.Select) or facts.scope is None:
        return False
    if select.args.get("group") or select.args.get("limit") or select.args.get("offset"):
        return False
    if select.args.get("fetch"):
        return False
    return not any(
        isinstance(node, (exp.AggFunc, exp.Window)) for p in select.expressions for node in p.walk()
    )


def tenant_projection(facts: ScopeFacts, alias: str, column: str) -> str | None:
    """Output name of an unmodified projection ``alias.column`` in ``facts``, if any."""
    select = facts.expression
    if not isinstance(select, exp.Select):
        return None
    for projection in select.expressions:
        inner = projection.this if isinstance(projection, exp.Alias) else projection
        if isinstance(inner, exp.Column) and inner.table == alias and inner.name.lower() == column:
            return str(projection.alias_or_name).lower()
    return None


PinCheck = Callable[[ScopeFacts, str, str], bool]


def consumers_pin(
    analysis: QueryAnalysis,
    facts: ScopeFacts,
    alias: str,
    column: str,
    pinned_in: PinCheck,
    depth: int = 0,
) -> bool:
    """True if every consumer of ``facts`` pins the projected tenant column (recursively)."""
    if depth > MAX_DEPTH or not pushdown_eligible(facts):
        return False
    output = tenant_projection(facts, alias, column)
    if output is None:
        return False
    users = consumers(analysis, facts)
    if not users:
        return False
    for consumer, consumer_alias in users:
        if pinned_in(consumer, consumer_alias, output):
            continue
        if consumers_pin(analysis, consumer, consumer_alias, output, pinned_in, depth + 1):
            continue
        return False
    return True
