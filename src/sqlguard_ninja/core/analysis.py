"""Parse SQL once and extract the facts every rule needs.

The analysis is deliberately *structural*: it records which base tables each scope reads,
which base columns each scope references (and in which clause and aggregate context), which
functions are called, and where the analysis was incomplete. Rules then interpret these
facts against a policy. Anything the analyser cannot attribute is recorded as *unresolved*
so rules can fail closed.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import OptimizeError, ParseError, SqlglotError, TokenError
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import Scope, traverse_scope

from sqlguard_ninja.policy.model import Catalog

# sqlglot logs a warning whenever it falls back to exp.Command; the guard reports those
# as findings, so the log line is noise.
logging.getLogger("sqlglot").setLevel(logging.ERROR)

SUPPORTED_DIALECTS = ("postgres", "sqlite", "mysql")
"""Dialects covered by the test-suite and benchmark. Others parse but are experimental."""


class Clause(StrEnum):
    SELECT = "select"
    WHERE = "where"
    JOIN = "join"
    GROUP = "group"
    HAVING = "having"
    ORDER = "order"
    QUALIFY = "qualify"
    OTHER = "other"


class AggregateKind(StrEnum):
    NONE = "none"
    STATISTICAL = "statistical"
    """Reduces many values to a statistic (COUNT, SUM, AVG, ...)."""
    VALUE_REVEALING = "value_revealing"
    """Returns an input value or all of them (MIN, MAX, ARRAY_AGG, window aggregates...)."""


_STATISTICAL_AGGS: tuple[type[exp.Expr], ...] = tuple(
    getattr(exp, n)
    for n in (
        "Count",
        "Sum",
        "Avg",
        "Stddev",
        "StddevPop",
        "StddevSamp",
        "Variance",
        "VariancePop",
        "ApproxDistinct",
        "CountIf",
        "Corr",
        "CovarPop",
        "CovarSamp",
    )
    if hasattr(exp, n)
)

_CLAUSE_KEYS = {
    "where": Clause.WHERE,
    "joins": Clause.JOIN,
    "group": Clause.GROUP,
    "having": Clause.HAVING,
    "order": Clause.ORDER,
    "qualify": Clause.QUALIFY,
    "expressions": Clause.SELECT,
}

_JSON_EXTRACT_TYPES: tuple[type[exp.Expr], ...] = tuple(
    getattr(exp, n)
    for n in (
        "JSONExtract",
        "JSONExtractScalar",
        "JSONBExtract",
        "JSONBExtractScalar",
        "JSONExtractArray",
    )
    if hasattr(exp, n)
)

# Statement and clause node types that must never appear in a read-only query.
WRITE_NODE_TYPES: tuple[type[exp.Expr], ...] = tuple(
    getattr(exp, n)
    for n in (
        "Insert",
        "Update",
        "Delete",
        "Merge",
        "Create",
        "Drop",
        "Alter",
        "TruncateTable",
        "Copy",
        "Grant",
        "Revoke",
        "LoadData",
        "Comment",
        "Analyze",
        "Cache",
        "Uncache",
        "Refresh",
        "Kill",
    )
    if hasattr(exp, n)
)

SESSION_NODE_TYPES: tuple[type[exp.Expr], ...] = tuple(
    getattr(exp, n)
    for n in (
        "Set",
        "Pragma",
        "Attach",
        "Detach",
        "Use",
        "Transaction",
        "Commit",
        "Rollback",
        "Execute",
        "Declare",
        "Describe",
        "Show",
        "Summarize",
    )
    if hasattr(exp, n)
)


@dataclass(frozen=True)
class TableRef:
    """A reference to a base (catalog) table inside one scope."""

    name: str
    """Normalised table name, without schema."""
    schema: str | None
    alias: str
    scope_id: int
    is_function: bool = False
    function_name: str | None = None

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}" if self.schema else self.name


@dataclass(frozen=True)
class ColumnRef:
    """A reference to a column of a base table."""

    table: str
    column: str
    clause: Clause
    aggregate: AggregateKind
    scope_id: int
    json_path: tuple[str, ...] | None = None
    whole_row: bool = False
    """True for ``SELECT t`` (entire row) or an expanded ``*``."""
    from_star: bool = False
    node: Any = field(default=None, compare=False, repr=False)
    """The sqlglot Column node (for lineage); not part of equality."""


@dataclass(frozen=True)
class FunctionRef:
    names: frozenset[str]
    """All names the function is known by: its source name and sqlglot's canonical name."""
    display: str
    known: bool
    """False when sqlglot does not recognise the function (``exp.Anonymous``)."""


@dataclass
class ScopeFacts:
    scope_id: int
    expression: exp.Expr
    tables: list[TableRef] = field(default_factory=list)
    """Base tables read in this scope, keyed by alias through ``alias_to_table``."""
    alias_to_table: dict[str, TableRef] = field(default_factory=dict)
    limit: int | None = None
    has_limit: bool = False
    limit_unparseable: bool = False
    depth: int = 0
    scope: Any = field(default=None, compare=False, repr=False)
    """The sqlglot Scope object (for lineage)."""


@dataclass
class QueryAnalysis:
    sql: str
    dialect: str
    statements: list[exp.Expr] = field(default_factory=list)
    root: exp.Expr | None = None
    qualified: exp.Expr | None = None
    parse_error: str | None = None
    qualify_error: str | None = None
    scopes: list[ScopeFacts] = field(default_factory=list)
    tables: list[TableRef] = field(default_factory=list)
    columns: list[ColumnRef] = field(default_factory=list)
    functions: list[FunctionRef] = field(default_factory=list)
    unresolved_columns: list[str] = field(default_factory=list)
    unexpandable_stars: list[str] = field(default_factory=list)
    node_count: int = 0
    join_count: int = 0
    max_depth: int = 0

    @property
    def ok(self) -> bool:
        return self.parse_error is None and self.root is not None

    @property
    def base_table_names(self) -> list[str]:
        return sorted({t.name for t in self.tables if not t.is_function})


def parse_statements(sql: str, dialect: str) -> list[exp.Expr]:
    """Parse ``sql`` into statements, dropping empty ones (e.g. a trailing ``;``)."""
    return [s for s in sqlglot.parse(sql, dialect=dialect) if s is not None]


def function_names(node: exp.Func) -> FunctionRef:
    if isinstance(node, exp.Anonymous):
        name = str(node.name).lower()
        return FunctionRef(frozenset({name}), name, known=False)
    canonical = node.sql_name().lower()
    names = {canonical, type(node).__name__.lower()}
    # Some functions keep their written name in the AST (e.g. CURRENT_VERSION for version()).
    meta_name = node.meta.get("name") if node.meta else None
    if isinstance(meta_name, str):
        names.add(meta_name.lower())
    return FunctionRef(frozenset(names), canonical, known=True)


def _unwrap_root(statement: exp.Expr) -> exp.Expr:
    node = statement
    while isinstance(node, (exp.Subquery, exp.Paren)) and node.this is not None:
        node = node.this
    return node


def _limit_value(select: exp.Expr) -> tuple[bool, int | None, bool]:
    """Return (has_limit, value, unparseable) for a SELECT or set operation."""
    limit = select.args.get("limit")
    if limit is None:
        fetch = select.args.get("fetch") if hasattr(select, "args") else None
        if fetch is None:
            return False, None, False
        count = fetch.args.get("count")
        limit_expr = count
    else:
        limit_expr = limit.expression if isinstance(limit, exp.Limit) else limit
    if isinstance(limit_expr, exp.Literal) and not limit_expr.is_string:
        try:
            return True, int(str(limit_expr.this)), False
        except ValueError:
            return True, None, True
    return True, None, True


def _clause_of(node: exp.Expr, scope_expr: exp.Expr) -> Clause:
    current = node
    while current.parent is not None and current is not scope_expr:
        parent = current.parent
        if parent is scope_expr:
            return _CLAUSE_KEYS.get(current.arg_key or "", Clause.OTHER)
        if isinstance(parent, exp.Join) and current.arg_key in ("on", "using"):
            return Clause.JOIN
        current = parent
    return Clause.OTHER


def _aggregate_of(node: exp.Expr, scope_expr: exp.Expr) -> AggregateKind:
    """Classify the innermost aggregate around ``node`` within its scope."""
    current = node.parent
    while current is not None and current is not scope_expr:
        if isinstance(current, exp.AggFunc):
            if isinstance(current.parent, exp.Window):
                # SUM(x) OVER (...) is computed per row and can reproduce single values.
                return AggregateKind.VALUE_REVEALING
            if isinstance(current, _STATISTICAL_AGGS):
                return AggregateKind.STATISTICAL
            return AggregateKind.VALUE_REVEALING
        if isinstance(current, (exp.Select, exp.Subquery)):
            break
        current = current.parent
    return AggregateKind.NONE


def _json_path(column: exp.Column) -> tuple[str, ...] | None:
    """Return the JSON path read from ``column``, or None if the whole value is read."""
    keys: list[str] = []
    node: exp.Expr = column
    parent = node.parent
    while isinstance(parent, _JSON_EXTRACT_TYPES) and parent.this is node:
        path = parent.expression
        if isinstance(path, exp.JSONPath):
            for part in path.expressions:
                if isinstance(part, exp.JSONPathKey):
                    keys.append(str(part.this).lower())
        elif isinstance(path, exp.Literal) and path.is_string:
            text = str(path.this).strip()
            if text.startswith("{") and text.endswith("}"):
                keys.extend(k.strip().strip('"').lower() for k in text[1:-1].split(",") if k)
            elif text.startswith("$"):
                keys.extend(k.lower() for k in text.lstrip("$").split(".") if k)
            else:
                keys.append(text.lower())
        elif isinstance(path, exp.Literal):
            pass  # numeric array index: the key path is unchanged
        else:
            return tuple(keys) if keys else None  # dynamic key: caller treats as whole value
        node = parent
        parent = node.parent
    return tuple(keys) if keys else None


def _table_name(table: exp.Table) -> tuple[str, str | None]:
    # Names are already normalised per dialect by qualify(); lower-casing again would
    # erase the case of quoted identifiers that PostgreSQL treats as distinct.
    return table.name, (table.db or None)


def _iter_scope_columns(scope: Scope) -> Iterator[exp.Column]:
    yield from scope.find_all(exp.Column)


def analyse(sql: str, dialect: str, catalog: Catalog | None, *, max_nodes: int) -> QueryAnalysis:
    """Parse and analyse ``sql``. Never raises for malformed input."""
    result = QueryAnalysis(sql=sql, dialect=dialect)
    try:
        result.statements = parse_statements(sql, dialect)
    except (ParseError, TokenError) as exc:
        result.parse_error = str(exc).splitlines()[0][:300]
        return result
    except SqlglotError as exc:  # pragma: no cover - defensive
        result.parse_error = f"{type(exc).__name__}: {exc}"[:300]
        return result
    if len(result.statements) != 1:
        return result

    root = _unwrap_root(result.statements[0])
    result.root = root
    result.node_count = sum(1 for _ in root.walk())
    if result.node_count > max_nodes:
        return result
    if not isinstance(root, (exp.Select, exp.SetOperation)):
        return result

    # Function calls are collected from the unqualified tree so that every call is seen,
    # including those in positions the qualifier rewrites.
    for func in root.find_all(exp.Func):
        result.functions.append(function_names(func))

    schema: dict[str, object] = dict(catalog.sqlglot_schema()) if catalog else {}
    try:
        qualified = qualify(
            root.copy(),
            schema=schema or None,
            dialect=dialect,
            validate_qualify_columns=False,
            quote_identifiers=False,
            identify=False,
        )
    except (OptimizeError, SqlglotError, KeyError, ValueError) as exc:
        result.qualify_error = f"{type(exc).__name__}: {exc}"[:300]
        return result
    result.qualified = qualified
    _collect_scopes(result, qualified, catalog)
    return result


def _collect_scopes(result: QueryAnalysis, qualified: exp.Expr, catalog: Catalog | None) -> None:
    scopes = traverse_scope(qualified)
    scope_ids = {id(s): i for i, s in enumerate(scopes)}
    seen_tables: set[int] = set()

    def depth_of(scope: Scope) -> int:
        d = 0
        parent = scope.parent
        while parent is not None:
            d += 1
            parent = parent.parent
        return d

    for scope in scopes:
        sid = scope_ids[id(scope)]
        facts = ScopeFacts(
            scope_id=sid, expression=scope.expression, depth=depth_of(scope), scope=scope
        )
        result.max_depth = max(result.max_depth, facts.depth)
        if isinstance(scope.expression, (exp.Select, exp.SetOperation)):
            facts.has_limit, facts.limit, facts.limit_unparseable = _limit_value(scope.expression)
        if isinstance(scope.expression, exp.Select):
            result.join_count += len(scope.expression.args.get("joins") or [])

        for alias, source in scope.sources.items():
            if not isinstance(source, exp.Table):
                continue
            seen_tables.add(id(source))
            if isinstance(source.this, exp.Identifier) and _is_cte_name(source):
                continue  # a CTE whose body is not a SELECT (e.g. DELETE ... RETURNING)
            if not isinstance(source.this, exp.Identifier):
                func = source.this
                fname = func.name.lower() if isinstance(func, exp.Func) else str(func).lower()
                ref = TableRef(
                    name=fname,
                    schema=None,
                    alias=alias,
                    scope_id=sid,
                    is_function=True,
                    function_name=fname,
                )
            else:
                name, schema_name = _table_name(source)
                ref = TableRef(name=name, schema=schema_name, alias=alias, scope_id=sid)
            facts.tables.append(ref)
            facts.alias_to_table[alias] = ref
            result.tables.append(ref)
        result.scopes.append(facts)

    # Second pass: columns (needs every scope's alias map for correlated references).
    by_scope = {id(s): result.scopes[scope_ids[id(s)]] for s in scopes}
    for scope in scopes:
        facts = by_scope[id(scope)]
        for column in _iter_scope_columns(scope):
            _record_column(result, scope, facts, column, by_scope, catalog)
        for node in scope.find_all(exp.TableColumn):
            alias = node.name
            row_ref = _resolve_alias(scope, alias, by_scope)
            if row_ref is None:
                continue
            _expand_whole_row(result, row_ref, facts, node, scope, catalog, from_star=False)
        for star_owner in _unexpanded_stars(scope):
            star_ref = _resolve_alias(scope, star_owner, by_scope) if star_owner else None
            label = f"{star_owner}.*" if star_owner else "*"
            if star_ref is not None and catalog is not None and star_ref.name in catalog.tables:
                _expand_whole_row(result, star_ref, facts, scope.expression, scope, catalog, True)
            else:
                result.unexpandable_stars.append(label)

    # Catch-all: base tables in positions no scope claimed (fail closed by recording them).
    for table in qualified.find_all(exp.Table):
        if id(table) in seen_tables or not isinstance(table.this, exp.Identifier):
            continue
        if _is_cte_name(table):
            continue
        name, schema_name = _table_name(table)
        result.tables.append(
            TableRef(name=name, schema=schema_name, alias=table.alias_or_name, scope_id=-1)
        )


def _is_cte_name(table: exp.Table) -> bool:
    if table.db:
        return False
    node: exp.Expr | None = table.parent
    while node is not None:
        with_ = node.args.get("with_") or node.args.get("with")
        if isinstance(with_, exp.With) and any(
            cte.alias_or_name.lower() == table.name.lower() for cte in with_.expressions
        ):
            return True
        node = node.parent
    return False


def _resolve_alias(scope: Scope, alias: str, by_scope: dict[int, ScopeFacts]) -> TableRef | None:
    current: Scope | None = scope
    while current is not None:
        facts = by_scope.get(id(current))
        if facts is not None and alias in facts.alias_to_table:
            return facts.alias_to_table[alias]
        if alias in current.sources:
            return None  # derived table / CTE: its own scope is checked separately
        current = current.parent
    return None


def _unexpanded_stars(scope: Scope) -> Iterator[str]:
    if not isinstance(scope.expression, exp.Select):
        return
    for projection in scope.expression.expressions:
        if isinstance(projection, exp.Star):
            yield ""
        elif isinstance(projection, exp.Column) and isinstance(projection.this, exp.Star):
            yield projection.table


def _expand_whole_row(
    result: QueryAnalysis,
    ref: TableRef,
    facts: ScopeFacts,
    node: exp.Expr,
    scope: Scope,
    catalog: Catalog | None,
    from_star: bool,
) -> None:
    if catalog is None or ref.name not in catalog.tables:
        result.unexpandable_stars.append(f"{ref.alias}.*")
        return
    clause = _clause_of(node, scope.expression) if node is not scope.expression else Clause.SELECT
    aggregate = (
        _aggregate_of(node, scope.expression)
        if node is not scope.expression
        else AggregateKind.NONE
    )
    for col_name in catalog.tables[ref.name].columns:
        result.columns.append(
            ColumnRef(
                table=ref.name,
                column=col_name,
                clause=clause,
                aggregate=aggregate,
                scope_id=facts.scope_id,
                whole_row=True,
                from_star=from_star,
            )
        )


def _record_column(
    result: QueryAnalysis,
    scope: Scope,
    facts: ScopeFacts,
    column: exp.Column,
    by_scope: dict[int, ScopeFacts],
    catalog: Catalog | None,
) -> None:
    if isinstance(column.this, exp.Star):
        return  # handled by star expansion
    alias = column.table
    name = column.name  # normalised by qualify()
    if not alias:
        # An unqualified name the qualifier could not attribute. It may be a select-list
        # alias (ORDER BY total); those are harmless and resolved here.
        # Only references *outside* the select list can point at a select alias; a bare
        # name in the select list that the qualifier left unqualified is unknown.
        if _clause_of(column, scope.expression) is not Clause.SELECT and _is_projection_alias(
            scope, name
        ):
            return
        result.unresolved_columns.append(name)
        return
    ref = _resolve_alias(scope, alias, by_scope)
    if ref is None:
        if not _alias_is_derived(scope, alias):
            result.unresolved_columns.append(f"{alias}.{name}")
        return
    if ref.is_function:
        return
    result.columns.append(
        ColumnRef(
            table=ref.name,
            column=name,
            clause=_clause_of(column, scope.expression),
            aggregate=_aggregate_of(column, scope.expression),
            scope_id=facts.scope_id,
            json_path=_json_path(column),
            node=column,
        )
    )


def _is_projection_alias(scope: Scope, name: str) -> bool:
    expr = scope.expression
    if not isinstance(expr, exp.Select):
        return False
    return any(isinstance(p, exp.Alias) and p.alias.lower() == name for p in expr.expressions)


def _alias_is_derived(scope: Scope, alias: str) -> bool:
    current: Scope | None = scope
    while current is not None:
        if alias in current.sources:
            return not isinstance(current.sources[alias], exp.Table)
        current = current.parent
    return False
