"""Separating SQL from values: placeholder discovery, the parameter contract, driver binding.

Used by :meth:`SQLCheckpoint.execute_safe`. The contract
(docs/security/SQL_INJECTION_PREVENTION.md):

* Templates use **named colon placeholders** (``:name``). Every other marker is refused:
  ``?``, ``?1``, ``%s``, ``%(name)s``, ``$1``, ``$name``, ``@name``, ``:1``. Drivers give those
  different meanings, and the guard must see exactly what the driver binds.
* Placeholders are found with the **dialect tokenizer**, so ``:name`` inside string literals,
  quoted identifiers and comments is text, not a parameter. The tokens are cross-checked
  against the parsed AST.
* Caller values must match the placeholders exactly: missing, extra, or case-colliding names
  are errors. Names owned by the trusted request context (the tenant) cannot be supplied by
  the caller, in any letter case.
* Values are passed to the **database driver**, never interpolated by this library. Only a
  documented set of types is accepted; anything else fails closed.
* The text handed to the driver is the validated text: identical for SQLite (``named``), or
  a reversible token-level translation to ``%(name)s`` for psycopg and PyMySQL (``pyformat``),
  verified by inverting it before execution.
"""

from __future__ import annotations

import datetime as dt
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal

import sqlglot
from sqlglot import exp
from sqlglot.dialects.dialect import Dialect
from sqlglot.errors import SqlglotError
from sqlglot.tokenizer_core import TokenType

ParamStyle = Literal["named", "pyformat"]
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
_INT_MIN, _INT_MAX = -(2**63), 2**63 - 1
SUPPORTED_TYPES = (
    "None, bool, int (64-bit), float (finite), Decimal (finite), str, bytes, date, datetime, time"
)


class SQLBindingError(ValueError):
    """The SQL template or the supplied values break the binding contract. Safe to display."""


@dataclass(frozen=True)
class BoundStatement:
    """What an executor receives: driver-ready SQL and the values to bind with it."""

    sql: str
    params: dict[str, Any] = field(repr=False)
    paramstyle: ParamStyle
    validated_sql: str
    placeholders: tuple[str, ...]

    def __repr__(self) -> str:  # never print values
        return f"BoundStatement(paramstyle={self.paramstyle!r}, placeholders={self.placeholders!r})"


@dataclass(frozen=True)
class _Span:
    name: str
    start: int
    end: int  # exclusive


def find_placeholders(sql: str, dialect: str) -> list[_Span]:
    """Named ``:name`` placeholders, located with the dialect tokenizer. Refuses other markers."""
    try:
        tokens = Dialect.get_or_raise(dialect).tokenize(sql)
    except SqlglotError as exc:
        raise SQLBindingError("the SQL could not be tokenized") from exc
    spans: list[_Span] = []
    for i, tok in enumerate(tokens):
        kind = tok.token_type
        if kind is TokenType.PLACEHOLDER:
            raise SQLBindingError("'?' placeholders are not supported; use :name")
        if kind is TokenType.PARAMETER or kind is TokenType.SESSION_PARAMETER:
            raise SQLBindingError("'@'/'$' markers are not supported; use :name")
        if kind is TokenType.MOD and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if nxt.start == tok.end + 1 and (
                nxt.token_type is TokenType.L_PAREN or nxt.text.lower() == "s"
            ):
                raise SQLBindingError("'%s'/'%(name)s' placeholders are not supported; use :name")
        if kind is TokenType.VAR and tok.text.startswith("$"):
            raise SQLBindingError("'$name' markers are not supported; use :name")
        if kind is TokenType.COLON:
            name_tok = tokens[i + 1] if i + 1 < len(tokens) else None
            if name_tok is None or name_tok.start != tok.end + 1:
                raise SQLBindingError("a ':' must be followed directly by a placeholder name")
            text = name_tok.text
            if not NAME_RE.fullmatch(text) or sql[name_tok.start : name_tok.end + 1] != text:
                raise SQLBindingError("placeholder names must match [A-Za-z_][A-Za-z0-9_]*")
            spans.append(_Span(text, tok.start, name_tok.end + 1))
    return spans


def _ast_placeholders(sql: str, dialect: str) -> list[str]:
    try:
        trees = [t for t in sqlglot.parse(sql, dialect=dialect) if t is not None]
    except SqlglotError as exc:
        raise SQLBindingError("the SQL could not be parsed") from exc
    if len(trees) != 1:
        raise SQLBindingError("exactly one SQL statement is required")
    names = []
    for node in trees[0].find_all(exp.Placeholder):
        name = node.name
        if not name:
            raise SQLBindingError("anonymous placeholders are not supported; use :name")
        names.append(name)
    return names


def check_value(name: str, value: Any) -> Any:
    """Return the value as it will be bound, or raise for unsupported types."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not _INT_MIN <= value <= _INT_MAX:
            raise SQLBindingError(f"value for {name!r} is outside the 64-bit integer range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SQLBindingError(f"value for {name!r} must be a finite number")
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise SQLBindingError(f"value for {name!r} must be a finite number")
        return value
    if isinstance(value, str):
        if "\x00" in value:
            raise SQLBindingError(f"value for {name!r} contains a NUL character")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise SQLBindingError(f"value for {name!r} is not valid Unicode text") from None
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, (dt.date, dt.time)):  # datetime is a date subclass
        return value
    raise SQLBindingError(
        f"value for {name!r} has unsupported type {type(value).__name__}; "
        f"supported: {SUPPORTED_TYPES}"
    )


def bind_statement(
    sql: str,
    dialect: str,
    params: Mapping[str, Any] | None,
    trusted: Mapping[str, Any],
    paramstyle: ParamStyle,
) -> BoundStatement:
    """Check the binding contract and produce the driver-ready statement."""
    if not isinstance(sql, str):
        raise SQLBindingError("the SQL template must be a string")
    params = dict(params or {})
    spans = find_placeholders(sql, dialect)
    token_names = [s.name for s in spans]
    if sorted(token_names) != sorted(_ast_placeholders(sql, dialect)):
        raise SQLBindingError("placeholders in the SQL are ambiguous")

    folded: dict[str, str] = {}
    for n in token_names:
        if folded.setdefault(n.casefold(), n) != n:
            raise SQLBindingError(
                f"placeholders {n!r} and {folded[n.casefold()]!r} differ only in case"
            )
    reserved = {k.casefold(): k for k in trusted}
    seen: dict[str, str] = {}
    for key in params:
        if not isinstance(key, str) or not NAME_RE.fullmatch(key):
            raise SQLBindingError(f"invalid parameter name {key!r}")
        if key.casefold() in reserved:
            raise SQLBindingError(
                f"parameter {key!r} is reserved for the trusted request context "
                "and cannot be supplied"
            )
        if seen.setdefault(key.casefold(), key) != key:
            raise SQLBindingError(
                f"parameters {key!r} and {seen[key.casefold()]!r} differ only in case"
            )

    names = set(token_names)
    missing = sorted(n for n in names if n not in params and n not in trusted)
    if missing:
        raise SQLBindingError(f"no value supplied for placeholder(s): {', '.join(missing)}")
    extra = sorted(k for k in params if k not in names)
    if extra:
        raise SQLBindingError(f"value(s) supplied for unknown placeholder(s): {', '.join(extra)}")

    values = {n: check_value(n, params[n] if n in params else trusted[n]) for n in sorted(names)}

    if paramstyle == "named":
        driver_sql = sql
    elif paramstyle == "pyformat":
        parts, pos = [], 0
        for s in spans:
            parts.append(sql[pos : s.start].replace("%", "%%"))
            parts.append(f"%({s.name})s")
            pos = s.end
        parts.append(sql[pos:].replace("%", "%%"))
        driver_sql = "".join(parts)
        # Prove the translation is exact: undoing the driver's formatting gives back the
        # validated text, so validation and execution see the same statement.
        if driver_sql % {n: f":{n}" for n in names} != sql:
            raise SQLBindingError("internal error: placeholder translation is not reversible")
    else:  # pragma: no cover - guarded by the type
        raise SQLBindingError(f"unsupported paramstyle {paramstyle!r}")
    return BoundStatement(driver_sql, values, paramstyle, sql, tuple(token_names))


# --------------------------------------------------------------------------- identifiers
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")


def safe_identifier(value: str, allowed: set[str] | frozenset[str], dialect: str) -> str:
    """Quote ``value`` as an identifier **only if** it is in the allowlist.

    Identifiers can never be bound as values. Map user choices to an application-owned set
    (``{"created_at", "total_amount"}``) and pass the result into the SQL template; the
    composed SQL is then validated by the policy like any other query.
    """
    if value not in allowed or not _IDENT_RE.fullmatch(value):
        raise SQLBindingError("identifier is not in the allowlist")
    return exp.to_identifier(value, quoted=True).sql(dialect=dialect)


def safe_order_by(
    column: str, direction: str, allowed: set[str] | frozenset[str], dialect: str
) -> str:
    """``<quoted column> ASC|DESC`` from allowlisted parts."""
    d = direction.upper() if isinstance(direction, str) else ""
    if d not in ("ASC", "DESC"):
        raise SQLBindingError("sort direction must be ASC or DESC")
    return f"{safe_identifier(column, allowed, dialect)} {d}"


def colon_placeholders(sql: str, dialect: str) -> str:
    """Render named placeholders of generated SQL as ``:name`` (sqlglot's PostgreSQL output
    uses ``%(name)s``). Used for the tenant-filter rewrite, whose output is then checked
    against the binding contract like any template."""
    tree = sqlglot.parse_one(sql, dialect=dialect)

    def _swap(node: exp.Expr) -> exp.Expr:
        if isinstance(node, exp.Placeholder) and node.name:
            return exp.Var(this=f":{node.name}")
        return node

    return tree.transform(_swap).sql(dialect=dialect)
