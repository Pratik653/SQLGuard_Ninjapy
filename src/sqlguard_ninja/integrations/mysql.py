"""MySQL executor (read-only, time-limited) with AST-based parameter binding.

PyMySQL cannot bind named parameters, and sqlglot's MySQL dialect cannot parse PyMySQL's
``%s`` markers. Validated MySQL SQL therefore uses named placeholders (``:tenant_id``).
Before execution this executor:

1. parses the exact validated string with sqlglot (MySQL dialect);
2. replaces each named placeholder whose value the trusted context supplies with a literal
   (integers, or strings with quotes doubled), refusing any placeholder that is not supplied.
   Strings containing a backslash or NUL are refused: their meaning depends on the server's
   ``NO_BACKSLASH_ESCAPES`` mode, and guessing it is not conservative;
3. sends the result without format parameters, so ``%`` in string literals needs no escaping.

Only placeholder nodes change; string literals and identifiers are never re-written (ADR-013).
Each statement runs in a ``START TRANSACTION READ ONLY`` with ``MAX_EXECUTION_TIME`` and is
rolled back. Use a MySQL account that has only SELECT privileges.

The guard parses MySQL with the server's default lexical rules. Some ``sql_mode`` flags change
how the server reads the same text (``ANSI_QUOTES`` turns ``"x"`` from a string into a column,
``NO_BACKSLASH_ESCAPES`` changes where a string ends), so the executor refuses to run on a
session with any flag in :data:`UNSAFE_SQL_MODES`. Custom executors must do the same.

Requires ``pip install "sqlguard-ninja[mysql]"``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import sqlglot
from sqlglot import exp

Rows = list[dict[str, Any]]

# sql_mode flags under which the server would read validated SQL differently from the guard.
UNSAFE_SQL_MODES = frozenset(
    {"ANSI", "ANSI_QUOTES", "NO_BACKSLASH_ESCAPES", "PIPES_AS_CONCAT", "HIGH_NOT_PRECEDENCE"}
)


class BindError(ValueError):
    """A placeholder in the SQL has no trusted value, or a value has an unsupported type."""


class UnsafeSessionError(RuntimeError):
    """The MySQL session's sql_mode would interpret validated SQL differently."""


def check_sql_mode(sql_mode: str) -> None:
    """Raise :class:`UnsafeSessionError` if ``sql_mode`` contains a flag that changes lexing."""
    flags = {f.strip().upper() for f in sql_mode.split(",") if f.strip()}
    unsafe = sorted(flags & UNSAFE_SQL_MODES)
    if unsafe:
        raise UnsafeSessionError(f"refusing to execute: sql_mode contains {', '.join(unsafe)}")


def bind_placeholders(sql: str, params: Mapping[str, Any]) -> str:
    """Return MySQL SQL with named placeholders replaced by escaped literals."""
    statements = [s for s in sqlglot.parse(sql, dialect="mysql") if s is not None]
    if len(statements) != 1:
        raise BindError("expected exactly one statement")
    tree = statements[0]

    def _replace(node: exp.Expr) -> exp.Expr:
        if not isinstance(node, exp.Placeholder):
            return node
        name = str(node.this or "")
        if not name or name not in params:
            raise BindError(f"no trusted value for placeholder {name or '?'!r}")
        value = params[name]
        if isinstance(value, bool) or value is None:
            raise BindError(f"unsupported value type for {name!r}")
        if isinstance(value, int):
            return exp.Literal.number(value)
        if isinstance(value, str):
            if "\\" in value or "\x00" in value:
                raise BindError(f"refusing backslash or NUL in value for {name!r}")
            return exp.Literal.string(value)
        raise BindError(f"unsupported value type for {name!r}")

    return tree.transform(_replace).sql(dialect="mysql")


def mysql_executor(
    connect: Callable[[], Any], max_rows: int = 200, max_execution_ms: int = 5000
) -> Callable[[str, Mapping[str, Any]], Rows]:  # pragma: no cover - needs a MySQL server
    """Executor for :meth:`SQLCheckpoint.execute` using a PyMySQL connection factory."""

    def run(sql: str, params: Mapping[str, Any]) -> Rows:
        bound = bind_placeholders(sql, params)
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT @@SESSION.sql_mode")
                check_sql_mode(str(cur.fetchone()[0] or ""))
                cur.execute("SET SESSION MAX_EXECUTION_TIME = %s", (int(max_execution_ms),))
                cur.execute("START TRANSACTION READ ONLY")
                try:
                    cur.execute(bound)  # no args: '%' in literals is not a format marker
                    cols = [d[0] for d in cur.description or ()]
                    return [dict(zip(cols, row, strict=False)) for row in cur.fetchmany(max_rows)]
                finally:
                    conn.rollback()
        finally:
            conn.close()

    return run
