"""MySQL executors (read-only, time-limited) with PyMySQL driver binding.

Validated MySQL SQL uses named placeholders (``:tenant_id``). Before execution the statement
goes through :func:`~sqlguard_ninja.integrations.binding.bind_statement`, which locates the
placeholders with the MySQL tokenizer and translates only them to PyMySQL's ``%(name)s``
markers (doubling every other ``%``); undoing that translation gives back the validated text.
The values are then passed to ``cursor.execute(sql, params)``: **PyMySQL** escapes them
(client-side binding; PyMySQL has no server-side prepared statements), honouring the
server's ``NO_BACKSLASH_ESCAPES`` status and sending bytes as hex literals. This library
never interpolates values itself (ADR-015 supersedes the AST literal substitution of ADR-013).

Each statement runs in ``START TRANSACTION READ ONLY`` with ``MAX_EXECUTION_TIME`` and is
rolled back. The connection must use a UTF-8 character set (``utf8mb4``): multi-byte
character sets such as GBK have historically broken client-side escaping. Use a MySQL account
that has only SELECT privileges.

The guard parses MySQL with the server's default lexical rules. Some ``sql_mode`` flags change
how the server reads the same text (``ANSI_QUOTES`` turns ``"x"`` from a string into a column,
``NO_BACKSLASH_ESCAPES`` changes where a string ends), so the executors refuse to run on a
session with any flag in :data:`UNSAFE_SQL_MODES`. Custom executors must do the same.

Requires ``pip install "sqlguard-ninja[mysql]"``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import sqlglot
from sqlglot import exp

from sqlguard_ninja.integrations.binding import (
    BoundStatement,
    ParamStyle,
    SQLBindingError,
    bind_statement,
)

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
    """Deprecated (kept for compatibility; no longer used by the executors, ADR-015).

    Returns MySQL SQL with named placeholders replaced by literals. Prefer driver binding
    through :meth:`SQLCheckpoint.execute_safe` with :class:`MySQLSafeExecutor`.
    """
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


SAFE_CHARSETS = frozenset({"utf8mb4", "utf8mb3", "utf8"})


def _run(
    connect: Callable[[], Any], stmt: BoundStatement, max_rows: int, max_execution_ms: int
) -> Rows:  # pragma: no cover - needs a MySQL server
    conn = connect()
    try:
        charset = str(getattr(conn, "charset", "")).lower()
        if charset not in SAFE_CHARSETS:
            raise UnsafeSessionError(
                f"refusing to execute: connection charset {charset!r} is not UTF-8"
            )
        with conn.cursor() as cur:
            cur.execute("SELECT @@SESSION.sql_mode")
            check_sql_mode(str(cur.fetchone()[0] or ""))
            cur.execute("SET SESSION MAX_EXECUTION_TIME = %s", (int(max_execution_ms),))
            cur.execute("START TRANSACTION READ ONLY")
            try:
                cur.execute(stmt.sql, stmt.params)  # PyMySQL binds; one formatting pass only
                cols = [d[0] for d in cur.description or ()]
                return [dict(zip(cols, row, strict=False)) for row in cur.fetchmany(max_rows)]
            finally:
                conn.rollback()
    finally:
        conn.close()


def mysql_executor(
    connect: Callable[[], Any], max_rows: int = 200, max_execution_ms: int = 5000
) -> Callable[[str, Mapping[str, Any]], Rows]:  # pragma: no cover - needs a MySQL server
    """Executor for :meth:`SQLCheckpoint.execute`: binds the trusted context values only."""

    def run(sql: str, params: Mapping[str, Any]) -> Rows:
        stmt = bind_statement(sql, "mysql", None, trusted=params, paramstyle="pyformat")
        return _run(connect, stmt, max_rows, max_execution_ms)

    return run


class MySQLSafeExecutor:
    """Executor for :meth:`SQLCheckpoint.execute_safe` (PyMySQL connection factory)."""

    dialect = "mysql"
    paramstyle: ParamStyle = "pyformat"

    def __init__(
        self, connect: Callable[[], Any], max_rows: int = 200, max_execution_ms: int = 5000
    ) -> None:
        self.connect, self.max_rows, self.max_execution_ms = connect, max_rows, max_execution_ms

    def __call__(self, stmt: BoundStatement) -> Rows:  # pragma: no cover - needs a MySQL server
        if stmt.paramstyle != "pyformat":
            raise SQLBindingError("MySQL executor needs a 'pyformat' statement")
        return _run(self.connect, stmt, self.max_rows, self.max_execution_ms)
