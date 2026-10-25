"""Small, safe executors used by the integrations and examples.

These are the *last* line of defence after the checkpoint: they open read-only sessions so
that the database itself refuses writes even if a query were authorized by mistake (or
deliberately, in audit mode). Use a least-privilege database account in production.
"""

from __future__ import annotations

import datetime as dt
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from decimal import Decimal
from typing import Any, Protocol

from sqlguard_ninja.integrations.binding import BoundStatement, ParamStyle, SQLBindingError

Rows = list[dict[str, Any]]


def _bound_params(sql: str, params: Mapping[str, Any]) -> dict[str, Any]:
    # Only pass parameters the statement mentions (whole-name match: ``:tenant_id`` must not
    # select ``tenant_id`` for ``:tenant_id_2``).
    return {
        k: v
        for k, v in params.items()
        if re.search(rf":{re.escape(k)}\b", sql) or f"%({k})s" in sql
    }


def sqlite_executor(conn: sqlite3.Connection, max_rows: int = 200) -> Callable[..., Rows]:
    """Execute on SQLite with ``PRAGMA query_only = ON`` (writes fail at the engine).

    Calls are serialised with a lock so one connection can be shared by threaded servers;
    open it with ``check_same_thread=False`` for that.
    """
    conn.execute("PRAGMA query_only = ON")
    lock = threading.Lock()

    def run(sql: str, params: Mapping[str, Any]) -> Rows:
        with lock:
            cur = conn.execute(sql, _bound_params(sql, params))
            cols = [d[0] for d in cur.description or ()]
            return [dict(zip(cols, row, strict=False)) for row in cur.fetchmany(max_rows)]

    return run


def _check_pg_session(conn: Any) -> None:  # pragma: no cover - needs PostgreSQL
    """The guard lexes strings as PostgreSQL does with standard_conforming_strings on."""
    row = conn.execute("SELECT current_setting('standard_conforming_strings')").fetchone()
    value = next(iter(row.values())) if isinstance(row, dict) else row[0]
    if str(value).lower() != "on":
        raise SQLBindingError("refusing to execute: standard_conforming_strings is off")


def psycopg_executor(
    conninfo: str, max_rows: int = 200, statement_timeout_ms: int = 5000
) -> Callable[..., Rows]:  # pragma: no cover - exercised by PostgreSQL integration tests
    """Execute on PostgreSQL in a READ ONLY transaction with a statement timeout.

    Use ``%(tenant_id)s`` style bind parameters in SQL sent to PostgreSQL.
    """
    import psycopg  # noqa: PLC0415 - optional dependency
    from psycopg.rows import dict_row  # noqa: PLC0415

    def run(sql: str, params: Mapping[str, Any]) -> Rows:
        with (
            psycopg.connect(conninfo, row_factory=dict_row) as conn,
            conn.transaction(force_rollback=True),
        ):
            _check_pg_session(conn)
            conn.execute("SET TRANSACTION READ ONLY")
            conn.execute(
                "SELECT set_config('statement_timeout', %s, true)", (str(statement_timeout_ms),)
            )
            cur = conn.execute(sql, _bound_params(sql, params))
            return list(cur.fetchmany(max_rows))

    return run


# --------------------------------------------------------------------------- safe executors
# Used by SQLCheckpoint.execute_safe. Each declares its dialect and parameter style, receives
# a BoundStatement, and hands SQL and values to the driver separately.


class SafeExecutor(Protocol):
    dialect: str
    paramstyle: ParamStyle

    def __call__(self, stmt: BoundStatement) -> Rows: ...


def _sqlite_value(value: Any) -> Any:
    # sqlite3's implicit date adapters are deprecated; store ISO-8601 text explicitly.
    if isinstance(value, (dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    return value


class SQLiteSafeExecutor:
    """SQLite with native ``sqlite3`` binding, ``query_only`` and a time budget."""

    dialect = "sqlite"
    paramstyle: ParamStyle = "named"

    def __init__(
        self, conn: sqlite3.Connection, max_rows: int = 200, timeout_s: float = 5.0
    ) -> None:
        conn.execute("PRAGMA query_only = ON")
        self.conn, self.max_rows, self.timeout_s = conn, max_rows, timeout_s
        self._lock = threading.Lock()

    def __call__(self, stmt: BoundStatement) -> Rows:
        if stmt.paramstyle != "named":
            raise SQLBindingError("SQLite executor needs a 'named' statement")
        params = {k: _sqlite_value(v) for k, v in stmt.params.items()}
        deadline = time.monotonic() + self.timeout_s
        with self._lock:
            self.conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10_000)
            try:
                cur = self.conn.execute(stmt.sql, params)
                cols = [d[0] for d in cur.description or ()]
                return [dict(zip(cols, row, strict=False)) for row in cur.fetchmany(self.max_rows)]
            finally:
                self.conn.set_progress_handler(None, 0)


class PsycopgSafeExecutor:  # pragma: no cover - exercised by PostgreSQL integration tests
    """PostgreSQL with psycopg 3 **server-side** binding (values travel separately from SQL).

    Runs in a READ ONLY transaction with ``statement_timeout`` and is always rolled back.
    psycopg's ``ClientCursor`` (client-side interpolation) is never used.
    """

    dialect = "postgres"
    paramstyle: ParamStyle = "pyformat"

    def __init__(
        self, conninfo: str, max_rows: int = 200, statement_timeout_ms: int = 5000
    ) -> None:
        self.conninfo, self.max_rows, self.timeout_ms = conninfo, max_rows, statement_timeout_ms

    def __call__(self, stmt: BoundStatement) -> Rows:
        import psycopg  # noqa: PLC0415 - optional dependency
        from psycopg.rows import dict_row  # noqa: PLC0415

        if stmt.paramstyle != "pyformat":
            raise SQLBindingError("PostgreSQL executor needs a 'pyformat' statement")
        with (
            psycopg.connect(self.conninfo, row_factory=dict_row) as conn,
            conn.transaction(force_rollback=True),
        ):
            if type(conn.cursor()) is not psycopg.Cursor:
                raise SQLBindingError("refusing a client-side binding cursor")
            _check_pg_session(conn)
            conn.execute("SET TRANSACTION READ ONLY")
            conn.execute(
                "SELECT set_config('statement_timeout', %s, true)", (str(self.timeout_ms),)
            )
            cur = conn.execute(stmt.sql, stmt.params)
            return list(cur.fetchmany(self.max_rows))
