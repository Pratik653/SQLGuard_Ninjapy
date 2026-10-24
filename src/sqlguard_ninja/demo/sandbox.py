"""A restricted, in-memory SQLite database with synthetic data for the demo.

The guard's ALLOW is not treated as sufficient. The database itself enforces:

* ``PRAGMA query_only`` and an **authorizer** that permits only reading tables and calling an
  allowlist of side-effect-free functions (no ATTACH, PRAGMA, writes, or schema changes);
* engine **limits** on string length, SQL length, expression depth, compound selects,
  attached databases and variables;
* a **step budget** through the progress handler, so runaway queries (recursive CTEs,
  cartesian products) are interrupted;
* a **row cap** and value truncation on results.

The database is created in memory from deterministic synthetic data, holds nothing real, and
is private to the process (or to the visitor's browser in the static demo).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlguard_ninja.benchmarking.fixtures import create_sqlite
from sqlguard_ninja.policy.model import Policy

ALLOWED_FUNCTIONS = frozenset(
    {
        "count", "sum", "avg", "min", "max", "total", "round", "abs", "lower", "upper",
        "length", "substr", "substring", "trim", "ltrim", "rtrim", "coalesce", "ifnull",
        "nullif", "iif", "instr", "like", "glob", "date", "time", "datetime", "julianday",
        "strftime", "unixepoch", "cast", "json_extract", "->", "->>", "row_number", "rank",
        "dense_rank", "ntile", "lag", "lead", "first_value", "last_value", "percent_rank",
        "cume_dist", "typeof", "concat", "concat_ws", "group_concat", "string_agg",
    }
)  # fmt: skip
_READ_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_RECURSIVE}
_LIMITS = {
    "SQLITE_LIMIT_LENGTH": 100_000,
    "SQLITE_LIMIT_SQL_LENGTH": 20_000,
    "SQLITE_LIMIT_COLUMN": 100,
    "SQLITE_LIMIT_EXPR_DEPTH": 100,
    "SQLITE_LIMIT_COMPOUND_SELECT": 10,
    "SQLITE_LIMIT_FUNCTION_ARG": 16,
    "SQLITE_LIMIT_ATTACHED": 0,
    "SQLITE_LIMIT_LIKE_PATTERN_LENGTH": 200,
    "SQLITE_LIMIT_VARIABLE_NUMBER": 8,
    "SQLITE_LIMIT_TRIGGER_DEPTH": 0,
}


class SandboxError(RuntimeError):
    """The database refused or interrupted the query. The message is safe to display."""


@dataclass(frozen=True)
class QueryResult:
    columns: list[str]
    rows: list[list[Any]]
    truncated: bool
    elapsed_ms: float


def make_authorizer(tables: frozenset[str]) -> Any:
    """Allow SELECT, reads of the given tables only, and allowlisted functions."""

    def authorize(action: int, arg1: str | None, arg2: str | None, *_: Any) -> int:
        if action == sqlite3.SQLITE_READ:
            return sqlite3.SQLITE_OK if (arg1 or "").lower() in tables else sqlite3.SQLITE_DENY
        if action in _READ_ACTIONS:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in ALLOWED_FUNCTIONS:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    return authorize


class Sandbox:
    """Thread-safe wrapper around one restricted in-memory connection."""

    def __init__(
        self,
        policy: Policy,
        *,
        max_rows: int = 100,
        max_steps: int = 2_000_000,
        timeout_s: float = 1.0,
        max_value_chars: int = 200,
    ) -> None:
        self.max_rows = max_rows
        self.max_steps = max_steps
        self.timeout_s = timeout_s
        self.max_value_chars = max_value_chars
        self._conn = create_sqlite(policy)
        self._conn.execute("PRAGMA query_only = ON")
        for name, value in _LIMITS.items():
            category = getattr(sqlite3, name, None)
            if category is not None:
                self._conn.setlimit(category, value)
        self._conn.set_authorizer(make_authorizer(frozenset(policy.catalog.tables)))
        self._lock = threading.Lock()

    def execute(self, sql: str, params: Mapping[str, Any]) -> QueryResult:
        """Run one read-only statement. Raises :class:`SandboxError` on refusal or timeout."""
        names = {k: v for k, v in params.items() if f":{k}" in sql}
        deadline = time.perf_counter() + self.timeout_s
        steps = 0

        def progress() -> int:
            nonlocal steps
            steps += 1000
            return 1 if steps > self.max_steps or time.perf_counter() > deadline else 0

        with self._lock:
            started = time.perf_counter()
            self._conn.set_progress_handler(progress, 1000)
            try:
                cur = self._conn.execute(sql, names)
                columns = [d[0] for d in cur.description or ()]
                raw = cur.fetchmany(self.max_rows + 1)
            except sqlite3.OperationalError as exc:
                text = str(exc).lower()
                if "interrupted" in text:
                    raise SandboxError("The query ran too long and was stopped.") from None
                if "not authorized" in text or "prohibited" in text or "readonly" in text:
                    raise SandboxError("The database refused this operation.") from None
                raise SandboxError("The database could not run this query.") from None
            except sqlite3.Error:
                raise SandboxError("The database could not run this query.") from None
            finally:
                self._conn.set_progress_handler(None, 0)
            elapsed = (time.perf_counter() - started) * 1000
        rows = [[self._cell(v) for v in row] for row in raw[: self.max_rows]]
        return QueryResult(columns, rows, len(raw) > self.max_rows, round(elapsed, 2))

    def _cell(self, value: Any) -> Any:
        if isinstance(value, float):
            return round(value, 4)
        if isinstance(value, bytes):
            return f"<{len(value)} bytes>"
        if isinstance(value, str) and len(value) > self.max_value_chars:
            return value[: self.max_value_chars] + "…"
        return value
