# ruff: noqa: RUF001, PLE2502 - adversarial Unicode and control characters are the point
"""SQL injection regression suite on real engines: SQLite, PostgreSQL (CI), MySQL 8.4 (CI).

Every untrusted value goes through SQLCheckpoint.execute_safe with driver binding. The tests
check what the database actually did: the value comes back byte-for-byte as data, predicates
match nothing they should not, tables are unchanged, and tenant scope holds.
"""

from __future__ import annotations

import datetime as dt
import os
import secrets
import sqlite3
from dataclasses import dataclass
from decimal import Decimal
from urllib.parse import urlparse

import pytest

from sqlguard_ninja import Guard
from sqlguard_ninja.benchmarking.fixtures import create_sqlite, populate
from sqlguard_ninja.integrations import (
    PsycopgSafeExecutor,
    RequestContext,
    SQLBindingError,
    SQLBlockedError,
    SQLCheckpoint,
    SQLiteSafeExecutor,
    safe_order_by,
)
from sqlguard_ninja.integrations.binding import bind_statement

PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "admin'--",
    "x'; DROP TABLE customers; --",
    "1; DROP TABLE customers",
    "' UNION SELECT card_number FROM payments --",
    "'||(SELECT card_number FROM payments LIMIT 1)||'",
    "\\' OR 1=1 -- ",
    "\\\\' OR 1=1 #",
    "\\",
    '" OR ""="',
    "`id` FROM payments --",
    "%s",
    "%(tenant_id)s",
    "%%",
    ":tenant_id",
    "$1",
    "$$; DROP TABLE customers; $$",
    "@tenant_id",
    "@@version",
    "?",
    "/* */ OR /* */ 1=1",
    "ʼ OR 1=1 --",
    "＇ OR 1=1 --",
    "’ OR 1=1",
    "abc‮dcba",
    "\U0001f600'\U0001f4a5",
    "ȩ́",
    "\x01\x02\x1b[0m\x7f",
    "line1\nline2\r\n\tend",
    "x" * 10_000,
    "",
    " ",
    "0x27",
    "CHAR(39)",
    "SLEEP(5)",
    "pg_sleep(5)",
    "1e309",
    "NULL",
]
ECHO = "SELECT c.id, :needle AS v FROM customers c WHERE c.tenant_id = :tenant_id ORDER BY c.id LIMIT 1"
FILTER = "SELECT c.id FROM customers c WHERE c.tenant_id = :tenant_id AND c.email = :needle"
COUNT = "SELECT COUNT(*) AS n FROM customers c WHERE c.tenant_id = :tenant_id"


@dataclass
class Engine:
    name: str
    cp: SQLCheckpoint
    run: object  # SafeExecutor
    writer: object  # executor with write privileges (proves the executor's own read-only mode)


def _mysql_engine(policy):
    import pymysql

    dsn = os.environ.get("SQLNINJA_MYSQL_DSN")
    if not dsn:
        pytest.skip("SQLNINJA_MYSQL_DSN not set")
    from sqlguard_ninja.integrations.mysql import MySQLSafeExecutor

    u = urlparse(dsn)
    db, user, pw = "sqlninja_sqli", "sqlninja_sqli_reader", secrets.token_hex(12)

    def connect(name, password, database=None, charset="utf8mb4"):
        return pymysql.connect(
            host=u.hostname,
            port=u.port or 3306,
            user=name,
            password=password,
            database=database,
            autocommit=False,
            charset=charset,
        )

    admin = connect(u.username or "root", u.password or "")
    with admin.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS {db}")
        cur.execute(f"CREATE DATABASE {db} CHARACTER SET utf8mb4")
        cur.execute("DROP USER IF EXISTS %s@'%%'", (user,))
        cur.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (user, pw))
        cur.execute(f"GRANT SELECT ON {db}.* TO %s@'%%'", (user,))
    admin.commit()
    admin.select_db(db)
    populate(admin, policy, "mysql")
    admin.close()
    reader = MySQLSafeExecutor(lambda: connect(user, pw, db))
    writer = MySQLSafeExecutor(lambda: connect(u.username or "root", u.password or "", db))
    return reader, writer, connect, (user, pw, db)


@pytest.fixture(
    scope="module",
    params=[
        "sqlite",
        pytest.param("postgres", marks=pytest.mark.postgres),
        pytest.param("mysql", marks=pytest.mark.mysql),
    ],
)
def engine(request, policy):
    name = request.param
    if name == "sqlite":
        run = SQLiteSafeExecutor(create_sqlite(policy))
        writer = SQLiteSafeExecutor(create_sqlite(policy))
    elif name == "postgres":
        env = request.getfixturevalue("pg")
        run, writer = PsycopgSafeExecutor(env.reader_dsn), PsycopgSafeExecutor(env.admin_dsn)
    else:
        run, writer, connect, creds = _mysql_engine(policy)
        request.node.mysql = (connect, creds)
    return Engine(name, SQLCheckpoint(Guard(policy), dialect=name), run, writer)


CTX = RequestContext(principal="sqli-suite", role="support_analyst", tenant_id=1)


def go(engine, sql, params=None, ctx=CTX):
    return engine.cp.execute_safe(sql, ctx, engine.run, params)


# --------------------------------------------------------------------------- values stay data
@pytest.mark.parametrize("payload", PAYLOADS, ids=range(len(PAYLOADS)))
def test_payload_round_trips_exactly_as_data(engine, payload):
    rows = go(engine, ECHO, {"needle": payload})
    assert len(rows) == 1 and rows[0]["v"] == payload


@pytest.mark.parametrize("payload", PAYLOADS, ids=range(len(PAYLOADS)))
def test_payload_in_predicate_matches_nothing(engine, payload):
    assert go(engine, FILTER, {"needle": payload}) == []


def test_tables_unchanged_after_payloads(engine):
    before = go(engine, COUNT)[0]["n"]
    for p in PAYLOADS:
        go(engine, FILTER, {"needle": p})
    assert go(engine, COUNT)[0]["n"] == before > 0


def test_benign_value_still_matches(engine):
    rows = go(engine, FILTER, {"needle": "user3@example.com"})
    assert rows == [{"id": 3}]


@pytest.mark.parametrize(
    "value",
    [0, -42, 2**62, 1.25, True, None, b"\x00'\\\xff", Decimal("12.50")],
    ids=["zero", "neg", "big", "float", "bool", "none", "bytes", "decimal"],
)
def test_typed_values_bind_as_values(engine, value):
    v = go(engine, ECHO, {"needle": value})[0]["v"]
    if isinstance(value, bytes):
        assert bytes(v) == value
    elif isinstance(value, bool):
        assert v in (True, 1)
    elif isinstance(value, Decimal):
        assert Decimal(str(v)) == value
    else:
        assert v == value


def test_dates_bind_as_values(engine):
    v = go(engine, ECHO, {"needle": dt.date(2026, 1, 2)})[0]["v"]
    assert str(v)[:10] == "2026-01-02"


# --------------------------------------------------------------------------- template text
def test_placeholder_lookalikes_in_literals_are_not_bound(engine):
    sql = (
        "SELECT ':needle' AS lit, '100%' AS pct, '%(needle)s' AS fake, :needle AS v "
        "FROM customers c WHERE c.tenant_id = :tenant_id LIMIT 1 -- :needle %"
    )
    row = go(engine, sql, {"needle": "real"})[0]
    assert (row["lit"], row["pct"], row["fake"], row["v"]) == (
        ":needle",
        "100%",
        "%(needle)s",
        "real",
    )


def test_postgres_dollar_and_escape_strings(engine):
    if engine.name != "postgres":
        pytest.skip("PostgreSQL string syntax")
    sql = (
        "SELECT $$:needle ' %$$ AS a, E'it\\'s :needle' AS b, :needle AS v "
        "FROM customers c WHERE c.tenant_id = :tenant_id LIMIT 1"
    )
    row = go(engine, sql, {"needle": "$$x$$"})[0]
    assert (row["a"], row["b"], row["v"]) == (":needle ' %", "it's :needle", "$$x$$")


def test_stacked_statements_in_the_template_are_refused(engine):
    with pytest.raises(SQLBindingError):
        go(engine, COUNT + "; SELECT 1")


# --------------------------------------------------------------------------- tenant ownership
def test_caller_cannot_supply_or_override_the_tenant(engine):
    for key in ("tenant_id", "TENANT_ID"):
        with pytest.raises(SQLBindingError, match="reserved"):
            go(engine, COUNT, {key: 2})


def test_tenant_filter_on_a_caller_value_is_denied(engine):
    sql = "SELECT c.id FROM customers c WHERE c.tenant_id = :wanted"
    with pytest.raises(SQLBlockedError):
        go(engine, sql, {"wanted": 2})


def test_tenant_rewrite_binds_the_trusted_tenant(engine, policy):
    cp = SQLCheckpoint(Guard(policy), dialect=engine.name, rewrite_tenant_filters=True)
    rows = cp.execute_safe(
        "SELECT o.tenant_id, o.status FROM orders o WHERE o.status = :status AND o.currency LIKE 'E%'",
        RequestContext(principal="t", role="support_analyst", tenant_id=2),
        engine.run,
        {"status": "paid"},
    )
    assert rows and {r["tenant_id"] for r in rows} == {2}


# --------------------------------------------------------------------------- policy still applies
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT c.id FROM customers c WHERE c.tenant_id = :tenant_id UNION SELECT p.card_number FROM payments p WHERE p.tenant_id = :tenant_id",
        "SELECT p.card_number FROM payments p WHERE p.tenant_id = :tenant_id AND p.order_id = :needle",
        "SELECT c.id FROM customers c WHERE c.tenant_id = :tenant_id OR c.email = :needle",
    ],
    ids=["union-protected", "protected-column", "or-around-tenant"],
)
def test_policy_blocks_structural_attacks(engine, sql):
    params = {"needle": "x"} if ":needle" in sql else None
    with pytest.raises(SQLBlockedError):
        go(engine, sql, params)


def test_allowlisted_dynamic_order_by(engine):
    order = safe_order_by("created_at", "desc", {"created_at", "total_amount"}, engine.name)
    rows = go(
        engine, f"SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id ORDER BY {order} LIMIT 3"
    )
    assert len(rows) == 3


# --------------------------------------------------------------------------- executor boundary
def test_executor_is_read_only_even_with_write_privileges(engine):
    stmt = bind_statement(
        "DELETE FROM customers WHERE tenant_id = :tenant_id",
        engine.name,
        None,
        {"tenant_id": 1},
        engine.writer.paramstyle,
    )
    with pytest.raises(Exception) as info:
        engine.writer(stmt)
    assert "read" in str(info.value).lower(), info.value  # the engine's read-only refusal


def test_executor_refuses_a_statement_in_the_wrong_style(engine):
    other = "pyformat" if engine.run.paramstyle == "named" else "named"
    stmt = bind_statement(COUNT, engine.name, None, {"tenant_id": 1}, other)
    with pytest.raises(SQLBindingError):
        engine.run(stmt)


def test_sqlite_runaway_query_is_interrupted(policy):
    run = SQLiteSafeExecutor(create_sqlite(policy), timeout_s=0.2)
    stmt = bind_statement(
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT MAX(n) FROM r",
        "sqlite",
        None,
        {},
        "named",
    )
    with pytest.raises(sqlite3.OperationalError, match="interrupted"):
        run(stmt)


@pytest.mark.mysql
@pytest.mark.parametrize(
    "setup",
    [
        "SET SESSION sql_mode = CONCAT(@@SESSION.sql_mode, ',NO_BACKSLASH_ESCAPES')",
        "SET SESSION sql_mode = 'ANSI_QUOTES'",
        "SET NAMES latin1",
    ],
    ids=["no-backslash-escapes", "ansi-quotes", "latin1"],
)
def test_mysql_refuses_sessions_that_change_lexing(policy, setup):
    from sqlguard_ninja.integrations.mysql import MySQLSafeExecutor, UnsafeSessionError

    _, _, connect, (user, pw, db) = _mysql_engine(policy)

    def session():
        conn = (
            connect(user, pw, db, charset="latin1") if "latin1" in setup else connect(user, pw, db)
        )
        with conn.cursor() as cur:
            cur.execute(setup)
        return conn

    stmt = bind_statement(ECHO, "mysql", {"needle": "\\' OR 1=1 -- "}, {"tenant_id": 1}, "pyformat")
    with pytest.raises(UnsafeSessionError):
        MySQLSafeExecutor(session)(stmt)
