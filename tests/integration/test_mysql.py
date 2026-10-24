"""MySQL integration tests (MySQL 8 via SQLNINJA_MYSQL_DSN; CI uses a service container).

The admin DSN creates a fresh database with the synthetic fixture and a SELECT-only account.
Every MySQL `allow` case in the corpus must then execute as that account through the
read-only executor, which is the independent label validation used for SQLite and PostgreSQL.
"""

from __future__ import annotations

import os
import secrets
from urllib.parse import urlparse

import pytest

from sqlguard_ninja import Guard
from sqlguard_ninja.benchmarking.dataset import load_dataset
from sqlguard_ninja.benchmarking.fixtures import populate
from sqlguard_ninja.integrations import RequestContext, SQLBlockedError, SQLCheckpoint
from tests.conftest import DATASET_PATH

pymysql = pytest.importorskip("pymysql")
from sqlguard_ninja.integrations.mysql import mysql_executor  # noqa: E402

pytestmark = pytest.mark.mysql
DSN = os.environ.get("SQLNINJA_MYSQL_DSN")
DATASET = load_dataset(DATASET_PATH)
ALLOWED = [c for c in DATASET.cases if c.dialect == "mysql" and c.expected.value == "allow"]
DB = "sqlninja_test"
READER = "sqlninja_reader"


def _connect(user: str, password: str, database: str | None = None):
    u = urlparse(DSN)
    return pymysql.connect(
        host=u.hostname,
        port=u.port or 3306,
        user=user,
        password=password,
        database=database,
        autocommit=False,
        charset="utf8mb4",
    )


@pytest.fixture(scope="module")
def reader(policy):
    if not DSN:
        pytest.skip("SQLNINJA_MYSQL_DSN not set")
    u = urlparse(DSN)
    password = secrets.token_hex(12)  # throwaway test credential
    admin = _connect(u.username or "root", u.password or "")
    with admin.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS {DB}")
        cur.execute(f"CREATE DATABASE {DB}")
        cur.execute("DROP USER IF EXISTS %s@'%%'", (READER,))
        cur.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (READER, password))
        cur.execute(f"GRANT SELECT ON {DB}.* TO %s@'%%'", (READER,))
    admin.commit()
    admin.select_db(DB)
    populate(admin, policy, "mysql")
    admin.close()
    return lambda: _connect(READER, password, DB)


@pytest.mark.parametrize("case", ALLOWED, ids=lambda c: c.id)
def test_allowed_mysql_case_executes_as_reader(reader, case):
    run = mysql_executor(reader)
    run(case.sql, case.context)


def test_reader_cannot_write(reader):
    conn = reader()
    try:
        with conn.cursor() as cur, pytest.raises(pymysql.err.OperationalError):
            cur.execute("DELETE FROM orders WHERE tenant_id = 1")
    finally:
        conn.close()


def test_executor_is_read_only_even_with_write_privileges(policy):
    if not DSN:
        pytest.skip("SQLNINJA_MYSQL_DSN not set")
    u = urlparse(DSN)
    run = mysql_executor(lambda: _connect(u.username or "root", u.password or "", DB))
    with pytest.raises(pymysql.err.MySQLError):
        run("DELETE FROM orders WHERE tenant_id = 1", {})


def test_checkpoint_end_to_end(reader, policy):
    cp = SQLCheckpoint(Guard(policy), dialect="mysql")
    ctx = RequestContext(principal="t", role="support_analyst", tenant_id=1)
    rows = cp.execute(
        "SELECT o.status, COUNT(*) AS n FROM orders o WHERE o.tenant_id = :tenant_id GROUP BY o.status",
        ctx,
        mysql_executor(reader),
    )
    assert rows and {"status", "n"} <= set(rows[0])
    with pytest.raises(SQLBlockedError):
        cp.execute(
            "SELECT p.card_number FROM payments p WHERE p.tenant_id = 1",
            ctx,
            mysql_executor(reader),
        )


def test_executor_refuses_ansi_quotes_session(reader):
    from sqlguard_ninja.integrations.mysql import UnsafeSessionError

    def ansi():
        conn = reader()
        with conn.cursor() as cur:
            cur.execute("SET SESSION sql_mode = CONCAT(@@SESSION.sql_mode, ',ANSI_QUOTES')")
        return conn

    with pytest.raises(UnsafeSessionError):
        mysql_executor(ansi)('SELECT "card_number" FROM payments', {})
