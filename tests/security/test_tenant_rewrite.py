"""AST tenant-filter rewrite: executed results stay inside the caller's tenant."""

from __future__ import annotations

import re

import pytest

from sqlguard_ninja import Guard, Policy
from sqlguard_ninja.benchmarking.fixtures import create_sqlite
from sqlguard_ninja.integrations import (
    InMemoryAuditSink,
    RequestContext,
    SQLBlockedError,
    SQLCheckpoint,
)
from sqlguard_ninja.integrations.executors import sqlite_executor
from sqlguard_ninja.tenancy import TenantRewriteRefused, apply_tenant_filters
from tests.conftest import POLICY_PATH

POLICY = Policy.from_file(POLICY_PATH)
GUARD = Guard(POLICY)


@pytest.fixture(scope="module")
def db():
    conn = create_sqlite(POLICY)
    yield conn
    conn.close()


def rewrite(sql, tenant=1, role="support_analyst", dialect="sqlite"):
    return apply_tenant_filters(
        GUARD, sql, role=role, context={"tenant_id": tenant}, dialect=dialect
    )


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT o.id, o.tenant_id FROM orders o",
        "SELECT o.id, o.tenant_id FROM orders o WHERE o.status = 'paid' OR 1 = 1",
        "SELECT o.id, o.tenant_id FROM orders o WHERE o.customer_id IN (SELECT c.id FROM customers c)",
        "SELECT o.id, o.tenant_id FROM orders o JOIN shipments s ON s.order_id = o.id",
        "SELECT o.id, o.tenant_id FROM orders o LEFT JOIN shipments s ON s.order_id = o.id",
        "WITH x AS (SELECT o.id, o.tenant_id FROM orders o) SELECT x.id, x.tenant_id FROM x",
        "SELECT o.id, o.tenant_id FROM orders o UNION ALL SELECT s.id, s.tenant_id FROM shipments s",
    ],
)
@pytest.mark.parametrize("tenant", [1, 2, 3])
def test_rewritten_queries_only_return_own_tenant(db, sql, tenant):
    r = rewrite(sql, tenant=tenant)
    assert r.rewritten and r.result is not None and r.result.allowed
    assert not re.search(r"tenant_id\s*=\s*\d", r.sql)  # value is bound, never inlined
    rows = db.execute(r.sql, {"tenant_id": tenant}).fetchall()
    assert rows and {row[1] for row in rows} == {tenant}


def test_already_pinned_query_is_unchanged():
    sql = "SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id"
    r = rewrite(sql)
    assert not r.rewritten and r.sql == sql


def test_postgres_uses_named_bind_style():
    r = rewrite("SELECT o.id FROM orders o", dialect="postgres")
    assert "%(tenant_id)s" in r.sql


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        ("SELECT o.id FROM orders o WHERE o.tenant_id = 2", "other than a missing tenant filter"),
        ("SELECT p.card_number FROM payments p", "other than a missing tenant filter"),
        ("DELETE FROM orders", "other than a missing tenant filter"),
        ("SELECT o.id FROM orders o FULL JOIN shipments s ON s.order_id = o.id", "RIGHT/FULL"),
        ("SELECT o.id FROM shipments s RIGHT JOIN orders o ON s.order_id = o.id", "RIGHT/FULL"),
        ("SELECT o.id, i.id FROM orders o CROSS JOIN order_items i", "did not pass validation"),
    ],
)
def test_refuses_when_safe_enforcement_is_not_established(sql, reason):
    with pytest.raises(TenantRewriteRefused, match=reason):
        rewrite(sql, dialect="postgres")


def test_refuses_without_context_or_parameter():
    with pytest.raises(TenantRewriteRefused, match="no trusted tenant context"):
        apply_tenant_filters(GUARD, "SELECT o.id FROM orders o", role="support_analyst", context={})
    with pytest.raises(TenantRewriteRefused, match="bind parameter"):
        apply_tenant_filters(
            GUARD,
            "SELECT o.id FROM orders o",
            role="support_analyst",
            context={"tenant_id": 1},
            parameter="other",
        )


def test_checkpoint_opt_in_rewrites_audits_and_executes(db):
    sink = InMemoryAuditSink()
    cp = SQLCheckpoint(GUARD, dialect="sqlite", audit_sink=sink, rewrite_tenant_filters=True)
    ctx = RequestContext(principal="agent", role="support_analyst", tenant_id=2, trace_id="t")
    rows = cp.execute("SELECT o.id, o.tenant_id FROM orders o", ctx, sqlite_executor(db))
    assert rows and {r["tenant_id"] for r in rows} == {2}
    assert sink.events[-1].tenant_filter_rewrite and sink.events[-1].authorized
    # Problems a rewrite cannot fix are still blocked, and the original query is audited.
    with pytest.raises(SQLBlockedError):
        cp.execute("SELECT o.id FROM orders o WHERE o.tenant_id = 1", ctx, sqlite_executor(db))
    assert not sink.events[-1].tenant_filter_rewrite


def test_checkpoint_default_does_not_rewrite(db):
    cp = SQLCheckpoint(GUARD, dialect="sqlite")
    ctx = RequestContext(principal="agent", role="support_analyst", tenant_id=1)
    with pytest.raises(SQLBlockedError):
        cp.execute("SELECT o.id FROM orders o", ctx, sqlite_executor(db))
