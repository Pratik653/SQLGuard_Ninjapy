"""Regression tests for parameter-marker divergences between the parser and the database.

Found during the v0.8.0 audit (SQLI-001, SQLI-002, SQLI-003; docs/security/SQL_INJECTION_THREAT_MODEL.md):
sqlglot parses ``@name`` and ``$name`` as bind parameters, and the tenant rule accepted them
as the trusted tenant parameter. PostgreSQL reads ``@x`` as ``abs(x)``, so
``o.tenant_id = @tenant_id`` matched every tenant and ``@salary`` hid a classified column
from the privacy rules. MySQL reads ``@x`` / ``@@x`` as session and system variables.
"""

from __future__ import annotations

import pytest

from sqlguard_ninja import Guard
from sqlguard_ninja.integrations import RequestContext, SQLCheckpoint

DIALECTS = ("postgres", "mysql", "sqlite")
MARKERS = ("@tenant_id", "$tenant_id", "@@tenant_id")


@pytest.mark.parametrize("dialect", DIALECTS)
@pytest.mark.parametrize("marker", MARKERS)
def test_non_standard_marker_never_pins_the_tenant(policy, dialect, marker):
    sql = f"SELECT o.id FROM orders o WHERE o.tenant_id = {marker}"
    r = Guard(policy).validate(
        sql, role="support_analyst", dialect=dialect, context={"tenant_id": 1}
    )
    assert r.denied, (dialect, marker)


@pytest.mark.parametrize("dialect", DIALECTS)
@pytest.mark.parametrize("expr", ["@salary", "$salary", "@@salary", "@@datadir", "@@hostname"])
def test_marker_cannot_hide_a_column_or_read_server_variables(policy, dialect, expr):
    sql = f"SELECT e.full_name, {expr} AS s FROM employees e LIMIT 2"
    assert Guard(policy).validate(sql, role="hr_analyst", dialect=dialect).denied, (dialect, expr)


@pytest.mark.parametrize("dialect", DIALECTS)
def test_named_placeholder_still_pins_the_tenant(policy, dialect):
    sql = "SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id"
    r = Guard(policy).validate(
        sql, role="support_analyst", dialect=dialect, context={"tenant_id": 1}
    )
    assert r.allowed


@pytest.mark.postgres
def test_postgres_absolute_value_operator_cannot_cross_tenants(pg, policy):
    """End to end on PostgreSQL: the query that leaked every tenant's rows is now refused."""
    from sqlguard_ninja.integrations import SQLBlockedError
    from sqlguard_ninja.integrations.executors import psycopg_executor

    cp = SQLCheckpoint(Guard(policy), dialect="postgres")
    ctx = RequestContext(principal="t", role="support_analyst", tenant_id=1)
    with pytest.raises(SQLBlockedError):
        cp.execute(
            "SELECT o.tenant_id, COUNT(*) AS n FROM orders o WHERE o.tenant_id = @tenant_id "
            "GROUP BY o.tenant_id",
            ctx,
            psycopg_executor(pg.reader_dsn),
        )
