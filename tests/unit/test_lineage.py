"""Fail-closed branches of core/lineage.py."""

from __future__ import annotations

import pytest
from sqlglot import exp

from sqlguard_ninja.core import lineage
from sqlguard_ninja.core.analysis import analyse


@pytest.fixture
def run(guard):
    def _run(sql, role="hr_analyst", **ctx):
        r = guard.validate(sql, role=role, dialect="postgres", context={"tenant_id": 1, **ctx})
        return r.decision.value, {f.rule_id for f in r.findings}

    return _run


@pytest.mark.parametrize(
    "sql",
    [
        # whole-row use of the CTE exposes the raw value
        "WITH s AS (SELECT e.salary FROM employees e) SELECT s FROM s",
        # the CTE body is a set operation: no plain projection to follow
        "WITH s AS (SELECT e.salary FROM employees e UNION SELECT e.salary FROM employees e) "
        "SELECT AVG(s.salary) FROM s",
        # scalar subquery: the raw value flows into the outer expression
        "SELECT (SELECT e.salary FROM employees e LIMIT 1) AS x",
        # window inside the projection
        "WITH s AS (SELECT SUM(e.salary) OVER () AS t FROM employees e) SELECT AVG(s.t) FROM s",
    ],
)
def test_aggregate_only_fails_closed(run, sql):
    decision, rules = run(sql)
    assert decision == "deny" and "privacy.aggregate_only" in rules


@pytest.mark.parametrize(
    "sql",
    [
        "WITH x AS (SELECT o.id, o.tenant_id, ROW_NUMBER() OVER () AS r FROM orders o) "
        "SELECT x.id FROM x WHERE x.tenant_id = 1",
        "WITH x AS (SELECT o.id, o.tenant_id FROM orders o OFFSET 5) "
        "SELECT x.id FROM x WHERE x.tenant_id = 1",
        "WITH x AS (SELECT o.id, o.tenant_id FROM orders o FETCH FIRST 5 ROWS ONLY) "
        "SELECT x.id FROM x WHERE x.tenant_id = 1",
        "WITH x AS (SELECT o.id FROM orders o) SELECT x.id FROM x",
    ],
)
def test_tenant_pushdown_fails_closed(run, sql):
    decision, rules = run(sql, role="support_analyst")
    assert decision == "deny" and "tenant.missing_predicate" in rules


def test_pushdown_through_join_consumer(run):
    sql = (
        "WITH x AS (SELECT o.id, o.tenant_id FROM orders o) "
        "SELECT x.id, s.status FROM x JOIN shipments s ON s.order_id = x.id AND s.tenant_id = 1 "
        "WHERE x.tenant_id = 1"
    )
    assert run(sql, role="support_analyst")[0] == "allow"


def test_depth_limit_returns_false(policy):
    a = analyse(
        "WITH s AS (SELECT e.salary FROM employees e) SELECT AVG(s.salary) FROM s",
        "postgres",
        policy.catalog,
        max_nodes=5000,
    )
    inner = a.scopes[0]
    node = next(c.node for c in a.columns if c.column == "salary")
    assert lineage.aggregated_downstream(a, inner, node) is True
    assert lineage.aggregated_downstream(a, inner, node, depth=lineage.MAX_DEPTH + 1) is False
    assert lineage.consumers_pin(a, inner, "e", "id", lambda *_: True, depth=99) is False


def test_resolve_base_unknown_alias(policy):
    a = analyse("SELECT e.id FROM employees e", "postgres", policy.catalog, max_nodes=5000)
    root = a.scopes[-1]
    assert lineage.resolve_base(a, root, exp.column("id", table="nope")) is None
    assert lineage.projection_output(exp.select("1"), exp.column("x")) is None
