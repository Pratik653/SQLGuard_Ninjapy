"""Role inheritance (explicit-deny precedence), policy metadata and decision ids."""

from __future__ import annotations

import pytest

from sqlguard_ninja import Guard, Policy, PolicyError
from sqlguard_ninja.integrations import InMemoryAuditSink, RequestContext, SQLCheckpoint

BASE = {
    "name": "inh",
    "metadata": {"revision": "2026.10.1", "owner": "data-governance"},
    "labels": {"contact": {}, "financial": {}},
    "catalog": {
        "tables": {
            "orders": {
                "tenant_column": "tenant_id",
                "columns": {
                    "id": "int",
                    "tenant_id": "int",
                    "status": "text",
                    "total": {"labels": ["financial"]},
                },
            },
            "customers": {
                "tenant_column": "tenant_id",
                "columns": {"id": "int", "tenant_id": "int", "email": {"labels": ["contact"]}},
            },
        }
    },
}


def policy(roles: dict) -> Policy:
    return Policy.from_dict({**BASE, "roles": roles})


def test_child_inherits_and_extends_grants():
    p = policy(
        {
            "base": {
                "tables": {"orders": ["id", "tenant_id", "status"]},
                "labels": {"financial": "deny"},
            },
            "support": {
                "extends": ["base"],
                "tables": {"customers": "*"},
                "labels": {"contact": "allow"},
            },
        }
    )
    role = p.effective_role("support")
    assert set(role.tables) == {"orders", "customers"}
    assert role.labels == {"financial": "deny", "contact": "allow"}
    g = Guard(p)
    ctx = {"tenant_id": 1}
    assert g.validate(
        "SELECT o.status FROM orders o WHERE o.tenant_id = 1", role="support", context=ctx
    ).allowed
    assert g.validate(
        "SELECT c.email FROM customers c WHERE c.tenant_id = 1", role="support", context=ctx
    ).allowed
    assert g.validate(
        "SELECT o.total FROM orders o WHERE o.tenant_id = 1", role="support", context=ctx
    ).denied


def test_column_grants_union_and_star_wins():
    p = policy(
        {
            "a": {"tables": {"orders": ["id", "tenant_id"]}},
            "b": {"extends": ["a"], "tables": {"orders": ["status"]}},
            "c": {"extends": ["a"], "tables": {"orders": "*"}},
        }
    )
    assert set(p.effective_role("b").tables["orders"].columns) == {"id", "tenant_id", "status"}
    assert p.effective_role("c").tables["orders"].columns == "*"


@pytest.mark.parametrize(
    ("child", "message"),
    [
        ({"labels": {"financial": "allow"}}, "label 'financial' is denied by a parent"),
        ({"tenant_scoped": False}, "cannot drop tenant scoping"),
        (
            {"tables": {"orders": {"columns": "*", "column_access": {"total": "allow"}}}},
            "column 'total' is denied by a parent",
        ),
        (
            {"tables": {"orders": {"columns": "*", "column_access": {"status": "allow"}}}},
            "column 'status' is in a parent role's deny_columns",
        ),
    ],
)
def test_child_cannot_relax_explicit_deny(child, message):
    parent = {
        "tables": {
            "orders": {
                "columns": "*",
                "deny_columns": ["status"],
                "column_access": {"total": "deny"},
            }
        },
        "labels": {"financial": "deny"},
    }
    with pytest.raises(PolicyError, match=message):
        policy({"parent": parent, "child": {"extends": ["parent"], **child}})


def test_unknown_parent_and_cycle_rejected():
    with pytest.raises(PolicyError, match="extends unknown role 'ghost'"):
        policy({"r": {"extends": ["ghost"]}})
    with pytest.raises(PolicyError, match="cycle"):
        policy({"a": {"extends": ["b"]}, "b": {"extends": ["a"]}})


def test_multiple_parents_merge_in_order():
    p = policy(
        {
            "orders_reader": {"tables": {"orders": ["id", "tenant_id"]}},
            "customer_reader": {"tables": {"customers": ["id", "tenant_id"]}},
            "both": {"extends": ["orders_reader", "customer_reader"]},
        }
    )
    assert set(p.effective_role("both").tables) == {"orders", "customers"}


def test_inherited_grants_are_validated_against_catalog():
    with pytest.raises(PolicyError, match=r"unknown column 'orders.nope'"):
        policy({"a": {"tables": {"orders": ["nope"]}}, "b": {"extends": ["a"]}})


def test_metadata_fingerprint_and_decision_ids():
    p = policy({"r": {"tables": {"orders": "*"}, "labels": {"financial": "allow"}}})
    assert p.revision == "2026.10.1" and len(p.fingerprint) == 16
    same = policy({"r": {"tables": {"orders": "*"}, "labels": {"financial": "allow"}}})
    changed = policy({"r": {"tables": {"orders": "*"}, "labels": {"financial": "review"}}})
    assert p.fingerprint == same.fingerprint != changed.fingerprint
    g = Guard(p)
    a = g.validate(
        "SELECT o.id FROM orders o WHERE o.tenant_id = 1", role="r", context={"tenant_id": 1}
    )
    b = g.validate(
        "SELECT o.id FROM orders o WHERE o.tenant_id = 1", role="r", context={"tenant_id": 1}
    )
    assert a.decision_id and a.decision_id != b.decision_id
    assert a.policy_revision == "2026.10.1" and a.policy_fingerprint == p.fingerprint


def test_audit_event_carries_policy_and_query_fingerprint():
    p = policy({"r": {"tables": {"orders": "*"}, "labels": {"financial": "allow"}}})
    sink = InMemoryAuditSink()
    cp = SQLCheckpoint(Guard(p), audit_sink=sink)
    ctx = RequestContext(principal="u", role="r", tenant_id=1, trace_id="corr-1")
    o1 = cp.evaluate("SELECT o.id FROM orders o WHERE o.tenant_id = 1 AND o.status = 'a'", ctx)
    cp.evaluate("SELECT o.id FROM orders o WHERE o.tenant_id = 1 AND o.status = 'b'", ctx)
    e1, e2 = sink.events
    assert e1.decision_id == o1.result.decision_id and e1.correlation_id == "corr-1"
    assert e1.policy_revision == "2026.10.1" and e1.policy_fingerprint == p.fingerprint
    assert e1.query_fingerprint == e2.query_fingerprint  # literal-insensitive
    assert e1.sql_sha256 != e2.sql_sha256
    assert "'a'" not in e1.model_dump_json()
