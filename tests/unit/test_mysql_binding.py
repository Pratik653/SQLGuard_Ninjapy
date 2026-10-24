"""MySQL placeholder binding (no server needed) and MySQL-dialect policy mechanics."""

from __future__ import annotations

import pytest

from sqlguard_ninja import Guard, Policy
from sqlguard_ninja.integrations.mysql import (
    BindError,
    UnsafeSessionError,
    bind_placeholders,
    check_sql_mode,
)


def test_binds_only_placeholder_nodes():
    sql = (
        "SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id "
        "AND o.status LIKE 'p%' AND o.status <> ':tenant_id'"
    )
    out = bind_placeholders(sql, {"tenant_id": 7})
    assert "o.tenant_id = 7" in out
    assert "'p%'" in out and "':tenant_id'" in out  # literals untouched


def test_string_values_are_escaped():
    value = "a'b' OR 1=1 -- "
    out = bind_placeholders("SELECT 1 FROM t WHERE x = :tenant_id", {"tenant_id": value})
    assert "'a''b'' OR 1=1 -- '" in out


@pytest.mark.parametrize(
    ("sql", "params", "message"),
    [
        ("SELECT 1 FROM t WHERE x = :other", {"tenant_id": 1}, "no trusted value"),
        ("SELECT 1 FROM t WHERE x = ?", {"tenant_id": 1}, "no trusted value"),
        ("SELECT 1; SELECT 2", {}, "exactly one statement"),
        ("SELECT 1 FROM t WHERE x = :tenant_id", {"tenant_id": 1.5}, "unsupported value"),
        ("SELECT 1 FROM t WHERE x = :tenant_id", {"tenant_id": None}, "unsupported value"),
        ("SELECT 1 FROM t WHERE x = :tenant_id", {"tenant_id": True}, "unsupported value"),
        ("SELECT 1 FROM t WHERE x = :tenant_id", {"tenant_id": "a\\"}, "backslash"),
        ("SELECT 1 FROM t WHERE x = :tenant_id", {"tenant_id": "a\x00"}, "NUL"),
    ],
    ids=["unknown-name", "anonymous", "multi", "float", "none", "bool", "backslash", "nul"],
)
def test_refuses_unsafe_binding(sql, params, message):
    with pytest.raises(BindError, match=message):
        bind_placeholders(sql, params)


def test_mysql_function_policy_mechanics():
    """Function rules apply under the MySQL dialect too (fictitious, policy-configured names)."""
    p = Policy.from_dict(
        {
            "name": "m",
            "dialect": "mysql",
            "catalog": {"tables": {"t": {"columns": {"id": "int"}}}},
            "functions": {"deny": ["acme_export"], "review": ["acme_lookup"]},
        }
    )
    g = Guard(p)
    assert g.validate("SELECT acme_export(t.id) FROM t").denied
    assert g.validate("SELECT acme_lookup(t.id) FROM t").requires_review
    assert g.validate("SELECT UPPER(CAST(t.id AS CHAR)) FROM t").allowed


def test_mysql_malformed_sql_fails_closed():
    p = Policy.from_dict(
        {"name": "m", "dialect": "mysql", "catalog": {"tables": {"t": {"columns": {"id": "int"}}}}}
    )
    g = Guard(p)
    for sql in ["SELEC id FROM t", "SELECT id FROM t WHERE", "SELECT `id FROM t"]:
        assert g.validate(sql).denied


@pytest.mark.parametrize(
    "mode",
    [
        "ANSI_QUOTES",
        "STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES",
        "pipes_as_concat",
        "ANSI",
        "HIGH_NOT_PRECEDENCE",
    ],
)
def test_unsafe_sql_modes_are_refused(mode):
    with pytest.raises(UnsafeSessionError):
        check_sql_mode(mode)


@pytest.mark.parametrize(
    "mode", ["", "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION"]
)
def test_default_sql_modes_are_accepted(mode):
    check_sql_mode(mode)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT o.id FROM orders o WHERE o.tenant_id = 1 INTO OUTFILE '/tmp/x'",
        "SELECT o.id FROM orders o WHERE o.tenant_id = %s",
        "SELECT o.id FROM orders o WHERE o.tenant_id = %(tenant_id)s",
        "SELECT o.id FROM orders o WHERE o.tenant_id = 1 FOR UPDATE",
        "SELECT o.id FROM orders o WHERE o.tenant_id = 1 AND",
    ],
    ids=["outfile", "pyformat", "pyformat-named", "for-update", "truncated"],
)
def test_mysql_edge_sql_is_denied(policy, sql):
    r = Guard(policy).validate(
        sql, role="support_analyst", context={"tenant_id": 1}, dialect="mysql"
    )
    assert r.denied
