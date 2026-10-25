# ruff: noqa: RUF001, PLE2502 - adversarial Unicode and control characters are the point
"""The execute_safe binding contract, independent of any database.

Classes of input (docs/security/SQL_INJECTION_THREAT_MODEL.md):
unsafe construction that must be refused, values that must stay data, benign templates that
must keep working.
"""

from __future__ import annotations

import datetime as dt
import math
from decimal import Decimal

import pytest

from sqlguard_ninja.integrations.binding import (
    SQLBindingError,
    bind_statement,
    find_placeholders,
    safe_identifier,
    safe_order_by,
)

T = {"tenant_id": 1}
BASE = "SELECT c.id FROM customers c WHERE c.tenant_id = :tenant_id AND c.email = :email"


def bind(sql=BASE, params=None, trusted=T, dialect="postgres", style="pyformat"):
    return bind_statement(
        sql, dialect, {"email": "x"} if params is None else params, trusted, style
    )


# --------------------------------------------------------------------------- refused markers
@pytest.mark.parametrize("dialect", ["postgres", "mysql", "sqlite"])
@pytest.mark.parametrize(
    "marker",
    ["?", "%s", "%(email)s", "$1", "$email", "@email", "@@email", ":1"],
)
def test_other_parameter_markers_are_refused(dialect, marker):
    sql = f"SELECT c.id FROM customers c WHERE c.tenant_id = :tenant_id AND c.email = {marker}"
    with pytest.raises(SQLBindingError):
        bind_statement(sql, dialect, {"email": "x"}, T, "pyformat")


@pytest.mark.parametrize("sql", ["SELECT : email", "SELECT :", "SELECT :1email", 'SELECT :"email"'])
def test_malformed_colon_usage_is_refused(sql):
    with pytest.raises(SQLBindingError):
        bind_statement(sql, "sqlite", {"email": "x"}, {}, "named")


def test_multiple_statements_are_refused():
    with pytest.raises(SQLBindingError, match="exactly one"):
        bind(BASE + "; SELECT 1")


# --------------------------------------------------------------------------- literals/comments
@pytest.mark.parametrize(
    ("dialect", "sql"),
    [
        ("postgres", "SELECT ':email' AS a, :email AS v"),
        ("postgres", "SELECT $$:email$$ AS a, :email AS v"),
        ("postgres", "SELECT E'it\\'s :email' AS a, :email AS v"),
        ("postgres", 'SELECT 1 AS ":email", :email AS v'),
        ("postgres", "SELECT :email AS v -- :tenant_id\n"),
        ("postgres", "SELECT /* :tenant_id */ :email AS v"),
        ("mysql", "SELECT ':email' AS a, `:email` AS b, :email AS v"),
        ("mysql", "SELECT 'it\\'s :email' AS a, :email AS v"),
        ("sqlite", "SELECT ':email' AS a, :email AS v /* :other */"),
    ],
)
def test_placeholders_inside_literals_and_comments_are_text(dialect, sql):
    spans = find_placeholders(sql, dialect)
    assert [s.name for s in spans] == ["email"]
    stmt = bind_statement(sql, dialect, {"email": "v"}, {}, "named")
    assert stmt.placeholders == ("email",)


def test_pyformat_translation_doubles_percent_and_is_reversible():
    sql = "SELECT c.id FROM customers c WHERE c.tenant_id = :tenant_id AND c.email LIKE '100%' AND c.city = :email -- 5% off"
    stmt = bind(sql)
    assert stmt.sql == (
        "SELECT c.id FROM customers c WHERE c.tenant_id = %(tenant_id)s AND c.email LIKE '100%%' "
        "AND c.city = %(email)s -- 5%% off"
    )
    assert stmt.sql % {"tenant_id": ":tenant_id", "email": ":email"} == sql
    assert stmt.validated_sql == sql


def test_named_style_executes_the_validated_text_unchanged():
    stmt = bind(style="named", dialect="sqlite")
    assert stmt.sql == BASE and stmt.params == {"email": "x", "tenant_id": 1}


def test_repeated_placeholder_binds_one_value():
    stmt = bind(BASE + " OR c.city = :email")
    assert stmt.params == {"email": "x", "tenant_id": 1}
    assert stmt.sql.count("%(email)s") == 2


# --------------------------------------------------------------------------- names
@pytest.mark.parametrize("key", ["tenant_id", "TENANT_ID", "Tenant_Id"])
def test_trusted_names_cannot_be_supplied_in_any_case(key):
    with pytest.raises(SQLBindingError, match="reserved"):
        bind(params={"email": "x", key: 2})


def test_trusted_context_attributes_are_all_reserved():
    with pytest.raises(SQLBindingError, match="reserved"):
        bind(params={"email": "x", "region": "eu"}, trusted={"tenant_id": 1, "region": "us"})


def test_missing_extra_and_case_colliding_names():
    with pytest.raises(SQLBindingError, match="no value"):
        bind(params={})
    with pytest.raises(SQLBindingError, match="unknown placeholder"):
        bind(params={"email": "x", "other": 1})
    with pytest.raises(SQLBindingError, match="differ only in case"):
        bind(params={"email": "x", "EMAIL": "y"})
    with pytest.raises(SQLBindingError, match="differ only in case"):
        bind("SELECT :email AS a, :EMAIL AS b", params={"email": "x"}, trusted={})
    with pytest.raises(SQLBindingError, match="invalid parameter name"):
        bind(params={"email": "x", "a b": 1})


def test_tenant_placeholder_comes_from_trusted_context_only():
    stmt = bind()
    assert stmt.params["tenant_id"] == 1
    with pytest.raises(SQLBindingError, match="no value"):
        bind(trusted={})


# --------------------------------------------------------------------------- values
@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        0,
        -(2**63),
        2**63 - 1,
        1.5,
        Decimal("1.10"),
        "",
        "ʼ＇‮😀",
        b"\x00\xff",
        bytearray(b"ab"),
        dt.date(2026, 1, 2),
        dt.datetime(2026, 1, 2, 3, 4),
        dt.time(5, 6),
    ],
)
def test_supported_values(value):
    out = bind(params={"email": value}).params["email"]
    assert out == (bytes(value) if isinstance(value, bytearray) else value)


@pytest.mark.parametrize(
    "value",
    [
        "a\x00b",
        "\ud800",
        2**63,
        -(2**63) - 1,
        math.nan,
        math.inf,
        Decimal("NaN"),
        Decimal("Infinity"),
        [1],
        {"a": 1},
        (1,),
        {1},
        object(),
        1j,
    ],
    ids=lambda v: type(v).__name__,
)
def test_unsupported_values_fail_closed(value):
    with pytest.raises(SQLBindingError):
        bind(params={"email": value})


def test_statement_repr_never_shows_values():
    assert "secret-value" not in repr(bind(params={"email": "secret-value"}))


# --------------------------------------------------------------------------- identifiers
ALLOWED = {"created_at", "total_amount"}


@pytest.mark.parametrize(
    ("dialect", "expected"),
    [("postgres", '"created_at"'), ("sqlite", '"created_at"'), ("mysql", "`created_at`")],
)
def test_safe_identifier_quotes_only_allowlisted_names(dialect, expected):
    assert safe_identifier("created_at", ALLOWED, dialect) == expected


@pytest.mark.parametrize(
    "value",
    [
        "id",
        "created_at; DROP TABLE orders",
        'created_at"',
        "created_at--",
        "CREATED_AT",
        "",
        "1abc",
    ],
)
def test_safe_identifier_refuses_everything_else(value):
    with pytest.raises(SQLBindingError):
        safe_identifier(value, ALLOWED | {"1abc"}, "postgres")


@pytest.mark.parametrize("direction", ["", "ASC; DROP TABLE x", "DESC NULLS", "random()", None])
def test_order_direction_is_asc_or_desc_only(direction):
    with pytest.raises(SQLBindingError):
        safe_order_by("created_at", direction, ALLOWED, "postgres")
    assert safe_order_by("created_at", "desc", ALLOWED, "postgres") == '"created_at" DESC'
