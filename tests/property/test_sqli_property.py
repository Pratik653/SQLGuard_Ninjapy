"""Property-based checks of the binding contract (Hypothesis)."""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sqlguard_ninja import Guard
from sqlguard_ninja.benchmarking.fixtures import create_sqlite
from sqlguard_ninja.integrations import RequestContext, SQLCheckpoint, SQLiteSafeExecutor
from sqlguard_ninja.integrations.binding import SQLBindingError, bind_statement

TEXT = st.text(
    st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), max_size=200
)
ECHO = "SELECT c.id, :v AS v FROM customers c WHERE c.tenant_id = :tenant_id ORDER BY c.id LIMIT 1"


@pytest.fixture(scope="module")
def setup(policy):
    return (
        SQLCheckpoint(Guard(policy), dialect="sqlite"),
        SQLiteSafeExecutor(create_sqlite(policy)),
        RequestContext(principal="p", role="support_analyst", tenant_id=1),
    )


@settings(
    max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(value=TEXT)
def test_any_text_value_round_trips_on_sqlite(setup, value):
    cp, run, ctx = setup
    assert cp.execute_safe(ECHO, ctx, run, {"v": value})[0]["v"] == value


@settings(max_examples=400, deadline=None)
@given(literal=TEXT, dialect=st.sampled_from(["postgres", "mysql", "sqlite"]))
def test_literal_contents_never_become_placeholders(literal, dialect):
    quoted = "'" + literal.replace("'", "''") + "'"
    sql = f"SELECT {quoted} AS a, :v AS b"
    try:
        stmt = bind_statement(sql, dialect, {"v": 1}, {}, "pyformat")
    except SQLBindingError:
        return  # refusing is always acceptable (e.g. MySQL backslash escapes in the literal)
    assert stmt.placeholders == ("v",)
    assert stmt.sql % {"v": ":v"} == sql
