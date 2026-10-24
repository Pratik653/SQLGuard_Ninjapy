"""Parser-level smoke tests for experimental dialects (SQL Server, Oracle).

These check only that the engine's core guarantees hold through sqlglot's parsers. They are
not evidence of supported status; see docs/guides/DATABASE_COMPATIBILITY.md.
"""

from __future__ import annotations

import pytest

from sqlguard_ninja.core.analysis import SUPPORTED_DIALECTS

CTX = {"tenant_id": 1}


@pytest.mark.parametrize("dialect", ["tsql", "oracle"])
@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("SELECT o.id FROM orders o WHERE o.tenant_id = 1", "allow"),
        ("SELECT o.id FROM orders o", "deny"),
        ("SELECT o.id FROM orders o WHERE o.tenant_id = 2", "deny"),
        ("DELETE FROM orders", "deny"),
        ("SELECT o.id FROM orders o WHERE o.tenant_id = 1; DROP TABLE orders", "deny"),
        ("SELECT p.card_number FROM payments p WHERE p.tenant_id = 1", "deny"),
    ],
    ids=["pinned", "missing-tenant", "other-tenant", "write", "stacked", "sensitive"],
)
def test_core_guarantees_hold(guard, dialect, sql, expected):
    if dialect == "oracle" and expected == "allow":
        # Oracle folds unquoted identifiers to UPPER case, so lower-case policy names do not
        # match and every query fails closed. Recorded as an experimental-dialect gap.
        expected = "deny"
    r = guard.validate(sql, role="support_analyst", dialect=dialect, context=CTX)
    assert r.decision.value == expected


def test_experimental_dialects_are_not_advertised():
    assert "tsql" not in SUPPORTED_DIALECTS and "oracle" not in SUPPORTED_DIALECTS
