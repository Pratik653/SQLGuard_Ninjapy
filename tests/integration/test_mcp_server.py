"""MCP server: service behaviour plus an end-to-end session with the official SDK client."""

from __future__ import annotations

import json
import sys

import pytest

from sqlguard_ninja import Policy
from sqlguard_ninja.mcp_server import (
    HARD_MAX_SQL_CHARS,
    RateLimiter,
    ServerIdentity,
    SQLGuardService,
)
from tests.conftest import POLICY_PATH, ROOT

POLICY = Policy.from_file(POLICY_PATH)
SAFE = "SELECT o.id, o.status FROM orders o WHERE o.tenant_id = :tenant_id"
CARD = "SELECT p.card_number FROM payments p WHERE p.tenant_id = :tenant_id"


def service(role="support_analyst", tenant="1", **kw):
    return SQLGuardService(POLICY, ServerIdentity(role=role, tenant=tenant), **kw)


def test_validate_and_explain():
    s = service()
    ok = s.validate_sql(SAFE)
    assert ok["decision"] == "allow" and ok["allowed"] and ok["decision_id"]
    bad = s.validate_sql(CARD)
    assert bad["decision"] == "deny"
    assert all("detail" not in f for f in bad["findings"])  # internal detail never exposed
    explained = s.explain_policy_decision(CARD)
    assert any(
        f.get("lineage", {}).get("base_column") == "payments.card_number"
        for f in explained["findings"]
    )
    assert explained["how_to_fix"]


def test_identity_is_fixed_server_side():
    s = service(tenant="2")
    assert s.validate_sql("SELECT o.id FROM orders o WHERE o.tenant_id = 1")["decision"] == "deny"
    assert s.validate_sql("SELECT o.id FROM orders o WHERE o.tenant_id = 2")["decision"] == "allow"
    with pytest.raises(ValueError, match="not defined"):
        service(role="ghost")


def test_missing_tenant_fails_closed():
    s = service(tenant=None)
    assert s.validate_sql(SAFE)["decision"] == "deny"


@pytest.mark.parametrize(
    ("sql", "dialect", "error"),
    [
        (123, None, "invalid_input"),
        ("x" * (HARD_MAX_SQL_CHARS + 1), None, "invalid_input"),
        (SAFE, "oracle", "unsupported_dialect"),
    ],
    ids=["non-string", "too-large", "unsupported-dialect"],  # keep ids short (env var limit)
)
def test_malformed_inputs(sql, dialect, error):
    assert service().validate_sql(sql, dialect)["error"] == error


def test_rate_limit():
    s = service(rate_limiter=RateLimiter(limit=2, window_s=60))
    assert "decision" in s.validate_sql(SAFE)
    assert "decision" in s.validate_sql(SAFE)
    assert s.validate_sql(SAFE)["error"] == "rate_limited"
    assert s.get_policy_capabilities()["error"] == "rate_limited"


def test_cost_and_capabilities():
    s = service(role="platform_admin")
    cost = s.inspect_query_cost("SELECT o.id, i.id FROM orders o CROSS JOIN order_items i")
    assert cost["static_score"] >= 80 and cost["factors"]
    assert s.inspect_query_cost("SELEC")["error"] == "unanalysable"
    caps = service().get_policy_capabilities()
    assert "employees" not in caps["tables"]  # ungranted tables are not revealed
    assert "card_number" not in caps["tables"]["payments"]["columns"]
    assert caps["tables"]["orders"]["tenant_filter_required"] == "tenant_id"
    hr = service(role="hr_analyst", tenant=None).get_policy_capabilities()
    assert hr["tables"]["employees"]["columns"]["salary"] == "aggregate_only"
    assert "national_id" not in hr["tables"]["employees"]["columns"]


def test_end_to_end_stdio_session():
    """Launch the real server as a subprocess and talk to it with the official MCP client."""
    pytest.importorskip("mcp")
    import anyio
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "sqlguard_ninja.mcp_server",
            "--policy",
            str(POLICY_PATH),
            "--role",
            "support_analyst",
            "--tenant",
            "1",
        ],
        cwd=str(ROOT),
    )

    async def session() -> dict:
        async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
            await client.initialize()
            tools = sorted(t.name for t in (await client.list_tools()).tools)
            ok = await client.call_tool("validate_sql", {"sql": SAFE})
            bad = await client.call_tool("validate_sql", {"sql": CARD})
            forged = await client.call_tool("validate_sql", {"sql": CARD, "role": "platform_admin"})
            caps = await client.call_tool("get_policy_capabilities", {})
            return {"tools": tools, "ok": ok, "bad": bad, "forged": forged, "caps": caps}

    out = anyio.run(session)

    def payload(result):
        if getattr(result, "structured_content", None):
            data = result.structured_content
            return data.get("result", data)
        return json.loads(result.content[0].text)

    assert out["tools"] == [
        "explain_policy_decision",
        "get_policy_capabilities",
        "inspect_query_cost",
        "validate_sql",
    ]
    assert payload(out["ok"])["decision"] == "allow"
    assert payload(out["bad"])["decision"] == "deny"
    # An extra 'role' argument must not grant anything: either rejected or ignored.
    forged = out["forged"]
    assert getattr(forged, "is_error", False) or payload(forged)["decision"] == "deny"
    assert "employees" not in payload(out["caps"])["tables"]
