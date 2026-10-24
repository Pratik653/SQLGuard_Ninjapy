"""Demo service, sandbox, server hardening and deployment manifests."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from sqlguard_ninja.demo.examples import EXAMPLES, ROLE_LABELS
from sqlguard_ninja.demo.sandbox import Sandbox, SandboxError
from sqlguard_ninja.demo.service import DemoService, check_examples, demo_policy

ROOT = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def service() -> DemoService:
    return DemoService()


# --------------------------------------------------------------------------- service
def test_every_example_has_its_expected_decision(service):
    assert check_examples(service) == []
    assert {e.role for e in EXAMPLES} == set(ROLE_LABELS)
    for role in ROLE_LABELS:
        expects = {e.expect for e in EXAMPLES if e.role == role}
        assert {"allow", "deny"} <= expects, role


def test_allowed_examples_execute(service):
    for e in EXAMPLES:
        if e.expect == "allow":
            ex = service.run(e.sql, e.role, 1)["execution"]
            assert ex["status"] == "ok" and ex["rows"], e.id


def test_denied_queries_never_execute(service):
    for e in EXAMPLES:
        if e.expect != "allow":
            assert service.run(e.sql, e.role, 1)["execution"]["status"] == "not_run", e.id


def test_tenant_results_are_isolated(service):
    out = service.tenant_isolation("sales_analyst")
    rows = [r["execution"]["rows"] for r in out["runs"]]
    assert len(rows) == 3 and rows[0] != rows[1] != rows[2]
    assert out["cross_tenant"]["decision"] == "deny"
    assert out["cross_tenant"]["findings"][0]["rule_id"] == "tenant.wrong_value"


def test_lineage_through_cte(service):
    sql = (
        "WITH r AS (SELECT o.customer_id, o.total_amount FROM orders o WHERE o.tenant_id = :tenant_id) "
        "SELECT r.customer_id, SUM(r.total_amount) AS spend FROM r GROUP BY r.customer_id"
    )
    lin = service.run(sql, "sales_analyst", 1)["lineage"]
    spend = next(o for o in lin["outputs"] if o["name"] == "spend")
    assert spend["sources"] == [{"table": "orders", "column": "total_amount"}]
    assert any(r["clause"] == "where" and r["column"] == "tenant_id" for r in lin["references"])


def test_json_path_lineage_shows_label(service):
    sql = "SELECT c.profile ->> '$.health.allergies' AS a FROM customers c WHERE c.tenant_id = :tenant_id"
    refs = service.run(sql, "customer_support", 1)["lineage"]["references"]
    health = next(r for r in refs if r["json_path"])
    assert health["labels"] == ["special_category"] and health["access"] == "deny"


@pytest.mark.parametrize(
    ("sql", "role", "tenant"),
    [
        ("", "sales_analyst", 1),
        ("SELECT 1", "admin", 1),
        ("SELECT 1", "sales_analyst", 9),
        ("SELECT 1", "sales_analyst", True),
        ("x" * 5001, "sales_analyst", 1),
        (None, "sales_analyst", 1),
    ],
    ids=["empty", "role", "tenant", "bool-tenant", "long", "none"],
)
def test_invalid_input_is_rejected(service, sql, role, tenant):
    assert service.run(sql, role, tenant)["error"] == "invalid_input"


def test_capabilities_reflect_policy(service):
    caps = service.capabilities("store_manager")
    employees = next(t for t in caps["tables"] if t["name"] == "employees")
    access = {c["name"]: c["access"] for c in employees["columns"]}
    assert access["salary"] == "aggregate_only"
    assert access["national_id"] == "not_granted"


def test_validation_only_mode():
    svc = DemoService(execute=False)
    out = svc.run("SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id", "store_manager", 1)
    assert out["decision"] == "allow" and out["execution"]["status"] == "disabled"


# --------------------------------------------------------------------------- sandbox
@pytest.fixture(scope="module")
def sandbox() -> Sandbox:
    return Sandbox(demo_policy(), timeout_s=0.5)


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM orders",
        "UPDATE orders SET status = 'x'",
        "CREATE TABLE t (a int)",
        "ATTACH DATABASE 'file.db' AS f",
        "PRAGMA table_info(orders)",
        "SELECT * FROM sqlite_master",
        "SELECT name FROM pragma_table_info('orders')",
        "SELECT randomblob(1000000)",
        "SELECT load_extension('x')",
        "SELECT printf('%s', 1)",
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT MAX(n) FROM r",
        "SELECT COUNT(*) FROM order_items a, order_items b, order_items c",
        "SELECT 1; SELECT 2",
    ],
)
def test_sandbox_refuses_at_the_database_level(sandbox, sql):
    with pytest.raises(SandboxError):
        sandbox.execute(sql, {})


def test_sandbox_caps_rows_and_values(sandbox):
    r = sandbox.execute("SELECT o.id FROM orders o", {})
    assert len(r.rows) == 100 and r.truncated


# --------------------------------------------------------------------------- server
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sqlguard_ninja.demo.app import DemoSettings, RateLimiter, create_app  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app(DemoSettings(rate_limit_per_minute=1000)))


def test_security_headers_and_health(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert (
        "script-src 'self'" in csp
        and "unsafe-inline" not in csp
        and "frame-ancestors 'none'" in csp
    )
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    assert client.get("/docs").status_code == 404


def test_api_round_trip(client):
    body = {
        "sql": "SELECT p.card_number FROM payments p WHERE p.tenant_id = :tenant_id",
        "role": "customer_support",
        "tenant": 1,
    }
    r = client.post("/api/run", json=body).json()
    assert r["decision"] == "deny" and r["execution"]["status"] == "not_run"
    assert client.post("/api/tenant_isolation", json={"role": "store_manager"}).status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"sql": "SELECT 1", "role": "admin", "tenant": 1},
        {"sql": "SELECT 1", "role": "sales_analyst", "tenant": 7},
        {"sql": "SELECT 1", "role": "sales_analyst", "tenant": 1, "tenant_id": 2},
    ],
    ids=["role", "tenant", "extra-field"],
)
def test_identity_cannot_be_forged(client, body):
    assert client.post("/api/run", json=body).status_code == 422


def test_body_limits(client):
    big = {"sql": "x" * 20_000, "role": "sales_analyst", "tenant": 1}
    assert client.post("/api/run", json=big).status_code == 413
    r = client.post(
        "/api/run",
        content=iter([b'{"sql":"SELECT 1"}']),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 411


def test_rate_limit():
    c = TestClient(create_app(DemoSettings(rate_limit_per_minute=3)))
    codes = [c.get("/api/meta").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert c.get("/healthz").status_code == 200  # probes are never rate limited


def test_rate_limiter_window_and_memory_bound():
    rl = RateLimiter(limit=2, max_clients=100, window_s=60)
    assert [rl.allow("a", now=0) for _ in range(3)] == [True, True, False]
    assert rl.allow("a", now=61)
    for i in range(500):
        rl.allow(f"c{i}", now=1)
    assert len(rl._hits) <= 100


def test_settings_are_validated():
    assert DemoSettings.from_env({"SQLNINJA_DEMO_EXECUTE": "false"}).execute is False
    with pytest.raises(ValueError, match="unknown settings"):
        DemoSettings.from_env({"SQLNINJA_DEMO_EXECTUE": "false"})
    with pytest.raises(ValueError):
        DemoSettings.from_env({"SQLNINJA_DEMO_RATE_LIMIT_PER_MINUTE": "0"})


# --------------------------------------------------------------------------- assets
def test_static_assets_have_no_inline_script_or_style():
    html = (ROOT / "src/sqlguard_ninja/demo/static/index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert " style=" not in html and "<style" not in html
    js = (ROOT / "src/sqlguard_ninja/demo/static/app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "eval(" not in js


def test_demo_benchmark_data_is_in_sync():
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_demo_data.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout


# --------------------------------------------------------------------------- deployment
def _docs(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]


def test_kubernetes_deployment_is_hardened():
    (dep,) = _docs(ROOT / "deploy/kubernetes/deployment.yaml")
    pod = dep["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    for c in pod["containers"]:
        sc = c["securityContext"]
        assert sc["readOnlyRootFilesystem"] and not sc["allowPrivilegeEscalation"]
        assert sc["capabilities"]["drop"] == ["ALL"]
        assert {"cpu", "memory"} <= set(c["resources"]["limits"])
        assert c["livenessProbe"]["httpGet"]["path"] == "/healthz"
        assert c["readinessProbe"]["httpGet"]["path"] == "/readyz"
        assert "envFrom" not in c and not any("secretKeyRef" in str(e) for e in c.get("env", []))
    (np,) = _docs(ROOT / "deploy/kubernetes/networkpolicy.yaml")
    assert np["spec"]["egress"] == [] and "Egress" in np["spec"]["policyTypes"]


def test_compose_and_dockerfile_are_hardened():
    svc = _docs(ROOT / "deploy/compose/docker-compose.yml")[0]["services"]["demo"]
    assert svc["read_only"] and svc["cap_drop"] == ["ALL"] and svc["user"] == "10001:10001"
    assert (
        "no-new-privileges:true" in svc["security_opt"] and svc["mem_limit"] and svc["pids_limit"]
    )
    assert all(p.startswith("127.0.0.1:") for p in svc["ports"])
    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 10001:10001" in docker and "HEALTHCHECK" in docker
    assert re.search(r"python:3\.12-slim@sha256:[0-9a-f]{64}", docker)
