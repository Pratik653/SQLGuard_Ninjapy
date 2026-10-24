"""The Grafana dashboard queries only metrics that GuardMetrics actually exports."""

from __future__ import annotations

import json
import re
import runpy
import sys
from pathlib import Path

import pytest

pytest.importorskip("prometheus_client")
from sqlguard_ninja.observability import GuardMetrics

ROOT = Path(__file__).parents[2]
DASHBOARD = json.loads(
    (ROOT / "deploy" / "grafana" / "sqlguard-ninja.json").read_text(encoding="utf-8")
)
EXPRS = [t["expr"] for p in DASHBOARD["panels"] for t in p["targets"]]


def _exported_names() -> set[str]:
    names = set()
    for family in GuardMetrics().registry.collect():
        names.add(family.name)
        for suffix in ("_total", "_bucket", "_count", "_sum", "_created"):
            names.add(family.name + suffix)
    return names


def test_every_query_uses_exported_metrics():
    exported = _exported_names()
    assert EXPRS
    for expr in EXPRS:
        used = set(re.findall(r"sqlguard_[a-z_]+", expr))
        assert used and used <= exported, (expr, used - exported)


def test_dashboard_structure():
    ids = [p["id"] for p in DASHBOARD["panels"]]
    assert len(ids) == len(set(ids))
    assert DASHBOARD["uid"] == "sqlguard-ninja"
    for p in DASHBOARD["panels"]:
        assert p["datasource"]["uid"] == "${datasource}"


def test_queries_use_only_bounded_labels():
    """No label that could carry a tenant id, principal or SQL is queried or grouped by."""
    allowed = {
        "decision",
        "role",
        "dialect",
        "policy",
        "rule_id",
        "action",
        "outcome",
        "mode",
        "error",
        "le",
        "revision",
        "fingerprint",
    }
    for expr in EXPRS:
        selectors = re.findall(r"(\w+)\s*(?:=~|!~|!=|=)\s*\"", expr)
        grouped = [x.strip() for g in re.findall(r"by \(([^)]*)\)", expr) for x in g.split(",")]
        assert set(selectors) | set(grouped) <= allowed, expr


def test_synthetic_traffic_generator_emits_every_dashboard_family(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["synthetic_traffic.py", "--iterations", "400", "--print"])
    runpy.run_path(
        str(ROOT / "examples" / "observability" / "synthetic_traffic.py"), run_name="__main__"
    )
    out = capsys.readouterr().out
    families = (
        "sqlguard_decisions_total",
        "sqlguard_findings_total",
        "sqlguard_checkpoint_outcomes_total",
        "sqlguard_validation_duration_seconds_bucket",
        "sqlguard_policy_info",
    )
    for family in families:
        assert re.search("^" + family + r"\{.*\} [1-9]", out, re.M), family
