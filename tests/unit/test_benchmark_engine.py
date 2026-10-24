from __future__ import annotations

import sys
from dataclasses import replace

import pytest

from sqlguard_ninja.benchmarking import adapters
from sqlguard_ninja.benchmarking.adapters import (
    EXTERNAL_TOOLS,
    CallableAdapter,
    NativeAdapter,
    SubprocessAdapter,
    _coerce_decision,
)
from sqlguard_ninja.benchmarking.compare import Thresholds, compare
from sqlguard_ninja.benchmarking.dataset import load_dataset
from sqlguard_ninja.benchmarking.metrics import CaseOutcome, percentile, summarise
from sqlguard_ninja.benchmarking.runner import (
    RESULT_SCHEMA,
    load_result,
    run_benchmark,
    write_result,
)
from sqlguard_ninja.benchmarking.translate import translate_for_role
from sqlguard_ninja.core.findings import Decision
from sqlguard_ninja.reporting.markdown import benchmark_report, comparison_report
from tests.conftest import DATASET_PATH

DS = load_dataset(DATASET_PATH)
SMALL = [
    c for c in DS.cases if c.base_id in {"DES-001", "TEN-001", "TEN-013", "PRV-010", "PRV-019"}
]

FAKE_WORKER = """\
import json, sys
sys.stdout.write(json.dumps({"library": "fake", "version": "9.9"}) + "\\n")
sys.stdout.flush()
for line in sys.stdin:
    req = json.loads(line)
    d = "deny" if "DROP" in req["sql"].upper() else "allow"
    sys.stdout.write(json.dumps({"decision": d, "reasons": ["r"], "latency_ms": 0.5}) + "\\n")
    sys.stdout.flush()
"""


def _o(expected, actual):
    return CaseOutcome(
        id="x",
        category="c",
        dialect="postgres",
        provenance="handwritten",
        expected=Decision(expected),
        actual=Decision(actual),
        latency_ms=1.0,
    )


def test_confusion_matrix_definitions():
    m = summarise(
        [
            _o("deny", "deny"),
            _o("review", "deny"),
            _o("deny", "allow"),
            _o("allow", "review"),
            _o("allow", "allow"),
        ]
    )
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (2, 1, 1, 1)
    assert m["recall"] == round(2 / 3, 4)
    assert m["precision"] == round(2 / 3, 4)
    assert m["false_positive_rate"] == 0.5
    assert m["exact_match_rate"] == 0.4


def test_empty_ratios_are_none():
    m = summarise([_o("allow", "allow")])
    assert m["recall"] is None and m["precision"] is None


def test_percentile_nearest_rank():
    assert percentile([], 50) is None
    assert percentile([5.0, 1.0, 3.0, 2.0, 4.0], 50) == 3.0
    assert percentile([1.0, 2.0], 99) == 2.0


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (True, "allow"),
        (False, "deny"),
        ("REVIEW", "review"),
        ({"allowed": True}, "allow"),
        ({"decision": "deny", "reasons": ["x"]}, "deny"),
        (("allow", ["r"]), "allow"),
        (Decision.REVIEW, "review"),
    ],
)
def test_coerce_decision(raw, expected):
    assert _coerce_decision(raw)[0].value == expected


def test_coerce_rejects_garbage():
    with pytest.raises(TypeError):
        _coerce_decision(42)


def test_native_run_and_report(tmp_path):
    result = run_benchmark(DS, NativeAdapter(DS.policy), SMALL, warmup=1)
    assert result["schema"] == RESULT_SCHEMA
    assert result["benchmark"]["cases_evaluated"] == len(SMALL)
    assert result["metrics"]["overall"]["errors"] == 0
    path = write_result(result, tmp_path / "r.json")
    assert load_result(path)["adapter"]["name"] == "native"
    text = benchmark_report(result)
    assert "By category" in text and "native" in text


def test_load_result_rejects_other_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"schema": "other"}')
    with pytest.raises(ValueError):
        load_result(p)


def test_callable_adapter_errors_fail_closed():
    def boom(sql, dialect, case):
        raise RuntimeError("bad")

    v = CallableAdapter(boom, name="boom").evaluate(SMALL[0])
    assert v.decision is Decision.DENY and "RuntimeError" in v.error


def test_callable_from_spec():
    adapter = CallableAdapter.from_spec("tests.unit.helpers:always_allow")
    result = run_benchmark(DS, adapter, SMALL, warmup=0)
    assert result["metrics"]["overall"]["fn"] == sum(c.unsafe for c in SMALL)
    with pytest.raises(ValueError):
        CallableAdapter.from_spec("no_colon")


def test_capability_subset_reported():
    adapter = CallableAdapter(lambda s, d, c: True, capabilities=frozenset({"destructive"}))
    m = run_benchmark(DS, adapter, SMALL, warmup=0)["metrics"]
    assert m["within_capability"]["cases"] < m["overall"]["cases"]


def test_translation_is_conservative(policy):
    cfg = translate_for_role(policy, "support_analyst", "postgres")
    assert "card_number" in cfg["tables"]["payments"]["deny_columns"]
    assert "employees" not in cfg["tables"]
    assert cfg["tables"]["orders"]["tenant_column"] == "tenant_id"
    assert "card_number" in cfg["pii_denylist"]
    hr = translate_for_role(policy, "hr_analyst", "postgres")
    assert "salary" in hr["tables"]["employees"]["deny_columns"]  # aggregate-only not expressible
    assert hr["tables"]["warehouses"]["tenant_column"] is None


def test_subprocess_adapter_protocol(tmp_path, monkeypatch):
    """Exercise the JSON Lines protocol with a stand-in worker on this interpreter."""
    (tmp_path / "fake_worker.py").write_text(FAKE_WORKER)
    monkeypatch.setattr(adapters, "WORKERS_DIR", tmp_path)
    spec = replace(EXTERNAL_TOOLS["sql-guardrail"], worker="fake_worker.py")
    adapter = SubprocessAdapter(spec, sys.executable, DS.policy)
    try:
        assert adapter.version == "9.9"
        v = adapter.evaluate(next(c for c in SMALL if c.base_id == "DES-001"))
        assert v.decision is Decision.DENY and v.latency_ms == 0.5
    finally:
        adapter.close()


def test_subprocess_adapter_reports_dead_worker(tmp_path, monkeypatch):
    (tmp_path / "dead.py").write_text("import sys; sys.exit(3)\n")
    monkeypatch.setattr(adapters, "WORKERS_DIR", tmp_path)
    spec = replace(EXTERNAL_TOOLS["sql-guardrail"], worker="dead.py")
    with pytest.raises(RuntimeError, match="exited"):
        SubprocessAdapter(spec, sys.executable, DS.policy)


# ------------------------------------------------------------------------------ compare
def _result(cases, fingerprint="f1", p95=1.0):
    return {
        "schema": RESULT_SCHEMA,
        "benchmark": {"name": "b", "version": "1", "fingerprint": fingerprint},
        "adapter": {"name": "native", "version": "x", "capabilities": "all"},
        "environment": {},
        "metrics": {
            "overall": {
                "recall": 1.0,
                "precision": 1.0,
                "false_positive_rate": 0.0,
                "latency_ms": {"p95": p95},
            }
        },
        "cases": cases,
    }


def _c(cid, expected, actual, category="tenant_isolation", reasons=(), error=None):
    unsafe, flagged = expected != "allow", actual != "allow"
    kind = ("tp" if flagged else "fn") if unsafe else ("fp" if flagged else "tn")
    return {
        "id": cid,
        "expected": expected,
        "actual": actual,
        "category": category,
        "reasons": list(reasons),
        "error": error,
        "kind": kind,
    }


def test_compare_detects_each_regression_class():
    base = _result(
        [
            _c("a", "deny", "deny"),
            _c("b", "allow", "allow"),
            _c("c", "review", "review"),
            _c("d", "deny", "allow"),
            _c("e", "allow", "allow"),
        ]
    )
    cand = _result(
        [
            _c("a", "deny", "allow"),
            _c("b", "allow", "deny"),
            _c("c", "review", "deny"),
            _c("d", "deny", "deny"),
            _c("e", "allow", "deny", reasons=["parse.error"]),
        ],
        p95=3.0,
    )
    comp = compare(base, cand, Thresholds(max_p95_latency_increase_pct=50))
    assert comp.security_regressions == ["a"] and comp.tenant_regressions == ["a"]
    assert set(comp.usability_regressions) == {"b", "e"}
    assert comp.improvements == ["d"]
    assert comp.decision_changes == ["c"]
    assert comp.new_parse_failures == ["e"]
    assert comp.p95_change_pct == 200.0
    assert not comp.passed and len(comp.failures) >= 3
    assert "FAILED" in comparison_report(comp)


def test_compare_identical_passes():
    r = _result([_c("a", "deny", "deny")])
    comp = compare(r, r)
    assert comp.passed and "PASSED" in comparison_report(comp)


def test_compare_flags_fingerprint_and_new_failing_case():
    base = _result([_c("a", "deny", "deny")])
    cand = _result([_c("a", "deny", "deny"), _c("new", "deny", "allow")], fingerprint="f2")
    comp = compare(base, cand)
    assert any("fingerprint" in f for f in comp.failures)
    assert comp.security_regressions == ["new"]
    same = _result([_c("a", "deny", "deny")], fingerprint="f2")
    assert compare(base, same, Thresholds(allow_benchmark_change=True)).passed


def test_compare_missing_cases_fail():
    base = _result([_c("a", "deny", "deny"), _c("b", "deny", "deny")])
    cand = _result([_c("a", "deny", "deny")])
    comp = compare(base, cand)
    assert comp.missing_cases == ["b"] and not comp.passed


def test_compare_metric_gates():
    r = _result([_c("a", "deny", "deny")])
    r["metrics"]["overall"].update(recall=0.5, false_positive_rate=0.3)
    comp = compare(r, r, Thresholds(min_recall=0.9, max_false_positive_rate=0.1))
    assert len(comp.failures) == 2


def test_compare_new_validator_error():
    base = _result([_c("a", "deny", "deny")])
    cand = _result([_c("a", "deny", "deny", error="boom")])
    comp = compare(base, cand)
    assert comp.new_errors == ["a"] and not comp.passed


def test_compare_flags_relabelled_cases():
    """Relabelling deny->allow together with an engine change must not pass silently."""
    base = _result([_c("a", "deny", "deny")])
    cand = _result([_c("a", "allow", "allow")])
    comp = compare(base, cand)
    assert comp.label_changes == ["a"] and not comp.passed
    assert compare(base, cand, Thresholds(allow_label_changes=True)).passed


# ------------------------------------------------------------- 0.2: tiers, CIs, CSV, hashes
def test_wilson_interval_properties():
    from sqlguard_ninja.benchmarking.metrics import wilson_interval

    assert wilson_interval(0, 0) is None
    lo, hi = wilson_interval(50, 100)
    assert lo < 0.5 < hi and round(lo, 2) == 0.40 and round(hi, 2) == 0.60
    lo, hi = wilson_interval(10, 10)
    assert hi == 1.0 and 0.65 < lo < 0.75  # perfect score still has a non-trivial lower bound


def test_f1_and_ci_in_summary():
    m = summarise(
        [_o("deny", "deny"), _o("deny", "allow"), _o("allow", "deny"), _o("allow", "allow")]
    )
    assert m["f1"] == 0.5
    assert m["confidence_95"]["method"] == "wilson"
    assert m["confidence_95"]["recall"][0] < 0.5 < m["confidence_95"]["recall"][1]
    assert m["throughput_per_s"] == 1000.0  # 4 evaluations x 1 ms


def test_tier_and_basis():
    from sqlguard_ninja.benchmarking.metrics import dataset_tier

    assert dataset_tier("handwritten") == "internal"
    assert dataset_tier("generated:tenant_matrix@1") == "internal"
    assert dataset_tier("human-reviewed:panel@1") == "internal"
    assert dataset_tier("external:acme-sql@1.0") == "independent"
    base = {
        "id": "x",
        "category": "c",
        "dialect": "postgres",
        "provenance": "handwritten",
        "expected": Decision.DENY,
        "actual": Decision.DENY,
        "latency_ms": 1.0,
    }
    assert CaseOutcome(**base, reasons=("parse.error",)).basis == "unsupported"
    assert (
        CaseOutcome(**base, reasons=("parse.error", "tenant.missing_predicate")).basis == "policy"
    )
    assert CaseOutcome(**{**base, "actual": Decision.ALLOW}).basis == "none"


def test_result_has_hashes_tiers_and_csv(tmp_path):
    from sqlguard_ninja.benchmarking.runner import write_csv

    result = run_benchmark(DS, NativeAdapter(DS.policy), SMALL, warmup=0)
    files = result["benchmark"]["files"]
    assert "manifest.yaml" in files and any(k.startswith("policy:") for k in files)
    assert all(len(h) == 64 for h in files.values())
    assert set(result["metrics"]["by_tier"]) == {"internal"}
    assert all(
        r["tier"] == "internal" and r["basis"] in ("policy", "unsupported", "none")
        for r in result["cases"]
    )
    path = write_csv(result, tmp_path / "r.csv")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("id,category,dialect,tier") and len(lines) == len(SMALL) + 1
    assert "By dataset tier" in benchmark_report(result)


def test_file_hashes_ignore_line_endings(tmp_path):
    import shutil

    from sqlguard_ninja.benchmarking.dataset import load_dataset as load

    src = DATASET_PATH.parent.parent  # benchmarks/
    dst = tmp_path / "benchmarks"
    shutil.copytree(src / "datasets" / "v1", dst / "datasets" / "v1")
    shutil.copytree(src / "policies", dst / "policies")
    a = load(dst / "datasets" / "v1").file_hashes()
    f = dst / "datasets" / "v1" / "manifest.yaml"
    f.write_bytes(f.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert load(dst / "datasets" / "v1").file_hashes() == a
