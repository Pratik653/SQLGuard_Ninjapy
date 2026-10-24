"""Run a dataset through an adapter and produce a versioned, machine-readable result."""

from __future__ import annotations

import csv
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from sqlguard_ninja.benchmarking.adapters import BenchmarkAdapter
from sqlguard_ninja.benchmarking.dataset import BenchmarkCase, Dataset
from sqlguard_ninja.benchmarking.metrics import CaseOutcome, compute_metrics

RESULT_SCHEMA = "sqlninja.benchmark-result/1"


def _pkg_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _git_revision(root: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            cwd=root,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def run_benchmark(
    dataset: Dataset,
    adapter: BenchmarkAdapter,
    cases: list[BenchmarkCase] | None = None,
    *,
    warmup: int = 3,
) -> dict[str, Any]:
    """Evaluate every case and return the result document (see ``RESULT_SCHEMA``)."""
    selected = dataset.cases if cases is None else cases
    for case in selected[:warmup]:  # first parses pay one-time import/JIT costs
        adapter.evaluate(case)
    caps = adapter.capabilities
    records: list[dict[str, Any]] = []
    outcomes: list[CaseOutcome] = []
    for case in selected:
        verdict = adapter.evaluate(case)
        outcome = CaseOutcome(
            id=case.id,
            category=case.category,
            dialect=case.dialect,
            provenance=case.provenance,
            expected=case.expected,
            actual=verdict.decision,
            latency_ms=verdict.latency_ms,
            error=verdict.error,
            in_capability=caps is None or case.category in caps,
            reasons=tuple(verdict.reasons),
        )
        outcomes.append(outcome)
        records.append(
            {
                "id": case.id,
                "category": case.category,
                "dialect": case.dialect,
                "provenance": case.provenance,
                "tier": outcome.tier,
                "basis": outcome.basis,
                "classification": case.classification.value,
                "reason": case.reason.value,
                "expected": case.expected.value,
                "actual": verdict.decision.value,
                "kind": outcome.kind,
                "reasons": list(verdict.reasons),
                "latency_ms": round(verdict.latency_ms, 4),
                "error": verdict.error,
                "in_capability": outcome.in_capability,
            }
        )
    return {
        "schema": RESULT_SCHEMA,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "benchmark": {
            "name": dataset.manifest.name,
            "version": dataset.manifest.version,
            "fingerprint": dataset.fingerprint,
            "files": dataset.file_hashes(),
            "cases_evaluated": len(selected),
        },
        "adapter": {
            "name": adapter.name,
            "version": adapter.version,
            "capabilities": sorted(caps) if caps is not None else "all",
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "sqlglot": _pkg_version("sqlglot"),
            "sqlguard_ninja": _pkg_version("sqlguard-ninja"),
            "git_revision": _git_revision(dataset.root),
        },
        "metrics": compute_metrics(outcomes),
        "cases": records,
    }


def write_result(result: dict[str, Any], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return p


CSV_FIELDS = (
    "id",
    "category",
    "dialect",
    "tier",
    "provenance",
    "classification",
    "reason",
    "expected",
    "actual",
    "kind",
    "basis",
    "latency_ms",
    "in_capability",
    "error",
)


def write_csv(result: dict[str, Any], path: str | Path) -> Path:
    """Per-case results as CSV (one row per evaluation)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for record in result["cases"]:
            writer.writerow(record)
    return p


def load_result(path: str | Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != RESULT_SCHEMA:
        raise ValueError(f"{path}: not a {RESULT_SCHEMA} document")
    return data
