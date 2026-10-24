"""Summarise published benchmark results into the demo's benchmark.json.

    python scripts/build_demo_data.py            # write
    python scripts/build_demo_data.py --check    # fail if the committed file is stale

Only numbers from the committed result files are used. Tiers are copied as they are: there
are no independent results, and the summary says so instead of inventing any.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results" / "v1.2.0"
OUT = ROOT / "src" / "sqlguard_ninja" / "demo" / "static" / "data" / "benchmark.json"
ADAPTERS = {
    "native": "SQLGuard Ninja",
    "sql-guardrail": "sql-guardrail",
    "agent-sql-guard": "agent-sql-guard",
    "krish2105-sqlguard": "krish2105/sqlguard",
}
KEYS = ("cases", "recall", "precision", "f1", "false_positive_rate")


def _pick(m: dict) -> dict:
    out = {k: m[k] for k in KEYS}
    out["ci95"] = {k: m["confidence_95"][k] for k in ("recall", "false_positive_rate")}
    return out


def build() -> dict:
    adapters, dataset = [], None
    for key, label in ADAPTERS.items():
        d = json.loads((RESULTS / f"{key}.json").read_text(encoding="utf-8"))
        m = d["metrics"]
        dataset = d["benchmark"]
        adapters.append(
            {
                "id": key,
                "label": label,
                "version": d["adapter"].get("version"),
                "overall": _pick(m["overall"]),
                "within_capability": _pick(m["within_capability"]),
                "latency_ms": {k: m["overall"]["latency_ms"][k] for k in ("p50", "p95")},
                "tiers": {t: v["cases"] for t, v in m["by_tier"].items()},
                "categories": {
                    c: {"cases": v["cases"], "recall": v["recall"], "fpr": v["false_positive_rate"]}
                    for c, v in sorted(m["by_category"].items())
                },
            }
        )
    assert dataset is not None
    tiers = adapters[0]["tiers"]
    return {
        "dataset": {
            "name": dataset["name"],
            "version": dataset["version"],
            "fingerprint": dataset["fingerprint"],
            "evaluations": dataset["cases_evaluated"],
        },
        "tiers": {"internal": tiers.get("internal", 0), "independent": tiers.get("independent", 0)},
        "notes": [
            "Every evaluation is internal: the corpus was written by this project "
            "alongside the engine.",
            "No independently sourced dataset exists yet (issue #6), so there is no "
            "independent result.",
            "Restricted-function and system-catalog categories are not in the corpus (issue #5).",
            "External tools are compared through a conservative policy translation; "
            "'within capability' is the fairer comparison.",
        ],
        "source": "benchmarks/results/v1.2.0",
        "adapters": adapters,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    text = json.dumps(build(), indent=1) + "\n"
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT} is stale; run scripts/build_demo_data.py")
            return 1
        print("demo benchmark data is up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
