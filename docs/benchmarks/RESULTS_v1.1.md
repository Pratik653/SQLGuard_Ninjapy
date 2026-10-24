# Benchmark results — corpus v1.1.0 (SQLGuard Ninja 0.2.0)

Raw files (JSON, CSV, Markdown), with per-file SHA-256 hashes of the dataset inside each JSON:
[`benchmarks/results/v1.1.0/`](../../benchmarks/results/v1.1.0/). Reproduce:

```bash
sqlninja benchmark run --dataset builtin:v1 --adapter native --csv results/native.csv
python scripts/setup_external_adapters.py   # repository checkout
sqlninja benchmark run --dataset builtin:v1 --adapter external:sql-guardrail
```

Environment: Windows 11, Python 3.11.9, sqlglot 30.24.0. 551 unique cases, 1,044 evaluations,
dataset fingerprint `6dc1b2a0d5e0d3a7`. Intervals are 95% Wilson score intervals.

## Read this first

* **All 1,044 evaluations are internal** (tier `internal`). No independently sourced dataset
  exists yet, so there is no independent result to report. See
  [BENCHMARK_BIAS_REVIEW.md](../guides/BENCHMARK_BIAS_REVIEW.md) and issue #6.
* The native engine was developed alongside this corpus. Its 100% shows consistency with the
  documented semantics, not real-world detection quality.
* Restricted-function and system-catalog categories are still absent (issue #5).
* External tools are evaluated through a conservative policy translation. The
  "within capability" figures are the fairer comparison.

## Summary

| Validator | Version | Recall (95% CI) | Precision | F1 | FPR (95% CI) | Recall / FPR within capability (cases) | p50 ms | p95 ms | Evals/s |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SQLGuard Ninja (native) | 0.2.0 | 100.0% (99.4–100.0) | 100.0% | 1.000 | 0.0% (0.0–0.9) | 100.0% / 0.0% (1044) | 1.92 | 3.33 | 498 |
| sql-guardrail | 0.5.2 | 98.7% (97.4–99.3) | 85.1% | 0.914 | 24.1% (20.3–28.3) | 98.3% / 19.7% (835) | 1.28 | 2.63 | 704 |
| agent-sql-guard | 0.2.0 | 67.3% (63.4–70.9) | 85.2% | 0.752 | 16.3% (13.1–20.0) | 89.4% / 17.7% (759) | 0.89 | 1.87 | 992 |
| krish2105/sqlguard | 0.1.0 (git 62327f2) | 65.3% (61.4–69.0) | 89.6% | 0.755 | 10.5% (8.0–13.8) | 83.5% / 5.2% (607) | 0.80 | 1.95 | 1060 |

Throughput is sequential, single-threaded and measured inside each validator's process.

For the native engine, flagged cases split into 588 decided by a policy rule and 20 decided
because the SQL was unparseable or an unsupported statement type. A denial is not
automatically a correct detection. External tools' rule codes are not mapped to this split.

## Changes from v1.0.0

* 21 new lineage boundary cases (`cases/08_lineage.yaml`, categories `privacy_lineage` and
  `tenant_lineage`). Every relaxed case sits next to cases that must stay denied.
* Two approved relabels, recorded in `benchmarks/datasets/v1/LABEL_CHANGES.yaml`: PRV-026
  (aggregate-only through a CTE) and TEN-021 (tenant push-down). Both changed deny → allow
  because of the 0.2.0 lineage semantics.
* The v1.0.0 results remain in `benchmarks/results/v1.0.0/` and [RESULTS_v1.md](RESULTS_v1.md).
