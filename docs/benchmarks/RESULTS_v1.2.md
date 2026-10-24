# Benchmark results — corpus v1.2.0 (SQLGuard Ninja 0.5.0)

Raw files (JSON, CSV, Markdown), with per-file SHA-256 hashes of the dataset inside each JSON:
[`benchmarks/results/v1.2.0/`](../../benchmarks/results/v1.2.0/). Reproduce:

```bash
sqlninja benchmark run --dataset builtin:v1 --adapter native --csv results/native.csv
python scripts/setup_external_adapters.py   # repository checkout
sqlninja benchmark run --dataset builtin:v1 --adapter external:sql-guardrail
```

Environment: Windows 11, Python 3.11.9, sqlglot 30.24.0. 577 unique cases,
1,070 evaluations, dataset fingerprint `0739c8aa0bbb15ed`. Intervals are 95% Wilson
score intervals.

## Read this first

* **All evaluations are internal** (tier `internal`). No independently sourced dataset exists
  yet (issue #6). See [BENCHMARK_BIAS_REVIEW.md](../guides/BENCHMARK_BIAS_REVIEW.md).
* The native engine was developed alongside this corpus. Its 100% shows consistency with the
  documented semantics, not real-world detection quality.
* Restricted-function and system-catalog categories are still absent (issue #5).
* External tools are evaluated through a conservative policy translation. The
  "within capability" figures are the fairer comparison. They do not declare MySQL support,
  so the MySQL cases fall outside their capability.

## Summary

| Validator | Version | Recall (95% CI) | Precision | F1 | FPR (95% CI) | Recall / FPR within capability (cases) | p50 ms | p95 ms | Evals/s |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SQLGuard Ninja (native) | 0.5.0 | 100.0% (99.4–100.0) | 100.0% | 1.000 | 0.0% (0.0–0.9) | 100.0% / 0.0% (1070) | 1.63 | 3.36 | 556 |
| sql-guardrail | 0.5.2 | 98.2% (96.9–99.0) | 84.7% | 0.909 | 24.8% (21.1–29.0) | 98.3% / 19.7% (835) | 0.96 | 1.84 | 955 |
| agent-sql-guard | 0.2.0 | 66.8% (63.0–70.4) | 85.1% | 0.748 | 16.3% (13.2–20.0) | 89.4% / 17.7% (759) | 0.68 | 1.44 | 1299 |
| krish2105/sqlguard | 0.1.0 | 64.8% (61.0–68.5) | 89.4% | 0.752 | 10.7% (8.2–14.0) | 83.5% / 5.2% (607) | 0.61 | 1.42 | 1373 |

Throughput is sequential, single-threaded and measured inside each validator's process.

For the native engine, flagged cases split into 600 decided by a policy rule and
23 decided because the SQL was unparseable or an unsupported statement type.

## MySQL cases (`dialect_mysql`)

| Validator | Cases | Recall | FPR |
|---|---:|---:|---:|
| SQLGuard Ninja (native) | 26 | 100.0% | 0.0% |
| sql-guardrail | 26 | 80.0% | 54.5% |
| agent-sql-guard | 26 | 46.7% | 18.2% |
| krish2105/sqlguard | 26 | 46.7% | 18.2% |

The 26 cases cover tenant isolation, joins, CTEs, sensitive columns and JSON paths, MySQL
syntax (backtick identifiers, `LIMIT a, b`, `WITH ROLLUP`, `REGEXP`, JSON `->>`, executable
comments, locking reads, `REPLACE`, `HANDLER`, `SET`), named placeholders, multi-statement input
and identifier case. `INTO OUTFILE`, `%s` placeholders and truncated SQL are covered by unit
tests (`tests/unit/test_mysql_binding.py`), not by the corpus. Two cases
(MY-401 `o.ID`, MY-402 `Orders`) are labelled **deny** on purpose: the guard does not fold
identifier case, which is a documented, fail-closed false positive for MySQL users
(see [DATABASE_COMPATIBILITY.md](../guides/DATABASE_COMPATIBILITY.md)). Every MySQL `allow`
case executes on MySQL 8.4 in CI as a SELECT-only account.

## Changes from v1.1.0

* 26 new MySQL cases (`cases/09_mysql.yaml`). No existing labels changed.
* The v1.1.0 results remain in `benchmarks/results/v1.1.0/` and [RESULTS_v1.1.md](RESULTS_v1.1.md).
