# Benchmark methodology

## Goal

Measure how well a SQL policy engine enforces a **declared** policy on concrete SQL: which
unsafe queries it stops, and which legitimate queries it wrongly blocks. Results are
reported transparently. The corpus is not an external standard.

## Corpus v1.0.0

* Location: `benchmarks/datasets/v1/` (`manifest.yaml`, `cases/*.yaml`, `generated/*.yaml`).
* Policy: `benchmarks/policies/retail_saas.yaml`. A synthetic multi-tenant retail schema with
  ten tables, nine classification labels and six roles.
* Size: **530 unique cases → 1,002 evaluations** (a case can target both PostgreSQL and SQLite).
  262 cases are handwritten and 268 generated. Outcomes: 568 deny, 420 allow, 14 review
  (counted over evaluations). Run `sqlninja dataset stats` for current numbers.
* **Not yet covered:** restricted-function and system-catalog categories. The engine rules
  exist, but v1.0.0 has no corpus cases for them.

### Case schema

| Field | Meaning |
|---|---|
| `id` | Stable id. The loader expands it to `<id>@<dialect>`. |
| `sql`, `dialects` | Query text and target dialects. |
| `role`, `context` | Policy role and trusted request context (default `tenant_id: 1`). |
| `expected` | Ideal decision under the policy semantics: `allow`, `deny` or `review`. |
| `expected_by_dialect` | Per-dialect override, e.g. quoted identifiers are case-sensitive only in PostgreSQL. |
| `classification` | `benign`, `malicious`, `policy_violation` or `sensitive`. Must be consistent with `expected`. |
| `reason` | Tool-agnostic reason code (`tenant_isolation`, `aggregate_only`, ...). Required for non-allow cases. |
| `category`, `tags` | Scenario category used for per-category metrics. |
| `provenance` | `handwritten` or `generated:<family>@<seed>`. |
| `explanation` | Why the expected outcome is right. |

The loader rejects inconsistent labels, unknown roles, duplicate ids and duplicate
`(sql, dialect, role, context)` tuples.

### Policy semantics that the labels follow

* **Read-only:** only a single SELECT or set operation. Any write or session statement
  anywhere in the tree is denied.
* **Tables and columns:** only granted tables and columns, in **any** clause. `*` is
  expanded with the catalog.
* **Labels:** explicit column rule > label rule > role default (`deny` for unlisted labels).
  `aggregate_only` columns may appear only inside statistical aggregates (COUNT, SUM, AVG, ...),
  not in filters, grouping, ordering, window aggregates or MIN/MAX. A statistical aggregate
  filtered or grouped by an `identifying` column requires review (small cohort).
  **Lineage-aware (since 1.1.0):** a raw projection inside a CTE or derived table is
  allowed only if every consumer aggregates that output statistically. Any raw, filtered,
  ordered, windowed or whole-row use downstream is denied. The small-cohort rule follows
  identifiers through derived scopes.
* **Tenant isolation:** every scope that reads a tenant-scoped table must connect its tenant
  column, through top-level `=` conjuncts (WHERE, INNER JOIN ON, or the ON of the LEFT JOIN
  that introduces it), to the context tenant or an approved bind parameter. `OR`, `NOT`,
  ranges, multi-value IN and casts of the column do not count. An outer pin satisfies an inner
  scope only through an unmodified projection of the tenant column, in a scope without
  aggregation, windows, LIMIT/OFFSET/FETCH, and when every consumer pins it (since 1.1.0).
* **Cost:** a static score of 50–79 means review and ≥80 means deny. Role limits on joins,
  depth and LIMIT are hard denials.

### Independent validation of labels

* Every SQLite `allow` case is **executed** on the synthetic fixture database
  (`tests/integration/test_corpus_sqlite_validation.py`).
* Every PostgreSQL `allow` case is **executed** on real PostgreSQL 16 as a SELECT-only role
  in a read-only transaction (`tests/integration/test_postgres.py`).
* This caught a mislabelled case (`FMT-010`): SQLite rejects a parenthesised top-level
  SELECT, so the case is now PostgreSQL-only.

### Generated cases

`scripts/generate_corpus.py` is enumerative (seed recorded for provenance) and **does not
import the engine**. It applies the semantics above to the policy YAML:

* `grant_matrix`: every role × table.
* `label_matrix`: every role × visible classified column, plus aggregate variants.
* `tenant_matrix`: every tenant table × 10 predicate patterns.
* `transform`: semantics-preserving rewrites (comments, whitespace, case, parentheses,
  derived-table and CTE wrapping) of 14 base queries.

`--check` makes CI fail if the committed files drift from the generator.

## Metrics

Positive class: expected `deny` or `review` (must not run unattended). Predicted positive:
decision is not `allow`.

* Recall = TP/(TP+FN), precision = TP/(TP+FP), FPR = FP/(FP+TN), FNR = FN/(FN+TP).
* Exact match = the three-way decision equals the expected decision.
* Reported overall, within the adapter's declared capability, per category, per dialect and
  per provenance (handwritten vs each generator family).
* Latency: nearest-rank p50/p95/p99 and max, measured around the validation call in the
  validator's own process, after 3 warm-up evaluations. Machine and Python version are
  recorded in every result file.

## Adapters

* `native`: SQLGuard Ninja.
* `external:<tool>`: a worker in the tool's own venv, speaking JSON Lines. Policy
  translation is in `benchmarking/translate.py`. Aggregate-only and review columns are put
  in denylists because those tools cannot express them, and this is documented in the reports.
* `callable:module:function`: any Python validator.

## Threats to validity

A quantified review is in [BENCHMARK_BIAS_REVIEW.md](BENCHMARK_BIAS_REVIEW.md).

* The corpus and the native engine were co-developed by the same authors. Native results
  show consistency with the stated semantics, not independent detection quality.
* Some semantics are deliberately strict (reference-based privacy, scope-local tenant pins).
  A validator with different but reasonable semantics will show "false positives" or
  "false negatives" on those cases. Per-case results make this inspectable.
* One schema and one policy. Real schemas vary.
* Latency depends on hardware. The CI gate disables the latency threshold by default.

## Reproduce

```bash
python -m pip install -e ".[dev]"
sqlninja benchmark run --dataset benchmarks/datasets/v1 --adapter native --output results/native.json
python scripts/setup_external_adapters.py
sqlninja benchmark run --dataset benchmarks/datasets/v1 --adapter external:sql-guardrail
```
