# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may change the API.

## [0.1.1] — 2026-10-24

Documentation and governance patch. No changes to policy decisions.

### Fixed
* README links were relative and broke on the PyPI project page. They are now absolute
  GitHub URLs, and a test keeps relative links out of the README.

### Added
* `docs/security/STATIC_ANALYSIS_LIMITS.md`: limits of static analysis, compensating
  controls, and a dialect support matrix (supported / experimental / untested).
* `docs/guides/BENCHMARK_BIAS_REVIEW.md`: quantified review of corpus v1 bias
  (co-development, generated labels, input distribution, outcome imbalance).
* `benchmarks/datasets/external/`: intake rules for independently sourced, held-out
  evaluation sets (no cases yet).
* `.github/CODEOWNERS`, and branch protection on `main` (pull requests and CI required).

### Unchanged known limitations
* No restricted-function or system-catalog benchmark cases; no external dataset yet.

## [0.1.0] — 2026-10-24

First release.

### Added
* Policy schema v1: catalog, classification labels, roles, tenant settings, function policy,
  limits, cost thresholds, disclosure mode. Policies are validated on load.
* Guard and rules on sqlglot 30: read-only statements, system catalogs, functions,
  table/column grants, privacy labels (deny / aggregate-only / review, JSON paths, small
  cohort, minimisation), tenant isolation, structure limits, static cost score.
* `SQLCheckpoint` with block / review / audit modes, approvals bound to the SQL hash
  (single use, expiry, no self-approval), retry lock-out, redacted audit events.
* LangChain tool, LangGraph nodes and router, FastAPI router, read-only executors.
* PostgreSQL `EXPLAIN (FORMAT JSON)` inspector with guard gating and a read-only,
  time-limited, rolled-back transaction.
* Benchmark corpus v1.0.0 (530 cases, 1,002 evaluations), seeded generator, metrics,
  adapters (native, callable, isolated external workers for three existing tools), JSON
  and Markdown reports, baseline comparison with a label-change gate.
* `sqlninja` CLI and a composite GitHub Action.

### Known limitations
* The benchmark corpus does not contain cases for two categories: **restricted functions** (e.g. calls to server file-access, sleep, dynamic-SQL or administrative functions) and **system catalogs** (PostgreSQL `pg_catalog`/`information_schema`, SQLite `sqlite_master`/`sqlite_schema`, in qualified, joined, CTE and nested positions). The corresponding rules (`function.*`, `catalog.system_object`) ship and run by default; their mechanics are unit-tested with fictitious function names, but their detection is not measured by the benchmark.
* Writes are always denied; only PostgreSQL and SQLite are tested.

### Packaging
* The reference corpus and policy are bundled in the wheel (`builtin:v1`, `builtin:retail_saas`).
* Published to PyPI through GitHub Actions Trusted Publishing (OIDC).

### Fixed during development (each with a regression test)
* Unknown select-list columns were allowed when qualification aliased them to themselves.
* `Guard.validate` raised on lone UTF-16 surrogates.
* Quoted mixed-case identifiers were re-lowercased, so PostgreSQL `"Orders"` matched `orders`.
* A cast of the tenant column was accepted as a tenant pin.
* LangGraph nodes did not receive the run config (it needs a `RunnableConfig` annotation).
* The shared SQLite connection could not be used from FastAPI worker threads.
* CLI output crashed on cp1252 consoles.
