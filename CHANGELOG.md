# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may change the API.

## [0.6.0] — 2026-10-24

### Added
* **Observability** (`sqlguard_ninja.observability`, extras `[otel]` and `[prometheus]`):
  * `Telemetry` and `InstrumentedGuard` emit OpenTelemetry spans `sqlguard.checkpoint` and
    `sqlguard.validate`.
  * `GuardMetrics` exports Prometheus counters and histograms for decisions, findings,
    latency, errors, resource-limit rejections, checkpoint outcomes and policy identity.
  * `SQLCheckpoint(telemetry=...)` instruments its guard automatically.
* **SARIF 2.1.0**: `sqlninja scan PATH... --format sarif|json|text --fail-on deny|review|never`.
  It validates every statement in SQL files, with stable fingerprints. Tests and CI validate the
  output against the OASIS schema.
* **Grafana dashboard** `deploy/grafana/sqlguard-ninja.json`, and a Prometheus + Grafana +
  synthetic-traffic stack (`examples/observability/`). A new CI job runs that stack.
* Audit events gain `schema_version` and `rate_limited`. New
  `SQLCheckpoint(principal_hmac_key=...)` option to pseudonymise principals.

### Security
* `redact_sql` now redacts hex, bit, byte (`E''`), dollar-quoted, Unicode (`U&''`) and
  national (`N''`) strings and whole `INTERVAL` expressions. Previously these could reach
  `sql_redacted` in audit logs. Comments are dropped, and if any literal token survives,
  redacted SQL is withheld. See threat model T19.

## [0.5.0] — 2026-10-24

### Added
* **MySQL 8** as a tested dialect within a documented scope: `sqlguard_ninja.integrations.mysql`
  (`mysql_executor`: read-only transaction, `MAX_EXECUTION_TIME`, rollback; `bind_placeholders`:
  AST-based binding of named placeholders, ADR-013), extra `[mysql]` (PyMySQL), and a MySQL 8.4
  service-container CI job that executes every MySQL `allow` case as a SELECT-only account.
* Corpus **1.2.0**: 26 MySQL cases (`cases/09_mysql.yaml`); results in
  `docs/benchmarks/RESULTS_v1.2.md`.
* `docs/guides/DATABASE_COMPATIBILITY.md`: compatibility matrix. SQL Server and Oracle are
  parser-level experimental with smoke tests; they are not accepted by the MCP server.
* The MCP server accepts `mysql` as a dialect.

### Security
* MySQL identifiers are compared exactly and never case-folded (fail closed). String values
  containing a backslash or NUL are refused at binding time. `mysql_executor` refuses sessions
  whose `sql_mode` changes lexing (`ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES`, `PIPES_AS_CONCAT`,
  `HIGH_NOT_PRECEDENCE`, `ANSI`); threat model T18.

## [0.4.0] — 2026-10-24

### Added
* **MCP server** (`sqlninja mcp`, `sqlguard_ninja.mcp_server`, extra `[mcp]` on the official
  MCP Python SDK 2.x). Tools: `validate_sql`, `explain_policy_decision`,
  `inspect_query_cost`, `get_policy_capabilities`. The role and tenant are fixed server-side,
  there is no execution and no database connection, internal detail is withheld, ungranted
  tables and columns are not disclosed, input is size-capped, and calls are rate-limited.
* An end-to-end test drives the real server over stdio with the SDK's `ClientSession`.
* Docs: `docs/guides/MCP_INTEGRATION.md`; threat model T17.

## [0.3.0] — 2026-10-24

### Added
* **Role inheritance** (`extends`): grants merge, explicit denies are sticky, and conflicts,
  unknown parents and cycles are load errors.
* **Policy metadata and identity:** `metadata.revision/owner/change_ticket`, a policy
  fingerprint, and a per-decision `decision_id`. Audit events add `policy_revision`,
  `policy_fingerprint`, `decision_id`, `correlation_id`, a literal-insensitive
  `query_fingerprint`, and `tenant_filter_rewrite`.
* **Policy CLI:** `policy template`, `policy diff` (effect classification,
  `--fail-on-relaxation`), `policy simulate` (`--against`, `--fail-on-change`),
  `policy explain` (decision or column access, with inheritance source).
* **Templates:** `minimal`, `multi_tenant_saas`, `analytics_readonly`.
* **Opt-in AST tenant-filter rewrite** (`sqlguard_ninja.tenancy`,
  `SQLCheckpoint(rewrite_tenant_filters=True)`) with re-validation and refusal rules (ADR-011).
* Docs: `docs/guides/POLICY_AS_CODE.md`; ADR-011, ADR-012; threat model T6a/T6b.

### Compatibility
* Policy files without the new fields behave exactly as before. `ValidationResult` gains
  fields with defaults.

## [0.2.0] — 2026-10-24

### Added
* **Lineage-aware privacy** (`core/lineage.py`). An `aggregate_only` column projected raw in a
  CTE or derived table is accepted only when every downstream consumer aggregates it
  statistically. Whole-row use, filters, ordering, windows, MIN/MAX and a raw use by any
  consumer stay denied (issue #8).
* **Tenant push-down.** An outer tenant pin on an unmodified projection of the tenant column
  satisfies the inner read when the inner scope has no aggregation, window, LIMIT, OFFSET or
  FETCH and every consumer pins it, recursively (issue #9).
* The small-cohort check follows identifiers through CTEs and derived tables, so the lineage
  relaxation cannot bypass it (found by new boundary case LIN-012).
* Privacy findings carry structured lineage metadata (base column, JSON path, scope, labels).
* Benchmark: `internal` / `independent` dataset tiers, flag basis (policy vs unsupported SQL),
  F1, 95% Wilson intervals, throughput, CSV output (`--csv`), per-file SHA-256 dataset hashes
  in results and `sqlninja dataset stats`.
* Approved-relabel workflow: `LABEL_CHANGES.yaml` (CODEOWNERS-protected) lists reviewed label
  changes; `benchmark compare --approved-label-changes` / `ci.approved_label_changes`.
* Corpus 1.1.0: 21 lineage boundary cases; 2 approved relabels (PRV-026, TEN-021).

### Changed
* Decisions changed for exactly two corpus cases (PRV-026, TEN-021: deny → allow); all other
  1,042 evaluations are unchanged.

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
