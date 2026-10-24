# Known limitations

Static SQL inspection is one layer. It does not replace database permissions, row-level
security, statement timeouts, resource limits or authentication.

## Scope
* Read-only workloads only (v0.1). All writes are denied.
* Dialects: PostgreSQL, SQLite and MySQL 8 are tested (MySQL within the scope in
  `docs/guides/DATABASE_COMPATIBILITY.md`). SQL Server and Oracle are parser-level
  **experimental**; Oracle denies everything against a lower-case catalog. Other sqlglot
  dialects are untested.
* MySQL identifier case is not folded: `o.ID` or `Orders` is denied even where MySQL would
  accept it. MySQL execution supports named placeholders with integer or plain string values
  only.
* Policy identifiers are matched in lower case. Quoted mixed-case table names
  (`"Orders"` in PostgreSQL) are treated as unknown tables and denied.

## Analysis
* Tenant push-down covers only unmodified projections in scopes without aggregation, windows
  or row limits. Other outer filters (for example on an aggregated CTE) do not pin the inner
  read, which is safe but can give false positives. Predicates under `OR`/`NOT` are ignored.
* Lineage follows CTEs and derived tables, not views or functions. A raw projection that
  reaches a statistical aggregate only through an expression in a non-SELECT clause is
  denied (safe, possibly a false positive).
* Small-cohort protection is heuristic: it flags filters/grouping on columns marked
  `identifying`. k-anonymity / minimum group size is not enforced.
* JSON paths are recognised for `->`, `->>`, `#>>` and `json_extract` with literal paths.
  Dynamic keys are treated as reading the whole document.
* User-defined functions are unknown to the parser. By default they only produce a warning;
  use `functions.mode: allowlist` in production.
* Static cost scores are heuristics based on catalog row estimates, not runtime predictions.

## Integrations
* Retry lock-out is keyed on `RequestContext.trace_id`. If the application does not supply a
  stable conversation id, every request is a new trace and lock-out has no effect.
* `ApprovalQueue` and audit sinks are in-process. Multi-instance deployments need a shared
  store (implement the `Approver` / `AuditSink` protocols).
* The bundled executors are minimal; production deployments should use their own pooled,
  least-privilege connections.

## Observability
* Telemetry covers the guard and the checkpoint. Spans and metrics from custom rules are the
  rule author's responsibility, and their exception *types* are recorded.
* `sql_redacted` is withheld (`null`) whenever redaction cannot be proven complete, so some
  audit events have no redacted SQL.
* Audit events contain the principal and tenant by design. `sql_sha256` of a short query with
  a guessable secret can be brute-forced, so treat audit logs as sensitive.
* `sqlninja scan` splits files on top-level semicolons. Procedural blocks, client meta-commands
  (`\i`, `GO`) and templated SQL are not understood and are reported as findings.

## Playground
* The playground validates in the SQLite dialect against a synthetic schema. It is a
  demonstration, not a hosted SQL service.
* Server-mode rate limits are per process. Use edge limits when running several replicas.
* The static build downloads about 16 MB (Pyodide) on first load.

## Query cost
* The static score uses declared `estimated_rows`; the planner uses real statistics. They
  can disagree, and neither predicts runtime.
* Plan inspection is PostgreSQL-only (not MySQL).

## Benchmark
* The corpus is authored by this project. Allow labels are validated by execution on SQLite
  and PostgreSQL 16, but it is not an external standard, and the native engine was
  developed alongside it.
* Missing benchmark categories. The benchmark corpus does not contain cases for two categories: **restricted functions** (e.g. calls to server file-access, sleep, dynamic-SQL or administrative functions) and **system catalogs** (PostgreSQL `pg_catalog`/`information_schema`, SQLite `sqlite_master`/`sqlite_schema`, in qualified, joined, CTE and nested positions). The corresponding rules (`function.*`, `catalog.system_object`) ship and run by default; their mechanics are unit-tested with fictitious function names, but their detection is not measured by the benchmark.
* External tools are compared through a documented, conservative policy translation.

## Security scope
* SQLGuard Ninja does not guarantee protection against SQL injection or data leakage. It
  validates SQL against a declared policy; database-native controls remain authoritative.

## Packaging
* In 0.1.0 the README links were relative and broke on the PyPI page; fixed in 0.1.1.
* The runnable examples live in the repository and are not part of the wheel.

## Benchmark validity
* See docs/guides/BENCHMARK_BIAS_REVIEW.md. No independently sourced (external) evaluation set
  exists yet; intake rules are in benchmarks/datasets/external/README.md.
