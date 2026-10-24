# Implementation progress

| Phase | Status | Commit | Tests | Notes |
|---|---|---|---|---|
| 0 Audit and checkpoint files | IMPLEMENTED | 375c52f^ | — | baseline v0.1.1 verified: clean tree, main@5206e96, PyPI 0.1.1 |
| 1a Benchmark tiers, basis, F1, Wilson CIs, throughput, CSV, hashes | RELEASED v0.2.0 | 375c52f | focused + full gate | |
| 1b Lineage: aggregate-only through CTEs, tenant push-down, small-cohort through derived scopes | RELEASED v0.2.0 | 8b59a38 | corpus 1.1.0 (21 boundary cases), 11 unit tests | LIN-012 found a real bypass of the small-cohort rule before release; fixed |
| 2a Role inheritance (sticky denies), revision/fingerprint, decision ids, audit fields | VERIFIED (local) | 2f1919c | test_policy_inheritance (11) | |
| 2b Policy diff/simulate/explain/templates CLI | VERIFIED (local) | e64859a | test_policy_tools (21) | |
| 2c Opt-in AST tenant-filter rewrite + checkpoint | VERIFIED (local) | b0b5ade | test_tenant_rewrite (32, executes on SQLite, tenants 1-3) | |
| 2d Docs, ADR-011/012, v0.3.0 bump | RELEASED v0.3.0 | 198a308 | full gate 1,804 passed, 94% | |
| 3 MCP server (stdio, validation-only) | RELEASED v0.4.0 | ecec4da | 9 tests incl. real SDK client; published-package stdio smoke test | version targets adapted |
| 4 MySQL tested dialect; SQL Server/Oracle experimental; compatibility matrix | RELEASED v0.5.0 | de4d03f | full gate 1,881 passed, 94%; CI MySQL 8.4: 15 passed, 0 skipped | sql_mode parser differential found and closed (T18) |
| 5 Observability: OTel spans, Prometheus metrics, audit schema, SARIF scan, Grafana + synthetic stack | VERIFIED (local, CI pending) | see PR | full gate 1,916 passed, 94% | redaction leak (hex/E''/$$/U&/N''/INTERVAL) found and fixed (T19) |
