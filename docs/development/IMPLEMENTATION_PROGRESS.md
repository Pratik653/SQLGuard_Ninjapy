# Implementation progress

| Phase | Status | Commit | Tests | Notes |
|---|---|---|---|---|
| 0 Audit and checkpoint files | IMPLEMENTED | 375c52f^ | — | baseline v0.1.1 verified: clean tree, main@5206e96, PyPI 0.1.1 |
| 1a Benchmark tiers, basis, F1, Wilson CIs, throughput, CSV, hashes | RELEASED v0.2.0 | 375c52f | focused + full gate | |
| 1b Lineage: aggregate-only through CTEs, tenant push-down, small-cohort through derived scopes | RELEASED v0.2.0 | 8b59a38 | corpus 1.1.0 (21 boundary cases), 11 unit tests | LIN-012 found a real bypass of the small-cohort rule before release; fixed |
