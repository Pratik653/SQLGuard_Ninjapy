# Test evidence

| Date | Scope | Command | Result |
|---|---|---|---|
| 2026-10-24 | Baseline (v0.1.1) | `pytest --cov` | 1,655 passed, 95% (local, Python 3.11) |
| 2026-10-24 | v0.2.0 candidate | full gate (`ruff`, `mypy`, corpus `--check`, `pytest --cov`, build, `twine check`) | 1,738 passed, 94% branch coverage; twine PASSED |
| 2026-10-24 | Benchmark, corpus 1.1.0 | `sqlninja benchmark run --dataset builtin:v1` (4 adapters) | see docs/benchmarks/RESULTS_v1.1.md |
| 2026-10-24 | v0.2.0 PR #17 | CI run on PR | 12/12 jobs green; gate: baseline from main, 4 approved relabels, 0 regressions |
| 2026-10-24 | v0.2.0 main | CI run 40107938223 on 8b59a38 | success |
| 2026-10-24 | v0.2.0 publish | release.yml run 40108113801 | build + publish success; wheel and sdist with PEP 740 provenance; 0.1.0 and 0.1.1 unchanged |
| 2026-10-24 | v0.2.0 fresh install | `pip install --no-cache-dir --index-url https://pypi.org/simple sqlguard-ninja==0.2.0` (Python 3.13, outside repo) | import from site-packages; lineage allow/deny and tenant push-down via CLI; bundled benchmark 1,044 evaluations with CSV, tiers, 14 file hashes |
| 2026-10-24 | v0.3.0 candidate | full gate | 1,804 passed, 94%; build + twine PASSED; 3 templates in wheel |
| 2026-10-24 | v0.3.0 release | PR #19 12/12; main CI on 198a308 success; release.yml run 40115952065 success | PyPI files with provenance |
| 2026-10-24 | v0.3.0 fresh install | pip from PyPI, Python 3.13, outside repo (3rd attempt; CDN lag) | templates, policy check/explain (inheritance), tenant rewrite, decision metadata OK |
| 2026-10-24 | v0.4.0 candidate (MCP) | tests/integration/test_mcp_server.py | 9 passed, including a real stdio ClientSession |
| 2026-10-24 | v0.4.0 release | PR #20 12/12; main CI on ecec4da success; release.yml run 40117676554 success | wheel and sdist on PyPI, both provenance endpoints 200; 0.1.0-0.3.0 unchanged |
| 2026-10-24 | v0.4.0 fresh install + MCP stdio | `pip install --no-cache-dir "sqlguard-ninja[mcp]==0.4.0"` (Python 3.13, outside repo, 4th attempt; CDN lag), then SDK `stdio_client`/`ClientSession` against installed `sqlninja mcp` | 4 tools; allow/deny/cross-tenant deny; 100,001-char input `invalid_input`; forged `role` argument has no effect (deny); capabilities hide denied tables, `read_only: true`; no finding detail leaked |
| 2026-10-24 | v0.5.0 candidate (MySQL) | full gate (`ruff`, `mypy`, corpus `--check`, `pytest --cov -m "not mysql"` incl. embedded PostgreSQL, build, `twine check --strict`) | 1,881 passed, 94%; twine PASSED; corpus 1.2.0: 1,070 evaluations, 4 adapters regenerated |
| 2026-10-24 | v0.5.0 release | PR #22 13/13 (MySQL job: 15 passed, 0 skipped); MySQL job added to required checks; main CI 40119298660 on de4d03f success; release.yml 40119480081 success | wheel and sdist on PyPI, both provenance endpoints 200; 0.1.0-0.4.0 unchanged |
| 2026-10-24 | v0.5.0 fresh install | `pip install --no-cache-dir "sqlguard-ninja[mysql]==0.5.0"` (Python 3.13, outside repo, `-I`; 2nd attempt) | PyMySQL 1.2.3; dialects include mysql; bundled corpus 1.2.0, 26 MySQL cases 0 mismatches; binding and sql_mode refusals; `o.ID` and card column denied. No MySQL server locally, so execution is evidenced by CI only |
| 2026-10-24 | v0.6.0 candidate (observability) | full gate (`ruff`, `mypy`, corpus `--check`, `pytest --cov -m "not mysql"`, build, `twine check --strict`) | 1,916 passed, 94%; twine PASSED; SARIF schema-valid; canary privacy tests over 13 literal forms |
