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
