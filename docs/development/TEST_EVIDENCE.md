# Test evidence

| Date | Scope | Command | Result |
|---|---|---|---|
| 2026-10-24 | Baseline (v0.1.1) | `pytest --cov` | 1,655 passed, 95% (local, Python 3.11) |
| 2026-10-24 | v0.2.0 candidate | full gate (`ruff`, `mypy`, corpus `--check`, `pytest --cov`, build, `twine check`) | 1,738 passed, 94% branch coverage; twine PASSED |
| 2026-10-24 | Benchmark, corpus 1.1.0 | `sqlninja benchmark run --dataset builtin:v1` (4 adapters) | see docs/benchmarks/RESULTS_v1.1.md |
