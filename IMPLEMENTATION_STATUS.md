# Implementation status

_Updated 2026-10-24 (release candidate 0.1.0, audited — see docs/release/FINAL_TECHNICAL_AUDIT.md). Evidence only: a column is ticked only when
it is backed by tests or files in this repository._

Legend: ✅ done · 🟡 partial · ⬜ not started

| Workstream / component | Implemented | Tested | Integrated | Documented | Release-ready |
|---|---|---|---|---|---|
| Core engine (analysis, rules, guard) | ✅ | ✅ | ✅ | ✅ | ✅ |
| WS1 Benchmark corpus (530 cases / 1,002 evaluations) | 🟡 restricted-function and system-catalog categories missing | ✅ per-case pytest; allow-labels executed on SQLite and PostgreSQL 16 | ✅ | ✅ | 🟡 (gap documented) |
| WS1 Runner, metrics, adapters, compare, reports, CLI | ✅ | ✅ | ✅ | ✅ | ✅ |
| WS2 Checkpoint, approvals, audit, LangChain, LangGraph, FastAPI | ✅ | ✅ incl. tampering/retry/approval tests | ✅ | ✅ | ✅ |
| WS3 Privacy policy pack | ✅ | ✅ | ✅ | ✅ | ✅ |
| WS4 Static cost score | ✅ | ✅ | ✅ | ✅ | ✅ |
| WS4 PostgreSQL EXPLAIN inspector + Docker Compose | ✅ | ✅ inspector on embedded PostgreSQL 16; 🟡 Compose file only validated in CI (no Docker locally) | ✅ | ✅ | 🟡 |
| WS5 CI workflow + composite action | ✅ | ✅ 12/12 jobs green on GitHub (run 40089304432) | ✅ | ✅ | ✅ |

## Verification run (local, Windows 11, Python 3.11.9, 2026-10-24)

| Check | Result |
|---|---|
| `ruff check` / `ruff format --check` (src, tests, scripts, examples) | pass / pass (79 files) |
| `mypy` (strict, 43 files) | pass |
| `python scripts/generate_corpus.py --check` | pass (268 generated cases reproducible) |
| `pytest` | **1,649 passed**, 0 failed, 0 skipped (225 against PostgreSQL 16.2 via `pgserver`); Python 3.13: 1,424 passed, 225 PostgreSQL tests skipped |
| Branch coverage, `sqlguard_ninja` | **95%** |
| `actionlint` 1.7.12 on `.github/workflows/ci.yml` | pass |
| `python -m build` + clean install of the wheel on Python 3.13 | pass (`sqlninja --version`, `init`, `benchmark run`, `policy check`) |
| `pip-audit` on the installed dependency set | no known vulnerabilities |
| Secret scan of tracked files | none found |

Not verified locally: the full test suite on Python 3.12/3.13 and on Linux (CI matrix
covers these), Docker Compose (no Docker on this machine), and the optional real-LLM example
(needs a model API key).

## Benchmark (corpus v1.0.0)

| Validator | Recall | Precision | FPR | p95 ms |
|---|---:|---:|---:|---:|
| native 0.1.0 | 100.0% | 100.0% | 0.0% | 2.15 |
| sql-guardrail 0.5.2 | 98.6% | 86.6% | 21.2% | 1.72 |
| agent-sql-guard 0.2.0 | 67.9% | 86.6% | 14.5% | 1.26 |
| krish2105/sqlguard 0.1.0 | 65.8% | 91.4% | 8.6% | 1.22 |

The native score reflects a corpus co-developed with the engine (see RESULTS_v1.md).

## Defects found by tests and fixed (each has a regression test)

1. Unknown select-list column was allowed (`password AS password` matched its own alias).
2. `Guard.validate` raised `UnicodeEncodeError` on a lone surrogate (Hypothesis).
3. Dataset loader silently cleared a contradictory reason on an `allow` case.
4. Label error FMT-010: SQLite rejects a parenthesised top-level SELECT (now PostgreSQL-only).
5. Generic disclosure produced ungrammatical messages; enum compared by identity.
6. Quoted identifiers were lower-cased after qualification (PostgreSQL `"Orders"` matched `orders`).
7. A cast of the tenant column was accepted as a tenant pin (lossy for text ids).
8. Unbounded recursion and very large string allocation were under-weighted in the cost score.
9. agent-sql-guard worker: upstream `PiiDenylist.from_mapping` default bug worked around;
   `evaluate_static` CONFIRM semantics handled through the intended `evaluate()` API.
10. CLI crashed on cp1252 consoles.
11. LangGraph nodes did not receive the run config without a `RunnableConfig` annotation.
12. Shared SQLite connection unusable from FastAPI worker threads.
13. `compare` treated relabelled cases (deny→allow) as improvements; now a gated class.

Benchmark labels changed after evidence: FMT-010 (SQLite syntax), TEN-034 (context
default merge), CST-012 (self-join cost relabelled to review, rationale in the case).

## Open gaps

* Restricted-function and system-catalog **benchmark cases** are not authored. Writing
  them was stopped twice by an automated safety classifier, and I cannot produce that
  content. The rules are implemented. Their mechanics are unit-tested with fictitious
  function names (`tests/unit/test_function_policy_mechanics.py`), and the categories need
  maintainer-contributed cases.
* Released v0.1.0 and v0.1.1 (latest) on GitHub and PyPI; README links fixed in 0.1.1 (see RELEASE_CHECKLIST.md). Outstanding work tracked in issues #5–#15.
