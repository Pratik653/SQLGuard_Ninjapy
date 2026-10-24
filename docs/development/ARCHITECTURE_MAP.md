# Architecture map (for maintainers and resumed sessions)

_Refresh only the sections an architectural change touches._

## Pipeline

`Guard.validate(sql, role, dialect, context)` (`core/guard.py`)
1. preflight: empty, length, invalid characters
2. `core/analysis.analyse()`: sqlglot parse → `qualify` → `traverse_scope`. It produces
   `QueryAnalysis` (per-scope `TableRef`s, `ColumnRef`s with clause, aggregate kind and JSON
   path; functions; unresolved columns; unexpandable stars; join count; depth).
3. rules (`core/rules/*`, `privacy/rules.py`, `query_cost/static.py`) → `Finding`s
4. `findings.combine()` → `Decision` (deny > review > allow) → `ValidationResult`

## Modules

| Area | Path | Notes |
|---|---|---|
| Policy schema v1 | `policy/model.py` | Pydantic; `Policy.from_file`; roles, labels, catalog, limits, cost |
| Analysis | `core/analysis.py` | the only SQL parser; reuse it, never add a second |
| Rules | `core/rules/{statements,catalog,functions,access,tenant,structure}.py` | `Rule` protocol (`rule_ids`, `check(ctx)`) |
| Privacy | `privacy/rules.py`, `privacy/suggest.py` | `resolve_column_access()` |
| Cost | `query_cost/static.py`, `query_cost/postgres.py` | EXPLAIN only on ALLOWed SQL |
| Integrations | `integrations/{checkpoint,audit,executors,langchain,langgraph,fastapi}.py` | `SQLCheckpoint` is the authorization point |
| Benchmark | `benchmarking/{dataset,adapters,translate,runner,metrics,compare,fixtures,builtin}.py`, `workers/` | result schema `sqlninja.benchmark-result/1` |
| Reporting | `reporting/markdown.py` | |
| CLI | `cli/main.py`, `cli/config.py`, `cli/templates.py` | argparse; `sqlninja` |

## Commands

| Purpose | Command |
|---|---|
| Dev install | `python -m pip install -e ".[dev]"` (venv: `.venv`, Python 3.11) |
| Gate | `ruff check src tests scripts examples && ruff format --check src tests scripts examples && mypy && python scripts/generate_corpus.py --check && pytest --cov=sqlguard_ninja` |
| PostgreSQL tests | embedded via `pgserver` locally; `SQLNINJA_PG_DSN` in CI |
| Benchmark | `sqlninja benchmark run --dataset builtin:v1` |
| Build | `python -m build && twine check --strict dist/*` |
| Release | PR → merge (protected `main`) → annotated tag `vX.Y.Z` → `gh release create` → `release.yml` (OIDC) |

On Windows, `gh` is at `%LOCALAPPDATA%\Microsoft\WinGet\Packages\GitHub.cli_*\bin\gh.exe`, and
its token lives in the Windows keyring, so run it from PowerShell, not the sandboxed bash.

## Boundaries

* The parser is sqlglot 30.x only, pinned to that major.
* Trust boundary: `RequestContext` is built by the application, never by the model.
* The executors in `integrations/executors.py` run read-only sessions.
