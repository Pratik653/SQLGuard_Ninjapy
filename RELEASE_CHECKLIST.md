# Release checklist — v0.1.0

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Personal email absent from publishable history (metadata + contents) | ✅ | 0 hits; commits use the GitHub-verified noreply address |
| 2 | Repo-local git identity set to noreply | ✅ | `git config --local user.email` |
| 3 | ruff check / format | ✅ | 79 files |
| 4 | mypy --strict | ✅ | 43 source files |
| 5 | Tests, Python 3.11 (Windows) incl. PostgreSQL 16.2 | ✅ | 1,649 passed, 0 failed |
| 6 | Tests, Python 3.13 (Windows) | ✅ | 1,424 passed, 225 PostgreSQL tests skipped (no pgserver build for 3.13) |
| 7 | Coverage (branch) | ✅ | 95% |
| 8 | Corpus reproducibility (`generate_corpus.py --check`) | ✅ | 268 generated cases |
| 9 | Build + `twine check` | ✅ | wheel and sdist PASSED |
| 10 | Clean wheel install smoke test | ✅ | Python 3.13 |
| 11 | pip-audit | ✅ | no known vulnerabilities |
| 12 | gitleaks (history) | ✅ | 6 commits, no leaks |
| 13 | gitleaks (directory) | ✅ | only false positives in git-ignored venvs |
| 14 | Private paths in tracked files | ✅ | none |
| 15 | Licence review | ✅ | THIRD_PARTY_NOTICES.md |
| 16 | Docs examples executable, links resolve | ✅ | tests/unit/test_docs.py |
| 17 | actionlint | ✅ | ci.yml |
| 18 | Restricted-function / system-catalog benchmark cases | ❌ | Not authored (see FINAL_TECHNICAL_AUDIT §6); documented as a limitation |
| 19 | Maintainer publication authorization | ✅ | given in chat (GitHub + PyPI) |
| 20 | GitHub repo created, pushed, public | ✅ | https://github.com/Pratik653/SQLGuard_Ninjapy — anonymous API: public, Apache-2.0 detected, `main` only |
| 21 | Public commit emails | ✅ | all commits: noreply address only (checked via the public API) |
| 22 | GitHub Actions, first run | ❌→fixed | run 40088280743: test matrix failed on an untracked results directory (`.gitignore` too broad); fixed in 08496a2 |
| 23 | GitHub Actions, all 12 jobs green | ✅ | run 40089006916 on 08496a2: tests 3.11/3.12/3.13 × Linux/Windows (1,423 passed, 3 skipped — external-tool tests, 92.87% coverage without PostgreSQL), PostgreSQL service 225 passed, Docker Compose 225 passed, gate, external validators, package build |
| 24 | Topics, private vulnerability reporting, Dependabot alerts, `pypi` environment | ✅ | configured via GitHub API |
| 25 | "Block command line pushes that expose my email" | ⏳ | maintainer setting (no API) |
| 26 | PyPI pending trusted publisher | ✅ | configured by maintainer; proven by a successful OIDC publish |
| 27 | Tag v0.1.0 + GitHub release + PyPI publish | ✅ | annotated tag `v0.1.0` → f5ac314dd87bea3be138c0f5b942cbf2d84d9efa; release https://github.com/Pratik653/SQLGuard_Ninjapy/releases/tag/v0.1.0; workflow run 40089832720 (build + publish succeeded); PyPI lists `sqlguard_ninja-0.1.0-py3-none-any.whl` and `sqlguard_ninja-0.1.0.tar.gz`, both with PEP 740 provenance |
| 28 | Fresh install from PyPI + smoke tests | ✅ | new venvs outside the repo, `--no-cache-dir --index-url https://pypi.org/simple`: core (Python 3.13) — import from site-packages, `--help`, README CLI and SDK examples, bundled 1,002-evaluation benchmark, init/run/baseline/compare; `[all]` (Python 3.11) — LangChain tool, LangGraph graph, FastAPI router (200/403), psycopg |
| 29 | CI on release commit | ✅ | run 40089304432 on f5ac314: 12/12 jobs succeeded |

Release commit: `f5ac314dd87bea3be138c0f5b942cbf2d84d9efa`. Later commits on `main` only update documentation.

# Release checklist — v0.1.1 (documentation and governance patch)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Local gate (ruff, format, mypy, corpus `--check`, pytest) | ✅ | 1,655 passed, 95% branch coverage |
| 2 | Build + `twine check --strict` | ✅ | wheel and sdist; long description has 0 relative links |
| 3 | Pull request with all required checks | ✅ | PR #4, run 40090989456: 12/12 jobs green (incl. gate reading the baseline from `main`) |
| 4 | Branch protection on `main` | ✅ | PRs required; 11 required checks, strict; enforced for admins; linear history; no force-push or deletion. Code-owner review not required while there is a single maintainer |
| 5 | CODEOWNERS | ✅ | `.github/CODEOWNERS` |
| 6 | CI on merged `main` | ✅ | run 40091146298 on bbebe6f: 12/12 |
| 7 | Tag + GitHub release | ✅ | annotated `v0.1.1` → bbebe6f462de2ddef76f78ecb39b447bca689fa8; https://github.com/Pratik653/SQLGuard_Ninjapy/releases/tag/v0.1.1 (marked latest) |
| 8 | PyPI publish (Trusted Publishing) | ✅ | run 40091303257; PyPI latest = 0.1.1; `sqlguard_ninja-0.1.1-py3-none-any.whl` (124,431 B) and `.tar.gz` (227,083 B), both with PEP 740 provenance |
| 9 | 0.1.0 preserved | ✅ | both 0.1.0 files unchanged (same sizes and SHA-256 prefixes), not yanked, still installable |
| 10 | PyPI page | ✅ | header "sqlguard-ninja 0.1.1"; README links resolve to GitHub |
| 11 | Fresh install, core (Python 3.13) | ✅ | `pip install --no-cache-dir --index-url https://pypi.org/simple sqlguard-ninja==0.1.1` outside the repo: import from site-packages, `--version`, `--help`, CLI deny/allow exit codes, SDK review decision, 1,002-evaluation bundled benchmark, init/run/baseline/compare |
| 12 | Fresh install, `[all]` (Python 3.11) | ✅ | LangChain tool, LangGraph graph, FastAPI router (200/403), psycopg 3.3.6 |
| 13 | Issues for outstanding work | ✅ | #5–#15 |

Note: the first fresh-install attempt saw only 0.1.0 through a stale CDN index entry seconds
after publication; a retry minutes later in a new venv installed 0.1.1.
