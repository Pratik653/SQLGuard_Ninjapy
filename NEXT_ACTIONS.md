# Next actions

_Updated 2026-10-24. On resume: read IMPLEMENTATION_STATUS.md, run
`.venv/Scripts/python -m pytest -q` and `git log --oneline`, then continue from the top._

## Release

v0.1.1 (latest) and v0.1.0 are published on GitHub and PyPI and verified (RELEASE_CHECKLIST.md).
`main` is protected: every change goes through a pull request with the 11 required checks.

## Maintainer actions

1. Enable "Block command line pushes that expose my email" (GitHub → Settings → Emails).
2. Turn on "Require review from Code Owners" once a second maintainer exists.
3. Delete the local `backup/pre-email-rewrite` branch when the old history is no longer needed (never pushed).

## Tracked work

All outstanding engineering work is filed as GitHub issues #5–#15 (benchmark coverage and
external dataset, corpus diversity, lineage-aware privacy, tenant push-down, function presets,
MySQL, upstream bug report, CI runner and Dependabot review, SARIF, governed writes).

## Engineering backlog

3. Restricted-function and system-catalog benchmark categories (maintainer-authored cases).
4. Independent held-out corpus written by people outside the project.
5. Lineage-aware aggregate-only checks; tenant predicate push-down into CTEs.
6. Function allowlist presets for PostgreSQL/SQLite analytics.
7. Propose the agent-sql-guard `PiiDenylist.from_mapping` default fix upstream.
