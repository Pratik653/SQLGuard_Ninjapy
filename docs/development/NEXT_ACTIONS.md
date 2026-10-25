# Next actions (development program)

1. SQL Server/Oracle real-database tests need vendor licence acceptance (maintainer decision); MySQL function/catalog cases stay under #5.
2. Demo is live at https://pratik653.github.io/SQLGuard_Ninjapy/; redeploy with pages.yml after demo changes. Remaining program work: issue #6 (independent dataset), issue #5 (function/catalog cases), SQL Server/Oracle database testing (needs licence approval).
3. v0.8.0: merge PR after CI (PostgreSQL + MySQL SQLi suites), release, verify PyPI provenance and a fresh install; then stop feature work (no v0.9 automatically). Consider a GitHub Security Advisory for SQLI-001/002 (maintainer decision).
