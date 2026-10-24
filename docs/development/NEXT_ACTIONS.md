# Next actions (development program)

1. SQL Server/Oracle real-database tests need vendor licence acceptance (maintainer decision); MySQL function/catalog cases stay under #5.
2. Merge the v0.6.0 (observability) PR after CI incl. the new observability job; add that job to required checks; release; verify PyPI + fresh `[otel,prometheus]` install.
3. Phase 6: interactive demo on the FastAPI backend (three roles, editor, explanations, lineage, benchmark dashboard, browser e2e tests).
4. Phases 7-8: Docker/Kubernetes reference, public demo (hosting needs maintainer authorization).
