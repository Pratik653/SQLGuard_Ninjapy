# Next actions (development program)

1. Merge the v0.5.0 (MySQL) PR once the MySQL CI job passes, add that job to the required checks, release, and verify PyPI and a fresh `[mysql]` install.
2. SQL Server/Oracle real-database tests need vendor licence acceptance (maintainer decision); MySQL function/catalog cases stay under #5.
3. Phase 5: OpenTelemetry/Prometheus extras, SARIF output (#14), Grafana dashboard JSON.
4. Phases 6-8: playground UI on the FastAPI backend, Docker/Kubernetes reference, public demo (hosting needs maintainer authorization).
