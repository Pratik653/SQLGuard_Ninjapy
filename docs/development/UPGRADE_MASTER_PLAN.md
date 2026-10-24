# Upgrade master plan (nine workstreams)

Status values: NOT_STARTED · IN_PROGRESS · IMPLEMENTED · VERIFIED · RELEASED · BLOCKED.
Machine-readable tracker: [`progress.json`](progress.json).

| # | Workstream | Target | Depends on | Key acceptance |
|---|---|---|---|---|
| 1 | Independent benchmarking: dataset tiers, provenance, hashes, F1/CI/throughput, CSV | v0.2.0 | — | internal vs external reported separately; reproducible; no self-authored data labelled independent |
| 2 | Lineage-aware privacy and tenant push-down | v0.2.0 | 1 | CTE/nested lineage tests; derived sensitive outputs protected; fail closed |
| 3 | Policy-as-code: inheritance, templates, validate/simulate/diff/explain, audit metadata | v0.3.0 | 2 | invalid configs rejected; diffs reviewable; tenant regression tests |
| 4 | MCP server (stdio), validation-only tools | v0.3.0 | 3 | real MCP client discovers and calls tools; no credentials in tool arguments |
| 5 | Dialects: MySQL tested in CI; SQL Server/Oracle parser-level experimental | v0.4.0 | 1 | matrix truthful; dialect tests automated |
| 6 | Observability: OpenTelemetry, Prometheus, SARIF, Grafana | v0.4.0 | 3 | optional extras; no literals in telemetry |
| 7 | Web dashboard and policy playground | v0.5.0 | 2, 3 | browser e2e smoke tests |
| 8 | Deployment: container, Compose, Kubernetes examples, health checks | v0.5.0 | 7 | Compose starts in CI; manifests validated |
| 9 | Public zero-API-key demo | v0.5.0 | 7, 8 | public URL verified unauthenticated; needs maintainer hosting authorization |

v1.0.0 is not planned until independent evaluation exists and the stability criteria are met.

## Constraints carried forward

* No new adversarial SQL corpora in function/catalog categories (blocked by the safety
  classifier; tracked in issue #5). External datasets only with verified licence and provenance
  (issue #6).
* `main` is protected: PRs, 11 required checks. Releases use Trusted Publishing.
