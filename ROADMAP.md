# Roadmap

Items are ordered by priority. Nothing here is promised by date.

## Next (0.2)

* **Benchmark coverage:** restricted-function and system-catalog case categories (the rules
  already exist; contributions welcome).
* **Independent corpus:** cases written by people who did not build the engine, kept as a
  separate held-out set and reported separately.
* **Lineage-aware privacy:** allow `aggregate_only` columns that are aggregated in an outer
  scope, without weakening reference-based checks elsewhere.
* **Tenant predicate push-down:** accept an outer tenant filter on a CTE or derived table
  column that maps directly to the base tenant column.
* **Function allowlist presets** for PostgreSQL and SQLite analytics workloads.

## Later

* Governed writes (`UPDATE`/`DELETE` with mandatory tenant predicates and row-limit checks).
* Tested support for MySQL, Snowflake and BigQuery, each with dialect-specific corpus cases.
* Policy generation from database catalogs, with labels proposed for human review.
* ~~SARIF output for code-scanning integrations.~~ Shipped in 0.6.0 (`sqlninja scan --format sarif`).
* PyPI release once the API is reviewed by early users.

## Upstream

* agent-sql-guard: `PiiDenylist.from_mapping` rejects its own default when `substrings`
  is omitted (found while writing its benchmark worker). A fix could be proposed upstream.
