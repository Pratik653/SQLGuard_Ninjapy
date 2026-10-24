# Query cost analysis

Two complementary signals. Both are **risk indicators, not guarantees** of runtime or
resource use. Always configure `statement_timeout` in the database.

## 1. Static score (always available, every dialect)

`StaticCostRule` is part of the default guard. It adds documented factor weights (capped at
100) using catalog `estimated_rows`:

| Factor | Points |
|---|---|
| Cartesian join (no ON/USING and no linking WHERE equality) | 25, or 40 when a side is large |
| Large table read without WHERE | 25 per alias |
| Large result possible, no LIMIT on the outer query | 10 |
| ORDER BY on large input without LIMIT | 10 |
| DISTINCT over large input | 5 |
| Leading-wildcard LIKE / regex filter on a large table | 10 / 5 |
| Subquery in the SELECT list over a large table | 10 |
| Large self-join | 10 |
| More than three joins | 5 per extra join |
| Nesting deeper than two levels | 5 per extra level |
| Recursive CTE / recursive arm without a WHERE | 30 / +30 |
| Row generator with a bound ≥ 1,000,000 / non-literal bound | 60 / 40 |
| String-allocation function with a size ≥ 1,000,000 | 60 |

`review_score` (default 50) → REVIEW and `deny_score` (default 80) → DENY. Tables without
`estimated_rows` are listed as unknown, and size factors are skipped for them.

Role `limits` (`max_joins`, `max_subquery_depth`, `max_limit`, `require_limit`) are hard
structural rules, separate from the score.

## 2. PostgreSQL planner estimate (optional)

```python
import psycopg
from sqlguard_ninja.query_cost.postgres import PostgresPlanInspector

inspector = PostgresPlanInspector(guard, lambda: psycopg.connect(READER_DSN))
report = inspector.inspect(
    sql, role="support_analyst", context={"tenant_id": 1}, params={"tenant_id": 1}
)
report.total_cost, report.plan_rows, report.static.score, report.findings
```

Safety properties, each covered by a test:

* Only `EXPLAIN (FORMAT JSON)` runs, never `ANALYZE`. A query that would divide by zero on
  every row plans without error, which shows it was not executed.
* Only ALLOWed statements reach the planner (`PlanInspectionRefused` otherwise). Planning can
  still evaluate immutable functions during constant folding, which is why the function
  policy runs first.
* `READ ONLY` transaction, local `statement_timeout`, forced rollback.
* Use a least-privilege role. The tests use a SELECT-only role.

Thresholds: `cost.max_plan_total_cost` and `cost.max_plan_rows` → REVIEW findings. Large
sequential scans and nested loops are reported as warnings.

### Why compare both

The static score uses *declared* production sizes. The planner uses the *actual* statistics
of the database it connects to. On the 200-row fixture database, the planner reports a tiny
cost for queries that the static score flags for a 10M-row production table. Choose the
signal that matches the environment you inspect against.

## Environments

* `docker compose -f docker/docker-compose.yml up -d`, then set
  `SQLNINJA_PG_DSN=postgresql://postgres:sqlninja-dev@localhost:55432/postgres`.
* Or `pip install pgserver` for an embedded server (used for local development here).
* SQLite-only users can rely on the static score; all non-PostgreSQL tests run without a
  database server.
