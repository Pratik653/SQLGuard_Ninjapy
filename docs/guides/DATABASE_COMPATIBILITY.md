# Database compatibility matrix

"Supported" means automated tests exercise the dialect end to end, including executing the
corpus's `allow` cases on a real server. Anything less is labelled explicitly. Treat
experimental dialects as unsupported for security decisions.

| Dialect | Parser | Real database tests | Policy coverage in corpus | Query-cost | Executor | Status |
|---|---|---|---|---|---|---|
| PostgreSQL | sqlglot `postgres` | PostgreSQL 16: service container and Docker Compose in CI, embedded locally | full corpus (dialect-tagged cases) | static score + `EXPLAIN (FORMAT JSON)` inspector | `psycopg_executor` (read-only transaction, statement timeout) | **Supported** |
| SQLite | sqlglot `sqlite` | in-process fixture database in every test job | full corpus | static score | `sqlite_executor` (`PRAGMA query_only`) | **Supported** |
| MySQL 8 | sqlglot `mysql` | MySQL 8.4 service container in CI (`tests/integration/test_mysql.py`) | 26 MySQL-specific cases (`cases/09_mysql.yaml`); shared semantics via the engine | static score (no planner integration) | `mysql_executor` (`START TRANSACTION READ ONLY`, `MAX_EXECUTION_TIME`, AST-based binding) | **Supported for the tested scope** (see notes) |
| SQL Server (T-SQL) | sqlglot `tsql` | none | parser-level smoke tests only | static score | none | **Experimental** |
| Oracle | sqlglot `oracle` | none | parser-level smoke tests only | static score | none | **Experimental** |
| Others (Snowflake, BigQuery, ...) | sqlglot | none | none | static score | none | **Untested** |

## MySQL notes

* **Identifier case is not folded.** MySQL column names are case-insensitive, but table-name case
  sensitivity depends on `lower_case_table_names` and the file system. Folding could merge
  distinct tables, so the guard compares identifiers exactly and **fails closed** on mixed-case
  references (`o.ID` is denied: a documented false positive). Use lower-case identifiers in
  policies and queries.
* **Placeholders.** Use named placeholders (`:tenant_id`). The MySQL executor replaces approved
  placeholders through the AST with literals of the trusted context values (integers, or
  strings with quotes doubled; strings containing a backslash or NUL are refused), then runs
  the statement without driver format parameters (ADR-013). PyMySQL's `%s` style cannot be
  parsed, so the guard denies it.
* **Session `sql_mode`.** The guard lexes MySQL with the server defaults. `ANSI_QUOTES` (`"x"`
  becomes a column), `NO_BACKSLASH_ESCAPES` (a string ends at a different place),
  `PIPES_AS_CONCAT`, `HIGH_NOT_PRECEDENCE` and `ANSI` would make the server read validated SQL
  differently, so `mysql_executor` refuses to run on such a session (`UnsafeSessionError`). If you
  write your own executor, check `@@SESSION.sql_mode` with `check_sql_mode` first.
* **Dialect rules.** Executable comments (`/*! ... */`) are denied. `REPLACE`, `HANDLER`, `SET`,
  locking reads and `INTO OUTFILE` are denied (some because they fail to parse, which fails
  closed).
* **Not covered:** MySQL-specific function and catalog benchmark cases (issue #5), and MySQL plan
  inspection.

## SQL Server and Oracle

Real-database testing would need the vendors' free container images (SQL Server Developer /
Express, Oracle Database Free). Each requires accepting the vendor's licence terms. That is a
maintainer decision, so it has not been done. Until then:

* the guard parses these dialects through sqlglot, and parser-level smoke tests check that
  writes, multi-statement input and tenant violations are denied
  (`tests/unit/test_experimental_dialects.py`);
* identifier quoting, function naming, catalogs and session statements specific to these
  engines are **not** verified;
* **Oracle folds unquoted identifiers to UPPER case**, so a lower-case policy catalog matches
  nothing and every query is denied (fail closed). Oracle needs case-aware policy name
  mapping before it can be supported;
* the MCP server and `SUPPORTED_DIALECTS` do not accept them.
