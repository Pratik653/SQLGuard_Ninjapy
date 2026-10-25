# SQL injection: landscape of existing tools (verified 2026-10-25)

Repository facts come from the GitHub API on 2026-10-25: licence (SPDX as reported, or the
licence file where SPDX says `NOASSERTION`), archived state, and last push. Capabilities and
limitations come from each project's own documentation. "Verified limitation" means stated by
the project or reproduced here. Nothing below claims a bypass of another tool.

| Tool | What it actually does | Category | Licence / status | Documented limitations | Where SQLGuard Ninja complements it |
|---|---|---|---|---|---|
| [libinjection](https://github.com/libinjection/libinjection) | Tokenizes an **input value**, folds the tokens, and matches the first few against a table of known-bad fingerprints | Runtime **detection** (heuristic) | BSD-3-Clause; active (pushed 2026-10-17) | Not a SQL parser. It looks at only the first five folded tokens, so a filler prefix can push a payload out of the window. Generic fragments such as `or 1=1` are missed, and SQL-looking prose can be flagged. The project says "a miss is not proof of safety". | It classifies input strings. SQLGuard Ninja instead keeps values out of the SQL structure (driver binding) and authorizes the statement's structure. |
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | Automated discovery and exploitation of injectable parameters in a running application | **Offensive testing** | GPL-2.0-or-later with exceptions (COPYING); active | It finds vulnerabilities; it does not prevent them. Use it only against systems you are authorized to test. | It was not run in this release. The suite here exercises the library API against local synthetic databases instead (no network targets). |
| [sql-guardrail](https://github.com/nickusevich/sql-guardrail) | Validates LLM-generated SQL against a policy before execution | **Authorization** of SQL text | MIT; pushed 2026-06-09 | No parameter-binding API; it works on SQL text. | Same layer as SQLGuard Ninja's Guard. SQLGuard Ninja adds driver-bound execution and tenant ownership of parameters. |
| [sakura-sky/sql-guard](https://github.com/sakura-sky/sql-guard) | Deterministic policy engine for LLM-generated SQL on sqlglot | **Authorization** | Apache-2.0 is declared in `pyproject.toml`, but the repository has no licence file (GitHub reports none) | Text-level policy. No execution or binding layer. | As above. Both depend on sqlglot, so the parser divergences found here (SQLI-001/002) are worth checking in any sqlglot-based guard. That has **not** been tested against sql-guard. |
| [Bandit B608](https://bandit.readthedocs.io/en/latest/plugins/b608_hardcoded_sql_expressions.html) | Flags SQL-looking strings built with `%`, `+`, `.format()`, f-strings or `str.replace` | **Static source scanning** | Apache-2.0; active | Pattern-based. LOW confidence by default, MEDIUM when the string reaches `execute`. It reports likely vectors, not confirmed injections. | Finds unsafe construction in application code. `execute_safe` gives that code a safe alternative. |
| [Semgrep rules](https://github.com/semgrep/semgrep-rules) (`python/lang/security/audit/formatted-sql-query`, `sqli/…`) | Pattern rules for formatted SQL reaching DB calls | Static source scanning | Semgrep Rules License v1.0 (not OSI) | Pattern-based; per-rule false positives and negatives. | Same as Bandit. |
| [CodeQL `py/sql-injection`](https://github.com/github/codeql/tree/main/python/ql/src/Security/CWE-089) | Taint tracking from remote sources to SQL execution sinks | Static source scanning (dataflow) | MIT (queries) | Depends on modelled sources and sinks. Not runtime. | Same: complementary. |
| `sqlsafe` | Two unrelated repositories use the name: [kriskimmerle/sqlsafe](https://github.com/kriskimmerle/sqlsafe) (MIT, single-file AST scanner with 15 rules, 0 stars, last push 2026-02-03) and alikesk222/sqlsafe (MIT, a "risk scorer") | Static scanning / scoring | MIT | Neither appears to be widely adopted, and no canonical project could be identified, so no capability claims are made. | Not compared. |
| [SQLAlchemy](https://github.com/sqlalchemy/sqlalchemy) `text()` / Core | Bound parameters (`:name`) passed to the DBAPI driver | **Prevention** (construction API) | MIT | Identifiers cannot be bound. `text()` with string formatting is still unsafe. | Uses the same `:name` convention. SQLGuard Ninja adds policy authorization and tenant ownership on top. |
| [psycopg 3](https://www.psycopg.org/psycopg3/docs/basic/from_pg2.html) | **Server-side binding**: query and values are sent separately (extended protocol). `ClientCursor` interpolates on the client instead. | Driver | LGPL-3.0 | Values only. `SET`, `NOTIFY` and DDL can't take parameters. Identifiers need `psycopg.sql`. | Used by `PsycopgSafeExecutor`, which refuses client-side cursors. |
| [PyMySQL](https://github.com/PyMySQL/PyMySQL) | **Client-side** binding: `cursor.execute(sql, args)` escapes each value and formats `%(name)s` once | Driver | MIT | No server-side prepared statements. String escaping follows the server's `NO_BACKSLASH_ESCAPES` status flag, and bytes are sent as `X'..'` (verified in `connections.py`). | Used by `MySQLSafeExecutor`, which additionally requires a UTF-8 connection charset and refuses lexing-changing `sql_mode` flags. |
| Python `sqlite3` | Native `sqlite3_bind_*` binding for `?`, `:name`, `@name`, `$name` | Driver | PSF | Binds all four markers. sqlglot parses `$name` as a column (SQLI-008). | `execute_safe` accepts only `:name`, so the guard and the driver agree. |
| [OWASP SQLi Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | Guidance | — | CC-BY-SA-4.0 | Primary defences: parameterized queries, safe stored procedures, and allowlists for identifiers and `ASC`/`DESC`. Escaping is strongly discouraged. Least privilege limits damage but does not prevent injection. | `execute_safe`, `safe_identifier` / `safe_order_by`, read-only executors, and least-privilege guidance follow this ordering. |

## Summary

* **Detection** (libinjection) and **source scanning** (Bandit, Semgrep, CodeQL) are signals.
  None of them prevents injection, and their documentation says so.
* **Prevention** comes from keeping values out of SQL text: parameter binding (psycopg
  server-side; PyMySQL and `sqlite3` through the driver).
* **Authorization of SQL text** (sql-guardrail, sql-guard, SQLGuard Ninja's Guard) decides
  whether a statement may run. It is a different control. It matters most when the SQL
  *itself* is untrusted, for example SQL written by an LLM.
* SQLGuard Ninja 0.8.0 combines the two in one checkpoint: the guard authorizes the template,
  and the driver binds the values. The release does not add a signature database or a
  source-code scanner (see SQL_INJECTION_PREVENTION.md, "Detection").
