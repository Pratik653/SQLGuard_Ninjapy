# SQL injection: what SQLGuard Ninja does not protect against

SQLGuard Ninja reduces SQL injection risk. It does not eliminate it, and no test suite proves
universal immunity. Specifically:

1. **Code that does not use `execute_safe`.** String-built SQL passed to `execute()`, to your
   own cursor, or to an ORM's raw API is not made safe. The guard may still deny the result,
   but a value concatenated into an *allowed* shape (for example an `id` in a permitted table)
   reads whatever that value selects. Use Bandit, Semgrep or CodeQL to find such code.
2. **Second-order injection.** A stored value that other code later concatenates into SQL.
3. **Identifiers without the allowlist helpers.** Building identifiers from user input
   without `safe_identifier` / `safe_order_by` is unsafe.
4. **Parser divergence beyond the known cases.** Validation uses sqlglot's model of each
   dialect. The divergences found so far (`@`/`$` markers, MySQL `sql_mode`, PostgreSQL
   `standard_conforming_strings`, non-UTF-8 MySQL charsets) are handled. Others may exist:
   * extensions and custom operators
   * server versions newer than tested (PostgreSQL 16, MySQL 8.4)
   * session settings changed by other code on pooled connections
5. **MySQL binding is client-side.** PyMySQL escapes values itself; there are no server-side
   prepared statements. It honours `NO_BACKSLASH_ESCAPES`, the executors require UTF-8 and
   refuse unsafe modes, but its correctness rests on PyMySQL.
6. **Custom executors.** Your own `SafeExecutor` must bind through the driver, check the
   session's lexing settings, and run read-only with a timeout. The library cannot verify that.
7. **Database-side code.** Stored procedures or functions that build dynamic SQL from their
   arguments.
8. **Authorization is not intent.** A permitted query can still be harmful (for example, a
   broad but allowed export). Policy design, approved templates, row-level security and
   least-privilege accounts remain necessary.
9. **SQL Server, Oracle and other dialects.** These have no safe executor. They are
   parser-level experimental and must not be used for security decisions.
10. **Denial of service.** Timeouts and row caps limit damage. They do not prevent load on a
    shared database.
11. **The audit `sql_sha256`.** A hash of a short query containing a guessable secret can be
    brute-forced. Parameter values are never hashed or logged.

Report suspected bypasses privately (SECURITY.md).
