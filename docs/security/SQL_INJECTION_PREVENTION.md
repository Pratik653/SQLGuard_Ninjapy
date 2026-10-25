# SQL injection prevention with SQLGuard Ninja

SQLGuard Ninja 0.8.0 combines two different controls in one checkpoint:

1. **Injection prevention:** untrusted *values* are bound by the database driver and never
   become SQL text.
2. **SQL authorization:** the *statement* (written by a developer, a client or an LLM) is
   checked against the policy before it runs: tables, columns, data labels, tenant filter,
   read-only access, cost.

Binding alone does not stop an LLM from writing `SELECT card_number FROM payments`;
authorization does. Authorization alone does not make string-built SQL safe; binding does.
Use both. Neither one is a guarantee (see [SQL_INJECTION_LIMITATIONS.md](SQL_INJECTION_LIMITATIONS.md)).

## The safe API

```python
from sqlguard_ninja import Guard, Policy
from sqlguard_ninja.integrations import RequestContext, SQLCheckpoint, PsycopgSafeExecutor

checkpoint = SQLCheckpoint(Guard(Policy.from_file("policy.yaml")), dialect="postgres")
executor = PsycopgSafeExecutor("postgresql://app_reader@db/app")  # SELECT-only account

rows = checkpoint.execute_safe(
    "SELECT o.id, o.status FROM orders o "
    "WHERE o.tenant_id = :tenant_id AND o.customer_email = :email",
    RequestContext(principal=user.id, role="support", tenant_id=user.tenant_id),  # from auth
    executor,
    params={"email": untrusted_email},
)
```

What happens:

1. **Contract check.** Placeholders are found with the dialect tokenizer. Only `:name` is
   accepted, and the tokens are cross-checked against the parsed statement. Values must match
   the placeholders exactly. A violation raises `SQLBindingError` (HTTP 400 in the FastAPI
   router).
2. **Authorization.** The exact template is evaluated by the policy and audited. Parameter
   values never appear in audit events, logs, traces or metrics. A denial raises
   `SQLBlockedError`.
3. **Execution.** The executor passes the template and the values to the driver separately.
   It runs in a read-only transaction with a timeout.

`SQLCheckpoint.execute()` (trusted context values only) is unchanged.

## Supported executors and parameter handling

| Database | Executor | Binding | Read-only and limits | Session checks |
|---|---|---|---|---|
| SQLite | `SQLiteSafeExecutor(conn)` | Native `sqlite3` binding (`:name`, the same text that was validated) | `PRAGMA query_only`, progress-handler time budget, row cap | — |
| PostgreSQL | `PsycopgSafeExecutor(conninfo)` | psycopg 3 **server-side** binding (extended protocol). Client-side cursors are refused. | `READ ONLY` transaction, `statement_timeout`, rollback, row cap | `standard_conforming_strings` must be `on` |
| MySQL 8 | `MySQLSafeExecutor(connect)` (`sqlguard_ninja.integrations.mysql`) | PyMySQL driver binding. This is **client-side**: PyMySQL escapes each value, honouring `NO_BACKSLASH_ESCAPES`; bytes are sent as hex. | `START TRANSACTION READ ONLY`, `MAX_EXECUTION_TIME`, rollback, row cap | UTF-8 connection charset; refuses `ANSI`, `ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES`, `PIPES_AS_CONCAT`, `HIGH_NOT_PRECEDENCE` |

For psycopg and PyMySQL, the `:name` template is translated to `%(name)s` at the placeholder
tokens only, and every other `%` is doubled. The executor checks that undoing this translation
gives back the validated text byte for byte, so validation and execution see the same
statement. Nothing is ever interpolated by SQLGuard Ninja itself, and there is no fallback to
interpolation: when the contract or a session check fails, the query does not run.

## The parameter contract

* **Placeholders:** `:name` with names matching `[A-Za-z_][A-Za-z0-9_]{0,62}`. The following
  are refused: `?`, `?1`, `:1`, `%s`, `%(name)s`, `$1`, `$name`, `@name`, `@@name`, and
  placeholders whose names differ only in case. A placeholder inside a string literal, a
  quoted identifier or a comment is text.
* **Values:** each placeholder needs exactly one value. Missing or extra names are errors, and
  a repeated placeholder binds one value.
* **Accepted types:** `None`, `bool`, 64-bit `int`, finite `float`, finite `Decimal`, `str`
  (no NUL, valid Unicode), `bytes` / `bytearray` / `memoryview`, `date`, `datetime` and
  `time`. Anything else (lists, dicts, NaN, out-of-range integers, custom objects) is refused.
* **SQLite storage:** dates and times are stored as ISO-8601 text, and `Decimal` as text.
* **Statements:** exactly one per call.

## Tenant parameter ownership

The tenant value is bound from `RequestContext.tenant_id`, under the policy's
`tenant.context_key`. All context attributes are also bound from the context. The caller can
**never** supply those names, in any letter case (`SQLBindingError: … is reserved`). The
tenant rule accepts only the policy's declared bind parameter (`:tenant_id`) as a tenant pin.
A filter on a caller-chosen placeholder (`WHERE o.tenant_id = :wanted`) is denied, and so are
variables and `@`/`$` markers. With `rewrite_tenant_filters=True`, the rewritten template is
re-checked against the contract, then authorized and executed. That rewritten template is the
one whose structure was approved.

## Dynamic identifiers

Values can be bound; identifiers (table names, column names, sort order) cannot. Map the
user's choice to an application-owned allowlist:

```python
from sqlguard_ninja.integrations import safe_order_by

order = safe_order_by(
    request.args["sort"],
    request.args["dir"],
    allowed={"created_at", "total_amount"},
    dialect="postgres",
)
rows = checkpoint.execute_safe(
    f"SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id ORDER BY {order} LIMIT 50",
    ctx,
    executor,
)
```

`safe_identifier` / `safe_order_by` refuse anything outside the allowlist, quote the name
for the dialect, and accept only `ASC` or `DESC`. The composed SQL is then authorized like
any other query.

## Unsafe versus safe

```python
# UNSAFE: the value becomes SQL text (Bandit B608 / CodeQL py/sql-injection flag this).
checkpoint.execute(f"SELECT ... WHERE c.email = '{email}'", ctx, run)

# UNSAFE: escaping by hand depends on dialect and server settings (OWASP: avoid).
checkpoint.execute("SELECT ... WHERE c.email = '" + email.replace("'", "''") + "'", ctx, run)

# SAFE: the value is bound by the driver; the template is authorized.
checkpoint.execute_safe("SELECT ... WHERE c.email = :email", ctx, executor, {"email": email})
```

## High-assurance option: approved templates

For applications with a fixed set of queries, `ApprovedTemplateRule` denies any statement
whose canonical structure is not on an allowlist:

```python
from sqlguard_ninja.core.rules.templates import ApprovedTemplateRule, ApprovedTemplates

templates = ApprovedTemplates.from_sql({"order_status": ORDER_STATUS_SQL}, dialect="postgres")
checkpoint = SQLCheckpoint(
    Guard(policy).with_rules([ApprovedTemplateRule(templates)]), dialect="postgres"
)
```

The fingerprint ignores comments, whitespace and keyword case. It keeps identifiers,
literals and placeholder names. It is an allowlist, not injection detection, and equal
fingerprints do not prove semantic equivalence.

## Detection

SQLGuard Ninja does not ship injection signatures or a source-code scanner. A runtime SQL
string cannot show whether its author concatenated a value into it. Use Bandit (B608),
Semgrep or CodeQL to find unsafe construction in source code, and keep binding as the
control. The runtime diagnostics are the contract errors above (unsupported marker,
unbound or extra placeholder, reserved name, unsupported type) plus the policy findings.

## Database privileges

* Use a dedicated account with `SELECT` only, on only the tables the application needs.
  Use views to narrow columns, and row-level security for tenant isolation where available.
* Keep timeouts on (the executors set them). Never use superuser, DBA or owner accounts.
* Least privilege limits the damage from a mistake. It does not prevent injection.

## Running the security regression suite

```bash
pytest -q tests/security/test_sqli_binding_contract.py tests/security/test_sqli_parameter_markers.py \
  tests/security/test_sqli_integrations.py tests/property/test_sqli_property.py
pytest -q tests/security/test_sqli_engines.py                     # SQLite (+ PostgreSQL if available)
SQLNINJA_PG_DSN=postgresql://postgres:...@localhost:5432/postgres pytest -q -m postgres tests/security/
SQLNINJA_MYSQL_DSN=mysql://root:...@127.0.0.1:3306/ pytest -q -m mysql tests/security/test_sqli_engines.py
```

CI runs the PostgreSQL and MySQL engine suites against service containers on every pull
request.
