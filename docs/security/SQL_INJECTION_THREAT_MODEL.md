# SQL injection threat model and v0.8.0 gap analysis

## Assets and trust boundaries

| Input | Trust | Owner |
|---|---|---|
| Role, tenant id, `RequestContext.attributes` | **Trusted** | The application's authentication layer, never the request body or the model |
| SQL template written by the application developer | Trusted for intent. It can still contain mistakes, so it is validated. | Developer |
| SQL written by an LLM or received from a client | **Untrusted** structure | Model / client |
| Parameter values (`params`) | **Untrusted** values | End user / model |
| Dynamic identifiers (sort column, etc.) | **Untrusted** until matched against an allowlist | End user |
| Database server configuration (`sql_mode`, `standard_conforming_strings`, charset) | Must match the guard's lexing assumptions | Operator |

The attacker can choose any parameter value, any identifier choice, and (for LLM- or
client-written SQL) the SQL text itself. The attacker cannot choose the role, the tenant or
context attributes.

## Attack classes and controls

| Class | Example | Control in 0.8.0 | Classification |
|---|---|---|---|
| Value breaks out of a literal | `' OR '1'='1`, `\' OR 1=1 -- `, Unicode quotes | Driver binding: values never enter SQL text | Must be prevented (construction) |
| Stacked statements | `x'; DROP TABLE t; --` as a value, or `; SELECT` in a template | Values are bound. Templates must contain exactly one statement (`SQLBindingError`), and the guard denies multiple statements. | Prevented |
| UNION or added predicates in untrusted SQL | `… UNION SELECT card_number …`, `OR 1=1` around the tenant filter | Guard: table, column and label rules, plus tenant pinning. Optional approved templates. | Rejected by policy |
| Identifier injection / dynamic ORDER BY | `created_at; DROP …`, `id DESC, (SELECT …)` | `safe_identifier` / `safe_order_by` allowlists. Identifiers can never be bound as values. | Prevented when the helper is used |
| Placeholder confusion | `:x` inside literals or comments, `%` in literals, `?`/`$1`/`@x` markers, case-colliding names | Tokenizer-located `:name` only, cross-checked against the AST. Reversible `%(name)s` translation. Other markers refused. | Prevented |
| Tenant override | Caller supplies `tenant_id` (any case), or filters on a caller-chosen placeholder | Reserved names (case-insensitive); the tenant rule accepts only the policy's bind parameter | Prevented |
| Parser/database divergence | `@x`, `$x`, `@@x`; MySQL `ANSI_QUOTES` / `NO_BACKSLASH_ESCAPES`; PostgreSQL `standard_conforming_strings=off`; non-UTF-8 MySQL charset | Guard denies variable/parameter markers. Executors check the session's lexing settings and refuse mismatches. | Prevented for the cases listed. Others are possible (limitations). |
| Resource exhaustion | Recursive CTEs, cartesian joins | Policy cost and structure limits; executor timeouts (SQLite progress handler, `statement_timeout`, `MAX_EXECUTION_TIME`); row caps | Mitigated |
| Writes through an authorized path | Audit mode, mistakes | Read-only transactions or `query_only`; least-privilege accounts | Mitigated at the database |
| Second-order injection | A stored value later concatenated into SQL by other code | Out of scope: only code that uses `execute_safe` is covered | Cannot be classified from SQL text |
| Malicious-but-valid query intent | A permitted query that is still undesirable | Policy design; approved templates for fixed query sets | Not an injection; policy question |

## Gap analysis (audit of v0.7.0, fixed in v0.8.0)

The audit traced every path from public API to cursor:

* `Guard.validate`
* `SQLCheckpoint.evaluate` / `execute`
* `sqlite_executor`, `psycopg_executor`, `mysql_executor`
* `tenancy.apply_tenant_filters`
* MCP tools (no execution)
* the FastAPI router
* the demo sandbox (no caller values)

| ID | Severity | Finding | Evidence | Affected | Fix | Regression tests |
|---|---|---|---|---|---|---|
| SQLI-001 | **Critical** | sqlglot parses `@name` as a bind parameter, and the tenant rule accepted it as the trusted tenant parameter. PostgreSQL reads `@tenant_id` as `abs(tenant_id)`, so `WHERE o.tenant_id = @tenant_id` was **allowed** and returned **every tenant's rows**. | Reproduced on PostgreSQL through `SQLCheckpoint` + `psycopg_executor`: rows for tenants 1, 2 and 3 for a tenant-1 caller | `Guard.validate`, `SQLCheckpoint`, MCP `validate_sql` (reported allow), ≤ 0.7.0, PostgreSQL | Guard denies `Parameter`/`SessionParameter` nodes (`parse.ambiguous_parameter`). The tenant rule no longer treats them as parameters. | `tests/security/test_sqli_parameter_markers.py` (including the PostgreSQL end-to-end test) |
| SQLI-002 | **High** | Same misparse: `@salary` hides a column from the column and privacy rules. On PostgreSQL it returns the value (`abs`). | Reproduced: `SELECT e.full_name, @salary` was allowed for a role that may only aggregate salary, and returned individual salaries | Same | Same | Same file |
| SQLI-003 | Medium | MySQL `@x` (user variables) and `@@x` (system variables, such as `@@datadir` and `@@hostname`) were allowed. They disclose server configuration, and a pooled connection's session state could stand in for a parameter (hypothetical; not reproduced). | Guard decisions (allow) | Guard, MySQL | Same denial | Same file |
| SQLI-004 | Medium (design) | No API took caller values separately. Integrators had to put untrusted values into the SQL text. | Code: `execute()` binds only trusted context values | `SQLCheckpoint`, FastAPI `/query` | `execute_safe` with driver binding; FastAPI `params` | `test_sqli_engines.py`, `test_sqli_binding_contract.py`, `test_sqli_integrations.py` |
| SQLI-005 | Medium | The MySQL executor substituted literals itself through the AST (ADR-013), rather than using the driver's binding. | Code review | `integrations.mysql` | PyMySQL driver binding through the reversible `%(name)s` translation. UTF-8 charset required. ADR-015. | `test_sqli_engines.py` (MySQL CI job) |
| SQLI-006 | Low | `_bound_params` selected context keys by substring (`:tenant_id` also matched `:tenant_id_2`). Extra bindings only; no value confusion. | Code review | Legacy executors | Whole-name match | Existing integration tests |
| SQLI-007 | Low | A PostgreSQL server with `standard_conforming_strings=off` would lex `'a\'` differently from the guard. | sqlglot tokenization probe | PostgreSQL executors | Executors refuse such sessions | Documented. The CI server uses the default (on). |
| SQLI-008 | Low | SQLite binds `$name`, but sqlglot parses it as a column. The guard denied it (unknown column), so it was not exploitable. | Tokenizer probe | Legacy SQLite path | `execute_safe` refuses `$`/`@`/`?` markers | `test_sqli_binding_contract.py` |
| SQLI-009 | Info | The PostgreSQL tenant rewrite emitted `%(name)s` with unescaped `%` literals. psycopg raised an error, so it failed closed. | Probe | Legacy rewrite + psycopg | `execute_safe` re-renders `:name` and doubles `%` | `test_tenant_rewrite_binds_the_trusted_tenant` |

**Disclosure.** SQLI-001 and SQLI-002 affect published versions ≤ 0.7.0 when the guard is used
with PostgreSQL. Users should upgrade to 0.8.0. See SECURITY.md.
