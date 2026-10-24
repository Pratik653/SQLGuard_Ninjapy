# Policy as code

Policies are versioned files reviewed like code. This guide covers inheritance, metadata,
templates and the review workflow. Field reference:
[POLICY_REFERENCE.md](POLICY_REFERENCE.md).

## Metadata and identity

```yaml
version: 1                      # schema version
name: shop
metadata:
  revision: "2026.10.2"         # your revision; recorded in every decision and audit event
  owner: data-governance
  change_ticket: SEC-1234
```

Every `ValidationResult` and audit event records:
- `decision_id`: unique per decision
- `policy_revision`
- `policy_fingerprint`: a 16-hex-character content hash that changes with any semantic change
Audit events also record the `correlation_id` (the request trace id) and a `query_fingerprint`,
which is the SHA-256 of the literal-redacted SQL. Queries that differ only in literal values
share a fingerprint, and literal values themselves are never logged.

## Role inheritance

```yaml
roles:
  tenant_base:
    tenant_scoped: true
    labels: {payment_card: deny}
  support:
    extends: [tenant_base]
    tables: {customers: "*", orders: [id, tenant_id, status]}
    labels: {contact: allow}
```

* Grants are merged. Column lists are unioned, and `"*"` wins.
* Label access and `column_access` override per key, and `limits` come from the nearest role
  that sets them.
* **Explicit denies are sticky.** A child cannot relax an inherited deny label, deny column
  rule, `deny_columns` entry, or `tenant_scoped: true`. The attempt is a load error (a
  *conflict*), not a silent override.
* Unknown parents and cycles are load errors. Grants inherited from parents are validated
  against the catalog just like direct grants.

`sqlninja policy explain --policy P --role R --column table.column` shows the effective access
and which role in the chain set each label.

## Templates

```bash
sqlninja policy template                         # list: minimal, multi_tenant_saas, analytics_readonly
sqlninja policy template multi_tenant_saas --output policies/policy.yaml
```

## Reviewing a change before activation

```bash
sqlninja policy diff policies/old.yaml policies/new.yaml            # every change, classified
sqlninja policy diff old.yaml new.yaml --fail-on-relaxation         # CI: block silent relaxations
sqlninja policy simulate --policy old.yaml --against new.yaml --cases examples.yaml
sqlninja policy explain --policy new.yaml --role support --tenant 1 --sql "SELECT ..."
```

* `diff` compares the **effective** policies, after inheritance. It classifies each change as
  `relaxes` (can only allow more), `restricts` or `neutral`. Covered areas: roles, table and
  column grants, `deny_columns`, column rules, label access, `tenant_scoped`, catalog labels
  and tenant columns, function policy, limits, defaults, cost thresholds and disclosure.
* `simulate` evaluates example queries (`{id, sql, role, context, expect}`) under the current
  policy and, optionally, a candidate. It reports decision changes and expectation mismatches,
  and exits 1 on mismatch, or with `--fail-on-change` when any decision changes.
* `explain` prints the structured decision: rule ids, messages, internal detail and lineage.
  Use it for operators. Agent-facing messages remain the redacted `agent_message`.

Suggested CI step for policy repositories:

```yaml
- run: sqlninja policy diff "$BASE_POLICY" policies/policy.yaml --fail-on-relaxation
- run: sqlninja policy simulate --policy policies/policy.yaml --cases policies/cases.yaml
```

## Tenant isolation: inspection, rewrite, and the database

1. **Inspection (default).** Every scope reading a tenant table must pin it to the context
   tenant. Otherwise the query is denied (see the methodology for the exact semantics).
2. **Opt-in rewrite.** `SQLCheckpoint(..., rewrite_tenant_filters=True)` or
   `sqlguard_ninja.tenancy.apply_tenant_filters()` adds the missing
   `alias.tenant_column = <bind parameter>` predicates through the AST, then **re-validates**.
   The rewritten string is what gets executed. It refuses when the query has any other
   problem (a forbidden column, another tenant's id, a write), when ownership is ambiguous
   (the preserved side of a RIGHT/FULL join), or when the rewritten SQL fails validation. The
   tenant value is always a bind parameter, never inlined.
3. **The database (authoritative).** Use PostgreSQL row-level security, or per-tenant
   credentials, as the real boundary. SQL inspection and rewriting are defence in depth. They
   cannot see views, functions or data an attacker reaches by other means.
