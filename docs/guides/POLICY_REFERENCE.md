# Policy reference (version 1)

A policy is a YAML or JSON file validated when it loads. A typo in a role grant fails at
start-up instead of silently changing behaviour. Run `sqlninja policy check --policy FILE`.

> This is a technical control library that helps implement data minimisation and
> need-to-know access. It does **not** certify compliance with GDPR or any other regulation.

```yaml
version: 1
name: shop
metadata: {revision: "2026.10.1", owner: data-governance}   # recorded in every decision
dialect: postgres            # default dialect for validate()
disclosure: names            # or "generic": agent messages never name tables/columns

labels:                      # classification labels: assigned by you, never inferred
  contact:   {sensitivity: high, masking: return the email domain}
  financial: {sensitivity: high}
  health:    {sensitivity: critical, special_category: true}

catalog:
  default_schema: public     # unqualified names and public.x resolve here; others are unknown
  tables:
    customers:
      tenant_column: tenant_id
      estimated_rows: 2000000          # used by the static cost score
      columns:
        id: {type: int, identifying: true}   # identifying -> small-cohort checks
        tenant_id: int
        email: {labels: [contact], alternatives: [email_domain]}
        email_domain: text
        profile:
          type: json
          json_fields:                   # labels for paths inside a JSON column
            health.allergies: [health]

roles:
  support:
    # extends: [base_role]          # inherit grants; inherited explicit denies cannot be relaxed
    tables:
      customers: [id, tenant_id, email, email_domain]   # or "*", or {columns, deny_columns, column_access}
    labels: {contact: allow, health: deny}
    unlisted_label_access: deny         # default for labels the role does not mention
    tenant_scoped: true                 # default
    limits: {max_limit: 1000}           # per-role override of top-level limits

tenant:
  context_key: tenant_id          # key in the trusted request context
  parameter_names: [tenant_id]    # bind params (:tenant_id, %(tenant_id)s) treated as the tenant

functions:
  mode: denylist                  # or allowlist (recommended for production)
  deny: []                        # extra names; built-ins cover file I/O, DoS, admin, dynamic SQL
  allow: []                       # allowlist mode: permitted names; denylist mode: exceptions
  review: []
  unknown_function_action: warn   # functions sqlglot does not know (possible UDFs)

limits: {max_joins: 8, max_subquery_depth: 5, max_limit: null, require_limit: false,
         max_sql_length: 20000, max_ast_nodes: 5000}

defaults:                         # actions for analysis gaps; deny = fail closed
  unknown_table_action: deny
  unresolved_column_action: deny
  unexpandable_star_action: deny
  catalog_access_action: deny
  minimization_action: warn
  small_cohort_action: review

cost: {enabled: true, review_score: 50, deny_score: 80, large_table_rows: 1000000,
       max_plan_total_cost: null, max_plan_rows: null}
```

## Access resolution for a column

1. Table not granted to the role → `table.not_permitted`.
2. Column not in the grant (or in `deny_columns`) → `column.not_permitted`.
3. `column_access` entry for the column → that access, and labels are ignored.
4. Otherwise, each label → `role.labels[label]` or `unlisted_label_access`:
   * `deny` → `privacy.label_denied`
   * `aggregate_only` → allowed only inside COUNT/SUM/AVG/STDDEV/VARIANCE/...; MIN/MAX/
     ARRAY_AGG and window aggregates count as value-revealing → `privacy.aggregate_only`
   * `review` → `privacy.label_review`
5. Reading a JSON column whole reveals all of its `json_fields` labels. Reading a path reveals
   labels of that path, its ancestors and its descendants.

Without roles, an implicit role grants every catalog table and denies every labelled column.

Inheritance, templates, `policy diff` / `simulate` / `explain` and the tenant-filter rewrite
are described in [POLICY_AS_CODE.md](POLICY_AS_CODE.md).

## Decisions

Each rule emits findings with an action (`deny`, `review`, `warn`). Any deny → **DENY**,
else any review → **REVIEW**, else **ALLOW**. `warn` findings (e.g. data-minimisation hints,
unknown functions) never block.

## Rule ids

| Area | Rule ids |
|---|---|
| Parsing | `parse.empty`, `parse.error`, `parse.too_long`, `parse.too_complex`, `parse.invalid_characters`, `parse.analysis_incomplete` |
| Statements | `statement.multiple`, `statement.not_read_only`, `statement.unsupported`, `statement.write_in_query`, `statement.select_into`, `statement.locking`, `statement.executable_comment` |
| Catalog / functions | `catalog.system_object`, `function.denied`, `function.not_allowlisted`, `function.review`, `function.unknown` |
| Access | `role.unknown`, `table.not_permitted`, `column.not_permitted`, `column.unresolved`, `column.star_unexpandable` |
| Privacy | `privacy.label_denied`, `privacy.aggregate_only`, `privacy.label_review`, `privacy.small_cohort`, `privacy.minimization` |
| Tenant | `tenant.context_missing`, `tenant.missing_predicate`, `tenant.wrong_value` |
| Structure / cost | `structure.max_joins`, `structure.max_depth`, `structure.limit_exceeded`, `structure.limit_missing`, `structure.limit_unparseable`, `cost.static_score` |

## Custom rules

```python
from sqlguard_ninja import Action, Category, Finding, Guard, Severity

class NoOrderByRandom:
    rule_ids = ("custom.order_by_random",)

    def check(self, ctx):
        if "RANDOM()" in ctx.analysis.sql.upper():
            yield Finding(rule_id="custom.order_by_random", category=Category.COST,
                          severity=Severity.LOW, action=Action.REVIEW,
                          message="ORDER BY RANDOM() scans the whole table.")

guard = Guard(policy).with_rules([NoOrderByRandom()])
```

`ctx.analysis` exposes the parsed tree, per-scope tables, attributed columns (clause,
aggregate kind, JSON path), functions and unresolved references.

## Label suggestions

`sqlninja policy suggest --policy FILE` lists unlabelled columns whose names *look*
sensitive. These are suggestions for a data owner to review. Enforcement never uses names.
