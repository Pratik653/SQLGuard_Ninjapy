# Architecture decision records

Each record states the context, the decision, and its consequences. Superseded decisions stay in
the file, marked as superseded.

---

## ADR-001 — Foundation: standalone package on sqlglot, with adapters for existing guards (Option A + C)

**Context.** Research ([COMPETITIVE_ANALYSIS.md](../research/COMPETITIVE_ANALYSIS.md)) found three
small but competent guards. None models roles, data classification, review workflows, or agent
integration. Two of them cannot be installed together (import-name collision, incompatible
sqlglot pins).

**Options considered.**

* *B — extend one existing guard.* sql-guardrail is the strongest candidate. But its policy model
  has no roles or labels, and it deliberately ignores dialects. Adding both would mean rewriting
  its core and its public API, which is a fork in all but name. The maintainer has not been
  consulted, and a fork would split a 5-star project's small community.
* *D — fork.* Rejected for the same reason. Licences would allow it.
* *A — standalone on sqlglot.* sqlglot already provides parsing, dialects, scope traversal and
  column qualification. The policy layer on top is where the domain logic lives.
* *C — compatibility layer.* Valuable for **benchmarking**, not for enforcement. Running several
  guards in the request path adds latency and gives inconsistent explanations.

**Decision.** Option A for the enforcement engine, built on sqlglot's `qualify` and
`traverse_scope`. Option C for the benchmark harness only: external guards are evaluated through
adapters, and users can run them alongside the native engine.

**Consequences.** We own the correctness of the policy layer, so the benchmark corpus must not be
tuned to our engine (see ADR-006). We stay compatible with sqlglot's release cadence by pinning to
one major version (`>=30,<31`).

## ADR-002 — Policy model: schema catalog + classification labels + roles

**Decision.** A policy file (YAML/JSON, `version: 1`, validated by Pydantic) declares:

* `catalog`: tables, columns, optional tenant column, row estimates, JSON field labels, and less
  sensitive `alternatives` for a column;
* `labels`: classification labels (`personal_identifier`, `contact`, `financial`, `hr`,
  `special_category`, ...) with sensitivity and masking advice;
* `roles`: table grants, column grants, and label rules (`allow`, `aggregate_only`, `review`,
  `deny`).

Precedence, most specific first: **explicit column rule → label rule → role default**. Labels come
only from configuration. Column names are never used to infer sensitivity at enforcement time.
A heuristic suggester exists (`sqlninja policy suggest`) but it writes *suggestions for a human*,
not policy.

**Consequences.** A guard with a schema can expand `SELECT *` exactly and attribute every column
to its base table. Unknown tables and unattributable columns are handled conservatively
(`deny` by default, `review` if configured).

## ADR-003 — Decision model: findings → decision; evaluation separate from authorization

**Decision.** Rules emit `Finding`s (rule id, category, severity, action ∈ {deny, review, warn},
safe-to-disclose message, internal detail, remediation). The guard combines them into a
`Decision` ∈ {ALLOW, REVIEW, DENY}: any deny → DENY; else any review → REVIEW; else ALLOW.

Execution is authorized by a separate `SQLCheckpoint` according to an `EnforcementMode`:

| Mode | DENY | REVIEW | ALLOW |
|---|---|---|---|
| `block` | not executed | not executed | executed |
| `review` | not executed | executed only with an approval bound to the SQL's SHA-256 and trace id | executed |
| `audit` | executed, `enforced=False` recorded | executed, recorded | executed |

The role and tenant come from a server-side `RequestContext`. They are never taken from tool
arguments, SQL comments or model output.

## ADR-004 — External validators run in isolated subprocess workers

**Context.** Import and dependency conflicts (COMPETITIVE_ANALYSIS §2).

**Decision.** An adapter protocol (`BenchmarkAdapter.evaluate(case) -> AdapterVerdict`) has three
implementations:

1. `native` — in-process SQLGuard Ninja;
2. `callable` — any user function `module:function` taking `(sql, dialect, case)`;
3. `subprocess` — a worker script executed by *another Python interpreter* (one virtual environment
   per external tool), speaking JSON Lines over stdin/stdout.

Workers for sql-guardrail, agent-sql-guard and krish2105/sqlguard ship in
`sqlguard_ninja/benchmarking/workers/`. `scripts/setup_external_adapters.py` creates pinned venvs.

**Consequences.** Latency for subprocess adapters is measured *inside the worker*, so IPC overhead
does not distort comparisons. Each external adapter states which case categories its policy
translation can express. Reports show results both on all cases and on those within declared
capability.

## ADR-005 — No rewriting of SQL in the enforcement path

**Decision.** The guard validates the exact string that will be executed. It never injects LIMITs
or rewrites predicates. Remediation text may *suggest* changes. Rewriting would mean the validated
string and the executed string differ, which is a known bypass class.

## ADR-006 — Benchmark labels are tool-independent

**Decision.** Each case records the *ideal* outcome under the policy semantics (`allow`, `deny`,
`review`), a binary security label, and a tool-agnostic reason code. Cases are not relabelled
because the native engine disagrees: that disagreement is a reported false positive or false
negative. Generated cases use a documented, seeded generator. Safe cases are validated by executing
them against the fixture database; unsafe cases are compiled against it where the engine can
compile them without executing them.

## ADR-007 — PostgreSQL plan inspection is gated

**Decision.** `PostgresPlanInspector` only runs `EXPLAIN (FORMAT JSON)`, never `ANALYZE`, and only
on statements the guard has already ALLOWed. It runs inside a `READ ONLY` transaction with
`SET LOCAL statement_timeout`, rolls back, and is documented to require a low-privilege role.
Planning can still evaluate immutable functions, which is why the guard's function policy runs
first.

## ADR-008 — Minimal core dependencies

**Decision.** Core: `sqlglot`, `pydantic`, `PyYAML`. CLI uses `argparse` (no Click/Typer).
Extras: `langchain`, `langgraph`, `fastapi`, `postgres` (`psycopg`), `dev`.

## ADR-009 — Licence: Apache-2.0

Apache-2.0 provides an explicit patent grant, which matters to enterprise adopters. It is
compatible with all dependencies we use (MIT, BSD, Apache-2.0). No third-party code is vendored.

## ADR-011 — Opt-in tenant-filter rewrite (refines ADR-005)

**Context.** Enterprise users want missing tenant filters added rather than rejected.

**Decision.** `sqlguard_ninja.tenancy.apply_tenant_filters` may add tenant predicates through
the AST. It is opt-in (`rewrite_tenant_filters=True`), uses bind parameters only, refuses on any
non-tenant problem or ambiguous ownership, and **re-validates** the rewritten SQL, which is the
exact string executed. ADR-005's invariant still holds: the validated string and the executed
string are identical.

**Consequences.** The rewritten SQL is the qualified form produced by sqlglot. It is equivalent
but may look different from the input. Database RLS remains the authoritative control.

## ADR-012 — Role inheritance with sticky explicit denies

**Decision.** `extends` merges grants. A child cannot relax an inherited explicit deny, and an
attempt is a load error. `policy diff` works on the effective (inherited) policy and classifies
relaxations so reviewers and CI can gate them.

## ADR-010 — Read-only scope for v0.1

**Decision.** v0.1 validates read-only workloads only. All writes are denied. Supporting governed
writes (UPDATE/DELETE with mandatory tenant predicates) is on the roadmap. Doing it properly needs
its own corpus and threat analysis.

## ADR-013 — MySQL: exact identifiers and AST placeholder binding

**Context.** MySQL folds column names but table-name case depends on `lower_case_table_names`
and the file system. PyMySQL binds only `%s`/`%(name)s` markers, which sqlglot's MySQL dialect
cannot parse, so the validated string could not be the executed string.

**Decision.** (1) Identifiers are compared exactly; the guard never folds MySQL identifier case,
and mixed-case references are denied (fail closed, documented false positive). (2) Validated MySQL
SQL uses named placeholders. `mysql_executor` parses the validated string, replaces only
`Placeholder` nodes with literals of trusted context values (integers, or strings with quotes
doubled; backslash and NUL refused because their meaning depends on `NO_BACKSLASH_ESCAPES`),
refuses unknown or anonymous placeholders, and sends the result with no driver parameters, inside
`START TRANSACTION READ ONLY` with `MAX_EXECUTION_TIME`, then rolls back. (3) The guard lexes
MySQL with server defaults, so the executor refuses sessions whose `sql_mode` contains
`ANSI`, `ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES`, `PIPES_AS_CONCAT` or `HIGH_NOT_PRECEDENCE`.

**Consequences.** This refines ADR-005: the executed string differs from the validated one only
in placeholder nodes, which carry server-side values, never user input. Literals and identifiers
are not rewritten. MySQL support is limited to the scope the CI service-container tests cover.

## ADR-014 — Playground: one service, static-first hosting, database-enforced sandbox

**Decision.** One Python `DemoService` backs both a FastAPI server and a static build in which
Pyodide runs the same code in the visitor's browser. Allowed queries run only in an in-memory
synthetic SQLite database. That database enforces read-only access itself: an authorizer
allowlist, `query_only`, engine limits and a step/time budget. The public deployment is the
static build on GitHub Pages: there is no server to abuse, no credentials, and no cost. The
static build self-hosts Pyodide and the wheels and verifies their checksums.

**Consequences.** The first static load downloads about 16 MB. The server mode stays available
for private use behind a proxy (Docker/Compose/Kubernetes references). In-process rate limits
are per replica.
