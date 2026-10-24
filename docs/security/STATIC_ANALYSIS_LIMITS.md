# Limits of static SQL analysis

SQLGuard Ninja decides by **reading** SQL, never by running it. That makes it fast,
deterministic and safe to run before execution. It also puts hard limits on what it can
know. This page lists those limits so deployers can put the right controls around it.

## What a static analyser cannot know

| Limit | Consequence | Compensating control |
|---|---|---|
| **Parser differential:** sqlglot's parse can differ from the database engine's parse for unusual syntax | A query the guard reads as harmless could mean something else to the server | Only use tested dialects; unparseable input is denied; least-privilege DB role |
| **Object definitions:** views, functions, triggers and rules are opaque | A permitted view or function can read or change data the policy would deny | Grant only vetted views; `functions.mode: allowlist`; no SECURITY DEFINER functions for the agent role |
| **Runtime data:** values, row counts, NULL patterns | Aggregates and filters can still leak information across many permitted queries (inference) | Small-cohort review, rate limits, auditing, minimum-group-size controls in the database or app |
| **Session state:** `search_path`, settings, temporary objects created elsewhere | An unqualified name may resolve to a different object at runtime | Fixed `search_path` for the agent role; deny session statements (default) |
| **Cost:** actual rows, cache state, concurrency | Static scores and planner estimates can be wrong in both directions | `statement_timeout`, connection limits, resource groups |
| **Intent:** why the query was written | A legitimate query can serve a harmful goal | Human review mode for sensitive labels; audit trail |
| **Writes:** governed DML is out of scope | All writes are denied in v0.1 | Separate, explicitly designed write paths |

The guard **fails closed** where it detects uncertainty: parse errors, incomplete qualification,
unattributable columns, `*` over unknown sources and unknown tables are denied by default. It
cannot detect uncertainty it does not know about. That is why the controls in the right-hand
column are required, not optional.

## Dialect support

| Dialect | Status | Evidence |
|---|---|---|
| PostgreSQL | **Supported.** Tested against PostgreSQL 16. | Corpus cases; every `allow` case executed on PostgreSQL 16 as a SELECT-only role (locally and in CI); plan inspection tested |
| SQLite | **Supported.** | Corpus cases; every `allow` case executed on the fixture database; SQLite-specific session statements denied |
| MySQL family | **Experimental.** | Executable-comment rule only; no corpus cases; not tested |
| Other sqlglot dialects (Snowflake, BigQuery, T-SQL, ...) | **Untested.** | Parsing may work. Policy behaviour, quoting and catalog rules are not verified. |

Treat "experimental" and "untested" as unsupported for security decisions.
Identifier-case handling follows each dialect's rules through sqlglot. For example, quoted
identifiers are case-sensitive in PostgreSQL but not in SQLite, and the corpus covers both.

## Coverage of the benchmark

The benchmark does **not** contain restricted-function or system-catalog cases in v1.0.0.
Those rules exist and run by default, but their detection rate is not measured. See
[BENCHMARK_BIAS_REVIEW.md](../guides/BENCHMARK_BIAS_REVIEW.md) for what the existing results
can and cannot show.

## Non-claims

SQLGuard Ninja does **not** guarantee protection against SQL injection, prompt injection or
data leakage, and it does not certify compliance with GDPR or any other regulation. It is one
defence-in-depth layer between an LLM and a database whose own permissions, row-level security
and resource limits remain authoritative. See the [threat model](THREAT_MODEL.md).
