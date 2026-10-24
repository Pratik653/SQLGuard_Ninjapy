# Benchmark bias review (corpus v1.0.0; still applicable to v1.1.0)

_Written 2026-10-24 for v0.1.1. Every number below was computed from the corpus with
`load_dataset("benchmarks/datasets/v1")`. The purpose is to say plainly how much the v1
results can be trusted, and what an external evaluation set must fix._

## Summary

The v1 corpus measures **consistency with SQLGuard Ninja's documented policy semantics**. It
does not measure real-world detection ability. The native 100% score should not be quoted
without this caveat. The four biases below are structural, not incidental.

## Findings

### B1. Co-development and single authorship (high)

The engine and all 530 cases were written by the same author in the same development
session. Every disagreement between them was resolved by changing one of the two, and those
changes are logged in IMPLEMENTATION_STATUS.md. A corpus tuned this way always converges
toward 100% for its own engine, so the score carries no information about cases the author
did not think of.

### B2. Generated labels restate the engine's semantics (high, for 51% of cases)

268 of the 530 unique cases (51%) are generated. The generator does not import the engine,
but its oracle encodes the **same** semantics (grant lookup, label resolution, tenant-pin
rules). The `label_matrix` (43 cases) and `tenant_matrix` (70) agree with the engine by
construction whenever both implement the specification correctly. That checks the
implementation against the specification. It cannot show that the specification is the
right policy.

### B3. Narrow input distribution (medium)

| Measure | Value | Why it matters |
|---|---|---|
| Cases using the `alias.column` style | 424 / 530 (80%) | LLMs often emit unqualified columns, where the analyser's fail-closed path for unresolvable columns dominates |
| Leading keyword in upper case | 426 / 530 | formatting variety comes mostly from 7 transform templates |
| Median SQL length | 64 characters (max 346) | real text-to-SQL output is often longer, with more joins |
| Cases with two or more JOINs | 1 | multi-join reasoning is barely exercised |
| Tenant context | tenant 1 in 528 / 530 | value-handling bugs specific to other ids would go unseen |
| Literal tenant pin vs bind parameter | 297 vs 8 | parameterised queries are under-represented |
| Role mix | `support_analyst` in 355 / 530 | other roles' policies are lightly covered |

### B4. Outcome and category imbalance (medium)

Of the 1,002 evaluations, 568 are deny, 420 allow and **14 review** (8 unique cases). Metrics
for the review outcome are therefore not statistically meaningful. Two policy categories,
restricted functions and system catalogs, have **no cases at all**.

### B5. Single synthetic schema and policy (medium)

All cases use one ten-table retail schema with explicit labels. Results may not transfer to
schemas with views, many-to-many joins, wide tables or naming conventions unlike this one.

### B6. Ground truth is policy semantics, not harm (by design)

Labels encode what the *policy* says, for example the scope-local tenant pin and
reference-based aggregate-only checks. A safe query can be labelled deny. That is documented,
but it means "false positive" here is measured against the policy, not against actual risk.

## What reduces these biases

1. **An external evaluation set** with independent provenance, kept separate from v1 and
   never used to tune the engine. Requirements: [`benchmarks/datasets/external/README.md`](../../benchmarks/datasets/external/README.md).
2. Reporting external results **separately** (the `by_provenance` breakdown already does this)
   and never merging them into the headline v1 figure.
3. More schemas and policies, LLM-generated SQL captured from real text-to-SQL runs against
   the fixture schema, and larger review and multi-join slices.

## Status

No external dataset is included in v0.1.1. One was requested, but this release does not add
new benchmark cases. It ships the intake process and these findings; the work is tracked as a
GitHub issue. Adding cases written by the engine's own author would not reduce B1 in any case.
