# Decision log (development program)

Architecture-level ADRs stay in `docs/architecture/ARCHITECTURE_DECISIONS.md`; this log records program decisions.

| Date | Decision | Reason |
|---|---|---|
| 2026-10-24 | Dataset tiers are declared by provenance prefix (`handwritten`, `generated:`, `human-reviewed:`, `external:`) and grouped as internal or independent in reports | Uses the existing provenance field; makes independence auditable per case |
| 2026-10-24 | Independent results are never merged into headline internal metrics | Prevents self-authored data being presented as independent |
| 2026-10-24 | Wilson score intervals for recall, precision and FPR | Well-behaved at small n and at proportions near 0 or 1; no extra dependency |
