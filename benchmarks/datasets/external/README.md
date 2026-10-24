# External evaluation datasets — intake requirements

This directory is reserved for evaluation sets that were **not** written by SQLGuard Ninja's
authors. It is intentionally empty in v0.1.1. See
[`docs/guides/BENCHMARK_BIAS_REVIEW.md`](../../../docs/guides/BENCHMARK_BIAS_REVIEW.md) for
why it exists.

## Rules

1. **Independent provenance.** Each dataset lives in its own sub-directory with a
   `PROVENANCE.md` that names the author or organisation, the creation method, the date, the
   source URL or commit, and how labels were assigned and reviewed.
2. **Licence first.** The dataset's licence must allow redistribution under, or alongside,
   Apache-2.0. Record the SPDX identifier in `PROVENANCE.md` and `THIRD_PARTY_NOTICES.md`.
   No dataset with an unknown or restrictive licence is merged.
3. **Synthetic data only.** No real personal data, customer data or credentials.
4. **Held out.** External cases must never be used to tune the engine. If a case reveals an
   engine bug, fix it, add a *separate* regression case under `benchmarks/datasets/v1`, and
   leave the external case and its label unchanged.
5. **Same schema format** as `benchmarks/datasets/v1` (a `manifest.yaml` with `case_files`
   and a policy). Every case uses
   `provenance: external:<dataset-name>@<version>` so reports break it out separately.
6. **Label validation.** `allow` cases must execute on the fixture databases, as in v1.
7. **Separate reporting.** Results are published per dataset and never merged into the v1
   headline numbers.

Proposals: open a "Benchmark case" issue first so licence and provenance can be checked
before any data is submitted.
