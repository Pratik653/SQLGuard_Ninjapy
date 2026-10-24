# CI integration

## Local workflow

```bash
sqlninja init                     # sqlninja.yaml, policies/policy.yaml, benchmarks/cases/
sqlninja benchmark run            # -> results/latest.json + results/latest.md
sqlninja benchmark baseline       # accept the reviewed result as benchmarks/baseline.json
git add benchmarks/baseline.json  # baselines change only through reviewed commits
```

`sqlninja benchmark baseline` refuses to run when `CI` is set. CI never updates baselines.

## SARIF and GitHub code scanning

`sqlninja scan` writes SARIF 2.1.0. Upload it with GitHub's own action, pinned to a commit SHA
you have reviewed. Uploading needs `security-events: write`, and code scanning must be available
for the repository.

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@<sha>
  - run: pip install sqlguard-ninja
  - run: sqlninja scan sql/ --policy policy.yaml --role reporting --tenant 1 --format sarif --output sqlninja.sarif --fail-on never
  - uses: github/codeql-action/upload-sarif@<sha>
    with:
      sarif_file: sqlninja.sarif
```

Results are fingerprinted per file, rule and literal-insensitive query, so changing only a
literal does not open a new alert. The log contains rule messages but no SQL snippet.

## GitHub Action

See [`examples/github-actions/sql-security.yml`](../../examples/github-actions/sql-security.yml).

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with: {persist-credentials: false}
  - uses: Pratik653/SQLGuard_Ninjapy@<commit-sha>
    with:
      config: sqlninja.yaml
      allow-benchmark-change: ${{ github.event_name == 'pull_request' }}
```

| Input | Default | Meaning |
|---|---|---|
| `config` | `sqlninja.yaml` | project config |
| `python-version` | `3.12` | |
| `package-spec` | (the pinned action checkout) | pip requirement for SQLGuard Ninja |
| `baseline-ref` | base branch on PRs | ref to read the baseline from |
| `fail-on-regression` | `true` | fail the job when the gate fails |
| `allow-benchmark-change` | `false` | permit added cases (they must still pass) |
| `upload-artifacts` / `artifact-name` | `true` / `sqlninja-results` | result, report, comparison |

Output: `passed`.

## What the gate detects

| Class | Fails by default | Threshold key |
|---|---|---|
| Unsafe case previously blocked, now allowed (incl. privacy and tenant subsets) | yes | `max_security_regressions: 0` |
| New unsafe case that is allowed | yes | counted as a security regression |
| Legitimate case newly blocked | yes | `max_usability_regressions: 0` |
| New validator errors / new parse failures on legitimate SQL | yes | `max_new_errors: 0` |
| Changed expected labels | yes | `--allow-label-changes` (human decision) |
| Missing baseline cases / changed corpus fingerprint | yes | `allow-benchmark-change` |
| Recall / FPR below or above limits | if set | `min_recall`, `max_false_positive_rate` |
| p95 latency increase | if set | `max_p95_latency_increase_pct` |

## Security of the action

* All third-party actions are pinned to commit SHAs.
* Inputs reach shell steps only through environment variables, never through `${{ }}`
  interpolation in scripts.
* For pull requests, the baseline is read from the **base branch** with `git show`, so a PR
  cannot approve its own regression by editing the baseline.
* Use `pull_request`, not `pull_request_target`. The action needs no secrets and only
  `contents: read`.
* Protect `benchmarks/` and policy files with CODEOWNERS review.

## This repository's own CI

`.github/workflows/ci.yml` runs lint, mypy, corpus reproducibility, tests on Python
3.11–3.13 (Linux and Windows), PostgreSQL in a service container and via Docker Compose, the
composite action against the committed native baseline, the external validators
(informational), and a clean wheel install.
