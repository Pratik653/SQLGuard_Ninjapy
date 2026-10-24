# Third-party notices

SQLGuard Ninja is licensed under Apache-2.0. **It does not vendor or copy third-party source
code.** The only third-party file in the repository is a test fixture, the SARIF schema
(below). The projects below are used as ordinary dependencies, installed by the package
manager under their own licences. Licences were read from installed package metadata on
2026-10-24. Always check the version you install.

## Runtime dependencies (core install)

| Package | Version tested | Licence | Use |
|---|---|---|---|
| [sqlglot](https://github.com/tobymao/sqlglot) | 30.24.0 | MIT | SQL parsing, dialects, scope analysis, column qualification |
| [pydantic](https://github.com/pydantic/pydantic) (+ pydantic-core) | 2.14.1 | MIT | Policy/config schema validation |
| [PyYAML](https://pyyaml.org/) | 6.0.3 | MIT | Policy and dataset files |

## Optional extras

| Extra | Package | Version tested | Licence |
|---|---|---|---|
| `langchain` | langchain-core | 1.7.0 | MIT |
| `langgraph` | langgraph | 1.2.17 | MIT |
| `fastapi` | fastapi / starlette | 0.162.0 / 1.9.0 | MIT / BSD-3-Clause |
| `postgres` | psycopg (+ psycopg-binary) | 3.3.6 | LGPL-3.0-only |
| `mcp` | mcp (official MCP Python SDK) | 2.3.0 | MIT |
| `mysql` | PyMySQL | 1.2.3 | MIT |
| `otel` | opentelemetry-api | 1.45.1 | Apache-2.0 |
| `prometheus` | prometheus-client | 0.26.0 | Apache-2.0 AND BSD-2-Clause |
| `demo` | fastapi / uvicorn | 0.162.0 / 0.54.0 | MIT / BSD-3-Clause |

psycopg is LGPL-3.0. SQLGuard Ninja only imports it at runtime when the `postgres` extra is
installed. It is not modified or bundled, which is compatible with distributing SQLGuard Ninja
under Apache-2.0.

## Development and test tools (not distributed)

pytest (MIT), pytest-cov (MIT), hypothesis (MPL-2.0), httpx (BSD-3-Clause), ruff (MIT),
mypy (MIT), build (MIT). `pgserver` is optionally used for local PostgreSQL tests. It is not a
declared dependency, and its package metadata on PyPI does not declare a licence. It bundles
PostgreSQL binaries (PostgreSQL License).

Tests also use jsonschema (MIT), opentelemetry-sdk (Apache-2.0), Playwright and
pytest-playwright (Apache-2.0), and axe-core 4.10.3 (MPL-2.0), which is downloaded at test time.

The **static playground build** (`scripts/build_static_demo.py`, not part of the package)
bundles Pyodide 0.29.5 (MPL-2.0, including CPython under the PSF License and SQLite, which is
public domain), sqlglot (MIT), and pydantic, PyYAML and their dependencies as packaged by
Pyodide. Their licences are listed in the generated `NOTICE.txt`.

## Test fixture: SARIF 2.1.0 JSON schema

`tests/data/sarif-schema-2.1.0.json` is the unmodified OASIS SARIF 2.1.0 (Errata 01) schema,
downloaded from
https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
(SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`). It is used only to
validate SARIF output in tests and is not part of the wheel.

> Copyright © OASIS Open 2020. All Rights Reserved. This document and translations of it may be
> copied and furnished to others, and derivative works that comment on or otherwise explain it
> or assist in its implementation may be prepared, copied, published, and distributed, in whole
> or in part, without restriction of any kind, provided that the above copyright notice and this
> section are included on all such copies and derivative works. (OASIS IPR Policy notice; see
> https://www.oasis-open.org/policies-guidelines/ipr/)

## External validators used for benchmarking only

Installed into isolated virtual environments by `scripts/setup_external_adapters.py`, never
redistributed:

| Tool | Version | Licence | Source |
|---|---|---|---|
| sql-guardrail | 0.5.2 | MIT | https://github.com/nickusevich/sql-guardrail |
| agent-sql-guard | 0.2.0 | Apache-2.0 declared in `pyproject.toml`; the repository contains no LICENSE file | https://github.com/sakura-sky/sql-guard |
| sqlguard (krish2105) | git 62327f2 | MIT | https://github.com/krish2105/sqlguard |

## GitHub Actions

`actions/checkout`, `actions/setup-python` and `actions/upload-artifact` (MIT, GitHub) are
referenced by commit SHA in the workflows and the composite action.

## Data

All benchmark data and fixture rows are synthetic and were written for this project. Card
numbers are the published test PAN `4111111111111111`. Emails use the reserved
`example.com`/`example.org` domains. No third-party datasets were used.
