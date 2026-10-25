# v0.8.0 release gate: SQL injection prevention

Every gate must pass before tagging. "Local" means Windows 11, Python 3.11.9, sqlglot 30.24.0,
and embedded PostgreSQL (pgserver). "CI" means the PR and `main` runs (Ubuntu; PostgreSQL 16
and MySQL 8.4 service containers).

| Gate | Evidence | Status |
|---|---|---|
| Native or driver binding verified per advertised executor | `test_sqli_engines.py`: 39 payloads round-trip byte-exact as data and match nothing as predicates; typed values; tables unchanged. SQLite and PostgreSQL ran locally (202 passed); PostgreSQL and MySQL run in CI. | Local ✅ / CI: see PR |
| No known critical or high bypass in `execute_safe` | Audit SQLI-001…009 (`docs/security/SQL_INJECTION_THREAT_MODEL.md`). SQLI-001 (critical) and SQLI-002 (high) were reproduced on PostgreSQL, fixed, and covered by regression tests. No open findings. | ✅ |
| Existing policy and tenant guarantees intact | Full suite: 2,291 passed, including the native corpus at 100% (unchanged labels and decisions), tenant rewrite and MCP | ✅ |
| Real database integration tests | CI PostgreSQL and MySQL jobs run `test_sqli_engines.py` (+ markers on PostgreSQL) | CI: see PR |
| Required CI checks | 17 checks on the PR and on `main` | CI |
| New injection security tests | 432 tests: contract 91, markers 28, engines 307 (SQLite, PostgreSQL and MySQL variants), integrations 4, property 2 (700 generated cases) | ✅ local |
| No public API regression | `execute()`, executors, `mysql_executor` and `bind_placeholders` are kept. `bind_placeholders` is deprecated (documented). New names are additive. | ✅ |
| No secrets in logs, traces, errors or SARIF | `test_sqli_integrations.py` canary: parameter values are absent from audit, logs, spans, metrics and error messages. The v0.6 canary tests still pass. | ✅ |
| Build + `twine check --strict` | Run at the gate | Gate |
| Fresh install outside the repository | Run after publish | Post-release |
| Documentation accurate | LANDSCAPE, THREAT_MODEL, PREVENTION, LIMITATIONS, ADR-015, README, CHANGELOG, SECURITY.md | ✅ |
| Independent tools | Bandit 1.9.4 on `src`: no high-severity findings. The one B608 is the fixture loader (catalog names only, values bound). B102 is the benchmark workers loading a bundled protocol file. B101 asserts are type narrowing. pip-audit on the locked environment: no known vulnerabilities. | ✅ |

## Reproduce

```bash
pytest -q tests/security/test_sqli_binding_contract.py tests/security/test_sqli_parameter_markers.py \
  tests/security/test_sqli_integrations.py tests/property/test_sqli_property.py tests/security/test_sqli_engines.py
SQLNINJA_MYSQL_DSN=mysql://root:<pw>@127.0.0.1:3306/ pytest -q -m mysql tests/security/test_sqli_engines.py
bandit -q -r src && pip-audit -r <(pip freeze --exclude-editable)
```

Passing these tests does not prove universal SQL injection immunity
(see `docs/security/SQL_INJECTION_LIMITATIONS.md`).
