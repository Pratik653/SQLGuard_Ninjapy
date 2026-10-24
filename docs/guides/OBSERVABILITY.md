# Observability

SQLGuard Ninja can emit OpenTelemetry traces, Prometheus metrics, structured JSON audit
events and SARIF reports. All of these are optional, and none are imported by the core.

```bash
python -m pip install "sqlguard-ninja[otel,prometheus]"
```

## Privacy contract

By default, **no signal contains**:

* SQL text, literal values or comments
* request context values (for example API keys or other attributes)
* the tenant id (in traces and metrics)
* the principal (in traces and metrics)
* internal finding `detail`

Signals carry the decision, rule ids, bounded labels and correlation identifiers. The
correlation identifiers are the decision id, the policy fingerprint and revision, the
literal-insensitive query fingerprint and the correlation (trace) id. Exception messages are
never recorded, because they can quote SQL; spans record only the exception type.

`tests/unit/test_observability.py` checks this. It sends queries containing a canary value
through the checkpoint in many literal forms and checks the canary appears in none of the
signals. The forms include:

* strings, comments, dollar-quoted, `E''`, `U&''`, `N''` and hex strings
* `INTERVAL` text and MySQL double-quoted strings
* unterminated and multi-statement input

The signals checked are audit JSON, logging output, exported spans and the Prometheus
exposition. The test also puts the canary in request-context secrets.

## Tracing (OpenTelemetry)

```python
from opentelemetry import trace
from sqlguard_ninja import Guard, Policy
from sqlguard_ninja.integrations import SQLCheckpoint
from sqlguard_ninja.observability import GuardMetrics, Telemetry

telemetry = Telemetry(tracer=trace.get_tracer("my-app"), metrics=GuardMetrics())
checkpoint = SQLCheckpoint(Guard(Policy.from_file("policy.yaml")), telemetry=telemetry)
```

The checkpoint instruments its guard automatically. To instrument a guard used on its own,
call `telemetry.instrument(guard)`. Configure exporters and sampling with the OpenTelemetry
SDK as usual.

| Span | Attributes |
|---|---|
| `sqlguard.checkpoint` | `sqlguard.mode`, `.decision`, `.decision_id`, `.authorized`, `.enforced`, `.rate_limited`, `.tenant_filter_rewrite`, `.correlation_id`, `.attempt` |
| `sqlguard.validate` (child) | `sqlguard.decision`, `.decision_id`, `.role`, `.dialect`, `.policy.name`, `.policy.revision`, `.policy.fingerprint`, `.findings.count`, `.findings.rule_ids`, `.query_fingerprint`; on exceptions `error.type` and an ERROR status |

## Metrics (Prometheus)

`GuardMetrics()` uses a private `CollectorRegistry`. To use your own, pass
`GuardMetrics(registry=...)`. Expose the metrics with `metrics.render()` (returns the body and
content type) or with `prometheus_client.start_http_server(port, registry=metrics.registry)`.

| Metric | Labels | Meaning |
|---|---|---|
| `sqlguard_decisions_total` | `decision`, `role`, `dialect`, `policy` | validations |
| `sqlguard_findings_total` | `rule_id`, `action` | findings per rule |
| `sqlguard_validation_duration_seconds` | `decision` | histogram |
| `sqlguard_validation_errors_total` | `error` (exception type) | exceptions during validation |
| `sqlguard_limit_rejections_total` | `rule_id` | length, AST size, structure and cost limits |
| `sqlguard_checkpoint_outcomes_total` | `mode`, `outcome` | `allowed`, `blocked`, `approved`, `rejected`, `audit_only`, `rate_limited` |
| `sqlguard_policy_info` | `policy`, `revision`, `fingerprint` | always 1 |

Label cardinality is bounded. A role not defined in the policy is reported as `unknown`.

## Audit events

`SQLCheckpoint(audit_sink=...)` writes one `AuditEvent` per decision. It works with
`JsonlAuditSink`, `LoggingAuditSink`, or your own sink. Each event carries:

* `schema_version` (`sqlninja.audit/1`), `decision_id`, `correlation_id`
* `policy_revision`, `policy_fingerprint`
* `sql_sha256`, `query_fingerprint`
* `sql_redacted`: literals become `?` and comments are dropped. It is withheld (`null`) if the
  SQL cannot be parsed, or if any literal token survives redaction.
* `rate_limited`, plus the rule ids and actions of the findings

Audit events do record the principal and tenant, because that is their purpose. Pass
`principal_hmac_key=` to store an HMAC-SHA256 pseudonym of the principal instead. Treat audit
logs as sensitive. If a short query embeds a guessable secret, its `sql_sha256` can be
brute-forced. Use `query_fingerprint` where an identifier is enough.

## SARIF

```bash
sqlninja scan sql/ --policy policy.yaml --role reporting --tenant 1 --format sarif --output sqlninja.sarif
```

`scan` validates every statement in `*.sql` files and splits them with the dialect tokenizer.
Each finding becomes a SARIF result:

* located at its statement
* level by action: `error` for deny, `warning` for review, `note` for warn
* carrying a `partialFingerprints` entry that is stable when only literals change

No code snippet is copied into the log. The output validates against the official OASIS SARIF
2.1.0 schema, both in the tests and in CI. To upload to GitHub code scanning, see
[CI_INTEGRATION.md](CI_INTEGRATION.md).

## Grafana dashboard and synthetic telemetry

`deploy/grafana/sqlguard-ninja.json` is a Grafana dashboard. It shows:

* decisions per second
* deny ratio and errors
* p50/p95/p99 latency
* top rules
* checkpoint outcomes
* resource-limit rejections
* decisions by role
* loaded policies

To see it with synthetic traffic:

```bash
docker compose -f examples/observability/docker-compose.yml up -d --wait
# Grafana (read-only, anonymous): http://127.0.0.1:3000/d/sqlguard-ninja
# Prometheus:                     http://127.0.0.1:9090
```

The traffic generator replays the bundled synthetic corpus through an instrumented
checkpoint. It executes nothing. CI starts this stack and checks two things: Prometheus has
scraped `sqlguard_decisions_total`, and Grafana has provisioned the dashboard and can query
Prometheus.
