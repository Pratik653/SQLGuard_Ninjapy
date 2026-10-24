"""Tracing, metrics, audit privacy and SARIF output."""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path

import jsonschema
import pytest

from sqlguard_ninja import Guard
from sqlguard_ninja.cli.main import main
from sqlguard_ninja.integrations import RequestContext, SQLCheckpoint
from sqlguard_ninja.integrations.audit import InMemoryAuditSink, LoggingAuditSink, redact_sql
from sqlguard_ninja.observability import GuardMetrics, Telemetry
from sqlguard_ninja.observability.telemetry import query_fingerprint
from sqlguard_ninja.reporting.sarif import ScanResult, split_statements, to_sarif

pytest.importorskip("prometheus_client")
otel_sdk = pytest.importorskip("opentelemetry.sdk.trace")
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)

SCHEMA = json.loads(
    (Path(__file__).parents[1] / "data" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)
CANARY = "CANARYzq7"  # must never appear in any emitted signal


@pytest.fixture
def otel():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer("test"), exporter


@pytest.fixture
def telemetry(otel):
    return Telemetry(tracer=otel[0], metrics=GuardMetrics())


def _sample(metrics: GuardMetrics, name: str, **labels: str) -> float:
    return metrics.registry.get_sample_value(name, labels) or 0.0


def ctx(tenant=1, trace="t-1", principal="alice@example.com"):
    return RequestContext(
        principal=principal, role="support_analyst", tenant_id=tenant, trace_id=trace
    )


# --------------------------------------------------------------------------- metrics
def test_decision_and_finding_metrics(policy, telemetry):
    g = telemetry.instrument(Guard(policy))
    g.validate(
        "SELECT o.id FROM orders o WHERE o.tenant_id = 1",
        role="support_analyst",
        context={"tenant_id": 1},
    )
    g.validate(
        "SELECT p.card_number FROM payments p WHERE p.tenant_id = 1",
        role="support_analyst",
        context={"tenant_id": 1},
    )
    g.validate("SELECT 1", role="no_such_role")
    m = telemetry.metrics
    base = {"role": "support_analyst", "dialect": "postgres", "policy": policy.name}
    assert _sample(m, "sqlguard_decisions_total", decision="allow", **base) == 1
    assert _sample(m, "sqlguard_decisions_total", decision="deny", **base) == 1
    assert (
        _sample(
            m,
            "sqlguard_decisions_total",
            decision="deny",
            role="unknown",
            dialect="postgres",
            policy=policy.name,
        )
        == 1
    )
    assert _sample(m, "sqlguard_findings_total", rule_id="column.not_permitted", action="deny") == 1
    assert _sample(m, "sqlguard_validation_duration_seconds_count", decision="allow") == 1
    assert (
        _sample(
            m,
            "sqlguard_policy_info",
            policy=policy.name,
            revision=policy.revision,
            fingerprint=policy.fingerprint,
        )
        == 1
    )


def test_limit_rejections_are_counted(policy, telemetry):
    g = telemetry.instrument(Guard(policy))
    g.validate("SELECT 1 " + " " * 200_000, role="support_analyst")
    assert (
        _sample(telemetry.metrics, "sqlguard_limit_rejections_total", rule_id="parse.too_long") == 1
    )


class _Boom:
    rule_ids = ("custom.boom",)

    def check(self, ctx):
        raise RuntimeError(f"failure quoting {CANARY}")


def test_errors_are_counted_and_spans_carry_only_the_type(policy, otel):
    tracer, exporter = otel
    t = Telemetry(tracer=tracer, metrics=GuardMetrics())
    g = t.instrument(Guard(policy).with_rules([_Boom()]))
    with pytest.raises(RuntimeError):
        g.validate(
            "SELECT o.id FROM orders o WHERE o.tenant_id = 1",
            role="support_analyst",
            context={"tenant_id": 1},
        )
    assert _sample(t.metrics, "sqlguard_validation_errors_total", error="RuntimeError") == 1
    (span,) = exporter.get_finished_spans()
    assert span.status.description == "RuntimeError"
    assert not span.events  # no exception event with the message
    assert CANARY not in json.dumps(span.to_json())


def test_checkpoint_outcomes_including_rate_limit(policy, telemetry):
    cp = SQLCheckpoint(Guard(policy), telemetry=telemetry, max_denied_attempts=2)
    bad = "SELECT p.card_number FROM payments p WHERE p.tenant_id = 1"
    for _ in range(3):
        cp.evaluate(bad, ctx())
    m = telemetry.metrics
    assert _sample(m, "sqlguard_checkpoint_outcomes_total", mode="block", outcome="blocked") == 2
    assert (
        _sample(m, "sqlguard_checkpoint_outcomes_total", mode="block", outcome="rate_limited") == 1
    )
    audit = SQLCheckpoint(Guard(policy), mode="audit", telemetry=telemetry)
    audit.evaluate(bad, ctx(trace="t-2"))
    assert _sample(m, "sqlguard_checkpoint_outcomes_total", mode="audit", outcome="audit_only") == 1


def test_metrics_render_exposition(telemetry, policy):
    telemetry.instrument(Guard(policy)).validate("SELECT 1", role="support_analyst")
    body, content_type = telemetry.metrics.render()
    assert b"sqlguard_decisions_total" in body and content_type.startswith("text/plain")


# --------------------------------------------------------------------------- tracing
def test_checkpoint_span_is_parent_of_validation_span(policy, otel):
    tracer, exporter = otel
    t = Telemetry(tracer=tracer)
    cp = SQLCheckpoint(Guard(policy), telemetry=t)
    out = cp.evaluate(
        "SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id", ctx(trace="corr-9")
    )
    spans = {s.name: s for s in exporter.get_finished_spans()}
    v, c = spans["sqlguard.validate"], spans["sqlguard.checkpoint"]
    assert v.parent.span_id == c.context.span_id
    assert v.attributes["sqlguard.decision"] == "allow"
    assert v.attributes["sqlguard.decision_id"] == out.result.decision_id
    assert v.attributes["sqlguard.policy.fingerprint"] == policy.fingerprint
    assert v.attributes["sqlguard.query_fingerprint"] == out.audit_event.query_fingerprint
    assert c.attributes["sqlguard.correlation_id"] == "corr-9"
    assert c.attributes["sqlguard.authorized"] is True


def test_no_tracer_no_metrics_is_a_no_op(policy):
    cp = SQLCheckpoint(Guard(policy), telemetry=Telemetry())
    assert cp.evaluate("SELECT o.id FROM orders o WHERE o.tenant_id = 1", ctx()).authorized


# --------------------------------------------------------------------------- privacy
SECRET_SQL = [
    ("postgres", f"SELECT o.id FROM orders o WHERE o.tenant_id = 1 AND o.status = '{CANARY}'"),
    ("postgres", f"SELECT o.id /* password={CANARY} */ FROM orders o WHERE o.tenant_id = 1"),
    ("postgres", f"SELECT o.id FROM orders o WHERE o.tenant_id = 1 -- token={CANARY}"),
    ("postgres", f"SELECT $${CANARY}$$ FROM orders o WHERE o.tenant_id = 1"),
    ("postgres", f"SELECT E'{CANARY}' FROM orders o WHERE o.tenant_id = 1"),
    ("postgres", f"SELECT U&'{CANARY}' FROM orders o WHERE o.tenant_id = 1"),
    ("postgres", f"SELECT N'{CANARY}' FROM orders o WHERE o.tenant_id = 1"),
    (
        "postgres",
        f"SELECT o.id FROM orders o WHERE o.created_at > NOW() - INTERVAL '5 {CANARY}' AND o.tenant_id = 1",
    ),
    ("postgres", "SELECT X'43414e415259' FROM orders o WHERE o.tenant_id = 1"),
    ("mysql", f'SELECT o.id FROM orders o WHERE o.tenant_id = 1 AND o.status = "{CANARY}"'),
    ("postgres", f"SELECT p.card_number FROM payments p WHERE p.card_number = '{CANARY}'"),
    ("postgres", f"SELECT o.id FROM orders o WHERE o.status = '{CANARY}"),  # unterminated
    (
        "postgres",
        f"SELECT o.id FROM orders o WHERE o.tenant_id = 2 AND o.status = '{CANARY}'; DROP TABLE x",
    ),
]


@pytest.mark.parametrize(("dialect", "sql"), SECRET_SQL, ids=range(len(SECRET_SQL)))
def test_no_literal_or_secret_reaches_any_signal(policy, otel, dialect, sql):
    tracer, exporter = otel
    metrics = GuardMetrics()
    sink = InMemoryAuditSink()
    stream = io.StringIO()
    logger = logging.getLogger(f"sqlguard_ninja.test.{id(stream)}")
    logger.addHandler(logging.StreamHandler(stream))
    logger.setLevel(logging.INFO)
    logger.propagate = False

    class Both:
        def emit(self, event):
            sink.emit(event)
            LoggingAuditSink(logger).emit(event)

    context = RequestContext(
        principal="alice@example.com",
        role="support_analyst",
        tenant_id=1,
        trace_id="trace-x",
        attributes={"api_key": f"key-{CANARY}", "tenant_secret": CANARY},
    )
    cp = SQLCheckpoint(
        Guard(policy),
        dialect=dialect,
        audit_sink=Both(),
        telemetry=Telemetry(tracer=tracer, metrics=metrics),
    )
    cp.evaluate(sql, context)
    emitted = [
        *(e.model_dump_json() for e in sink.events),
        stream.getvalue(),
        *(json.dumps(s.to_json()) for s in exporter.get_finished_spans()),
        metrics.render()[0].decode(),
    ]
    for text in emitted:
        assert CANARY.lower() not in text.lower()
        assert "43414e415259" not in text.lower()
    spans = exporter.get_finished_spans()
    for s in spans:
        assert "alice" not in json.dumps(s.to_json())  # principal stays out of telemetry
        assert not any(
            "tenant" in k and k != "sqlguard.tenant_filter_rewrite" for k in s.attributes
        )


def test_redaction_withholds_unknown_literal_forms():
    assert redact_sql("SELECT a FROM t WHERE b = 'x'", "postgres") == "SELECT a FROM t WHERE b = ?"
    for dialect, sql in SECRET_SQL[:10]:
        out = redact_sql(sql, dialect)
        assert out is None or CANARY not in out


def test_principal_can_be_pseudonymised(policy):
    sink = InMemoryAuditSink()
    cp = SQLCheckpoint(Guard(policy), audit_sink=sink, principal_hmac_key=b"k" * 32)
    cp.evaluate("SELECT 1", ctx())
    (event,) = sink.events
    assert event.principal.startswith("hmac-sha256:") and "alice" not in event.model_dump_json()
    assert event.schema_version == "sqlninja.audit/1"


def test_query_fingerprint_ignores_literals():
    a = query_fingerprint("SELECT o.id FROM orders o WHERE o.tenant_id = 1", "postgres")
    b = query_fingerprint("SELECT o.id FROM orders o WHERE o.tenant_id = 2", "postgres")
    assert a == b and a is not None


# --------------------------------------------------------------------------- SARIF
SQL_FILE = (
    "SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id;\n"
    "\n"
    "SELECT p.card_number\n  FROM payments p WHERE p.tenant_id = 1;\n"
    "SELECT o.id FROM orders o WHERE o.tenant_id = 1 AND o.status = 'a;b'\n"
)


def test_split_statements_positions():
    sts = split_statements(SQL_FILE, "postgres")
    assert [(s.start_line, s.start_column, s.end_line) for s in sts] == [
        (1, 1, 1),
        (3, 1, 4),
        (5, 1, 5),
    ]
    assert sts[2].sql.endswith("'a;b'")


def test_split_statements_falls_back_on_tokenizer_errors():
    sts = split_statements("SELECT 1;\nSELECT 'oops\n", "postgres")
    assert [s.start_line for s in sts] == [1, 2]


def _scan(policy, text, uri="q.sql"):
    g = Guard(policy)
    return [
        ScanResult(
            uri,
            st,
            g.validate(st.sql, role="support_analyst", context={"tenant_id": 1}),
            query_fingerprint(st.sql, "postgres"),
        )
        for st in split_statements(text, "postgres")
    ]


def test_sarif_is_schema_valid_and_meaningful(policy):
    log = to_sarif(_scan(policy, SQL_FILE), policy, ["q.sql"])
    jsonschema.validate(log, SCHEMA)
    run = log["runs"][0]
    results = run["results"]
    assert {r["ruleId"] for r in results} == {"column.not_permitted", "privacy.label_denied"}
    assert all(r["level"] == "error" for r in results)
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert [x["id"] for x in run["tool"]["driver"]["rules"]][results[0]["ruleIndex"]] == results[0][
        "ruleId"
    ]
    assert run["properties"]["policyFingerprint"] == policy.fingerprint


def test_sarif_review_is_warning_and_no_sql_is_copied(policy):
    text = f"SELECT o.id FROM orders o WHERE o.status = '{CANARY}'"
    log = to_sarif(_scan(policy, text), policy)
    jsonschema.validate(log, SCHEMA)
    assert CANARY not in json.dumps(log)
    assert {r["level"] for r in log["runs"][0]["results"]} <= {"error", "warning", "note"}


def test_sarif_fingerprints_are_stable_across_literals(policy):
    a = to_sarif(_scan(policy, "SELECT o.id FROM orders o WHERE o.tenant_id = 2"), policy)
    b = to_sarif(_scan(policy, "SELECT o.id FROM orders o WHERE o.tenant_id = 3"), policy)
    fa = [r["partialFingerprints"] for r in a["runs"][0]["results"]]
    assert fa and fa == [r["partialFingerprints"] for r in b["runs"][0]["results"]]


def test_cli_scan_sarif_and_exit_codes(tmp_path, capsys):
    (tmp_path / "ok.sql").write_text(
        "SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id;\n", encoding="utf-8"
    )
    (tmp_path / "bad.sql").write_text(
        "SELECT p.card_number FROM payments p WHERE p.tenant_id = 1;\n", encoding="utf-8"
    )
    out = tmp_path / "out.sarif"
    args = [
        "scan",
        str(tmp_path),
        "--policy",
        "builtin:retail_saas",
        "--role",
        "support_analyst",
        "--tenant",
        "1",
        "--root",
        str(tmp_path),
    ]
    assert main([*args, "--format", "sarif", "--output", str(out)]) == 1
    log = json.loads(out.read_text(encoding="utf-8"))
    jsonschema.validate(log, SCHEMA)
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in log["runs"][0]["results"]
    }
    assert uris == {"bad.sql"}
    assert main([*args, "--fail-on", "never"]) == 0
    assert (
        main(
            [
                "scan",
                str(tmp_path / "ok.sql"),
                "--policy",
                "builtin:retail_saas",
                "--role",
                "support_analyst",
                "--tenant",
                "1",
            ]
        )
        == 0
    )
    capsys.readouterr()
