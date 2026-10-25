"""execute_safe through the FastAPI router, and parameter values never reaching any signal."""

from __future__ import annotations

import io
import json
import logging

import pytest

from sqlguard_ninja import Guard
from sqlguard_ninja.benchmarking.fixtures import create_sqlite
from sqlguard_ninja.integrations import (
    RequestContext,
    SQLBindingError,
    SQLCheckpoint,
    SQLiteSafeExecutor,
)
from sqlguard_ninja.integrations.audit import InMemoryAuditSink, LoggingAuditSink

CANARY = "CANARYp4r4m"
Q = "SELECT c.id FROM customers c WHERE c.tenant_id = :tenant_id AND c.email = :email"


def test_parameter_values_never_reach_audit_logs_or_telemetry(policy):
    otel = pytest.importorskip("opentelemetry.sdk.trace")
    pytest.importorskip("prometheus_client")
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from sqlguard_ninja.observability import GuardMetrics, Telemetry

    exporter = InMemorySpanExporter()
    provider = otel.TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    metrics, sink, stream = GuardMetrics(), InMemoryAuditSink(), io.StringIO()
    logger = logging.getLogger("sqlguard_ninja.test.params")
    logger.addHandler(logging.StreamHandler(stream))
    logger.setLevel(logging.INFO)
    logger.propagate = False

    class Both:
        def emit(self, event):
            sink.emit(event)
            LoggingAuditSink(logger).emit(event)

    cp = SQLCheckpoint(
        Guard(policy),
        dialect="sqlite",
        audit_sink=Both(),
        telemetry=Telemetry(tracer=provider.get_tracer("t"), metrics=metrics),
    )
    ctx = RequestContext(principal="u", role="support_analyst", tenant_id=1)
    run = SQLiteSafeExecutor(create_sqlite(policy))
    cp.execute_safe(Q, ctx, run, {"email": CANARY})
    with pytest.raises(SQLBindingError) as info:
        cp.execute_safe(Q, ctx, run, {"email": [CANARY]})
    emitted = [
        *(e.model_dump_json() for e in sink.events),
        stream.getvalue(),
        *(json.dumps(s.to_json()) for s in exporter.get_finished_spans()),
        metrics.render()[0].decode(),
        str(info.value),
    ]
    assert sink.events and all(CANARY not in text for text in emitted)


def test_fastapi_query_binds_params(policy):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from sqlguard_ninja.integrations.fastapi import create_router

    app = FastAPI()
    app.include_router(
        create_router(
            SQLCheckpoint(Guard(policy), dialect="sqlite"),
            lambda: RequestContext(principal="u", role="support_analyst", tenant_id=1),
            safe_executor=SQLiteSafeExecutor(create_sqlite(policy)),
        )
    )
    c = TestClient(app)
    assert c.post(
        "/v1/sql/query", json={"sql": Q, "params": {"email": "user3@example.com"}}
    ).json()["rows"] == [{"id": 3}]
    assert (
        c.post("/v1/sql/query", json={"sql": Q, "params": {"email": "' OR 1=1 --"}}).json()["rows"]
        == []
    )
    forged = c.post("/v1/sql/query", json={"sql": Q, "params": {"email": "x", "tenant_id": 2}})
    assert forged.status_code == 400 and forged.json()["detail"]["error"] == "invalid_parameters"
    assert (
        c.post("/v1/sql/query", json={"sql": Q, "params": {"email": {"a": 1}}}).status_code == 422
    )
    blocked = c.post(
        "/v1/sql/query",
        json={"sql": "SELECT p.card_number FROM payments p WHERE p.tenant_id = :tenant_id"},
    )
    assert blocked.status_code == 403


def test_fastapi_legacy_executor_rejects_params(policy):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from sqlguard_ninja.integrations.executors import sqlite_executor
    from sqlguard_ninja.integrations.fastapi import create_router

    app = FastAPI()
    app.include_router(
        create_router(
            SQLCheckpoint(Guard(policy), dialect="sqlite"),
            lambda: RequestContext(principal="u", role="support_analyst", tenant_id=1),
            executor=sqlite_executor(create_sqlite(policy)),
        )
    )
    r = TestClient(app).post("/v1/sql/query", json={"sql": Q, "params": {"email": "x"}})
    assert r.status_code == 400


def test_executor_dialect_must_match(policy):
    cp = SQLCheckpoint(Guard(policy), dialect="postgres")
    with pytest.raises(SQLBindingError, match="dialect"):
        cp.execute_safe(
            Q,
            RequestContext(principal="u", role="support_analyst", tenant_id=1),
            SQLiteSafeExecutor(create_sqlite(policy)),
            {"email": "x"},
        )
