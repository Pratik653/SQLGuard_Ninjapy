"""Tracing and the instrumented guard.

The tracer is any OpenTelemetry ``Tracer`` (``opentelemetry.trace.get_tracer(...)``); the
exporter and sampling are configured by the application through the OpenTelemetry SDK.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from sqlguard_ninja._version import __version__
from sqlguard_ninja.core.findings import ValidationResult
from sqlguard_ninja.core.guard import Guard
from sqlguard_ninja.integrations.audit import redact_sql
from sqlguard_ninja.observability.metrics import GuardMetrics

if TYPE_CHECKING:
    from sqlguard_ninja.integrations.audit import AuditEvent


def query_fingerprint(sql: str, dialect: str) -> str | None:
    """SHA-256 of the redacted SQL: equal for queries that differ only in literals."""
    redacted = redact_sql(sql, dialect)
    return hashlib.sha256(redacted.encode()).hexdigest() if redacted else None


class Telemetry:
    """Bundle of an optional tracer and optional :class:`GuardMetrics`."""

    def __init__(self, *, tracer: Any | None = None, metrics: GuardMetrics | None = None) -> None:
        self.tracer = tracer
        self.metrics = metrics

    @classmethod
    def from_opentelemetry(
        cls, metrics: GuardMetrics | None = None, name: str = "sqlguard_ninja"
    ) -> Telemetry:
        """Use the globally configured OpenTelemetry tracer provider."""
        try:
            from opentelemetry import trace  # noqa: PLC0415 - optional extra
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                'Tracing needs the extra: pip install "sqlguard-ninja[otel]"'
            ) from exc
        return cls(tracer=trace.get_tracer(name, __version__), metrics=metrics)

    def instrument(self, guard: Guard) -> InstrumentedGuard:
        if isinstance(guard, InstrumentedGuard) and guard.telemetry is self:
            return guard
        return InstrumentedGuard(guard, self)

    @contextmanager
    def span(self, name: str) -> Iterator[Any | None]:
        if self.tracer is None:
            yield None
            return
        with self.tracer.start_as_current_span(
            name, record_exception=False, set_status_on_exception=False
        ) as span:
            yield span

    def checkpoint(self, event: AuditEvent, span: Any | None) -> None:
        if span is not None:
            span.set_attributes(
                {
                    "sqlguard.mode": event.mode,
                    "sqlguard.decision": event.decision,
                    "sqlguard.decision_id": event.decision_id,
                    "sqlguard.authorized": event.authorized,
                    "sqlguard.enforced": event.enforced,
                    "sqlguard.rate_limited": event.rate_limited,
                    "sqlguard.tenant_filter_rewrite": event.tenant_filter_rewrite,
                    "sqlguard.correlation_id": event.correlation_id or "",
                    "sqlguard.attempt": event.attempt,
                }
            )
        if self.metrics is not None:
            self.metrics.observe_checkpoint(event)


def _error_status(span: Any, error: BaseException) -> None:
    # Only the exception type: messages can quote the SQL that caused them.
    from opentelemetry.trace import Status, StatusCode  # noqa: PLC0415 - optional extra

    span.set_attribute("error.type", type(error).__name__)
    span.set_status(Status(StatusCode.ERROR, type(error).__name__))


class InstrumentedGuard(Guard):
    """A :class:`Guard` that emits a span and metrics for every validation."""

    def __init__(self, guard: Guard, telemetry: Telemetry) -> None:
        super().__init__(guard.policy, guard.rules)
        self.telemetry = telemetry
        self._roles = frozenset(guard.policy.roles)
        if telemetry.metrics is not None:
            telemetry.metrics.register_policy(guard.policy)

    def with_rules(self, extra: Any) -> InstrumentedGuard:
        return InstrumentedGuard(super().with_rules(extra), self.telemetry)

    def validate(
        self,
        sql: str,
        *,
        role: str | None = None,
        dialect: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> ValidationResult:
        t = self.telemetry
        started = time.perf_counter()
        with t.span("sqlguard.validate") as span:
            try:
                result = super().validate(sql, role=role, dialect=dialect, context=context)
            except Exception as exc:
                if t.metrics is not None:
                    t.metrics.observe_error(exc)
                if span is not None:
                    _error_status(span, exc)
                raise
            duration = time.perf_counter() - started
            if span is not None:
                span.set_attributes(_span_attributes(result, sql, self._roles))
            if t.metrics is not None:
                t.metrics.observe_validation(result, duration, self._roles)
        return result


def _span_attributes(result: ValidationResult, sql: str, roles: frozenset[str]) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "sqlguard.decision": result.decision.value,
        "sqlguard.decision_id": result.decision_id,
        "sqlguard.role": result.role if result.role in roles else "unknown",
        "sqlguard.dialect": result.dialect,
        "sqlguard.policy.name": result.policy_name,
        "sqlguard.policy.revision": result.policy_revision,
        "sqlguard.policy.fingerprint": result.policy_fingerprint,
        "sqlguard.findings.count": len(result.findings),
        "sqlguard.findings.rule_ids": sorted({f.rule_id for f in result.findings}),
    }
    fingerprint = query_fingerprint(sql, result.dialect)
    if fingerprint:
        attrs["sqlguard.query_fingerprint"] = fingerprint
    return attrs
