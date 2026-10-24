"""Optional, privacy-safe observability: OpenTelemetry tracing and Prometheus metrics.

Nothing here is imported by the core. Install the extras you use::

    pip install "sqlguard-ninja[otel]"         # tracing (opentelemetry-api)
    pip install "sqlguard-ninja[prometheus]"   # metrics (prometheus-client)

Signals never contain SQL text, literal values, the tenant id, the principal, request
context values or internal finding detail. They carry the decision, the rule ids, bounded
labels (role, dialect, policy) and identifiers for correlation: the decision id, policy
fingerprint and revision, the literal-insensitive query fingerprint and the correlation id.
"""

from sqlguard_ninja.observability.metrics import GuardMetrics
from sqlguard_ninja.observability.telemetry import InstrumentedGuard, Telemetry

__all__ = ["GuardMetrics", "InstrumentedGuard", "Telemetry"]
