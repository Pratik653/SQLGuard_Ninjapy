"""Prometheus metrics for validation and checkpoint decisions (extra ``[prometheus]``).

Label values are bounded: roles not defined in the policy are reported as ``unknown``, and no
label carries SQL, tenant ids or principals.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlguard_ninja.core.findings import Action, Category, ValidationResult

if TYPE_CHECKING:
    from sqlguard_ninja.integrations.audit import AuditEvent
    from sqlguard_ninja.policy.model import Policy

# Findings that mean a resource limit stopped or flagged the query.
LIMIT_RULES = frozenset({"parse.too_long", "parse.too_complex"})
LIMIT_CATEGORIES = frozenset({Category.STRUCTURE, Category.COST})
DURATION_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)


def _require() -> Any:
    try:
        import prometheus_client  # noqa: PLC0415 - optional extra
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            'Prometheus metrics need the extra: pip install "sqlguard-ninja[prometheus]"'
        ) from exc
    return prometheus_client


class GuardMetrics:
    """Counters and histograms in a Prometheus registry (a private one by default)."""

    def __init__(self, registry: Any | None = None, namespace: str = "sqlguard") -> None:
        prom = _require()
        self._prom = prom
        self.registry = registry if registry is not None else prom.CollectorRegistry()
        r, ns = self.registry, namespace
        self.decisions = prom.Counter(
            "decisions",
            "Validation decisions.",
            ["decision", "role", "dialect", "policy"],
            namespace=ns,
            registry=r,
        )
        self.findings = prom.Counter(
            "findings", "Policy findings by rule.", ["rule_id", "action"], namespace=ns, registry=r
        )
        self.duration = prom.Histogram(
            "validation_duration_seconds",
            "Time spent validating one SQL string.",
            ["decision"],
            namespace=ns,
            registry=r,
            buckets=DURATION_BUCKETS,
        )
        self.errors = prom.Counter(
            "validation_errors",
            "Exceptions raised during validation.",
            ["error"],
            namespace=ns,
            registry=r,
        )
        self.limits = prom.Counter(
            "limit_rejections",
            "Queries denied or flagged by a resource limit.",
            ["rule_id"],
            namespace=ns,
            registry=r,
        )
        self.checkpoint = prom.Counter(
            "checkpoint_outcomes",
            "Checkpoint authorization outcomes.",
            ["mode", "outcome"],
            namespace=ns,
            registry=r,
        )
        self.policy_info = prom.Gauge(
            "policy_info",
            "Loaded policy identity (value is always 1).",
            ["policy", "revision", "fingerprint"],
            namespace=ns,
            registry=r,
        )

    def register_policy(self, policy: Policy) -> None:
        self.policy_info.labels(policy.name, policy.revision, policy.fingerprint).set(1)

    def observe_validation(
        self, result: ValidationResult, duration_s: float, roles: frozenset[str]
    ) -> None:
        role = result.role if result.role in roles else "unknown"
        decision = result.decision.value
        self.decisions.labels(decision, role, result.dialect, result.policy_name).inc()
        self.duration.labels(decision).observe(duration_s)
        for f in result.findings:
            self.findings.labels(f.rule_id, f.action.value).inc()
            if f.action is not Action.WARN and (
                f.rule_id in LIMIT_RULES or f.category in LIMIT_CATEGORIES
            ):
                self.limits.labels(f.rule_id).inc()

    def observe_error(self, error: BaseException) -> None:
        self.errors.labels(type(error).__name__).inc()

    def observe_checkpoint(self, event: AuditEvent) -> None:
        if event.rate_limited:
            outcome = "rate_limited"
        elif not event.enforced:
            outcome = "audit_only"
        elif event.approval is not None:
            outcome = "approved" if event.authorized else "rejected"
        else:
            outcome = "allowed" if event.authorized else "blocked"
        self.checkpoint.labels(event.mode, outcome).inc()

    def render(self) -> tuple[bytes, str]:
        """The text exposition format and its content type, for a ``/metrics`` endpoint."""
        return self._prom.generate_latest(self.registry), self._prom.CONTENT_TYPE_LATEST
