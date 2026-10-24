"""Pre-execution SQL checkpoint for agents.

The checkpoint separates two questions:

1. *Policy evaluation* — what does the policy say about this SQL for this caller?
   (:meth:`Guard.validate`, a pure function of SQL + policy + trusted context.)
2. *Execution authorization* — given that verdict, the enforcement mode and any human
   approval, may this exact SQL run now?

Nothing an LLM produces can change either answer. The role and tenant come from a
:class:`RequestContext` the application builds from its own authentication. Tool arguments,
SQL comments and model "explanations" are not inputs to either decision. Approvals are bound
to the SHA-256 of the exact SQL, the trace and the requesting principal, and can be used once.
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, TypeVar

from sqlguard_ninja.core.findings import Decision, ValidationResult
from sqlguard_ninja.core.guard import Guard
from sqlguard_ninja.integrations.audit import AuditEvent, AuditSink, redact_sql

T = TypeVar("T")


class EnforcementMode(StrEnum):
    BLOCK = "block"
    """DENY and REVIEW are not executed."""
    REVIEW = "review"
    """DENY is not executed; REVIEW runs only with a valid human approval."""
    AUDIT = "audit"
    """Everything runs; findings are recorded with ``enforced=False``. Monitoring only."""


@dataclass(frozen=True)
class RequestContext:
    """Trusted, server-side facts about the request. Build it from your auth layer only."""

    principal: str
    role: str | None
    tenant_id: Any = None
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def policy_context(self, tenant_key: str) -> dict[str, Any]:
        ctx = dict(self.attributes)
        if self.tenant_id is not None:
            ctx[tenant_key] = self.tenant_id
        return ctx


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    trace_id: str
    principal: str
    role: str | None
    sql_sha256: str
    summary: str
    created_at: float


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    approver: str
    reason: str = ""


class Approver(Protocol):
    """Decide (or defer) an approval request. Return None while pending."""

    def decide(self, request: ApprovalRequest) -> ApprovalDecision | None: ...


class DenyAllApprover:
    """Default: nothing is ever approved."""

    def decide(self, request: ApprovalRequest) -> ApprovalDecision | None:
        return ApprovalDecision(False, "system", "no approver configured")


class CallbackApprover:
    """Synchronous approval through a callback (e.g. a CLI prompt or chat-ops bot)."""

    def __init__(self, fn: Callable[[ApprovalRequest], ApprovalDecision | None]) -> None:
        self.fn = fn

    def decide(self, request: ApprovalRequest) -> ApprovalDecision | None:
        return self.fn(request)


class ApprovalQueue:
    """Asynchronous human approval.

    A REVIEW query is parked as a pending request. A human (a different principal) approves it
    out of band; the agent may then re-submit *the identical SQL* within ``ttl_s`` seconds.
    Each approval is single-use.
    """

    def __init__(self, ttl_s: float = 900.0, clock: Callable[[], float] = time.time) -> None:
        self.ttl_s = ttl_s
        self.clock = clock
        self.pending: dict[str, ApprovalRequest] = {}
        self._decided: dict[str, tuple[ApprovalRequest, ApprovalDecision, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(req: ApprovalRequest) -> str:
        return f"{req.trace_id}|{req.principal}|{req.sql_sha256}"

    def decide(self, request: ApprovalRequest) -> ApprovalDecision | None:
        key = self._key(request)
        with self._lock:
            decided = self._decided.get(key)
            if decided is not None:
                _req, decision, at = decided
                if self.clock() - at > self.ttl_s:
                    del self._decided[key]
                    return ApprovalDecision(False, decision.approver, "approval expired")
                del self._decided[key]  # single use
                return decision
            if not any(self._key(p) == key for p in self.pending.values()):
                self.pending[request.request_id] = request
            return None

    def _resolve(self, request_id: str, approver: str, approved: bool, reason: str) -> None:
        with self._lock:
            req = self.pending.get(request_id)
            if req is None:
                raise KeyError(f"no pending approval {request_id!r}")
            if approver == req.principal:
                raise PermissionError("the requesting principal cannot approve its own query")
            del self.pending[request_id]
            self._decided[self._key(req)] = (
                req,
                ApprovalDecision(approved, approver, reason),
                self.clock(),
            )

    def approve(self, request_id: str, approver: str, reason: str = "") -> None:
        self._resolve(request_id, approver, True, reason)

    def reject(self, request_id: str, approver: str, reason: str = "") -> None:
        self._resolve(request_id, approver, False, reason)


@dataclass(frozen=True)
class CheckpointOutcome:
    authorized: bool
    """May the exact SQL be executed now?"""
    enforced: bool
    """False in audit mode: a negative verdict was recorded but did not stop execution."""
    would_block: bool
    """True whenever the policy verdict was not ALLOW, regardless of mode."""
    mode: EnforcementMode
    result: ValidationResult
    agent_message: str
    """Text safe to return to the LLM. Never contains approval tokens or internal detail."""
    approval_request: ApprovalRequest | None = None
    approval: ApprovalDecision | None = None
    attempt: int = 1
    locked_out: bool = False
    audit_event: AuditEvent | None = None


class SQLBlockedError(PermissionError):
    def __init__(self, outcome: CheckpointOutcome) -> None:
        super().__init__(outcome.agent_message)
        self.outcome = outcome


class SQLCheckpoint:
    """Evaluate and authorize SQL before execution. Thread-safe."""

    def __init__(
        self,
        guard: Guard,
        mode: EnforcementMode | str = EnforcementMode.BLOCK,
        *,
        approver: Approver | None = None,
        audit_sink: AuditSink | None = None,
        max_denied_attempts: int | None = 5,
        dialect: str | None = None,
        log_redacted_sql: bool = True,
        rewrite_tenant_filters: bool = False,
    ) -> None:
        self.guard = guard
        self.mode = EnforcementMode(mode)
        self.approver: Approver = approver or DenyAllApprover()
        self.audit_sink = audit_sink
        self.max_denied_attempts = max_denied_attempts
        self.dialect = dialect or guard.policy.dialect
        self.log_redacted_sql = log_redacted_sql
        self.rewrite_tenant_filters = rewrite_tenant_filters
        """Opt-in: add missing tenant filters via AST rewrite, then validate the rewrite."""
        self._attempts: dict[str, int] = {}
        self._denials: dict[str, int] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ evaluate
    def evaluate(
        self, sql: str, context: RequestContext, *, _rewritten: bool = False
    ) -> CheckpointOutcome:
        started = time.perf_counter()
        policy_ctx = context.policy_context(self.guard.policy.tenant.context_key)
        result = self.guard.validate(
            sql, role=context.role, dialect=self.dialect, context=policy_ctx
        )
        with self._lock:
            attempt = self._attempts.get(context.trace_id, 0) + 1
            self._attempts[context.trace_id] = attempt
            denials = self._denials.get(context.trace_id, 0)
        locked = self.max_denied_attempts is not None and denials >= self.max_denied_attempts

        would_block = result.decision is not Decision.ALLOW
        approval_request: ApprovalRequest | None = None
        approval: ApprovalDecision | None = None
        if locked and self.mode is not EnforcementMode.AUDIT:
            authorized, enforced = False, True
        elif result.decision is Decision.ALLOW:
            authorized, enforced = True, True
        elif self.mode is EnforcementMode.AUDIT:
            authorized, enforced = True, False
        elif result.decision is Decision.REVIEW and self.mode is EnforcementMode.REVIEW:
            approval_request = ApprovalRequest(
                request_id=uuid.uuid4().hex,
                trace_id=context.trace_id,
                principal=context.principal,
                role=context.role,
                sql_sha256=result.sql_sha256,
                summary="; ".join(f.message for f in result.blocking_findings)[:500],
                created_at=time.time(),
            )
            approval = self.approver.decide(approval_request)
            if approval is not None and approval.approver == context.principal:
                approval = ApprovalDecision(False, approval.approver, "self-approval rejected")
            authorized = approval is not None and approval.approved
            enforced = True
        else:
            authorized, enforced = False, True

        if not authorized and enforced:
            with self._lock:
                self._denials[context.trace_id] = self._denials.get(context.trace_id, 0) + 1

        redacted = redact_sql(sql, self.dialect)
        message = self._agent_message(
            result, authorized, enforced, locked, approval_request, approval
        )
        event = AuditEvent(
            trace_id=context.trace_id,
            principal=context.principal,
            role=result.role,
            tenant=None if context.tenant_id is None else str(context.tenant_id),
            mode=self.mode.value,
            decision=result.decision.value,
            authorized=authorized,
            enforced=enforced,
            would_block=would_block,
            sql_sha256=result.sql_sha256,
            sql_redacted=redacted if self.log_redacted_sql else None,
            query_fingerprint=hashlib.sha256(redacted.encode()).hexdigest() if redacted else None,
            dialect=self.dialect,
            policy=result.policy_name,
            policy_revision=result.policy_revision,
            policy_fingerprint=result.policy_fingerprint,
            decision_id=result.decision_id,
            correlation_id=context.trace_id,
            tenant_filter_rewrite=_rewritten,
            findings=[
                {"rule_id": f.rule_id, "action": f.action.value, "category": f.category.value}
                for f in result.findings
            ],
            approval=None
            if approval is None
            else {"approved": approval.approved, "approver": approval.approver},
            attempt=attempt,
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
        if self.audit_sink is not None:
            self.audit_sink.emit(event)
        return CheckpointOutcome(
            authorized=authorized,
            enforced=enforced,
            would_block=would_block,
            mode=self.mode,
            result=result,
            agent_message=message,
            approval_request=approval_request,
            approval=approval,
            attempt=attempt,
            locked_out=locked,
            audit_event=event,
        )

    @staticmethod
    def _agent_message(
        result: ValidationResult,
        authorized: bool,
        enforced: bool,
        locked: bool,
        approval_request: ApprovalRequest | None,
        approval: ApprovalDecision | None,
    ) -> str:
        if locked and not authorized:
            return (
                "Query blocked: too many policy violations in this session. "
                "No further queries will run in this conversation."
            )
        reasons = "; ".join(
            f.message + (f" Suggestion: {f.remediation}" if f.remediation else "")
            for f in result.blocking_findings
        )
        if authorized and not enforced:
            return "Query executed (audit mode). Policy findings were recorded."
        if authorized:
            return "Query permitted."
        if approval_request is not None:
            if approval is None:
                return (
                    "Query requires human approval and was not executed. "
                    f"Reason: {reasons} Approval is handled outside this conversation."
                )
            return f"Query was not approved and was not executed. Reason: {reasons}"
        return (
            f"Query blocked by policy and not executed. Reason: {reasons} "
            "This decision is enforced by the server and cannot be overridden by the assistant."
        )

    # ------------------------------------------------------------------- execute
    def execute(
        self,
        sql: str,
        context: RequestContext,
        executor: Callable[[str, Mapping[str, Any]], T],
    ) -> T:
        """Evaluate, then run ``executor(sql, params)`` only if authorized.

        ``params`` contains the trusted context values (e.g. ``tenant_id``) for bind
        parameters. The SQL is executed exactly as validated. With
        ``rewrite_tenant_filters=True``, a query whose only problem is a missing tenant filter
        is rewritten (see :mod:`sqlguard_ninja.tenancy`); the *rewritten* string is then
        evaluated, audited and executed.
        """
        rewritten = False
        if self.rewrite_tenant_filters:
            # Imported lazily: tenancy depends on the guard, not the other way round.
            from sqlguard_ninja.tenancy import (  # noqa: PLC0415
                TenantRewriteRefused,
                apply_tenant_filters,
            )

            policy_ctx = context.policy_context(self.guard.policy.tenant.context_key)
            try:
                rewrite = apply_tenant_filters(
                    self.guard, sql, role=context.role, context=policy_ctx, dialect=self.dialect
                )
            except TenantRewriteRefused:
                rewrite = None  # fall through: evaluate the original and report its findings
            if rewrite is not None and rewrite.rewritten:
                sql, rewritten = rewrite.sql, True
        outcome = self.evaluate(sql, context, _rewritten=rewritten)
        if not outcome.authorized:
            raise SQLBlockedError(outcome)
        params = context.policy_context(self.guard.policy.tenant.context_key)
        return executor(sql, params)
