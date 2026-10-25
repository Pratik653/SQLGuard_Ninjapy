"""Agent and application integrations.

The framework-specific modules (``langchain``, ``langgraph``, ``fastapi``) import their
frameworks and are only available with the matching extra installed.
"""

from sqlguard_ninja.integrations.audit import (
    AuditEvent,
    InMemoryAuditSink,
    JsonlAuditSink,
    LoggingAuditSink,
    redact_sql,
)
from sqlguard_ninja.integrations.binding import (
    BoundStatement,
    SQLBindingError,
    safe_identifier,
    safe_order_by,
)
from sqlguard_ninja.integrations.checkpoint import (
    ApprovalDecision,
    ApprovalQueue,
    ApprovalRequest,
    CallbackApprover,
    CheckpointOutcome,
    DenyAllApprover,
    EnforcementMode,
    RequestContext,
    SQLBlockedError,
    SQLCheckpoint,
)
from sqlguard_ninja.integrations.executors import (
    PsycopgSafeExecutor,
    SafeExecutor,
    SQLiteSafeExecutor,
)

__all__ = [
    "ApprovalDecision",
    "ApprovalQueue",
    "ApprovalRequest",
    "AuditEvent",
    "BoundStatement",
    "CallbackApprover",
    "CheckpointOutcome",
    "DenyAllApprover",
    "EnforcementMode",
    "InMemoryAuditSink",
    "JsonlAuditSink",
    "LoggingAuditSink",
    "PsycopgSafeExecutor",
    "RequestContext",
    "SQLBindingError",
    "SQLBlockedError",
    "SQLCheckpoint",
    "SQLiteSafeExecutor",
    "SafeExecutor",
    "redact_sql",
    "safe_identifier",
    "safe_order_by",
]
