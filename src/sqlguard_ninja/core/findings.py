"""Structured diagnostics produced by policy rules and combined into a decision."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """How serious a finding is. Independent of the action taken."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(StrEnum):
    """What a single finding asks the guard to do."""

    DENY = "deny"
    REVIEW = "review"
    WARN = "warn"


class Decision(StrEnum):
    """The combined verdict for one SQL string."""

    ALLOW = "allow"
    REVIEW = "review"
    DENY = "deny"


class Category(StrEnum):
    """Tool-agnostic finding categories, shared with the benchmark taxonomy."""

    PARSE = "parse"
    STATEMENT = "statement"
    CATALOG = "catalog"
    FUNCTION = "function"
    TABLE_ACCESS = "table_access"
    COLUMN_ACCESS = "column_access"
    PRIVACY = "privacy"
    TENANT = "tenant"
    COST = "cost"
    STRUCTURE = "structure"


class Finding(BaseModel):
    """One observation made by a rule.

    ``message`` is safe to show to the caller (including an LLM agent). ``detail`` may name
    schema objects and is meant for audit logs and operators; integrations decide whether
    to disclose it based on ``Policy.disclosure``.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str
    category: Category
    severity: Severity
    action: Action
    message: str
    detail: str | None = None
    table: str | None = None
    column: str | None = None
    labels: tuple[str, ...] = ()
    remediation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


_ACTION_RANK = {Action.WARN: 0, Action.REVIEW: 1, Action.DENY: 2}


def combine(findings: list[Finding]) -> Decision:
    """Combine findings: any deny wins, then any review, otherwise allow."""
    worst = max((_ACTION_RANK[f.action] for f in findings), default=0)
    if worst == 2:
        return Decision.DENY
    if worst == 1:
        return Decision.REVIEW
    return Decision.ALLOW


class ValidationResult(BaseModel):
    """Outcome of :meth:`sqlguard_ninja.Guard.validate`."""

    model_config = ConfigDict(frozen=True)

    decision: Decision
    findings: tuple[Finding, ...]
    sql_sha256: str
    dialect: str
    role: str | None
    policy_name: str
    policy_version: int
    policy_revision: str = "unversioned"
    policy_fingerprint: str = ""
    decision_id: str = ""
    """Unique id of this decision (correlates the result, audit event and logs)."""
    tables: tuple[str, ...] = ()
    columns: tuple[str, ...] = ()
    elapsed_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        """True only for an unconditional ALLOW."""
        return self.decision is Decision.ALLOW

    @property
    def requires_review(self) -> bool:
        return self.decision is Decision.REVIEW

    @property
    def denied(self) -> bool:
        return self.decision is Decision.DENY

    @property
    def blocking_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.action is not Action.WARN)

    def explain(self, *, include_detail: bool = False) -> str:
        """Human-readable explanation, one line per finding."""
        if not self.findings:
            return f"{self.decision.value.upper()}: no policy findings."
        lines = [f"{self.decision.value.upper()}:"]
        for f in self.findings:
            line = f"  [{f.action.value}] {f.rule_id}: {f.message}"
            if include_detail and f.detail:
                line += f" ({f.detail})"
            if f.remediation:
                line += f" Suggestion: {f.remediation}"
            lines.append(line)
        return "\n".join(lines)
