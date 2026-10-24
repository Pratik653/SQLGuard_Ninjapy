"""Audit events and sinks.

Events never contain literal values from the SQL by default: the statement is stored as its
SHA-256 plus a *redacted* form in which every literal is replaced by ``?`` and comments are
dropped. That keeps customer data and secrets that an LLM may have inlined out of logs.
Events also omit request context values and internal finding detail. ``sql_sha256`` of a
short query with a guessable secret can be brute-forced; treat audit logs as sensitive and
use ``query_fingerprint`` (hash of the redacted form) where an identifier is enough.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import sqlglot
from pydantic import BaseModel, ConfigDict, Field
from sqlglot import exp
from sqlglot.dialects.dialect import Dialect
from sqlglot.errors import SqlglotError
from sqlglot.tokenizer_core import TokenType

# Every node type that carries a value written in the SQL text. INTERVAL is replaced whole
# because sqlglot splits ``INTERVAL '5 secret'`` into a literal and a free-text unit.
_VALUE_NODES: tuple[type[exp.Expr], ...] = (
    exp.Literal,
    exp.HexString,
    exp.BitString,
    exp.ByteString,
    exp.RawString,
    exp.UnicodeString,
    exp.National,
    exp.Interval,
)
_VALUE_TOKENS = frozenset(
    t for t in TokenType if t.name == "NUMBER" or t.name.endswith("_STRING") or t.name == "STRING"
)


def redact_sql(sql: str, dialect: str) -> str | None:
    """Replace every literal with ``?`` and drop comments. None if it cannot be done safely.

    After the AST rewrite the output is tokenized again; if any string or number token
    survives (a literal form this function does not know), the result is withheld.
    """
    try:
        statements = [s for s in sqlglot.parse(sql, dialect=dialect) if s is not None]
    except SqlglotError:
        return None
    if not statements:
        return None

    def _strip(node: exp.Expr) -> exp.Expr:
        if isinstance(node, _VALUE_NODES):
            return exp.Var(this="?")  # dialect-neutral marker, never a bind parameter
        return node

    try:
        out = "; ".join(
            s.transform(_strip).sql(dialect=dialect, comments=False) for s in statements
        )
        tokens = Dialect.get_or_raise(dialect).tokenize(out)
    except SqlglotError:
        return None
    if any(t.token_type in _VALUE_TOKENS for t in tokens):
        return None
    return out


AUDIT_SCHEMA = "sqlninja.audit/1"


class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = AUDIT_SCHEMA
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="milliseconds")
    )
    event_type: str = "sql.checkpoint"
    trace_id: str
    principal: str | None
    role: str | None
    tenant: str | None
    mode: str
    decision: str
    authorized: bool
    enforced: bool
    would_block: bool
    sql_sha256: str
    sql_redacted: str | None
    query_fingerprint: str | None = None
    """SHA-256 of the redacted SQL: equal for queries that differ only in literals."""
    dialect: str
    policy: str
    policy_revision: str = "unversioned"
    policy_fingerprint: str = ""
    decision_id: str = ""
    correlation_id: str | None = None
    tenant_filter_rewrite: bool = False
    """True when the executed SQL is the AST-rewritten form with tenant filters added."""
    findings: list[dict[str, Any]]
    approval: dict[str, Any] | None = None
    attempt: int = 1
    rate_limited: bool = False
    """True when the session exceeded ``max_denied_attempts`` and the query was refused."""
    elapsed_ms: float = 0.0


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class InMemoryAuditSink:
    """Keeps events in a list. For tests and demos."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        with self._lock:
            self.events.append(event)


class JsonlAuditSink:
    """Append one JSON object per line. Thread-safe within a process."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        line = event.model_dump_json() + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)


class LoggingAuditSink:
    """Emit events through :mod:`logging` as JSON strings."""

    def __init__(self, logger: logging.Logger | None = None, level: int = logging.INFO) -> None:
        self.logger = logger or logging.getLogger("sqlguard_ninja.audit")
        self.level = level

    def emit(self, event: AuditEvent) -> None:
        self.logger.log(self.level, json.dumps(event.model_dump(mode="json")))
