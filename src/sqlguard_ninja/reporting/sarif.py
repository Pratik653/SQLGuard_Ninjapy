"""SARIF 2.1.0 output for scanning SQL files (GitHub code scanning and other SARIF viewers).

Each finding becomes one SARIF result located at the statement that produced it. Messages
are the caller-safe ``Finding.message`` text; internal ``detail`` is never included, and no
code snippet is copied into the log, so SQL literals stay in the scanned file only.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlglot.dialects.dialect import Dialect
from sqlglot.errors import SqlglotError
from sqlglot.tokenizer_core import TokenType

from sqlguard_ninja import __version__
from sqlguard_ninja.core.findings import Action, Category, ValidationResult
from sqlguard_ninja.policy.model import Policy

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/Pratik653/SQLGuard_Ninjapy"
RULES_URI = INFORMATION_URI + "/blob/main/docs/guides/POLICY_REFERENCE.md"
_LEVEL = {Action.DENY: "error", Action.REVIEW: "warning", Action.WARN: "note"}
_CATEGORY_TEXT = {
    Category.PARSE: "The SQL could not be parsed or analysed safely.",
    Category.STATEMENT: "The statement type is not permitted.",
    Category.CATALOG: "The query reads a system catalog.",
    Category.FUNCTION: "The query calls a restricted function.",
    Category.TABLE_ACCESS: "The query reads a table the role may not use.",
    Category.COLUMN_ACCESS: "The query reads a column the role may not use.",
    Category.PRIVACY: "The query exposes classified data in a way the policy does not allow.",
    Category.TENANT: "The query is not restricted to the caller's tenant.",
    Category.COST: "The query is estimated to be too expensive.",
    Category.STRUCTURE: "The query exceeds a structural limit.",
}


@dataclass(frozen=True)
class Statement:
    """One statement cut from a file, with 1-based line/column positions."""

    sql: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int


@dataclass(frozen=True)
class ScanResult:
    uri: str
    statement: Statement
    result: ValidationResult
    query_fingerprint: str | None


def _position(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    column = offset - (text.rfind("\n", 0, offset) + 1) + 1
    return line, column


def split_statements(text: str, dialect: str) -> list[Statement]:
    """Split on top-level semicolons using the dialect tokenizer.

    If the text cannot be tokenized (an unterminated string, say), it is split at semicolons
    that end a line instead. Every chunk is still validated, so the malformed part is denied
    rather than skipped.
    """
    try:
        tokens = Dialect.get_or_raise(dialect).tokenize(text)
    except SqlglotError:
        tokens = None
    chunks: list[tuple[int, int]] = []
    if tokens is None:
        pos = 0
        for m in [*re.finditer(r";[ \t]*(?=\r?\n|$)", text), None]:
            end = m.start() if m else len(text)
            piece = text[pos:end]
            if piece.strip():
                lead = len(piece) - len(piece.lstrip())
                chunks.append((pos + lead, pos + len(piece.rstrip())))
            if m:
                pos = m.end()
    else:
        current: list[Any] = []
        for tok in [*tokens, None]:
            if tok is None or tok.token_type is TokenType.SEMICOLON:
                if current:
                    chunks.append((current[0].start, current[-1].end + 1))
                current = []
            else:
                current.append(tok)
    out = []
    for start, end in chunks:
        sl, sc = _position(text, start)
        el, ec = _position(text, end)
        out.append(Statement(text[start:end], sl, sc, el, ec))
    return out


def _fingerprint(uri: str, rule_id: str, query_fingerprint: str | None, sql: str) -> str:
    basis = query_fingerprint or hashlib.sha256(sql.encode("utf-8", "surrogatepass")).hexdigest()
    return hashlib.sha256(f"{uri}\0{rule_id}\0{basis}".encode()).hexdigest()[:32]


def to_sarif(
    results: Sequence[ScanResult], policy: Policy, scanned: Iterable[str] = ()
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log. Clean statements produce no results."""
    rules: dict[str, dict[str, Any]] = {}
    sarif_results = []
    for item in results:
        for f in item.result.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_id.replace(".", "_"),
                    "shortDescription": {"text": _CATEGORY_TEXT[f.category]},
                    "helpUri": RULES_URI,
                    "defaultConfiguration": {"level": _LEVEL[f.action]},
                    "properties": {"category": f.category.value, "tags": ["security", "sql"]},
                }
            text = f.message + (f" Suggestion: {f.remediation}" if f.remediation else "")
            st = item.statement
            sarif_results.append(
                {
                    "ruleId": f.rule_id,
                    "ruleIndex": list(rules).index(f.rule_id),
                    "level": _LEVEL[f.action],
                    "message": {"text": text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": item.uri, "uriBaseId": "%SRCROOT%"},
                                "region": {
                                    "startLine": st.start_line,
                                    "startColumn": st.start_column,
                                    "endLine": st.end_line,
                                    "endColumn": st.end_column,
                                },
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "sqlguardNinja/v1": _fingerprint(
                            item.uri, f.rule_id, item.query_fingerprint, st.sql
                        )
                    },
                    "properties": {
                        "decision": item.result.decision.value,
                        "decisionId": item.result.decision_id,
                        "severity": f.severity.value,
                    },
                }
            )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SQLGuard Ninja",
                        "semanticVersion": __version__,
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "artifacts": [{"location": {"uri": u, "uriBaseId": "%SRCROOT%"}} for u in scanned],
                "invocations": [{"executionSuccessful": True}],
                "results": sarif_results,
                "properties": {
                    "policy": policy.name,
                    "policyRevision": policy.revision,
                    "policyFingerprint": policy.fingerprint,
                },
            }
        ],
    }


def relative_uri(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
