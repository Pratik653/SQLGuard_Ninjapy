"""The :class:`Guard` validates one SQL string against a policy for one role."""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sqlguard_ninja.core.analysis import analyse
from sqlguard_ninja.core.findings import (
    Action,
    Category,
    Finding,
    Severity,
    ValidationResult,
    combine,
)
from sqlguard_ninja.core.rules.access import ColumnAccessRule, TableAccessRule
from sqlguard_ninja.core.rules.base import Rule, RuleContext
from sqlguard_ninja.core.rules.catalog import SystemCatalogRule
from sqlguard_ninja.core.rules.functions import FunctionPolicyRule
from sqlguard_ninja.core.rules.statements import ReadOnlyStatementRule
from sqlguard_ninja.core.rules.structure import StructureLimitsRule
from sqlguard_ninja.core.rules.tenant import TenantIsolationRule
from sqlguard_ninja.policy.model import Access, Policy, Role, TableGrant
from sqlguard_ninja.privacy.rules import PrivacyPolicyRule
from sqlguard_ninja.query_cost.static import StaticCostRule


def default_rules() -> list[Rule]:
    """The built-in rule pipeline, in evaluation order."""
    return [
        ReadOnlyStatementRule(),
        SystemCatalogRule(),
        FunctionPolicyRule(),
        TableAccessRule(),
        ColumnAccessRule(),
        PrivacyPolicyRule(),
        TenantIsolationRule(),
        StructureLimitsRule(),
        StaticCostRule(),
    ]


def sql_sha256(sql: str) -> str:
    # surrogatepass: hashing must not fail on input that is itself rejected as invalid.
    return hashlib.sha256(sql.encode("utf-8", errors="surrogatepass")).hexdigest()


def _preflight(sql: str, policy: Policy, limits_len: int) -> Finding | None:
    if not sql or not sql.strip():
        return Finding(
            rule_id="parse.empty",
            category=Category.PARSE,
            severity=Severity.LOW,
            action=Action.DENY,
            message="The query is empty.",
        )
    if len(sql) > limits_len:
        return Finding(
            rule_id="parse.too_long",
            category=Category.PARSE,
            severity=Severity.MEDIUM,
            action=Action.DENY,
            message=f"The query is longer than {limits_len} characters.",
        )
    try:
        sql.encode("utf-8")
    except UnicodeEncodeError:
        return Finding(
            rule_id="parse.invalid_characters",
            category=Category.PARSE,
            severity=Severity.HIGH,
            action=Action.DENY,
            message="The query is not valid UTF-8 text.",
        )
    if "\x00" in sql:
        return Finding(
            rule_id="parse.invalid_characters",
            category=Category.PARSE,
            severity=Severity.HIGH,
            action=Action.DENY,
            message="The query contains NUL characters.",
        )
    return None


class Guard:
    """Validate SQL against a :class:`~sqlguard_ninja.policy.Policy`.

    The guard is stateless and thread-safe: create one per policy at start-up and reuse it.
    It never executes SQL and never rewrites it — callers must execute exactly the string
    they validated.

    Example::

        guard = Guard(Policy.from_file("policy.yaml"))
        result = guard.validate("SELECT id FROM orders WHERE tenant_id = :tenant_id",
                                role="support_analyst", context={"tenant_id": 42})
        if not result.allowed:
            print(result.explain())
    """

    def __init__(self, policy: Policy, rules: Sequence[Rule] | None = None) -> None:
        self.policy = policy
        self.rules: list[Rule] = list(rules) if rules is not None else default_rules()

    def with_rules(self, extra: Iterable[Rule]) -> Guard:
        """Return a new guard with additional custom rules appended."""
        return Guard(self.policy, [*self.rules, *extra])

    def _implicit_role(self) -> Role:
        return Role(
            description="implicit: policy defines no roles",
            tables={name: TableGrant() for name in self.policy.catalog.tables},
            unlisted_label_access=Access.DENY,
        )

    def validate(
        self,
        sql: str,
        *,
        role: str | None = None,
        dialect: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> ValidationResult:
        """Validate ``sql`` and return a :class:`ValidationResult`. Never raises on bad SQL."""
        started = time.perf_counter()
        dialect = (dialect or self.policy.dialect).lower()
        context = dict(context or {})
        findings: list[Finding] = []

        role_name, role_obj = self.policy.role(role)
        if not self.policy.roles:
            role_obj = self._implicit_role()
        elif role_obj is None:
            findings.append(
                Finding(
                    rule_id="role.unknown",
                    category=Category.TABLE_ACCESS,
                    severity=Severity.HIGH,
                    action=Action.DENY,
                    message="No valid role was supplied for this request.",
                    detail=f"role {role!r} is not defined in policy {self.policy.name!r}",
                )
            )
        limits = self.policy.effective_limits(role_obj)

        pre = _preflight(sql, self.policy, limits.max_sql_length)
        analysis = None
        if pre is not None:
            findings.append(pre)
        else:
            analysis = analyse(sql, dialect, self.policy.catalog, max_nodes=limits.max_ast_nodes)
            findings.extend(self._structural_findings(analysis, limits.max_ast_nodes))

        if analysis is not None and not findings_block_analysis(findings):
            ctx = RuleContext(
                analysis=analysis,
                policy=self.policy,
                role_name=role_name,
                role=role_obj,
                limits=limits,
                context=context,
            )
            for rule in self.rules:
                findings.extend(rule.check(ctx))

        elapsed = (time.perf_counter() - started) * 1000
        return ValidationResult(
            decision=combine(findings),
            findings=tuple(findings),
            sql_sha256=sql_sha256(sql or ""),
            dialect=dialect,
            role=role_name,
            policy_name=self.policy.name,
            policy_version=self.policy.version,
            policy_revision=self.policy.revision,
            policy_fingerprint=self.policy.fingerprint,
            decision_id=uuid.uuid4().hex,
            tables=tuple(analysis.base_table_names) if analysis else (),
            columns=tuple(sorted({f"{c.table}.{c.column}" for c in analysis.columns}))
            if analysis
            else (),
            elapsed_ms=elapsed,
        )

    @staticmethod
    def _structural_findings(analysis: Any, max_nodes: int) -> list[Finding]:
        out: list[Finding] = []
        if analysis.parse_error is not None:
            out.append(
                Finding(
                    rule_id="parse.error",
                    category=Category.PARSE,
                    severity=Severity.MEDIUM,
                    action=Action.DENY,
                    message="The query could not be parsed in the configured SQL dialect.",
                    detail=analysis.parse_error,
                )
            )
        elif len(analysis.statements) == 0:
            out.append(
                Finding(
                    rule_id="parse.empty",
                    category=Category.PARSE,
                    severity=Severity.LOW,
                    action=Action.DENY,
                    message="The query contains no statement.",
                )
            )
        elif len(analysis.statements) > 1:
            out.append(
                Finding(
                    rule_id="statement.multiple",
                    category=Category.STATEMENT,
                    severity=Severity.CRITICAL,
                    action=Action.DENY,
                    message="Only one statement may be executed at a time.",
                    detail=f"{len(analysis.statements)} statements",
                )
            )
        elif analysis.node_count > max_nodes:
            out.append(
                Finding(
                    rule_id="parse.too_complex",
                    category=Category.PARSE,
                    severity=Severity.MEDIUM,
                    action=Action.DENY,
                    message="The query is too complex to analyse safely.",
                    detail=f"{analysis.node_count} AST nodes > {max_nodes}",
                )
            )
        elif analysis.qualify_error is not None:
            out.append(
                Finding(
                    rule_id="parse.analysis_incomplete",
                    category=Category.PARSE,
                    severity=Severity.MEDIUM,
                    action=Action.DENY,
                    message="The query could not be fully analysed, so it is not permitted.",
                    detail=analysis.qualify_error,
                )
            )
        return out


def findings_block_analysis(findings: list[Finding]) -> bool:
    """Parse-level failures and multi-statements stop the rule pipeline.

    An incomplete *qualification* does not: statement, catalog and function rules still
    run on the parsed tree so the caller gets the most specific reason available.
    """
    return any(
        (f.rule_id.startswith("parse.") and f.rule_id != "parse.analysis_incomplete")
        or f.rule_id == "statement.multiple"
        for f in findings
    )
