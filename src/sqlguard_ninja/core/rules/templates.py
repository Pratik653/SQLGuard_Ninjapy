"""Approved query templates: an optional allowlist of statement structures.

For applications with a fixed set of queries, :class:`ApprovedTemplates` pins exactly which
statements may run. A template's **structural fingerprint** is the SHA-256 of the parsed
statement re-generated in canonical form: comments removed, whitespace and keyword case
normalized, identifiers and literals kept exactly, placeholders kept by name. Any change to
tables, columns, predicates, joins, unions, literals or the number of statements yields a
different fingerprint and the query is denied (``template.unapproved``).

This is an allowlist, not SQL injection detection, and fingerprint equality is not a proof
of semantic equivalence: two different texts that canonicalize identically are treated as
the same template. It complements, and never replaces, policy authorization and driver
binding.

    templates = ApprovedTemplates.from_sql({"order_status": "SELECT ... WHERE o.id = :order_id"},
                                           dialect="postgres")
    guard = Guard(policy).with_rules([ApprovedTemplateRule(templates)])
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

import sqlglot
from sqlglot import exp

from sqlguard_ninja.core.findings import Action, Category, Finding, Severity
from sqlguard_ninja.core.rules.base import RuleContext


def structural_fingerprint(statement: exp.Expr, dialect: str) -> str:
    tree = statement.copy()
    for node in tree.walk():
        node.comments = None
    return hashlib.sha256(tree.sql(dialect=dialect, comments=False).encode()).hexdigest()


@dataclass(frozen=True)
class ApprovedTemplates:
    dialect: str
    fingerprints: Mapping[str, str]  # fingerprint -> template name

    @classmethod
    def from_sql(cls, templates: Mapping[str, str], dialect: str) -> ApprovedTemplates:
        prints: dict[str, str] = {}
        for name, sql in templates.items():
            trees = [t for t in sqlglot.parse(sql, dialect=dialect) if t is not None]
            if len(trees) != 1:
                raise ValueError(f"template {name!r} must contain exactly one statement")
            prints[structural_fingerprint(trees[0], dialect)] = name
        return cls(dialect, prints)

    def match(self, statement: exp.Expr) -> str | None:
        return self.fingerprints.get(structural_fingerprint(statement, self.dialect))


class ApprovedTemplateRule:
    """Deny any statement whose structure is not an approved template."""

    rule_ids = ("template.unapproved",)

    def __init__(self, templates: ApprovedTemplates) -> None:
        self.templates = templates

    def check(self, ctx: RuleContext) -> Iterator[Finding]:
        statements = ctx.analysis.statements
        if len(statements) == 1 and self.templates.match(statements[0]) is not None:
            return
        yield Finding(
            rule_id="template.unapproved",
            category=Category.STATEMENT,
            severity=Severity.HIGH,
            action=Action.DENY,
            message="This query does not match any approved query template.",
            remediation="Use one of the application's approved queries.",
        )
