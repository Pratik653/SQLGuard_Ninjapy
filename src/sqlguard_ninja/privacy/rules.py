"""Privacy policy pack: label-based column restrictions, aggregate-only access, data
minimisation and small-cohort re-identification warnings.

This is a technical control library. It helps implement data-minimisation and
need-to-know principles; it does not certify GDPR compliance.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from sqlguard_ninja.core.analysis import (
    AggregateKind,
    Clause,
    ColumnRef,
    _aggregate_of,
    _clause_of,
)
from sqlguard_ninja.core.findings import Action, Category, Finding, Severity
from sqlguard_ninja.core.lineage import aggregated_downstream, derived_references
from sqlguard_ninja.core.rules.base import RuleContext
from sqlguard_ninja.policy.model import Access, ColumnDef, Disclosure, Policy, Role, Sensitivity

_SEVERITY = {
    Sensitivity.LOW: Severity.LOW,
    Sensitivity.MEDIUM: Severity.MEDIUM,
    Sensitivity.HIGH: Severity.HIGH,
    Sensitivity.CRITICAL: Severity.CRITICAL,
}


@dataclass(frozen=True)
class ColumnAccessDecision:
    """How a role may use one column, and why."""

    restrictions: tuple[tuple[Access, str], ...]
    """(access, source) pairs; source is ``column:<name>`` or ``label:<label>``."""
    labels: frozenset[str]

    @property
    def strongest(self) -> Access:
        order = [Access.DENY, Access.AGGREGATE_ONLY, Access.REVIEW, Access.ALLOW]
        present = {a for a, _ in self.restrictions}
        return next((a for a in order if a in present), Access.ALLOW)


def resolve_column_access(
    policy: Policy,
    role: Role | None,
    table: str,
    column: str,
    json_path: tuple[str, ...] | None = None,
) -> ColumnAccessDecision:
    """Resolve effective access: explicit column rule → label rules → role default."""
    tdef = policy.catalog.tables.get(table)
    cdef: ColumnDef | None = tdef.columns.get(column) if tdef else None
    labels = frozenset(cdef.effective_labels(json_path)) if cdef else frozenset()
    if role is not None:
        grant = role.tables.get(table)
        if grant is not None and column in grant.column_access:
            return ColumnAccessDecision(
                ((grant.column_access[column], f"column:{table}.{column}"),), labels
            )
    restrictions: list[tuple[Access, str]] = []
    for label in sorted(labels):
        access = Access.DENY if role is None else role.labels.get(label, role.unlisted_label_access)
        if access is not Access.ALLOW:
            restrictions.append((access, f"label:{label}"))
    return ColumnAccessDecision(tuple(restrictions), labels)


class PrivacyPolicyRule:
    rule_ids = (
        "privacy.label_denied",
        "privacy.aggregate_only",
        "privacy.label_review",
        "privacy.small_cohort",
        "privacy.minimization",
    )

    def check(self, ctx: RuleContext) -> Iterator[Finding]:
        policy = ctx.policy
        role = ctx.role
        emitted: set[tuple[str, str, str]] = set()
        aggregate_only_used = False
        star_labelled: dict[str, set[str]] = {}

        for ref in ctx.analysis.columns:
            tdef = policy.catalog.tables.get(ref.table)
            if tdef is None or ref.column not in tdef.columns:
                continue
            if role is not None and ref.table not in role.tables:
                continue
            decision = resolve_column_access(policy, role, ref.table, ref.column, ref.json_path)
            if ref.whole_row and decision.labels:
                star_labelled.setdefault(ref.table, set()).update(decision.labels)
            for access, source in decision.restrictions:
                finding = self._finding_for(ctx, ref, access, source, decision.labels)
                if finding is None:
                    if access is Access.AGGREGATE_ONLY:
                        aggregate_only_used = True
                    continue
                key = (finding.rule_id, f"{ref.table}.{ref.column}", "")
                if key in emitted:
                    continue
                emitted.add(key)
                yield finding

        if aggregate_only_used:
            yield from self._small_cohort(ctx)

        for table, labels in sorted(star_labelled.items()):
            yield Finding(
                rule_id="privacy.minimization",
                category=Category.PRIVACY,
                severity=Severity.LOW,
                action=policy.defaults.minimization_action,
                message=f"Selecting every column of {ctx.name('table', table)} returns "
                "classified data; select only the columns the task needs.",
                labels=tuple(sorted(labels)),
                table=table,
            )
        yield from self._alternatives(ctx)

    # -------------------------------------------------------------- helpers
    def _finding_for(
        self,
        ctx: RuleContext,
        ref: ColumnRef,
        access: Access,
        source: str,
        labels: frozenset[str],
    ) -> Finding | None:
        policy = ctx.policy
        col_txt = ctx.name("column", f"{ref.table}.{ref.column}")
        label_names = tuple(sorted(labels))
        label_defs = [policy.labels[x] for x in label_names if x in policy.labels]
        severity = max(
            (_SEVERITY[d.sensitivity] for d in label_defs),
            default=Severity.MEDIUM,
            key=list(Severity).index,
        )
        special = any(d.special_category for d in label_defs)
        masking = next((d.masking for d in label_defs if d.masking), None)
        alt = self._allowed_alternative(ctx, ref)
        remediation_parts = []
        if alt:
            remediation_parts.append(f"Use {ctx.name('column', alt)} instead.")
        if masking:
            remediation_parts.append(f"Recommended treatment: {masking}.")
        remediation = " ".join(remediation_parts) or None
        path_txt = f" (JSON path {'.'.join(ref.json_path)})" if ref.json_path else ""
        cls_txt = (
            "special-category personal data"
            if special
            else ("classified data (" + ", ".join(label_names) + ")" if label_names else "data")
        )
        if policy.disclosure == Disclosure.GENERIC:
            cls_txt = "classified data"
        meta = {
            "source": source,
            "clause": ref.clause.value,
            "aggregate": ref.aggregate.value,
            # Structured lineage for explanations (kept in metadata, not in agent messages).
            "lineage": {
                "base_column": f"{ref.table}.{ref.column}",
                "json_path": list(ref.json_path) if ref.json_path else None,
                "scope_id": ref.scope_id,
                "labels": sorted(labels),
            },
        }

        if access is Access.DENY:
            return Finding(
                rule_id="privacy.label_denied",
                category=Category.PRIVACY,
                severity=Severity.CRITICAL if special else severity,
                action=Action.DENY,
                message=f"The {col_txt}{path_txt} contains {cls_txt} that this role may not "
                "access.",
                detail=f"restricted by {source}",
                table=ref.table,
                column=ref.column,
                labels=label_names,
                remediation=remediation,
                metadata=meta,
            )
        if access is Access.AGGREGATE_ONLY:
            if ref.aggregate is AggregateKind.STATISTICAL:
                return None
            if self._aggregated_via_lineage(ctx, ref):
                return None
            where = (
                "in a filter, grouping or ordering"
                if ref.clause in (Clause.WHERE, Clause.JOIN, Clause.GROUP, Clause.ORDER)
                else "as individual values"
            )
            return Finding(
                rule_id="privacy.aggregate_only",
                category=Category.PRIVACY,
                severity=severity,
                action=Action.DENY,
                message=f"The {col_txt} may only be used inside statistical aggregates "
                f"(COUNT, SUM, AVG, ...), not {where}.",
                detail=f"restricted by {source}; aggregate={ref.aggregate.value}",
                table=ref.table,
                column=ref.column,
                labels=label_names,
                remediation=remediation
                or "Aggregate the column (e.g. AVG) and group by non-identifying attributes.",
                metadata=meta,
            )
        if access is Access.REVIEW:
            return Finding(
                rule_id="privacy.label_review",
                category=Category.PRIVACY,
                severity=severity,
                action=Action.REVIEW,
                message=f"Access to the {col_txt} ({cls_txt}) requires human approval.",
                detail=f"restricted by {source}",
                table=ref.table,
                column=ref.column,
                labels=label_names,
                remediation=remediation,
                metadata=meta,
            )
        return None

    @staticmethod
    def _aggregated_via_lineage(ctx: RuleContext, ref: ColumnRef) -> bool:
        """A raw projection in a CTE or derived table that is only aggregated downstream."""
        if ref.aggregate is not AggregateKind.NONE or ref.clause is not Clause.SELECT:
            return False
        if ref.node is None or ref.whole_row:
            return False
        facts = next((s for s in ctx.analysis.scopes if s.scope_id == ref.scope_id), None)
        return facts is not None and aggregated_downstream(ctx.analysis, facts, ref.node)

    def _allowed_alternative(self, ctx: RuleContext, ref: ColumnRef) -> str | None:
        tdef = ctx.policy.catalog.tables[ref.table]
        cdef = tdef.columns[ref.column]
        for alt in cdef.alternatives:
            decision = resolve_column_access(ctx.policy, ctx.role, ref.table, alt)
            if decision.strongest is Access.ALLOW and self._granted(ctx, ref.table, alt):
                return f"{ref.table}.{alt}"
        return None

    @staticmethod
    def _granted(ctx: RuleContext, table: str, column: str) -> bool:
        if ctx.role is None:
            return True
        grant = ctx.role.tables.get(table)
        if grant is None or column in grant.deny_columns:
            return False
        return grant.columns == "*" or column in grant.columns

    def _small_cohort(self, ctx: RuleContext) -> Iterator[Finding]:
        """Aggregates over a group filtered or grouped by an identifier reveal single values.

        Identifiers are followed through CTEs and derived tables, so lineage-based relaxation of
        aggregate-only checks cannot bypass this rule (regression case LIN-012).
        """
        catalog = ctx.policy.catalog
        clauses = (Clause.WHERE, Clause.GROUP, Clause.HAVING)  # join keys are expected ids
        candidates: list[tuple[str, str, Clause]] = [
            (ref.table, ref.column, ref.clause)
            for ref in ctx.analysis.columns
            if ref.clause in clauses and ref.aggregate is AggregateKind.NONE
        ]
        for facts, node, (table, col) in derived_references(ctx.analysis, clauses):
            if _aggregate_of(node, facts.expression) is AggregateKind.NONE:
                candidates.append((table, col, _clause_of(node, facts.expression)))
        for table, column, clause in candidates:
            tdef = catalog.tables.get(table)
            if tdef is None or column not in tdef.columns:
                continue
            if tdef.columns[column].identifying:
                yield Finding(
                    rule_id="privacy.small_cohort",
                    category=Category.PRIVACY,
                    severity=Severity.MEDIUM,
                    action=ctx.policy.defaults.small_cohort_action,
                    message="An aggregate of restricted data is filtered or grouped by an "
                    "identifying column, which can reveal individual values.",
                    detail=f"identifying column {table}.{column} in {clause.value}",
                    table=table,
                    column=column,
                    remediation="Group by non-identifying attributes and ensure groups are "
                    "large enough (k-anonymity is not checked statically).",
                )
                return

    def _alternatives(self, ctx: RuleContext) -> Iterator[Finding]:
        """Suggest less sensitive alternatives for permitted-but-labelled columns."""
        seen: set[tuple[str, str]] = set()
        for ref in ctx.analysis.columns:
            if ref.whole_row or ref.clause is not Clause.SELECT:
                continue
            key = (ref.table, ref.column)
            if key in seen:
                continue
            seen.add(key)
            tdef = ctx.policy.catalog.tables.get(ref.table)
            if tdef is None or ref.column not in tdef.columns:
                continue
            if not tdef.columns[ref.column].alternatives:
                continue
            decision = resolve_column_access(ctx.policy, ctx.role, ref.table, ref.column)
            if decision.strongest is not Access.ALLOW or not decision.labels:
                continue
            alt = self._allowed_alternative(ctx, ref)
            if alt:
                yield Finding(
                    rule_id="privacy.minimization",
                    category=Category.PRIVACY,
                    severity=Severity.INFO,
                    action=Action.WARN,
                    message=f"The {ctx.name('column', f'{ref.table}.{ref.column}')} is "
                    f"classified; {ctx.name('column', alt)} may be sufficient.",
                    table=ref.table,
                    column=ref.column,
                    labels=tuple(sorted(decision.labels)),
                    remediation=f"Prefer {alt}.",
                )
