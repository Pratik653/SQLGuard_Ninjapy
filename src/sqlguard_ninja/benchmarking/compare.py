"""Compare a candidate benchmark result with an approved baseline.

A comparison never updates the baseline. Regressions are classified so CI can gate on the
ones that matter most:

* ``security_regressions`` — an unsafe case the baseline flagged is now ALLOWED.
* ``sensitive_regressions`` / ``tenant_regressions`` — subsets in privacy and tenant categories.
* ``usability_regressions`` — a safe case the baseline allowed is now blocked.
* ``decision_changes`` — any other change of decision (e.g. deny → review).
* ``new_errors`` — validator crashes or new parse failures not present in the baseline.
* ``latency`` — p95 change in percent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PRIVACY_CATEGORIES = frozenset({"sensitive_field", "json_fields"})
TENANT_CATEGORIES = frozenset({"tenant_isolation"})


@dataclass(frozen=True)
class Thresholds:
    max_security_regressions: int = 0
    max_usability_regressions: int = 0
    max_new_errors: int = 0
    min_recall: float | None = None
    max_false_positive_rate: float | None = None
    max_p95_latency_increase_pct: float | None = None
    """None disables the latency gate (CI hardware varies)."""
    allow_benchmark_change: bool = False
    allow_label_changes: bool = False
    approved_label_changes: frozenset[str] = frozenset()
    """Case ids (base ids or ``id@dialect``) whose relabel was approved in LABEL_CHANGES.yaml."""
    """Expected outcomes of existing cases changed. Off by default: relabelling a case is
    exactly how a regression could be hidden, so it needs explicit human approval."""


@dataclass
class Comparison:
    baseline: dict[str, Any]
    candidate: dict[str, Any]
    security_regressions: list[str] = field(default_factory=list)
    sensitive_regressions: list[str] = field(default_factory=list)
    tenant_regressions: list[str] = field(default_factory=list)
    usability_regressions: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    decision_changes: list[str] = field(default_factory=list)
    new_errors: list[str] = field(default_factory=list)
    new_parse_failures: list[str] = field(default_factory=list)
    missing_cases: list[str] = field(default_factory=list)
    label_changes: list[str] = field(default_factory=list)
    approved_label_changes: list[str] = field(default_factory=list)
    added_cases: list[str] = field(default_factory=list)
    p95_change_pct: float | None = None
    failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict[str, Any]:
        keys = [
            "security_regressions",
            "sensitive_regressions",
            "tenant_regressions",
            "usability_regressions",
            "improvements",
            "decision_changes",
            "new_errors",
            "new_parse_failures",
            "missing_cases",
            "label_changes",
            "approved_label_changes",
            "added_cases",
            "p95_change_pct",
            "failures",
        ]
        return {"passed": self.passed, **{k: getattr(self, k) for k in keys}}


def _is_parse_failure(record: dict[str, Any]) -> bool:
    return any(str(r).startswith("parse.") for r in record.get("reasons", ()))


def compare(
    baseline: dict[str, Any], candidate: dict[str, Any], thresholds: Thresholds | None = None
) -> Comparison:
    t = thresholds or Thresholds()
    c = Comparison(baseline, candidate)
    base = {r["id"]: r for r in baseline["cases"]}
    cand = {r["id"]: r for r in candidate["cases"]}
    c.missing_cases = sorted(set(base) - set(cand))
    c.added_cases = sorted(set(cand) - set(base))

    for cid in sorted(set(base) & set(cand)):
        b, n = base[cid], cand[cid]
        if b["expected"] != n["expected"]:
            if cid in t.approved_label_changes or cid.split("@")[0] in t.approved_label_changes:
                c.approved_label_changes.append(cid)
            else:
                c.label_changes.append(cid)
        if n.get("error") and not b.get("error"):
            c.new_errors.append(cid)
        if _is_parse_failure(n) and not _is_parse_failure(b) and n["expected"] == "allow":
            c.new_parse_failures.append(cid)
        if b["actual"] == n["actual"]:
            continue
        unsafe = n["expected"] != "allow"
        if unsafe and b["actual"] != "allow" and n["actual"] == "allow":
            c.security_regressions.append(cid)
            if n["category"] in PRIVACY_CATEGORIES:
                c.sensitive_regressions.append(cid)
            if n["category"] in TENANT_CATEGORIES:
                c.tenant_regressions.append(cid)
        elif not unsafe and b["actual"] == "allow" and n["actual"] != "allow":
            c.usability_regressions.append(cid)
        elif n["actual"] == n["expected"]:
            c.improvements.append(cid)
        else:
            c.decision_changes.append(cid)

    # Cases that are new in the candidate still count when they are unsafe and allowed:
    # a PR must not be able to add a failing case and the code that fails it together.
    for cid in c.added_cases:
        if cand[cid]["kind"] == "fn":
            c.security_regressions.append(cid)

    bp95 = baseline["metrics"]["overall"]["latency_ms"]["p95"]
    np95 = candidate["metrics"]["overall"]["latency_ms"]["p95"]
    if bp95 and np95:
        c.p95_change_pct = round((np95 - bp95) / bp95 * 100, 1)

    bfp = baseline["benchmark"]["fingerprint"]
    nfp = candidate["benchmark"]["fingerprint"]
    if bfp != nfp and not t.allow_benchmark_change:
        c.failures.append(
            f"benchmark fingerprint changed ({bfp} -> {nfp}); regenerate and approve a new "
            "baseline, or pass allow_benchmark_change"
        )
    if c.label_changes and not t.allow_label_changes:
        c.failures.append(
            f"{len(c.label_changes)} case label(s) changed; relabelling requires explicit approval"
        )
    if c.missing_cases and not t.allow_benchmark_change:
        c.failures.append(f"{len(c.missing_cases)} baseline cases are missing from the candidate")
    if len(c.security_regressions) > t.max_security_regressions:
        c.failures.append(f"{len(c.security_regressions)} security regression(s)")
    if len(c.usability_regressions) > t.max_usability_regressions:
        c.failures.append(f"{len(c.usability_regressions)} newly blocked legitimate case(s)")
    if len(c.new_errors) + len(c.new_parse_failures) > t.max_new_errors:
        c.failures.append(
            f"{len(c.new_errors)} new validator error(s), "
            f"{len(c.new_parse_failures)} new parse failure(s)"
        )
    overall = candidate["metrics"]["overall"]
    if t.min_recall is not None and (overall["recall"] or 0) < t.min_recall:
        c.failures.append(f"recall {overall['recall']} below {t.min_recall}")
    fpr = overall["false_positive_rate"]
    if (
        t.max_false_positive_rate is not None
        and fpr is not None
        and fpr > t.max_false_positive_rate
    ):
        c.failures.append(f"false-positive rate {fpr} above {t.max_false_positive_rate}")
    if (
        t.max_p95_latency_increase_pct is not None
        and c.p95_change_pct is not None
        and c.p95_change_pct > t.max_p95_latency_increase_pct
    ):
        c.failures.append(
            f"p95 latency +{c.p95_change_pct}% exceeds {t.max_p95_latency_increase_pct}%"
        )
    return c
