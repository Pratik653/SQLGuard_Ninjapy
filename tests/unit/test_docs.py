"""Documentation claims are executable: snippets run and relative links resolve."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from sqlguard_ninja import Action, Category, Finding, Guard, Policy, Severity
from sqlguard_ninja.cli.main import main
from tests.conftest import POLICY_PATH, ROOT

DOCS = [
    ROOT / "README.md",
    *sorted((ROOT / "docs").rglob("*.md")),
    *[ROOT / n for n in ("SECURITY.md", "CONTRIBUTING.md", "KNOWN_LIMITATIONS.md", "ROADMAP.md")],
]


def test_readme_cli_example(capsys):
    code = main(
        [
            "validate",
            "--policy",
            "builtin:retail_saas",
            "--role",
            "support_analyst",
            "--tenant",
            "1",
            "--sql",
            "SELECT o.id FROM orders o WHERE o.tenant_id = 1 OR 1 = 1",
        ]
    )
    out = capsys.readouterr().out
    assert code == 1
    assert out.startswith("DENY:")
    assert "[deny] tenant.missing_predicate: Every read of table 'orders'" in out


def test_readme_sdk_example():
    guard = Guard(Policy.from_file(POLICY_PATH))
    r = guard.validate(
        "SELECT department, AVG(salary) FROM employees GROUP BY department",
        role="hr_analyst",
        dialect="postgres",
    )
    assert r.allowed and r.findings == ()
    text = guard.validate("SELECT full_name, salary FROM employees", role="hr_analyst").explain()
    assert text.startswith("DENY:") and "privacy.aggregate_only" in text


def test_policy_reference_sample_loads():
    text = (ROOT / "docs" / "guides" / "POLICY_REFERENCE.md").read_text(encoding="utf-8")
    sample = re.search(r"```yaml\n(.*?)```", text, re.S).group(1)
    policy = Policy.from_dict(yaml.safe_load(sample))
    g = Guard(policy)
    ctx = {"tenant_id": 1}
    assert g.validate(
        "SELECT c.email FROM customers c WHERE c.tenant_id = 1", role="support", context=ctx
    ).allowed
    assert g.validate(
        "SELECT c.profile->'health'->>'allergies' FROM customers c WHERE c.tenant_id = 1",
        role="support",
        context=ctx,
    ).denied


def test_policy_reference_custom_rule():
    class NoOrderByRandom:
        rule_ids = ("custom.order_by_random",)

        def check(self, ctx):
            if "RANDOM()" in ctx.analysis.sql.upper():
                yield Finding(
                    rule_id="custom.order_by_random",
                    category=Category.COST,
                    severity=Severity.LOW,
                    action=Action.REVIEW,
                    message="ORDER BY RANDOM() scans the whole table.",
                )

    guard = Guard(Policy.from_file(POLICY_PATH)).with_rules([NoOrderByRandom()])
    r = guard.validate("SELECT w.name FROM warehouses w ORDER BY RANDOM()", role="hr_analyst")
    assert r.requires_review


LINK = re.compile(r"\]\(([^)#\s]+)(#[^)]*)?\)")
REPO_BLOB = "https://github.com/Pratik653/SQLGuard_Ninjapy/blob/main/"


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(doc: Path):
    text = doc.read_text(encoding="utf-8")
    missing = []
    for target, _ in LINK.findall(text):
        if target.startswith(REPO_BLOB):
            # Absolute links into this repository must still point at real files.
            if not (ROOT / target.removeprefix(REPO_BLOB)).exists():
                missing.append(target)
            continue
        if re.match(r"^[a-z]+:", target):
            continue  # external URL
        if not (doc.parent / target).resolve().exists():
            missing.append(target)
    assert not missing, f"{doc.name}: broken links {missing}"


def test_readme_privacy_and_cost_outputs():
    guard = Guard(Policy.from_file(POLICY_PATH))
    ctx = {"tenant_id": 1}
    card = guard.validate(
        "SELECT p.card_number FROM payments p WHERE p.tenant_id = 1",
        role="support_analyst",
        context=ctx,
    ).explain()
    assert "privacy.label_denied: The column 'payments.card_number' contains classified" in card
    assert "Use column 'payments.card_last4' instead" in card
    cohort = guard.validate("SELECT AVG(salary) FROM employees WHERE id = 7", role="hr_analyst")
    assert cohort.explain().startswith("REVIEW:") and "privacy.small_cohort" in cohort.explain()
    cost = guard.validate(
        "SELECT o.id, i.id FROM orders o CROSS JOIN order_items i", role="platform_admin"
    ).explain()
    assert "cost.static_score: Estimated query cost risk is 100/100" in cost


def test_readme_privacy_yaml_fragment_is_valid():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    fragment = yaml.safe_load(
        re.search(r"## Privacy policies.*?```yaml\n(.*?)```", text, re.S).group(1)
    )
    full = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    for role, spec in fragment["roles"].items():
        for label, access in spec["labels"].items():
            assert full["roles"][role]["labels"][label] == access


def test_readme_has_no_relative_links():
    """The README is the PyPI long description; relative links break there (0.1.0 defect)."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    relative = [t for t, _ in LINK.findall(text) if not re.match(r"^[a-z]+:", t)]
    assert relative == []
