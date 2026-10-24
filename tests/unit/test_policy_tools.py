"""Policy-as-code tooling: diff, simulate, explain, templates (SDK and CLI)."""

from __future__ import annotations

import json

import pytest
import yaml

from sqlguard_ninja import Policy
from sqlguard_ninja.cli.main import main
from sqlguard_ninja.policy.tools import (
    TEMPLATES,
    Effect,
    SimCase,
    diff_policies,
    explain_column,
    simulate,
    template_text,
)
from tests.conftest import POLICY_PATH


def _variant(mutate) -> Policy:
    data = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    mutate(data)
    return Policy.from_dict(data)


@pytest.fixture(scope="module")
def base() -> Policy:
    return Policy.from_file(POLICY_PATH)


def test_identical_policies_have_no_changes(base):
    d = diff_policies(base, _variant(lambda d: None))
    assert d.changes == [] and d.old_fingerprint == d.new_fingerprint


@pytest.mark.parametrize(
    ("mutate", "path", "effect"),
    [
        (
            lambda d: d["roles"]["support_analyst"]["labels"].update(payment_card="allow"),
            "roles.support_analyst.labels.payment_card",
            Effect.RELAXES,
        ),
        (
            lambda d: d["roles"]["hr_analyst"]["labels"].update(hr="deny"),
            "roles.hr_analyst.labels.hr",
            Effect.RESTRICTS,
        ),
        (
            lambda d: d["roles"]["warehouse_analyst"]["tables"].update(employees="*"),
            "roles.warehouse_analyst.tables.employees",
            Effect.RELAXES,
        ),
        (
            lambda d: d["roles"]["support_analyst"]["tables"].pop("payments"),
            "roles.support_analyst.tables.payments",
            Effect.RESTRICTS,
        ),
        (
            lambda d: d["roles"]["support_analyst"].update(tenant_scoped=False),
            "roles.support_analyst.tenant_scoped",
            Effect.RELAXES,
        ),
        (
            lambda d: d["catalog"]["tables"]["orders"].pop("tenant_column"),
            "catalog.orders.tenant_column",
            Effect.RELAXES,
        ),
        (
            lambda d: d["catalog"]["tables"]["employees"]["columns"]["salary"].update(
                labels=["hr"]
            ),
            "catalog.employees.salary.labels",
            Effect.RELAXES,
        ),
        (
            lambda d: d["functions"].update(mode="allowlist", allow=["count"]),
            "functions.mode",
            Effect.RESTRICTS,
        ),
        (lambda d: d["limits"].update(max_limit=None), "limits.max_limit", Effect.RELAXES),
        (lambda d: d["cost"].update(deny_score=95), "cost.deny_score", Effect.RELAXES),
        (
            lambda d: d.update(defaults={"unresolved_column_action": "warn"}),
            "defaults.unresolved_column_action",
            Effect.RELAXES,
        ),
    ],
)
def test_diff_classifies_effects(base, mutate, path, effect):
    d = diff_policies(base, _variant(mutate))
    match = [c for c in d.changes if c.path == path]
    assert match and match[0].effect is effect, d.changes


def test_column_grant_add_and_remove(base):
    def mutate(d):
        d["roles"]["warehouse_analyst"]["tables"]["orders"] = [
            "id",
            "tenant_id",
            "created_at",
            "total_amount",
        ]

    d = diff_policies(base, _variant(mutate))
    cols = [c for c in d.changes if c.path == "roles.warehouse_analyst.tables.orders.columns"]
    assert {c.effect for c in cols} == {Effect.RELAXES, Effect.RESTRICTS}


def test_simulate_against_candidate(base):
    relaxed = _variant(
        lambda d: (
            d["roles"]["support_analyst"]["labels"].update(financial="allow")
            or d["roles"]["support_analyst"]["tables"].update(payments="*")
        )
    )
    cases = [
        SimCase(
            sql="SELECT p.iban FROM payments p WHERE p.tenant_id = 1",
            role="support_analyst",
            context={"tenant_id": 1},
            expect="deny",
            id="iban",
        ),
        SimCase(
            sql="SELECT o.id FROM orders o WHERE o.tenant_id = 1",
            role="support_analyst",
            context={"tenant_id": 1},
            expect="allow",
            id="ok",
        ),
    ]
    rows = {r["id"]: r for r in simulate(base, cases, relaxed)}
    assert rows["iban"]["decision"] == "deny" and rows["iban"]["candidate_decision"] == "allow"
    assert rows["iban"]["changed"] and rows["iban"]["candidate_matches_expectation"] is False
    assert not rows["ok"]["changed"] and rows["ok"]["matches_expectation"]


def test_explain_column_traces_inheritance():
    p = Policy.from_dict(yaml.safe_load(template_text("multi_tenant_saas")))
    info = explain_column(p, "finance", "payments", "card_number")
    assert info["inherits"] == ["tenant_base"]
    assert info["effective_access"] == "deny"  # not in the finance column grant
    card = explain_column(p, "support", "customers", "email")
    assert card["effective_access"] == "allow" and card["labels"][0]["set_by_role"] == "support"
    with pytest.raises(KeyError):
        explain_column(p, "ghost", "customers", "email")
    with pytest.raises(KeyError):
        explain_column(p, "support", "customers", "nope")


@pytest.mark.parametrize("kind", TEMPLATES)
def test_templates_load(kind):
    assert Policy.from_dict(yaml.safe_load(template_text(kind))).name == kind


def test_template_unknown():
    with pytest.raises(KeyError):
        template_text("nope")


# --------------------------------------------------------------------------------- CLI
def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_template_and_diff(capsys, tmp_path):
    assert "multi_tenant_saas" in run(capsys, "policy", "template")[1]
    target = tmp_path / "p.yaml"
    assert run(capsys, "policy", "template", "multi_tenant_saas", "--output", str(target))[0] == 0
    assert run(capsys, "policy", "template", "multi_tenant_saas", "--output", str(target))[0] == 2
    assert run(capsys, "policy", "template", "nope")[0] == 2
    relaxed = tmp_path / "relaxed.yaml"
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    data["roles"]["support"]["labels"]["payment_card"] = "deny"  # unchanged (inherited deny)
    data["roles"]["finance"]["tables"]["payments"] = "*"  # relaxation
    data["metadata"]["revision"] = "0.2"
    relaxed.write_text(yaml.safe_dump(data), encoding="utf-8")
    code, out, _ = run(capsys, "policy", "diff", str(target), str(relaxed))
    assert code == 0 and "relaxation" in out and "0.1" in out and "0.2" in out
    assert run(capsys, "policy", "diff", str(target), str(relaxed), "--fail-on-relaxation")[0] == 1
    code, out, _ = run(capsys, "policy", "diff", str(target), str(relaxed), "--format", "json")
    assert json.loads(out)["relaxations"] >= 1


def test_cli_simulate_and_explain(capsys, tmp_path):
    cases = tmp_path / "cases.yaml"
    cases.write_text(
        "- {id: c1, sql: 'SELECT o.id FROM orders o WHERE o.tenant_id = 1', role: support_analyst,"
        " context: {tenant_id: 1}, expect: allow}\n"
        "- {id: c2, sql: 'SELECT o.id FROM orders o', role: support_analyst,"
        " context: {tenant_id: 1}, expect: allow}\n",
        encoding="utf-8",
    )
    code, out, _ = run(
        capsys, "policy", "simulate", "--policy", str(POLICY_PATH), "--cases", str(cases)
    )
    assert code == 1 and "1 expectation mismatch" in out
    code, out, _ = run(
        capsys,
        "policy",
        "simulate",
        "--policy",
        str(POLICY_PATH),
        "--cases",
        str(cases),
        "--against",
        str(POLICY_PATH),
        "--fail-on-change",
    )
    assert code == 1 and "0 changed" in out  # still fails on the mismatch
    assert (
        run(capsys, "policy", "simulate", "--policy", str(POLICY_PATH), "--cases", "missing.yaml")[
            0
        ]
        == 2
    )
    code, out, _ = run(
        capsys,
        "policy",
        "explain",
        "--policy",
        str(POLICY_PATH),
        "--role",
        "support_analyst",
        "--tenant",
        "1",
        "--sql",
        "SELECT p.card_number FROM payments p WHERE p.tenant_id = 1",
    )
    payload = json.loads(out)
    assert payload["decision"] == "deny" and payload["decision_id"]
    assert any(f["lineage"] for f in payload["findings"] if f["rule_id"].startswith("privacy."))
    assert run(capsys, "policy", "explain", "--policy", str(POLICY_PATH), "--role", "x")[0] == 2
    assert (
        run(
            capsys,
            "policy",
            "explain",
            "--policy",
            str(POLICY_PATH),
            "--role",
            "x",
            "--column",
            "orders.id",
        )[0]
        == 2
    )
