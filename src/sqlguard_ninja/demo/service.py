"""The demo's backend logic: plain functions returning JSON-safe dicts.

The same :class:`DemoService` runs in the FastAPI server (``sqlninja demo serve``) and, in the
static demo, inside the visitor's browser through Pyodide. Identity (role and tenant) is
chosen from a fixed list; the SQL text is the only free input. Allowed queries run in the
restricted synthetic :class:`~sqlguard_ninja.demo.sandbox.Sandbox`; review and deny
decisions never execute.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.lineage import lineage as sqlglot_lineage

from sqlguard_ninja._version import __version__
from sqlguard_ninja.benchmarking.builtin import benchmarks_root
from sqlguard_ninja.core.analysis import analyse
from sqlguard_ninja.core.findings import Decision, ValidationResult
from sqlguard_ninja.core.guard import Guard
from sqlguard_ninja.demo.examples import EXAMPLES, ROLE_LABELS, TENANT_DEMO, TENANTS, as_dicts
from sqlguard_ninja.demo.sandbox import Sandbox, SandboxError
from sqlguard_ninja.policy.model import Policy
from sqlguard_ninja.policy.tools import explain_column

DIALECT = "sqlite"
MAX_SQL_CHARS = 5000
_ACCESS_RANK = {"allow": 0, "aggregate_only": 1, "review": 2, "deny": 3, "not_granted": 4}
_DECISION_TEXT = {
    Decision.ALLOW: "Allowed",
    Decision.REVIEW: "Needs human review",
    Decision.DENY: "Denied",
}


def demo_policy() -> Policy:
    """The retail catalog and labels with the three demo roles."""
    base = yaml.safe_load(
        (benchmarks_root() / "policies" / "retail_saas.yaml").read_text(encoding="utf-8")
    )
    roles = yaml.safe_load((Path(__file__).with_name("roles.yaml")).read_text(encoding="utf-8"))
    base.update(
        name="retail_demo",
        description="Public demo: synthetic retail data, three roles.",
        dialect=DIALECT,
        roles=roles,
        metadata={"revision": f"demo-{__version__}", "owner": "sqlguard-ninja demo"},
    )
    return Policy.from_dict(base)


class InputError(ValueError):
    """Bad demo input; the message is safe to show."""


class DemoService:
    def __init__(self, *, execute: bool = True) -> None:
        self.policy = demo_policy()
        self.guard = Guard(self.policy)
        self.sandbox = Sandbox(self.policy) if execute else None
        self._tenant_ids = {t["id"] for t in TENANTS}

    # ------------------------------------------------------------------ inputs
    def _check(self, sql: Any, role: Any, tenant: Any) -> tuple[str, str, int]:
        if role not in ROLE_LABELS:
            raise InputError("Choose one of the demo roles.")
        if (
            not isinstance(tenant, int)
            or isinstance(tenant, bool)
            or tenant not in self._tenant_ids
        ):
            raise InputError("Choose one of the demo store groups.")
        if not isinstance(sql, str) or not sql.strip():
            raise InputError("Enter a SQL query.")
        if len(sql) > MAX_SQL_CHARS:
            raise InputError(f"Queries are limited to {MAX_SQL_CHARS} characters in the demo.")
        return sql, role, tenant

    # ------------------------------------------------------------------ public API
    def meta(self) -> dict[str, Any]:
        roles = []
        for key, label in ROLE_LABELS.items():
            role = self.policy.effective_role(key)
            assert role is not None
            roles.append({"id": key, "label": label, "description": role.description})
        return {
            "version": __version__,
            "policy": {
                "name": self.policy.name,
                "revision": self.policy.revision,
                "fingerprint": self.policy.fingerprint,
            },
            "dialect": DIALECT,
            "executes": self.sandbox is not None,
            "roles": roles,
            "tenants": list(TENANTS),
            "examples": as_dicts(),
            "tenant_demo_sql": TENANT_DEMO,
            "schema": self._schema(),
        }

    def run(self, sql: Any, role: Any, tenant: Any) -> dict[str, Any]:
        try:
            sql, role, tenant = self._check(sql, role, tenant)
        except InputError as exc:
            return {"error": "invalid_input", "message": str(exc)}
        result = self.guard.validate(sql, role=role, dialect=DIALECT, context={"tenant_id": tenant})
        out = self._decision(result, role, tenant)
        out["lineage"] = self._lineage(sql, role)
        out["execution"] = self._execute(result, sql, tenant)
        return out

    def tenant_isolation(self, role: Any) -> dict[str, Any]:
        if role not in ROLE_LABELS:
            return {"error": "invalid_input", "message": "Choose one of the demo roles."}
        sql = TENANT_DEMO
        runs = []
        for t in TENANTS:
            result = self.guard.validate(
                sql, role=role, dialect=DIALECT, context={"tenant_id": t["id"]}
            )
            runs.append(
                {
                    "tenant": t,
                    "decision": result.decision.value,
                    "execution": self._execute(result, sql, t["id"]),
                }
            )
        forged = "SELECT COUNT(*) AS orders FROM orders o WHERE o.tenant_id = 2"
        attempt = self.guard.validate(forged, role=role, dialect=DIALECT, context={"tenant_id": 1})
        return {
            "sql": sql,
            "runs": runs,
            "cross_tenant": {
                "sql": forged,
                "as_tenant": TENANTS[0],
                **self._decision(attempt, role, 1),
            },
        }

    def capabilities(self, role: Any) -> dict[str, Any]:
        if role not in ROLE_LABELS:
            return {"error": "invalid_input", "message": "Choose one of the demo roles."}
        tables = []
        for tname, tdef in self.policy.catalog.tables.items():
            cols = [
                {
                    "name": c,
                    "labels": sorted(d.effective_labels()),
                    "access": self._access(role, tname, c),
                }
                for c, d in tdef.columns.items()
            ]
            tables.append({"name": tname, "tenant_column": tdef.tenant_column, "columns": cols})
        return {"role": role, "tables": tables}

    # ------------------------------------------------------------------ helpers
    def _schema(self) -> list[dict[str, Any]]:
        return [
            {
                "name": n,
                "tenant_column": t.tenant_column,
                "columns": [
                    {"name": c, "labels": sorted(d.effective_labels())}
                    for c, d in t.columns.items()
                ],
            }
            for n, t in self.policy.catalog.tables.items()
        ]

    def _decision(self, result: ValidationResult, role: str, tenant: int) -> dict[str, Any]:
        findings = [
            {
                "rule_id": f.rule_id,
                "action": f.action.value,
                "severity": f.severity.value,
                "category": f.category.value,
                "message": f.message,
                "remediation": f.remediation,
                "table": f.table,
                "column": f.column,
                "labels": list(f.labels),
            }
            for f in result.findings
        ]
        role_label = ROLE_LABELS[role]
        group = next(t["label"] for t in TENANTS if t["id"] == tenant)
        if result.decision is Decision.ALLOW:
            tenant_owned = [
                t
                for t in result.tables
                if (d := self.policy.catalog.tables.get(t)) is not None and d.tenant_column
            ]
            scope = (
                f"every tenant-owned table is filtered to {group}."
                if tenant_owned
                else "it reads only shared tables, which no tenant owns."
            )
            summary = f"Every table and column used is permitted for {role_label}, and {scope}"
        elif result.decision is Decision.REVIEW:
            summary = (
                "The policy requires a person to approve this query before it runs. "
                "The demo never runs queries that need review."
            )
        else:
            n = len(result.blocking_findings)
            summary = f"{n} policy rule{'s' if n != 1 else ''} blocked this query. It was not run."
        return {
            "decision": result.decision.value,
            "headline": _DECISION_TEXT[result.decision],
            "summary": summary,
            "findings": findings,
            "decision_id": result.decision_id,
            "elapsed_ms": round(result.elapsed_ms, 2),
            "tables": list(result.tables),
        }

    def _execute(self, result: ValidationResult, sql: str, tenant: int) -> dict[str, Any]:
        if self.sandbox is None:
            return {"status": "disabled", "message": "This deployment validates only."}
        if result.decision is not Decision.ALLOW:
            return {"status": "not_run", "message": "Only allowed queries are run."}
        try:
            r = self.sandbox.execute(sql, {"tenant_id": tenant})
        except SandboxError as exc:
            return {"status": "refused", "message": str(exc)}
        return {
            "status": "ok",
            "columns": r.columns,
            "rows": r.rows,
            "truncated": r.truncated,
            "elapsed_ms": r.elapsed_ms,
        }

    def _access(
        self, role: str, table: str, column: str, json_path: tuple[str, ...] | None = None
    ) -> str:
        try:
            info = explain_column(self.policy, role, table, column)
        except KeyError:
            return "not_granted"
        if not info["column_granted"]:
            return "not_granted"
        effective = self.policy.effective_role(role)
        assert effective is not None
        labels = self.policy.catalog.tables[table].columns[column].effective_labels(json_path)
        modes = [effective.labels.get(lb, effective.unlisted_label_access).value for lb in labels]
        return max(modes, key=_ACCESS_RANK.__getitem__, default="allow")

    def _lineage(self, sql: str, role: str) -> dict[str, Any] | None:
        """Base columns each output column comes from, and how every column is used."""
        limits = self.policy.effective_limits(self.policy.effective_role(role))
        analysis = analyse(sql, DIALECT, self.policy.catalog, max_nodes=limits.max_ast_nodes)
        if not analysis.ok or analysis.root is None:
            return None
        seen: dict[tuple[Any, ...], dict[str, Any]] = {}
        for c in analysis.columns:
            path = ".".join(c.json_path) if c.json_path else None
            key = (c.table, c.column, path, c.clause.value, c.aggregate.value)
            if key in seen:
                continue
            coldef = self.policy.catalog.tables[c.table].columns.get(c.column)
            seen[key] = {
                "table": c.table,
                "column": c.column,
                "json_path": path,
                "clause": c.clause.value,
                "aggregate": c.aggregate.value,
                "whole_row": c.whole_row,
                "labels": sorted(coldef.effective_labels(c.json_path)) if coldef else [],
                "access": self._access(role, c.table, c.column, c.json_path),
            }
        return {"outputs": self._outputs(analysis.root), "references": list(seen.values())}

    def _outputs(self, root: exp.Expr) -> list[dict[str, Any]]:
        if not isinstance(root, exp.Select):
            return []
        tables = self.policy.catalog.tables
        schema = {n: dict.fromkeys(t.columns, "text") for n, t in tables.items()}
        outputs = []
        for proj in root.expressions[:30]:
            name = proj.alias_or_name
            if not name or name == "*":
                continue
            try:
                node = sqlglot_lineage(name, root, schema=schema, dialect=DIALECT)
            except (SqlglotError, KeyError, ValueError, AttributeError):
                outputs.append({"name": name, "sources": None})
                continue
            sources = sorted(
                {
                    (leaf.source.name, leaf.name.split(".")[-1])
                    for leaf in node.walk()
                    if not leaf.downstream and isinstance(leaf.source, exp.Table)
                }
            )
            outputs.append(
                {"name": name, "sources": [{"table": t, "column": c} for t, c in sources]}
            )
        return outputs


def check_examples(service: DemoService) -> list[str]:
    """Ids of examples whose decision differs from the expected one (used by tests)."""
    return [
        e.id
        for e in EXAMPLES
        if service.guard.validate(
            e.sql, role=e.role, dialect=DIALECT, context={"tenant_id": 1}
        ).decision.value
        != e.expect
    ]
