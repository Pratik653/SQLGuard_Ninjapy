"""Model Context Protocol (MCP) server exposing SQLGuard Ninja as a validation service.

Security model:

* **Identity is server-side.** The role and tenant are fixed when the server starts, from the
  operator's configuration (for example an MCP client config). No tool accepts a role, a
  tenant or an approval, so a model cannot choose its own permissions.
* **No execution, no credentials.** The server never connects to a database. It has no
  connection-string arguments and no filesystem tools. It only validates and explains SQL.
* **Agent-safe output.** Tools return the agent-facing messages and remediations. Internal
  detail is omitted, and lineage only names columns the role is allowed to know about.
* **Resource limits.** A hard input-size cap applies before parsing, plus a per-process rate
  limit.

Run: ``sqlninja mcp --policy policy.yaml --role support --tenant 42`` (stdio transport).
Requires ``pip install "sqlguard-ninja[mcp]"``.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from sqlguard_ninja._version import __version__
from sqlguard_ninja.core.analysis import SUPPORTED_DIALECTS, analyse
from sqlguard_ninja.core.findings import ValidationResult
from sqlguard_ninja.core.guard import Guard
from sqlguard_ninja.policy.model import Access, Disclosure, Policy
from sqlguard_ninja.privacy.rules import resolve_column_access
from sqlguard_ninja.query_cost.static import analyse_static_cost

HARD_MAX_SQL_CHARS = 100_000


@dataclass(frozen=True)
class ServerIdentity:
    """Trusted request identity, configured by the operator, never by the model."""

    role: str
    tenant: str | None = None
    principal: str = "mcp-client"


class RateLimiter:
    """Sliding-window limiter: at most ``limit`` calls per ``window_s`` seconds."""

    def __init__(self, limit: int = 120, window_s: float = 60.0) -> None:
        self.limit = limit
        self.window_s = window_s
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            while self._calls and now - self._calls[0] > self.window_s:
                self._calls.popleft()
            if len(self._calls) >= self.limit:
                return False
            self._calls.append(now)
            return True


class SQLGuardService:
    """Transport-independent tool implementations (unit-testable without MCP)."""

    def __init__(
        self,
        policy: Policy,
        identity: ServerIdentity,
        *,
        dialect: str | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        if policy.roles and policy.effective_role(identity.role) is None:
            raise ValueError(f"role {identity.role!r} is not defined in the policy")
        self.policy = policy
        self.guard = Guard(policy)
        self.identity = identity
        self.dialect = (dialect or policy.dialect).lower()
        self.rate_limiter = rate_limiter or RateLimiter()

    # ------------------------------------------------------------------ helpers
    def _context(self) -> dict[str, Any]:
        if self.identity.tenant is None:
            return {}
        return {self.policy.tenant.context_key: self.identity.tenant}

    def _precheck(self, sql: Any, dialect: str | None) -> tuple[str, str] | dict[str, Any]:
        if not self.rate_limiter.allow():
            return {"error": "rate_limited", "message": "Too many requests; try again shortly."}
        if not isinstance(sql, str):
            return {"error": "invalid_input", "message": "sql must be a string."}
        if len(sql) > HARD_MAX_SQL_CHARS:
            return {"error": "invalid_input", "message": "sql is too large."}
        chosen = (dialect or self.dialect).lower()
        if chosen not in SUPPORTED_DIALECTS:
            return {
                "error": "unsupported_dialect",
                "message": f"Supported dialects: {', '.join(SUPPORTED_DIALECTS)}.",
            }
        return sql, chosen

    def _validate(self, sql: str, dialect: str) -> ValidationResult:
        return self.guard.validate(
            sql, role=self.identity.role, dialect=dialect, context=self._context()
        )

    def _public_findings(
        self, result: ValidationResult, with_lineage: bool
    ) -> list[dict[str, Any]]:
        out = []
        generic = self.policy.disclosure == Disclosure.GENERIC
        for f in result.findings:
            item: dict[str, Any] = {
                "rule_id": f.rule_id,
                "action": f.action.value,
                "category": f.category.value,
                "message": f.message,
            }
            if f.remediation:
                item["remediation"] = f.remediation
            if with_lineage and not generic and f.metadata.get("lineage"):
                lineage = f.metadata["lineage"]
                item["lineage"] = {
                    "base_column": lineage.get("base_column"),
                    "json_path": lineage.get("json_path"),
                    "labels": lineage.get("labels"),
                }
            out.append(item)
        return out

    # -------------------------------------------------------------------- tools
    def validate_sql(self, sql: Any, dialect: str | None = None) -> dict[str, Any]:
        checked = self._precheck(sql, dialect)
        if isinstance(checked, dict):
            return checked
        result = self._validate(*checked)
        return {
            "decision": result.decision.value,
            "allowed": result.allowed,
            "findings": self._public_findings(result, with_lineage=False),
            "decision_id": result.decision_id,
            "policy_revision": result.policy_revision,
            "note": "Validation only: this server never executes SQL. Database permissions "
            "remain authoritative.",
        }

    def explain_policy_decision(self, sql: Any, dialect: str | None = None) -> dict[str, Any]:
        checked = self._precheck(sql, dialect)
        if isinstance(checked, dict):
            return checked
        result = self._validate(*checked)
        return {
            "decision": result.decision.value,
            "decision_id": result.decision_id,
            "role": self.identity.role,
            "tenant_scoped": bool(self.identity.tenant),
            "policy": {"name": result.policy_name, "revision": result.policy_revision},
            "findings": self._public_findings(result, with_lineage=True),
            "how_to_fix": [f.remediation for f in result.findings if f.remediation],
        }

    def inspect_query_cost(self, sql: Any, dialect: str | None = None) -> dict[str, Any]:
        checked = self._precheck(sql, dialect)
        if isinstance(checked, dict):
            return checked
        text, chosen = checked
        limits = self.policy.effective_limits(self.policy.role(self.identity.role)[1])
        analysis = analyse(text, chosen, self.policy.catalog, max_nodes=limits.max_ast_nodes)
        if not analysis.ok or analysis.qualified is None:
            return {"error": "unanalysable", "message": "The query could not be analysed."}
        report = analyse_static_cost(analysis, self.policy)
        return {
            "static_score": report.score,
            "review_threshold": self.policy.cost.review_score,
            "deny_threshold": self.policy.cost.deny_score,
            "factors": [
                {"code": f.code, "points": f.points, "explanation": f.explanation}
                for f in report.factors
            ],
            "note": "Static heuristic only; no execution plan is requested from any database.",
        }

    def get_policy_capabilities(self) -> dict[str, Any]:
        """What this identity may query: permitted tables/columns and how they may be used."""
        if not self.rate_limiter.allow():
            return {"error": "rate_limited", "message": "Too many requests; try again shortly."}
        role = self.policy.effective_role(self.identity.role) if self.policy.roles else None
        tables: dict[str, Any] = {}
        for tname, tdef in self.policy.catalog.tables.items():
            grant = role.tables.get(tname) if role is not None else None
            if role is not None and grant is None:
                continue  # do not reveal tables the role cannot use
            columns = {}
            for cname in tdef.columns:
                listed = grant is None or grant.columns == "*" or cname in grant.columns
                if not listed or (grant is not None and cname in grant.deny_columns):
                    continue
                access = resolve_column_access(self.policy, role, tname, cname).strongest
                if access is Access.DENY:
                    continue
                columns[cname] = access.value
            needs_pin = bool(tdef.tenant_column) and (role is None or role.tenant_scoped)
            tables[tname] = {
                "columns": columns,
                "tenant_filter_required": tdef.tenant_column if needs_pin else None,
            }
        limits = self.policy.effective_limits(role)
        return {
            "role": self.identity.role,
            "policy": {"name": self.policy.name, "revision": self.policy.revision},
            "dialects": list(SUPPORTED_DIALECTS),
            "default_dialect": self.dialect,
            "read_only": True,
            "tenant_bind_parameter": self.policy.tenant.parameter_names[0]
            if self.policy.tenant.parameter_names
            else None,
            "limits": {"max_limit": limits.max_limit, "max_joins": limits.max_joins},
            "tables": tables,
            "column_access_values": {
                "allow": "may be selected and filtered",
                "aggregate_only": "only inside COUNT/SUM/AVG-style aggregates",
                "review": "requires human approval",
            },
        }


def build_server(service: SQLGuardService) -> Any:
    """Create the MCP server with the four tools bound to ``service``."""
    from mcp.server.mcpserver import MCPServer  # noqa: PLC0415 - optional dependency

    server = MCPServer(
        name="sqlguard-ninja",
        version=__version__,
        instructions=(
            "Validate SQL before running it. The server enforces a fixed role and tenant "
            "chosen by the operator; you cannot change them. It never executes SQL."
        ),
    )

    @server.tool(description="Validate one SQL statement against the configured policy.")
    def validate_sql(sql: str, dialect: str | None = None) -> dict[str, Any]:
        return service.validate_sql(sql, dialect)

    @server.tool(description="Explain why a SQL statement is allowed, denied or needs review.")
    def explain_policy_decision(sql: str, dialect: str | None = None) -> dict[str, Any]:
        return service.explain_policy_decision(sql, dialect)

    @server.tool(description="Estimate query cost risk with static heuristics (no execution).")
    def inspect_query_cost(sql: str, dialect: str | None = None) -> dict[str, Any]:
        return service.inspect_query_cost(sql, dialect)

    @server.tool(description="List the tables, columns and rules available to this identity.")
    def get_policy_capabilities() -> dict[str, Any]:
        return service.get_policy_capabilities()

    return server


def serve(
    policy: Policy, identity: ServerIdentity, dialect: str | None = None
) -> None:  # pragma: no cover - exercised through the stdio integration test
    build_server(SQLGuardService(policy, identity, dialect=dialect)).run("stdio")


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin CLI wrapper
    import argparse  # noqa: PLC0415

    from sqlguard_ninja.benchmarking.builtin import resolve  # noqa: PLC0415

    p = argparse.ArgumentParser(prog="sqlguard-ninja-mcp")
    p.add_argument("--policy", required=True)
    p.add_argument("--role", required=True)
    p.add_argument("--tenant")
    p.add_argument("--dialect")
    args = p.parse_args(argv)
    policy = Policy.from_file(resolve(args.policy, "policy"))
    serve(policy, ServerIdentity(role=args.role, tenant=args.tenant), args.dialect)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
