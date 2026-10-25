"""FastAPI integration: a router exposing validation and guarded execution.

Authentication is the application's job. Pass a dependency that returns a
:class:`RequestContext` built from your own auth (session, JWT, mTLS...). The request body
can never set the role or tenant. Install with ``pip install "sqlguard-ninja[fastapi]"``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from sqlguard_ninja.integrations.binding import SQLBindingError
from sqlguard_ninja.integrations.checkpoint import RequestContext, SQLBlockedError, SQLCheckpoint
from sqlguard_ninja.integrations.executors import SafeExecutor

Scalar = str | int | float | bool | None


class SQLRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sql: str = Field(max_length=100_000)
    params: dict[str, Scalar] | None = Field(default=None, max_length=100)
    """Untrusted values for ``:name`` placeholders (needs ``safe_executor``)."""


class FindingOut(BaseModel):
    rule_id: str
    action: str
    message: str
    remediation: str | None = None


class ValidateResponse(BaseModel):
    decision: str
    authorized: bool
    message: str
    findings: list[FindingOut]
    trace_id: str


def create_router(
    checkpoint: SQLCheckpoint,
    context_dependency: Callable[..., RequestContext],
    executor: Callable[[str, Mapping[str, Any]], Any] | None = None,
    prefix: str = "/v1/sql",
    safe_executor: SafeExecutor | None = None,
) -> APIRouter:
    """``safe_executor`` enables ``/query`` with driver-bound ``params`` (execute_safe)."""
    router = APIRouter(prefix=prefix, tags=["sql"])

    @router.post("/validate", response_model=ValidateResponse)
    def validate(
        body: SQLRequest,
        ctx: RequestContext = Depends(context_dependency),  # noqa: B008
    ) -> ValidateResponse:
        outcome = checkpoint.evaluate(body.sql, ctx)
        return ValidateResponse(
            decision=outcome.result.decision.value,
            authorized=outcome.authorized,
            message=outcome.agent_message,
            findings=[
                FindingOut(
                    rule_id=f.rule_id,
                    action=f.action.value,
                    message=f.message,
                    remediation=f.remediation,
                )
                for f in outcome.result.findings
            ],
            trace_id=ctx.trace_id,
        )

    if executor is not None or safe_executor is not None:

        @router.post("/query")
        def query(
            body: SQLRequest,
            ctx: RequestContext = Depends(context_dependency),  # noqa: B008
        ) -> dict[str, Any]:
            try:
                if safe_executor is not None:
                    rows = checkpoint.execute_safe(body.sql, ctx, safe_executor, body.params)
                elif body.params:
                    raise HTTPException(status_code=400, detail={"error": "params_unsupported"})
                else:
                    assert executor is not None
                    rows = checkpoint.execute(body.sql, ctx, executor)
            except SQLBindingError as exc:
                raise HTTPException(
                    status_code=400, detail={"error": "invalid_parameters", "message": str(exc)}
                ) from exc
            except SQLBlockedError as exc:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "decision": exc.outcome.result.decision.value,
                        "message": exc.outcome.agent_message,
                    },
                ) from exc
            return {"rows": rows, "trace_id": ctx.trace_id}

    return router
