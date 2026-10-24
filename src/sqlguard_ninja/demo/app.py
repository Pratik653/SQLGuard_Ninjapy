"""FastAPI server for the interactive demo (``sqlninja demo serve``; extra ``[demo]``).

No login, API keys or credentials: the role and store group are picked from fixed lists, and
SQL text is the only free input. Hardening:

* configuration from environment variables, validated at start-up (:class:`DemoSettings`);
* per-client rate limiting and a request-body size cap;
* strict security headers (CSP without inline script, no framing, no referrer);
* ``/healthz`` (liveness) and ``/readyz`` (the sandbox answers a query);
* allowed queries run only in the restricted synthetic sandbox; set
  ``SQLNINJA_DEMO_EXECUTE=false`` for validation-only.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sqlguard_ninja.demo.service import MAX_SQL_CHARS, DemoService

STATIC = Path(__file__).with_name("static")
RoleId = Literal["sales_analyst", "customer_support", "store_manager"]
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'; object-src 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class DemoSettings(BaseModel):
    """Server settings. Read from ``SQLNINJA_DEMO_*`` environment variables."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execute: bool = True
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10_000)
    max_body_bytes: int = Field(default=16_384, ge=1024, le=1_048_576)
    trust_proxy_headers: bool = False
    """Use the first ``X-Forwarded-For`` address as the client. Only behind a trusted proxy."""
    max_tracked_clients: int = Field(default=10_000, ge=100, le=1_000_000)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> DemoSettings:
        env = os.environ if env is None else env
        prefix = "SQLNINJA_DEMO_"
        known = {f"{prefix}{name.upper()}": name for name in cls.model_fields}
        unknown = sorted(k for k in env if k.startswith(prefix) and k not in known)
        if unknown:
            raise ValueError(f"unknown settings: {', '.join(unknown)}")
        return cls.model_validate({known[k]: v for k, v in env.items() if k in known})


class RateLimiter:
    """Fixed-window counter per client, with bounded memory (oldest clients evicted)."""

    def __init__(self, limit: int, max_clients: int, window_s: float = 60.0) -> None:
        self.limit, self.window_s, self.max_clients = limit, window_s, max_clients
        self._hits: OrderedDict[str, tuple[float, int]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, client: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            start, count = self._hits.pop(client, (now, 0))
            if now - start >= self.window_s:
                start, count = now, 0
            count += 1
            self._hits[client] = (start, count)
            while len(self._hits) > self.max_clients:
                self._hits.popitem(last=False)
            return count <= self.limit


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sql: str = Field(max_length=MAX_SQL_CHARS)
    role: RoleId
    tenant: int = Field(ge=1, le=3)


class RoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: RoleId


def create_app(settings: DemoSettings | None = None) -> FastAPI:
    settings = settings or DemoSettings.from_env()
    service = DemoService(execute=settings.execute)
    limiter = RateLimiter(settings.rate_limit_per_minute, settings.max_tracked_clients)
    app = FastAPI(title="SQLGuard Ninja demo", docs_url=None, redoc_url=None, openapi_url=None)

    def client_id(request: Request) -> str:
        if settings.trust_proxy_headers:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded:
                return forwarded.split(",")[0].strip()[:64]
        return request.client.host if request.client else "unknown"

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.path.startswith("/api/"):
            length = request.headers.get("content-length")
            if request.method == "POST" and length is None:
                # Chunked bodies have no declared size; refuse rather than buffer them.
                return _headers(JSONResponse({"error": "length_required"}, status_code=411))
            if length is not None and (
                not length.isdigit() or int(length) > settings.max_body_bytes
            ):
                return _headers(JSONResponse({"error": "too_large"}, status_code=413))
            if not limiter.allow(client_id(request)):
                resp = JSONResponse(
                    {
                        "error": "rate_limited",
                        "message": "Too many requests. Try again in a minute.",
                    },
                    status_code=429,
                )
                resp.headers["Retry-After"] = "60"
                return _headers(resp)
        return _headers(await call_next(request))

    @app.exception_handler(ValidationError)
    async def invalid(_: Request, __: ValidationError) -> JSONResponse:
        return JSONResponse({"error": "invalid_input"}, status_code=422)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        ok = service.sandbox is None or service.sandbox.execute("SELECT 1 AS ok", {}).rows == [[1]]
        return JSONResponse(
            {"status": "ready" if ok else "not_ready"}, status_code=200 if ok else 503
        )

    @app.get("/api/meta")
    def meta() -> dict[str, Any]:
        return service.meta()

    @app.post("/api/run")
    def run(body: RunIn) -> dict[str, Any]:
        return service.run(body.sql, body.role, body.tenant)

    @app.post("/api/tenant_isolation")
    def tenant_isolation(body: RoleIn) -> dict[str, Any]:
        return service.tenant_isolation(body.role)

    @app.post("/api/capabilities")
    def capabilities(body: RoleIn) -> dict[str, Any]:
        return service.capabilities(body.role)

    @app.get("/config.json")
    def config() -> dict[str, str]:
        return {"mode": "server"}

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    app.mount("/", StaticFiles(directory=STATIC), name="static")
    return app


def _headers(response: Response) -> Response:
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:  # pragma: no cover - blocking
    import uvicorn  # noqa: PLC0415 - optional extra

    uvicorn.run(create_app(), host=host, port=port, proxy_headers=False, server_header=False)
