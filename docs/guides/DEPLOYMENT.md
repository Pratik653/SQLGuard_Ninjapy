# Playground and deployment

**Live demo:** https://pratik653.github.io/SQLGuard_Ninjapy/. It is deployed from `main` by
`.github/workflows/pages.yml` (manual dispatch) to GitHub Pages, with Actions as the source
and HTTPS enforced. Only the `main` branch may deploy to the `github-pages` environment.

The playground is a web app on a synthetic retail database. It has:

* three roles: Sales Analyst, Customer Support and Store Manager
* example queries and plain-language explanations
* lineage, tenant isolation, role permissions and a benchmark dashboard

It needs no login, API key or credentials.

It runs in two modes from the same frontend and the same Python `DemoService`:

| Mode | How | Where SQL is validated and run |
|---|---|---|
| **Static** (recommended for public hosting) | `python scripts/build_static_demo.py site/` | in the visitor's browser, through Pyodide in a Web Worker; no server |
| **Server** | `pip install "sqlguard-ninja[demo]"` then `sqlninja demo serve` | FastAPI server, restricted in-memory sandbox |

## Execution safety

The demo does not rely on the parser alone, or on rolling back a transaction. Only queries
the policy **allows** run, and they run against an in-memory SQLite database of synthetic
data. That database enforces its own restrictions (`sqlguard_ninja/demo/sandbox.py`):

* `PRAGMA query_only`.
* An **authorizer** that allows only `SELECT`, reads of the catalog's tables and an allowlist
  of side-effect-free functions. ATTACH, PRAGMA, writes, schema changes, `sqlite_master` and
  `load_extension` are refused by the engine.
* **Engine limits**: string length, SQL length, expression depth, compound selects, zero
  attached databases, and few variables.
* A **step and time budget** through the progress handler. Recursive CTEs and cartesian
  products are interrupted.
* A row cap of 100, plus value truncation.

The database holds no real data. In the static build it exists only in the visitor's browser.
Set `SQLNINJA_DEMO_EXECUTE=false` for a validation-only server.

`tests/unit/test_demo.py` checks every one of these refusals.

## Server settings

Settings are read from the environment and validated at start-up. Unknown or invalid values
stop the server.

| Variable | Default | Meaning |
|---|---|---|
| `SQLNINJA_DEMO_EXECUTE` | `true` | run allowed queries in the sandbox |
| `SQLNINJA_DEMO_RATE_LIMIT_PER_MINUTE` | `60` | per-client API requests per minute (per process) |
| `SQLNINJA_DEMO_MAX_BODY_BYTES` | `16384` | request body cap; bodies without `Content-Length` are refused |
| `SQLNINJA_DEMO_TRUST_PROXY_HEADERS` | `false` | take the client from `X-Forwarded-For`; enable only behind a proxy that overwrites it |
| `SQLNINJA_DEMO_MAX_TRACKED_CLIENTS` | `10000` | memory bound for the rate limiter |

The server also:

* sends a strict CSP with no inline script, `frame-ancestors 'none'`, `nosniff`, and
  `no-referrer`
* disables the OpenAPI and docs pages
* exposes `/healthz` (liveness) and `/readyz` (the sandbox answers)
* rejects identity forgery: role and tenant come from fixed enums, and extra fields are
  rejected with 422

## Docker and Compose

```bash
docker build -t sqlguard-ninja-demo .
docker compose -f deploy/compose/docker-compose.yml up -d --build --wait
```

The image is multi-stage, with the base pinned by digest. It runs as non-root (UID 10001) and
has a `HEALTHCHECK`. The Compose file adds:

* a read-only root filesystem with a small tmpfs
* `cap_drop: ALL` and `no-new-privileges`
* memory, CPU and PID limits
* port binding to localhost only

CI builds the image and runs it under those restrictions. It then checks that the user is
UID 10001, that the probes pass, that the CSP header is present, and that one allowed and one
denied API call behave correctly.

## Kubernetes (example)

`deploy/kubernetes/` (Kustomize) contains:

* a Deployment:
  * non-root with a RuntimeDefault seccomp profile
  * read-only root filesystem with all capabilities dropped
  * no service-account token
  * resource limits
  * startup, liveness and readiness probes
* a Service and a PodDisruptionBudget
* a NetworkPolicy that allows ingress only from the ingress controller and **no egress**
* an example Ingress with edge rate limits

CI validates these manifests against the Kubernetes schemas with `kubernetes-validate --strict`.
Replace the image reference with the digest you built and scanned. The in-process rate
limiter is per replica, so keep the edge limit.

## Public hosting (decision)

Hosting is recorded as ADR-014. Several free options were compared.

**Static options:**

* **GitHub Pages** is free for public repositories and serves over HTTPS. It is already
  part of the project's GitHub account, with no new vendor, and the build is a single
  workflow.
* **Cloudflare Pages** and **Netlify** have free static tiers. Each would need a new
  account and adds a vendor.

**Server options:** Render, Fly.io and Koyeb have free or trial container tiers. They add an
always-on attack surface, can sleep on idle, may change their terms, and some require a
payment card.

**Chosen: the static build on GitHub Pages.** Validation and execution happen in each
visitor's browser, so there is no shared server to abuse and no database to protect. It runs
at zero cost. The `_headers` file sets the CSP and related headers on hosts that support it.
On GitHub Pages, a `<meta>` CSP applies instead.

`.github/workflows/pages.yml` builds the site, tests that exact build in Chromium with every
external request blocked, and deploys it. It runs **only when started manually**, after the
maintainer enables Pages (Settings → Pages → Source: GitHub Actions). Pages was enabled
on 2026-10-24. The deployment was then checked at the public URL in fresh, unauthenticated
browser contexts, on desktop and mobile:

* all three roles, with allowed and denied queries
* tenant isolation, explanations, lineage, permissions and benchmarks
* no external hosts contacted
* no missing assets and no console errors

Redeploy after changing the demo by running the workflow again.
