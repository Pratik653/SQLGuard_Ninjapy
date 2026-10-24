"""The static (Pyodide) build in a real browser, served by a plain static file server.

Build first: ``python scripts/build_static_demo.py site`` and set ``SQLNINJA_STATIC_SITE=site``.
The test blocks every request that leaves the local origin, proving the site is self-contained.
"""

from __future__ import annotations

import functools
import http.server
import os
import shutil
import threading
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.e2e
SITE = os.environ.get("SQLNINJA_STATIC_SITE")


class _Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".wasm": "application/wasm",
        ".mjs": "text/javascript",
    }

    def log_message(self, *args):  # quiet
        pass


@pytest.fixture(scope="module")
def static_url(tmp_path_factory):
    if not SITE or not (Path(SITE) / "config.json").exists():
        pytest.skip("static site not built (set SQLNINJA_STATIC_SITE)")
    # Serve under a repository-style subpath, as GitHub Pages does (/<repo>/).
    root = tmp_path_factory.mktemp("pages")
    shutil.copytree(Path(SITE).resolve(), root / "SQLGuard_Ninjapy")
    handler = functools.partial(_Handler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/SQLGuard_Ninjapy/"
    server.shutdown()


def test_static_site_runs_entirely_in_the_browser(page: Page, static_url: str, shots):
    external: list[str] = []

    def block(route):
        if route.request.url.startswith(static_url):
            route.continue_()
        else:
            external.append(route.request.url)
            route.abort()

    page.route("**/*", block)
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(static_url)
    expect(page.locator("body[data-ready='true']")).to_be_attached(timeout=120_000)
    expect(page.locator("#mode-pill")).to_have_text("Runs in your browser")

    page.get_by_role("radio", name="Store Manager").check()
    page.locator("[data-example='manager-salary-by-dept']").click()
    expect(page.locator(".verdict")).to_have_attribute("data-decision", "allow", timeout=30_000)
    expect(page.locator("[data-section='execution']")).to_have_attribute("data-status", "ok")
    page.screenshot(path=str(shots / "10-static-allow.png"), full_page=True)

    page.locator("[data-example='manager-salaries']").click()
    expect(page.locator(".verdict")).to_have_attribute("data-decision", "deny")
    expect(page.locator("[data-rule='privacy.aggregate_only']")).to_be_visible()

    page.get_by_role("tab", name="Tenant isolation").click()
    page.locator("#tenant-run").click()
    expect(page.locator("[data-tenant='cross'] .verdict")).to_have_attribute(
        "data-decision", "deny"
    )

    page.get_by_role("tab", name="Benchmarks").click()
    expect(page.locator("[data-tier='independent'] .stat")).to_have_text("0")
    assert external == [], external
    assert errors == [], errors
