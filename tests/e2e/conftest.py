"""Browser end-to-end fixtures: a live demo server on a free local port."""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip("playwright")
uvicorn = pytest.importorskip("uvicorn")

AXE_URL = "https://cdn.jsdelivr.net/npm/axe-core@4.10.3/axe.min.js"
SHOTS = Path(__file__).parents[2] / ".pytest_tmp" / "screenshots"


def pytest_collection_modifyitems(config, items):
    # Playwright's sync API keeps an event loop running for the session, which breaks later
    # tests that start their own loop. Browser tests therefore run only when selected.
    if "e2e" in (config.getoption("markexpr") or "") and "not e2e" not in config.getoption(
        "markexpr"
    ):
        return
    skip = pytest.mark.skip(reason="browser tests run with -m e2e")
    for item in items:
        if "e2e" in item.keywords:
            item.add_marker(skip)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(url: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server did not start: {url}")


@pytest.fixture(scope="session")
def demo_url():
    from sqlguard_ninja.demo.app import DemoSettings, create_app

    port = _free_port()
    app = create_app(DemoSettings(rate_limit_per_minute=10_000))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/"
    _wait(url + "healthz")
    yield url
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def axe_source() -> str | None:
    try:
        with urllib.request.urlopen(AXE_URL, timeout=15) as r:
            return r.read().decode("utf-8")
    except OSError:
        return None


@pytest.fixture
def browser_context_args(browser_context_args):
    # bypass_csp only so the test can inject axe-core; the app itself never needs it.
    return {**browser_context_args, "bypass_csp": True}


@pytest.fixture
def shots() -> Path:
    SHOTS.mkdir(parents=True, exist_ok=True)
    return SHOTS
