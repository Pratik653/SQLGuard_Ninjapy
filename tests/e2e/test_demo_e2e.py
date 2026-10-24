"""The playground in a real browser (server mode)."""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.e2e


@pytest.fixture
def app(page: Page, demo_url: str):
    errors: list[str] = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(demo_url)
    expect(page.locator("body[data-ready='true']")).to_be_attached(timeout=15_000)
    yield page
    assert not errors, errors


def run_example(page: Page, example_id: str) -> None:
    page.locator(f"[data-example='{example_id}']").click()
    expect(page.locator("#result")).to_have_attribute("aria-busy", "false")


def choose_role(page: Page, label: str) -> None:
    page.get_by_role("radio", name=label).check()


def test_loads_with_three_roles_and_tenants(app: Page, shots):
    expect(app.get_by_role("radio")).to_have_count(3)
    for name in ("Sales Analyst", "Customer Support", "Store Manager"):
        expect(app.get_by_role("radio", name=name)).to_be_attached()
    expect(app.locator("#tenant option")).to_have_count(3)
    expect(app.locator("#mode-pill")).to_have_text("Server mode")
    app.screenshot(path=str(shots / "01-loaded.png"), full_page=True)


def test_allowed_query_runs_and_shows_lineage(app: Page, shots):
    choose_role(app, "Sales Analyst")
    run_example(app, "sales-revenue")
    verdict = app.locator(".verdict")
    expect(verdict).to_have_attribute("data-decision", "allow")
    expect(app.locator("[data-section='execution']")).to_have_attribute("data-status", "ok")
    assert app.locator("[data-section='execution'] tbody tr").count() > 0
    lineage = app.locator("[data-section='lineage']")
    expect(lineage).to_contain_text("orders.total_amount")
    expect(lineage).to_contain_text("revenue")
    app.screenshot(path=str(shots / "02-allowed.png"), full_page=True)


def test_denied_query_explains_and_does_not_run(app: Page, shots):
    choose_role(app, "Customer Support")
    run_example(app, "support-card-number")
    expect(app.locator(".verdict")).to_have_attribute("data-decision", "deny")
    expect(app.locator("[data-rule='privacy.label_denied']")).to_contain_text("payment_card")
    expect(app.locator(".finding .fix").first).to_contain_text("How to fix")
    expect(app.locator("[data-section='execution']")).to_have_attribute("data-status", "not_run")
    app.screenshot(path=str(shots / "03-denied.png"), full_page=True)


def test_same_query_differs_by_role(app: Page):
    sql = "SELECT c.email FROM customers c WHERE c.tenant_id = :tenant_id LIMIT 5"
    app.locator("#sql").fill(sql)
    choose_role(app, "Customer Support")
    app.locator("#run").click()
    expect(app.locator(".verdict")).to_have_attribute("data-decision", "allow")
    choose_role(app, "Sales Analyst")
    app.locator("#sql").fill(sql)
    app.locator("#run").click()
    expect(app.locator(".verdict")).to_have_attribute("data-decision", "deny")


def test_keyboard_shortcut_runs(app: Page):
    app.locator("#sql").fill("SELECT o.id FROM orders o WHERE o.tenant_id = :tenant_id LIMIT 3")
    app.locator("#sql").press("Control+Enter")
    expect(app.locator(".verdict")).to_have_attribute("data-decision", "allow")


def test_untrusted_text_is_rendered_as_text(app: Page):
    payload = "SELECT '<img src=x onerror=alert(1)>' AS x FROM orders o WHERE o.tenant_id = :tenant_id LIMIT 1"
    app.locator("#sql").fill(payload)
    app.locator("#run").click()
    expect(app.locator("[data-section='execution']")).to_contain_text("<img src=x")
    assert app.locator("#result img").count() == 0


def test_tenant_isolation_tab(app: Page, shots):
    app.get_by_role("tab", name="Tenant isolation").click()
    app.locator("#tenant-run").click()
    for t in ("1", "2", "3"):
        expect(app.locator(f"[data-tenant='{t}'] tbody tr").first).to_be_visible()
    cross = app.locator("[data-tenant='cross'] .verdict")
    expect(cross).to_have_attribute("data-decision", "deny")
    a = app.locator("[data-tenant='1'] tbody").inner_text()
    b = app.locator("[data-tenant='2'] tbody").inner_text()
    assert a != b
    app.screenshot(path=str(shots / "04-tenants.png"), full_page=True)


def test_policy_tab_lists_role_access(app: Page):
    app.get_by_role("tab", name="Role permissions").click()
    app.locator("#policy-role").select_option("store_manager")
    salary = app.locator("[data-table='employees'] .col-row", has_text="salary")
    expect(salary).to_contain_text("aggregate only")


def test_benchmark_tab_separates_internal_and_independent(app: Page, shots):
    app.get_by_role("tab", name="Benchmarks").click()
    banner = app.locator("[data-section='tier-warning']")
    expect(banner).to_contain_text("Internal benchmark results only")
    expect(app.locator("[data-tier='independent'] .stat")).to_have_text("0")
    expect(app.locator("[data-adapter='native']").first).to_be_visible()
    app.get_by_role("button", name="Within each tool's capability").click()
    expect(app.get_by_role("button", name="Within each tool's capability")).to_have_attribute(
        "aria-pressed", "true"
    )
    app.screenshot(path=str(shots / "05-bench.png"), full_page=True)


def test_tabs_support_arrow_keys(app: Page):
    app.get_by_role("tab", name="Playground").focus()
    app.keyboard.press("ArrowRight")
    expect(app.get_by_role("tab", name="Tenant isolation")).to_have_attribute(
        "aria-selected", "true"
    )
    expect(app.locator("#panel-tenant")).to_be_visible()


@pytest.mark.parametrize("width", [360, 768])
def test_no_horizontal_overflow_on_small_screens(page: Page, demo_url: str, width: int, shots):
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(demo_url)
    expect(page.locator("body[data-ready='true']")).to_be_attached(timeout=15_000)
    page.locator("[data-example='support-shipments']").click()
    expect(page.locator(".verdict")).to_be_visible()
    for tab in ("Playground", "Tenant isolation", "Role permissions", "Benchmarks"):
        page.get_by_role("tab", name=tab).click()
        overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
        assert overflow <= 1, (tab, overflow)
    page.get_by_role("tab", name="Playground").click()
    page.screenshot(path=str(shots / f"06-mobile-{width}.png"), full_page=True)


def test_accessibility_axe(app: Page, axe_source):
    if axe_source is None:
        pytest.skip("axe-core could not be downloaded")
    # Panels fade in; axe would sample colours mid-animation. Reduced motion disables it.
    app.emulate_media(reduced_motion="reduce")
    run_example(app, "support-orders")
    app.add_script_tag(content=axe_source)
    for tab in ("Playground", "Tenant isolation", "Role permissions", "Benchmarks", "About"):
        app.get_by_role("tab", name=tab).click()
        if tab == "Tenant isolation":
            app.locator("#tenant-run").click()
            expect(app.locator("[data-tenant='cross']")).to_be_visible()
        if tab == "Benchmarks":
            expect(app.locator("[data-section='tier-warning']")).to_be_visible()
        result = app.evaluate(
            "async () => (await axe.run(document, {resultTypes: ['violations']})).violations"
            ".filter(v => ['serious', 'critical'].includes(v.impact))"
            ".map(v => v.id + ': ' + v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | '))"
        )
        assert result == [], (tab, result)


def test_links_to_project_docs_and_limitations(app: Page):
    links = app.get_by_role("navigation", name="Project links").get_by_role("link")
    expect(links).to_have_count(4)
    hrefs = [links.nth(i).get_attribute("href") for i in range(4)]
    assert any(h.endswith("KNOWN_LIMITATIONS.md") for h in hrefs)
    assert any("pypi.org/project/sqlguard-ninja" in h for h in hrefs)
