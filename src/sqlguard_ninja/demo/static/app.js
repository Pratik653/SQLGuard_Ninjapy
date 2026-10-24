// SQLGuard Ninja playground. No framework; all data is rendered with textContent.

const $ = (sel) => document.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const pct = (x) => (x === null || x === undefined ? "–" : `${(x * 100).toFixed(1)}%`);
const ACCESS_TEXT = {
  allow: "allowed",
  aggregate_only: "aggregate only",
  review: "needs review",
  deny: "denied by label",
  not_granted: "not granted",
};
const CLAUSE_TEXT = {
  select: "returned", where: "filter", join: "join condition", group: "group key",
  having: "having", order: "sort key", qualify: "qualify", other: "other",
};
const ICON = { allow: "✓", review: "!", deny: "✕" };

// ------------------------------------------------------------------ backends
class HttpBackend {
  label = "Server mode";
  async init() {}
  async call(method, args = {}) {
    const opts = method === "meta"
      ? { method: "GET" }
      : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(args) };
    const res = await fetch(`api/${method}`, opts);
    if (res.status === 429) throw new Error("Too many requests. Wait a minute and try again.");
    if (!res.ok) throw new Error(`The server answered ${res.status}.`);
    return res.json();
  }
}

class WorkerBackend {
  label = "Runs in your browser";
  constructor(config) {
    this.config = config;
    this.pending = new Map();
    this.seq = 0;
  }
  init(onProgress) {
    this.worker = new Worker("worker.js");
    this.worker.onmessage = (ev) => {
      const { id, ok, result, error, progress } = ev.data;
      if (progress) { onProgress?.(progress); return; }
      const p = this.pending.get(id);
      if (!p) return;
      this.pending.delete(id);
      ok ? p.resolve(result) : p.reject(new Error(error));
    };
    return this.call("__init__", this.config);
  }
  call(method, args = {}) {
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, method, args });
    });
  }
}

async function loadConfig() {
  try {
    const res = await fetch("config.json", { cache: "no-cache" });
    if (res.ok) return await res.json();
  } catch { /* fall through */ }
  return { mode: "server" };
}

// ------------------------------------------------------------------ state
const state = { meta: null, role: "customer_support", tenant: 1, backend: null, bench: null, benchView: "overall" };

// ------------------------------------------------------------------ tabs
function setupTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const select = (tab, focus = true) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    }
    if (focus) tab.focus();
    history.replaceState(null, "", `#${tab.id.slice(4)}`);
    onTab(tab.id);
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => select(t));
    t.addEventListener("keydown", (e) => {
      const d = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
      if (d) { e.preventDefault(); select(tabs[(i + d + tabs.length) % tabs.length]); }
      if (e.key === "Home") { e.preventDefault(); select(tabs[0]); }
      if (e.key === "End") { e.preventDefault(); select(tabs[tabs.length - 1]); }
    });
  });
  const initial = tabs.find((t) => `#${t.id.slice(4)}` === location.hash) || tabs[0];
  select(initial, false);
}

function onTab(id) {
  if (id === "tab-policy") renderPolicy();
  if (id === "tab-bench") renderBench();
}

// ------------------------------------------------------------------ playground
function renderIdentity() {
  const roles = $("#roles");
  roles.replaceChildren(
    ...state.meta.roles.map((r) =>
      el("label", { class: "role-option" },
        el("input", {
          type: "radio", name: "role", value: r.id, checked: r.id === state.role,
          onchange: () => { state.role = r.id; renderExamples(); syncPolicyRole(); },
        }),
        el("span", { class: "role-name", text: r.label }),
        el("span", { class: "role-desc", text: r.description }),
      ),
    ),
  );
  const tenant = $("#tenant");
  tenant.replaceChildren(...state.meta.tenants.map((t) => el("option", { value: t.id, text: `${t.label} (tenant ${t.id})` })));
  tenant.value = String(state.tenant);
  tenant.onchange = () => { state.tenant = Number(tenant.value); };
}

function renderExamples() {
  const list = $("#examples");
  const items = state.meta.examples.filter((e) => e.role === state.role);
  list.replaceChildren(
    ...items.map((e) =>
      el("li", {},
        el("button", {
          class: "example", type: "button", "data-example": e.id, title: e.lesson,
          onclick: () => { $("#sql").value = e.sql; runQuery(); },
        },
          el("span", { text: e.title }),
          el("span", { class: `chip ${e.expect}`, text: e.expect, "aria-label": `expected: ${e.expect}` }),
        ),
      ),
    ),
  );
  if (!$("#sql").value && items.length) $("#sql").value = items[0].sql;
}

async function runQuery() {
  const sql = $("#sql").value;
  const out = $("#result");
  const btn = $("#run");
  btn.disabled = true;
  out.setAttribute("aria-busy", "true");
  try {
    const r = await state.backend.call("run", { sql, role: state.role, tenant: state.tenant });
    out.replaceChildren(...renderRun(r));
  } catch (err) {
    out.replaceChildren(errorCard(err.message));
  } finally {
    btn.disabled = false;
    out.setAttribute("aria-busy", "false");
  }
}

function errorCard(message) {
  return el("div", { class: "card error-box", role: "alert" }, el("strong", { text: "Something went wrong. " }), message);
}

function verdictCard(r, extra) {
  return el("div", { class: `card verdict ${r.decision}`, "data-decision": r.decision },
    el("div", { class: "icon", "aria-hidden": "true", text: ICON[r.decision] }),
    el("h2", { text: r.headline }),
    el("p", { text: r.summary }),
    extra ? el("p", { class: "meta-line", text: extra }) : null,
  );
}

function renderRun(r) {
  if (r.error) return [errorCard(r.message || "Invalid input.")];
  const parts = [verdictCard(r, `decision ${r.decision_id.slice(0, 12)} · checked in ${r.elapsed_ms} ms`)];
  if (r.findings.length) {
    parts.push(
      el("div", { class: "card" },
        el("h3", { class: "card-title", text: r.decision === "allow" ? "Notes" : "Why" }),
        el("ul", { class: "findings" },
          r.findings.map((f) =>
            el("li", { class: "finding", "data-rule": f.rule_id },
              el("div", { class: "finding-head" },
                el("span", { class: `chip ${f.action}`, text: f.action }),
                el("span", { class: "chip mono", text: f.rule_id }),
                f.labels.length ? el("span", { class: "chip", text: f.labels.join(", ") }) : null,
              ),
              el("p", { text: f.message }),
              f.remediation ? el("p", { class: "fix" }, el("strong", { text: "How to fix: " }), f.remediation) : null,
            ),
          ),
        ),
      ),
    );
  }
  if (r.lineage) parts.push(renderLineage(r.lineage));
  parts.push(renderExecution(r.execution));
  return parts;
}

function renderLineage(lin) {
  const card = el("div", { class: "card lineage", "data-section": "lineage" },
    el("h3", { class: "card-title", text: "Lineage" }),
    el("p", { class: "muted small", text: "Where each output column comes from, and how every base column is used. Access is shown for the selected role." }),
  );
  const outs = lin.outputs.filter((o) => o.sources && o.sources.length);
  if (outs.length) {
    const access = new Map(lin.references.map((x) => [`${x.table}.${x.column}`, x.access]));
    const flow = el("div", { class: "flow", role: "group", "aria-label": "Output column lineage" },
      el("span", { class: "flow-head", text: "Base column" }), el("span"), el("span", { class: "flow-head", text: "Output" }),
    );
    for (const o of outs) {
      for (const s of o.sources) {
        const a = access.get(`${s.table}.${s.column}`) || "allow";
        flow.append(
          el("div", { class: "node" },
            el("span", { class: "mono", text: `${s.table}.${s.column}` }), " ",
            el("span", { class: `chip access-${a}`, text: ACCESS_TEXT[a] }),
          ),
          el("span", { class: "arrow", "aria-hidden": "true", text: "→" }),
          el("div", { class: "node out", "aria-label": `flows to output ${o.name}` }, el("span", { class: "mono", text: o.name })),
        );
      }
    }
    card.append(flow);
  }
  if (lin.references.length) {
    card.append(
      el("div", { class: "table-wrap", tabindex: "0", role: "region", "aria-label": "Table" },
        el("table", {},
          el("caption", { class: "muted small", text: "Column usage" }),
          el("thead", {}, el("tr", {}, ["Column", "Used as", "Aggregated", "Labels", "Access"].map((h) => el("th", { scope: "col", text: h })))),
          el("tbody", {},
            lin.references.map((x) =>
              el("tr", {},
                el("td", { class: "col-name", text: `${x.table}.${x.column}${x.json_path ? " → " + x.json_path : ""}` }),
                el("td", { text: CLAUSE_TEXT[x.clause] || x.clause }),
                el("td", { text: x.aggregate === "none" ? "no" : x.aggregate.replace("_", " ") }),
                el("td", { text: x.labels.join(", ") || "–" }),
                el("td", {}, el("span", { class: `chip access-${x.access}`, text: ACCESS_TEXT[x.access] })),
              ),
            ),
          ),
        ),
      ),
    );
  }
  return card;
}

function dataTable(columns, rows) {
  const numeric = columns.map((_, i) => rows.length > 0 && rows.every((r) => typeof r[i] === "number" || r[i] === null));
  return el("div", { class: "table-wrap", tabindex: "0", role: "region", "aria-label": "Query result rows" },
    el("table", {},
      el("thead", {}, el("tr", {}, columns.map((c, i) => el("th", { scope: "col", class: numeric[i] ? "num" : null, text: c })))),
      el("tbody", {}, rows.map((row) => el("tr", {}, row.map((v, i) => el("td", { class: numeric[i] ? "num" : null, text: v === null ? "NULL" : String(v) }))))),
    ),
  );
}

function renderExecution(ex) {
  const card = el("div", { class: "card", "data-section": "execution", "data-status": ex.status });
  if (ex.status === "ok") {
    card.append(
      el("h3", { class: "card-title", text: "Result" }),
      el("p", { class: "muted small", text: `${ex.rows.length} row${ex.rows.length === 1 ? "" : "s"}${ex.truncated ? " (first 100 shown)" : ""} · ${ex.elapsed_ms} ms · read-only synthetic sandbox` }),
      ex.rows.length ? dataTable(ex.columns, ex.rows) : el("p", { class: "muted", text: "No rows match." }),
    );
  } else {
    card.append(el("h3", { class: "card-title", text: "Not executed" }), el("p", { class: "muted", text: ex.message }));
  }
  return card;
}

// ------------------------------------------------------------------ tenant isolation
async function runTenant() {
  const out = $("#tenant-out");
  out.replaceChildren(el("p", { class: "muted", text: "Running…" }));
  try {
    const r = await state.backend.call("tenant_isolation", { role: state.role });
    if (r.error) { out.replaceChildren(errorCard(r.message)); return; }
    const cards = r.runs.map((run) =>
      el("div", { class: "card tenant-card", "data-tenant": run.tenant.id },
        el("h3", { text: `${run.tenant.label} · :tenant_id = ${run.tenant.id}` }),
        run.execution.status === "ok" ? dataTable(run.execution.columns, run.execution.rows) : el("p", { class: "muted", text: run.execution.message }),
      ),
    );
    const x = r.cross_tenant;
    cards.push(
      el("div", { class: "card tenant-card", "data-tenant": "cross" },
        el("h3", { text: `Signed in as ${x.as_tenant.label}, asking for tenant 2` }),
        el("pre", { class: "code", tabindex: "0", text: x.sql }),
        verdictCard(x),
        x.findings.length ? el("p", { class: "small", text: x.findings[0].message }) : null,
      ),
    );
    out.replaceChildren(...cards);
  } catch (err) {
    out.replaceChildren(errorCard(err.message));
  }
}

// ------------------------------------------------------------------ policy
function syncPolicyRole() {
  const sel = $("#policy-role");
  if (sel.value !== state.role) { sel.value = state.role; if (!$("#panel-policy").hidden) renderPolicy(); }
}

async function renderPolicy() {
  const role = $("#policy-role").value || state.role;
  const out = $("#policy-out");
  try {
    const r = await state.backend.call("capabilities", { role });
    const rank = (t) => (t.columns.every((c) => c.access === "not_granted") ? 1 : 0);
    const tables = [...r.tables].sort((a, b) => rank(a) - rank(b));
    out.replaceChildren(
      ...tables.map((t) => {
        const none = rank(t) === 1;
        return el("div", { class: "card", "data-table": t.name },
          el("h3", { class: "card-title" }, el("span", { class: "col-name", text: t.name }), none ? el("span", { class: "chip access-not_granted", text: " no access" }) : null),
          el("p", { class: "muted small", text: t.tenant_column ? `Tenant-owned: every query must filter ${t.tenant_column}.` : "Shared table (not tenant-owned)." }),
          none ? null : el("div", {}, t.columns.map((c) =>
            el("div", { class: "col-row" },
              el("span", { class: "col-name", text: c.name }),
              el("span", {}, c.labels.length ? el("span", { class: "chip", text: c.labels.join(", ") }) : null, " ",
                el("span", { class: `chip access-${c.access}`, text: ACCESS_TEXT[c.access] })),
            ),
          )),
        );
      }),
    );
  } catch (err) {
    out.replaceChildren(errorCard(err.message));
  }
}

// ------------------------------------------------------------------ benchmarks
async function renderBench() {
  const out = $("#bench-out");
  if (!state.bench) {
    try {
      const res = await fetch("data/benchmark.json");
      state.bench = await res.json();
    } catch (err) { out.replaceChildren(errorCard("Benchmark data could not be loaded.")); return; }
  }
  const b = state.bench;
  const view = state.benchView;
  const bar = (value, ci, cls, label) =>
    el("div", { class: "bar-track", role: "img", "aria-label": `${label}: ${pct(value)}${ci ? `, 95% interval ${pct(ci[0])} to ${pct(ci[1])}` : ""}` },
      el("div", { class: `bar-fill ${cls}`, style: null, "data-w": value }),
      ci ? el("div", { class: "bar-ci", "data-l": ci[0], "data-r": ci[1] }) : null,
    );
  const metricBlock = (title, key, cls, help) =>
    el("div", { class: "card" },
      el("h3", { class: "card-title", text: title }),
      el("p", { class: "muted small", text: help }),
      el("div", { class: "bars" },
        b.adapters.map((a) => {
          const m = a[view];
          return el("div", { class: "bar-row", "data-adapter": a.id },
            el("span", { text: `${a.label} ${a.version || ""}` }),
            bar(m[key], m.ci95[key], cls, `${a.label} ${title}`),
            el("span", { class: "bar-value", text: pct(m[key]) }),
          );
        }),
      ),
    );
  const toggle = el("div", { class: "toggle", role: "group", "aria-label": "Case set" },
    ["overall", "within_capability"].map((v) =>
      el("button", {
        type: "button", "aria-pressed": String(view === v),
        text: v === "overall" ? "All cases" : "Within each tool's capability",
        onclick: () => { state.benchView = v; renderBench(); },
      }),
    ),
  );
  const cats = Object.keys(b.adapters[0].categories);
  out.replaceChildren(
    el("div", { class: "banner", role: "note", "data-section": "tier-warning" },
      el("h2", { text: "Internal benchmark results only" }),
      el("p", { text: `All ${b.tiers.internal.toLocaleString()} evaluations come from the project's own corpus, written alongside the engine. There are ${b.tiers.independent} independent evaluations, so no independent result exists. A score of 100% here shows consistency with the documented semantics, not real-world detection quality.` }),
    ),
    el("div", { class: "tier-row" },
      el("div", { class: "card", "data-tier": "internal" }, el("p", { class: "muted small", text: "Internal evaluations" }), el("p", { class: "stat", text: b.tiers.internal.toLocaleString() }), el("p", { class: "small", text: `Corpus ${b.dataset.name} ${b.dataset.version} · fingerprint ${b.dataset.fingerprint}` })),
      el("div", { class: "card", "data-tier": "independent" }, el("p", { class: "muted small", text: "Independent evaluations" }), el("p", { class: "stat zero", text: String(b.tiers.independent) }), el("p", { class: "small", text: "Waiting for a licensed, independently sourced dataset (issue #6)." })),
    ),
    toggle,
    el("div", { class: "bench-grid" },
      metricBlock("Recall", "recall", "", "Share of unsafe queries that were blocked or sent to review. Higher is better; whiskers show the 95% Wilson interval."),
      metricBlock("False-positive rate", "false_positive_rate", "fpr", "Share of safe queries that were wrongly blocked. Lower is better."),
    ),
    el("div", { class: "card", style: null },
      el("h3", { class: "card-title", text: "Summary" }),
      el("div", { class: "table-wrap", tabindex: "0", role: "region", "aria-label": "Table" },
        el("table", {},
          el("thead", {}, el("tr", {}, ["Validator", "Cases", "Recall", "Precision", "F1", "FPR", "p95 latency"].map((h, i) => el("th", { scope: "col", class: i ? "num" : null, text: h })))),
          el("tbody", {}, b.adapters.map((a) => {
            const m = a[view];
            return el("tr", {},
              el("th", { scope: "row", text: `${a.label} ${a.version || ""}` }),
              el("td", { class: "num", text: m.cases }),
              el("td", { class: "num", text: pct(m.recall) }),
              el("td", { class: "num", text: pct(m.precision) }),
              el("td", { class: "num", text: m.f1.toFixed(3) }),
              el("td", { class: "num", text: pct(m.false_positive_rate) }),
              el("td", { class: "num", text: `${a.latency_ms.p95.toFixed(2)} ms` }),
            );
          })),
        ),
      ),
    ),
    el("div", { class: "card" },
      el("h3", { class: "card-title", text: "Recall by category (all cases)" }),
      el("div", { class: "table-wrap", tabindex: "0", role: "region", "aria-label": "Table" },
        el("table", {},
          el("thead", {}, el("tr", {}, el("th", { scope: "col", text: "Category" }), b.adapters.map((a) => el("th", { scope: "col", class: "num", text: a.label })))),
          el("tbody", {}, cats.map((c) =>
            el("tr", {},
              el("th", { scope: "row", text: `${c.replaceAll("_", " ")} (${b.adapters[0].categories[c].cases})` }),
              b.adapters.map((a) => el("td", { class: "num", text: a.categories[c].recall === null ? "safe cases only" : pct(a.categories[c].recall) })),
            ),
          )),
        ),
      ),
    ),
    el("div", { class: "card prose" },
      el("h3", { class: "card-title", text: "How to read this" }),
      el("ul", {}, b.notes.map((n) => el("li", { text: n }))),
      el("p", { class: "small muted", text: `Source: ${b.source} in the repository.` }),
    ),
  );
  // Widths are set through the CSSOM (the page's CSP forbids inline style attributes).
  for (const f of out.querySelectorAll(".bar-fill")) f.style.width = `${Number(f.dataset.w) * 100}%`;
  for (const c of out.querySelectorAll(".bar-ci")) {
    c.style.left = `${Number(c.dataset.l) * 100}%`;
    c.style.width = `${Math.max(0.5, (Number(c.dataset.r) - Number(c.dataset.l)) * 100)}%`;
  }
}

// ------------------------------------------------------------------ boot
async function boot() {
  const config = await loadConfig();
  const backend = config.mode === "pyodide" ? new WorkerBackend(config) : new HttpBackend();
  state.backend = backend;
  const bootText = $("#boot-text");
  try {
    await backend.init((msg) => { bootText.textContent = msg; });
    state.meta = await backend.call("meta");
  } catch (err) {
    $("#boot").replaceChildren(errorCard(`The demo could not start: ${err.message}`));
    return;
  }
  $("#mode-pill").textContent = backend.label;
  $("#about-version").textContent = `SQLGuard Ninja ${state.meta.version} · policy ${state.meta.policy.name} (${state.meta.policy.revision}, fingerprint ${state.meta.policy.fingerprint})${state.meta.executes ? "" : " · validation only"}`;
  $("#tenant-sql").textContent = state.meta.tenant_demo_sql;
  const pr = $("#policy-role");
  pr.replaceChildren(...state.meta.roles.map((r) => el("option", { value: r.id, text: r.label })));
  pr.value = state.role;
  pr.onchange = renderPolicy;
  renderIdentity();
  renderExamples();
  $("#run").addEventListener("click", runQuery);
  $("#sql").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runQuery(); }
  });
  $("#tenant-run").addEventListener("click", runTenant);
  $("#boot").hidden = true;
  document.body.dataset.ready = "true";
  setupTabs();
}

boot();
