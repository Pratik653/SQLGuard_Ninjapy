// Static mode: runs SQLGuard Ninja inside the visitor's browser with Pyodide (self-hosted).
// Nothing is sent to a server; the synthetic database lives in this worker's memory.
/* global importScripts, loadPyodide */

let pyodide = null;
const METHODS = new Set(["meta", "run", "tenant_isolation", "capabilities"]);

async function init(config) {
  const index = new URL(config.pyodide, self.location.href).href;
  importScripts(`${index}pyodide.js`);
  self.postMessage({ progress: "Loading Python (WebAssembly)…" });
  pyodide = await loadPyodide({ indexURL: index });
  self.postMessage({ progress: "Loading the policy engine…" });
  await pyodide.loadPackage(config.packages, { messageCallback: () => {} });
  await pyodide.loadPackage(config.wheels.map((w) => new URL(w, self.location.href).href), { messageCallback: () => {} });
  self.postMessage({ progress: "Building the synthetic database…" });
  pyodide.runPython("from sqlguard_ninja.demo.service import DemoService\n_svc = DemoService()");
  return { ready: true };
}

function call(method, args) {
  if (!METHODS.has(method)) throw new Error("unknown method");
  pyodide.globals.set("_req", JSON.stringify({ method, args }));
  const text = pyodide.runPython(
    "import json as _j\n_r = _j.loads(_req)\n_j.dumps(getattr(_svc, _r['method'])(**_r['args']))",
  );
  return JSON.parse(text);
}

self.onmessage = async (ev) => {
  const { id, method, args } = ev.data;
  try {
    const result = method === "__init__" ? await init(args) : call(method, args);
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err && err.message ? err.message.split("\n").slice(-2).join(" ") : err) });
  }
};
