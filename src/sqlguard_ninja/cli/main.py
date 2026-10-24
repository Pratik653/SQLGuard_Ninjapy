"""``sqlninja`` command-line interface.

Exit codes:

* ``validate``: 0 allow, 1 deny, 3 review, 2 usage or configuration error.
* ``scan``: 0 when no finding reaches ``--fail-on``, 1 otherwise, 2 usage error.
* ``benchmark compare`` / ``policy check``: 0 pass, 1 fail, 2 usage or configuration error.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from sqlguard_ninja._version import __version__
from sqlguard_ninja.benchmarking import builtin
from sqlguard_ninja.benchmarking.adapters import (
    EXTERNAL_TOOLS,
    BenchmarkAdapter,
    CallableAdapter,
    NativeAdapter,
    SubprocessAdapter,
)
from sqlguard_ninja.benchmarking.compare import compare
from sqlguard_ninja.benchmarking.dataset import DatasetError, load_dataset
from sqlguard_ninja.benchmarking.runner import load_result, run_benchmark, write_csv, write_result
from sqlguard_ninja.cli.config import CISection, ProjectConfig
from sqlguard_ninja.cli.templates import FILES
from sqlguard_ninja.core.findings import Decision
from sqlguard_ninja.core.guard import Guard
from sqlguard_ninja.policy.model import Policy, PolicyError
from sqlguard_ninja.policy.tools import (
    TEMPLATES,
    diff_policies,
    explain_column,
    explain_result,
    load_sim_cases,
    simulate,
    template_text,
)
from sqlguard_ninja.privacy.suggest import suggest_labels
from sqlguard_ninja.reporting.markdown import benchmark_report, comparison_report

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_REVIEW = 0, 1, 2, 3


class CLIError(Exception):
    """A user-facing error; printed without a traceback, exit code 2."""


def _out(text: str) -> None:
    line = text + ("\n" if not text.endswith("\n") else "")
    try:
        sys.stdout.write(line)
    except UnicodeEncodeError:
        # Legacy consoles (e.g. Windows cp1252) cannot print symbols used in reports.
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        sys.stdout.write(line.encode(encoding, errors="replace").decode(encoding))


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _load_config(path: str | None) -> tuple[ProjectConfig, Path]:
    if path is None:
        default = Path("sqlninja.yaml")
        if default.exists():
            return ProjectConfig.load(default)
        return ProjectConfig(), Path.cwd()
    try:
        return ProjectConfig.load(path)
    except (OSError, ValueError) as exc:
        raise CLIError(f"cannot load config {path}: {exc}") from exc


def _resolve(base: Path, value: str | None) -> Path | str | None:
    if value is None:
        return None
    if value.startswith(builtin.PREFIX):
        return value  # resolved by builtin.resolve() where it is loaded
    p = Path(value)
    return p if p.is_absolute() else base / p


def _resolve_file(base: Path, value: str | None) -> Path | None:
    """Resolve an output/baseline file path (never a ``builtin:`` reference)."""
    if value is None:
        return None
    p = Path(value)
    return p if p.is_absolute() else base / p


def _load_policy(path: str | Path | None) -> Policy:
    if path is None:
        raise CLIError(
            "no policy given (use --policy FILE, --policy builtin:retail_saas, "
            "or set 'policy' in sqlninja.yaml)"
        )
    try:
        return Policy.from_file(builtin.resolve(path, "policy"))
    except (PolicyError, FileNotFoundError) as exc:
        raise CLIError(str(exc)) from exc


def _write_summary(markdown: str) -> None:
    """Append to the GitHub Actions job summary when running in Actions."""
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")


# ------------------------------------------------------------------------------- commands
def cmd_validate(args: argparse.Namespace) -> int:
    cfg, base = _load_config(args.config)
    policy = _load_policy(args.policy or _resolve(base, cfg.policy))
    if sum(x is not None for x in (args.sql, args.file)) + bool(args.stdin) != 1:
        raise CLIError("give exactly one of --sql, --file or --stdin")
    if args.sql is not None:
        sql = args.sql
    elif args.file is not None:
        sql = Path(args.file).read_text(encoding="utf-8")
    else:
        sql = sys.stdin.read()
    context: dict[str, Any] = {}
    if args.context:
        try:
            context = json.loads(args.context)
        except json.JSONDecodeError as exc:
            raise CLIError(f"--context is not valid JSON: {exc}") from exc
        if not isinstance(context, dict):
            raise CLIError("--context must be a JSON object")
    if args.tenant is not None:
        context[policy.tenant.context_key] = args.tenant
    result = Guard(policy).validate(sql, role=args.role, dialect=args.dialect, context=context)
    if args.format == "json":
        _out(result.model_dump_json(indent=2))
    else:
        _out(result.explain(include_detail=args.verbose))
    return {Decision.ALLOW: EXIT_OK, Decision.DENY: EXIT_FAIL, Decision.REVIEW: EXIT_REVIEW}[
        result.decision
    ]


_RANK = {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.DENY: 2}


def _scan_files(paths: Sequence[str], pattern: str) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(x for x in p.rglob(pattern) if x.is_file()))
        elif p.is_file():
            files.append(p)
        else:
            raise CLIError(f"no such file or directory: {p}")
    return files


def cmd_scan(args: argparse.Namespace) -> int:
    from sqlguard_ninja.observability.telemetry import query_fingerprint  # noqa: PLC0415
    from sqlguard_ninja.reporting.sarif import (  # noqa: PLC0415
        ScanResult,
        relative_uri,
        split_statements,
        to_sarif,
    )

    cfg, base = _load_config(args.config)
    policy = _load_policy(args.policy or _resolve(base, cfg.policy))
    dialect = (args.dialect or policy.dialect).lower()
    context: dict[str, Any] = {}
    if args.tenant is not None:
        context[policy.tenant.context_key] = args.tenant
    guard = Guard(policy)
    root = Path(args.root or ".")
    files = _scan_files(args.paths, args.pattern)
    results: list[ScanResult] = []
    for path in files:
        uri = relative_uri(path, root)
        text = path.read_text(encoding="utf-8")
        for st in split_statements(text, dialect):
            r = guard.validate(st.sql, role=args.role, dialect=dialect, context=context)
            results.append(ScanResult(uri, st, r, query_fingerprint(st.sql, dialect)))
    uris = [relative_uri(p, root) for p in files]
    if args.format == "sarif":
        payload = json.dumps(to_sarif(results, policy, uris), indent=2)
    elif args.format == "json":
        payload = json.dumps(
            [
                {
                    "uri": s.uri,
                    "line": s.statement.start_line,
                    "decision": s.result.decision.value,
                    "decision_id": s.result.decision_id,
                    "findings": [
                        {"rule_id": f.rule_id, "action": f.action.value, "message": f.message}
                        for f in s.result.findings
                    ],
                }
                for s in results
            ],
            indent=2,
        )
    else:
        lines = [
            f"{s.uri}:{s.statement.start_line}: {s.result.decision.value.upper()}"
            + "".join(f"\n  [{f.action.value}] {f.rule_id}: {f.message}" for f in s.result.findings)
            for s in results
        ]
        payload = "\n".join(lines) or "no SQL statements found"
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        _out(payload)
    if args.fail_on == "never":
        return EXIT_OK
    threshold = _RANK[Decision(args.fail_on)]
    worst = max((_RANK[s.result.decision] for s in results), default=0)
    return EXIT_FAIL if worst >= threshold else EXIT_OK


def cmd_policy_check(args: argparse.Namespace) -> int:
    cfg, base = _load_config(args.config)
    policy = _load_policy(args.policy or _resolve(base, cfg.policy))
    tables = policy.catalog.tables
    labelled = sum(1 for t in tables.values() for c in t.columns.values() if c.effective_labels())
    _out(f"policy '{policy.name}' (version {policy.version}, dialect {policy.dialect}) is valid")
    _out(f"  tables: {len(tables)}  labelled columns: {labelled}  labels: {len(policy.labels)}")
    _out(f"  roles: {', '.join(policy.roles) or '(none: implicit role)'}")
    tenant_tables = [n for n, t in tables.items() if t.tenant_column]
    _out(f"  tenant-scoped tables: {', '.join(tenant_tables) or '(none)'}")
    warnings = []
    if policy.functions.mode == "denylist":
        warnings.append("functions.mode is 'denylist'; 'allowlist' is safer for production")
    for name in policy.roles:
        role = policy.effective_role(name)
        assert role is not None
        if not role.tenant_scoped and tenant_tables:
            warnings.append(f"role '{name}' is not tenant-scoped")
    for w in warnings:
        _out(f"  warning: {w}")
    return EXIT_OK


def cmd_policy_suggest(args: argparse.Namespace) -> int:
    cfg, base = _load_config(args.config)
    policy = _load_policy(args.policy or _resolve(base, cfg.policy))
    suggestions = suggest_labels(policy.catalog)
    _out("# Suggestions only - review with the data owner before adding to the policy.")
    if not suggestions:
        _out("# no unlabelled columns matched the heuristics")
    for s in suggestions:
        _out(f"{s.table}.{s.column}: [{s.label}]   # matched '{s.matched}'")
    return EXIT_OK


def cmd_policy_template(args: argparse.Namespace) -> int:
    if not args.kind:
        _out("available templates: " + ", ".join(TEMPLATES))
        return EXIT_OK
    try:
        text = template_text(args.kind)
    except KeyError as exc:
        raise CLIError(str(exc.args[0])) from exc
    if args.output:
        path = Path(args.output)
        if path.exists() and not args.force:
            raise CLIError(f"refusing to overwrite {path}; use --force")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        _out(f"wrote {path}")
    else:
        _out(text)
    return EXIT_OK


def cmd_policy_diff(args: argparse.Namespace) -> int:
    old, new = _load_policy(args.old), _load_policy(args.new)
    diff = diff_policies(old, new)
    if args.format == "json":
        _out(json.dumps(diff.as_dict(), indent=2, default=str))
    else:
        _out(
            f"policy diff {old.revision} ({old.fingerprint}) -> {new.revision} "
            f"({new.fingerprint}): {len(diff.changes)} change(s), "
            f"{len(diff.relaxations)} relaxation(s)"
        )
        for c in diff.changes:
            _out(f"  [{c.effect.value:9}] {c.path}: {c.before!s} -> {c.after!s}")
    if args.fail_on_relaxation and diff.relaxations:
        return EXIT_FAIL
    return EXIT_OK


def cmd_policy_simulate(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    against = _load_policy(args.against) if args.against else None
    try:
        cases = load_sim_cases(args.cases)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise CLIError(f"cannot load cases {args.cases}: {exc}") from exc
    rows = simulate(policy, cases, against)
    if args.format == "json":
        _out(json.dumps(rows, indent=2))
    else:
        for r in rows:
            line = f"{r['id']:>6} {r['role'] or '-':18} {r['decision']:6}"
            if against is not None:
                marker = " CHANGED" if r["changed"] else ""
                line += f" -> {r['candidate_decision']:6}{marker}"
            if r["expect"] is not None:
                line += f"  expect={r['expect']}"
            _out(line)
    key = "candidate_matches_expectation" if against is not None else "matches_expectation"
    mismatches = sum(1 for r in rows if r.get(key) is False)
    changed = sum(1 for r in rows if r.get("changed"))
    _out(f"{len(rows)} case(s); {mismatches} expectation mismatch(es); {changed} changed")
    if mismatches or (args.fail_on_change and changed):
        return EXIT_FAIL
    return EXIT_OK


def cmd_policy_explain(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    if bool(args.sql) == bool(args.column):
        raise CLIError("give exactly one of --sql or --column TABLE.COLUMN")
    if args.column:
        table, _, column = args.column.partition(".")
        try:
            payload = explain_column(policy, args.role, table.lower(), column.lower())
        except KeyError as exc:
            raise CLIError(str(exc.args[0])) from exc
    else:
        context: dict[str, Any] = {}
        if args.tenant is not None:
            context[policy.tenant.context_key] = args.tenant
        result = Guard(policy).validate(
            args.sql, role=args.role, dialect=args.dialect, context=context
        )
        payload = explain_result(result)
    _out(json.dumps(payload, indent=2, default=str))
    return EXIT_OK


def cmd_mcp(args: argparse.Namespace) -> int:  # pragma: no cover - blocks on stdio
    try:
        from sqlguard_ninja.mcp_server import ServerIdentity, serve  # noqa: PLC0415
    except ImportError as exc:
        raise CLIError('the MCP server needs: pip install "sqlguard-ninja[mcp]"') from exc
    policy = _load_policy(args.policy)
    try:
        serve(policy, ServerIdentity(role=args.role, tenant=args.tenant), args.dialect)
    except ValueError as exc:
        raise CLIError(str(exc)) from exc
    return EXIT_OK


def cmd_demo_serve(args: argparse.Namespace) -> int:  # pragma: no cover - blocks serving
    try:
        from sqlguard_ninja.demo.app import serve  # noqa: PLC0415 - optional extra
    except ImportError as exc:
        raise CLIError('the demo needs the extra: pip install "sqlguard-ninja[demo]"') from exc
    _out(f"SQLGuard Ninja demo on http://{args.host}:{args.port}/ (synthetic data only)")
    serve(args.host, args.port)
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.directory)
    existing = [name for name in FILES if (root / name).exists()]
    if existing and not args.force:
        raise CLIError(f"refusing to overwrite {existing}; use --force")
    for name, text in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        _out(f"wrote {path}")
    _out("next: sqlninja benchmark run --config " + str(root / "sqlninja.yaml"))
    return EXIT_OK


def _make_adapter(spec: str, policy: Policy, python: str | None) -> BenchmarkAdapter:
    if spec == "native":
        return NativeAdapter(policy)
    if spec.startswith("callable:"):
        return CallableAdapter.from_spec(spec.removeprefix("callable:"))
    if spec.startswith("external:"):
        name = spec.removeprefix("external:")
        if name not in EXTERNAL_TOOLS:
            raise CLIError(f"unknown external tool {name!r}; choose from {sorted(EXTERNAL_TOOLS)}")
        interpreter = python or str(
            Path(".venvs")
            / name
            / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        )
        if not Path(interpreter).exists():
            raise CLIError(
                f"no interpreter for {name} at {interpreter}; run "
                "scripts/setup_external_adapters.py or pass --python"
            )
        return SubprocessAdapter(EXTERNAL_TOOLS[name], interpreter, policy)
    raise CLIError("adapter must be 'native', 'external:<tool>' or 'callable:<module>:<fn>'")


def cmd_benchmark_run(args: argparse.Namespace) -> int:
    cfg, base = _load_config(args.config)
    bench = cfg.benchmark
    dataset_path = args.dataset or _resolve(base, bench.dataset)
    try:
        dataset = load_dataset(builtin.resolve(str(dataset_path), "dataset"))
    except (DatasetError, PolicyError, OSError) as exc:
        raise CLIError(f"cannot load dataset {dataset_path}: {exc}") from exc
    cases = dataset.filter(dialect=args.dialect or bench.dialect, category=args.category)
    if not cases:
        raise CLIError("no cases match the filters")
    adapter = _make_adapter(args.adapter or bench.adapter, dataset.policy, args.python)
    try:
        result = run_benchmark(dataset, adapter, cases)
    finally:
        adapter.close()
    output = Path(args.output) if args.output else _resolve_file(base, bench.output)
    assert output is not None
    write_result(result, output)
    report = benchmark_report(result)
    report_path = Path(args.report) if args.report else _resolve_file(base, bench.report)
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report + "\n", encoding="utf-8")
    if args.csv:
        write_csv(result, args.csv)
    if args.summary:
        _write_summary(report)
    m = result["metrics"]["overall"]
    _out(
        f"{adapter.name} {adapter.version}: {m['cases']} evaluations, recall "
        f"{m['recall']}, precision {m['precision']}, F1 {m['f1']}, "
        f"FPR {m['false_positive_rate']}, "
        f"p95 {m['latency_ms']['p95']} ms -> {output}"
    )
    return EXIT_OK


def _approved_ids(path: str | Path) -> frozenset[str]:
    """Case ids from a LABEL_CHANGES.yaml (each entry needs id, from, to, rationale)."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise CLIError(f"cannot read approved label changes {path}: {exc}") from exc
    ids = set()
    for entry in data.get("changes", []):
        missing = {"id", "from", "to", "rationale"} - set(entry)
        if missing:
            raise CLIError(f"{path}: entry {entry.get('id')!r} lacks {sorted(missing)}")
        ids.add(str(entry["id"]))
    return frozenset(ids)


def _thresholds(args: argparse.Namespace, ci: CISection, base: Path) -> Any:
    t = ci.thresholds(allow_benchmark_change=args.allow_benchmark_change)
    t = type(t)(**{**t.__dict__, "allow_label_changes": args.allow_label_changes})
    approved_file = args.approved_label_changes or _resolve_file(base, ci.approved_label_changes)
    if approved_file is not None:
        t = type(t)(**{**t.__dict__, "approved_label_changes": _approved_ids(approved_file)})
    overrides = {
        k: getattr(args, k)
        for k in (
            "max_security_regressions",
            "max_usability_regressions",
            "min_recall",
            "max_false_positive_rate",
            "max_p95_latency_increase_pct",
        )
        if getattr(args, k) is not None
    }
    return type(t)(**{**t.__dict__, **overrides})


def cmd_benchmark_compare(args: argparse.Namespace) -> int:
    cfg, base = _load_config(args.config)
    baseline_path = args.baseline or _resolve_file(base, cfg.ci.baseline)
    candidate_path = args.candidate or _resolve_file(base, cfg.benchmark.output)
    try:
        baseline = load_result(str(baseline_path))
        candidate = load_result(str(candidate_path))
    except (OSError, ValueError) as exc:
        raise CLIError(str(exc)) from exc
    comp = compare(baseline, candidate, _thresholds(args, cfg.ci, base))
    report = comparison_report(comp)
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(report + "\n", encoding="utf-8")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(comp.as_dict(), indent=2) + "\n", encoding="utf-8")
    if args.summary:
        _write_summary(report)
    _out(report)
    return EXIT_OK if comp.passed else EXIT_FAIL


def cmd_benchmark_baseline(args: argparse.Namespace) -> int:
    """Copy a reviewed result to the baseline path. Meant to be run by a human."""
    cfg, base = _load_config(args.config)
    source = Path(args.candidate) if args.candidate else _resolve_file(base, cfg.benchmark.output)
    target = Path(args.output) if args.output else _resolve_file(base, cfg.ci.baseline)
    assert source is not None and target is not None
    if os.environ.get("CI") and not args.i_understand_this_is_ci:
        raise CLIError("refusing to update a baseline inside CI; review and commit it locally")
    load_result(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    _out(f"baseline updated: {target} (commit it for review)")
    return EXIT_OK


def cmd_report_generate(args: argparse.Namespace) -> int:
    result = load_result(args.result)
    text = benchmark_report(result)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        _out(text)
    return EXIT_OK


def cmd_dataset_stats(args: argparse.Namespace) -> int:
    cfg, base = _load_config(args.config)
    path = args.dataset or _resolve(base, cfg.benchmark.dataset)
    try:
        ds = load_dataset(builtin.resolve(str(path), "dataset"))
    except (DatasetError, PolicyError, OSError) as exc:
        raise CLIError(str(exc)) from exc
    _out(
        json.dumps(
            {"fingerprint": ds.fingerprint, **ds.stats(), "files": ds.file_hashes()}, indent=2
        )
    )
    return EXIT_OK


# --------------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sqlninja",
        description="Policy enforcement and security benchmarking for LLM-generated SQL.",
    )
    p.add_argument("--version", action="version", version=f"sqlninja {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", help="sqlninja.yaml (default: ./sqlninja.yaml if present)")

    v = sub.add_parser("validate", help="validate one SQL statement")
    common(v)
    v.add_argument("--policy")
    v.add_argument("--sql")
    v.add_argument("--file")
    v.add_argument("--stdin", action="store_true")
    v.add_argument("--role")
    v.add_argument("--dialect")
    v.add_argument("--tenant", help="trusted tenant id (sets the policy's tenant context key)")
    v.add_argument("--context", help="JSON object of trusted request context")
    v.add_argument("--format", choices=["text", "json"], default="text")
    v.add_argument("--verbose", "-v", action="store_true", help="include internal detail")
    v.set_defaults(func=cmd_validate)

    sc = sub.add_parser("scan", help="validate every statement in SQL files (text, JSON, SARIF)")
    common(sc)
    sc.add_argument("paths", nargs="+", help="files or directories")
    sc.add_argument("--policy")
    sc.add_argument("--role")
    sc.add_argument("--dialect")
    sc.add_argument("--tenant", help="trusted tenant id for tenant-filter checks")
    sc.add_argument("--pattern", default="*.sql", help="file glob inside directories")
    sc.add_argument("--root", help="base directory for SARIF URIs (default: current directory)")
    sc.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    sc.add_argument("--output", help="write to this file instead of stdout")
    sc.add_argument("--fail-on", choices=["deny", "review", "never"], default="deny")
    sc.set_defaults(func=cmd_scan)

    dm = sub.add_parser("demo", help="interactive playground").add_subparsers(
        dest="demo_cmd", required=True
    )
    dserve = dm.add_parser("serve", help="serve the playground (synthetic data, no login)")
    dserve.add_argument("--host", default="127.0.0.1")
    dserve.add_argument("--port", type=int, default=8000)
    dserve.set_defaults(func=cmd_demo_serve)

    i = sub.add_parser("init", help="write a starter sqlninja.yaml, policy and test cases")
    i.add_argument("directory", nargs="?", default=".")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    pol = sub.add_parser("policy", help="policy utilities").add_subparsers(
        dest="policy_cmd", required=True
    )
    pc = pol.add_parser("check", help="validate a policy file and print a summary")
    common(pc)
    pc.add_argument("--policy")
    pc.set_defaults(func=cmd_policy_check)
    ps = pol.add_parser("suggest", help="suggest labels for unlabelled columns (heuristic)")
    common(ps)
    ps.add_argument("--policy")
    ps.set_defaults(func=cmd_policy_suggest)
    pt = pol.add_parser("template", help="print or write a policy template")
    pt.add_argument("kind", nargs="?", help="template name (omit to list)")
    pt.add_argument("--output")
    pt.add_argument("--force", action="store_true")
    pt.set_defaults(func=cmd_policy_template)
    pd = pol.add_parser("diff", help="semantic diff of two policies, flagging relaxations")
    pd.add_argument("old")
    pd.add_argument("new")
    pd.add_argument("--format", choices=["text", "json"], default="text")
    pd.add_argument("--fail-on-relaxation", action="store_true")
    pd.set_defaults(func=cmd_policy_diff)
    psim = pol.add_parser(
        "simulate", help="evaluate example queries; optionally against a candidate"
    )
    psim.add_argument("--policy", required=True)
    psim.add_argument("--cases", required=True, help="YAML list of {sql, role, context, expect}")
    psim.add_argument("--against", help="candidate policy to compare with")
    psim.add_argument("--format", choices=["text", "json"], default="text")
    psim.add_argument("--fail-on-change", action="store_true")
    psim.set_defaults(func=cmd_policy_simulate)
    pe = pol.add_parser("explain", help="explain a decision or a column's effective access")
    pe.add_argument("--policy", required=True)
    pe.add_argument("--role", required=True)
    pe.add_argument("--sql")
    pe.add_argument("--column", help="TABLE.COLUMN")
    pe.add_argument("--dialect")
    pe.add_argument("--tenant")
    pe.set_defaults(func=cmd_policy_explain)

    bench = sub.add_parser("benchmark", help="run and compare benchmarks").add_subparsers(
        dest="bench_cmd", required=True
    )
    br = bench.add_parser("run", help="evaluate a dataset with an adapter")
    common(br)
    br.add_argument("--dataset")
    br.add_argument("--adapter", help="native | external:<tool> | callable:<module>:<function>")
    br.add_argument("--python", help="interpreter for an external adapter's venv")
    br.add_argument("--dialect")
    br.add_argument("--category")
    br.add_argument("--output")
    br.add_argument("--report")
    br.add_argument("--csv", help="also write per-case results as CSV")
    br.add_argument("--summary", action="store_true", help="append to GITHUB_STEP_SUMMARY")
    br.set_defaults(func=cmd_benchmark_run)

    bc = bench.add_parser("compare", help="compare a result with an approved baseline")
    common(bc)
    bc.add_argument("--baseline")
    bc.add_argument("--candidate")
    bc.add_argument("--report")
    bc.add_argument("--json")
    bc.add_argument("--summary", action="store_true")
    bc.add_argument("--max-security-regressions", type=int)
    bc.add_argument("--max-usability-regressions", type=int)
    bc.add_argument("--min-recall", type=float)
    bc.add_argument("--max-false-positive-rate", type=float)
    bc.add_argument("--max-p95-latency-increase-pct", type=float)
    bc.add_argument("--allow-benchmark-change", action="store_true")
    bc.add_argument("--allow-label-changes", action="store_true")
    bc.add_argument("--approved-label-changes", help="LABEL_CHANGES.yaml listing reviewed relabels")
    bc.set_defaults(func=cmd_benchmark_compare)

    bb = bench.add_parser("baseline", help="accept a reviewed result as the new baseline")
    common(bb)
    bb.add_argument("--candidate")
    bb.add_argument("--output")
    bb.add_argument("--i-understand-this-is-ci", action="store_true", help=argparse.SUPPRESS)
    bb.set_defaults(func=cmd_benchmark_baseline)

    mcp = sub.add_parser("mcp", help="run the MCP server (stdio) for a fixed role and tenant")
    mcp.add_argument("--policy", required=True, help="policy file or builtin:<name>")
    mcp.add_argument("--role", required=True, help="trusted role for every request")
    mcp.add_argument("--tenant", help="trusted tenant for every request")
    mcp.add_argument("--dialect")
    mcp.set_defaults(func=cmd_mcp)

    rep = sub.add_parser("report", help="reports").add_subparsers(dest="report_cmd", required=True)
    rg = rep.add_parser("generate", help="render a Markdown report from a result JSON")
    rg.add_argument("--result", required=True)
    rg.add_argument("--output")
    rg.set_defaults(func=cmd_report_generate)

    ds = sub.add_parser("dataset", help="dataset utilities").add_subparsers(
        dest="dataset_cmd", required=True
    )
    dst = ds.add_parser("stats", help="validate a dataset and print statistics")
    common(dst)
    dst.add_argument("--dataset")
    dst.set_defaults(func=cmd_dataset_stats)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        code: int = args.func(args)
    except CLIError as exc:
        _err(f"error: {exc}")
        return EXIT_USAGE
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
