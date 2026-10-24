"""Generate synthetic validation traffic and expose Prometheus metrics.

Replays the bundled benchmark corpus (synthetic schema, synthetic values) through an
instrumented :class:`SQLCheckpoint`. Nothing is executed and no database is used.

    pip install "sqlguard-ninja[prometheus]"
    python examples/observability/synthetic_traffic.py --port 9464     # serve forever
    python examples/observability/synthetic_traffic.py --iterations 200 --print
"""

from __future__ import annotations

import argparse
import random
import time
import uuid

from sqlguard_ninja import Guard, Policy
from sqlguard_ninja.benchmarking.builtin import benchmarks_root
from sqlguard_ninja.benchmarking.dataset import load_dataset
from sqlguard_ninja.integrations import RequestContext, SQLCheckpoint
from sqlguard_ninja.observability import GuardMetrics, Telemetry

DATA = benchmarks_root()


def build(metrics: GuardMetrics) -> tuple[SQLCheckpoint, list]:
    policy = Policy.from_file(str(DATA / "policies" / "retail_saas.yaml"))
    cases = [
        c for c in load_dataset(str(DATA / "datasets" / "v1")).cases if c.dialect == "postgres"
    ]
    checkpoint = SQLCheckpoint(
        Guard(policy), mode="block", telemetry=Telemetry(metrics=metrics), max_denied_attempts=None
    )
    return checkpoint, cases


def step(checkpoint: SQLCheckpoint, cases: list, rng: random.Random) -> None:
    case = rng.choice(cases)
    ctx = RequestContext(
        principal=f"synthetic-{rng.randrange(20)}",
        role=case.role,
        tenant_id=case.context.get("tenant_id"),
        trace_id=uuid.uuid4().hex,
    )
    checkpoint.evaluate(case.sql, ctx)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9464)
    ap.add_argument("--rate", type=float, default=20.0, help="validations per second")
    ap.add_argument("--iterations", type=int, default=0, help="stop after N (0 = forever)")
    ap.add_argument("--seed", type=int, default=20261024)
    ap.add_argument("--print", action="store_true", help="print the exposition and exit")
    args = ap.parse_args()

    metrics = GuardMetrics()
    checkpoint, cases = build(metrics)
    rng = random.Random(args.seed)
    if args.print:
        for _ in range(args.iterations or 100):
            step(checkpoint, cases, rng)
        print(metrics.render()[0].decode())
        return

    from prometheus_client import start_http_server

    start_http_server(args.port, addr=args.host, registry=metrics.registry)
    print(f"serving metrics on http://{args.host}:{args.port}/metrics", flush=True)
    n = 0
    while args.iterations == 0 or n < args.iterations:
        step(checkpoint, cases, rng)
        n += 1
        time.sleep(1 / args.rate)


if __name__ == "__main__":
    main()
