"""CI smoke check for the observability stack: Prometheus scraped the synthetic metrics
and Grafana provisioned the dashboard with a working Prometheus datasource."""

import json
import sys
import time
import urllib.parse
import urllib.request


def get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.load(r)


def main() -> int:
    q = urllib.parse.quote("sum(sqlguard_decisions_total)")
    for _ in range(40):
        data = get(f"http://127.0.0.1:9090/api/v1/query?query={q}")["data"]["result"]
        if data and float(data[0]["value"][1]) > 0:
            break
        time.sleep(3)
    else:
        print("Prometheus has no sqlguard_decisions_total samples")
        return 1
    dash = get("http://127.0.0.1:3000/api/dashboards/uid/sqlguard-ninja")["dashboard"]
    exprs = [t["expr"] for p in dash["panels"] for t in p["targets"]]
    ds = urllib.parse.quote(
        exprs[0].replace("$__rate_interval", "1m").replace('{policy=~"$policy"}', "")
    )
    proxied = get(
        f"http://127.0.0.1:3000/api/datasources/proxy/uid/prometheus/api/v1/query?query={ds}"
    )
    print(
        f"decisions={data[0]['value'][1]} panels={len(dash['panels'])}",
        f"grafana_query={proxied['status']}",
    )
    return 0 if proxied["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
