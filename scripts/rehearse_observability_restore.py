"""Restore a synthetic scrape into Prometheus and query the provisioned dashboard."""

import argparse
import json
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml
from prometheus_snapshot import restore, snapshot

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy/observability"
NETWORK = "inf064-restore"
NAMES = ("inf064-fixture", "inf064-source", "inf064-prometheus", "inf064-grafana")
FIXTURE = r"""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Metrics(BaseHTTPRequestHandler):
    n = 0
    def do_GET(self):
        Metrics.n += 1
        count = Metrics.n
        body = f'''inference_gateway_backend_metrics_fresh{{backend_id="engine"}} 1
inference_gateway_backend_requests_running{{backend_id="engine"}} 12
inference_gateway_backend_requests_waiting{{backend_id="engine"}} 2
inference_gateway_backend_kv_cache_usage_ratio{{backend_id="engine"}} 0.55
inference_gateway_terminal_total{{cause="completed"}} {count}
inference_gateway_requests_by_tenant_total{{tenant="a"}} {count * 2}
inference_gateway_admission_by_tenant_total{{tenant="a",outcome="allowed"}} {count}
inference_gateway_rejections_by_tenant_total{{tenant="a",code="tenant_concurrency_limit"}} {count}
DCGM_FI_DEV_GPU_UTIL 72
DCGM_FI_DEV_FB_USED 12098
keda_scaler_metrics_value 2
keda_scaler_active 1
'''.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

HTTPServer(("0.0.0.0", 8000), Metrics).serve_forever()
"""


def docker(*args, check=True, env=None):
    return subprocess.run(
        ["docker", *map(str, args)],
        text=True,
        capture_output=True,
        check=check,
        timeout=240,
        env=env,
    )


def api(base, path, body=None):
    request = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    with urllib.request.urlopen(request, timeout=6) as response:
        return json.load(response)


def wait(check, code):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except OSError:
            pass
        time.sleep(0.5)
    raise TimeoutError(code)


def origin(container, port):
    address = docker("port", container, f"{port}/tcp").stdout.strip()
    if not address.startswith("127.0.0.1:") or "\n" in address:
        raise ValueError("fixture API must publish only loopback")
    return "http://" + address


def run(work):
    work = work.resolve()
    work.mkdir()
    compose = yaml.safe_load((DEPLOY / "compose.yaml").read_text())
    prometheus = compose["services"]["prometheus"]["image"]
    grafana = compose["services"]["grafana"]["image"]
    python_image = json.loads((ROOT / "deploy/package-a/pins.json").read_bytes())[
        "python_image"
    ]
    source = work / "source-tsdb"
    source.mkdir()
    source_cfg = work / "scrape.json"
    source_cfg.write_text(
        json.dumps(
            {
                "global": {"scrape_interval": "500ms", "scrape_timeout": "400ms"},
                "scrape_configs": [
                    {
                        "job_name": "fixture",
                        "static_configs": [{"targets": ["inf064-fixture:8000"]}],
                    }
                ],
            }
        )
    )
    target_cfg = work / "empty-scrape.json"
    target_cfg.write_text('{"scrape_configs": []}')
    docker("network", "create", NETWORK)
    created = []

    def launch(name, *args):
        docker("run", "--detach", "--name", name, "--network", NETWORK, *args)
        created.append(name)

    try:
        launch(NAMES[0], python_image, "python", "-c", FIXTURE)
        launch(
            NAMES[1],
            "--user",
            "0:0",
            "-p",
            "127.0.0.1::9090",
            "-v",
            f"{source_cfg}:/etc/prometheus/prometheus.yml:ro",
            "-v",
            f"{source}:/prometheus",
            prometheus,
            "--config.file=/etc/prometheus/prometheus.yml",
            "--storage.tsdb.path=/prometheus",
            "--web.enable-admin-api",
        )
        source_url = origin(NAMES[1], 9090)
        sample_query = "/api/v1/query?" + urllib.parse.urlencode(
            {"query": "count_over_time(inference_gateway_terminal_total[10s]) > 5"}
        )
        wait(
            lambda: api(source_url, sample_query)["data"]["result"], "synthetic_scrapes"
        )
        evaluation_ms = int(time.time() * 1000)
        archive = work / "tsdb.tar.gz"
        exported = snapshot(source_url, source, archive)
        docker("rm", "-f", NAMES[1])
        created.remove(NAMES[1])
        restored = work / "restored-tsdb"
        verified = restore(archive, exported["sha256"], restored)
        launch(
            NAMES[2],
            "--network-alias",
            "prometheus",
            "-p",
            "127.0.0.1::9090",
            "--user",
            "0:0",
            "-v",
            f"{target_cfg}:/etc/prometheus/prometheus.yml:ro",
            "-v",
            f"{restored}:/prometheus",
            prometheus,
            "--config.file=/etc/prometheus/prometheus.yml",
            "--storage.tsdb.path=/prometheus",
        )
        launch(
            NAMES[3],
            "-p",
            "127.0.0.1::3000",
            "-e",
            "GF_AUTH_ANONYMOUS_ENABLED=true",
            "-e",
            "GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer",
            "-v",
            f"{DEPLOY / 'grafana/provisioning'}:/etc/grafana/provisioning:ro",
            "-v",
            f"{DEPLOY / 'grafana/dashboards'}:/var/lib/grafana/dashboards:ro",
            grafana,
        )
        grafana_url = origin(NAMES[3], 3000)
        local_json = json.loads(
            (DEPLOY / "grafana/dashboards/inference-platform.json").read_bytes()
        )
        loaded = wait(
            lambda: api(grafana_url, "/api/dashboards/uid/" + local_json["uid"]),
            "dashboard_provision",
        )
        counts = []
        for panel in loaded["dashboard"]["panels"]:
            for target in panel.get("targets", []):
                ref = target["refId"]
                expr = target["expr"].replace("$__rate_interval", "60s")
                result = api(
                    grafana_url,
                    "/api/ds/query",
                    {
                        "from": str(evaluation_ms - 60_000),
                        "to": str(evaluation_ms),
                        "queries": [
                            {
                                "refId": ref,
                                "expr": expr,
                                "datasource": {
                                    "type": "prometheus",
                                    "uid": "prometheus",
                                },
                                "instant": True,
                                "range": False,
                                "intervalMs": 500,
                                "maxDataPoints": 120,
                            }
                        ],
                    },
                )["results"][ref]
                count = sum(
                    bool(frame["data"]["values"] and frame["data"]["values"][0])
                    for frame in result.get("frames", [])
                )
                if result.get("error") or count == 0:
                    raise ValueError(f"empty restored query: {panel['title']} / {ref}")
                counts.append({"panel": panel["title"], "target": ref, "series": count})
        if not counts:
            raise ValueError("dashboard has no requests to validate")
    finally:
        for container in reversed(created):
            docker("rm", "-f", container, check=False)
        docker("network", "rm", NETWORK)
    result = {
        "scope": "synthetic scrape, actual Prometheus snapshot and Grafana datasource",
        "export": exported,
        "restore": verified,
        "queries": counts,
    }
    (work / "restore-receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    run(parser.parse_args().work)
