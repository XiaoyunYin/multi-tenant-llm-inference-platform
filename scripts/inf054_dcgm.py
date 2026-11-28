"""Require stable per-node DCGM scrapes before each timed GPU release."""

import json
import math
import re
import time
from collections import Counter
from datetime import datetime

from inf054_eks_workload import SAMPLE_ERRORS

from inference_platform.credential_redaction import redact_values

WAIT_S = 120
LATER_WAIT_S = 45
DIAGNOSTICS_S = 60
RESERVE_S = WAIT_S + 8 * LATER_WAIT_S + DIAGNOSTICS_S
POLL_S = 5
MIN_UPTIME_S = 30
CADVISOR_S = 12
RECEIPT_BYTES = 128 * 1024
SELECTOR = "app=dcgm-exporter"
SERVICE = "kubernetes.io/service-name=dcgm-exporter"
FIELDS = ("DCGM_FI_DEV_GPU_UTIL", "DCGM_FI_DEV_FB_USED")
MEMORY = (
    "container_memory_max_usage_bytes",
    "container_memory_working_set_bytes",
    "container_oom_events_total",
)


def series_expression(field):
    metric = f'{field}{{job="dcgm"}}'
    # Query the underlying scrape timestamp as a value, not the evaluation time.
    return (
        f"label_replace(timestamp({metric}) and "
        f"(time() - timestamp({metric}) < 5) and (abs({metric}) < +Inf), "
        f'"gate_field", "{field}", "job", "dcgm")'
    )


FRESH = " or ".join(series_expression(field) for field in FIELDS)


def epoch(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def exporter(pod):
    return next(
        (
            row
            for row in (pod.get("status") or {}).get("containerStatuses") or []
            if row.get("name") == "dcgm-exporter"
        ),
        {},
    )


def node_map(pods):
    return {
        node: pod
        for pod in pods
        if (node := (pod.get("spec") or {}).get("nodeName")) is not None
        and not (pod.get("metadata") or {}).get("deletionTimestamp")
    }


def poll_witness(slices, series, nodes, pods, now):
    samples = {}
    for row in series:
        labels = row["metric"]
        field = labels.get("gate_field")
        stamp = float(row["value"][1])
        if field in FIELDS and math.isfinite(stamp):
            samples.setdefault(labels["instance"], {})[field] = stamp
    assigned = node_map(pods)
    entries = {}
    trail = []
    for index, node in enumerate(sorted(nodes), 1):
        pod = assigned.get(node, {})
        name = (pod.get("metadata") or {}).get("name")
        status = exporter(pod)
        running = (status.get("state") or {}).get("running") or {}
        began = running.get("startedAt")
        uptime = now - epoch(began) if began else None
        candidates = {
            f"{address}:9400"
            for group in slices
            for ep in group.get("endpoints") or []
            if ep.get("nodeName") == node
            and (ep.get("conditions") or {}).get("ready") is True
            and name is not None
            and (ep.get("targetRef") or {}).get("name") == name
            for address in ep.get("addresses") or []
        }
        endpoint = next(iter(candidates)) if len(candidates) == 1 else None
        stamps = samples.get(endpoint, {})
        restarts = status.get("restartCount")
        trail.append(
            {
                "node": f"node-{index}",
                "endpoint_ready": endpoint is not None,
                "restart_count": restarts,
                "uptime_s": None if uptime is None else round(uptime, 3),
                "scrape_stamps": stamps,
            }
        )
        if (
            endpoint is not None
            and set(stamps) == set(FIELDS)
            and restarts == 0
            and uptime is not None
            and uptime >= MIN_UPTIME_S
        ):
            entries[node] = (
                endpoint,
                (pod.get("metadata") or {}).get("uid"),
                began,
                stamps,
            )
    return entries, trail


def advances(first, second):
    return first.keys() == second.keys() and all(
        first[node][:3] == state[:3]
        and all(state[3][field] > first[node][3][field] for field in FIELDS)
        for node, state in second.items()
    )


def diagnostic_text(value, credential):
    text = redact_values(value, secrets=(credential,))
    patterns = (
        r"\b\d{12}\b",
        r"\b(?:i|vol|eni|subnet|vpc|sg)-[0-9a-f]+\b",
        r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b",
        r"\b(?:ip|ec2)-(?:\d+-){3}\d+(?:\.[\w.-]+)?\b",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"(?i)(?:X-Amz-|x-aws-)[\w-]+=[^&\s]+",
    )
    for pattern in patterns:
        text = re.sub(pattern, "[REDACTED]", text)
    return text


def safe(window, value):
    return diagnostic_text(value, getattr(window.cluster, "credential", ""))


def exported_metrics(body, name):
    metrics = {}
    for line in body.splitlines():
        metric, sep, rest = line.partition("{")
        if not sep or metric not in MEMORY:
            continue
        tags, sep, value = rest.rpartition("}")
        if not sep or not re.search(r'(?:^|,)container="dcgm-exporter"(?:,|$)', tags):
            continue
        if not re.search(r'(?:^|,)pod="' + re.escape(name) + r'"(?:,|$)', tags):
            continue
        number = float(value.split()[0])
        if math.isfinite(number) and number > 0:
            metrics[metric] = max(number, metrics.get(metric, 0))
    return {metric: metrics.get(metric) for metric in MEMORY}


def status_rows(window, end, role):
    nodes = window.get(end, "nodes", "-l", f"m5-role={role}").get("items") or []
    pods = window.get(end, "pods", "-l", SELECTOR).get("items") or []
    return nodes, pods


def cadvisor(window, end, nodes, pods, *, check_access=False):
    assigned = node_map(pods)
    result = {"nodes": []}
    if check_access:
        try:
            result["node_proxy_allowed"] = (
                window.k(
                    min(end, time.monotonic() + POLL_S),
                    "auth",
                    "can-i",
                    "get",
                    "nodes",
                    "--subresource=proxy",
                ).strip()
                == "yes"
            )
        except SAMPLE_ERRORS as error:
            result["node_proxy_error"] = type(error).__name__
    for index, item in enumerate(
        sorted(nodes, key=lambda n: n["metadata"]["name"])[:4], 1
    ):
        name = item["metadata"]["name"]
        pod = assigned.get(name, {})
        pod_name = (pod.get("metadata") or {}).get("name")
        container = next(
            (
                c
                for c in (pod.get("spec") or {}).get("containers") or []
                if c.get("name") == "dcgm-exporter"
            ),
            {},
        )
        row = {
            "node": f"node-{index}",
            "pod": safe(window, pod_name)[:128] if pod_name else None,
            "restart_count": exporter(pod).get("restartCount"),
            "memory_limit": (
                (container.get("resources") or {}).get("limits") or {}
            ).get("memory"),
        }
        if pod_name:
            try:
                metrics = window.k(
                    min(end, time.monotonic() + POLL_S),
                    "get",
                    "--raw",
                    f"/api/v1/nodes/{name}/proxy/metrics/cadvisor",
                )
                row.update(exported_metrics(metrics, pod_name))
            except SAMPLE_ERRORS as error:
                row["read_error"] = type(error).__name__
        else:
            row["read_error"] = "ExporterPodMissing"
        result["nodes"].append(row)
    return result


def capture_memory(window, end, role):
    try:
        nodes, pods = status_rows(window, min(end, time.monotonic() + POLL_S), role)
        return cadvisor(window, end, nodes, pods)
    except SAMPLE_ERRORS as error:
        return {"read_error": type(error).__name__, "nodes": []}


def snapshot(window, end, nodes, pods):
    def read(*args, log=False):
        try:
            value = window.k(min(end, time.monotonic() + POLL_S), *args)
        except SAMPLE_ERRORS as error:
            return {"error": type(error).__name__}
        content = safe(window, value).encode()
        if log:
            return {
                "head": content[:4096].decode(errors="ignore"),
                "tail": content[-4096:].decode(errors="ignore"),
            }
        return {"tail": content[-4096:].decode(errors="ignore")}

    result = {"nodes": [], "pods": [], "memory": cadvisor(window, end, nodes, pods)}
    for index, node in enumerate(
        sorted(nodes, key=lambda n: n["metadata"]["name"])[:4], 1
    ):
        status = node.get("status") or {}
        result["nodes"].append(
            {
                "node": f"node-{index}",
                "capacity": status.get("capacity"),
                "allocatable": status.get("allocatable"),
                "memory_pressure": next(
                    (
                        c.get("status")
                        for c in status.get("conditions") or []
                        if c.get("type") == "MemoryPressure"
                    ),
                    None,
                ),
                "node_info": {
                    key: (status.get("nodeInfo") or {}).get(key)
                    for key in (
                        "kernelVersion",
                        "containerRuntimeVersion",
                        "kubeletVersion",
                    )
                },
            }
        )
    try:
        result["targets"] = [
            {
                key: safe(window, str(target.get(key) or ""))[:512]
                for key in ("health", "lastError", "lastScrape")
            }
            for target in window.targets(min(end, time.monotonic() + POLL_S))
            if (target.get("labels") or {}).get("job") == "dcgm"
        ][:8]
    except SAMPLE_ERRORS as error:
        result["target_read_error"] = type(error).__name__
    for pod in pods[:2]:
        name = pod["metadata"]["name"]
        state = exporter(pod)
        compact = {
            key: {
                label: safe(window, fields[label])[:512]
                for label in ("reason", "message", "startedAt", "finishedAt")
                if fields.get(label)
            }
            | {
                label: fields[label]
                for label in ("exitCode", "signal")
                if label in fields
            }
            for side in ("state", "lastState")
            for key, fields in (state.get(side) or {}).items()
        }
        result["pods"].append(
            {
                "pod": safe(window, name),
                "phase": (pod.get("status") or {}).get("phase"),
                "restart_count": state.get("restartCount"),
                "states": compact,
                "describe": read("describe", "pod", name),
                "current_log": read("logs", name, "--tail=-1", log=True),
                "previous_log": read("logs", name, "--previous", "--tail=-1", log=True),
            }
        )
    result.update(
        describe=read("describe", "daemonset", "dcgm-exporter"),
        events=read("get", "events", "--sort-by=.lastTimestamp"),
        service=read("get", "service", "dcgm-exporter", "-o", "json"),
        endpoints=read("get", "endpointslices", "-l", SERVICE, "-o", "json"),
    )
    return result


def write_receipt(receipt, value):
    raw = (
        json.dumps(
            value, allow_nan=False, ensure_ascii=False, separators=(",", ":")
        ).encode()
        + b"\n"
    )
    if len(raw) > RECEIPT_BYTES:
        value["snapshot"] = {"error": "DiagnosticSizeLimit"}
        raw = json.dumps(value, allow_nan=False, separators=(",", ":")).encode() + b"\n"
    if len(raw) > RECEIPT_BYTES:
        raise ValueError("inf054_dcgm_receipt_limit")
    receipt.write_bytes(raw)


def require_dcgm(window, receipt, *, node_role="gpu", count=2, wait_s=WAIT_S):
    started = time.monotonic()
    cutoff = started + wait_s
    errors = Counter()
    previous = {}
    nodes, pods = [], []
    polls = []
    ready = False
    while time.monotonic() < cutoff:
        end = min(cutoff, time.monotonic() + POLL_S)
        poll = {"at_s": round(time.monotonic() - started, 3)}
        polls.append(poll)
        try:
            nodes, pods = status_rows(window, end, node_role)
            slices = window.get(end, "endpointslices", "-l", SERVICE).get("items") or []
            current, poll["nodes"] = poll_witness(
                slices,
                window.query(end, FRESH),
                {row["metadata"]["name"] for row in nodes},
                pods,
                time.time(),
            )
        except SAMPLE_ERRORS as error:
            poll["error"] = type(error).__name__
            errors[poll["error"]] += 1
            previous = {}
        else:
            ready = len(nodes) == len(previous) == len(current) == count and advances(
                previous, current
            )
            if ready:
                break
            previous = current
        time.sleep(max(0, end - time.monotonic()))
    value = {
        "expected_nodes": count,
        "ready": ready,
        "elapsed_s": time.monotonic() - started,
        "wait_bound_s": wait_s,
        "diagnostic_bound_s": DIAGNOSTICS_S if not ready else 0,
        "poll_errors": dict(errors),
        "polls": polls,
    }
    if ready:
        value["at_gate"] = cadvisor(window, cutoff, nodes, pods, check_access=True)
    else:
        value["snapshot"] = snapshot(window, cutoff + DIAGNOSTICS_S, nodes, pods)
    write_receipt(receipt, value)
    if not ready:
        raise ValueError("inf054_dcgm_not_ready")
    return value
