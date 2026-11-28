"""Observe Terraform Apply while the native controller owns its deadline."""

import os
import json
import re
import signal
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone

import inf060_diagnostics as diagnostics
from l4_compat_deadline import fenced_stop


CAPACITY = b"InsufficientInstanceCapacity"
READ_BYTES = 64 * 1024
ZONE = re.compile(r"us-east-1[a-f]\Z")
SUGGESTIONS = re.compile(r"\b(?:or choosing|or choose)\s+([\s\S]+)", re.IGNORECASE)
ZONE_LIST = re.compile(
    r"us-east-1[a-f](?:(?:\s*,\s*(?:or\s+)?|\s+or\s+)us-east-1[a-f])*"
)
CREATE_EVENTS = (
    "RunInstances",
    "CreateVpc",
    "CreateSubnet",
    "CreateInternetGateway",
    "CreateSecurityGroup",
    "CreateRouteTable",
    "CreateRole",
    "CreateInstanceProfile",
)
AWS_CODE = re.compile(r"[A-Za-z][A-Za-z0-9.]{0,95}\Z")


def capacity_zones(raw):
    text = re.sub(r"\x1b\[[0-9;]*m|│", "", raw.decode(errors="replace"))
    match = SUGGESTIONS.search(text)
    choices = ZONE_LIST.match(match[1]) if match else None
    return (
        list(dict.fromkeys(re.findall(r"us-east-1[a-f]", choices[0])))
        if choices
        else []
    )


def cloudtrail_create_readback(invoke, role_name, start, end):
    """Count only create calls issued by this packet's unique operator role."""
    start_at = datetime.fromtimestamp(start, timezone.utc).isoformat()
    end_at = datetime.fromtimestamp(end, timezone.utc).isoformat()
    summary = {}
    for name in CREATE_EVENTS:
        try:
            page = invoke(
                "cloudtrail",
                "lookup-events",
                [
                    "--lookup-attributes",
                    f"AttributeKey=EventName,AttributeValue={name}",
                    "--start-time",
                    start_at,
                    "--end-time",
                    end_at,
                    "--max-results",
                    "50",
                    "--no-paginate",
                ],
            )
            outcomes = Counter()
            for row in page["Events"]:
                event = json.loads(row["CloudTrailEvent"])
                issuer = (
                    event.get("userIdentity", {})
                    .get("sessionContext", {})
                    .get("sessionIssuer", {})
                )
                if (
                    issuer.get("userName") != role_name
                    or event.get("eventName") != name
                ):
                    continue
                code = event.get("errorCode")
                if code is None:
                    outcomes["no_error_recorded"] += 1
                elif AWS_CODE.fullmatch(code or ""):
                    outcomes[code] += 1
                else:
                    outcomes["other_error"] += 1
            summary[name] = {
                "status": "partial" if page.get("NextToken") else "checked",
                "outcomes": dict(outcomes),
            }
        except (
            OSError,
            KeyError,
            ValueError,
            TypeError,
            subprocess.SubprocessError,
        ) as error:
            summary[name] = {
                "status": "unavailable",
                "error_type": type(error).__name__,
            }
    return {"start_utc": start_at, "end_utc": end_at, "events": summary}


def run(argv, *, cwd, output, timeout, env, zone):
    """Stream both file descriptors and shut down Terraform before cleanup."""
    started = time.monotonic()
    end = started + timeout
    status = {
        "requested_zone": zone,
        "suggested_zones": [],
        "reason": "apply_start_failed",
    }
    child = None
    argv = [str(arg) for arg in argv]
    try:
        with output.open("xb") as stream, output.open("rb") as reader:
            child = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=os.name != "nt",
            )
            recent = b""
            while True:
                block = reader.read(READ_BYTES)
                recent = (recent + block)[-READ_BYTES:]
                if CAPACITY in recent:
                    status.update(
                        reason="gpu_capacity_unavailable",
                        suggested_zones=capacity_zones(recent),
                    )
                    if os.name != "nt" and child.poll() is None:
                        # One interrupt lets Terraform flush partial resource state.
                        child.send_signal(signal.SIGINT)
                        try:
                            child.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            pass
                    tail = recent + reader.read(READ_BYTES)
                    status["suggested_zones"] = capacity_zones(tail)
                    raise ValueError("inf060:gpu_capacity_unavailable")
                if not block and (code := child.poll()) is not None:
                    if last := reader.read(READ_BYTES):
                        reader.seek(-len(last), os.SEEK_CUR)
                        continue
                    status["reason"] = "apply_complete" if code == 0 else "apply_error"
                    if code:
                        raise RuntimeError(f"check_exit:{output.name}:{code}")
                    break
                if time.monotonic() >= end:
                    status["reason"] = "apply_timeout"
                    raise subprocess.TimeoutExpired(argv, timeout)
                if len(block) < READ_BYTES:
                    time.sleep(min(0.05, max(0, end - time.monotonic())))
    finally:
        if child is not None:
            fenced_stop(child)
        record = {
            **status,
            "exit_code": child.returncode if child else None,
            "elapsed_s": time.monotonic() - started,
        }
        diagnostics.write(output.with_suffix(".status.json"), record)
    return record
