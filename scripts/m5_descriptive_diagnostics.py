"""Repo-free failure collection and final cost receipts, including refusals."""

import hashlib
import inspect
import json
import math
import time
from pathlib import Path


from inference_platform.credential_redaction import redact_values

COLLECTOR = (
    "import os, re\n"
    + inspect.getsource(redact_values)
    + r"""
import hashlib, json, shutil, subprocess, time
from pathlib import Path

def capture(root, token):
    stop = time.monotonic() + 30
    partial = root / 'source.bundle'
    result = {'schema': 'm5-prebootstrap-diagnostics-v1', 'complete': True}
    if partial.exists():
        before = partial.stat()
        h, read = hashlib.sha256(), 0
        with partial.open('rb') as stream:
            while time.monotonic() < stop:
                data = stream.read(1024**2)
                if not data: break
                h.update(data); read += len(data)
        after = partial.stat()
        result['partial_upload'] = {'bytes': after.st_size, 'hashed_bytes': read,
            'sha256': h.hexdigest(), 'hash_complete': read == after.st_size,
            'stable': (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)}
    else:
        result['partial_upload'] = {'bytes': 0, 'exists': False}
    result['tails'] = {}
    logs = [str(root / 'results/runner/descriptive' / (phase + '.log'))
            for phase in ('provision', 'export')]
    logs += ['/var/log/cloud-init-output.log', '/var/log/amazon/ssm/amazon-ssm-agent.log', str(root / 'bootstrap.log')]
    for name in logs:
        try:
            with open(name, 'rb') as log:
                log.seek(0, 2); size = log.tell(); log.seek(max(0, size - 2000))
                text = log.read(2000).decode('utf-8', errors='replace')
            text = redact_values(text, secrets=(token,))
            result['tails'][name] = text
        except OSError as error:
            result['tails'][name] = {'error': type(error).__name__}
    try:
        state = subprocess.run(['systemctl', 'show', 'dec077-terminate.timer',
            '--property=LoadState,ActiveState,NextElapseUSecRealtime'], capture_output=True, timeout=5)
        result['timer'] = {'exit_code': state.returncode, 'stdout': state.stdout.decode(errors='replace')[:2000]}
    except (OSError, subprocess.TimeoutExpired) as error:
        result['timer'] = {'error': type(error).__name__}
    result['disk'] = dict(zip(('total', 'used', 'free'), shutil.disk_usage(root)))
    result['memory'] = {line.split(':')[0]: line.split(':')[1].strip()
        for line in Path('/proc/meminfo').read_text().splitlines()
        if line.split(':')[0] in {'MemTotal', 'MemAvailable', 'MemFree'}}
    # Even replacement characters in a binary log must fit one SSM response.
    while len(json.dumps(result).encode()) > 18000:
        for name, text in result['tails'].items():
            if isinstance(text, str): result['tails'][name] = text[len(text)//2:]
    return result
"""
)


def collect(host, directory, end, *, root="/opt/dec077"):
    """Always preserve a receipt; collection failure must never delay teardown."""
    started = time.time()
    try:
        if host is None:
            raise ValueError("descriptive:diagnostics_host_unavailable")
        seconds = min(60, int(end - time.time()))
        if seconds < 1:
            raise TimeoutError("descriptive:diagnostics_export_deadline")
        # Upload has its own narrower deadline, which may already be expired.
        # Enter the export bracket without extending the original session end.
        host.deadline = min(end, time.time() + seconds)
        script = (
            "python3 - <<'DEC100_DIAGNOSTICS'\n"
            + COLLECTOR
            + "\nprint('PREBOOTSTRAP_DIAGNOSTICS=' + json.dumps(capture(Path("
            + repr(root)
            + "), "
            + repr(host.token)
            + ")))\nDEC100_DIAGNOSTICS"
        )
        response = host.ssm(
            host.host,
            [script],
            timeout_s=seconds,
            step="descriptive.prebootstrap_diagnostics",
        )
        lines = [
            s.removeprefix("PREBOOTSTRAP_DIAGNOSTICS=")
            for s in response["StandardOutputContent"].splitlines()
            if s.startswith("PREBOOTSTRAP_DIAGNOSTICS=")
        ]
        if len(lines) != 1:
            raise ValueError("descriptive:diagnostics_truncated")
        result = json.loads(lines[0])
    except Exception as error:
        result = {"complete": False, "error": type(error).__name__ + ":" + str(error)}
    result["elapsed_s"] = time.time() - started
    path = Path(directory) / "prebootstrap-diagnostics.json"
    data = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(data)
    return {
        "kind": "repo-free-diagnostics",
        "files": {
            path.name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        },
    }


def write_cost(directory, *, now=None):
    """Same explicit forecast formula as the accepted Round 376 cost record."""
    directory = Path(directory)
    now = time.time() if now is None else now
    result = {
        "schema": "m5-descriptive-operator-cost-v1",
        "invoice": False,
        "finished_epoch": now,
    }
    try:
        manifest = json.loads((directory / "manifest.json").read_bytes())
        consumed = directory / "consumed.json"
        if not consumed.exists():
            result.update(
                consumed=False,
                elapsed_s=0,
                capacity_wait_elapsed_s=0,
                other_elapsed_s=0,
                task_cost_estimate_usd=0,
                basis="pre-consume refusal; no billable operator action",
            )
        else:
            started = json.loads(consumed.read_bytes())["started_epoch"]
            basis = manifest["forecast_basis"]
            elapsed = max(0, now - started)
            estimate = (
                math.ceil(
                    (elapsed / 3600 * basis["hourly_usd"] + basis["fixed_other_usd"])
                    * basis["margin"]
                    * 100
                )
                / 100
            )
            prior = manifest["host_manifest"]["prior_spend_usd"]
            wait_file = directory / "capacity-wait.json"
            waiting = (
                json.loads(wait_file.read_bytes())["elapsed_s"]
                if wait_file.exists()
                else 0
            )
            result.update(
                consumed=True,
                started_epoch=started,
                elapsed_s=elapsed,
                capacity_wait_elapsed_s=waiting,
                other_elapsed_s=max(0, elapsed - waiting),
                forecast_basis=basis,
                task_cost_estimate_usd=estimate,
                product_prior_estimate_usd=prior,
                cumulative_product_estimate_usd=prior + estimate,
                basis="Full-resource consume-to-exit duration plus sealed fixed allowance and margin, rounded up to cents; estimate, not invoice",
            )
    except Exception as error:
        result.update(complete=False, error=type(error).__name__)
    if directory.is_dir():
        (directory / "operator-cost.json").write_bytes(
            (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        )
    return result
