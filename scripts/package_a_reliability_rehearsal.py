"""Real loopback runner/reconnect and killed-operator recovery controls (no AWS)."""

import argparse
import importlib.util
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

from inference_platform import package_a_operator as operator
from inference_platform.package_a_cloud import (
    CPU_VALIDATION_CHECKS,
    TASK_CHECKS,
    Lifecycle,
    save,
    sha,
)
from inference_platform.package_a_secrets import control_token
from inference_platform.session_stop import stop_forward

sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_a_host import Host, server  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "55aab5c31347eb53a0769772787c380a47d93d1e"


def baseline_modules(output):
    modules = []
    for name, source in (
        (
            "inference_platform.dec077_old_operator",
            "python/src/inference_platform/package_a_operator.py",
        ),
        ("dec077_old_host", "scripts/package_a_host.py"),
    ):
        path = (
            output
            / "baseline/python/src/inference_platform"
            / (name.rsplit(".", 1)[-1] + ".py")
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            subprocess.check_output(["git", "show", BASELINE + ":" + source], cwd=ROOT)
        )
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    return modules


def fixture_manifest(directory):
    manifest = {
        "checks": list(
            CPU_VALIDATION_CHECKS
            if os.environ.get("PACKAGE_A_CPU_VALIDATION") == "1"
            else TASK_CHECKS
        ),
        "session_manager_plugin_path": "unused-fixture",
        "hourly_all_resources_usd": 0.4,
        "cleanup_cost_reserve_usd": 1,
    }
    save(directory / "manifest.json", manifest)
    return manifest


def fixture_host(directory, token, host_class, duration):
    host = host_class(
        directory / "host", token, sha(directory / "manifest.json"), time.time() + 120
    )
    (host.repo / "scripts").mkdir(parents=True)
    (host.root / "stage.json").write_text("{}")
    # Only the expensive bootstrap/work is fixture-bound. Host starts a real
    # process group; retries, status, cancellation, logs and archives are real.
    (host.repo / "scripts/package_a_bootstrap.sh").write_text(
        '#!/bin/sh\nset -eu\nmkdir -p "$2"\nprintf "started %s\\n" "$$" >> "$2/starts.log"\n'
        f'sleep {duration}\nprintf "finished\\n" > "$2/complete.log"\n'
    )
    http = server(host, port=0)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    return host, http, thread


def helper(helpers):
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(180)"], start_new_session=True
    )
    helpers.append(child)
    return child


def transport_case(directory, fault, ports_class=operator.Ports, host_class=Host):
    directory.mkdir(parents=True)
    manifest = fixture_manifest(directory)
    helpers, runner_pids = [], set()
    ports = ports_class(directory, manifest)
    host, http, thread = fixture_host(
        directory, ports.token, host_class, 35 if fault == "outage30" else 1
    )
    outage_end, phase, lost = [0], ["work"], [False]
    failures, starts = [0], []
    dispatch = host.dispatch

    def counted_dispatch(path, data, headers):
        result = dispatch(path, data, headers)
        if path == "/start" and host.child:
            runner_pids.add(host.child.pid)
        return result

    host.dispatch = counted_dispatch

    class FixturePorts(ports_class):
        def task_cost(self, start, now):
            legacy_cost = getattr(super(), "task_cost", None)
            return legacy_cost(start, now) if legacy_cost else super().cost(start, now)

        def cumulative_cost(self, start, now):
            legacy_total = getattr(super(), "cumulative_cost", None)
            if legacy_total:
                return legacy_total(start, now)
            return self.manifest.get("prior_spend_usd", 0) + self.task_cost(start, now)

        def tunnel(self, instance):
            if phase[0] == "work" and time.time() < outage_end[0]:
                failures[0] += 1
                raise ConnectionResetError("fixture sustained SSM establishment outage")
            return http.server_port, helper(helpers)

        def rpc(self, port, path, token, data=None, headers=None):
            if phase[0] == "work" and path == "/status" and time.time() < outage_end[0]:
                raise ConnectionResetError("fixture sustained status outage")
            result = super().rpc(port, path, token, data, headers)
            if path == "/start":
                starts.append(time.time())
                if fault == "lost_start" and not lost[0]:
                    lost[0] = True
                    raise ConnectionResetError("reply lost after real start committed")
                if fault in {"outage30", "until_end"}:
                    outage_end[0] = time.time() + 30
            return result

        def apply(self, end):
            self.started, self.host = time.time(), "fixture-no-EC2"

        def bootstrap(self, end):
            self.request("/status", end=end)

        def upload(self, end):
            self.request(
                "/manifest", (directory / "manifest.json").read_bytes(), end=end
            )

        def run_checks(self, end):
            return super().run_checks(
                min(end, time.time() + (3 if fault == "until_end" else 60))
            )

        def retrieve(self, end):
            phase[0] = "cleanup"
            return super().retrieve(end)

        def teardown(self, end):
            host.cancel()
            if self.child:
                stop_forward(self.child)
                self.child = None
            return {"destroy_completed": True}

        def inventory(self, end):
            return {
                "empty": all(child.poll() is not None for child in helpers)
                and host.child.poll() is not None
            }

    # Preserve the exact credential used by the real host, including old code's
    # per-constructor token. The crash test separately exercises fresh recovery.
    ports = FixturePorts(directory, manifest)
    host.token = ports.token
    started = time.time()
    try:
        result = Lifecycle(ports, manifest, directory / "final").run()
        valid = (
            result.get("retrieve", {}).get("complete") is True
            and result["inventory"]["empty"]
        )
        if fault == "until_end":
            valid = (
                valid
                and not result["complete"]
                and result.get("halt", "").startswith(
                    "TimeoutError:ssm_transport_absolute_deadline"
                )
                and time.time() - started >= 3
            )
        else:
            valid = (
                valid
                and result["complete"]
                and len(runner_pids) == 1
                and host.child.returncode == 0
            )
        if fault == "outage30":
            valid = valid and failures[0] >= 3 and time.time() - started >= 30
        return {
            "fault": fault,
            "oracle_passed": valid,
            "lifecycle": result,
            "runner_pids": sorted(runner_pids),
            "start_replies": len(starts),
            "failed_reconnects": failures[0],
            "reconnects": getattr(ports, "reconnects", 0),
            "elapsed_s": time.time() - started,
        }
    finally:
        host.cancel()
        for child in helpers:
            stop_forward(child)
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def worker(directory, port):
    """Actual operator process, killed by the parent after real /start."""
    manifest = json.loads((directory / "manifest.json").read_bytes())
    helpers = []

    class WorkerPorts(operator.Ports):
        def tunnel(self, instance):
            child = helper(helpers)
            save(directory / "worker-helper.json", {"pid": child.pid})
            return port, child

        def apply(self, end):
            self.host, self.started = "fixture-no-EC2", time.time()

        def bootstrap(self, end):
            self.request("/status", end=end)

        def upload(self, end):
            self.request(
                "/manifest", (directory / "manifest.json").read_bytes(), end=end
            )

        def run_checks(self, end):
            self.request("/start", b"", end=end)
            save(directory / "worker-started.json", {"pid": os.getpid()})
            time.sleep(120)

    ports = WorkerPorts(directory, manifest)
    save(directory / "operator.lock", {"pid": os.getpid()})
    Lifecycle(ports, manifest, directory / "final").run()


def recovery_case(directory, *, wrong=False, recovery_module=operator):
    directory.mkdir(parents=True)
    fixture_manifest(directory)
    token = control_token(directory, create=True)
    host, http, thread = fixture_host(directory, token, Host, 60)
    helpers = []
    child = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker",
            str(directory),
            "--port",
            str(http.server_port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    events = []
    try:
        end = time.time() + 20
        while (
            (
                not (directory / "worker-started.json").exists()
                or not (host.output / "starts.log").exists()
            )
            and time.time() < end
            and child.poll() is None
        ):
            time.sleep(0.05)
        if not (directory / "worker-started.json").exists():
            raise AssertionError("worker_failed_before_real_start")
        child.kill()
        child.wait(timeout=10)
        crashed = json.loads((directory / "final/lifecycle.json").read_bytes())
        if crashed["events"] != ["apply", "bootstrap", "upload", "run_checks"]:
            raise AssertionError("operator_did_not_crash_during_real_lifecycle_run")
        if wrong:
            (directory / "control-token.secret").write_text("0" * 64)

        recovery_receipt_roots = []

        class RecoveryPorts(recovery_module.Ports):
            def instance_ids(self):
                return ["fixture-no-EC2"]

            def tunnel(self, instance):
                return http.server_port, helper(helpers)

            def retrieve(self, end):
                events.append("retrieve")
                recovery_receipt_roots.append(self.runtime)
                return super().retrieve(end)

            def teardown(self, end):
                events.append("teardown")
                host.cancel()
                if self.child:
                    stop_forward(self.child)
                    self.child = None
                return {"destroy_completed": True}

            def inventory(self, end):
                events.append("inventory")
                return {
                    "empty": host.child.poll() is not None
                    and all(x.poll() is not None for x in helpers)
                }

        with (
            patch.object(recovery_module, "Ports", RecoveryPorts),
            patch.object(recovery_module, "executing_binding", lambda *args: None),
        ):
            result = recovery_module.recover(directory, "fixture")
        retrieved = result["retrieve"].get("complete") is True
        valid = (
            events == ["retrieve", "teardown", "inventory"]
            and result["inventory"]["empty"]
        )
        valid = valid and (
            ("403" in result["retrieve"].get("error", "") and not retrieved)
            if wrong
            else retrieved
            and sha(recovery_receipt_roots[-1] / "receipts.tar.gz")
            == result["retrieve"]["sha256"]
        )
        # The only persisted credential is the owner-only ignored secret file.
        for path in directory.rglob("*"):
            if (
                path.is_file()
                and path.name != "control-token.secret"
                and token.encode() in path.read_bytes()
            ):
                raise AssertionError("control_token_leaked_to_artifact")
        return {
            "wrong_token": wrong,
            "oracle_passed": valid,
            "operator_exit": child.returncode,
            "crashed_lifecycle_events": crashed["events"],
            "recovery": result,
            "events": events,
            "token_mode": oct(
                (directory / "control-token.secret").stat().st_mode & 0o777
            ),
        }
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        pid_file = directory / "worker-helper.json"
        if pid_file.exists():
            try:
                os.killpg(json.loads(pid_file.read_bytes())["pid"], signal.SIGTERM)
            except ProcessLookupError:
                pass
        for item in helpers:
            stop_forward(item)
        host.cancel()
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.port)
        return
    args.output.mkdir(parents=True, exist_ok=False)
    old_operator, old_host = baseline_modules(args.output)
    current, baseline = [], []
    for fault in ("lost_start", "outage30", "until_end"):
        current.append(transport_case(args.output / fault, fault))
        baseline.append(
            transport_case(
                args.output / (fault + "-55aab5c"),
                fault,
                old_operator.Ports,
                old_host.Host,
            )
        )
    recovery = [
        recovery_case(args.output / "recover"),
        recovery_case(args.output / "wrong-token", wrong=True),
    ]
    old_recovery = recovery_case(
        args.output / "recover-55aab5c", recovery_module=old_operator
    )
    result = {
        "transport": current,
        "baseline_transport": baseline,
        "recovery": recovery,
        "baseline_recovery": old_recovery,
        "baseline_commit": BASELINE,
        "fixtures": [
            "cloud resources",
            "SSM establishment",
            "small runner shell workload",
            "recover executing-binding check",
        ],
        "aws_calls": 0,
        "billable_actions": 0,
    }
    save(args.output / "reliability.json", result)
    if not all(x["oracle_passed"] for x in current + recovery) or any(
        x["oracle_passed"] for x in baseline + [old_recovery]
    ):
        raise AssertionError("reliability_distribution_or_baseline_sensitivity")
    print(
        json.dumps(
            {
                "current": [x["oracle_passed"] for x in current + recovery],
                "baseline": [x["oracle_passed"] for x in baseline + [old_recovery]],
                "outage_failed_reconnects": current[1]["failed_reconnects"],
            }
        )
    )


if __name__ == "__main__":
    main()
