"""Real DEC-077 HTTP upload/export with lost replies and owned helper processes.

Cloud resource methods and SSM session establishment are explicit fixtures; the
real Ports request/upload/retrieve implementations, Host protocol, byte/hash
bindings, reconnects, process stopping and lifecycle finally path run unchanged.
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from inference_platform.package_a_cloud import (
    CAP_USD,
    CPU_VALIDATION_CHECKS,
    TASK_CHECKS,
    CLEANUP_S,
    DEADLINE_S,
    Lifecycle,
    save,
    sha,
)
from inference_platform.package_a_operator import Ports
from inference_platform.session_stop import stop_forward

sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_a_host import Host, server  # noqa: E402


def run(output, fault):
    directory = output / fault
    directory.mkdir(parents=True)
    bundle = directory / "source.bundle"
    bundle.write_bytes(os.urandom(2 * 1024**2 + 71))
    manifest = {
        "bundle_bytes": bundle.stat().st_size,
        "bundle_sha256": sha(bundle),
        "upload_timeout_s": 120,
        "hourly_all_resources_usd": 0.4,
        "cleanup_cost_reserve_usd": 1,
        "checks": list(
            CPU_VALIDATION_CHECKS
            if os.environ.get("PACKAGE_A_CPU_VALIDATION") == "1"
            else TASK_CHECKS
        ),
        "session_manager_plugin_path": "unused-fixture",
        "operator_tools": {},
    }
    save(directory / "manifest.json", manifest)
    host = Host(
        directory / "host",
        "fixture",
        sha(directory / "manifest.json"),
        time.time() + 60,
    )
    dispatch = host.dispatch
    # Git bundle staging is independently run with the real bundle on Linux.
    host.dispatch = lambda path, data, headers: (
        {"staged": True, "fixture_git_stage_only": True}
        if path == "/stage"
        else dispatch(path, data, headers)
    )
    http = server(host, port=0)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    helpers, lost = [], set()
    clock_offset = [0]

    class FixturePorts(Ports):
        active = False
        cap_seen = False

        def tunnel(self, instance):
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(120)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            helpers.append(child)
            return http.server_port, child

        def rpc(self, port, path, token, data=None, headers=None):
            result = super().rpc(port, path, token, data, headers)
            if (
                fault == "lost_ssm"
                and path in {"/upload/1048576", "/archive/0"}
                and path not in lost
            ):
                lost.add(path)
                raise ConnectionResetError(
                    "fault: real request committed, transport reply lost"
                )
            return result

        def task_cost(self, start, now):
            return max(0, now - start) * 0.0001

        def cumulative_cost(self, start, now):
            self.cap_seen = self.cap_seen or (fault == "cap" and self.active)
            return CAP_USD + 0.1 if self.cap_seen else self.task_cost(start, now)

        def apply(self, end):
            self.active = True
            self.host = "fixture-no-EC2"
            self.deadline = end

        def bootstrap(self, end):
            host.output.mkdir(exist_ok=True)
            (host.output / "bootstrap.log").write_text("real existing setup log\n")
            self.phase("readiness", lambda: self.request("/status", end=end))
            if fault == "deadline":
                clock_offset[0] = DEADLINE_S - CLEANUP_S + 1

        def run_checks(self, end):
            (host.output / "check.log").write_bytes(
                b"raw stdout before injected stop\n"
            )
            if fault == "check":
                raise RuntimeError("injected mid-check failure")
            if fault == "lost_ssm_halt":
                raise ConnectionError("injected mid-run session loss")
            if fault == "gate":
                save(
                    host.output / "runner.json",
                    {"status": "SKIPPED_GATE", "thresholds_unchanged": True},
                )
                raise RuntimeError("injected memory gate skip")

        def teardown(self, end):
            host.cancel()
            if self.child:
                stop_forward(self.child)
                self.child = None
            self.active = False
            return {"destroy_completed": True, "fixture_cloud_resources": True}

        def inventory(self, end):
            return {
                "empty": not self.active
                and all(child.poll() is not None for child in helpers),
                "owned_helper_returncodes": [child.poll() for child in helpers],
            }

    ports = FixturePorts(directory, manifest)
    ports.token = "fixture"
    try:
        result = Lifecycle(
            ports,
            manifest,
            directory / "final",
            clock=lambda: time.time() + clock_offset[0],
        ).run()
        retrieved = result["retrieve"].get("complete") is True
        expected_retrieval = (
            result["retrieve"].get("status") == "unreachable" and not retrieved
            if fault == "cap"  # Cap checkpoint halts before bootstrap/status.
            else retrieved
        )
        if not expected_retrieval or not result["inventory"]["empty"]:
            raise AssertionError("fault_did_not_retrieve_and_teardown:" + fault)
        if fault == "lost_ssm" and (
            lost != {"/upload/1048576", "/archive/0"} or len(helpers) != 3
        ):
            raise AssertionError("missing_real_transport_reconnects")
        if fault not in {"none", "lost_ssm"} and result["complete"]:
            raise AssertionError("fault_misreported_complete")
        return {
            "fault": fault,
            "lifecycle": result,
            "lost_replies": sorted(lost),
            "helpers_spawned": len(helpers),
            "retrieved_archive_sha256": sha(ports.runtime / "receipts.tar.gz")
            if retrieved
            else None,
        }
    finally:
        for child in helpers:
            stop_forward(child)
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    receipts = [
        run(args.output, fault)
        for fault in (
            "none",
            "gate",
            "check",
            "lost_ssm",
            "lost_ssm_halt",
            "deadline",
            "cap",
        )
    ]
    save(
        args.output / "transport.json",
        {
            "scenarios": receipts,
            "limits_of_evidence": "Cloud create/destroy and SSM establishment are fixtures; real Host/Ports HTTP, files, hashes, helpers and reconnects",
            "aws_calls": 0,
            "billable_actions": 0,
        },
    )
    print(
        json.dumps(
            {
                row["fault"]: {
                    "retrieved": row["lifecycle"]["retrieve"]["complete"],
                    "inventory_empty": row["lifecycle"]["inventory"]["empty"],
                    "helpers": row["helpers_spawned"],
                }
                for row in receipts
            }
        )
    )


if __name__ == "__main__":
    main()
