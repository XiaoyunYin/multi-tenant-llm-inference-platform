"""R291/R292 lifecycle distributions and unchanged-29737e7 controls; no AWS."""

import argparse
import importlib.util
import io
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform import package_a_operator as operator
from inference_platform.package_a_cloud import (
    CLEANUP_S,
    DEADLINE_S,
    EXPORT_MAX_BYTES,
    Lifecycle,
    save,
    sha,
    transfer_seconds,
)
from inference_platform.session_stop import stop_forward

sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_a_reliability_rehearsal import fixture_host, fixture_manifest, helper  # noqa: E402
from package_a_host import Host  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "29737e713c92413152d39608cf0f5a91bc2cecd2"


class CostCompatibility:
    """Keep historical Ports controls runnable after Lifecycle split costs."""

    def task_cost(self, start, now):
        task_cost = getattr(super(), "task_cost", None)
        return task_cost(start, now) if task_cost else super().cost(start, now)

    def cumulative_cost(self, start, now):
        cumulative_cost = getattr(super(), "cumulative_cost", None)
        if cumulative_cost:
            return cumulative_cost(start, now)
        return self.manifest.get("prior_spend_usd", 0) + self.task_cost(start, now)


def baseline(directory):
    path = directory / "baseline/python/src/inference_platform/package_a_operator.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(
        subprocess.check_output(
            [
                "git",
                "show",
                BASELINE + ":python/src/inference_platform/package_a_operator.py",
            ],
            cwd=ROOT,
        )
    )
    spec = importlib.util.spec_from_file_location(
        "inference_platform.r226_old_operator", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ssm_regression(ports_class):
    # Run exactly the same unit test against both production implementations.
    spec = importlib.util.spec_from_file_location(
        "r226_tests", ROOT / "python/tests/test_package_a_cloud.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.Ports = ports_class
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream).run(
        unittest.TestSuite(
            [
                module.PackageACloudTests(
                    "test_real_ports_ssm_retries_first_invocation_exit_254"
                )
            ]
        )
    )
    return {
        "oracle_passed": result.wasSuccessful(),
        "tests": result.testsRun,
        "output": stream.getvalue(),
    }


def early_failure(directory, module):
    directory.mkdir(parents=True)
    manifest = fixture_manifest(directory)
    now, events = [1000.0], []

    class FixturePorts(CostCompatibility, module.Ports):
        def apply(self, end):
            self.host, self.started = "fixture-no-EC2", now[0]

        def bootstrap(self, end):
            raise RuntimeError("fixture bootstrap failed before host.py starts")

        def tunnel(self, instance):
            raise ConnectionResetError("fixture agent never launched")

        def teardown(self, end):
            events.append({"event": "teardown", "elapsed_s": now[0] - 1000})
            return {"destroy_completed": True}

        def inventory(self, end):
            events.append({"event": "inventory", "elapsed_s": now[0] - 1000})
            return {"empty": True}

    ports = FixturePorts(directory, manifest)
    with (
        patch.object(time, "time", side_effect=lambda: now[0]),
        patch.object(
            time,
            "sleep",
            side_effect=lambda seconds: now.__setitem__(0, now[0] + seconds),
        ),
    ):
        result = Lifecycle(
            ports, manifest, directory / "final", clock=lambda: now[0]
        ).run()
    return {
        "oracle_passed": (
            result["deadline_epoch"] - result["first_possible_billable_at_epoch"]
            == DEADLINE_S
            and events[0]["elapsed_s"] <= transfer_seconds(EXPORT_MAX_BYTES)
            and result["retrieve"].get("status") == "unreachable"
            and "bootstrap failed" in result.get("halt", "")
            and result["events"]
            == ["apply", "bootstrap", "retrieve", "teardown", "inventory"]
            and result["inventory"]["empty"]
        ),
        "elapsed_s": now[0] - 1000,
        "clock": "virtual; original six-hour deadline and real retry/backoff code",
        "reconnects": ports.reconnects,
        "events": events,
        "lifecycle": result,
    }


def archive_outage(directory, module):
    directory.mkdir(parents=True)
    manifest = fixture_manifest(directory)
    ports = module.Ports(directory, manifest)
    host, http, thread = fixture_host(directory, ports.token, Host, 1)
    host.output.mkdir(parents=True)
    (host.output / "uncompressible.log").write_bytes(os.urandom(3 * 1024**2))
    helpers, events, failures = [], [], []
    outage_end, triggered = [0], [False]
    started = time.monotonic()

    def event(name):
        events.append({"event": name, "elapsed_s": time.monotonic() - started})

    class FixturePorts(CostCompatibility, module.Ports):
        def tunnel(self, instance):
            if time.monotonic() < outage_end[0]:
                failures.append(time.monotonic() - started)
                raise ConnectionResetError("fixture mid-archive SSM outage")
            return http.server_port, helper(helpers)

        def rpc(self, port, path, token, data=None, headers=None):
            if time.monotonic() < outage_end[0]:
                raise ConnectionResetError("fixture mid-archive transport outage")
            result = super().rpc(port, path, token, data, headers)
            event(path)
            if path == "/archive/0" and not triggered[0]:
                triggered[0] = True
                outage_end[0] = time.monotonic() + 30
                event("outage_started_after_first_chunk")
            return result

        def apply(self, end):
            self.host, self.started = "fixture-no-EC2", time.time()

        def bootstrap(self, end):
            self.request("/status", end=end)

        def upload(self, end):
            self.request(
                "/manifest", (directory / "manifest.json").read_bytes(), end=end
            )

        def teardown(self, end):
            event("teardown")
            host.cancel()
            if self.child:
                stop_forward(self.child)
                self.child = None
            return {"destroy_completed": True}

        def inventory(self, end):
            event("inventory")
            return {
                "empty": host.child.poll() is not None
                and all(x.poll() is not None for x in helpers)
            }

    ports = FixturePorts(directory, manifest)
    host.token = ports.token
    try:
        result = Lifecycle(ports, manifest, directory / "final").run()
        labels = [x["event"] for x in events]
        return {
            "oracle_passed": (
                result["complete"]
                and triggered[0]
                and len(failures) >= 3
                and result["retrieve"]["bytes"] > 1024**2
                and sha(ports.runtime / "receipts.tar.gz")
                == result["retrieve"]["sha256"]
                and labels.index("/freeze")
                < labels.index("/archive/0")
                < labels.index("outage_started_after_first_chunk")
                < labels.index("/archive/1048576")
                < labels.index("teardown")
                < labels.index("inventory")
                and time.monotonic() - started >= 30
            ),
            "elapsed_s": time.monotonic() - started,
            "reconnects": ports.reconnects,
            "failed_reconnect_elapsed_s": failures,
            "events": events,
            "lifecycle": result,
        }
    finally:
        host.cancel()
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
    old = baseline(args.output)
    result = {
        "baseline_commit": BASELINE,
        "ssm": ssm_regression(operator.Ports),
        "baseline_ssm": ssm_regression(old.Ports),
        "early_bootstrap": early_failure(args.output / "early", operator),
        "baseline_early_bootstrap": early_failure(args.output / "early-old", old),
        "archive_outage30": archive_outage(args.output / "archive", operator),
        "baseline_archive_outage30": archive_outage(args.output / "archive-old", old),
        "aws_calls": 0,
        "billable_actions": 0,
        "fixtures": [
            "cloud resources/SSM establishment",
            "bootstrap failure",
            "one-second runner",
            "virtual early-halt clock",
        ],
        "cleanup_reserve_s": CLEANUP_S,
    }
    save(args.output / "r226.json", result)
    if not all(
        result[x]["oracle_passed"]
        for x in (
            "ssm",
            "early_bootstrap",
            "archive_outage30",
            "baseline_archive_outage30",
        )
    ):
        raise AssertionError("current_or_preserved_archive_reconnect_failed")
    if any(
        result[x]["oracle_passed"] for x in ("baseline_ssm", "baseline_early_bootstrap")
    ):
        raise AssertionError("29737e7_regression_controls_did_not_fail")
    print(
        json.dumps(
            {
                key: value.get("oracle_passed")
                for key, value in result.items()
                if isinstance(value, dict)
            }
        )
    )


if __name__ == "__main__":
    main()
