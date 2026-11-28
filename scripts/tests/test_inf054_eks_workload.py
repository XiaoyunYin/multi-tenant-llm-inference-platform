"""Offline checks for the registered INF-054 schedule and receipt custody."""

import hashlib
import json
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inf054_autoscaling import ARMS, CYCLES, tape
from inf054_autoscaling import keda_image_refs, serving_values
from inf054_helm_releases import HelmReleases
from inf054_dcgm import RESERVE_S
from inf054_eks_workload import (
    gpu_release_seconds,
    read_tape,
    run,
    summarize,
    transfer_snapshot,
    workload_reserve,
    write_rows,
)


class FixtureCluster:
    snapshot = b"test snapshot payload"

    def __init__(self):
        self.events = []
        self.keda = []

    @contextmanager
    def release(self, arm, number, values, end):
        self.events.append(("install", arm, number))
        if values["autoscaling"]["enabled"]:
            self.keda.append((number, values["autoscaling"]["threshold"]))
        try:
            yield self
        finally:
            self.events.append(("uninstall", arm, number))

    def observe(self, end):
        return {"ready": 1, "waiting": 0, "private_label": "fixture-private"}

    def offer(self, prompt, cap, end):
        return {
            "http_status": 200,
            "outcome": "completed",
            "completion_tokens": cap,
            "ttft_s": 0.125,
            "completed_s": 4.5,
            "replica_ordinal": 0,
            "private_prompt": prompt,
            "gateway_code": "fixture-private",
        }

    def downscale(self, end):
        self.events.append(("downscale",))
        return {"observed": False}

    def freeze_tsdb(self, end):
        self.events.append(("freeze",))
        binding = {
            "sha256": hashlib.sha256(self.snapshot).hexdigest(),
            "bytes": len(self.snapshot),
        }

        def read(offset, wanted, _end):
            return self.snapshot[offset : offset + wanted]

        return binding, read


def accelerated_window(send, tasks, *, window_s, drain_s, start):
    if window_s != 960 or drain_s != 120:
        raise AssertionError("production durations changed")
    return [
        send(slot, start + window_s + drain_s)
        if offset < 1
        else {"outcome": "missed_offer"}
        for offset, slot in tasks
    ]


class Inf054WorkloadTests(unittest.TestCase):
    def gpu_deadline(self):
        return (
            time.monotonic()
            + 30
            + workload_reserve(
                len(ARMS) * CYCLES,
                observe_downscale=True,
                release_seconds=gpu_release_seconds(),
                dcgm_seconds=RESERVE_S,
            )
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tape = self.root / "rendered.jsonl"
        write_rows(
            self.tape,
            ({**row, "prompt": "fixture prompt " + str(row["slot"])} for row in tape()),
        )
        self.digest = hashlib.sha256(self.tape.read_bytes()).hexdigest()

    def test_helm_lifecycle_keeps_values_and_pins_on_bound_context(self):
        events = []
        downloaded = self.root / "helm-fixture.tgz"
        downloaded.write_bytes(b"fixture chart")
        pin = {"sha256": hashlib.sha256(downloaded.read_bytes()).hexdigest()}
        end = time.monotonic() + 30

        @contextmanager
        def namespace(arm, number, _end):
            name = f"mti-{arm}-{number}"
            yield SimpleNamespace(
                name=name, values={"clientImage": "fixture"}, cleanup_end=end
            )

        @contextmanager
        def backend(prepared, _end):
            events.append(("backend", prepared.name))
            yield "ready"

        def invoke(*argv, timeout):
            self.assertEqual(
                argv[:5], ("helm", "--kubeconfig", "fixture", "--kube-context", "owned")
            )
            self.assertGreater(timeout, 0)
            verb, name = argv[5:7]
            events.append((verb, name))
            if (verb, name) == ("template", "keda"):
                return SimpleNamespace(
                    stdout=json.dumps(
                        {
                            "kind": "Deployment",
                            "spec": {
                                "template": {
                                    "spec": {
                                        "containers": [
                                            {"image": image}
                                            for image in keda_image_refs()
                                        ]
                                    }
                                }
                            },
                        }
                    )
                )
            return SimpleNamespace(stdout="")

        helm = HelmReleases(
            "helm", "fixture", "owned", self.root, namespace, backend, invoke=invoke
        )
        with (
            patch("inf054_helm_releases.PINS", {"keda": pin}),
            helm.keda(downloaded, install_end=end, cleanup_end=end),
        ):
            with helm.release("keda", 2, serving_values("keda"), end) as started:
                self.assertEqual(started, "ready")
        self.assertEqual(
            events,
            [
                ("template", "keda"),
                ("install", "keda"),
                ("template", "inf054"),
                ("install", "inf054"),
                ("backend", "mti-keda-2"),
                ("uninstall", "inf054"),
                ("uninstall", "keda"),
            ],
        )
        values = json.loads((self.root / "mti-keda-2.json").read_bytes())
        self.assertEqual(values["autoscaling"]["threshold"], "2")
        self.assertTrue(values["snapshotAdminAPI"])

    def test_nine_cycles_use_same_slots_and_freeze_before_uninstall(self):
        ports = FixtureCluster()
        output = self.root / "out"
        reports = run(
            ports,
            self.tape,
            self.digest,
            output,
            absolute_end=self.gpu_deadline(),
            scheduler=accelerated_window,
        )
        expect = [(arm, index) for arm in ARMS for index in range(1, CYCLES + 1)]
        self.assertEqual([(row["arm"], row["cycle"]) for row in reports], expect)
        self.assertTrue(
            all(row["offered"] == 2760 and row["complete"] for row in reports)
        )
        self.assertEqual(ports.keda, [(1, "2"), (2, "2"), (3, "2")])
        self.assertEqual(ports.events.count(("downscale",)), 1)
        self.assertEqual(ports.events.count(("freeze",)), 9)
        for arm, index in expect:
            end = ports.events.index(("uninstall", arm, index))
            self.assertEqual(ports.events[end - 1], ("freeze",))
            dest = output / f"{arm}-{index}"
            self.assertEqual((dest / "tsdb.tar.gz").read_bytes(), ports.snapshot)
            self.assertNotIn(b"fixture prompt", (dest / "offers.jsonl").read_bytes())
            self.assertNotIn(b"fixture-private", (dest / "gauges.jsonl").read_bytes())

    def test_changed_prompt_and_schedule_are_each_refused(self):
        data = self.tape.read_bytes().replace(
            b'"output_cap": 64', b'"output_cap": 2', 1
        )
        self.tape.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "inf054_tape_hash"):
            read_tape(self.tape, self.digest)
        with self.assertRaisesRegex(ValueError, "inf054_tape_slot"):
            read_tape(self.tape, hashlib.sha256(data).hexdigest())

    def test_deadline_prevents_release_and_partial_receipt_still_freezes(self):
        ports = FixtureCluster()
        with self.assertRaisesRegex(TimeoutError, "inf054_cycle_reserve"):
            run(
                ports,
                self.tape,
                self.digest,
                self.root / "too_short",
                absolute_end=time.monotonic() + 18000,
            )
        self.assertEqual(ports.events, [])

        def refused(*args, **kwargs):
            raise TimeoutError("fixture")

        output = self.root / "partial"
        with self.assertRaisesRegex(TimeoutError, "fixture"):
            run(
                ports,
                self.tape,
                self.digest,
                output,
                absolute_end=self.gpu_deadline(),
                scheduler=refused,
            )
        self.assertEqual(
            ports.events,
            [("install", "fixed-1", 1), ("freeze",), ("uninstall", "fixed-1", 1)],
        )
        self.assertFalse(
            json.loads((output / "summary.json").read_bytes())[0]["complete"]
        )

    def test_corrupt_or_late_snapshot_never_publishes(self):
        root = self.root / "tsdb.tar.gz"
        binding = {"bytes": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
        with self.assertRaisesRegex(ValueError, "inf054_snapshot_hash"):
            transfer_snapshot(lambda *_: b"y", binding, root, time.monotonic() + 5)
        with self.assertRaisesRegex(TimeoutError, "inf054_snapshot_deadline"):
            transfer_snapshot(lambda *_: b"x", binding, root, time.monotonic() - 1)
        self.assertFalse(root.exists())
        self.assertFalse(root.with_suffix(".partial").exists())

    def test_slo_recount_uses_scheduled_slots_at_usability_split(self):
        summary = summarize(
            [
                {"scheduled_s": 59, "outcome": "missed_offer"},
                {
                    "scheduled_s": 60,
                    "outcome": "completed",
                    "ttft_s": 0.2,
                    "completed_s": 5,
                },
                {
                    "scheduled_s": 90,
                    "outcome": "rejected",
                    "http_status": 429,
                    "gateway_code": "system_capacity",
                },
            ],
            90,
        )
        self.assertEqual(summary["baseline"]["offered"], 1)
        self.assertEqual(summary["burst"]["slo_attainment"], 0.5)
        self.assertEqual(summary["pre_usable"]["slo_goodput_per_s"], 1 / 30)
        self.assertEqual(
            summary["post_usable"]["http_429_by_code"], {"system_capacity": 1}
        )
