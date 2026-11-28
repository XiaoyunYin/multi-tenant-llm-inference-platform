"""R600 and R601 regressions for the INF-054 seal and workload phase."""

import hashlib
import json
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from inf054_cpu_helm import (
    ChatTemplateAdapter,
    GPUHelmPorts,
    HelmProofPorts,
    PRODUCER,
    TAPE,
    build_tape_input,
)
from inf054_eks_workload import TEARDOWN_S, workload_reserve

from inference_platform.m5_descriptive_operator import phase_deadline

TAPE_SHA = "6f19ddabb51fe02975cc6afdb2a0bc5ad021b1bcfeed8f85c41a42eb889f6467"


class HelmProofTests(unittest.TestCase):
    def test_dcgm_stop_exports_diagnostics_before_timed_workload(self):
        with tempfile.TemporaryDirectory() as name:
            ports = GPUHelmPorts.__new__(GPUHelmPorts)
            ports.output = Path(name)
            ports.namespace = "mti-fixture"
            work = ports.output / "inf054-helm"
            work.mkdir()
            gate = b'{"ready":false,"snapshot":{"pods":[]}}\n'
            (work / "dcgm-gate-keda-2.json").write_bytes(gate)
            inventory = ports.export()
            frozen = ports.output / "frozen"
            self.assertEqual((frozen / "dcgm-gate-keda-2.json").read_bytes(), gate)
            self.assertEqual(
                json.loads((frozen / "proof.json").read_bytes())["reason"],
                "inf054_dcgm_not_ready",
            )
            self.assertIn("dcgm-gate-keda-2.json", str(inventory))

    def test_tape_producer_reproduces_reviewed_bytes(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            build_tape_input(path)
            with (path / TAPE).open("rb") as stream:
                self.assertEqual(
                    hashlib.file_digest(stream, "sha256").hexdigest(), TAPE_SHA
                )
            producer = json.loads((path / PRODUCER).read_bytes())
            self.assertEqual(producer["sha256"], TAPE_SHA)
            self.assertEqual(
                (producer["rows"], producer["rendered_tokens"]), (2760, 1024)
            )

    def test_adapter_rejects_unregistered_chat_template_flags(self):
        adapter = ChatTemplateAdapter(lambda rows: [len(rows)])
        flags = {"tokenize": True, "add_generation_prompt": True, "return_dict": False}
        messages = [{"role": "user", "content": "fixture"}]
        self.assertEqual(adapter.apply_chat_template(messages, **flags), [1])
        for key, value in flags.items():
            with self.subTest(flag=key):
                with self.assertRaisesRegex(ValueError, "inf054_chat_template_flags"):
                    adapter.apply_chat_template(messages, **{**flags, key: not value})

    def test_export_retains_receipts_on_failure_after_keda_install(self):
        @contextmanager
        def install(_chart, **_deadlines):
            yield {"status": "installed", "elapsed_s": 1}

        with tempfile.TemporaryDirectory() as name:
            ports = HelmProofPorts.__new__(HelmProofPorts)
            ports.output = Path(name)
            ports.namespace = "mti-fixture"
            ports.image_archive = ports.output / "images.tar"
            ports.binding = {"inf054_cpu_helm": {"tape_sha256": TAPE_SHA}}
            ports.deadline = time.monotonic() + 10000
            (ports.output / "inf054-images.secret").write_text(
                '{"images":{"gateway":"g","client":"c"}}', encoding="utf-8"
            )
            with (
                patch("inf054_cpu_helm.install_helm"),
                patch("inf054_cpu_helm.download"),
                patch("inf054_cpu_helm.chart_checks", return_value={"golden": "pass"}),
                patch("inf054_cpu_helm.Dec100Workload") as workload,
                patch(
                    "inf054_cpu_helm.run",
                    side_effect=RuntimeError("fixture_after_install"),
                ),
            ):
                workload.return_value.helm.keda.side_effect = install
                with self.assertRaisesRegex(RuntimeError, "fixture_after_install"):
                    ports.proof()
            ports.export()
            frozen = ports.output / "frozen"
            self.assertEqual(
                {
                    p.relative_to(frozen).as_posix()
                    for p in frozen.rglob("*")
                    if p.is_file()
                },
                {
                    "proof.json",
                    "chart-checks.json",
                    "keda-install.json",
                    "keda-1/readiness.jsonl",
                },
            )
            self.assertEqual(
                json.loads((frozen / "chart-checks.json").read_bytes())["golden"],
                "pass",
            )
            self.assertEqual(
                json.loads((frozen / "keda-install.json").read_bytes())["status"],
                "installed",
            )
            self.assertEqual(
                json.loads((frozen / "keda-1/readiness.jsonl").read_bytes()),
                {"event": "pending"},
            )
            self.assertFalse(
                json.loads((frozen / "proof.json").read_bytes())["complete"]
            )

    def test_proof_rejects_late_start_at_the_sealed_phase_deadline(self):
        timing = {"cleanup_reserve_seconds": 1800, "retrieval_reserve_seconds": 4416}
        ports = HelmProofPorts.__new__(HelmProofPorts)
        ports.original_end = 18000
        ports.deadline = phase_deadline(ports.original_end, timing, "inf054-helm-proof")
        self.assertEqual(ports.deadline, 11784)
        with patch("inf054_cpu_helm.time.monotonic", return_value=9400):
            with patch("inf054_cpu_helm.install_helm") as install:
                with self.assertRaisesRegex(TimeoutError, "inf054_helm_phase_reserve"):
                    ports.proof()
                install.assert_not_called()
        self.assertEqual(workload_reserve(1, observe_downscale=True), 5340)
        self.assertEqual(workload_reserve(1, observe_downscale=True) - TEARDOWN_S, 3540)


if __name__ == "__main__":
    unittest.main()
