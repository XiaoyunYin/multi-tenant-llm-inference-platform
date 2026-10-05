import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.stage_c_fitness import (
    capture_uses_connect,
    check_fitness,
    main,
    vllm_publisher_binds,
)
from inference_platform.stage_c_session import prepare, sha, write_json


class FitnessTest(unittest.TestCase):
    def setUp(self):
        # Other provider checks use fixtures; the new fail-closed receipt gate is
        # tested independently in test_remote_source_fitness and by real Docker.
        gate = patch(
            "inference_platform.remote_source_fitness.remote_source_fitness",
            return_value=(True, "unit-only clean remote provider fixture"),
        )
        gate.start()
        self.addCleanup(gate.stop)

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[2]
        cls.directory = tempfile.TemporaryDirectory(prefix="fitness-", dir=cls.root / ".cache")
        cls.path = Path(cls.directory.name)
        payload = cls.path / "payload"
        cls.manifest = prepare(cls.root, payload, "windows" if os.name == "nt" else "linux")
        manifest_path = payload / "staging-manifest.json"
        cls.inputs = json.loads(
            (cls.root / "docs/INF011_STAGE_C_SESSION_INPUTS.json").read_text(encoding="utf-8")
        )
        # Test current committed source with disposable pins. Historical paid
        # staging records must remain stale until separately reviewed/re-pinned.
        cls.inputs["staging"] = {
            **cls.inputs["staging"],
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha(manifest_path),
            "entrypoint_sha256": cls.manifest["entrypoint"]["sha256"],
            "source_commit": cls.manifest["source_commit"],
        }

        from inference_platform.host_headroom import source_fingerprint

        proof = cls.path / "unit-headroom-proof.txt"
        proof.write_text("unit fixture only", encoding="utf-8")
        bound = cls.path / "unit-headroom.json"
        write_json(
            bound,
            {
                "schema": "inf011-constrained-rehearsal.v1",
                "status": "passed",
                "source_files_sha256": source_fingerprint(cls.root),
                "memory_budget_bytes": 6 * 1024**3,
                "cpu_limit": 2,
                "measured_request_count": 7000,
                "completed_run_count": 4,
                "peak_memory_bytes": 100000000,
                "oom_kill_delta": 0,
                "host_series_sample_count": 1,
                "process_peaks": {
                    role: {"peak_rss_bytes": 1000000, "peak_cpu_percent": 1}
                    for role in ("host_controller", "capture", "gateway", "sampler")
                },
                "evidence_sha256": {proof.relative_to(cls.root).as_posix(): sha(proof)},
                "final_export_bytes": 1000,
                "measurement_digests": [
                    {
                        "run_number": n,
                        "path": proof.relative_to(cls.root).as_posix(),
                        "bytes": proof.stat().st_size,
                        "sha256": sha(proof),
                    }
                    for n in range(1, 5)
                ],
            },
        )
        cls.inputs["host_headroom_receipt_path"] = str(bound)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def current_inputs(self):
        return json.loads(json.dumps(self.inputs))

    def test_real_tokenizer_pin_mismatch_blocks_fitness(self):
        root = self.root
        inputs = self.current_inputs()
        launcher = (root / "infra/terraform/pilot/user-data.sh.tftpl").read_text(encoding="utf-8")
        for field, value in (("tokenizer_file_sha256", {}), ("model_revision", "unreviewed")):
            with self.subTest(field=field):
                records = check_fitness(launcher, {**inputs, field: value}, root)
                row = next(
                    row for row in records if row["prerequisite"] == "real_chat_prompt_fitness"
                )
                self.assertFalse(row["provided"])
                self.assertIsNone(row["evidence"])

    def test_bind_rule_and_real_capture_connection_are_required(self):
        root = self.root
        inputs = self.current_inputs()
        launcher = (root / "infra/terraform/pilot/user-data.sh.tftpl").read_text(encoding="utf-8")
        # A matching config with the old endpoint must fail fitness for socket semantics.
        inputs["kv_events"]["endpoint"] = "tcp://127.0.0.1:5557"
        broken = launcher.replace("tcp://*:5557", "tcp://127.0.0.1:5557")
        row = next(
            row
            for row in check_fitness(broken, inputs, root)
            if row["prerequisite"] == "kv_publisher"
        )
        self.assertFalse(row["provided"])
        for endpoint in ("tcp://*:5557", "tcp://[::]:5557", "ipc:///tmp/events", "inproc://events"):
            self.assertTrue(vllm_publisher_binds(endpoint))
        self.assertFalse(vllm_publisher_binds("tcp://127.0.0.1:5557"))
        source = (root / "python/src/inference_platform/kv_event_capture.py").read_text(
            encoding="utf-8"
        )
        self.assertTrue(capture_uses_connect(source))
        self.assertFalse(
            capture_uses_connect(
                source.replace("subscriber.connect(endpoint)", "subscriber.bind(endpoint)")
            )
        )

    def test_cli_decodes_terraform_console_json_layers_and_fails_missing_provider(self):
        root = self.root
        launcher = (root / "infra/terraform/pilot/user-data.sh.tftpl").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            rendered = Path(directory) / "rendered.json"
            output = Path(directory) / "fitness.json"
            inputs_path = Path(directory) / "inputs.json"
            write_json(inputs_path, self.current_inputs())
            args = [
                "fitness",
                "--rendered-json",
                str(rendered),
                "--inputs",
                str(inputs_path),
                "--root",
                str(root),
                "--output",
                str(output),
            ]
            for text, status in (
                (launcher, 0),
                (launcher.replace("--kv-events-config", "--missing"), 1),
            ):
                rendered.write_text(json.dumps(json.dumps(text)), encoding="utf-8")
                with patch("sys.argv", args), patch("builtins.print"):
                    self.assertEqual(main(), status)
                rows = json.loads(output.read_text(encoding="utf-8"))["prerequisites"]
                self.assertEqual(len(rows), 26)
                self.assertEqual(
                    sum(row["prerequisite"] == "host_headroom_bound" for row in rows), 1
                )
                self.assertTrue(all(row["provider"] and row["runtime_check"] for row in rows))

    def test_missing_launcher_prerequisite_and_topic_mismatch_fail(self):
        root = self.root
        inputs = self.current_inputs()
        launcher = (root / "infra/terraform/pilot/user-data.sh.tftpl").read_text(encoding="utf-8")
        records = check_fitness(launcher, inputs, root)
        self.assertTrue(all(row["provided"] for row in records), records)
        for fragment in ("--kv-events-config", "VLLM_SERVER_DEV_MODE=1", "127.0.0.1:9400:9400"):
            with self.subTest(fragment=fragment):
                broken = "\n".join(line for line in launcher.splitlines() if fragment not in line)
                self.assertFalse(
                    all(row["provided"] for row in check_fitness(broken, inputs, root))
                )
        inputs["kv_events"]["topic"] = "wrong-topic"
        self.assertFalse(all(row["provided"] for row in check_fitness(launcher, inputs, root)))

    def test_unprovided_protocol_and_timeout_fail(self):
        root = self.root
        inputs = self.current_inputs()
        launcher = (root / "infra/terraform/pilot/user-data.sh.tftpl").read_text(encoding="utf-8")
        for change in ("timeout", "duration", "decode"):
            broken = json.loads(json.dumps(inputs))
            if change == "timeout":
                broken["gateway_launcher_environment"]["GATEWAY_FIRST_ITEM_TIMEOUT"] = "5s"
            elif change == "duration":
                broken["protocol"]["seconds_per_level"] = 1
            else:
                broken["workload_sizing"]["reference_max_tokens"] = 128
            with self.subTest(change=change):
                self.assertFalse(
                    all(row["provided"] for row in check_fitness(launcher, broken, root))
                )

    def test_hash_pinned_manifest_with_stale_source_still_fails_committed_provenance(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest["files"][0]["sha256"] = "0" * 64
        stale_path = self.path / "stale-manifest.json"
        write_json(stale_path, manifest)
        inputs = self.current_inputs()
        inputs["staging"].update(manifest_path=str(stale_path), manifest_sha256=sha(stale_path))
        launcher = (self.root / "infra/terraform/pilot/user-data.sh.tftpl").read_text(
            encoding="utf-8"
        )
        records = check_fitness(launcher, inputs, self.root)
        for name in (
            "reviewed_session_entrypoint",
            "staged_payload_git_provenance",
            "bounded_readiness_and_owned_cleanup",
        ):
            with self.subTest(prerequisite=name):
                row = next(row for row in records if row["prerequisite"] == name)
                self.assertFalse(row["provided"])
        self.assertIn(
            "staged source differs",
            next(row for row in records if row["prerequisite"] == "staged_payload_git_provenance")[
                "provider"
            ],
        )
