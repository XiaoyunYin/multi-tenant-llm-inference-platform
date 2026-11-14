import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from environment_requirements import require_history

from inference_platform.r1_agent import Host
from inference_platform.r1_spec import SPEC_COMMIT, verify_spec

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("r1_bootstrap", ROOT / "scripts/r1-host-bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def archive(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return stream.getvalue()


class CloudTests(unittest.TestCase):
    def test_catalog_host_size_keeps_observed_guest_memory_separate(self):
        host = Host.__new__(Host)
        host.role = "generator"
        host.config = {
            "cpu_budget": 8,
            "catalog_memory_bytes": 16 * 1024**3,
            "memory_catalog_source": "AWS c6i.2xlarge DescribeInstanceTypes receipt",
            "nic": "eth0",
            "nic_limit_bps": 3125000000,
            "nic_limit_source": "AWS rated baseline",
        }
        host.processes = []
        host.prior_cpu = host.prior_nic = host.prior_time = None

        def read(path):
            if path.as_posix() == "/proc/stat":
                return "cpu 1 2 3 4 5 6 7 8\n"
            if path.as_posix() == "/proc/meminfo":
                return "MemTotal: 15500000 kB\nMemAvailable: 14000000 kB\n"
            return "0"

        with (
            patch("inference_platform.r1_agent.Path.read_text", read),
            patch(
                "inference_platform.r1_agent.subprocess.check_output",
                return_value="Leap status : Normal",
            ),
            patch("inference_platform.r1_agent.process_snapshot", return_value={}),
        ):
            resource = host.resources(1000000000)
        self.assertEqual(resource["memory_bytes"], 16 * 1024**3)
        self.assertEqual(resource["observed_memory_bytes"], 15500000 * 1024)
        self.assertEqual(resource["observed_memory_available_bytes"], 14000000 * 1024)
        self.assertFalse(resource["memory_fixture"])
        self.assertIn("DescribeInstanceTypes", resource["memory_capacity_source"])

    def test_bundle_integrity_inventory_and_traversal_before_execution(self):
        files = {"bin/uv": b"unit-uv", "bin/gateway": b"unit-gateway"}
        manifest = {
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        }
        files["payload.json"] = json.dumps(manifest).encode()
        data = archive(files)
        with tempfile.TemporaryDirectory() as root:
            bootstrap.unpack(data, Path(root) / "valid", hashlib.sha256(data).hexdigest())
            self.assertEqual((Path(root) / "valid/bin/uv").read_bytes(), b"unit-uv")
            with self.assertRaisesRegex(ValueError, "SHA mismatch"):
                bootstrap.unpack(data, Path(root) / "wrong", "0" * 64)
            unsafe = archive({"../escape": b"bad"})
            with self.assertRaisesRegex(ValueError, "unsafe bundle"):
                bootstrap.unpack(unsafe, Path(root) / "unsafe", hashlib.sha256(unsafe).hexdigest())
            extra = archive({**files, "unreviewed": b"extra"})
            with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                bootstrap.unpack(extra, Path(root) / "extra", hashlib.sha256(extra).hexdigest())

    def test_bundle_retry_after_successful_stage_returns_staged(self):
        files = {"bin/uv": b"unit-uv", "bin/gateway": b"unit-gateway"}
        manifest = {
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        }
        files["payload.json"] = json.dumps(manifest).encode()
        data = archive(files)
        bundle_sha = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root) / "payload"
            first = bootstrap.staged_bundle_response(data, destination, bundle_sha)
            retry = bootstrap.staged_bundle_response(data, destination, bundle_sha)
        self.assertEqual(first, {"staged": True})
        self.assertEqual(retry, {"staged": True, "already_staged": True})

    def test_export_floor_requires_matching_physical_probe_and_no_active_gateways(self):
        host = Host.__new__(Host)
        host.role, host.processes, host.namespace, host.closing, host.config = (
            "service",
            [],
            None,
            False,
            {},
        )
        core = {
            "samples": [{"raw_bytes_per_second": 1000}],
            "generator_hostname": "redacted-at-source",
        }
        from inference_platform.r1_spec import encoded

        value = {
            **core,
            "measurement_sha256": hashlib.sha256(encoded(core)).hexdigest(),
            "agent_config": {
                "export_minimum_bytes_per_second": 500,
                "export_link_rate_source": "unit physical probe",
            },
        }
        host.handle("/export/link", value, 1)
        self.assertEqual(host.config["export_minimum_bytes_per_second"], 500)
        value["agent_config"]["export_minimum_bytes_per_second"] = 501
        with self.assertRaisesRegex(ValueError, "differs from measured"):
            host.handle("/export/link", value, 1)
        host.processes = [object()]
        with self.assertRaisesRegex(ValueError, "before calibration"):
            host.handle("/export/link", value, 1)

    def test_host_spec_artifact_checks_identical_registered_bytes_without_git(self):
        import subprocess

        require_history(ROOT, SPEC_COMMIT)
        accepted = subprocess.check_output(
            ["git", "show", SPEC_COMMIT + ":docs/R1_PRE_REGISTRATION.md"], cwd=ROOT
        )
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "spec.md"
            path.write_bytes(accepted)
            with patch(
                "inference_platform.r1_spec.subprocess.check_output",
                side_effect=AssertionError("no Git on host"),
            ):
                verify_spec(SPEC_COMMIT, artifact=path)
                path.write_bytes(accepted + b"changed")
                with self.assertRaisesRegex(ValueError, "specification bytes"):
                    verify_spec(SPEC_COMMIT, artifact=path)
