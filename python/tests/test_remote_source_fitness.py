import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from inference_platform.remote_source_fitness import (
    STEPS,
    remote_fingerprint,
    remote_source_fitness,
)
from inference_platform.stage_c_session import (
    ENTRYPOINT,
    bootstrap_commands,
    git,
    sha,
    source_paths,
    write_json,
)


class RemoteSourceFitnessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[2]
        cls.sources = {
            p: git(cls.root, "show", "HEAD:" + p) for p in source_paths(cls.root, "HEAD")
        }
        cls.fingerprint = remote_fingerprint(cls.root)
        cls.commit = git(cls.root, "rev-parse", "HEAD").decode().strip()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root / ".cache")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.expected = {p: hashlib.sha256(data).hexdigest() for p, data in self.sources.items()}
        self.manifest = {
            "source_commit": self.commit,
            "files": [{"path": p, "sha256": h} for p, h in self.expected.items()],
            "entrypoint": {"path": ENTRYPOINT, "sha256": self.expected[ENTRYPOINT]},
            "gateway_artifact": {"goos": "linux"},
        }
        write_json(self.path / "manifest.json", self.manifest)
        commands = bootstrap_commands(
            self.sources[ENTRYPOINT],
            sha(self.path / "manifest.json"),
            self.manifest,
            "/opt/inf011/reviewed",
            "local-clean-remote-fixture",
            22280,
            rehearse=True,
        )
        self.proof = {
            "status": "passed",
            "initial_environment": {
                "PATH": "/opt/round58-venv/bin:/usr/local/bin:/usr/bin:/bin",
                "HOME": "/tmp",
                "LANG": "C.UTF-8",
            },
            "inherited_bytecode_variable": False,
            "fake_readiness": "ready",
            "shared_capture_started": True,
            "real_capture": {
                "host_prepare_paths_before_capture": True,
                "continuous_decoded_block_stored_count": 1,
            },
            "worker_returncode": 0,
            "same_worker_identity_after_restart": True,
            "aws_calls_made": False,
            "bootstrap_commands_sha256": hashlib.sha256(json.dumps(commands).encode()).hexdigest(),
            "checkpoints": [
                {
                    "step": step,
                    "tree": "bundle" if step in STEPS[:2] else "staged",
                    "files_sha256": self.expected.copy(),
                }
                for step in STEPS
            ],
        }
        self.receipt = {
            "schema": "inf011-clean-remote-rehearsal.v1",
            "status": "passed",
            "source_files_sha256": self.fingerprint,
            "source_commit": self.commit,
            "manifest_path": (self.path / "manifest.json").relative_to(self.root).as_posix(),
            "manifest_sha256": sha(self.path / "manifest.json"),
            "proof_path": (self.path / "proof.json").relative_to(self.root).as_posix(),
            "steps": list(STEPS),
            "aws_calls_made": False,
        }
        self.persist()

    def persist(self):
        write_json(self.path / "proof.json", self.proof)
        self.receipt["proof_sha256"] = sha(self.path / "proof.json")
        write_json(self.path / "receipt.json", self.receipt)

    def fitness(self):
        return remote_source_fitness(self.root, self.path / "receipt.json")

    def test_matching_unit_metadata_is_accepted_and_missing_receipt_fails(self):
        self.assertTrue(self.fitness()[0])
        self.assertFalse(remote_source_fitness(self.root, self.path / "absent")[0])

    def test_stale_executable_or_tampered_proof_fails(self):
        self.receipt["source_files_sha256"] = {}
        self.persist()
        self.assertIn("committed executable", self.fitness()[1])
        self.receipt["source_files_sha256"] = self.fingerprint
        self.persist()
        (self.path / "proof.json").write_text("{}")
        self.assertIn("checksum", self.fitness()[1])

    def test_wrong_entrypoint_pin_fails(self):
        self.manifest["entrypoint"]["sha256"] = "0" * 64
        write_json(self.path / "manifest.json", self.manifest)
        self.receipt["manifest_sha256"] = sha(self.path / "manifest.json")
        self.persist()
        self.assertIn("entrypoint pin", self.fitness()[1])

    def test_inherited_setting_bootstrap_change_missing_step_or_tree_change_fails(self):
        baseline = json.dumps(self.proof)
        for defect in ("inheritance", "bootstrap", "step", "extra", "hash", "readiness", "restart"):
            self.proof = json.loads(baseline)
            if defect == "inheritance":
                self.proof["inherited_bytecode_variable"] = True
            elif defect == "bootstrap":
                self.proof["bootstrap_commands_sha256"] = "0" * 64
            elif defect == "step":
                self.proof["checkpoints"].pop()
            elif defect == "extra":
                self.proof["checkpoints"][2]["files_sha256"]["extra.pyc"] = "0" * 64
            elif defect == "hash":
                self.proof["checkpoints"][3]["files_sha256"][ENTRYPOINT] = "0" * 64
            elif defect == "readiness":
                self.proof["fake_readiness"] = "failed"
            else:
                self.proof["same_worker_identity_after_restart"] = False
            self.persist()
            with self.subTest(defect=defect):
                self.assertFalse(self.fitness()[0])


if __name__ == "__main__":
    unittest.main()
