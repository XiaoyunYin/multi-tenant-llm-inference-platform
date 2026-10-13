import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from inference_platform.r1_bundle import validate_reviewed_bundle

ROOT = Path(__file__).resolve().parents[2]
CURRENT_ROUND89_SHA256 = "e6012bfc8733b94dbcfb348963d85f261a13310af32c98b022cabb062c7df436"
TEST_HEAD = "a" * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive_bytes(files, source_head=TEST_HEAD, manifest_files=None):
    manifest_files = manifest_files or {name: sha(data) for name, data in files.items()}
    payload = json.dumps(
        {"source_head": source_head, "files": manifest_files},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in sorted({**files, "payload.json": payload}.items()):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mtime = 0
            archive.addfile(item, io.BytesIO(data))
    return output.getvalue()


def write_bundle(root, files, source_head=TEST_HEAD, manifest_files=None):
    relative = "bundle/payload.tar.gz"
    bundle = root / relative
    bundle.parent.mkdir(parents=True, exist_ok=True)
    data = archive_bytes(files, source_head, manifest_files)
    bundle.write_bytes(data)
    return relative, data


def current_python_hashes(bundle_path, source_head):
    with tarfile.open(bundle_path, "r:gz") as archive:
        names = [
            member.name for member in archive.getmembers() if member.name.startswith("python/")
        ]
    return {
        name: sha(
            subprocess.check_output(["git", "-C", str(ROOT), "show", f"{source_head}:{name}"])
        )
        for name in names
    }


class R1BundleTests(unittest.TestCase):
    def setUp(self):
        self.files = {
            "python/src/inference_platform/example.py": b"source = 'bound'\n",
            "bin/gateway": b"gateway binary",
            "bin/uv": b"uv binary",
        }

    def validate(self, root, relative, data, *, source_head=TEST_HEAD, source_hashes=None):
        return validate_reviewed_bundle(
            root,
            {
                "bundle_path": relative,
                "bundle_sha256": sha(data),
                "source_head": source_head,
                "source_sha256": source_hashes
                if source_hashes is not None
                else {
                    "python/src/inference_platform/example.py": sha(
                        self.files["python/src/inference_platform/example.py"]
                    )
                },
            },
        )

    def test_valid_manifest_python_sources_and_gateway_head_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relative, data = write_bundle(root, self.files)
            receipt = self.validate(root, relative, data)
        self.assertEqual(receipt["python_files"], 1)
        self.assertEqual(receipt["gateway_sha256"], sha(self.files["bin/gateway"]))

    def test_python_source_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relative, data = write_bundle(root, self.files)
            bound = {"python/src/inference_platform/example.py": sha(b"different")}
            with self.assertRaisesRegex(ValueError, "differs from source_sha256"):
                self.validate(root, relative, data, source_hashes=bound)

    def test_missing_python_source_map_entry_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relative, data = write_bundle(root, self.files)
            with self.assertRaisesRegex(ValueError, "missing from source_sha256"):
                self.validate(root, relative, data, source_hashes={})

    def test_payload_member_hash_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_hashes = {name: sha(data) for name, data in self.files.items()}
            bad_hashes["bin/gateway"] = "0" * 64
            relative, data = write_bundle(root, self.files, manifest_files=bad_hashes)
            with self.assertRaisesRegex(ValueError, "payload hash mismatch: bin/gateway"):
                self.validate(root, relative, data)

    def test_payload_source_head_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relative, data = write_bundle(root, self.files, source_head="b" * 40)
            with self.assertRaisesRegex(ValueError, "source_head differs"):
                self.validate(root, relative, data, source_head=TEST_HEAD)

    def test_archive_digest_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relative, data = write_bundle(root, self.files)
            (root / relative).write_bytes(data + b"changed")
            with self.assertRaisesRegex(ValueError, "bundle SHA256 mismatch"):
                self.validate(root, relative, data)

    def test_current_round89_bundle_is_refused_against_current_python_sources(self):
        bundle = ROOT / ".cache/round89/paid/paid-payload.tar.gz"
        if not bundle.is_file():
            self.skipTest("local Round89 bundle is not present in this checkout")
        bundle_sha = sha(bundle.read_bytes())
        self.assertEqual(bundle_sha, CURRENT_ROUND89_SHA256)
        with tarfile.open(bundle, "r:gz") as archive:
            payload = json.load(archive.extractfile("payload.json"))
        current_head = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip()
        current_hashes = current_python_hashes(bundle, current_head)
        inputs = {
            "bundle_path": bundle.relative_to(ROOT).as_posix(),
            "bundle_sha256": bundle_sha,
            # Use the old manifest head here to isolate the Python source binding check.
            "source_head": payload["source_head"],
            "source_sha256": current_hashes,
        }
        with self.assertRaisesRegex(ValueError, "bundled Python source differs from source_sha256"):
            validate_reviewed_bundle(ROOT, inputs)

    def test_rebuilt_round116_bundle_matches_its_committed_source_tree(self):
        bundle = ROOT / ".cache/round116/paid/paid-payload.tar.gz"
        if not bundle.is_file():
            self.skipTest("Round116 bundle has not been built in this checkout")
        with tarfile.open(bundle, "r:gz") as archive:
            payload = json.load(archive.extractfile("payload.json"))
        inputs = {
            "bundle_path": bundle.relative_to(ROOT).as_posix(),
            "bundle_sha256": sha(bundle.read_bytes()),
            "source_head": payload["source_head"],
            "source_sha256": current_python_hashes(bundle, payload["source_head"]),
        }
        receipt = validate_reviewed_bundle(ROOT, inputs)
        self.assertEqual(receipt["source_head"], payload["source_head"])


if __name__ == "__main__":
    unittest.main()
