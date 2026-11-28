import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prometheus_snapshot import restore, snapshot


class PrometheusSnapshotTests(unittest.TestCase):
    def archive(self, root, name, *, symlink=False):
        path = root / "snapshot.tgz"
        with tarfile.open(path, "w:gz") as stream:
            item = tarfile.TarInfo(name)
            if symlink:
                item.type = tarfile.SYMTYPE
                item.linkname = "local-target"
                stream.addfile(item)
            else:
                data = b'{"fixture":true}'
                item.size = len(data)
                stream.addfile(item, io.BytesIO(data))
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_export_hashes_the_closed_archive(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            name = "20261125T052000Z-abcd"
            block = "01JZZZZZZZZZZZZZZZZZZZZZZZ"
            source = root / "snapshots" / name / block
            source.mkdir(parents=True)
            (source / "meta.json").write_bytes(b'{"fixture":true}')
            archive = root / "snapshot.tgz"
            reply = io.BytesIO(
                b'{"status":"success","data":{"name":"20261125T052000Z-abcd"}}'
            )
            with patch(
                "prometheus_snapshot.urllib.request.urlopen", return_value=reply
            ):
                result = snapshot("http://127.0.0.1:9090", root, archive)
            data = archive.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            self.assertEqual(result, {"sha256": digest, "bytes": len(data), "files": 1})
            target = root / "restored"
            restore(archive, digest, target)
            self.assertEqual(
                (target / block / "meta.json").read_bytes(), b'{"fixture":true}'
            )

    def test_restore_checks_digest_before_creating_data(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            archive, digest = self.archive(root, "01JZZZZZZZZZZZZZZZZZZZZZZZ/meta.json")
            output = root / "restored"
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                restore(archive, "0" * 64, output)
            self.assertFalse(output.exists())
            self.assertEqual(restore(archive, digest, output)["files"], 1)

    def test_restore_rejects_non_block_path_or_link(self):
        for name, symlink in (
            ("wrong/meta.json", False),
            ("01JZZZZZZZZZZZZZZZZZZZZZZZ/meta.json", True),
        ):
            with (
                self.subTest(name=name, symlink=symlink),
                tempfile.TemporaryDirectory() as work,
            ):
                root = Path(work)
                archive, digest = self.archive(root, name, symlink=symlink)
                with self.assertRaisesRegex(ValueError, "invalid TSDB archive member"):
                    restore(archive, digest, root / "restored")
                self.assertFalse((root / "restored").exists())
