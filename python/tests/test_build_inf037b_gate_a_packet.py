from __future__ import annotations

import ast
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import build_inf037b_gate_a_packet as packet  # noqa: E402

from inference_platform.package_a_operator import load_packet_manifest  # noqa: E402


def _ast_dict_value(node, key):
    if not isinstance(node, ast.Dict):
        raise AssertionError(f"expected literal dict for {key}")
    for candidate, value in zip(node.keys, node.values, strict=True):
        if isinstance(candidate, ast.Constant) and candidate.value == key:
            return value
    raise AssertionError(f"missing dict key {key}")


def _literal_dict_keys(node):
    if not isinstance(node, ast.Dict):
        raise AssertionError("expected literal dict")
    return {
        key.value
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }


def _role_path_manifest_keys():
    operator_path = packet.ROOT / "python/src/inference_platform/package_a_operator.py"
    base_path = packet.ROOT / "python/src/inference_platform/r1_cloud_operator.py"
    trees = [
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for path in (operator_path, base_path)
    ]
    methods = {}
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in {"Ports", "Operator"}:
                methods[node.name] = {
                    child.name: child
                    for child in node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                }

    pending = [
        ("Ports", name)
        for name in (
            "bootstrap",
            "upload",
            "request",
            "upload_gate_a_inputs",
            "run_checks",
            "retrieve",
        )
    ]
    visited = set()
    required = set()
    while pending:
        class_name, name = pending.pop()
        owner = class_name
        method = methods.get(class_name, {}).get(name)
        if method is None and class_name == "Ports":
            owner = "Operator"
            method = methods.get("Operator", {}).get(name)
        if method is None or (owner, name) in visited:
            continue
        visited.add((owner, name))
        for node in ast.walk(method):
            if isinstance(node, ast.Subscript):
                target = node.value
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr == "manifest"
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                    and isinstance(node.slice, ast.Constant)
                    and isinstance(node.slice.value, str)
                ):
                    required.add(node.slice.value)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self"
            ):
                pending.append((class_name, node.func.attr))
    return required, visited


class GateARoleManifestTests(unittest.TestCase):
    def test_rehearsal_checks_compact_phase_readback_inside_store_receipt(self):
        import gate_a_operator_rehearsal as rehearsal

        compact_phase = {
            "phase": "archive",
            "store_receipt": {
                "readback_verified": True,
                "recovery": {
                    "manifest": {"archive/a": {"bytes": 1}},
                    "manifest_sha256": "recovery-hash",
                },
                "s3": {
                    "objects": {"archive/a": {"bytes": 1}},
                    "manifest_sha256": "s3-hash",
                },
            },
            "object_count": 1,
        }
        self.assertTrue(rehearsal.phase_store_receipts_verified(compact_phase))
        self.assertEqual(
            rehearsal.phase_receipt_summary(compact_phase),
            {
                "phase": "archive",
                "readback_verified": True,
                "recovery_manifest_sha256": "recovery-hash",
                "s3_manifest_sha256": "s3-hash",
                "object_count": 1,
            },
        )
        compact_phase["store_receipt"]["readback_verified"] = False
        self.assertFalse(rehearsal.phase_store_receipts_verified(compact_phase))

    def test_packet_role_manifests_cover_hard_reads_on_the_role_path(self):
        required, visited = _role_path_manifest_keys()
        self.assertTrue({"Ports", "Operator"}.issubset({name for name, _ in visited}))

        source = (packet.ROOT / "scripts/build_inf037b_gate_a_packet.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        build = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_build_packet"
        )
        manifest_assignment = next(
            node
            for node in ast.walk(build)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "manifest" for target in node.targets
            )
            and isinstance(node.value, ast.Dict)
        )
        runner = _ast_dict_value(manifest_assignment.value, "gate_a_runner")
        common_call = _ast_dict_value(runner, "common")
        self.assertIsInstance(common_call, ast.Call)
        self.assertIsInstance(common_call.func, ast.Name)
        self.assertEqual(common_call.func.id, "gate_a_runner_common")
        common_input = common_call.args[0]
        common_values = {name: None for name in _literal_dict_keys(common_input)}
        common_values["bundle_bytes"] = 1024**2
        common = packet.gate_a_runner_common(common_values)
        roles = _ast_dict_value(runner, "roles")
        role_keys = {
            name: _literal_dict_keys(_ast_dict_value(roles, name))
            for name in ("receiver", "sender")
        }

        operator_source = (
            packet.ROOT / "python/src/inference_platform/package_a_operator.py"
        ).read_text(encoding="utf-8")
        operator_tree = ast.parse(operator_source)
        gate_operator = next(
            node
            for node in operator_tree.body
            if isinstance(node, ast.ClassDef) and node.name == "GateAOperator"
        )
        run_roles = next(
            node
            for node in gate_operator.body
            if isinstance(node, ast.FunctionDef) and node.name == "_run_roles"
        )
        for name in ("receiver_manifest", "sender_manifest"):
            assignment = next(
                node
                for node in ast.walk(run_roles)
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == name for target in node.targets
                )
            )
            self.assertTrue(
                any(
                    key is None and isinstance(value, ast.Name) and value.id == "common"
                    for key, value in zip(
                        assignment.value.keys, assignment.value.values, strict=True
                    )
                ),
                name,
            )

        for role in ("receiver", "sender"):
            emitted = set(common) | role_keys[role] | {"workload", "role", "deadline_epoch"}
            self.assertTrue(
                required.issubset(emitted), f"{role} misses {sorted(required - emitted)}"
            )

    def test_rehearsal_input_bundle_is_relative_to_the_operator_directory(self):
        import gate_a_operator_rehearsal as rehearsal

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packet_dir = root / "operator-packet"
            packet_dir.mkdir()
            source = root / "campaign" / "gate-a-inputs.tar"
            source.parent.mkdir()
            source.write_bytes(b"small rehearsal bundle")
            local = packet_dir / source.name
            local.write_bytes(source.read_bytes())
            binding = rehearsal.create_gate_a_inputs(
                packet_dir,
                {"input_bundle": local, "input_inventory": {"fixture/a": {"bytes": 1}}},
                "gate-a-rehearsal",
                "round-327-test",
            )

            self.assertEqual(binding["bundle_path"], "gate-a-inputs.tar")
            self.assertEqual(binding["bundle_bytes"], len(b"small rehearsal bundle"))
            self.assertEqual(binding["bundle_sha256"], packet.package_sha(local))

            with self.assertRaisesRegex(ValueError, "input_bundle_not_operator_local"):
                rehearsal.create_gate_a_inputs(
                    packet_dir,
                    {"input_bundle": source, "input_inventory": {}},
                    "gate-a-rehearsal",
                    "round-327-test",
                )


class GateAPacketCleanupTests(unittest.TestCase):
    def test_refusal_preserves_only_bounded_diagnostics_and_is_not_loadable(self):
        with tempfile.TemporaryDirectory(prefix="gate-a-refusal-root-") as temporary:
            with patch.object(packet, "ROOT", Path(temporary)):
                directory = packet.ROOT / ".cache" / ("r323-refusal-" + uuid.uuid4().hex)

                def refused_build(path, **_kwargs):
                    path.mkdir(parents=True)
                    (path / "sealed.log").write_text("sealed plan refused\n", encoding="utf-8")
                    (path / "sealed.command.json").write_text("{}\n", encoding="utf-8")
                    (path / "gate-a-inputs.tar").write_bytes(b"input tar")
                    (path / "source.bundle").write_bytes(b"source bundle")
                    terraform = path / "terraform"
                    terraform.mkdir()
                    (terraform / "create.tfplan").write_bytes(b"plan")
                    raise RuntimeError("sealed refusal")

                try:
                    with patch.object(packet, "_build_packet", side_effect=refused_build):
                        with self.assertRaisesRegex(RuntimeError, "sealed refusal"):
                            packet.build_packet(
                                directory,
                                fixture="fixture",
                                fixture_proof="proof",
                                sizing_proof="sizing",
                                spool_output="spool",
                                specs="specs",
                                refresh_path="refresh",
                            )
                    refused = list(directory.parent.glob(directory.name + ".refused-*"))
                    self.assertEqual(len(refused), 1)
                    refused = refused[0]
                    self.assertEqual(
                        (refused / "sealed.log").read_text(encoding="utf-8"),
                        "sealed plan refused\n",
                    )
                    self.assertTrue((refused / "sealed.command.json").is_file())
                    self.assertFalse((refused / "gate-a-inputs.tar").exists())
                    self.assertFalse((refused / "source.bundle").exists())
                    self.assertFalse((refused / "terraform/create.tfplan").exists())
                    self.assertFalse(directory.exists())
                    with self.assertRaisesRegex(ValueError, "gate_a_packet:refused_directory"):
                        load_packet_manifest(refused)
                finally:
                    for path in directory.parent.glob(directory.name + ".refused-*"):
                        packet.remove_tree(path)

    def test_packet_without_manifest_cannot_be_loaded(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "gate_a_packet:manifest_missing"):
                load_packet_manifest(temporary)

    def test_operator_aws_cli_preflight_covers_live_pairs_and_refuses_invalid_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            observed = []
            commands = []

            def parser(argv, **_kwargs):
                commands.append(argv)
                pair = tuple(argv[1:3])
                observed.append(pair)
                if pair[0] == "s3":
                    raise ValueError("AWS CLI invalid choice: s3 operation")
                return {"exit": 0, "log_sha256": "a" * 64}

            result = packet.preflight_operator_aws_cli("aws.exe", Path(temporary), runner=parser)

        self.assertEqual(len(result), 23)
        self.assertEqual(len(observed), 23)
        self.assertTrue(all(command[3:] == ["--generate-cli-skeleton"] for command in commands))
        self.assertEqual(set(observed), set(packet.operator_aws_cli_pairs()))
        self.assertTrue(all(service != "s3" for service, _ in observed))

    def test_windows_cleanup_retries_readonly_git_pack_file(self):
        with tempfile.TemporaryDirectory(prefix="gate-a-packet-cleanup-") as temporary:
            root = Path(temporary) / "shallow.git"
            pack = root / "objects" / "pack"
            pack.mkdir(parents=True)
            index = pack / "pack.idx"
            index.write_bytes(b"git pack index")
            original_rmtree = packet.shutil.rmtree
            retries = []

            def fail_once(path, *, onerror):
                self.assertEqual(Path(path), root)
                error = PermissionError("read-only Git pack index")
                onerror(os.unlink, str(index), (PermissionError, error, None))
                retries.append(index.exists())
                original_rmtree(path)

            with patch.object(packet.shutil, "rmtree", side_effect=fail_once):
                packet.remove_tree(root, platform_name="nt")

            self.assertEqual(retries, [False])
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
