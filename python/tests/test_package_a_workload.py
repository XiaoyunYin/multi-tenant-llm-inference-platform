import base64
import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.eks_deployment import (
    NGINX_IMAGE,
    PROMETHEUS_IMAGE,
    PYTHON_IMAGE,
    REDIS_IMAGE,
)
from inference_platform.package_a_images import KIND_LOCAL_IMAGE_TAGS
from inference_platform.package_a_workload import preflight_manifest, workload_objects

ROOT = Path(__file__).resolve().parents[2]


def rehearsal():
    spec = importlib.util.spec_from_file_location(
        "rehearsal", ROOT / "scripts/rehearse_eks_package_a.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def kind_manifest():
    manifest = preflight_manifest()
    local = ("mti-gateway:r309", "mti-fake:stage1")
    used = rehearsal().mutate_kind_manifest(
        manifest,
        local[0],
        {
            "nginx": NGINX_IMAGE,
            "redis": REDIS_IMAGE,
            "prometheus": PROMETHEUS_IMAGE,
            "python": PYTHON_IMAGE,
        },
        local,
    )
    return manifest, set(used), set(KIND_LOCAL_IMAGE_TAGS.values()) | set(local)


class WorkloadTests(unittest.TestCase):
    def test_r312_prepare_calls_binding_before_bundle_or_terraform(self):
        from test_package_a_cloud import PackageACloudTests

        from inference_platform import package_a_operator as operator

        if not hasattr(operator, "bind_workload_preflight"):
            self.fail("prepare has no workload-preflight binding function")
        receipt = PackageACloudTests.valid_real_dependency_preflight_receipt()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ("deploy/k8s/pins.json", "scripts/rehearse_eks_package_a.py"):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            for section in (
                "go_real_redis",
                "go_real_redis_race",
                "gateway_build",
                "gateway_redis_e2e",
                "gateway_config",
            ):
                receipt.setdefault(section, {}).update(
                    log=section + ".log", log_sha256=hashlib.sha256(b"ok").hexdigest()
                )
                (root / (section + ".log")).write_bytes(b"ok")
            for section in ("cleanup", "verify_removed"):
                receipt["gateway_redis_e2e"][section] = {
                    "log": section + ".log",
                    "log_sha256": hashlib.sha256(b"ok").hexdigest(),
                }
                (root / (section + ".log")).write_bytes(b"ok")
            receipt["gateway_redis_e2e"]["build"].update(
                log="gateway-build.log",
                log_sha256=hashlib.sha256(b"ok").hexdigest(),
                binary_path="gateway",
                binary_sha256=hashlib.sha256(b"binary").hexdigest(),
            )
            (root / "gateway-build.log").write_bytes(b"ok")
            (root / "gateway").write_bytes(b"binary")
            path = root / "receipt.json"
            path.write_text(json.dumps(receipt), encoding="utf-8")
            with (
                patch.object(operator, "ROOT", root),
                patch.object(
                    operator, "bind_workload_preflight", side_effect=ValueError("binding_sentinel")
                ) as binding,
                patch.object(operator, "git") as git,
                patch.object(operator, "sealed_plans") as terraform,
                self.assertRaisesRegex(ValueError, "binding_sentinel"),
            ):
                operator.prepare(
                    root / "packet", root / "not-read-refresh", commit="c" * 40, preflight=path
                )
            binding.assert_called_once()
            git.assert_not_called()
            terraform.assert_not_called()
            self.assertFalse((root / "packet/source.bundle").exists())

    def test_r312_binding_refuses_changed_workload_log(self):
        from test_package_a_cloud import PackageACloudTests

        from inference_platform import package_a_operator as operator

        bind = getattr(operator, "bind_workload_preflight", None)
        if bind is None:
            self.fail("prepare has no workload-preflight binding function")
        receipt = PackageACloudTests.valid_real_dependency_preflight_receipt()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt["workload_files_sha256"] = {
                name: hashlib.sha256(b"ok").hexdigest()
                for name in (
                    "workload-manifest.json",
                    "gateway-env.json",
                    "cache-salt.secret",
                    "nginx.conf",
                    "nginx-answer.json",
                    "nginx-receipt.json",
                )
            }
            records = [
                receipt["gateway_config"],
                *(
                    receipt["nginx_start"][key]
                    for key in ("start", "inspect", "logs", "cleanup", "verify_removed")
                ),
            ]
            for i, record in enumerate(records):
                record.update(log=f"workload-{i}.log", log_sha256=hashlib.sha256(b"ok").hexdigest())
            for name in (*receipt["workload_files_sha256"], *(record["log"] for record in records)):
                (root / name).write_bytes(b"ok")
            (root / "workload-0.log").write_bytes(b"changed after preflight")
            with self.assertRaisesRegex(
                ValueError, "workload_preflight_file_changed:workload-0.log"
            ):
                bind(receipt, root)

    def test_r314_prepare_requires_new_kind_receipts(self):
        from test_package_a_cloud import PackageACloudTests

        from inference_platform import package_a_operator as operator

        receipt = PackageACloudTests.valid_real_dependency_preflight_receipt()
        for field, value in (
            ("complete", False),
            ("coverage_percent", 99),
            ("skipped_tests", 1),
            ("files_sha256", {}),
            ("kubectl_sha256", "0" * 64),
        ):
            changed = copy.deepcopy(receipt)
            changed["kind_no_cluster"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "kind_no_cluster"):
                operator.validate_real_dependency_preflight_receipt(changed, "c" * 40)
        del receipt["kind_no_cluster"]
        with self.assertRaisesRegex(ValueError, "kind_no_cluster"):
            operator.validate_real_dependency_preflight_receipt(receipt, "c" * 40)

    def test_tls_generation_ignores_a_missing_system_openssl_config(self):
        from inference_platform.package_a_workload import test_tls_command

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            command = test_tls_command(path)
            completed = subprocess.run(
                [str(v) for v in command],
                capture_output=True,
                env={**os.environ, "OPENSSL_CONF": str(path / "missing-system.cnf")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((path / "tls.key").stat().st_size)
            self.assertIn("BEGIN CERTIFICATE", (path / "tls.crt").read_text())

    def test_r309_real_kind_gateway_policy_is_accepted_by_router(self):
        manifest, _, _ = kind_manifest()
        pod = workload_objects(manifest)["StatefulSet", "gateway"]["spec"]["template"]["spec"]
        env = {e["name"]: e.get("value") for e in pod["containers"][0]["env"]}
        # Read the actual Go policy constants referenced by routerForPolicy.
        source = (ROOT / "internal/gateway/router.go").read_text()
        router = (
            (ROOT / "cmd/gateway/main.go")
            .read_text()
            .split("func routerForPolicy(", 1)[1]
            .split("\n}", 1)[0]
        )
        names = set(re.findall(r"case string\(gateway\.(RoutingPolicy\w+)\)", router))
        accepted = {
            value
            for name, value in re.findall(
                r'(RoutingPolicy\w+)\s+RoutingPolicy\s*=\s*"([a-z_]+)"', source
            )
            if name in names
        }
        self.assertTrue(accepted)
        self.assertIn(env["GATEWAY_ROUTING_POLICY"], accepted)

    def test_r309_real_kind_nginx_pid_and_all_temp_paths_are_writable(self):
        manifest, _, _ = kind_manifest()
        objects = workload_objects(manifest)
        config = objects["ConfigMap", "streaming-ingress"]["data"]["nginx.conf"]
        for directive in (
            "pid",
            "client_body_temp_path",
            "proxy_temp_path",
            "fastcgi_temp_path",
            "uwsgi_temp_path",
            "scgi_temp_path",
        ):
            self.assertRegex(config, rf"(?m)^\s*{directive}\s+/tmp/[^;]+;")
        pod = objects["Deployment", "streaming-ingress"]["spec"]["template"]["spec"]
        self.assertTrue(pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"])

    def test_r309_real_kind_all_controller_images_are_loaded_and_never_pulled(self):
        manifest, used, loaded = kind_manifest()
        self.assertEqual(used, loaded)
        for obj in manifest["items"]:
            if obj["kind"] in ("Deployment", "StatefulSet", "DaemonSet"):
                for container in obj["spec"]["template"]["spec"]["containers"]:
                    self.assertIn(container["image"], loaded)
                    self.assertEqual(container["imagePullPolicy"], "Never")

    def test_r309_kind_salt_is_canonical_32_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache-salt.secret"
            rehearsal().write_kind_secret(path)
            key = path.read_text().strip()
        raw = base64.urlsafe_b64decode(key + "=")
        self.assertEqual(len(raw), 32)
        self.assertEqual(base64.urlsafe_b64encode(raw).decode().rstrip("="), key)

    def test_r309_prepare_requires_both_checks_and_binds_every_result(self):
        from test_package_a_cloud import PackageACloudTests

        from inference_platform.package_a_operator import (
            validate_real_dependency_preflight_receipt,
            validate_workload_preflight_files,
        )

        receipt = PackageACloudTests.valid_real_dependency_preflight_receipt()
        validate_real_dependency_preflight_receipt(receipt, "c" * 40)
        for section in ("gateway_config", "nginx_start"):
            for field, value in (
                (("complete", False), ("exit_code", 2))
                if section == "gateway_config"
                else (
                    ("complete", False),
                    ("running", False),
                    ("https_status", None),
                    ("container_removed", False),
                )
            ):
                mutated = copy.deepcopy(receipt)
                mutated[section][field] = value
                with self.subTest(section=section, field=field), self.assertRaises(ValueError):
                    validate_real_dependency_preflight_receipt(mutated, "c" * 40)
            mutated = copy.deepcopy(receipt)
            del mutated[section]
            with self.assertRaises(ValueError):
                validate_real_dependency_preflight_receipt(mutated, "c" * 40)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            files = (
                "workload-manifest.json",
                "gateway-env.json",
                "cache-salt.secret",
                "nginx.conf",
                "nginx-answer.json",
                "nginx-receipt.json",
            )
            import hashlib

            receipt["workload_files_sha256"] = {
                name: hashlib.sha256(b"ok").hexdigest() for name in files
            }
            records = [receipt["gateway_config"]] + [
                receipt["nginx_start"][k]
                for k in ("start", "inspect", "logs", "cleanup", "verify_removed")
            ]
            for i, record in enumerate(records):
                record.update(log=f"check-{i}.log", log_sha256=hashlib.sha256(b"ok").hexdigest())
            for name in (*files, *(r["log"] for r in records)):
                (root / name).write_bytes(b"ok")
            validate_workload_preflight_files(receipt, root)
            for name in (*files, *(r["log"] for r in records)):
                (root / name).write_bytes(b"changed")
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "file_changed"):
                    validate_workload_preflight_files(receipt, root)
                (root / name).write_bytes(b"ok")


if __name__ == "__main__":
    unittest.main()
