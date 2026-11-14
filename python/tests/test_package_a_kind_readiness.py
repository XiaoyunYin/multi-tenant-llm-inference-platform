"""R314/R416 CLI semantics and manifest readiness, without a kind cluster."""

import ast
import copy
import importlib.util
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from package_a_kind_api import (  # noqa: E402
    check_api,
    pinned_kubectl,
    rendered_kind_manifest,
    replacement_blocks,
)
from rehearse_row5_kind import render_row5_manifest  # noqa: E402

from inference_platform import package_a_cloud  # noqa: E402
from inference_platform.package_a_cloud import (  # noqa: E402
    ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S,
)
from inference_platform.package_a_workload import preflight_manifest  # noqa: E402

READINESS_RESOLUTION_ALLOWLIST = {}


def rehearsal():
    spec = importlib.util.spec_from_file_location(
        "rehearse_eks_package_a", ROOT / "scripts/rehearse_eks_package_a.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def readiness_commands(source, bindings=None, *, source_name="<source>"):
    """Resolve readiness argv passed to k() and row5's _manifest_call()."""
    commands = []
    used_allowlist = set()

    def unresolved(node, function):
        key = (source_name, node.lineno, function)
        reason = READINESS_RESOLUTION_ALLOWLIST.get(key)
        if isinstance(reason, str) and reason.strip():
            used_allowlist.add(key)
            return True
        raise AssertionError(
            f"unresolved readiness command at {source_name}:{node.lineno} ({function})"
        )

    def visit(node, bindings):
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            try:
                values = ast.literal_eval(node.iter)
            except (ValueError, TypeError):
                pass
            else:
                for value in values:
                    loop_bindings = {**bindings, node.target.id: value}
                    for child in node.body:
                        visit(child, loop_bindings)
                for child in node.orelse:
                    visit(child, bindings)
                return
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                try:
                    bindings[target.id] = eval(
                        compile(ast.Expression(node.value), "<readiness>", "eval"),
                        {"__builtins__": {}},
                        bindings,
                    )
                except (AttributeError, NameError, TypeError, ValueError):
                    pass
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "k":
                if not node.args or not isinstance(node.args[0], ast.Constant):
                    unresolved(node, "k")
                elif node.args[0].value in ("wait", "rollout"):
                    try:
                        command = [
                            eval(
                                compile(ast.Expression(arg), "<readiness>", "eval"),
                                {"__builtins__": {}},
                                bindings,
                            )
                            for arg in node.args
                        ]
                    except (AttributeError, NameError, TypeError, ValueError):
                        unresolved(node, "k")
                    else:
                        commands.append(command)
            elif node.func.id == "_manifest_call":
                assert len(node.args) >= 5, ast.unparse(node)
                command_node = node.args[4]
                if not (
                    isinstance(command_node, ast.List)
                    and command_node.elts
                    and isinstance(command_node.elts[0], ast.Constant)
                ):
                    unresolved(node, "_manifest_call")
                elif command_node.elts[0].value in ("wait", "rollout"):
                    try:
                        command = eval(
                            compile(ast.Expression(command_node), "<readiness>", "eval"),
                            {"__builtins__": {}},
                            bindings,
                        )
                    except (AttributeError, NameError, TypeError, ValueError):
                        unresolved(node, "_manifest_call")
                    else:
                        commands.append(command)
        for child in ast.iter_child_nodes(node):
            visit(child, bindings)

    visit(ast.parse(source), dict(bindings or {}))
    assert used_allowlist == set(READINESS_RESOLUTION_ALLOWLIST), (
        "stale readiness resolution allowlist entries: "
        f"{set(READINESS_RESOLUTION_ALLOWLIST) - used_allowlist}"
    )
    return commands


def validate_readiness(source, manifest=None, *, bindings=None, source_name="<source>"):
    manifest = manifest or rendered_kind_manifest()
    objects = {(o["kind"].lower(), o["metadata"]["name"]): o for o in manifest["items"]}
    commands = readiness_commands(source, bindings, source_name=source_name)
    assert commands, "no readiness commands found"
    for argv in commands:
        targets = [arg for arg in argv if not arg.startswith("-") and "/" in arg]
        if not targets and argv[0] == "wait" and "nodes" in argv:
            continue  # Cluster node readiness is outside the rendered workload manifest.
        assert len(targets) == 1, argv
        kind, name = targets[0].split("/", 1)
        if kind == "pod":
            workload, ordinal = name.rsplit("-", 1)
            obj = objects[("statefulset", workload)]
            assert int(ordinal) < obj["spec"]["replicas"], argv
        else:
            obj = objects[(kind, name)]
        if argv[:2] == ["rollout", "status"]:
            assert obj["kind"] in ("Deployment", "DaemonSet", "StatefulSet"), argv
            if obj["kind"] == "StatefulSet":
                assert (
                    obj["spec"].get("updateStrategy", {}).get("type", "RollingUpdate")
                    == "RollingUpdate"
                ), f"rollout status on {targets[0]} uses OnDelete"
        else:
            assert argv[0] == "wait", argv
            assert not any(
                a in ("-l", "--selector") or a.startswith("--selector=") for a in argv
            ), argv
            if kind == "statefulset":
                assert (
                    f"--for=jsonpath={{.status.readyReplicas}}={obj['spec']['replicas']}" in argv
                ), argv
            else:
                conditions = [a for a in argv if a.startswith("--for=")]
                assert kind == "pod" and len(conditions) == 1, argv
                assert (
                    conditions[0] == "--for=create"
                    or conditions[0] == "--for=condition=Ready"
                    or conditions[0].startswith("--for=jsonpath=")
                ), argv
                if (
                    name.startswith("gateway-")
                    and objects[("statefulset", "vllm")]["spec"]["replicas"] == 0
                ):
                    assert conditions[0] != "--for=condition=Ready", argv
    return commands


class KindReadinessTests(unittest.TestCase):
    def test_every_readiness_command_matches_rendered_kind_manifest(self):
        source = (ROOT / "scripts/rehearse_eks_package_a.py").read_text(encoding="utf-8")
        commands = validate_readiness(source, source_name="rehearse_eks_package_a.py")
        self.assertEqual(len(commands), 8)
        self.assertEqual(
            [argv[2] for argv in commands if "--for=jsonpath={.status.readyReplicas}=2" in argv],
            ["statefulset/vllm", "statefulset/gateway"],
        )

    def test_row5_readiness_commands_match_rendered_row5_manifest(self):
        source = (ROOT / "scripts/rehearse_row5_kind.py").read_text(encoding="utf-8")
        manifest, _ = render_row5_manifest("mti-m5-readiness", "example.invalid/gateway:test")
        commands = validate_readiness(
            source,
            manifest,
            source_name="rehearse_row5_kind.py",
            bindings={
                "timeout": ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S,
                **{
                    name: value
                    for name, value in vars(package_a_cloud).items()
                    if name.startswith("ROW5_KIND_")
                },
            },
        )
        gateway_waits = [argv for argv in commands if any("pod/gateway-" in arg for arg in argv)]
        self.assertEqual(
            gateway_waits,
            [
                [
                    "wait",
                    "--for=create",
                    "pod/gateway-0",
                    f"--timeout={ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S}s",
                ],
                [
                    "wait",
                    "--for=jsonpath={.status.containerStatuses[0].started}=true",
                    "pod/gateway-0",
                    f"--timeout={ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S}s",
                ],
                [
                    "wait",
                    "--for=create",
                    "pod/gateway-1",
                    f"--timeout={ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S}s",
                ],
                [
                    "wait",
                    "--for=jsonpath={.status.containerStatuses[0].started}=true",
                    "pod/gateway-1",
                    f"--timeout={ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S}s",
                ],
            ],
        )
        self.assertIn(
            [
                "rollout",
                "status",
                "deployment/redis",
                f"--timeout={ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S}s",
            ],
            commands,
        )

    def test_unresolved_manifest_call_argv_mutant_fails_closed(self):
        mutant = """
def wait_for_gateway():
    argv = ["wait", "--for=create", "pod/gateway-0", "--timeout=90s"]
    _manifest_call(kubectl, kubeconfig, context, namespace, argv, timeout=95)
"""
        with self.assertRaisesRegex(AssertionError, "unresolved readiness command"):
            readiness_commands(mutant, source_name="rehearse_row5_kind.py")

    def test_row5_manifest_gateway_parallel_vllm_ordered_and_both_ondelete(self):
        manifest, _ = render_row5_manifest("mti-m5-readiness", "example.invalid/gateway:test")
        statefulsets = {
            obj["metadata"]["name"]: obj
            for obj in manifest["items"]
            if obj["kind"] == "StatefulSet"
        }
        self.assertEqual(statefulsets["gateway"]["spec"]["podManagementPolicy"], "Parallel")
        self.assertEqual(statefulsets["gateway"]["spec"]["updateStrategy"]["type"], "OnDelete")
        self.assertEqual(statefulsets["vllm"]["spec"]["podManagementPolicy"], "OrderedReady")
        self.assertEqual(statefulsets["vllm"]["spec"]["updateStrategy"]["type"], "OnDelete")

    def test_pinned_kubectl_fake_api_and_actual_replacement_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            transcript = check_api(Path(directory) / "api")
        self.assertTrue(transcript["complete"])
        self.assertEqual(
            sum(c.get("absent_wait_observed", False) for c in transcript["commands"]), 2
        )
        requests = transcript["requests"]
        self.assertTrue(
            any(
                r.get("response_code") == 404 and r["path"].endswith("/pods/vllm-0")
                for r in requests
            )
        )
        self.assertTrue(any(r.get("query", {}).get("watch") for r in requests))

    def test_missing_pinned_kubectl_is_failure(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("package_a_kind_api.ROOT", Path(directory)),
        ):
            target = Path(directory) / "deploy/k8s"
            target.mkdir(parents=True)
            (target / "pins.json").write_bytes((ROOT / "deploy/k8s/pins.json").read_bytes())
            with self.assertRaises(FileNotFoundError):
                pinned_kubectl()

    def test_same_uid_is_rejected_before_ready_at_both_sites(self):
        source = (ROOT / "scripts/rehearse_eks_package_a.py").read_text(encoding="utf-8")
        for block in replacement_blocks(source):
            calls = []
            with self.subTest(site=block[0].lineno), self.assertRaises(AssertionError):
                exec(
                    compile(ast.Module(body=block, type_ignores=[]), "<replacement>", "exec"),
                    {
                        "k": lambda *a, _calls=calls, **kw: _calls.append(a),
                        "pods": lambda: {"vllm-0": {"metadata": {"uid": "old"}}},
                        "old_uids": {"vllm-0": "old"},
                        "new_uid": "previous",
                    },
                )
            self.assertFalse(any("--for=condition=Ready" in c for c in calls))

    def test_error_identifies_actual_command(self):
        module = rehearsal()
        with patch.object(module.subprocess, "run") as run:
            run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="synthetic failure")
            with self.assertRaises(RuntimeError) as caught:
                module.run(
                    [
                        "kubectl",
                        "--kubeconfig",
                        "config",
                        "--context",
                        "kind-fixture",
                        "-n",
                        "fixture",
                        "wait",
                        "--for=jsonpath={.status.readyReplicas}=2",
                        "statefulset/vllm",
                    ]
                )
        self.assertIn("wait", str(caught.exception))
        self.assertIn("statefulset/vllm", str(caught.exception))
        self.assertNotIn("--kubeconfig", str(caught.exception))

    def test_secret_create_argv_contains_only_file_paths(self):
        module = rehearsal()
        source = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        secret_calls = [
            node
            for node in ast.walk(source)
            if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "k"
            and [getattr(a, "value", None) for a in node.args[:2]] == ["create", "secret"]
        ]
        self.assertEqual(len(secret_calls), 2)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            secret = output / "cache-salt.secret"
            module.write_kind_secret(secret)
            commands = []
            for call in secret_calls:
                exec(
                    compile(ast.Expression(call), "<secret argv>", "eval"),
                    {
                        "k": lambda *a: commands.append(a),
                        "ROOT": ROOT,
                        "secret": secret,
                        "args": SimpleNamespace(output=output),
                    },
                )
            argv = json.dumps([[str(a) for a in command] for command in commands])
            self.assertNotIn(secret.read_text().strip(), argv)
            self.assertNotIn("local-dev-token", argv)
            self.assertNotIn("--from-literal", argv)
            self.assertIn("--from-file=cache-salt.secret=", argv)
            self.assertIn("--cert", argv)
            self.assertIn("--key", argv)

    def test_four_drain_streams_cover_both_backends_for_all_gateway_parities(self):
        module = rehearsal()
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        body = next(
            node.body
            for node in ast.walk(tree)
            if isinstance(node, ast.Try)
            and any(
                isinstance(s, ast.Assert)
                and "env_values['GATEWAY_ROUTING_POLICY']" in ast.unparse(s)
                for s in node.body
            )
        )
        begin = next(
            i
            for i, s in enumerate(body)
            if isinstance(s, ast.Assert)
            and "env_values['GATEWAY_ROUTING_POLICY']" in ast.unparse(s)
        )
        end = next(i for i in range(begin, len(body)) if isinstance(body[i], ast.For))
        block = ast.Module(body=body[begin : end + 1], type_ignores=[])

        class InlineThread:
            def __init__(self, target, args):
                self.target, self.args = target, args

            def start(self):
                self.target(*self.args)

        for parity in itertools.product((0, 1), repeat=2):
            picks = dict(enumerate(parity))

            def stream(port, picks=picks):
                backend = picks[port] % 2
                picks[port] += 1
                return {"port": port, "backend": backend}

            scope = {
                "manifest": preflight_manifest(),
                "ROOT": ROOT,
                "json": json,
                "threading": SimpleNamespace(Thread=InlineThread),
                "ports": [0, 1],
                "stream": stream,
                "env_values": module.admission_settings(preflight_manifest()),
                "capacity_wait": lambda: None,
            }
            exec(compile(block, "<drain setup>", "exec"), scope)
            with self.subTest(parity=parity):
                self.assertEqual(len(scope["draining"]), 4)
                self.assertEqual(
                    {(d["port"], d["backend"]) for d in scope["draining"]},
                    set(itertools.product((0, 1), repeat=2)),
                )
            # Refuse before creating clients when the rendered admission cap drops.
            insufficient = copy.deepcopy(scope["manifest"])
            for obj in insufficient["items"]:
                if obj["kind"] == "StatefulSet" and obj["metadata"]["name"] == "gateway":
                    for env in obj["spec"]["template"]["spec"]["containers"][0]["env"]:
                        if env["name"] == "ADMISSION_RUNNING":
                            env["value"] = "1"
            with self.assertRaises(AssertionError):
                exec(
                    compile(block, "<drain admission>", "exec"),
                    {
                        **scope,
                        "manifest": insufficient,
                        "env_values": module.admission_settings(insufficient),
                    },
                )
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "deploy/local"
            config.mkdir(parents=True)
            config.joinpath("tenants.json").write_text(
                json.dumps({"tenants": [{"tenant_id": "tenant-local", "max_concurrent": 3}]})
            )
            with self.assertRaises(AssertionError):
                exec(
                    compile(block, "<tenant admission>", "exec"), {**scope, "ROOT": Path(directory)}
                )


if __name__ == "__main__":
    unittest.main()
