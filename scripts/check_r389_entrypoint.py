"""Offline R389 fallback: digest-verified OCI config, archived usage, wrapper path."""

import argparse
import ast
import hashlib
import importlib.util
import json
import sys
import tarfile
import types
from pathlib import Path
from unittest.mock import patch

from inference_platform.eks_deployment import VLLM_IMAGE, resources
from inference_platform.r1_spec import parse_engine_argv

ROOT = Path(__file__).resolve().parents[1]
PINNED = "98dff2a81d747d1dba01a47f939f48c3526d4206"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prove(image_directory, source_root, inputs):
    manifest_raw = (image_directory / "image-manifest.json").read_bytes()
    assert "sha256:" + sha(manifest_raw) == VLLM_IMAGE.rsplit("@", 1)[1]
    manifest = json.loads(manifest_raw)
    if "manifests" in manifest:
        platform = next(
            row
            for row in manifest["manifests"]
            if row.get("platform", {}).get("os") == "linux"
            and row["platform"].get("architecture") == "amd64"
        )
        raw = (image_directory / "image-linux-amd64-manifest.json").read_bytes()
        assert "sha256:" + sha(raw) == platform["digest"]
        manifest = json.loads(raw)
    config_raw = (image_directory / "image-config.json").read_bytes()
    assert "sha256:" + sha(config_raw) == manifest["config"]["digest"]
    config = json.loads(config_raw)["config"]
    assert config["Entrypoint"] == ["vllm", "serve"] and config.get("Cmd") is None
    archive = (
        ROOT / "docs/evidence/m5-l4-compatibility/execution-2026-10-26/receipts.tar.gz"
    )
    with tarfile.open(archive) as stream:
        usage = stream.extractfile("results/l4-engine.log").read()
    assert (
        sha(usage) == "812652e7fe00252f662462d5214f0ad3ec4f36e1e13977ea322146cb95eb84c6"
    )
    spec = importlib.util.spec_from_file_location(
        "r389_capture_runtime", ROOT / "deploy/eks/capture_runtime.py"
    )
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    items = resources(inputs, "runtime-code")["items"]
    container = next(
        row
        for row in items
        if row["kind"] == "StatefulSet" and row["metadata"]["name"] == "vllm"
    )["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == ["python3", "/capture-code/capture_runtime.py"]
    flags = parse_engine_argv(container["args"])
    for flag in flags:
        assert flag.encode() in usage, flag
    assert "--enable-prefix-caching | --no-enable-prefix-caching" in usage.decode()
    # Exercise the actual supervisor main -> child -> API main route with only
    # the vLLM imports replaced. This is argv forwarding, not a real vLLM parse.
    launcher = types.ModuleType("vllm.entrypoints.launchers.launcher")
    entry = types.ModuleType("vllm.entrypoints.launchers.api_server.entry")
    vllm = types.ModuleType("vllm")
    vllm.__version__ = "0.29.0"
    bindings = {}
    for module, relative, expected in (
        (launcher, "vllm/entrypoints/launchers/launcher.py", runtime.LAUNCHER_SHA256),
        (entry, "vllm/entrypoints/launchers/api_server/entry.py", runtime.ENTRY_SHA256),
    ):
        path = source_root / relative
        raw = path.read_bytes().replace(b"\r\n", b"\n")
        assert sha(raw) == expected, relative
        # Runtime hash checks read these same canonical bytes.
        assert b"\r\n" not in path.read_bytes(), "use a canonical LF source checkout"
        module.__file__ = str(path)
        bindings[relative] = expected

    class Server:
        async def startup(self):
            pass

    launcher.NoSignalServer = Server
    captured = []
    entry.main = lambda: captured.append(sys.argv.copy())
    modules = {"vllm": vllm, launcher.__name__: launcher, entry.__name__: entry}
    for name in (
        "vllm.entrypoints",
        "vllm.entrypoints.launchers",
        "vllm.entrypoints.launchers.api_server",
    ):
        modules[name] = types.ModuleType(name)
    modules["vllm.entrypoints.launchers"].launcher = launcher
    modules["vllm.entrypoints.launchers.api_server"].entry = entry

    class Supervisor:
        def __init__(self, root, uid):
            assert uid == "r389-local-proof"

        def run(self, argv):
            assert argv[2] == "--child" and argv[3:] == container["args"]
            runtime.child(Path("unused"), argv[3:])
            return 0

    with (
        patch.dict(sys.modules, modules),
        patch.dict("os.environ", {"POD_UID": "r389-local-proof"}),
        patch.object(runtime, "Supervisor", Supervisor),
        patch.object(sys, "argv", ["capture_runtime.py", *container["args"]]),
    ):
        try:
            runtime.main()
        except SystemExit as exc:
            assert exc.code == 0
    assert captured == [["vllm", *container["args"]]]
    # Pin and inspect the real parser function, rather than pretending the stub
    # imported vLLM or validated option values.
    tree = ast.parse(
        (source_root / "vllm/entrypoints/launchers/api_server/entry.py").read_bytes()
    )
    main = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    text = ast.unparse(main)
    assert "parser = make_arg_parser(parser)" in text
    assert "args = parser.parse_args()" in text
    return {
        "basis": "archived usage + digest-verified image config; real wrapper forwarding with stub imports",
        "real_image_parse": False,
        "image": VLLM_IMAGE,
        "config_sha256": sha(config_raw),
        "entrypoint": config["Entrypoint"],
        "cmd": config.get("Cmd"),
        "kubernetes_command_overrides_image_entrypoint": True,
        "argv_at_api_server_main": captured[0],
        "registered_flags_present_in_usage": list(flags),
        "usage_archive": archive.relative_to(ROOT).as_posix(),
        "usage_member": "results/l4-engine.log",
        "usage_sha256": sha(usage),
        "vllm_source_commit": PINNED,
        "source_bindings": bindings,
        "api_main": text,
        "provider_calls": 0,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-directory", type=Path, required=True)
    parser.add_argument("--vllm-source", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prove(
        args.image_directory, args.vllm_source, json.loads(args.inputs.read_bytes())
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("R389 entrypoint fallback: PASS (not an in-image parse)")
