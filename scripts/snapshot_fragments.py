"""Pinned gitleaks fragment coordinates; no scanner modification or value output."""

import hashlib
import json
import os
import subprocess

MODULE = "github.com/zricethezav/gitleaks/v8"
VERSION = "v8.30.0"
MODULE_SUM = "h1:5heLlxRQkHfXgTJgdQsJhi/evX1oj6i+xBanDu2XUM8="
MOD_SUM = "h1:M5JQW5L+vZmkAqs9EX29hFQnn7uFz9sOQCPNewaZD9E="
TARGETS = (
    "scripts/tests/fixtures/gitleaks-8.30-r371-spans.json",
    "experiments/inf037a/kind-2026-10-02-r090/observations.json",
    *(f"experiments/r0/attempt7/run-{n}.digest.json.gz" for n in (1, 2, 4)),
)


def provenance(view, cache, helper_bytes, image):
    targets = [path for path in TARGETS if (view / path).is_file()]
    if not targets:
        return {"files": {}}
    tool = cache / "fragment-tool"
    tool.mkdir()
    (tool / "main.go").write_bytes(helper_bytes)
    (tool / "go.mod").write_text(
        f"module scanner-provenance\n\ngo 1.26.6\n\nrequire {MODULE} {VERSION}\n"
    )
    env = {
        **os.environ,
        "GOWORK": "off",
        "GOTOOLCHAIN": "local",
        "GOPROXY": "https://proxy.golang.org",
        "GOSUMDB": "sum.golang.org",
        "GONOSUMDB": "",
        "GONOPROXY": "",
        "GOPRIVATE": "",
        "GOFLAGS": "",
        "CGO_ENABLED": "0",
        "GOOS": "linux",
        "GOARCH": "amd64",
    }
    downloaded = json.loads(
        subprocess.check_output(
            ["go", "mod", "download", "-json", MODULE + "@" + VERSION],
            cwd=tool,
            env=env,
        )
    )
    if downloaded.get("Sum") != MODULE_SUM or downloaded.get("GoModSum") != MOD_SUM:
        raise ValueError("snapshot:fragment_module_pin")
    binary = tool / "provenance"
    subprocess.run(
        ["go", "build", "-mod=mod", "-o", str(binary), "."],
        cwd=tool,
        env=env,
        check=True,
    )
    result = json.loads(
        subprocess.check_output(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--entrypoint=/tool/provenance",
                "--mount",
                f"type=bind,src={tool},dst=/tool,readonly",
                "--mount",
                f"type=bind,src={view},dst=/source,readonly",
                image,
                "/source",
                *targets,
            ]
        )
    )
    if result["go_version"] != "go1.26.6":
        raise ValueError("snapshot:fragment_go_pin")
    if set(targets) - result["files"].keys():
        raise ValueError("snapshot:fragment_file_coverage")
    result.update(
        module=MODULE,
        version=VERSION,
        module_sum=MODULE_SUM,
        go_mod_sum=MOD_SUM,
        helper_sha256=hashlib.sha256(helper_bytes).hexdigest(),
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        go_sum_sha256=hashlib.sha256((tool / "go.sum").read_bytes()).hexdigest(),
        image=image,
        network="none",
        readonly=True,
    )
    return result
