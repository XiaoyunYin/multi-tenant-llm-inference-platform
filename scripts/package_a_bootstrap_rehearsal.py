"""Literal bootstrap under env -i; clean exact source and missing-export control."""

import json
import shutil
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, "/repo/python/src")
sys.path.insert(0, "/repo/scripts")
from inference_platform.package_a_cloud import TASK_CHECKS, run_exe, save, sha  # noqa: E402
from package_a_host import Host, host_environment  # noqa: E402

BARE_ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


def bootstrap_command(script, runtime, output, *, with_environment=True):
    environment = host_environment() if with_environment else BARE_ENVIRONMENT
    return [
        "env",
        "-i",
        *(name + "=" + value for name, value in environment.items()),
        "sh",
        str(script),
        str(runtime),
        str(output),
    ]


def main():
    out = Path("/out")
    out.mkdir(exist_ok=True)
    root = Path("/opt/dec077")
    root.mkdir(parents=True)
    head = Path("/bundle/head.txt").read_text().strip()
    pins = json.loads(Path("/repo/deploy/package-a/pins.json").read_bytes())
    manifest = {
        "source_commit": head,
        "python_sha256": json.loads(Path("/bundle/python-hashes.json").read_bytes()),
        "pins": pins,
        "checks": list(TASK_CHECKS),
        "instance_type": "bootstrap-stand-in-not-EC2",
        "ami": "not-EC2",
        "on_demand_usd_per_hour": 0,
        "python_executable": "/opt/dec077/repo/python/.venv/bin/python",
        "deadline_epoch": 0,
    }
    host = Host(root, "fixture-not-a-cloud-token", "unused", time.time() + 120)
    host.manifest = {**manifest, "bundle_sha256": sha("/bundle/source.bundle")}
    shutil.copyfile("/bundle/source.bundle", host.partial)
    staged = host.dispatch("/stage", b"", {})
    repo = host.repo
    save(out / "runtime.json", manifest)
    downloads = root / "downloads"
    downloads.mkdir()
    for name, item in pins.items():
        if isinstance(item, dict):
            shutil.copyfile(Path("/artifacts") / name, downloads / name)
            if sha(downloads / name) != item["sha256"]:
                raise AssertionError("preplaced_archive_hash")
    tools = Path("/tmp/boot-tools")
    tools.mkdir()
    with tarfile.open("/artifacts/python") as archive:
        archive.extractall(tools, filter="data")
    # Only apt/systemd are fixture-bound. The child gets the real agent's env.
    Path("/usr/sbin/python3").symlink_to(tools / "python/bin/python3.12")
    for name in ("apt-get", "systemctl"):
        path = Path("/usr/sbin") / name
        path.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> /out/service-fixtures.log\n')
        path.chmod(0o755)
    literal = repo / "scripts/package_a_bootstrap.sh"
    results = {}
    for name in ("without-exports", "clean"):
        results[name] = run_exe(
            bootstrap_command(
                literal,
                out / "runtime.json",
                out / name,
                with_environment=name == "clean",
            ),
            cwd=repo,
            output=out / (name + ".log"),
            timeout=900,
            expected="refuse",
        )
    failure = (out / "without-exports.log").read_text()
    if not any(word in failure for word in ("HOME", "GOPATH", "GOCACHE")):
        raise AssertionError("missing_exports_control_failed_for_wrong_reason")
    runner = json.loads((out / "clean/runner/runner.json").read_bytes())
    if runner["source"]["commit"] != head or not runner["checks"][0].get("sample"):
        raise AssertionError("bootstrap_did_not_reach_verified_source_and_first_gate")
    if any(row["status"] == "PASS" for row in runner["checks"]):
        raise AssertionError("expired_rehearsal_must_not_execute_checks")
    if not (repo / ".cache/kind-build/gateway").is_file():
        raise AssertionError("real_go_build_missing")
    save(
        out / "bootstrap-rehearsal.json",
        {
            "results": results,
            "source_head": head,
            "staged": staged,
            "literal_bootstrap_sha256": sha(literal),
            "pins_unchanged_sha256": sha(repo / "deploy/package-a/pins.json"),
            "launch_environment": host_environment(),
            "negative_launch_environment": BARE_ENVIRONMENT,
            "verified_source": "PASS",
            "uv_sync_go_mod_download_go_build": "real",
            "first_gate_sample": runner["checks"][0]["sample"],
            "check_distribution": [row["status"] for row in runner["checks"]],
            "prepare_images": runner["prepare_images"],
            "negative_without_exports": "REFUSED",
            "billable_actions": 0,
            "fixtures": [
                "apt-get",
                "systemctl",
                "hash-verified archives preplaced at production cache paths",
                "expired work admission",
            ],
        },
    )


if __name__ == "__main__":
    main()
