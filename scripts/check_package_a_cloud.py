"""No-bill DEC-077 rehearsal entrypoint; sealed plans, real processes and faults."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from inference_platform.package_a_cloud import (
    HOST_TIMER_S,
    INSTANCE_TYPE,
    run_exe,
    save,
    sha,
    utc,
)
from inference_platform.package_a_operator import ROOT, python_hashes, sealed_plans
from inference_platform.package_a_images import LINUX_E2E_IMAGE
from package_a_local_preflight import run_preflight


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tools-image", default="r87-generator-tools:local")
    parser.add_argument("--linux-e2e-image", default=LINUX_E2E_IMAGE)
    parser.add_argument("--locked-site", type=Path)
    args = parser.parse_args()
    if args.locked_site is not None and not args.locked_site.is_dir():
        raise ValueError("package_a:locked_site_missing")

    def locked_mounts():
        return (
            []
            if args.locked_site is None
            else [
                "--mount",
                f"type=bind,source={args.locked_site},target=/locked-site,readonly",
                "-e",
                "PYTHONPATH=/repo/python/src:/repo/python/tests:/locked-site",
            ]
        )

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schema": "dec077-offline-rehearsal-v1",
        "utc": utc(),
        "billable_actions": 0,
        "complete": False,
        "tools_image": args.tools_image,
        "linux_e2e_image": args.linux_e2e_image,
        "locked_site_readonly": args.locked_site is not None,
    }
    try:
        receipt["unit_and_fault_tests"] = run_exe(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "python/tests",
                "-p",
                "test_package_a_cloud.py",
                "-v",
            ],
            cwd=ROOT,
            output=output / "tests.log",
            timeout=120,
            env={**os.environ, "DEC077_FAULT_OUTPUT": str(output / "faults.json")},
        )
        receipt["faults"] = json.loads((output / "faults.json").read_bytes())
        receipt["r305_mutants"] = run_exe(
            [
                sys.executable,
                "scripts/probe_r305_mutants.py",
                "--output",
                output / "r305-mutants",
            ],
            cwd=ROOT,
            output=output / "r305-mutants.log",
            timeout=180,
        )
        receipt["r305_mutation_results"] = json.loads(
            (output / "r305-mutants/receipt.json").read_bytes()
        )
        preflight_args = (
            {}
            if args.linux_e2e_image == LINUX_E2E_IMAGE and args.locked_site is None
            else {"linux_image": args.linux_e2e_image, "locked_site": args.locked_site}
        )
        receipt["real_dependency_preflight"] = run_preflight(
            output / "real-dependency-preflight", **preflight_args
        )
        receipt["transport"] = run_exe(
            [
                sys.executable,
                "scripts/package_a_transport_rehearsal.py",
                "--output",
                output / "transport",
            ],
            cwd=ROOT,
            output=output / "transport.log",
            timeout=120,
        )
        if os.name == "nt":
            receipt["windows_ssm"] = run_exe(
                [
                    sys.executable,
                    "scripts/r1_windows_cli_rehearsal.py",
                    "--output",
                    output / "windows-ssm",
                ],
                cwd=ROOT,
                output=output / "windows-ssm.log",
                timeout=60,
            )
        head = (
            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT)
            .decode()
            .strip()
        )
        bundle_dir = output / "bundle"
        bundle_dir.mkdir()
        bare = bundle_dir / "shallow.git"
        subprocess.run(
            [
                "git",
                "clone",
                "--bare",
                "--no-local",
                "--depth",
                "1",
                ROOT.as_uri(),
                str(bare),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(bare),
                "bundle",
                "create",
                str(bundle_dir / "source.bundle"),
                "--all",
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
        (bundle_dir / "head.txt").write_text(head + "\n")
        save(bundle_dir / "python-hashes.json", python_hashes(head))
        linux = output / "linux"
        linux.mkdir()
        argv = [
            "docker",
            "run",
            "--rm",
            "--name",
            "dec077-linux-rehearsal",
            "--network",
            "none",
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "--cpus",
            "2",
            "--pids-limit",
            "128",
        ]
        for source, target in (
            (ROOT, "/repo"),
            (ROOT / ".cache/dec077-tools", "/artifacts"),
            (bundle_dir, "/bundle"),
        ):
            argv += ["--mount", f"type=bind,source={source},target={target},readonly"]
        argv += locked_mounts()
        argv += [
            "--mount",
            f"type=bind,source={linux},target=/out",
            args.tools_image,
            "/opt/r87-probe-venv/bin/python",
            "/repo/scripts/package_a_linux_rehearsal.py",
        ]
        receipt["linux"] = run_exe(
            argv, cwd=ROOT, output=output / "linux.log", timeout=300
        )
        for label, command, network in (
            (
                "linux-tests",
                [
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "python/tests",
                    "-p",
                    "test_package_a_cloud.py",
                    "-v",
                ],
                False,
            ),
            (
                "reliability",
                [
                    "scripts/package_a_reliability_rehearsal.py",
                    "--output",
                    "/out/results",
                ],
                False,
            ),
            ("bootstrap", ["scripts/package_a_bootstrap_rehearsal.py"], True),
            (
                "r226",
                ["scripts/package_a_r226_rehearsal.py", "--output", "/out/results"],
                False,
            ),
        ):
            destination = output / label
            destination.mkdir()
            container = [
                "docker",
                "run",
                "--rm",
                "--init",
                "--name",
                "dec077-" + label,
                "--memory",
                "1g" if label in {"bootstrap", "linux-tests"} else "256m",
                "--memory-swap",
                "1g" if label in {"bootstrap", "linux-tests"} else "256m",
                "--cpus",
                "2",
                "--pids-limit",
                "128",
            ]
            if not network:
                container += ["--network", "none"]
            for source, target in (
                (ROOT, "/repo"),
                (ROOT / ".cache/dec077-tools", "/artifacts"),
                (bundle_dir, "/bundle"),
            ):
                container += [
                    "--mount",
                    f"type=bind,source={source},target={target},readonly",
                ]
            container += [
                "--mount",
                f"type=bind,source={destination},target=/out",
                "-e",
                "PYTHONPATH=/repo/python/src",
                "-e",
                "PYTHONDONTWRITEBYTECODE=1",
                "-w",
                "/repo",
                args.tools_image,
                "/opt/r87-probe-venv/bin/python",
                *command,
            ]
            at = container.index(args.tools_image)
            container[at:at] = locked_mounts()
            receipt[label] = run_exe(
                container,
                cwd=ROOT,
                output=output / (label + ".log"),
                timeout=1000 if label == "bootstrap" else 150,
            )
        mismatch = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--memory",
            "192m",
            "--memory-swap",
            "256m",
            "--cpus",
            "2",
            "--pids-limit",
            "128",
            "--mount",
            f"type=bind,source={linux},target=/out",
            "-e",
            "PYTHONPATH=/out/host/repo/python/src",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "-w",
            "/out/host/repo",
            "python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d",
            "python",
            "scripts/size_inf037b_sanitized_export.py",
            "--container-mode",
            "--source-manifest",
            "/out/smoke-source.json",
            "--preflight-only",
        ]
        receipt["memory_mismatch"] = run_exe(
            mismatch,
            cwd=ROOT,
            output=output / "memory-mismatch.log",
            timeout=30,
            expected="refuse",
        )
        mismatch_log = (output / "memory-mismatch.log").read_text()
        if (
            "memory.max" not in mismatch_log
            or "differs from manifest" not in mismatch_log
        ):
            raise ValueError("mismatch_failed_for_wrong_reason")
        save(
            output / "input.tfvars.json",
            {
                "enable_task": True,
                "instance_type": INSTANCE_TYPE,
                "ami": "ami-02a9cdd4e98bc3c78",
                "session": "dec077-20261019",
                "source_commit": head,
                "root_gib": 64,
                "host_timer_seconds": HOST_TIMER_S,
            },
        )
        receipt["sealed"] = sealed_plans(output)
        receipt["plans"] = json.loads((output / "sealed-plans.json").read_bytes())
        receipt["complete"] = True
    finally:
        files = [
            ROOT / "python/src/inference_platform/package_a_cloud.py",
            ROOT / "python/src/inference_platform/package_a_operator.py",
            ROOT / "python/src/inference_platform/package_a_secrets.py",
            ROOT / "python/tests/test_package_a_cloud.py",
            *sorted((ROOT / "scripts").glob("package_a_*.py")),
            ROOT / "scripts/probe_r305_mutants.py",
            ROOT / "scripts/rehearse_eks_package_a.py",
            ROOT / "scripts/package-a-cloud.ps1",
            ROOT / "scripts/package_a_bootstrap.sh",
            *sorted((ROOT / "infra/terraform/package_a").glob("*.tf")),
            ROOT / "infra/terraform/package_a/user-data.sh",
            Path(__file__),
            ROOT / "deploy/package-a/routine-tools.Dockerfile",
        ]
        receipt["working_source_sha256"] = {
            str(p.relative_to(ROOT)).replace("\\", "/"): sha(p) for p in files
        }
        save(output / "rehearsal.json", receipt)
    print(
        json.dumps(
            {
                "complete": receipt["complete"],
                "faults": len(receipt["faults"]),
                "create_sha256": receipt["plans"]["create_sha256"],
                "destroy_sha256": receipt["plans"]["destroy_sha256"],
            }
        )
    )


if __name__ == "__main__":
    main()
