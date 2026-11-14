"""Build a review-only L4 packet. No AWS SDK, CLI, reservation or Apply path."""

import argparse
import io
import json
import subprocess
import tarfile
from pathlib import Path

from inference_platform import inf037b_native
from inference_platform.inf037b_archive import encode, file_facts, sha
from inference_platform.l4_compat import HOST_TIMER_S, PINS, requests, worksheet
from inference_platform.package_a_cloud import save

ROOT = Path(__file__).resolve().parents[1]


def prepare(output, vllm_source, base_commit=None):
    output.mkdir(parents=True, exist_ok=False)
    overlay = output / "overlay"
    manifest = inf037b_native.build_overlay(vllm_source, overlay)
    names = (
        subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
        )
        .decode()
        .split("\0")
    )
    sources = {}
    for name in sorted(set(names)):
        if not name or not (ROOT / name).is_file():
            continue
        if name.startswith(
            (
                "python/",
                "cmd/",
                "internal/",
                "infra/terraform/l4_compat/",
                "scripts/l4_compat",
            )
        ) or name in (
            "go.mod",
            "go.sum",
            "deploy/eks/capture_runtime.py",
            "scripts/prepare_l4_compat.py",
            "scripts/finalize_l4_compat.py",
            "scripts/l4_compat_host.py",
            "scripts/l4_compat_container.py",
            "scripts/check_l4_compat.py",
            "scripts/rehearse_l4_compat.py",
            "scripts/l4_compat_bootstrap.sh",
            "scripts/l4_compat_deadline.py",
            "scripts/l4_compat_service.py",
            "scripts/l4_compat_controller.py",
            "scripts/package_a_host.py",
            "scripts/package_a_sealed.py",
        ):
            if "__pycache__" not in name and "/.terraform/" not in name:
                sources[name] = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
    for name, data in {
        p.relative_to(output).as_posix(): p.read_bytes()
        for p in overlay.rglob("*")
        if p.is_file()
    }.items():
        sources[name] = data
    source_manifest = {
        name: {"sha256": sha(data), "bytes": len(data)}
        for name, data in sources.items()
    }
    save(output / "sources.json", source_manifest)
    tools = json.loads((ROOT / ".cache/dec077-tools/artifacts.json").read_bytes())
    save(output / "tools.json", {name: tools[name] for name in ("go", "python")})
    save(output / "requests.json", requests())
    spec = {
        "schema": "single-l4-compatibility-v1",
        "pins": PINS,
        "sources_sha256": sha(encode(source_manifest)),
        "overlay": manifest,
        "requests_sha256": sha(encode(requests())),
        "approval": "Claude committed exact-plan review, then Xiaoyun exact-hash approval; no marker or Apply now",
        "provider_calls": 0,
        "scope": "seven requests; sequential slot aliases on one engine; no EKS/two-slot fitness/R366 acceptance",
    }
    save(output / "packet.json", spec)
    for name in ("sources.json", "requests.json", "packet.json", "tools.json"):
        sources[name] = (output / name).read_bytes()
    with (output / "payload.tar.gz").open("wb") as raw:
        import gzip

        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                for name, data in sorted(sources.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(data), 0o644
                    archive.addfile(info, io.BytesIO(data))
    facts = file_facts(output / "payload.tar.gz")
    save(output / "worksheet.json", worksheet(facts["bytes"]))
    save(
        output / "payload-receipt.json",
        {
            **facts,
            "sources_sha256": spec["sources_sha256"],
            "source_base_commit": base_commit
            or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT)
            .decode()
            .strip(),
            "basis": "exact LF working snapshot; commit/blob join required before handoff",
            "provider_calls": 0,
        },
    )
    save(
        output / "input.tfvars.json",
        {
            "enable_task": True,
            "ami": PINS["ami"],
            "instance_type": PINS["instance_type"],
            "root_gib": PINS["root_gib"],
            "host_timer_seconds": HOST_TIMER_S,
            "session": "dec077-l4-20261026",
            "source_sha256": spec["sources_sha256"],
        },
    )
    return spec


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vllm-source", type=Path, required=True)
    parser.add_argument(
        "--base-commit",
        help="Committed historical base for an uncommitted exact-source snapshot",
    )
    args = parser.parse_args()
    print(
        json.dumps(prepare(args.output, args.vllm_source, args.base_commit), indent=2)
    )
