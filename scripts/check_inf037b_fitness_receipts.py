"""Join the Round263 offline fitness receipts to actual index/commit Git blobs."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = "docs/evidence/m5-package-b4b-fitness"
BASE = "f5024845d45947f247a650b90d6504ffc656b6ce"
NAMES = (
    "setup-linux.json",
    "setup-native.json",
    "fitness-core-linux.json",
    "regression-linux.json",
    "lifecycle-validation.json",
    "integration-linux.json",
    "terminal-linux.json",
    "local-checks.json",
)
PROTECTED = (
    "controller",
    "placement",
    "contract",
    "authority",
    "ports",
    "durable_ports",
    "attempts",
    "resolver",
    "lifecycle",
    "integration",
    "terminal",
)


def blob(revision, path):
    return subprocess.check_output(["git", "show", f"{revision}:{path}"], cwd=ROOT)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect(directory, revision):
    inputs, summaries = {}, {}
    counts = {
        "setup-linux.json": 21,
        "setup-native.json": 20,
        "fitness-core-linux.json": 18,
        "regression-linux.json": 231,
        "lifecycle-validation.json": 60,
        "integration-linux.json": 11,
        "terminal-linux.json": 18,
    }
    for name in NAMES:
        receipt = json.loads((directory / name).read_bytes())
        for path, value in receipt["inputs"].items():
            assert path not in inputs or inputs[path] == value, (
                "inconsistent source",
                name,
                path,
            )
            assert digest(blob(revision, path)) == value, (
                "Git source mismatch",
                name,
                path,
            )
            inputs[path] = value
        if "tests" in receipt:
            assert receipt["tests"] == counts[name], name
            assert (
                receipt["tests"] > 0
                and receipt["skips"] == 0
                and not receipt["failures"]
            ), name
            if name.endswith("linux.json") or name == "lifecycle-validation.json":
                assert (
                    receipt["platform"] == "Linux" and receipt["python"] == "3.12.7"
                ), name
            summaries[name] = {
                k: receipt[k] for k in ("tests", "skips", "failures", "elapsed_ms")
            }
        else:
            assert receipt["checks"] and all(
                c["exit_code"] == 0 for c in receipt["checks"]
            ), name
            summaries[name] = {"checks": len(receipt["checks"]), "all_passed": True}
    for module in PROTECTED:
        path = f"python/src/inference_platform/inf037b_{module}.py"
        assert blob(revision, path) == blob(BASE, path), path
    registration = "docs/INF037B_REGISTRATION_V4.md"
    assert (
        digest(blob(revision, registration))
        == "b3e3fddb1a3a8b02d06d8e243a9afd829c200f5e9602fa0d42ba8fa1bd97c62a"
    )
    assert blob(revision, registration) == blob("619d2c5", registration)
    for path in (
        "scripts/check_inf037b_fitness_receipts.py",
        "docs/INF037B_PRE_REGISTRATION.md",
    ):
        inputs[path] = digest(blob(revision, path))
    cases = json.loads((directory / "setup-linux.json").read_bytes())["cases"]
    assert any(c.get("case") == "process_setup_none" for c in cases)
    assert any(c.get("case") == "process_setup_fitness_signal" for c in cases)
    assert any(c.get("case") == "process_setup_fitness_control" for c in cases)
    assert any(
        c.get("nonmutating") is True
        and set(c.get("rows", {}))
        == {"sse", "equivalence", "publication", "clocks", "ingress"}
        for c in cases
    )
    return {
        "inputs": inputs,
        "summaries": summaries,
        "base": BASE,
        "unchanged_modules": PROTECTED,
        "mutation_rerun": "not required: controller and placement Git blobs unchanged; prior results remain historical",
        "Git_blob_inputs_verified": True,
        "paid_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / PACKET)
    parser.add_argument(
        "--revision", default="", help="Empty = Git index; HEAD = committed target"
    )
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = inspect(args.directory, args.revision)
    if args.write:
        (args.directory / "receipt-inspection.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        (args.directory / "SHA256SUMS").write_text(
            "".join(
                digest((args.directory / name).read_bytes()) + "  " + name + "\n"
                for name in sorted((*NAMES, "receipt-inspection.json"))
            ),
            encoding="utf-8",
            newline="\n",
        )
    else:
        for line in (args.directory / "SHA256SUMS").read_text().splitlines():
            wanted, name = line.split("  ")
            assert digest(blob(args.revision, PACKET + "/" + name)) == wanted, name
    print(
        json.dumps(
            {
                "source_inputs": len(result["inputs"]),
                "receipts": len(NAMES) + 1,
                "summaries": result["summaries"],
            }
        )
    )


if __name__ == "__main__":
    main()
