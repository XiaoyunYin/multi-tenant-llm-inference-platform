"""Verify setup receipts against staged/committed Git blobs, never working bytes."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = "docs/evidence/m5-package-b4b-setup"
NAMES = (
    "setup-linux.json",
    "setup-native.json",
    "collectors-linux.json",
    "lifecycle-validation.json",
    "regression-linux.json",
    "integration-linux.json",
    "terminal-linux.json",
    "controller-mutants.json",
    "placement-mutants.json",
    "local-checks.json",
)


def git_blob(revision, path):
    return subprocess.check_output(["git", "show", f"{revision}:{path}"], cwd=ROOT)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def receipt_inputs(receipt, name):
    if "inputs" in receipt:
        return receipt["inputs"]
    module = "controller" if name.startswith("controller") else "placement"
    assert receipt["baseline"] == "PASS", name
    return {
        f"python/src/inference_platform/inf037b_{module}.py": receipt[
            module + "_lf_sha256"
        ],
        f"python/tests/test_inf037b_{module}.py": receipt["tests_lf_sha256"],
    }


def inspect(directory, revision):
    inputs, summaries, readiness = {}, {}, []
    expected = {
        "collectors-linux.json": 49,
        "setup-linux.json": 9,
        "setup-native.json": 8,
        "regression-linux.json": 231,
        "lifecycle-validation.json": 60,
        "integration-linux.json": 11,
        "terminal-linux.json": 18,
    }
    for name in NAMES:
        receipt = json.loads((directory / name).read_bytes())
        for path, value in receipt_inputs(receipt, name).items():
            assert path not in inputs or inputs[path] == value, (
                "inconsistent input",
                name,
                path,
            )
            assert digest(git_blob(revision, path)) == value, (
                "Git input mismatch",
                name,
                path,
            )
            inputs[path] = value
        if "tests" in receipt:
            assert (
                receipt["tests"] > 0
                and receipt["skips"] == 0
                and not receipt["failures"]
            ), name
            if name in expected:
                assert receipt["tests"] == expected[name], name
            summaries[name] = {
                k: receipt[k] for k in ("tests", "skips", "failures", "elapsed_ms")
            }
        elif "mutants" in receipt:
            survivors = [m for m in receipt["mutants"] if not m["killed"]]
            assert len(survivors) == (5 if name.startswith("controller") else 1), name
            assert all(m.get("survivor_reason") for m in survivors), name
            summaries[name] = {
                "total": len(receipt["mutants"]),
                "killed": sum(m["killed"] for m in receipt["mutants"]),
                "justified_survivors": len(survivors),
            }
            if name.startswith("controller"):
                readiness = [
                    m
                    for m in receipt["mutants"]
                    if "controller:readiness_cutoff" in m["check"]
                    and str(m.get("expected_test", "")).startswith(
                        "test_fallback_acquire_readiness_cutoff"
                    )
                ]
                assert len(readiness) == 3 and all(m["killed"] for m in readiness)
        else:
            assert receipt["checks"] and all(
                c["exit_code"] == 0 for c in receipt["checks"]
            ), name
            summaries[name] = {"checks": len(receipt["checks"]), "all_passed": True}
    for path in (
        "python/tests/fixtures/inf037b_gateway_sse.json",
        "scripts/check_inf037b_setup_receipts.py",
        "docs/INF037B_REGISTRATION_V4.md",
        "docs/INF037B_PRE_REGISTRATION.md",
    ):
        inputs[path] = digest(git_blob(revision, path))
    assert (
        inputs["docs/INF037B_REGISTRATION_V4.md"]
        == "b3e3fddb1a3a8b02d06d8e243a9afd829c200f5e9602fa0d42ba8fa1bd97c62a"
    )
    assert git_blob(revision, "docs/INF037B_REGISTRATION_V4.md") == git_blob(
        "619d2c5c6e6d243728e203a97fca3ca90d6f03a6", "docs/INF037B_REGISTRATION_V4.md"
    )
    protected = [
        "authority",
        "ports",
        "durable_ports",
        "attempts",
        "resolver",
        "lifecycle",
        "integration",
        "terminal",
    ]
    for module in protected:
        path = f"python/src/inference_platform/inf037b_{module}.py"
        assert git_blob(revision, path) == git_blob(
            "36a0bf67452540d39d5bded7bb6932f25f009b09", path
        ), path
    return {
        "inputs": inputs,
        "summaries": summaries,
        "acquire_readiness_mutants": readiness,
        "protected_modules_unchanged": protected,
        "base": "36a0bf67452540d39d5bded7bb6932f25f009b09",
        "Git_blob_inputs_verified": True,
        "paid_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / PACKET)
    parser.add_argument(
        "--revision",
        default="",
        help="Empty means the Git index; HEAD verifies a commit",
    )
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = inspect(args.directory, args.revision)
    if args.write:
        (args.directory / "receipt-inspection.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        names = (*NAMES, "receipt-inspection.json")
        (args.directory / "SHA256SUMS").write_text(
            "".join(
                digest((args.directory / name).read_bytes()) + "  " + name + "\n"
                for name in sorted(names)
            ),
            encoding="utf-8",
            newline="\n",
        )
    else:
        for line in (args.directory / "SHA256SUMS").read_text().splitlines():
            wanted, name = line.split("  ")
            assert digest(git_blob(args.revision, PACKET + "/" + name)) == wanted, name
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
