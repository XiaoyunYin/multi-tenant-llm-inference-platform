"""Offline R149 regression: actual da8209e Session versus the current Session."""

import argparse
import hashlib
import json
import subprocess
import types
from pathlib import Path

from inference_platform.r1_fake import Fake
from inference_platform.r1_rehearsal import verify
from inference_platform.r1_session import Session
from inference_platform.r1_spec import encoded

OLD_HEAD = "da8209eedd9c97574385990b8de838d524187aed"


class NinthCandidate(Fake):
    """Keep eight deliberately invalid candidates to exercise all nine waits."""

    def phase(self, *args, **kwargs):
        result = super().phase(*args, **kwargs)
        if args[0].startswith("candidate-") and args[0] != "candidate-W4-f1.25":
            result["resources_valid"] = False
        return result


def rehearsal(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    old_source = subprocess.check_output(
        ["git", "show", f"{OLD_HEAD}:python/src/inference_platform/r1_session.py"],
        cwd=root,
    )
    old_module = types.ModuleType("inference_platform.r149_old_session")
    old_module.__package__ = "inference_platform"
    exec(compile(old_source, f"{OLD_HEAD}:r1_session.py", "exec"), old_module.__dict__)
    cases = {}
    for label, implementation, adapter in (
        ("old", old_module.Session, Fake),
        ("fixed", Session, Fake),
        ("fixed-nine-candidates", Session, NinthCandidate),
    ):
        io = adapter("success")
        session = implementation(
            io, {"manifest_sha256": "fixture"}, output / label, head=label
        )
        result = session.run()
        if label == "old":
            assert result["error"] == "configuration refused while work remains", (
                result["error"]
            )
            assert len(io.configurations) == 1
            assert all(not slot["consumed"] for slot in result["slots"])
        else:
            assert result["error"] is None, result["error"]
            verify(output / label, "success")
        frozen = next(
            (e for e in session.events if e["event"] == "calibration_frozen"), None
        )
        waits = [e for e in session.events if e["event"] == "calibration_idle_wait"]
        if label != "old":
            assert frozen["elapsed_s"] < 2700
            assert len(waits) == (9 if label == "fixed-nine-candidates" else 1)
            assert all(e["success"] and e["consecutive_zero_polls"] == 3 for e in waits)
        cases[label] = {
            "error": result["error"],
            "configurations_accepted": len(io.configurations),
            "completed_comparisons": len(result["runs"]),
            "calibration_elapsed_s": frozen["elapsed_s"]
            if frozen
            else result["elapsed_s"],
            "session_elapsed_s": result["elapsed_s"],
            "timeline": [
                e
                for e in session.events
                if e["event"]
                in {"phase_record", "calibration_idle_wait", "calibration_frozen"}
                and (
                    frozen is None
                    or e["session_elapsed_s"] <= frozen["session_elapsed_s"]
                )
            ],
        }
    receipt = {
        "old_session_head": OLD_HEAD,
        "old_session_sha256": hashlib.sha256(old_source).hexdigest(),
        "fixed_session_sha256": hashlib.sha256(
            (root / "python/src/inference_platform/r1_session.py")
            .read_bytes()
            .replace(b"\r\n", b"\n")
        ).hexdigest(),
        "fake_sha256": hashlib.sha256(
            (root / "python/src/inference_platform/r1_fake.py")
            .read_bytes()
            .replace(b"\r\n", b"\n")
        ).hexdigest(),
        "fake_uncached_request_s": 0.27,
        "fixture_only": True,
        "cases": cases,
    }
    (output / "receipt.json").write_bytes(encoded(receipt) + b"\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(rehearsal(args.output), indent=2))
