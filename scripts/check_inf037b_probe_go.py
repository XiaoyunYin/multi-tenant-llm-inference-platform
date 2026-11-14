"""Only the new upstream-close source/ownership checks; summary receipts only."""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = "TestGatewayCancellationReachesUpstream|TestUpstreamCloseCaptureConcurrentOwnersAndResult"


def run(overlay=None):
    command = ["go", "test", "-json", "-count=1"]
    if overlay:
        command.append("-overlay=" + str(overlay))
    command.extend(["./internal/gateway", "-run", TESTS])
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        timeout=120,
        env={**os.environ, "GOFLAGS": "-buildvcs=false"},
    )
    events = [
        json.loads(line) for line in result.stdout.splitlines() if line.startswith(b"{")
    ]
    return {
        "command": command,
        "exit_code": result.returncode,
        "pass": sum(e["Action"] == "pass" and bool(e.get("Test")) for e in events),
        "skip": sum(e["Action"] == "skip" for e in events),
        "failures": [e.get("Test", "package") for e in events if e["Action"] == "fail"],
        "log_sha256": hashlib.sha256(result.stdout + result.stderr).hexdigest(),
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    baseline = run()
    assert (
        baseline["exit_code"] == 0 and baseline["pass"] == 2 and baseline["skip"] == 0
    )
    summary = {
        "schema": "inf037b-probe-go-mutations-v1",
        "baseline": baseline,
        "mutants": [],
    }
    cases = [
        (
            "handler.go",
            "omit upstream-close source event",
            'Record("upstream_close",',
            'Record("omitted_upstream_close",',
        ),
        (
            "upstream_capture.go",
            "close without shared single owner",
            """func (b *capturedUpstreamBody) Close() error {
	b.once.Do(func() {
		b.closing()
		b.err = b.ReadCloser.Close()
	})
	return b.err
}""",
            """func (b *capturedUpstreamBody) Close() error {
	b.closing()
	return b.ReadCloser.Close()
}""",
        ),
    ]
    for name, label, original, replacement in cases:
        path = ROOT / "internal/gateway" / name
        source = path.read_text()
        assert source.count(original) == 1
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            changed = source.replace(original, replacement)
            target = temp / name
            target.write_text(changed)
            overlay = temp / "overlay.json"
            overlay.write_text(
                json.dumps({"Replace": {str(path.resolve()): str(target.resolve())}})
            )
            result = run(overlay)
        killed = (
            result["exit_code"] != 0
            and bool(result["failures"])
            and result["skip"] == 0
        )
        summary["mutants"].append(
            {
                "file": path.relative_to(ROOT).as_posix(),
                "label": label,
                "original": original,
                "replacement": replacement,
                "killed": killed,
                "source_lf_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "mutated_lf_sha256": hashlib.sha256(changed.encode()).hexdigest(),
                **result,
            }
        )
    summary["killed"] = sum(m["killed"] for m in summary["mutants"])
    summary["survivors"] = len(cases) - summary["killed"]
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(
        json.dumps(
            {
                "baseline_pass": baseline["pass"],
                "killed": summary["killed"],
                "survivors": summary["survivors"],
            }
        )
    )
    assert summary["survivors"] == 0


if __name__ == "__main__":
    main()
