"""Compare actual baseline/candidate artifacts after the timed jobs finish."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "python/src"))
from inference_platform import inf037b_archive as archive  # noqa: E402


def compare(baseline, candidate):
    results = []
    for fraction in (5, 10, 25):
        roots = [root / f"safe-{fraction}" for root in (baseline, candidate)]
        observed = []
        for root in roots:
            archive.verify_archive(root)
            observed.append(
                {
                    p.relative_to(root).as_posix(): archive.file_facts(p)
                    for p in sorted(root.rglob("*"))
                    if p.is_file()
                }
            )
        if observed[0] != observed[1]:
            raise RuntimeError(
                f"candidate artifact differs from accepted output: {fraction}%"
            )
        results.append(
            {
                "fraction_percent": fraction,
                "equal": True,
                "files": len(observed[0]),
                "bytes": sum(v["bytes"] for v in observed[0].values()),
                "inventory": observed[0],
            }
        )
    return {
        "schema": "inf037b-r366-byte-comparison-v1",
        "source_sha256": {
            str(p.relative_to(REPO)).replace("\\", "/"): hashlib.sha256(
                p.read_bytes()
            ).hexdigest()
            for p in (Path(__file__), Path(archive.__file__))
        },
        "results": results,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(compare(args.baseline, args.candidate), indent=2) + "\n"
    )
    print("All three exports independently verified and byte-identical")
