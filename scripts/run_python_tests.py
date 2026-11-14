"""Run deterministic whole-module shards whose union is unittest discovery."""

import argparse
import json
import sys
from pathlib import Path

from cpu_test_runner import run_modules
from weighted_test_shards import distribute

WEIGHT_DATA = json.loads(
    (
        Path(__file__).resolve().parents[1] / "deploy/package-a/cpu-test-weights.json"
    ).read_bytes()
)
WEIGHTS_S = {name: row["weight_s"] for name, row in WEIGHT_DATA["modules"].items()}


def weighted_shards(paths, count):
    if count < 2:
        raise ValueError("weighted CPU validation requires at least two shards")
    for path in paths:
        if path.name not in WEIGHTS_S:
            raise ValueError("cpu_weights:missing:" + path.name)
    shards, totals = [[] for _ in range(count)], [0] * count
    others = []
    for path in paths:
        if path.name == "test_inf037b_collectors.py":
            shards[0].append(path)
            totals[0] += WEIGHTS_S[path.name]
        else:
            others.append(path)
    for index, shard in enumerate(
        distribute(others, count - 1, lambda p: WEIGHTS_S[p.name], lambda p: p.name), 1
    ):
        shards[index].extend(shard)
    return [sorted(shard) for shard in shards]


def modules(directory, index, count, *, weighted=False):
    if count <= 0 or not 0 <= index < count:
        raise ValueError("invalid shard")
    paths = sorted(Path(directory).glob("test*.py"))
    return weighted_shards(paths, count)[index] if weighted else paths[index::count]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--weighted", action="store_true")
    parser.add_argument("--ceiling", type=int)
    args = parser.parse_args()
    directory = Path("python/tests").resolve()
    sys.path.insert(0, str(directory))
    selected = modules(directory, args.index, args.count, weighted=args.weighted)
    print(
        json.dumps(
            {
                "shard": args.index,
                "count": args.count,
                "modules": [p.name for p in selected],
                "weights_s": {p.name: WEIGHTS_S[p.name] for p in selected}
                if args.weighted
                else {},
                "weight_basis": WEIGHT_DATA["basis"],
                "ceiling_s": args.ceiling,
            }
        ),
        flush=True,
    )
    result = run_modules(
        [p.stem for p in selected],
        dump_after=max(1, args.ceiling - 30) if args.ceiling else None,
    )
    return int(not result.wasSuccessful())


if __name__ == "__main__":
    raise SystemExit(main())
