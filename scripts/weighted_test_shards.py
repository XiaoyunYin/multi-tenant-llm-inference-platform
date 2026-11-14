"""Deterministic longest-processing-time allocation shared by CPU test runners."""


def distribute(items, count, weight, identity=lambda item: item):
    if count < 1:
        raise ValueError("test_shards:count")
    shards, totals = [[] for _ in range(count)], [0.0] * count
    for item in sorted(items, key=lambda item: (-weight(item), identity(item))):
        index = min(range(count), key=lambda index: (totals[index], index))
        shards[index].append(item)
        totals[index] += weight(item)
    return [sorted(shard, key=identity) for shard in shards]
