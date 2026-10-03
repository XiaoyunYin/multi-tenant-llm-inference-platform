"""Clock provenance and precision checks for experiment artifacts."""

import time
from typing import Any


def measurement_clocks(*, wall_clock: bool = False) -> dict[str, Any]:
    """Reject coarse interval timing; explicitly label coarse wall conversion."""
    names = ("perf_counter", "time") if wall_clock else ("perf_counter",)
    clocks = {name: vars(time.get_clock_info(name)).copy() for name in names}
    limit = 0.001
    if clocks["perf_counter"]["resolution"] > limit:
        raise RuntimeError("perf_counter resolution is coarser than 1 ms; refusing measurement")
    warnings = []
    if wall_clock and clocks["time"]["resolution"] > limit:
        warnings.append(
            "COARSE_WALL_CLOCK: wall-to-perf_counter conversion includes wall-clock "
            "quantization coarser than 1 ms; event lag is not sub-ms evidence"
        )
    return {
        "interval_clock": "perf_counter",
        "deadline_clock": "perf_counter",
        "resolution_limit_seconds": limit,
        "clocks": clocks,
        "measurement_warnings": warnings,
    }
