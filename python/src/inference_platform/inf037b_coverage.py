"""Registration-v3 periodic coverage, derived from archived source inventory.

The spec cannot choose sources, event types, cadences, windows or exemptions.
Only independently captured lifecycle endpoints waive a vLLM UID's absence.
"""

from .inf037b_contract import GATEWAYS
from .inf037b_sources import carries_observation


def _pre_metrics_absence(rows, uid, start_ms, end_ms):
    """A cumulative lifecycle receipt proves no metrics server since UID creation.

    This is not a failed scrape or an ordinary container-state snapshot. The live
    producer must retain the complete independent lifecycle evidence it attests.
    Only the receipt's lower clock bound is proven; contradictory observations
    prevent the waiver rather than being hidden by it.
    """
    lifecycle = [
        r
        for r in rows
        if r["source_kind"] == "kubernetes"
        and r["payload"].get("pod_uid") == uid
        and r["time_ms_bounds"]
        and r.get("error") is None
        and r.get("missing_reason") is None
    ]
    created = [r for r in lifecycle if r["payload"]["event"] == "pod_created"]
    if len(created) != 1:
        return [], []
    proofs = [
        r
        for r in lifecycle
        if r["payload"]["event"] == "container_state"
        and r["payload"].get("container_state") == "metrics_not_started"
        and r["payload"].get("reason") == "continuous_lifecycle_since_pod_creation"
        and r["time_ms_bounds"][0] >= created[0]["time_ms_bounds"][1]
        and r["time_ms_bounds"][1] <= end_ms
    ]
    if not proofs:
        return [], []
    proof = max(proofs, key=lambda r: r["time_ms_bounds"][0])
    until = proof["time_ms_bounds"][0]
    # A later receipt cannot repair known loss in its claimed continuous history.
    # Unknown time bounds cannot establish that the loss happened after it.
    if any(
        r["source_kind"] == "kubernetes"
        and r["payload"].get("pod_uid") == uid
        and (r.get("error") is not None or r.get("missing_reason") is not None)
        and (not r["time_ms_bounds"] or r["time_ms_bounds"][0] <= until)
        for r in rows
    ):
        return [], []
    if any(
        r["time_ms_bounds"]
        and r["time_ms_bounds"][0] <= until
        and r["payload"].get("pod_uid") == uid
        and (
            r["source_kind"] == "vllm"
            and r["payload"]["event"] == "sample"
            or r["source_kind"] == "kubernetes"
            and r["payload"]["event"] in ("startup", "ready")
        )
        for r in rows
    ):
        return [], []
    return [[start_ms, until]], [created[0]["raw_ref"], proof["raw_ref"]]


def registered_coverage(source, start_ms, end_ms):
    rows = source.rows
    inventory = {}
    for row in rows:
        key = (row["source_kind"], row["source_identity"], row["source_generation"])
        inventory.setdefault(key, []).append(row)
    contracts = []

    def add(key, event, cadence, match=None, absence=(), proofs=()):
        kind, identity, generation = key
        contracts.append(
            {
                "kind": kind,
                "identity": identity,
                "generation": generation,
                "event": event,
                "cadence_ms": cadence,
                "payload_match": match or {},
                "start_ms": start_ms,
                "end_ms": end_ms,
                "absent_intervals": list(absence),
                "lifecycle_proofs": list(proofs),
            }
        )

    gateways, pods, clocks = set(), set(), set()
    for key, stream in sorted(inventory.items()):
        kind = key[0]
        if kind == "gateway":
            for gateway in sorted({r["payload"].get("gateway_uid") for r in stream} - {None}):
                gateways.add(gateway)
                for event in ("install", "health"):
                    add(key, event, 250, {"gateway_uid": gateway})
        elif kind in ("redis", "kubernetes"):
            add(key, "snapshot", 250)
        elif kind == "clocks":
            for clock, boot in sorted(
                {
                    (r["payload"].get("clock_id"), r["payload"].get("boot_id"))
                    for r in stream
                    if r["payload"].get("clock_id") and r["payload"].get("boot_id")
                }
            ):
                if clock and boot:
                    clocks.add((clock, boot))
                    add(key, "mapping", 1000, {"clock_id": clock, "boot_id": boot})
        elif kind == "vllm":
            for uid in sorted({r["payload"].get("pod_uid") for r in stream} - {None}):
                pods.add(uid)
                absence, proofs = [], []
                starts = [
                    r
                    for r in rows
                    if r["source_kind"] == "kubernetes"
                    and r["payload"].get("pod_uid") == uid
                    and r["payload"]["event"] == "startup"
                    and r["time_ms_bounds"]
                ]
                ends = [
                    r
                    for r in stream
                    if r["payload"].get("pod_uid") == uid
                    and r["payload"]["event"] == "process_end"
                    and r["time_ms_bounds"]
                ]
                if len(starts) == 1:
                    absence.append([start_ms, starts[0]["time_ms_bounds"][0]])
                    proofs.append(starts[0]["raw_ref"])
                elif not starts:
                    absence, proofs = _pre_metrics_absence(rows, uid, start_ms, end_ms)
                if len(ends) == 1:
                    absence.append([ends[0]["time_ms_bounds"][1], end_ms])
                    proofs.append(ends[0]["raw_ref"])
                add(key, "sample", 500, {"pod_uid": uid}, absence, proofs)
    for gateway in sorted(set(GATEWAYS) - gateways):
        for event in ("install", "health"):
            add(("gateway", gateway, "unobserved"), event, 250, {"gateway_uid": gateway})
    for kind in ("redis", "kubernetes", "vllm", "clocks"):
        if not any(c["kind"] == kind for c in contracts):
            add(
                (kind, "unobserved", "unobserved"),
                {
                    "redis": "snapshot",
                    "kubernetes": "snapshot",
                    "vllm": "sample",
                    "clocks": "mapping",
                }[kind],
                1000 if kind == "clocks" else 500 if kind == "vllm" else 250,
            )
    expected_pods = set()
    for row in rows:
        if not carries_observation(row):
            continue
        p = row["payload"]
        if row["source_kind"] == "gateway":
            expected_pods.update(m["uid"] for m in p.get("members") or [] if m.get("uid"))
        if row["source_kind"] == "kubernetes":
            expected_pods.update(m["uid"] for m in p.get("endpoints") or [] if m.get("uid"))
        # Any lifecycle observation establishes the UID's existence. Missing
        # creation/startup/receipt rows must not remove it from metrics coverage.
        if row["source_kind"] == "kubernetes" and p.get("pod_uid"):
            expected_pods.add(p["pod_uid"])
        clock = row["source_time"]
        if clock and clock["clock_id"] != "measurement":
            remote = (clock["clock_id"], row["source_generation"])
            if remote not in clocks:
                clocks.add(remote)
                add(
                    ("clocks", "unobserved:" + remote[0], remote[1]),
                    "mapping",
                    1000,
                    {"clock_id": remote[0], "boot_id": remote[1]},
                )
    for uid in sorted(expected_pods - pods):
        absence, proofs = _pre_metrics_absence(rows, uid, start_ms, end_ms)
        add(
            ("vllm", "unobserved:" + uid, "unobserved"),
            "sample",
            500,
            {"pod_uid": uid},
            absence,
            proofs,
        )
    results = []
    for contract in contracts:
        arguments = {k: v for k, v in contract.items() if k != "lifecycle_proofs"}
        result = source.cadence(**arguments)
        result["lifecycle_proofs"] = contract["lifecycle_proofs"]
        results.append(result)
    return {
        "basis": "registration_v3_lines_25_29_48_52",
        "maximum_gap_ms": 2000,
        "start_ms": start_ms,
        "end_ms": end_ms,
        "contracts": contracts,
        "results": results,
    }
