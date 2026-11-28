"""Reviewed zone inventory and deadline-bounded reuse of the R1 capacity probe."""

import hashlib
import json
import time
from datetime import UTC, datetime

from m5_descriptive_cleanup import pages

# Round 379: the ordinary us-east-1 AZ set EKS supports; 1e is excluded.
# This is an eligibility filter, never evidence of current GPU capacity.
EKS_ZONES = ("us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d", "us-east-1f")


def zone_pairs(offerings):
    rows = offerings["InstanceTypeOfferings"]
    gpu = sorted(
        {r["Location"] for r in rows if r["InstanceType"] == "g6.xlarge"}
        & set(EKS_ZONES)
    )
    cpu = sorted(
        {r["Location"] for r in rows if r["InstanceType"] == "c6i.2xlarge"}
        & set(EKS_ZONES)
    )
    if not gpu or any(not set(cpu) - {zone} for zone in gpu):
        raise ValueError("descriptive:quota_or_offering")
    return [
        {"zone": zone, "control_plane_zone": next(z for z in cpu if z != zone)}
        for zone in gpu
    ]


def select_capacity(
    ports,
    *,
    clock=time.monotonic,
    sleep=time.sleep,
    epoch=time.time,
    prepare_choice=None,
):
    """Select at most one sealed plan; never Apply here or extend a deadline.

    All R1 create/cancel/readback command outputs have per-probe directories.
    Keep 90 seconds inside the wait for cancellation, even on probe failure.
    Bootstrap/arming already spent time; it cannot move the wait's latest end.
    """
    timing = ports.manifest["timing"]
    budget = timing["capacity_wait_budget_seconds"]
    spacing = timing["capacity_cycle_spacing_seconds"]
    if spacing < 60 or budget < 0:
        raise ValueError("descriptive:capacity_wait_inputs")
    start = clock()
    components = timing.get("streaming_components")
    transfers = (
        components["archive_transfers_s"] + components["in_session_transfer_probe_s"]
        if components
        else timing["retrieval_reserve_seconds"]
    )
    reserved = (
        timing["minimum_workload_seconds"]
        + timing["initial_startup_budget_seconds"]
        + timing["source_upload_budget_seconds"]
        + transfers
        + timing["cleanup_reserve_seconds"]
        + timing["remaining_infrastructure_seconds"]
    )
    if "selected_work_seconds" in timing:
        # The already-armed hard stop includes a separate post-selection window.
        if start > ports.deadline - timing["selected_work_seconds"] - budget:
            raise TimeoutError("descriptive:bootstrap_before_capacity_deadline")
        stop = start + budget
    else:
        stop = min(start + budget, ports.deadline - reserved)
    record = {
        "schema": "m5-descriptive-capacity-wait.v1",
        "started_epoch": epoch(),
        "budget_s": budget,
        "latest_end_monotonic": stop,
        "cycle_spacing_s": spacing,
        "zone_order": [a["zone"] for a in ports.manifest["alternatives"]],
        "probes": [],
        "status": "RUNNING",
        "elapsed_s": 0,
        "selected_zone": None,
    }
    path = ports.directory / "capacity-wait.json"

    def save():
        record["elapsed_s"] = max(0, clock() - start)
        path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def exhaust():
        raise ValueError("descriptive:capacity_unavailable_all_reviewed_zones")

    save()
    try:
        cycle = 0
        while True:
            cycle += 1
            for alternative in ports.manifest["alternatives"]:
                if clock() + 91 >= stop:
                    exhaust()
                ports.capacity.inputs["availability_zone"] = alternative["zone"]
                directory = (
                    ports.directory
                    / "capacity"
                    / f"cycle-{cycle:04}"
                    / alternative["zone"]
                )
                directory.mkdir(parents=True)
                ports.capacity.directory = directory
                item = {
                    "cycle": cycle,
                    "zone": alternative["zone"],
                    "at_utc": datetime.fromtimestamp(epoch(), UTC).isoformat(),
                    "start_offset_s": clock() - start,
                    "cleanup_verified": False,
                }
                record["probes"].append(item)
                save()
                selected = False
                try:
                    result = ports.capacity.reserve_capacity(
                        min(stop - 90, clock() + 180)
                    )
                    (directory / "probe.json").write_text(
                        json.dumps(result), encoding="utf-8"
                    )
                    item.update(
                        result=result["result"], error_code=result.get("error_code")
                    )
                    if result["result"] == "success":
                        identifier = result["capacity_reservation_id"]
                        if prepare_choice is not None:
                            prepare_choice(identifier, deadline=stop - 90)
                        else:
                            ports.make_targeted(identifier, deadline=stop - 90)
                            from botocore.config import Config

                            arn = f"arn:aws:ec2:us-east-1:{ports.manifest['account']}:capacity-reservation/{identifier}"
                            group = ports.manifest["capacity_group_arn"]
                            timeout = min(5, (stop - 90 - clock()) / 2)
                            if timeout <= 0:
                                exhaust()
                            groups = ports.sdk.client(
                                "resource-groups",
                                config=Config(
                                    connect_timeout=timeout,
                                    read_timeout=timeout,
                                    retries={"total_max_attempts": 1},
                                ),
                            )
                            groups.group_resources(Group=group, ResourceArns=[arn])
                            members = pages(
                                groups,
                                "list_group_resources",
                                "ResourceIdentifiers",
                                Group=group,
                            )
                            if [m["ResourceArn"] for m in members] != [arn]:
                                raise ValueError("descriptive:capacity_group_members")
                        if clock() >= stop - 90:
                            exhaust()
                        selected = True
                        item["cleanup_not_required"] = (
                            "selected active reservation; normal teardown owns cancellation"
                        )
                        record.update(
                            status="SELECTED", selected_zone=alternative["zone"]
                        )
                        return alternative
                    if result["result"] != "capacity_unavailable":
                        raise ValueError(
                            "descriptive:capacity_probe:"
                            + str(result.get("error_code"))
                        )
                except Exception as error:
                    item["error"] = type(error).__name__ + ":" + str(error)
                    raise
                finally:
                    try:
                        if not selected:
                            clean = ports.capacity.cancel_session_capacity_reservations(
                                min(stop, clock() + 90)
                            )
                            item["cleanup_verified"] = clean is True
                            if clean is not True:
                                raise RuntimeError(
                                    "descriptive:capacity_cleanup_unverified"
                                )
                    finally:
                        readbacks = {}
                        for source in sorted(directory.glob("*.stdout")):
                            readbacks[source.name] = hashlib.sha256(
                                source.read_bytes()
                            ).hexdigest()
                        item["readback_sha256"] = readbacks
                        item["elapsed_s"] = clock() - start - item["start_offset_s"]
                        save()
            # A complete cycle ends before this pause begins. No clipped pause
            # may permit another probe sooner than the sealed minimum spacing.
            if clock() + spacing + 91 >= stop:
                exhaust()
            sleep(spacing)
    except Exception as error:
        record.update(status="HALTED", error=type(error).__name__ + ":" + str(error))
        raise
    finally:
        record["finished_epoch"] = epoch()
        save()
