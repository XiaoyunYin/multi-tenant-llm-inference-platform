"""Seal-time timing and source checks for the INF-054 GPU Helm variant."""

import json
import tarfile

from inf060_eks_cpu_plan import HELM_TAPE, canonical_digest, policy_actions
from inf060_eks_gpu_plan import verify_gpu_streaming_plan
from inference_platform.m5_descriptive_operator import session_timing
from m5_descriptive_capacity import zone_pairs
from m5_descriptive_cleanup import (
    PAIR_BOOTSTRAP_SECONDS,
    PAIR_SESSION_SECONDS,
    PAIR_WAIT_SECONDS,
    PAIR_WORK_SECONDS,
)

SESSION = "m5-desc-r475-gpu"
MARKER = "GPU EKS HELM PLAN APPROVED"
BINDING = "inf054_gpu_helm"
TAPE_SHA = "6f19ddabb51fe02975cc6afdb2a0bc5ad021b1bcfeed8f85c41a42eb889f6467"
SESSION_SECONDS = PAIR_SESSION_SECONDS
CAP_LIMIT_USD = 72.00
WAIT_HOURLY_USD = (
    0  # No instances before composed Apply; fixed USD 3 includes bootstrap/S3/Lambda.
)


def gpu_helm_timing(startup_s, upload_s):
    from inf054_cpu_helm import KEDA_INSTALL_S
    from inf054_dcgm import DIAGNOSTICS_S, LATER_WAIT_S, RESERVE_S, WAIT_S
    from inf054_eks_workload import gpu_release_seconds, workload_reserve

    timing = session_timing(startup_s, upload_s)
    # Keep release cleanup, KEDA install and both retrieval hops entirely
    # inside the selected work envelope. The paired search is separate.
    workload = KEDA_INSTALL_S + workload_reserve(
        9,
        observe_downscale=True,
        release_seconds=gpu_release_seconds(),
        dcgm_seconds=RESERVE_S,
    )
    timing.update(
        session_seconds=SESSION_SECONDS,
        minimum_workload_seconds=workload,
        # The model cache and readiness phases are inside the existing
        # apply-through-staging reserve. Each release reserves its chart readiness.
        initial_startup_budget_seconds=0,
        capacity_wait_budget_seconds=PAIR_WAIT_SECONDS,
        capacity_bootstrap_seconds=PAIR_BOOTSTRAP_SECONDS,
        selected_work_seconds=PAIR_WORK_SECONDS,
        remaining_infrastructure_seconds=timing[
            "apply_through_staging_reserve_seconds"
        ],
        dcgm_ready_seconds=WAIT_S,
        dcgm_later_ready_seconds=LATER_WAIT_S,
        dcgm_diagnostics_seconds=DIAGNOSTICS_S,
    )
    nonwait = sum(
        timing[key]
        for key in (
            "minimum_workload_seconds",
            "source_upload_budget_seconds",
            "retrieval_reserve_seconds",
            "cleanup_reserve_seconds",
            "remaining_infrastructure_seconds",
        )
    )
    if nonwait >= PAIR_WORK_SECONDS:
        raise ValueError("inf054_gpu_capacity_envelope")
    timing["infrastructure_before_capacity_wait_seconds"] = PAIR_BOOTSTRAP_SECONDS
    timing["selected_slack_seconds"] = PAIR_WORK_SECONDS - nonwait
    return timing


def gpu_helm_estimate(hourly, *, attempts=1):
    import math

    attempt = (
        PAIR_WORK_SECONDS / 3600 * hourly
        + PAIR_WAIT_SECONDS / 3600 * WAIT_HOURLY_USD
        + 3
    ) * 1.25
    return math.ceil(attempts * attempt * 100) / 100


def gpu_helm_forecast(hourly):
    if gpu_helm_estimate(hourly, attempts=2) > CAP_LIMIT_USD:
        raise ValueError("inf054_gpu_cost_envelope")
    return gpu_helm_estimate(hourly)


def verify_gpu_helm(directory, manifest):
    from build_m5_descriptive_packet import sha
    from inf054_cpu_helm import verify_tape_input
    from inf060_eks_cpu_plan import HELM_TAPE_RECEIPT
    from m5_descriptive_eks import validate_cleanup_resource_tags

    descriptive = manifest["descriptive"]
    binding = descriptive[BINDING]
    timing = manifest["timing"]
    if (
        manifest["session"] != SESSION
        or descriptive["session"] != SESSION
        or manifest["session_seconds"] != SESSION_SECONDS
        or descriptive["timing"] != timing
        or timing
        != gpu_helm_timing(
            descriptive["startup_seconds"], manifest["payload_transfer"]["bound_s"]
        )
        or manifest["forecast_usd"]
        != gpu_helm_forecast(manifest["forecast_basis"]["hourly_usd"])
        or binding["cap_usd"]
        != gpu_helm_estimate(manifest["forecast_basis"]["hourly_usd"], attempts=2)
        or manifest["forecast_basis"]["capacity_wait_hourly_usd"] != WAIT_HOURLY_USD
        or manifest["forecast_basis"]["fixed_other_usd"] != 3
        or manifest["forecast_basis"]["margin"] != 1.25
        or descriptive.get("cpu_clock_rehearsal")
        or descriptive.get("streaming")
    ):
        raise ValueError("inf054_gpu_envelope")
    alternatives = manifest["alternatives"]
    live = json.loads((directory / "live-inputs/refresh.json").read_bytes())
    [offering] = [
        row
        for row in live["sources"]
        if row["operation"] == "describe_instance_type_offerings"
    ]
    observed = zone_pairs(
        json.loads((directory / "live-inputs" / offering["response"]).read_bytes())
    )
    zones = {entry["zone"] for entry in observed}
    if alternatives != [
        {**row, "directory": "zone-" + row["zone"]} for row in observed
    ]:
        raise ValueError("inf054_gpu_zones")
    roots = {row["directory"]: row for row in manifest["plans"]}
    if set(roots) != {"bootstrap", "backstop", *("zone-" + zone for zone in zones)}:
        raise ValueError("inf054_gpu_plan_roots")
    for name, row in roots.items():
        if (row["sha256"], row["json_sha256"]) != tuple(
            manifest["files"][f"{name}/{file}"]["sha256"]
            for file in ("create.tfplan", "show.stdout")
        ):
            raise ValueError("inf054_gpu_plan_digest")
    backstop_plan = json.loads((directory / "backstop/show.stdout").read_bytes())
    cleanup = json.loads(
        next(
            r["change"]["after"]["policy"]
            for r in backstop_plan["resource_changes"]
            if r["type"] == "aws_iam_role_policy"
        )
    )
    if canonical_digest(cleanup) != manifest["cleanup_policy_sha256"]:
        raise ValueError("inf054_gpu_cleanup_policy")
    hosts = (directory / "package_a/user-data.sh").read_text(encoding="utf-8")
    expected_user_data = hosts.replace("${host_timer_seconds}", str(SESSION_SECONDS))
    lambda_env = next(
        r["change"]["after"]["environment"]
        for r in backstop_plan["resource_changes"]
        if r["type"] == "aws_lambda_function"
    )
    if lambda_env != [
        {
            "variables": {
                "SESSION": SESSION,
                "PARAMETER": "/" + SESSION + "/deadline",
                "STATE_BUCKET": manifest["state_bucket"],
                "SESSION_SECONDS": str(SESSION_SECONDS),
            }
        }
    ]:
        raise ValueError("inf054_gpu_backstop_timer")
    policies = {}
    for row in alternatives:
        name = row["directory"]
        if name != "zone-" + row["zone"] or row["control_plane_zone"] not in zones - {
            row["zone"]
        }:
            raise ValueError("inf054_gpu_zone_root")
        plan = json.loads((directory / name / "show.stdout").read_bytes())
        verify_gpu_streaming_plan(plan)
        validate_cleanup_resource_tags(plan, SESSION, cleanup)
        facts = {r["address"]: r["change"]["after"] for r in plan["resource_changes"]}
        host = facts["module.operator.aws_instance.task[0]"]
        cuda = facts["module.eks.aws_launch_template.gpu[0]"]
        variables = plan["variables"]
        target = cuda["capacity_reservation_specification"][0]
        if (
            variables["zones"]["value"] != [row["zone"], row["control_plane_zone"]]
            or variables["session"]["value"] != SESSION
            or variables["session_seconds"]["value"] != SESSION_SECONDS
            or target["capacity_reservation_preference"] != "capacity-reservations-only"
            or host.get("user_data") != expected_user_data
        ):
            raise ValueError("inf054_gpu_plan_variables")
        policy = json.loads(facts["aws_iam_role_policy.operator"]["policy"])
        expected_scope = {
            "eks:DescribeCluster": f"arn:aws:eks:us-east-1:{manifest['account']}:cluster/{SESSION}",
            "ecr:BatchGetImage": f"arn:aws:ecr:us-east-1:{manifest['account']}:repository/{SESSION}",
            "ecr:GetAuthorizationToken": "*",
        }
        mapped = {
            action: entry["Resource"]
            for entry in policy["Statement"]
            for action in entry["Action"]
        }
        if any(
            mapped.get(action) != resource
            for action, resource in expected_scope.items()
        ):
            raise ValueError("inf054_gpu_operator_policy_scope")

        policies[name] = {
            "policy_sha256": canonical_digest(policy),
            "actions": policy_actions(policy),
        }
    if binding["policies"] != policies or binding["tape_sha256"] != TAPE_SHA:
        raise ValueError("inf054_gpu_policy_or_tape")
    inputs = manifest["host_manifest"]["gate_a_inputs"]
    facts = manifest["files"][HELM_TAPE]
    if (
        inputs["inventory"] != {HELM_TAPE: facts}
        or facts["sha256"] != TAPE_SHA
        or inputs["bundle_path"] != "inf054-tape.tar"
        or sha(directory / HELM_TAPE_RECEIPT)
        != manifest["files"][HELM_TAPE_RECEIPT]["sha256"]
    ):
        raise ValueError("inf054_gpu_tape")
    verify_tape_input(directory, facts)
    bundled = manifest["files"][inputs["bundle_path"]]
    if (inputs["bundle_bytes"], inputs["bundle_sha256"]) != (
        bundled["bytes"],
        bundled["sha256"],
    ):
        raise ValueError("inf054_gpu_tape_bundle")
    with tarfile.open(directory / inputs["bundle_path"], "r:") as tape:
        [member] = tape.getmembers()
        if (
            member.name != HELM_TAPE
            or not member.isfile()
            or member.size != facts["bytes"]
        ):
            raise ValueError("inf054_gpu_tape_bundle")
        with tape.extractfile(member) as stream:
            import hashlib

            if hashlib.file_digest(stream, "sha256").hexdigest() != TAPE_SHA:
                raise ValueError("inf054_gpu_tape_bundle")


def require_regional_capacity(sdk, session, *, selected):
    from m5_descriptive_cleanup import pages

    values = pages(
        sdk.client("ec2"),
        "describe_capacity_reservations",
        "CapacityReservations",
        Filters=[{"Name": "state", "Values": ["active", "pending"]}],
    )
    if selected:
        valid = (
            len(values) == 1
            and values[0].get("State") == "active"
            and values[0].get("TotalInstanceCount") == 2
            and values[0].get("AvailableInstanceCount") == 2
            and values[0].get("InstanceType") == "g6.xlarge"
            and {row["Key"]: row["Value"] for row in values[0].get("Tags", [])}.get(
                "Session"
            )
            == session
        )
    else:
        valid = not values
    if not valid:
        raise ValueError("inf054_gpu_regional_capacity_busy")
