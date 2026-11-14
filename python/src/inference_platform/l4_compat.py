"""No-provider L4 compatibility packet arithmetic and retained-evidence checks.

This is seven setup requests, not the research probe or the R366 host gate.
"""

import copy
import math

from .eks_deployment import MODEL, NGINX_IMAGE, REDIS_IMAGE, REVISION, VLLM_IMAGE
from .inf037b_controls import CONTROL_PAYLOADS, CONTROL_TOKENS
from .inf037b_requests import SSEDecoder
from .package_a_cloud import COST_FIXED_USD, transfer_seconds

DEADLINE_S = 4200
CLEANUP_S = 600
HOST_TIMER_S = DEADLINE_S - CLEANUP_S
READY_BY_S = 2700
REQUESTS_S = 7 * 30
FREEZE_S = 240
EXPORT_BYTES = 32 * 1024**2
CAP_USD = 5.0
HOURLY_CEILING_USD = 2.0
PINS = {
    "vllm": VLLM_IMAGE,
    "nginx": NGINX_IMAGE,
    "redis": REDIS_IMAGE,
    "model": MODEL,
    "revision": REVISION,
    "dtype": "bfloat16",
    "ami": "ami-0c244e62d32d4ca4e",
    "instance_type": "g6.xlarge",
    "region": "us-east-1",
    "zone": "us-east-1a",
    "root_gib": 128,
}


def need(condition, reason):
    if not condition:
        raise ValueError("l4:" + reason)


def worksheet(bundle_bytes):
    upload = transfer_seconds(bundle_bytes)
    export = transfer_seconds(EXPORT_BYTES)
    # READY_BY includes Apply (<=600), host boot, tools/model/image staging,
    # source verification, two fresh builds, TLS and both gateways' readiness.
    need(600 + upload < READY_BY_S, "upload_reserve")
    total = READY_BY_S + REQUESTS_S + FREEZE_S + export + CLEANUP_S
    need(total <= DEADLINE_S, "deadline_reserve")
    need(READY_BY_S + REQUESTS_S + FREEZE_S + export <= HOST_TIMER_S, "host_export_reserve")
    estimate = (DEADLINE_S / 3600 * HOURLY_CEILING_USD + COST_FIXED_USD + 1) * 1.15
    need(estimate <= CAP_USD, "cost_cap")
    return {
        "origin": "first possible billable action; never reset by boot or readiness",
        "deadline_seconds": DEADLINE_S,
        "host_timer_seconds": HOST_TIMER_S,
        "apply_seconds": 600,
        "ready_by_seconds": READY_BY_S,
        "upload_seconds_inside_readiness": upload,
        "request_seconds": REQUESTS_S,
        "freeze_seconds": FREEZE_S,
        "export_max_bytes": EXPORT_BYTES,
        "export_seconds": export,
        "cleanup_seconds": CLEANUP_S,
        "forecast_wall_seconds": total,
        "unused_deadline_seconds": DEADLINE_S - total,
        "hourly_all_resources_ceiling_usd": HOURLY_CEILING_USD,
        "fixed_allowance_usd": COST_FIXED_USD,
        "cleanup_reserve_usd": 1,
        "reserve_fraction": 0.15,
        "forecast_usd": estimate,
        "hard_cap_usd": CAP_USD,
        "price_basis": "conservative $2/h ceiling; not a current provider quote",
        "arithmetic": "DEC-077 transfer_seconds: two byte passes plus 60s; fixed and cleanup cost reserves",
    }


def requests():
    result = []
    for slot in (0, 1):
        for gateway in ("gateway0", "gateway1"):
            rid = f"ingress-{gateway}-{slot}"
            result.append(
                {
                    "id": rid,
                    "gateway": gateway,
                    "slot": slot,
                    "payload": copy.deepcopy(CONTROL_PAYLOADS[rid]),
                    "cancel": False,
                }
            )
        if slot == 0:
            for gateway in ("gateway0", "gateway1"):
                rid = "cancel-" + gateway
                result.append(
                    {
                        "id": rid,
                        "gateway": gateway,
                        "slot": slot,
                        "payload": copy.deepcopy(CONTROL_PAYLOADS[rid]),
                        "cancel": True,
                    }
                )
            payload = copy.deepcopy(CONTROL_PAYLOADS["cancel-gateway0"])
            payload["max_tokens"] = 1
            result.append(
                {
                    "id": "one-token-refusal",
                    "gateway": "gateway0",
                    "slot": 0,
                    "payload": payload,
                    "cancel": True,
                    "refusal": True,
                }
            )
    return result


def read_summary(reads, *, completed, tokens):
    """Actual read1 enter/return brackets, independent of normalized point times."""
    decoder = SSEDecoder()
    content, finish, done = None, None, None
    for index, row in enumerate(reads):
        lo, hi = row["bracket_ns"]
        need(type(lo) is int and type(hi) is int and lo <= hi, "read_bracket")
        if index:
            need(reads[index - 1]["bracket_ns"][1] <= lo, "read_order")
        previous = decoder.finish, decoder.done
        decoder.feed(bytes.fromhex(row["hex"]), [lo // 1_000_000, hi // 1_000_000])
        if decoder.content and content is None:
            content = row["bracket_ns"]
        if decoder.finish and not previous[0]:
            finish = row["bracket_ns"]
        if decoder.done and not previous[1]:
            done = row["bracket_ns"]
    if completed:
        need(decoder.report()["complete"], "complete_sse")
        need(content[1] < finish[0] and content[1] < done[0], "separate_content_finish")
    gap = (finish[1] - content[1]) / 1e9 if content and finish else None
    return {
        "first_content_ns": content,
        "finish_ns": finish,
        "done_ns": done,
        "first_content_to_finish_seconds": gap,
        "decode_tokens_per_second": (tokens - 1) / gap if gap and tokens > 1 else None,
        "decode_basis": "(completion_tokens-1)/(finish read return-first-content read return); includes buffering",
        "decoder": decoder.report(),
    }


def native_summary(events, *, external, cancel_ns=None, manifest=None, origin=None):
    if manifest is not None:
        roles = {}
        from .inf037b_native import TARGETS

        for event in events:
            chain = event["ancestry"]
            need(
                chain[0] == {"pid": event["pid"], "start": event["process_start"]}
                and chain[-1]
                == {"pid": origin["supervisor_pid"], "start": origin["supervisor_start"]},
                "native_ancestry",
            )
            if event["event"] == "installed":
                need(
                    event["source_sha256"] == manifest["files"][TARGETS[event["kind"]][0]],
                    "native_source",
                )
                roles.setdefault(event["kind"], set()).add((event["pid"], event["process_start"]))
            elif event["event"] in (
                "identity",
                "accept",
                "abort_intent",
                "abort_ack",
                "native_end",
            ):
                role = {"identity": "input", "accept": "scheduler", "native_end": "scheduler"}.get(
                    event["event"], "api"
                )
                need(
                    (event["pid"], event["process_start"]) in roles.get(role, set()), "native_role"
                )
                if event["event"] == "native_end":
                    need(
                        (event["pid"], event["process_start"]) in roles.get("core", set()),
                        "native_core_role",
                    )
        need(set(roles) == set(TARGETS), "native_install_inventory")
    identities = [e for e in events if e["event"] == "identity" and e["external"] == external]
    need(len(identities) == 1, "native_identity")
    internal = identities[0]["internal"]
    selected = [e for e in events if e.get("internal") == internal]
    by_kind = {e["event"]: e for e in selected}
    need(len(by_kind) == len(selected) and "accept" in by_kind, "native_duplicate_or_accept")
    end, confirmed = by_kind.get("native_end"), by_kind.get("terminal")
    need(end is not None and confirmed is not None and confirmed["terminal"] == end, "native_end")
    if cancel_ns is not None:
        need("abort_intent" in by_kind and "abort_ack" in by_kind, "native_api_abort")
        need(
            by_kind["abort_intent"]["cause"] in ("CancelledError", "GeneratorExit"),
            "native_abort_cause",
        )
        need(
            cancel_ns <= by_kind["abort_intent"]["mono_ns"] <= end["mono_ns"]
            and by_kind["abort_ack"]["mono_ns"] >= by_kind["abort_intent"]["mono_ns"]
            and end["status"] == "FINISHED_ABORTED"
            and end["abort_rpc"] is True
            and confirmed["terminal_reason"] == "client_cancel_abort",
            "native_abort_rpc_free",
        )
    else:
        need(
            end["status"] == "FINISHED_LENGTH_CAPPED" and confirmed["terminal_reason"] == "length",
            "native_length",
        )
    return {
        "internal": internal,
        "external": external,
        "events": by_kind,
        "cancellation_to_native_abort_ms": (end["mono_ns"] - cancel_ns) / 1e6
        if cancel_ns
        else None,
    }


def measured_booking(durations):
    need(
        len(durations) == 6 and all(math.isfinite(v) and 0 < v < 30 for v in durations),
        "control_durations",
    )
    allowance = 2 * max(durations)
    return {
        "control_tokens_tested": CONTROL_TOKENS,
        "maximum_control_seconds": max(durations),
        "twice_maximum_seconds": allowance,
        "fits_request_timeout": allowance < 30,
        "decision": "retain 64 only if twice maximum <30s and all increment/abort checks pass; otherwise prepare a shorter fixed length for review; no automatic second request set",
    }
