"""Dated EC2 network-card baseline facts and reviewed per-role NIC allocation.

Offline only. Refresh supplies raw DescribeInstanceTypes bytes and its query
receipt. Peak/burst/throughput fields never supply a missing guaranteed baseline.
"""

import datetime as dt
import re
from decimal import Decimal, InvalidOperation

from .inf037b_archive import encode, sha
from .inf037b_resolver import exact, integer, require

REASON = "resource:unresolved:nic_guaranteed_baseline"


def instance_type_facts(raw, query):
    import json

    exact(query["exit"], 0, "resource:nic_refresh_failed")
    exact(sha(raw), query["sha256"], "resource:nic_refresh_hash")
    stamp = dt.datetime.fromisoformat(query["utc"])
    require(stamp.tzinfo is not None, "resource:nic_refresh_date")
    response = json.loads(raw, parse_float=Decimal)
    facts = {}
    for item in response.get("InstanceTypes", []):
        name = item["InstanceType"]
        require(name not in facts, "resource:nic_duplicate_type")
        cards = item.get("NetworkInfo", {}).get("NetworkCards", []) or []
        facts[name] = {
            "NetworkCards": [
                {
                    **{"NetworkCardIndex": card.get("NetworkCardIndex")},
                    **(
                        {"BaselineBandwidthInGbps": str(card["BaselineBandwidthInGbps"])}
                        if card.get("BaselineBandwidthInGbps") is not None
                        else {}
                    ),
                }
                for card in cards
            ]
        }
    return {
        "schema": "inf037b-instance-type-facts-v1",
        "utc": query["utc"],
        "response_sha256": query["sha256"],
        "instance_types": facts,
    }


def baseline_bytes(gbps):
    try:
        require(type(gbps) in (str, int, float, Decimal), REASON)
        rate = Decimal(str(gbps))
        require(rate.is_finite() and rate > 0, REASON)
        numerator, denominator = rate.as_integer_ratio()
        result = numerator * 10**9 // (denominator * 8)
        require(result > 0, REASON)
        return result
    except (InvalidOperation, ValueError, TypeError) as exc:
        # IntegrityError is a ValueError; keep the same named refusal either way.
        raise ValueError(REASON) from exc


def nic_capacity_documents(record, *, instance_type, instance_identity, binding, allocations):
    """All allocations for this instance/card must be submitted together.

    The exact plan binds the complete role allocation and its hash. The producer
    never chooses a rate or infers a card/interface mapping from traffic.
    """
    exact(record["schema"], "inf037b-instance-type-facts-v1", "resource:nic_refresh_schema")
    require(
        type(instance_identity) is str and bool(instance_identity), "resource:nic_instance_identity"
    )
    require(
        re.fullmatch("[0-9a-f]{64}", record["response_sha256"] or ""), "resource:nic_refresh_hash"
    )
    require(
        dt.datetime.fromisoformat(record["utc"]).tzinfo is not None, "resource:nic_refresh_date"
    )
    facts = record.get("instance_types", {}).get(instance_type)
    require(type(facts) is dict, REASON)
    cards = {}
    for card in facts.get("NetworkCards", []):
        index = card.get("NetworkCardIndex")
        require(integer(index) and index >= 0 and index not in cards, REASON)
        cards[index] = card
    require(bool(allocations), "resource:nic_allocation")
    totals, documents = {}, {}
    allocation_sha = sha(
        encode(
            {
                "instance_identity": instance_identity,
                "instance_type": instance_type,
                "binding": binding,
                "allocations": allocations,
            }
        )
    )
    for allocation in allocations:
        role, index = allocation["role"], allocation["network_card_index"]
        require(role not in documents, "resource:nic_duplicate_role")
        require(integer(index) and index >= 0 and index in cards, REASON)
        card = cards[index]
        require("BaselineBandwidthInGbps" in card, REASON)
        baseline = baseline_bytes(card["BaselineBandwidthInGbps"])
        rate = allocation["bytes_per_second"]
        require(integer(rate) and rate > 0, "resource:nic_allocation")
        totals[index] = totals.get(index, 0) + rate
        require(totals[index] <= baseline, "resource:nic_allocation_exceeds_baseline")
        require(
            bool(allocation["boot_id"])
            and integer(allocation["ifindex"])
            and allocation["ifindex"] > 0,
            "resource:nic_interface_identity",
        )
        identity = allocation["interface_identity"]
        require(
            type(identity) is list
            and len(identity) == 2
            and all(integer(v) and v >= 0 for v in identity),
            "resource:nic_interface_identity",
        )
        documents[role] = {
            "schema": "inf037b-nic-capacity-v1",
            "binding": binding,
            "role": role,
            "boot_id": allocation["boot_id"],
            "interface_identity": identity,
            "ifindex": allocation["ifindex"],
            "basis": "guaranteed_baseline",
            "bytes_per_second": rate,
            "instance_type": instance_type,
            "instance_identity": instance_identity,
            "network_card_index": index,
            "source_reference": {
                "service": "ec2",
                "operation": "DescribeInstanceTypes",
                "field": "NetworkInfo.NetworkCards[].BaselineBandwidthInGbps",
                "utc": record["utc"],
                "response_sha256": record["response_sha256"],
                "facts_sha256": sha(encode(record)),
                "allocation_sha256": allocation_sha,
                "baseline_gbps": card["BaselineBandwidthInGbps"],
                "baseline_bytes_per_second": baseline,
            },
        }
    return documents
