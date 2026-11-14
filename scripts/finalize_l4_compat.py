"""Bind the $0 saved plans and local operator tools. Never invokes a provider."""

import argparse
import json
import shutil
import sys
from pathlib import Path

from inference_platform.inf037b_archive import sha
from inference_platform.l4_compat import CAP_USD, PINS, worksheet
from inference_platform.package_a_cloud import save

ROOT = Path(__file__).resolve().parents[1]


def finalize(directory, previous_operator, query_recipes):
    packet = json.loads((directory / "packet.json").read_bytes())
    receipt = json.loads((directory / "payload-receipt.json").read_bytes())
    previous = json.loads(previous_operator.read_bytes())
    sealed = json.loads((directory / "sealed-plans.json").read_bytes())
    old_queries = json.loads(query_recipes.read_bytes())
    queries = {}
    for name, old in (
        ("compute", "g6.xlarge-price"),
        ("gp3", "gp3-price"),
        ("ipv4", "ipv4-price"),
        ("quota", "gvt-quota"),
    ):
        argv = old_queries[old]["argv"]
        queries[name] = argv[5 : argv.index("--output")]
    queries.update(
        ami=["ec2", "describe-images", "--image-ids", PINS["ami"]],
        shape=["ec2", "describe-instance-types", "--instance-types", "g6.xlarge"],
        offerings=[
            "ec2",
            "describe-instance-type-offerings",
            "--location-type",
            "availability-zone",
            "--filters",
            "Name=instance-type,Values=g6.xlarge",
            "Name=location,Values=" + PINS["zone"],
        ],
        instances=[
            "ec2",
            "describe-instances",
            "--filters",
            "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down",
        ],
    )
    tools = previous["operator_tools"]
    for row in tools.values():
        if sha(Path(row["path"]).read_bytes()) != row["sha256"]:
            raise ValueError("local_operator_tool_changed")
    shutil.copyfile(directory / "payload.tar.gz", directory / "source.bundle")
    manifest = {
        "schema": "single-l4-operator-v1",
        "pins": PINS,
        "source_commit": receipt["source_base_commit"],
        "source_commit_basis": "historical base only; execution requires --review-target and exact source/blob joins",
        "sources_sha256": packet["sources_sha256"],
        "source_manifest_file_sha256": sha((directory / "sources.json").read_bytes()),
        "bundle_sha256": receipt["sha256"],
        "bundle_bytes": receipt["bytes"],
        "instance_type": "g6.xlarge",
        "ami": PINS["ami"],
        "hourly_all_resources_usd": 2.0,
        "cleanup_cost_reserve_usd": 1,
        "prior_spend_usd": 0,
        "hard_cap_usd": CAP_USD,
        "account_id_sha256": previous["account_id_sha256"],
        "operator_tools": tools,
        "session_manager_plugin_path": previous["session_manager_plugin_path"],
        "sealed_plans": sealed,
        "preflight_queries": queries,
        **worksheet(receipt["bytes"]),
        "upload_timeout_s": worksheet(receipt["bytes"])[
            "upload_seconds_inside_readiness"
        ],
        "apply_authorized": False,
        "historical_quote_only": "Round116 2026-10-09 compute $0.8048/h, gp3 $0.08/GiB-month, IPv4 $0.005/h; future preflight enforces the $2/h ceiling",
    }
    save(directory / "manifest.json", manifest)
    argv = [sys.executable, str(ROOT / "scripts/l4_compat_controller.py")]
    commands = {
        name: [*argv, mode, "--directory", str(directory.resolve())]
        for name, mode in (
            ("controller", "execute"),
            ("cleanup", "cleanup"),
            ("inventory", "inventory"),
        )
    }
    save(directory / "commands.json", commands)
    save(
        directory / "binding-receipt.json",
        {
            "provider_calls": 0,
            "apply": False,
            "reservations": 0,
            "marker": False,
            "create_plan_sha256": sealed["create_sha256"],
            "manifest_sha256": sha((directory / "manifest.json").read_bytes()),
            "sources_sha256": packet["sources_sha256"],
            "source_bundle_sha256": receipt["sha256"],
            "commands_sha256": sha((directory / "commands.json").read_bytes()),
            "approval_arguments": ["L4_REVIEW_TARGET", "L4_OWNER_APPROVED_HASH"],
            "readiness": "NOT_RUN: provider availability/quota/inventory/pricing and real GPU/runtime compatibility",
        },
    )
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--previous-operator", type=Path, required=True)
    parser.add_argument("--query-recipes", type=Path, required=True)
    args = parser.parse_args()
    finalize(args.directory, args.previous_operator, args.query_recipes)
