"""Offline EKS manifest rendering / teardown receipt verification. Never applies."""

import argparse
import json
from pathlib import Path

from inference_platform.eks_deployment import render, smoke_snapshot, verify_teardown
from inference_platform.m5_descriptive import resources as descriptive_resources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    manifest = sub.add_parser("render")
    manifest.add_argument("--inputs", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)
    descriptive = sub.add_parser("render-descriptive")
    descriptive.add_argument("--namespace", required=True)
    descriptive.add_argument("--gateway-image", required=True)
    descriptive.add_argument("--tls-secret", default="gateway-tls")
    descriptive.add_argument("--output", type=Path, required=True)
    teardown = sub.add_parser("verify-teardown")
    teardown.add_argument("--inventory", type=Path, required=True)
    teardown.add_argument("--session-id", required=True)
    teardown.add_argument("--destroy-finished-ms", type=int, required=True)
    smoke = sub.add_parser("smoke")
    smoke.add_argument("--snapshot", type=Path, required=True)
    smoke.add_argument("--inputs", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "render-descriptive":
        result = descriptive_resources(
            args.namespace, args.gateway_image, args.tls_secret
        )
        args.output.write_text(
            json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    "resources": len(result["items"]),
                    "applied": False,
                    "authority": "DEC-100",
                }
            )
        )
    elif args.action == "render":
        result = render(
            args.inputs,
            args.output,
            Path(__file__).resolve().parents[1] / "deploy/eks/capture_runtime.py",
        )
        print(json.dumps({"resources": len(result["items"]), "applied": False}))
    elif args.action == "smoke":
        print(
            json.dumps(
                smoke_snapshot(
                    json.loads(args.snapshot.read_bytes()),
                    json.loads(args.inputs.read_bytes()),
                )
            )
        )
    else:
        print(
            json.dumps(
                verify_teardown(
                    json.loads(args.inventory.read_bytes()),
                    session_id=args.session_id,
                    after_ms=args.destroy_finished_ms,
                )
            )
        )


if __name__ == "__main__":
    main()
