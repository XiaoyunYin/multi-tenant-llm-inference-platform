"""Build NIC authority documents from a bound read-only refresh; no AWS call."""

import argparse
from pathlib import Path

from inference_platform.inf037b_archive import encode, sha, strict_json
from inference_platform.inf037b_nic import nic_capacity_documents
from inference_platform.inf037b_resources import RESOURCE_ROLES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", type=Path, required=True)
    parser.add_argument("--allocation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    refresh = strict_json(args.refresh.read_bytes())
    allocation = strict_json(args.allocation.read_bytes())
    documents = nic_capacity_documents(refresh["instance_type_facts"], **allocation)
    if not set(documents) <= set(RESOURCE_ROLES):
        raise ValueError("resource:nic_role")
    args.output.mkdir(exist_ok=False, parents=True)
    for role, document in documents.items():
        raw = encode(document)
        (args.output / (role + ".json")).write_bytes(raw)
        print(role, sha(raw))


if __name__ == "__main__":
    main()
