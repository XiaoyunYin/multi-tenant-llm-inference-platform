"""Portable owner component; real files, explicit non-POSIX barrier witness."""

from test_inf037b_eks_probe import component_owner

from inference_platform.inf037b_capture_inventory import source_inventory, wire_files


def resource_owner(case, roles=("measurement",)):
    owner = component_owner(case)
    before = owner.sources
    added = {
        "resource:" + role: [
            ["controller", "resource:" + role, "generation"],
            ["clocks", "clock:resource:" + role, "resource-boot"],
        ]
        for role in roles
    }
    owner.sources = added
    owner.binding["capture_inventory"] = {
        "schema": "inf037b-capture-inventory-v1",
        "sources": [{"name": name} for name in added],
        "wire_files": sorted(p for files in wire_files(added).values() for p in files.values()),
    }
    owner._open_wire_sources()
    for name in added:
        case.addCleanup(owner.wire[name]["data"].close)
        case.addCleanup(owner.wire[name]["index"].close)
        owner.binding["capture_budgets"][name] = {
            "raw_bytes": 1000000,
            "index_bytes": 1000000,
            "records": 1000,
        }
    owner.sources = {**before, **added}
    owner.binding["capture_inventory"] = source_inventory(resource_roles=roles)
    owner.operation_store.write({"operations": {owner.label: owner.operation}})
    return owner
