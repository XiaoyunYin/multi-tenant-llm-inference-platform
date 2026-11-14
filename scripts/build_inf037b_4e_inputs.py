"""Deterministic 4e stop/interface inventory; no network or infrastructure plan."""

import argparse
import ast
import json
import re
from pathlib import Path
from inference_platform.inf037b_archive import encode, sha

ROOT = Path(__file__).resolve().parents[1]
ASSIGNMENTS = ROOT / "docs/INF037B_4E_INPUT_ASSIGNMENTS.json"
OUTPUT = ROOT / "docs/INF037B_4E_INPUT_INVENTORY.json"


def collect(root=ROOT, *, include_schedule=True):
    root = Path(root)
    entries = {}
    sources = {}

    def add(name, path, line, symbol, kind, reason=None):
        row = entries.setdefault(
            name, {"id": name, "consumers": [], "refusal_templates": []}
        )
        loc = {"path": path, "line": line, "symbol": symbol, "kind": kind}
        if loc not in row["consumers"]:
            row["consumers"].append(loc)
        if reason and reason not in row["refusal_templates"]:
            row["refusal_templates"].append(reason)

    def walk(node, path, scope="module"):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = scope + "." + node.name if scope != "module" else node.name
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for name in re.findall(r"\b4e_[a-z][a-z0-9_]*", node.value):
                reason = (
                    node.value
                    if node.value.startswith("eks:unfinished:")
                    else (
                        "eks:unfinished:<port>:4e_execution_runtime"
                        if node.value == ":4e_execution_runtime"
                        else None
                    )
                )
                if reason and reason.endswith(":"):
                    reason += "<runtime_key>"
                add(
                    name,
                    path,
                    node.lineno,
                    scope,
                    "refusal" if reason else "declared_input",
                    reason,
                )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (
                path.endswith("inf037b_eks_fixture.py")
                and node.func.attr == "reference"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                add(
                    "fixture_input:" + node.args[0].value,
                    path,
                    node.lineno,
                    scope,
                    "required_fixture_input",
                    "eks:fixture_input:" + node.args[0].value,
                )
            if (
                node.func.attr == "dependency"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                name = node.args[0].value
                add(
                    name,
                    path,
                    node.lineno,
                    scope,
                    "dependency",
                    "eks:unfinished:" + name if name.startswith("4e_") else None,
                )
            if path.endswith("inf037b_eks_execution.py") and node.func.attr in {
                "need",
                "component",
            }:
                if (
                    not node.args
                    or not isinstance(node.args[0], ast.Constant)
                    or not isinstance(node.args[0].value, str)
                ):
                    raise ValueError(f"4e_inventory:dynamic_key:{path}:{node.lineno}")
                name = "4e_" + node.args[0].value
                add(
                    name,
                    path,
                    node.lineno,
                    scope,
                    "runtime_input",
                    "eks:unfinished:" + name,
                )
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Subscript)
            and isinstance(t.slice, ast.Constant)
            and t.slice.value == "missing_interfaces"
            for t in node.targets
        ):
            for n in ast.walk(node.value):
                if isinstance(n, ast.Constant) and isinstance(n.value, str):
                    add(n.value, path, n.lineno, scope, "declared_missing_interface")
        if isinstance(node, ast.FunctionDef):
            names = {
                "LifecycleAuthorityPort.inventory": "eks.inventory",
                "LifecycleAuthorityPort.create": "eks.creation",
                "TerminalAuthorityPort.effect": "eks.terminal.*",
                "TerminalAuthorityPort.inventory": "eks.terminal.inventory",
            }
            if scope in names:
                add(names[scope], path, node.lineno, scope, "provider_consumer")
        for child in ast.iter_child_nodes(node):
            walk(child, path, scope)

    for file in sorted(
        (root / "python/src/inference_platform").glob("inf037b_eks*.py")
    ):
        relative = file.relative_to(root).as_posix()
        raw = file.read_bytes().replace(b"\r\n", b"\n")
        sources[relative] = sha(raw)
        walk(ast.parse(raw), relative)
    if include_schedule:
        from inference_platform.inf037b_eks_commands import capture_instance_schedule

        schedule = capture_instance_schedule()
        path = "python/src/inference_platform/inf037b_eks_commands.py"
        tree = ast.parse((root / path).read_bytes())
        line = next(
            n.lineno
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "capture_instance_schedule"
        )
        for row in schedule["logical_scopes"]:
            if row["status"] == "unresolved":
                add(
                    "capture_scope:" + row["scope"],
                    path,
                    line,
                    "capture_instance_schedule",
                    "unresolved_owner_sources",
                )
    # The source/mount guard labels are aliases of these literal config fields.
    path = "python/src/inference_platform/inf037b_eks_fixture.py"
    if (root / path).exists():
        tree = ast.parse((root / path).read_bytes())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value in {
                "eks:fixture_input:source",
                "eks:fixture_input:export_mount",
            }:
                name = (
                    "maximum_fixture_source"
                    if node.value.endswith(":source")
                    else "export_fixture_mount_path"
                )
                add(
                    "fixture_input:" + name,
                    path,
                    node.lineno,
                    "StagedCreation.validate",
                    "required_fixture_input",
                    node.value,
                )
    for row in entries.values():
        row["consumers"].sort(key=lambda x: (x["path"], x["line"], x["kind"]))
        row["refusal_templates"].sort()
    return entries, sources


def assign(entries, rules):
    assigned = {}
    for rule in rules["rules"]:
        names = (
            [n for n in entries if n.startswith(rule["prefix"])]
            if "prefix" in rule
            else rule["ids"]
        )
        for name in names:
            if name in assigned:
                raise ValueError("4e_inventory:duplicate_assignment:" + name)
            assigned[name] = {
                k: v for k, v in rule.items() if k not in {"ids", "prefix"}
            }
    missing = sorted(entries.keys() - assigned.keys())
    unused = sorted(assigned.keys() - entries.keys())
    if missing or unused:
        raise ValueError(
            "4e_inventory:assignment_coverage:"
            + repr({"missing": missing, "unused": unused})
        )
    rows = []
    for name in sorted(entries):
        row = {**entries[name], **assigned[name]}
        if row["part"] not in rules["parts"]:
            raise ValueError("4e_inventory:unknown_part:" + row["part"])
        if not row["producer"] or not row["environment"]:
            raise ValueError("4e_inventory:producer_environment:" + name)
        if not set(row["environment"]) <= {
            "unpaid",
            "aws_cpu_host",
            "gpu_host",
            "eks_account",
        }:
            raise ValueError("4e_inventory:environment:" + name)
        rows.append(row)
    return rows


def inventory(root=ROOT, assignments=ASSIGNMENTS):
    entries, sources = collect(root)
    raw = Path(assignments).read_bytes()
    rules = json.loads(raw)
    rows = assign(entries, rules)
    return {
        "schema": "inf037b-4e-input-inventory-v1",
        "scope": "accepted components and unfinished operational bindings; not a plan or admission verdict",
        "source_lf_sha256": sources,
        "assignments": {
            "path": Path(assignments).relative_to(Path(root)).as_posix(),
            "sha256": sha(raw.replace(b"\r\n", b"\n")),
        },
        "parts": rules["parts"],
        "inputs": rows,
        "counts": {
            "inputs": len(rows),
            "consumer_locations": sum(len(r["consumers"]) for r in rows),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = inventory()
    value = encode(report)
    if args.check:
        if args.output.read_bytes() != value:
            raise ValueError("4e_inventory:stale_output")
    else:
        args.output.write_bytes(value)
    print(json.dumps(report["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
