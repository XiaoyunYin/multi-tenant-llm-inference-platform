"""Derive partitioned counts from unittest summaries and Go terminal test events.

Verbose test labels are never counted: setUpClass skips and redirected stages
can make that list differ from the framework's authoritative summary (R523).
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


def summarize(text):
    summaries = re.findall(
        r"^Ran (\d+) tests? in [^\n]+\n\s*\n?(OK(?: \([^\n]*\))?|FAILED \([^\n]*\))",
        text,
        re.MULTILINE,
    )
    if summaries:
        result = {"framework": "unittest", "run": 0, "pass": 0, "skip": 0, "fail": 0}
        for run, conclusion in summaries:
            fields = {
                k.strip(): int(v)
                for k, v in re.findall(r"([A-Za-z ]+)=(\d+)", conclusion)
            }
            skipped = fields.get("skipped", 0)
            failed = sum(
                fields.get(k, 0) for k in ("failures", "errors", "unexpected successes")
            )
            result["run"] += int(run)
            result["skip"] += skipped
            result["fail"] += failed
            result["pass"] += int(run) - skipped - failed
    else:
        tests = {}
        for line in text.splitlines():
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("Test") and event.get("Action") in {"pass", "skip", "fail"}:
                key = (event["Package"], event["Test"])
                if key in tests:
                    raise ValueError("test_summary:duplicate_go_terminal")
                tests[key] = event["Action"]
        if not tests:
            raise ValueError("test_summary:no_framework_summary")
        result = {"framework": "go", "run": len(tests)}
        result.update(
            {k: list(tests.values()).count(k) for k in ("pass", "skip", "fail")}
        )
    if (
        min(result[k] for k in ("run", "pass", "skip", "fail")) < 0
        or sum(result[k] for k in ("pass", "skip", "fail")) != result["run"]
    ):
        raise ValueError("test_summary:invalid_partition")
    return result


def negative_control(name, data, receipt):
    """A verified killed-mutant log is a control, not a passing suite.

    Subtest diagnostics can exceed unittest's test count. Never invent a
    partition or ignore arbitrary failures: require the existing probe's exact
    killed/nonzero/hash receipt for each explicitly named child log.
    """
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != "r305-default-mutant-probe-v1"
    ):
        return None
    mutants = receipt.get("mutants")
    if not isinstance(mutants, dict):
        raise ValueError("test_summary:negative_control_receipt")
    rows = [
        (key, row)
        for key, row in mutants.items()
        if isinstance(row, dict) and row.get("log_path") == name
    ]
    if not rows:
        return None
    key, row = rows[0]
    digest = hashlib.sha256(data).hexdigest()
    if (
        len(rows) != 1
        or receipt.get("all_killed") is not True
        or row.get("killed") is not True
        or type(row.get("exit_code")) is not int
        or row["exit_code"] == 0
        or row.get("log_sha256") != digest
    ):
        raise ValueError("test_summary:negative_control_receipt")
    return {
        "kind": "expected_mutant_failure",
        "mutant": key,
        "exit_code": row["exit_code"],
        "log_sha256": digest,
        "counted_as_test": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", type=Path, nargs="*")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = (
        summarize_directory(args.directory)
        if args.directory
        else {
            str(p): summarize(p.read_text(encoding="utf-8", errors="replace"))
            for p in args.logs
        }
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def summarize_directory(directory):
    root = Path(directory)
    result = {
        "framework_logs": {},
        "negative_control_logs": {},
        "non_test_logs": [],
        "partitions_valid": True,
    }
    for path in sorted(root.rglob("*.log")):
        data = path.read_bytes()
        text = data.decode(encoding="utf-8", errors="replace")
        name = path.relative_to(root).as_posix()
        receipt = path.with_name("receipt.json")
        control = (
            negative_control(path.name, data, json.loads(receipt.read_bytes()))
            if receipt.is_file()
            else None
        )
        if control is not None:
            result["negative_control_logs"][name] = control
            continue
        try:
            result["framework_logs"][name] = summarize(text)
            if re.fullmatch(r"scripts-shard-\d+\.log", name):
                finished = {}
                for line in text.splitlines():
                    if line.startswith('{"module_finish":'):
                        event = json.loads(line)
                        module = event["module_finish"]
                        if module in finished:
                            raise ValueError("test_summary:duplicate_module_finish")
                        finished[module] = event["tests"]
                result["framework_logs"][name]["completed_modules"] = finished
        except ValueError as error:
            if str(error) != "test_summary:no_framework_summary":
                raise
            result["non_test_logs"].append(name)
    return result


if __name__ == "__main__":
    main()
