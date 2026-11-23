"""Run the sealed probe on the already-owned DEC-099 CPU host."""

import base64
import json
import math
import os
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

import inf060_probe_spec as spec
import inf060_probe_results as probe_results
from inf060_probe_operator import checked_packet, synthetic_review


def mutations(packet, root):
    def replace(path, value):
        spec.save(path, value)
        folder = path.parents[1] if path.parent.name == "terraform" else path.parent
        manifest = spec.load(folder / "manifest.json")
        manifest["artifacts"][path.relative_to(folder).as_posix()] = spec.facts(path)
        spec.save(folder / "manifest.json", manifest)

    rows = []
    cases = [
        ("artifact_hash", "artifact_hash:requests.json"),
        ("wrong_image", "engine_image_argv_env"),
        ("wrong_interpreter", "engine_interpreter"),
        ("missing_logging", "artifact_missing:" + spec.LOG_CONFIG),
        ("missing_timer", "timer"),
        ("over_cap", "over_cap"),
    ]
    if "operator_host" in spec.load(packet / "manifest.json"):
        cases += [
            ("wrong_role_policy", "operator_policy_hash"),
            ("missing_operator_timer", "operator_timer"),
            ("over_operator_cap", "operator_budget"),
            (
                "missing_operator_data",
                "operator_runtime_data:deploy/package-a/cpu-test-weights.json",
            ),
        ]
    for name, expected in cases:
        target = root / name
        shutil.copytree(
            packet,
            target,
            ignore=shutil.ignore_patterns("supervisor", "operator", ".terraform"),
        )
        if name == "artifact_hash":
            with (target / "requests.json").open("ab") as out:
                out.write(b" ")
        elif name == "wrong_image":
            engine = spec.load(target / "engine.json")
            engine["control"]["image"] = "invalid@sha256:" + "0" * 64
            replace(target / "engine.json", engine)
        elif name == "wrong_interpreter":
            engine = spec.load(target / "engine.json")
            engine["control"]["argv"][0] = "python"
            replace(target / "engine.json", engine)
        elif name == "missing_logging":
            (target / spec.LOG_CONFIG).unlink()
        elif name == "missing_timer":
            file = target / "terraform/user-data.sh"
            file.write_bytes(
                file.read_bytes().replace(
                    b"systemctl enable --now dec077-terminate.timer", b"true"
                )
            )
            manifest = spec.load(target / "manifest.json")
            manifest["artifacts"]["terraform/user-data.sh"] = spec.facts(file)
            spec.save(target / "manifest.json", manifest)
        elif name in {
            "wrong_role_policy",
            "missing_operator_timer",
            "over_operator_cap",
            "missing_operator_data",
        }:
            manifest = spec.load(target / "manifest.json")
            host = manifest["operator_host"]
            if name == "wrong_role_policy":
                host["role_policy_sha256"] = "0" * 64
            elif name == "missing_operator_timer":
                file = target / "operator-host/user-data.sh"
                file.write_bytes(
                    file.read_bytes().replace(
                        b"systemctl enable --now dec077-terminate.timer", b"true"
                    )
                )
                host["artifacts"]["user-data.sh"] = spec.facts(file)
            elif name == "over_operator_cap":
                host["cap_usd"] = 0
            else:
                from inf060_operator_packet import RUNTIME_DATA

                archive = target / "operator-host/runtime.tar.gz"
                mutant = archive.with_suffix(".mutant")
                with (
                    tarfile.open(archive) as source,
                    tarfile.open(mutant, "w:gz") as output,
                ):
                    for member in source:
                        if member.name != RUNTIME_DATA[0]:
                            output.addfile(member, source.extractfile(member))
                mutant.replace(archive)
                host["artifacts"]["runtime.tar.gz"] = spec.facts(archive)
            spec.save(target / "manifest.json", manifest)
        else:
            manifest = spec.load(target / "manifest.json")
            manifest["hard_cap_usd"] = 0
            spec.save(target / "manifest.json", manifest)
        try:
            if "operator_host" in spec.load(target / "manifest.json"):
                from inf060_operator_packet import verify

                native = spec.verify_packet(target)
                verify(target, native)
                spec.approval(
                    synthetic_review(target),
                    native,
                    spec.facts(target / "manifest.json")["sha256"],
                )
            else:
                checked_packet(target, synthetic_review(target))
        except ValueError as error:
            spec.check(
                str(error) == "inf060:" + expected,
                "unexpected_mutation_refusal:" + name,
            )
            rows.append(
                {"name": name, "refusal": str(error), "product_billable_actions": 0}
            )
        else:
            raise ValueError("inf060:mutant_reached_billable_boundary:" + name)
    return rows


def rehearse(routine, end, packet):
    manifest = checked_packet(packet, synthetic_review(packet))
    spec.check(
        manifest["source_commit"] == routine.manifest["source_commit"],
        "rehearsal_source",
    )
    limit = min(spec.TOTAL_S + 30, end - time.time())
    spec.check(limit > spec.TOTAL_S, "routine_rehearsal_reserve")
    if "operator_host" in manifest:
        from inf060_aws_operator import operate
        from inference_platform.private_identifier_scan import (
            find_identifier_violations,
        )

        operation = routine.directory / "aws-operator"
        summary = operate(
            packet,
            operation,
            routine.inputs["aws_profile"],
            routine=routine,
        )
        row = summary["gpu"]
        spec.check(
            row and row["supervisor_complete"] and row["supervisor_exit"] == 0,
            "rehearsal_failed",
        )
        observed = summary["results"]
        report_path = operation / "probe-results.json"
        report = spec.load(report_path)
        worst = max(part["elapsed_s"] for part in observed["round_trips"])
        cap_chunks = math.ceil(probe_results.MAX_BYTES / probe_results.CHUNK_BYTES)
        spec.check(
            summary["operator"]["destroy_completed"]
            and summary["operator"]["inventory"]["empty"]
            and observed["status"] == "verified"
            and spec.facts(report_path) == {k: observed[k] for k in ("bytes", "sha256")}
            and observed["bytes"] <= probe_results.MAX_BYTES
            and all(len(arm["observations"]) == 120 for arm in report["arms"].values())
            and len(report["arms"]) == 2
            and worst <= probe_results.CHUNK_TIMEOUT_S
            and cap_chunks * probe_results.CHUNK_TIMEOUT_S
            + probe_results.TRANSFER_RESERVE_S
            <= probe_results.TRANSFER_S,
            "results_rehearsal",
        )
        spec.check(
            not find_identifier_violations(
                {"docs/evidence/probe-results.json": report_path.read_bytes()},
                manifest["account_id_sha256"],
            ),
            "results_identifiers",
        )
        spec.save(
            operation / "results-validation.json",
            {
                "identifier_scan": "PASS",
                "transfer": observed,
                "max_observed_round_trip_s": worst,
                "cap_chunks": cap_chunks,
                "transfer_budget_s": probe_results.TRANSFER_S,
                "chunk_timeout_s": probe_results.CHUNK_TIMEOUT_S,
                "transfer_reserve_s": probe_results.TRANSFER_RESERVE_S,
                "post_destroy_file_verified": True,
            },
        )
        forced = operate(
            packet,
            routine.directory / "aws-operator-preapply",
            routine.inputs["aws_profile"],
            routine=routine,
            early_exit=True,
        )
        spec.check(
            forced["gpu"] is None
            and forced["preapply"]["service_exit"] == 1
            and forced["preapply"]["consume_absent"] is True
            and forced["preapply"]["state_present"] is False
            and forced["operator"]["destroy_completed"] is True,
            "preapply_rehearsal_failed",
        )
        for name in ("prepare", "launch_engine"):
            failure_run = routine.directory / ("aws-operator-failure-" + name)
            failed = operate(
                packet,
                failure_run,
                routine.inputs["aws_profile"],
                routine=routine,
                mock_failure=name,
            )
            diagnostic_path = failure_run / "failure-diagnostics.json"
            record = spec.load(diagnostic_path)
            archive = record["gpu_archive"]
            failure = archive["phases"]["prepare"]["error"]
            check = failure["message"]
            spec.check(
                check == "inf060:rehearsal_" + name
                and any(frame.endswith(":" + name) for frame in failure["frames"])
                and {
                    "ERROR [worker.py:42]",
                    "ModuleNotFoundError",
                    "engine core initialization failed",
                }
                <= set(archive["tails"]["host_launcher"]["lines"])
                and not failed["gpu"]["supervisor_complete"]
                and failed["gpu"]["supervisor_exit"] != 0
                and failed["operator"]["destroy_completed"] is True
                and failed["operator"]["inventory"]["empty"] is True
                and failed["diagnostics"]["status"] == "verified"
                and failed["results"]["status"] == "verified"
                and spec.load(failure_run / "probe-results.json")["phases"]["prepare"][
                    "exit_code"
                ]
                == 1
                and spec.facts(diagnostic_path)
                == {key: failed["diagnostics"][key] for key in ("bytes", "sha256")},
                "failure_diagnostic_rehearsal:" + name,
            )
            spec.check(
                not find_identifier_violations(
                    {
                        "docs/evidence/"
                        + diagnostic_path.name: diagnostic_path.read_bytes()
                    },
                    manifest["account_id_sha256"],
                ),
                "failure_diagnostic_identifiers",
            )
            spec.save(
                failure_run / "validation.json",
                {
                    "check": check,
                    "identifier_scan": "PASS",
                    "summary": failed,
                },
            )
        receipt = shlex.quote(base64.b64encode(spec.data(row)).decode())
        evidence = shlex.quote(
            base64.b64encode(
                spec.data({"mock": summary, "forced_exit": forced})
            ).decode()
        )
        routine.deadline = end
        routine.ssm(
            routine.host,
            [
                "set -eu; umask 077",
                "printf %s "
                + receipt
                + " | base64 -d > /opt/dec077/results/inf060-probe/rehearsal.json",
                "printf %s "
                + evidence
                + " | base64 -d > /opt/dec077/results/inf060-probe/operator.json",
            ],
            timeout_s=45,
            step="inf060.rehearsal_receipt",
        )
        spec.save(routine.runtime / "inf060-rehearsal.json", row)
        spec.check(
            row["supervisor_complete"] and row["supervisor_exit"] == 0,
            "rehearsal_failed",
        )
        return row
    with tempfile.TemporaryDirectory(
        prefix="inf060-mutations-", dir=os.environ["TMPDIR"]
    ) as directory:
        results = mutations(packet, Path(directory))
    process = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("inf060_probe_operator.py")),
            "launch",
            "--directory",
            str(packet),
            "--profile",
            routine.inputs["aws_profile"],
            "--routine-directory",
            str(routine.directory),
        ],
        timeout=limit,
        capture_output=True,
        check=False,
    )
    (routine.runtime / "inf060-rehearsal.log").write_bytes(
        process.stdout + process.stderr
    )
    supervisor = routine.directory / "inf060-supervisor"
    attempts = list(supervisor.glob("attempt-*"))
    spec.check(len(attempts) == 1, "rehearsal_supervisor_attempt")
    result = spec.load(attempts[0] / "deadline.json")
    summary = {
        "manifest_sha256": spec.facts(packet / "manifest.json")["sha256"],
        "source": manifest["source_commit"],
        "plan_sha256": manifest["sealed_plans"]["create_sha256"],
        "image_inputs": {
            name: manifest["artifacts"][name]
            for name in ("engine.json", "tools.json", spec.LOG_CONFIG)
        },
        "mutations": results,
        "supervisor_complete": result["complete"],
        "supervisor_stages": result["stages"],
        "deadline_from_origin_s": result["deadline_epoch"] - result["t0_epoch"],
        "work_stop_from_origin_s": result["work_stop_epoch"] - result["t0_epoch"],
        "substitutions": {
            "terraform_apply": "existing verified DEC-099 CPU host",
            "gpu_image_and_weights": "CPU mock and deterministic canary strings",
            "timer": "real DEC-099 instance timer liveness; 4200s product user-data timer validated in saved plan",
            "product_destroy": "no product resources created; routine destroy independently verified",
            "approval": "synthetic string through real parser, without modifying REVIEW.md",
        },
        "real": [
            "independent supervisor",
            "AWS SSM command and forwarding",
            "bounded source transfer",
            "agent /manifest,/upload,/stage,/start,/freeze",
            "env-i launcher and all phase commands",
            "gateway build and process",
            "Redis",
            "nginx TLS",
            "client/SSE/join/sanitizer",
            "clock exchanges",
            "receipt retrieval and tagged inventory",
        ],
    }
    if result["complete"]:
        transfer = attempts[0] / "operator/source-transfer.jsonl"
        rows = [json.loads(line) for line in transfer.read_bytes().splitlines()]
        summary["source_transfer"] = {
            "bytes": sum(r["bytes"] for r in rows),
            "rows": rows,
            "worst_acknowledged_chunk_bps": min(
                r["bytes"] / r["elapsed_s"] for r in rows
            ),
        }
    encoded = shlex.quote(base64.b64encode(spec.data(summary)).decode())
    routine.deadline = min(end, time.time() + 60)
    routine.ssm(
        routine.host,
        [
            "set -eu",
            "install -d -m 0700 /opt/dec077/results/inf060-probe",
            "printf %s "
            + encoded
            + " | base64 -d > /opt/dec077/results/inf060-probe/rehearsal.json",
        ],
        timeout_s=45,
        step="inf060.rehearsal_receipt",
    )
    spec.save(routine.runtime / "inf060-rehearsal.json", summary)
    spec.check(process.returncode == 0 and result["complete"], "rehearsal_failed")
