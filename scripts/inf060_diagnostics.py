"""Bounded failure evidence. Free-form remote text never enters a receipt."""

import hashlib
import json
import math
import re
import tarfile
import traceback
from pathlib import Path


MAX_BYTES = 48 * 1024
TAIL_BYTES = 24 * 1024
TAIL_LINES = 200
SSM_STDOUT_BYTES = 24_000
CHUNK_BYTES = 6000
PHASES = ("prepare", "control", "restart", "logged", "freeze")
STEPS = ("bootstrap", "upload", "run_checks", "retrieve", "stop_forward")
LOGS = ("agent", "stage", "engine", "gateway", "mock-control", "mock-logged", "command")
FAILURES = ("prepare", "launch_engine")
CHECKS = frozenset(
    """
    phase_deadline logging_config host_gpu image_digest go_download_bound go_digest
    model_stage weight_pin rendered_prompt_length redis_readiness process_reuse
    process_identity_changed engine_argv_env_readback running_engine_env
    mounted_logging_hash startup_suppression epoch_logging_readback
    tls_and_runtime_usage_smoke engine_cpu_accounting suppression_refused
    unlogged_frontend_abort generation_changed export_bytes arm_reserve
    engine_log_retrieval mock_generation
    unresolved_occupied_slots clock_exchange clock_bracket clock_step
    bounded_engine_log truncated_engine_log engine_log_encoding content_type
    model_size_revision receipt_retrieval ssm_registration host_start
    host_weights_timeout timer_and_readiness quota_or_owned_inventory
    gpu_capacity_unavailable
    offering_changed ami_changed availability_zone apply_reserve live_ingress
    operator_work_budget supervisor_origin remote_supervisor_attempt readiness
    runner_original_work_deadline diagnostic_binding diagnostic_deadline
    diagnostic_chunk_length diagnostic_hash diagnostic_json
    gpu_destroy_unverified missing_arm instance_role_identity operator_remaining_lifetime
    rehearsal_prepare rehearsal_launch_engine
    results_binding results_deadline results_chunk_length results_hash results_json
    results_missing_phase_or_arm results_missing_arm_fields results_missing_operation
    results_size_cap results_suppression results_member_size results_phase results_slots
    results_cancel_join results_join_totals results_clock_count results_assignment
    results_stamp results_interval results_integer results_number results_enum
    results_elapsed results_assignments results_outcomes
    clock_discontinuity clock_bracket_inconsistent
    """.split()
)
EXCEPTIONS = frozenset(
    """
    ValueError RuntimeError TimeoutError TimeoutExpired CalledProcessError
    FileNotFoundError PermissionError OSError JSONDecodeError KeyError TypeError
    UnicodeDecodeError MemoryError ConnectionError HTTPError URLError Exception
    """.split()
)
COMMAND_ERROR = re.compile(
    r"command:(docker|go|systemctl|nvidia-smi|openssl|curl|sha256sum)"
    r"(?::(pull|run|inspect|image|wait|exec|ps|rm|build|start|is-active|logs))?"
    r":(?:exit=-?\d{1,3}|timeout)\Z"
)
SIGNATURES = {
    "cuda out of memory": "CUDA out of memory",
    "no space left on device": "no space left on device",
    "connection refused": "connection refused",
    "context deadline exceeded": "context deadline exceeded",
    "error response from daemon": "Docker daemon error",
    "unauthorizedoperation": "AWS UnauthorizedOperation",
    "accessdenied": "AWS AccessDenied",
    "insufficientinstancecapacity": "AWS InsufficientInstanceCapacity",
    "reference to undeclared input variable": "Terraform undeclared input variable",
    "toomanyrequests": "rate limited",
    "nvrm: xid": "NVIDIA Xid",
    "health check failed": "health check failed",
    "unrecognized arguments": "unrecognized arguments",
    "engine core initialization failed": "engine core initialization failed",
    "no available memory for the cache blocks": "no available memory for the cache blocks",
    "modulenotfounderror": "ModuleNotFoundError",
    "importerror": "ImportError",
    "no cuda gpus are available": "no CUDA GPUs are available",
    "cuda driver version is insufficient": "CUDA driver version is insufficient",
    "address already in use": "address already in use",
    "permission denied": "permission denied",
}
SCRIPTS = Path(__file__).resolve().parent
FILE_LINE = r"[A-Za-z_][A-Za-z0-9_]{0,63}\.py:[1-9][0-9]{0,6}"
LOCATION = r"(?:WARNING|ERROR|CRITICAL) \[" + FILE_LINE + r"\]"
LOG_LOCATION = re.compile(
    r"^(?:\((?:APIServer|EngineCore(?:_[A-Za-z0-9]+)?) pid=[0-9]+\) )?[0-9]{1,12}\.[0-9]{6} ("
    + LOCATION
    + r")(?= |$)"
)
PYTHON_ERROR = re.compile(
    r"^([A-Za-z_][\w.]{0,79}(?:Error|Exception))(?=:|$)", re.ASCII
)
FRAME = re.compile(FILE_LINE + r":(?:[A-Za-z_][A-Za-z0-9_]{0,63}|<module>|<lambda>)\Z")


def injected_failure(mock_host, requested):
    return requested if mock_host and requested in FAILURES else None


def scrub_line(line):
    """Keep closed diagnostic codes or recognized error signatures only."""
    line = line.strip()
    if line.startswith("inf060:"):
        code = line.removeprefix("inf060:")
        if (
            code in CHECKS
            or COMMAND_ERROR.fullmatch(code)
            or code in {"phase:" + name for name in PHASES}
            or code in {"price_changed:" + name for name in ("compute", "gp3", "ipv4")}
        ):
            return line
    if line in EXCEPTIONS or line in SIGNATURES.values():
        return line
    if re.fullmatch(r"runner_failed:-?\d{1,3}", line):
        return line
    if re.fullmatch(LOCATION, line):
        return line
    if match := LOG_LOCATION.match(line):
        return match[1]
    if match := PYTHON_ERROR.match(line):
        return match[1]
    if re.match(r"Killed(?:\b|$)", line):
        return "Killed"
    for signature, label in SIGNATURES.items():
        if signature in line.lower():
            return label
    return "[redacted]"


def exception_record(exc):
    name = type(exc).__name__
    frames = []
    for frame, position in traceback.walk_tb(exc.__traceback__):
        filename = Path(frame.f_code.co_filename).resolve()
        item = f"{filename.name}:{position}:{frame.f_code.co_name}"
        if filename.is_relative_to(SCRIPTS) and FRAME.fullmatch(item):
            frames.append(item)
    return {
        "type": name
        if name in EXCEPTIONS or PYTHON_ERROR.fullmatch(name)
        else "Exception",
        "message": scrub_line(str(exc)[-TAIL_BYTES:]),
        "frames": frames[-8:],
    }


def encoded(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded(value))


def tail(raw, *, original_bytes=None):
    original_bytes = len(raw) if original_bytes is None else original_bytes
    lines = raw[-TAIL_BYTES:].decode(errors="replace").splitlines()
    return {
        "lines": [scrub_line(line) for line in lines[-TAIL_LINES:]],
        "source_bytes": original_bytes,
        "truncated": original_bytes > TAIL_BYTES or len(lines) > TAIL_LINES,
    }


def file_tail(path):
    with path.open("rb") as stream:
        size = stream.seek(0, 2)
        stream.seek(max(0, size - TAIL_BYTES))
        return tail(stream.read(TAIL_BYTES), original_bytes=size)


def number(value):
    return (
        value
        if type(value) in (int, float) and abs(value) < 10**11 and math.isfinite(value)
        else None
    )


def status_body(row):
    result = {"runner_exit": number(row.get("runner_exit"))}
    for key in ("manifest_bound", "staged", "runner_started", "cancelled"):
        if type(row.get(key)) is bool:
            result[key] = row[key]
    if type(row.get("offset")) is int:
        result["offset"] = number(row["offset"])
    return result


def read_json(path):
    try:
        if path.stat().st_size <= MAX_BYTES:
            return json.loads(path.read_bytes())
    except (OSError, ValueError):
        pass
    return None


def safe_timing(row):
    return {
        key: number(row.get(key))
        for key in ("start_epoch", "end_epoch", "elapsed_s", "exit_code")
    }


def safe_error(row):
    if not isinstance(row, dict):
        return None
    name = row.get("type")
    message = row.get("message")
    return {
        "type": name
        if isinstance(name, str)
        and (name in EXCEPTIONS or PYTHON_ERROR.fullmatch(name))
        else "Exception",
        "message": scrub_line(message) if isinstance(message, str) else "[redacted]",
        "frames": [
            frame
            for frame in row.get("frames", [])
            if isinstance(frame, str) and FRAME.fullmatch(frame)
        ][-8:]
        if isinstance(row.get("frames"), list)
        else [],
    }


def read_member(archive, member):
    if member.size <= MAX_BYTES:
        try:
            return json.load(archive.extractfile(member))
        except (ValueError, UnicodeError):
            pass
    return None


def read_archive(path):
    if not path.is_file():
        return {"status": "missing", "phases": {}, "tails": {}}
    result = {"status": "available", "phases": {}, "tails": {}}
    phase_members = {f"results/phase-{name}.json": name for name in PHASES}
    error_members = {f"results/error-{name}.json": name for name in PHASES}
    tail_members = {f"results/failure-{name}.json": name for name in LOGS}
    try:
        with tarfile.open(path) as archive:
            for member in archive:
                if not member.isfile():
                    continue
                if member.name == "bootstrap.log":
                    with archive.extractfile(member) as stream:
                        stream.seek(max(0, member.size - TAIL_BYTES))
                        result["tails"]["host_launcher"] = tail(
                            stream.read(TAIL_BYTES), original_bytes=member.size
                        )
                elif member.name in phase_members:
                    row = read_member(archive, member)
                    if isinstance(row, dict):
                        result["phases"].setdefault(
                            phase_members[member.name], {}
                        ).update(safe_timing(row))
                elif member.name in error_members:
                    row = safe_error(read_member(archive, member))
                    if row:
                        result["phases"].setdefault(error_members[member.name], {})[
                            "error"
                        ] = row
                elif member.name in tail_members:
                    row = read_member(archive, member)
                    if isinstance(row, dict) and isinstance(row.get("lines"), list):
                        result["tails"][tail_members[member.name]] = {
                            "lines": [
                                scrub_line(line)
                                for line in row["lines"][-TAIL_LINES:]
                                if isinstance(line, str)
                            ],
                            "source_bytes": number(row.get("source_bytes")),
                            "truncated": row.get("truncated") is True
                            or len(row["lines"]) > TAIL_LINES,
                        }
    except (OSError, tarfile.TarError, EOFError):
        result["status"] = "unreadable"
    return result


def collect(attempt):
    local = attempt / "operator"
    archive = read_archive(local / "receipts.tar.gz")
    retrieval = read_json(local / "retrieval.json")
    if isinstance(retrieval, dict):
        digest = retrieval.get("sha256")
        retrieval = {
            "complete": retrieval.get("complete") is True,
            "bytes": number(retrieval.get("bytes")),
            "elapsed_s": number(retrieval.get("elapsed_s")),
            "sha256": digest
            if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
            else None,
            "truncated_files": len(retrieval["truncated_files"])
            if isinstance(retrieval.get("truncated_files"), list)
            else None,
            **{
                key: retrieval[key]
                for key in ("status", "reason")
                if retrieval.get(key)
                in ("unreachable", "status_never_answered", "freeze_unanswered")
            },
        }
    last_status = read_json(attempt / "runner-status.json")
    steps = {}
    for step in STEPS:
        row = read_json(attempt / ("step-" + step + ".json"))
        if isinstance(row, dict):
            steps[step] = {**safe_timing(row), "error": safe_error(row.get("error"))}
    for stage in ("controller", "cleanup", "inventory", "apply"):
        path = local / "apply.log" if stage == "apply" else attempt / (stage + ".log")
        if path.is_file():
            archive["tails"][stage] = file_tail(path)
    record = {
        "controller_error": safe_error(read_json(attempt / "controller-error.json")),
        "steps": steps,
        "run_checks": status_body(last_status)
        if isinstance(last_status, dict)
        else None,
        "retrieval": retrieval if isinstance(retrieval, dict) else None,
        "gpu_archive": archive,
    }
    row = read_json(local / "apply.status.json")
    if isinstance(row, dict) and row.get("reason") in (
        "gpu_capacity_unavailable",
        "apply_timeout",
        "apply_error",
        "apply_start_failed",
        "apply_complete",
    ):
        zone = row.get("requested_zone")
        if isinstance(zone, str) and re.fullmatch(r"us-east-1[a-f]", zone):
            record["apply"] = {
                "reason": row["reason"],
                "requested_zone": zone,
                "suggested_zones": [
                    value
                    for value in row.get("suggested_zones", [])[:6]
                    if isinstance(value, str) and re.fullmatch(r"us-east-1[a-f]", value)
                ],
                "elapsed_s": number(row.get("elapsed_s")),
                "exit_code": number(row.get("exit_code")),
            }
    return record


def publish(path, record):
    tails = record.get("gpu_archive", {}).get("tails", {})
    while len(encoded(record)) > MAX_BYTES:
        longest = max(tails.values(), key=lambda item: len(item["lines"]))
        longest["lines"] = longest["lines"][max(1, len(longest["lines"]) // 2) :]
        longest["truncated"] = True
    write(path, record)
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def preview(record):
    return {
        **({"apply": record["apply"]} if "apply" in record else {}),
        "controller_error": record.get("controller_error"),
        "failed_steps": {
            name: row["error"]
            for name, row in record.get("steps", {}).items()
            if row.get("error")
        },
        "failed_phases": {
            name: row
            for name, row in record.get("gpu_archive", {}).get("phases", {}).items()
            if row.get("exit_code") or row.get("error")
        },
        "runner_exit": (record.get("run_checks") or {}).get("runner_exit"),
        "archive_status": record.get("gpu_archive", {}).get("status"),
    }
