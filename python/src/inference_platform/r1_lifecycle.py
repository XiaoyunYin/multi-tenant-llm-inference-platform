"""Saved-plan R1 lifecycle. Offline adapters and paid execution share execute()."""

import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import sqlite3
import subprocess
import time
import uuid
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path

from .r1_bundle import validate_reviewed_bundle
from .r1_spec import SPEC_COMMIT, encoded
from .session_stop import stop_forward, terminate_operator_sessions

ROLES = ("gpu-0", "gpu-1", "service", "generator")
ENVELOPE, EXPORT_START, TEARDOWN_START = 16080, 15180, 15780
R1_SESSION_CAP_USD = Decimal("34.70")
M4_PHASE_CAP_USD = Decimal("86.54")
APPLY_WATCHDOG_SECONDS, APPLY_INTERRUPT_GRACE_SECONDS = 600, 10
CAPACITY_PROBE_TIMEOUT_SECONDS = 180
CAPACITY_RESERVATION_END_GRACE_SECONDS = 900
CAPACITY_RESERVATION_PENDING_TIMEOUT_SECONDS = 60
CAPACITY_RESERVATION_SETTLE_TIMEOUT_SECONDS = 60
CAPACITY_RESERVATION_POLL_SECONDS = 2
CAPACITY_RESERVATION_WINDOW_MARGIN_SECONDS = 20
CAPACITY_CLI_CONNECT_TIMEOUT_SECONDS = 5
CAPACITY_CLI_READ_TIMEOUT_SECONDS = 10
CAPACITY_RESERVATION_TERMINAL_STATES = frozenset({"cancelled", "expired", "failed"})
CAPACITY_ERROR = re.compile(
    r"InsufficientInstanceCapacity|InsufficientHostCapacity|insufficient capacity", re.I
)
CAPACITY_CODE = re.compile(r"(?:Server\.)?Insufficient(?:Instance|Host)Capacity", re.I)
AVAILABILITY_ZONE = re.compile(r"\b(?:us|ap|eu|sa|ca|me|af)-[a-z]+-\d[a-z]\b", re.I)


class PaidHalt(ValueError):
    pass


class QuotaDenied(PaidHalt):
    pass


class InfrastructureAbort(RuntimeError):
    """A Terraform Apply failure with a redacted, machine-readable classification."""

    def __init__(self, details):
        self.details = details
        super().__init__("infrastructure Apply aborted: " + details["cause"])


class CapacityProbeFailure(RuntimeError):
    """A failed pre-consume reservation request; the plan remains unconsumed."""

    def __init__(self, result, error_code=None):
        self.result = result
        self.error_code = error_code
        super().__init__("capacity probe failed: " + result)


class CapacityReservationCleanupFailure(RuntimeError):
    """Reservation cancellation could not be verified; teardown must fail closed."""


def _utc_timestamp(value):
    return (
        datetime.datetime.fromtimestamp(value, datetime.UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _cloudtrail_utc(value):
    parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    return parsed.astimezone(datetime.UTC)


def summarize_capacity_events(response, fallback_zone=None):
    """Reduce one CloudTrail page to capacity-only fields, dropping identities and raw events."""
    events = response.get("Events", []) if isinstance(response, dict) else []
    matches, error_codes, zones, instance_types, timestamps = [], set(), set(), {}, []
    for item in events:
        if not isinstance(item, dict):
            continue
        try:
            event = json.loads(item.get("CloudTrailEvent", "{}"))
        except (TypeError, json.JSONDecodeError):
            continue
        if event.get("eventName") != "RunInstances":
            continue
        code = event.get("errorCode")
        message = event.get("errorMessage") or ""
        if not (CAPACITY_ERROR.search(str(code or "")) or CAPACITY_ERROR.search(message)):
            continue
        matches.append(item)
        if code:
            error_codes.add(str(code).split(":", 1)[0])
        params = event.get("requestParameters") or {}
        placement = params.get("placement") or {}
        zone = placement.get("availabilityZone")
        if not zone:
            zone_match = AVAILABILITY_ZONE.search(message)
            zone = zone_match.group(0) if zone_match else None
        if zone:
            zones.add(str(zone))
        instance_type = params.get("instanceType")
        if instance_type:
            instance_types[instance_type] = instance_types.get(instance_type, 0) + 1
        else:
            instance_set = params.get("instancesSet") or {}
            for instance in instance_set.get("items", []):
                instance_type = instance.get("instanceType")
                if instance_type:
                    instance_types[instance_type] = instance_types.get(instance_type, 0) + 1
        event_time = event.get("eventTime")
        if event_time:
            timestamps.append(_cloudtrail_utc(event_time))
    return {
        "lookup_event_count": len(events),
        "lookup_results_truncated": bool(response.get("NextToken"))
        if isinstance(response, dict)
        else False,
        "capacity_event_count": len(matches),
        "error_code": ",".join(sorted(error_codes)) or None,
        "availability_zone": ",".join(sorted(zones)) or (fallback_zone if matches else None),
        "time_span_utc": (
            {
                "start_utc": min(timestamps).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "end_utc": max(timestamps).isoformat(timespec="seconds").replace("+00:00", "Z"),
            }
            if timestamps
            else None
        ),
        "instance_type_counts": dict(sorted(instance_types.items())),
    }


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ConsumeGate:
    """SQLite FULL-sync transaction survives process exits and excludes all plans."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS plans (hash TEXT PRIMARY KEY, status TEXT, started REAL, metadata TEXT)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS halt (id INTEGER PRIMARY KEY CHECK(id=1), reason TEXT)"
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    def consume(self, plan_hash, metadata=None, approval_plan_hashes=None):
        siblings = frozenset({plan_hash} if approval_plan_hashes is None else approval_plan_hashes)
        if plan_hash not in siblings:
            raise ValueError("saved plan is not in the approval's marker set")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT reason FROM halt").fetchone():
                    raise ValueError("paid work halted; owner resolution required")
                placeholders = ",".join("?" for _ in siblings)
                if db.execute(
                    f"SELECT hash FROM plans WHERE hash IN ({placeholders})", tuple(siblings)
                ).fetchone():
                    raise ValueError(
                        "saved plan already consumed in this approval; sibling plans retired"
                    )
                if db.execute("SELECT hash FROM plans WHERE status != 'verified'").fetchone():
                    raise ValueError("prior lifecycle requires verified teardown")
                db.execute(
                    "INSERT INTO plans VALUES (?, 'consumed', ?, ?)",
                    (plan_hash, time.time(), json.dumps(metadata)),
                )
                db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise ValueError("saved plan already consumed") from exc
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def finish(self, plan_hash, verified):
        with self.connect() as db:
            db.execute(
                "UPDATE plans SET status=? WHERE hash=?",
                ("verified" if verified else "uncertain", plan_hash),
            )
            if not verified:
                self.halt("teardown not verified")

    def halt(self, reason):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO halt VALUES (1, ?)", (reason,))

    def recovery_inputs(self, plan_hash):
        with self.connect() as db:
            row = db.execute("SELECT metadata FROM plans WHERE hash=?", (plan_hash,)).fetchone()
        if row is None or row[0] == "null":
            raise ValueError("no durable recovery binding for this saved plan")
        return json.loads(row[0])

    def plan_status(self, plan_hash):
        with self.connect() as db:
            row = db.execute("SELECT status FROM plans WHERE hash=?", (plan_hash,)).fetchone()
        return row[0] if row else None


def validate_inputs_commands(repo, inputs_path, inputs):
    """Every bound operator command must use the actual inputs file, rooted at the repo."""
    repo = Path(repo).resolve()
    relative = Path(inputs_path).resolve().relative_to(repo).as_posix()
    commands = inputs.get("commands")
    if not isinstance(commands, dict) or not commands:
        raise ValueError("R1 commands must reference their own --inputs file")
    for name, argv in commands.items():
        if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
            raise ValueError(f"R1 command {name} must be an argv list")
        indexes = [i for i, arg in enumerate(argv) if arg == "--inputs"]
        if (
            len(indexes) != 1
            or indexes[0] + 1 >= len(argv)
            or any(arg.startswith("--inputs=") for arg in argv)
        ):
            raise ValueError(f"R1 command {name} must pass exactly one --inputs <path>")
        try:
            command_path = (repo / argv[indexes[0] + 1]).resolve().relative_to(repo).as_posix()
        except ValueError as exc:
            raise ValueError(f"R1 command {name} --inputs path is outside the repo") from exc
        if command_path != relative:
            raise ValueError(f"R1 command {name} must reference its own --inputs file: {relative}")


def admit(plan, inputs, approval, *, repo=None, inputs_path=None):
    repo = Path(repo or Path.cwd()).resolve()
    validate_inputs_commands(repo, inputs_path or repo / "docs/R1_SESSION_INPUTS.json", inputs)
    if sha(plan) != inputs["plan_sha256"]:
        raise ValueError("saved-plan hash mismatch")
    if inputs["spec_commit"] != SPEC_COMMIT or inputs["roles"] != list(ROLES):
        raise ValueError("R1 exact topology/spec mismatch")
    if (
        inputs["region"] != "us-east-1"
        or inputs["gpu_type"] != "g6.xlarge"
        or inputs["cpu_type"] != "c6i.2xlarge"
    ):
        raise ValueError("unreviewed region/shape")
    if Decimal(str(inputs["m4_estimate_usd"])) > M4_PHASE_CAP_USD:
        raise ValueError("M4 estimate exceeds Xiaoyun DEC-058 cap")
    if not Decimal("0") < Decimal(str(inputs["session_estimate_usd"])) <= R1_SESSION_CAP_USD:
        raise ValueError("R1 session estimate exceeds the $34.70 cap")
    if inputs.get("quota_denied"):
        raise ValueError("quota denied before launch; paid work halted")
    return approval(inputs)


def execute(adapter, plan, inputs, gate, approval, receipt, *, inputs_path=None):
    """Single orchestration entrypoint, used by all virtual cases and real Apply."""
    events, error, exported, consumed, measure_started = [], None, False, False, False
    reservation, cancellation_attempts = None, 0
    probe_cleanup_attempted = False
    capacity_cancel_failed, exit_code = False, 1
    ready_completed, apply_call_started = False, False
    started = adapter.now()

    def record(event, **fields):
        events.append(
            {
                "event": (
                    "fixture_" if adapter.fixture and event != "quota_denial_reported" else ""
                )
                + event,
                "elapsed_s": adapter.now() - started,
                **fields,
            }
        )
        receipt.write_bytes(
            encoded({"plan_sha256": inputs["plan_sha256"], "events": events}) + b"\n"
        )

    def cancel_reservation(reason, deadline):
        nonlocal cancellation_attempts, capacity_cancel_failed, error
        if reservation is None:
            return True
        cancellation_attempts += 1
        try:
            outcome = adapter.cancel_capacity(reservation["capacity_reservation_id"], deadline)
            verified = bool(outcome.get("verified"))
            record(
                "capacity_reservation_cancelled"
                if verified
                else "capacity_reservation_cancel_failed",
                reason=reason,
                state=outcome.get("state"),
                cancel_requested=bool(outcome.get("cancel_requested")),
                verified=verified,
                capacity_reservation_id=reservation["capacity_reservation_id"],
            )
        except Exception as exc:
            verified = False
            record(
                "capacity_reservation_cancel_failed",
                reason=reason,
                error=type(exc).__name__,
                verified=False,
                capacity_reservation_id=reservation["capacity_reservation_id"],
            )
        if not verified:
            capacity_cancel_failed = True
            error = error or "capacity reservation cancellation not verified"
            gate.halt("capacity reservation cancellation not verified")
        return verified

    record("begin", fixture=adapter.fixture, deadline_s=ENVELOPE)
    try:
        if inputs.get("quota_denied"):
            gate.halt("INF-057 quota denied before launch")
        approval_plan_hashes = admit(
            plan, inputs, approval, repo=getattr(adapter, "repo", None), inputs_path=inputs_path
        )
        if isinstance(adapter, Production):
            adapter.preflight(plan, inputs, record)
        else:
            adapter.preflight(plan, inputs)
        try:
            probe = adapter.reserve_capacity(adapter.now() + CAPACITY_PROBE_TIMEOUT_SECONDS)
        except Exception as exc:
            record(
                "capacity_probe",
                result="partial",
                error_code=type(exc).__name__,
                error=str(exc),
                zone=inputs.get("availability_zone"),
                consumed=False,
                cleanup_verified=False,
                capacity_reservation_id=getattr(exc, "capacity_reservation_id", None),
                state=getattr(exc, "state", "unknown"),
            )
            cleanup_verified = False
            if isinstance(adapter, Production):
                try:
                    cleanup_verified = adapter.cancel_session_capacity_reservations(
                        adapter.now() + 30, record, "preconsume_probe_exception"
                    )
                except Exception as cleanup_exc:
                    record(
                        "capacity_reservation_cleanup_failed",
                        reason="preconsume_probe_exception",
                        error=type(cleanup_exc).__name__,
                    )
            if not cleanup_verified:
                capacity_cancel_failed = True
                gate.halt("preconsume capacity reservation cleanup not verified")
                record(
                    "capacity_reservation_cancel_failed",
                    reason="preconsume_probe_exception",
                    cancel_requested=False,
                    verified=False,
                )
            raise CapacityProbeFailure("partial", type(exc).__name__) from exc
        probe_event = {
            "result": probe["result"],
            "error_code": probe.get("error_code"),
            "zone": probe.get("zone"),
            "end_date_utc": probe.get("end_date_utc"),
            "consumed": False,
            "cleanup_verified": probe.get("cleanup_verified"),
            "capacity_reservation_id": probe.get("capacity_reservation_id"),
            "state": probe.get("state"),
        }
        if "cleanup_attempted" in probe:
            probe_event["cleanup_attempted"] = probe["cleanup_attempted"]
        record(
            "capacity_probe",
            **probe_event,
        )
        if probe["result"] != "success":
            cleanup_verified = probe.get("cleanup_verified", True)
            if probe.get("capacity_reservation_id"):
                reservation = {"capacity_reservation_id": probe["capacity_reservation_id"]}
                probe_cleanup_attempted = bool(probe.get("cleanup_attempted"))
                if not probe.get("cleanup_attempted"):
                    cleanup_verified = cancel_reservation(
                        "preconsume_probe_failure", adapter.now() + 30
                    )
            if isinstance(adapter, Production):
                try:
                    session_cleanup = adapter.cancel_session_capacity_reservations(
                        adapter.now() + 30, record, "preconsume_probe_failure"
                    )
                    cleanup_verified = session_cleanup and (
                        cleanup_verified if probe.get("capacity_reservation_id") else True
                    )
                except Exception as exc:
                    cleanup_verified = False
                    capacity_cancel_failed = True
                    record(
                        "capacity_reservation_cleanup_failed",
                        reason="preconsume_probe_failure",
                        error=type(exc).__name__,
                    )
            if capacity_cancel_failed or not cleanup_verified:
                if not capacity_cancel_failed:
                    record(
                        "capacity_reservation_cancel_failed",
                        reason="preconsume_probe_failure",
                        state=probe.get("state"),
                        cancel_requested=False,
                        verified=False,
                    )
                gate.halt("preconsume capacity reservation cleanup not verified")
                capacity_cancel_failed = True
            raise CapacityProbeFailure(probe["result"], probe.get("error_code"))
        reservation = {"capacity_reservation_id": probe["capacity_reservation_id"]}
        gate_metadata = {
            **inputs,
            "_capacity_reservation_id": probe["capacity_reservation_id"],
            "_approval_review_round": getattr(approval, "review_round", None),
            "_approval_plan_sha256": sorted(approval_plan_hashes or {inputs["plan_sha256"]}),
        }
        gate.consume(inputs["plan_sha256"], gate_metadata, approval_plan_hashes)
        consumed = True
        record(
            "plan_consumed",
            plan_sha256=inputs["plan_sha256"],
            apply_count=1,
            capacity_reservation_id=probe["capacity_reservation_id"],
        )
        apply_call_started = True
        adapter.apply(plan, started + 2400, record)
        apply_call_started = False
        if not cancel_reservation("gpu_hosts_running", adapter.now() + 30):
            raise CapacityReservationCleanupFailure("post-Apply reservation cancel failed")
        adapter.ready(started + 2400, record)
        ready_completed = True
        record("ready", processes_resident=True, admissions_open=False)
        if adapter.quota_denied_after():
            gate.halt("INF-057 quota denied after launch")
            record(
                "quota_denial_reported",
                later_paid_work_halted=True,
                current_bounded_lifecycle_continues=True,
            )
        measure_started = True
        adapter.measure(started + EXPORT_START, record)
    except CapacityProbeFailure as exc:
        error = str(exc)
        exit_code = 2
        record(
            "work_ended",
            error=f"{type(exc).__name__}: {exc}",
            consumed=False,
            gate_plan_status=gate.plan_status(inputs["plan_sha256"]),
        )
    except InfrastructureAbort as exc:
        record("infrastructure_abort", **exc.details)
        error = str(exc)
        record("work_ended", error=f"{type(exc).__name__}: {exc}")
        if apply_call_started:
            cancel_reservation("apply_failed", adapter.now() + 30)
    except Exception as exc:
        if isinstance(exc, PaidHalt):
            gate.halt(str(exc))
        error = f"{type(exc).__name__}: {exc}"
        record("work_ended", error=error)
        if apply_call_started:
            cancel_reservation("apply_failed", adapter.now() + 30)
    finally:
        if consumed:
            if reservation is not None and cancellation_attempts == 0:
                cancel_reservation("lifecycle_failed_before_apply", adapter.now() + 30)
            safe_to_close = ready_completed
            if measure_started and hasattr(adapter, "recover_measure"):
                try:
                    safe_to_close = adapter.recover_measure(started + EXPORT_START, record)
                except Exception as exc:
                    safe_to_close = False
                    record("measure_state_unknown", error=str(exc), close_sent=False)
                    # A failed confirmation is not evidence of host failure. Preserve
                    # admissions through the original work cutoff even on channel loss.
                    adapter.wait_until(started + EXPORT_START)
            try:
                if safe_to_close:
                    adapter.close_admissions(min(started + TEARDOWN_START, adapter.now() + 30))
                    record("admissions_closed")
                else:
                    record(
                        "admissions_close_skipped",
                        reason=(
                            "readiness incomplete"
                            if not ready_completed
                            else "host running or unknown; host owns finish"
                        ),
                    )
            except Exception as exc:
                error = error or f"admission closure failed: {exc}"
            try:
                remaining = started + TEARDOWN_START - adapter.now()
                if not ready_completed and not measure_started and remaining > 0:
                    record("export_skipped", reason="readiness incomplete; bounded SSM diagnostics")
                    diagnostics = adapter.readiness_diagnostics(
                        min(started + TEARDOWN_START, adapter.now() + 60)
                    )
                    record("readiness_diagnostics_finished", hosts=diagnostics)
                elif remaining > 0:
                    record("export_attempted", allowance_s=min(600, remaining))
                    exported = adapter.export(min(started + TEARDOWN_START, adapter.now() + 600))
                    if not exported:
                        error = error or "export failed"
                    record("export_finished", complete=exported)
                else:
                    record("export_skipped", reason="teardown reserve")
            except Exception as exc:
                if not ready_completed and not measure_started:
                    record("readiness_diagnostics_finished", error=str(exc))
                else:
                    error = error or f"export failed: {exc}"
                    record("export_finished", complete=False, error=str(exc))
            cancel_reservation("before_destroy", started + ENVELOPE)
            if isinstance(adapter, Production):
                try:
                    tagged_clean = adapter.cancel_session_capacity_reservations(
                        started + ENVELOPE, record, "before_destroy"
                    )
                except Exception as exc:
                    tagged_clean = False
                    record(
                        "capacity_reservation_cancel_failed",
                        reason="before_destroy",
                        error=type(exc).__name__,
                        verified=False,
                    )
                if not tagged_clean:
                    capacity_cancel_failed = True
                    gate.halt("session capacity reservation cleanup not verified before destroy")
            try:
                # Cleanup gets the original absolute deadline even after Apply failure.
                record("destroy_started")
                adapter.destroy(started + ENVELOPE, record)
                record("destroy_finished")
            except Exception as exc:
                error = error or f"destroy failed: {exc}"
                record("destroy_failed", error=str(exc))
            try:
                remaining = adapter.verify_teardown(started + ENVELOPE)
                verified = not remaining
            except Exception as exc:
                remaining, verified = ["inventory query failed: " + str(exc)], False
            if capacity_cancel_failed:
                if "capacity-reservation-cancel-failed" not in remaining:
                    remaining.append("capacity-reservation-cancel-failed")
                verified = False
            record("teardown_verified", empty=verified, remaining=remaining)
            gate.finish(inputs["plan_sha256"], verified)
            if not verified:
                error = "teardown verification failed; paid work halted: " + str(remaining)
        else:
            remaining = []
            if (
                reservation is not None
                and cancellation_attempts == 0
                and not probe_cleanup_attempted
            ):
                cancel_reservation("unconsumed_lifecycle_exit", adapter.now() + 30)
            if capacity_cancel_failed:
                remaining = ["capacity-reservation-cancel-failed"]
                record("teardown_verified", empty=False, remaining=remaining)
    result = {
        "scenario": getattr(adapter, "scenario", None),
        "fixture": adapter.fixture,
        "aws_calls": adapter.aws_calls,
        "plan_sha256": inputs["plan_sha256"],
        "apply_count": int(consumed),
        "error": error,
        "exit_code": exit_code if error is not None else 0,
        "gate_plan_status": gate.plan_status(inputs["plan_sha256"]),
        "export_complete": exported,
        "remaining_inventory": remaining,
        "elapsed_s": adapter.now() - started,
        "deadline_s": ENVELOPE,
        "events": events,
        "entrypoint": "inference_platform.r1_lifecycle.execute",
    }
    receipt.write_bytes(encoded(result) + b"\n")
    return result


class Production:
    fixture = False

    def __init__(self, repo, inputs, directory, terraform=None):
        self.repo, self.inputs, self.directory = (
            Path(repo).resolve(),
            inputs,
            Path(directory).resolve(),
        )
        self.stack = self.repo / "infra/terraform/r1"
        self.terraform = (self.repo / inputs["terraform"]).resolve()
        if not self.terraform.is_file():
            raise FileNotFoundError("reviewed Terraform binary is missing")
        if terraform is not None:
            override = Path(terraform)
            if not override.is_absolute():
                override = self.repo / override
            if override.resolve() != self.terraform:
                raise ValueError("--terraform differs from the reviewed inputs terraform path")
        self.aws_calls = 0
        self.plan_path = self.directory / "consumed.tfplan"

    @staticmethod
    def now():
        return time.perf_counter()

    def child_environment(self):
        child_env = {
            **os.environ,
            "AWS_CLI_OUTPUT_ENCODING": "utf-8",
            "AWS_PROFILE": self.inputs["aws_profile"],
            "AWS_REGION": self.inputs["region"],
            "AWS_DEFAULT_REGION": self.inputs["region"],
        }
        plugin_path = self.inputs.get("session_manager_plugin_path")
        if plugin_path:
            plugin_dir = (self.repo / plugin_path).resolve().parent
            child_env["PATH"] = os.pathsep.join((str(plugin_dir), os.environ.get("PATH", "")))
        return child_env

    def command(self, argv, deadline, name):
        remaining = deadline - self.now()
        if remaining <= 0:
            raise TimeoutError(name + " deadline exhausted")
        stdout, stderr = self.directory / (name + ".stdout"), self.directory / (name + ".stderr")
        child_env = self.child_environment()
        is_operator = "inference_platform.r1_cloud_operator" in argv
        invocation_token = secrets.token_urlsafe(32) if is_operator else None
        if invocation_token is not None:
            child_env["R1_OPERATOR_INVOCATION"] = invocation_token
        with stdout.open("wb") as out, stderr.open("wb") as err:
            child = subprocess.Popen(
                argv,
                cwd=self.repo,
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
                start_new_session=os.name != "nt",
            )
            try:
                code = child.wait(timeout=remaining)
            except BaseException:
                try:
                    if invocation_token is not None:
                        results = terminate_operator_sessions(
                            self.repo / self.inputs["runtime_directory"], invocation_token
                        )
                        (self.directory / (name + "-session-termination.json")).write_bytes(
                            encoded(results) + b"\n"
                        )
                finally:
                    stop_forward(child)
                raise
        if code:
            raise RuntimeError(f"{name} exited {code}; retained private logs")
        return stdout.read_bytes()

    def tf(self, args, deadline, name):
        return self.command(
            [str(self.terraform), "-chdir=" + str(self.stack), *args], deadline, name
        )

    def aws(self, service, operation, args, deadline, name):
        self.aws_calls += 1
        return json.loads(
            self.command(
                [
                    "aws",
                    "--region",
                    self.inputs["region"],
                    "--profile",
                    self.inputs["aws_profile"],
                    service,
                    operation,
                    *args,
                    "--output",
                    "json",
                    "--no-cli-pager",
                ],
                deadline,
                name,
            ).decode("utf-8")
        )

    def capacity_reservation_filters(self):
        session = str(self.inputs["session_id"])
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", session):
            raise ValueError("session ID is not safe for the reservation tag filter")
        return [
            "Name=tag:Project,Values=multi-tenant-llm-inference-platform",
            "Name=tag:Session,Values=" + session,
            "Name=tag:Milestone,Values=INF-040",
        ]

    def describe_capacity_reservations(self, deadline, name, reservation_id=None):
        args = ["--cli-connect-timeout", str(CAPACITY_CLI_CONNECT_TIMEOUT_SECONDS)]
        args += ["--cli-read-timeout", str(CAPACITY_CLI_READ_TIMEOUT_SECONDS)]
        if reservation_id:
            args += ["--capacity-reservation-ids", reservation_id]
        else:
            args += ["--filters", *self.capacity_reservation_filters()]
        value = self.aws("ec2", "describe-capacity-reservations", args, deadline, name)
        reservations = value.get("CapacityReservations")
        if not isinstance(reservations, list):
            raise ValueError("DescribeCapacityReservations returned no reservation list")
        return reservations

    @staticmethod
    def _reservation_state(item):
        return str(item.get("State") or item.get("state") or "").lower()

    @staticmethod
    def _reservation_failure(item):
        details = []
        for key in (
            "Status",
            "status",
            "StatusCode",
            "statusCode",
            "StatusMessage",
            "statusMessage",
        ):
            value = item.get(key)
            if value is not None:
                details.append(
                    json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value)
                )
        reason = " ".join(details)
        code_match = CAPACITY_CODE.search(reason)
        capacity_match = CAPACITY_ERROR.search(reason)
        if code_match or capacity_match:
            return "capacity_unavailable", (
                code_match.group(0) if code_match else "InsufficientInstanceCapacity"
            )
        return "create_error", reason[:160] or "CapacityReservationFailed"

    def _wait_reservation_out_of_pending(self, reservation_id, deadline, timeout, name):
        stop = min(
            deadline - CAPACITY_RESERVATION_WINDOW_MARGIN_SECONDS,
            self.now() + timeout,
        )
        last_item = None
        while self.now() < stop:
            try:
                items = self.describe_capacity_reservations(stop, name, reservation_id)
            except Exception:
                # A just-created ID can be briefly invisible. Keep the last state
                # and retry until this bounded window closes.
                items = None
            if items is not None:
                if not items:
                    return None
                last_item = items[0]
                if self._reservation_state(last_item) != "pending":
                    return last_item
            remaining = stop - self.now()
            if remaining > 0:
                time.sleep(min(CAPACITY_RESERVATION_POLL_SECONDS, remaining))
        return last_item

    def _reservation_matches_probe(self, item, reservation_id):
        count = item.get("TotalInstanceCount", item.get("totalInstanceCount"))
        available = item.get("AvailableInstanceCount", item.get("availableInstanceCount"))
        zone = item.get("AvailabilityZone", item.get("availabilityZone"))
        instance_type = item.get("InstanceType", item.get("instanceType"))
        platform = item.get("InstancePlatform", item.get("instancePlatform"))
        tenancy = item.get("Tenancy", item.get("tenancy"))
        criteria = item.get("InstanceMatchCriteria", item.get("instanceMatchCriteria"))
        return bool(
            reservation_id
            and self._reservation_state(item) == "active"
            and count == 2
            and available == 2
            and zone == self.inputs["availability_zone"]
            and instance_type == self.inputs["gpu_type"]
            and platform == "Linux/UNIX"
            and tenancy == "default"
            and str(criteria).lower() == "open"
        )

    def reserve_capacity(self, deadline):
        """Request an immediate, short-lived open ODCR before the durable consume."""
        if deadline <= self.now():
            return {
                "result": "create_error",
                "error_code": "TimeoutError",
                "zone": self.inputs.get("availability_zone"),
                "cleanup_verified": False,
            }
        end_date = (
            (
                datetime.datetime.now(datetime.UTC)
                + datetime.timedelta(seconds=CAPACITY_RESERVATION_END_GRACE_SECONDS)
            )
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        tags = (
            "ResourceType=capacity-reservation,Tags=["
            "{Key=Project,Value=multi-tenant-llm-inference-platform},"
            f"{{Key=Session,Value={self.inputs['session_id']}}},"
            "{Key=Milestone,Value=INF-040}]"
        )
        client_token = str(uuid.uuid4())
        args = [
            "--client-token",
            client_token,
            "--instance-type",
            self.inputs["gpu_type"],
            "--instance-platform",
            "Linux/UNIX",
            "--availability-zone",
            self.inputs["availability_zone"],
            "--instance-count",
            "2",
            "--instance-match-criteria",
            "open",
            "--tenancy",
            "default",
            "--end-date-type",
            "limited",
            "--end-date",
            end_date,
            "--tag-specifications",
            tags,
            "--cli-connect-timeout",
            str(CAPACITY_CLI_CONNECT_TIMEOUT_SECONDS),
            "--cli-read-timeout",
            str(CAPACITY_CLI_READ_TIMEOUT_SECONDS),
        ]
        try:
            response = self.aws(
                "ec2", "create-capacity-reservation", args, deadline, "capacity-reservation-create"
            )
        except Exception as exc:
            stderr_path = self.directory / "capacity-reservation-create.stderr"
            try:
                stderr = stderr_path.read_text(encoding="utf-8")
            except OSError:
                stderr = ""
            match = re.search(r"An error occurred \(([^)]+)\)", stderr)
            code = match.group(1) if match else type(exc).__name__
            result = "capacity_unavailable" if CAPACITY_CODE.search(code) else "create_error"
            return {
                "result": result,
                "error_code": code,
                "zone": self.inputs.get("availability_zone"),
                "end_date_utc": end_date,
                "cleanup_verified": False,
            }

        item = response.get("CapacityReservation")
        if not isinstance(item, dict):
            item = response.get("capacityReservation")
        item = item if isinstance(item, dict) else {}
        reservation_id = item.get("CapacityReservationId") or item.get("capacityReservationId")
        state = self._reservation_state(item)
        zone = item.get("AvailabilityZone") or item.get("availabilityZone")
        if state == "pending" and reservation_id:
            last_state = state
            try:
                settled = self._wait_reservation_out_of_pending(
                    reservation_id,
                    deadline,
                    CAPACITY_RESERVATION_PENDING_TIMEOUT_SECONDS,
                    "capacity-reservation-pending-probe",
                )
                if settled is not None:
                    item = settled
                    state = self._reservation_state(item)
                    zone = item.get("AvailabilityZone") or item.get("availabilityZone") or zone
                last_state = state or last_state
                if state == "failed":
                    result, code = self._reservation_failure(item)
                    return {
                        "result": result,
                        "error_code": code,
                        "zone": zone or self.inputs.get("availability_zone"),
                        "end_date_utc": end_date,
                        "capacity_reservation_id": reservation_id,
                        "state": state,
                        "cleanup_verified": True,
                        "cleanup_attempted": True,
                    }
                if state == "pending":
                    settled = self._wait_reservation_out_of_pending(
                        reservation_id,
                        deadline,
                        CAPACITY_RESERVATION_SETTLE_TIMEOUT_SECONDS,
                        "capacity-reservation-pending-settle",
                    )
                    if settled is not None:
                        item = settled
                        state = self._reservation_state(item)
                        zone = item.get("AvailabilityZone") or item.get("availabilityZone") or zone
                    last_state = state or last_state
                    if state == "active":
                        outcome = self.cancel_capacity(reservation_id, self.now() + 30)
                        return {
                            "result": "create_error",
                            "error_code": "ReservationPendingTimeout",
                            "zone": zone or self.inputs.get("availability_zone"),
                            "end_date_utc": end_date,
                            "capacity_reservation_id": reservation_id,
                            "state": state,
                            "cleanup_verified": outcome["verified"],
                            "cleanup_attempted": True,
                        }
                    if state == "failed":
                        result, code = self._reservation_failure(item)
                        return {
                            "result": result,
                            "error_code": code,
                            "zone": zone or self.inputs.get("availability_zone"),
                            "end_date_utc": end_date,
                            "capacity_reservation_id": reservation_id,
                            "state": state,
                            "cleanup_verified": True,
                            "cleanup_attempted": True,
                        }
                    return {
                        "result": "partial",
                        "error_code": "ReservationPendingTimeout",
                        "zone": zone or self.inputs.get("availability_zone"),
                        "end_date_utc": end_date,
                        "capacity_reservation_id": reservation_id,
                        "state": state or last_state or "unknown",
                        "cleanup_verified": False,
                    }
            except Exception:
                return {
                    "result": "partial",
                    "error_code": "ReservationStateUnknown",
                    "zone": zone or self.inputs.get("availability_zone"),
                    "end_date_utc": end_date,
                    "capacity_reservation_id": reservation_id,
                    "state": last_state or "unknown",
                    "cleanup_verified": False,
                }

        if state == "failed":
            result, code = self._reservation_failure(item)
            return {
                "result": result,
                "error_code": code,
                "zone": zone or self.inputs.get("availability_zone"),
                "end_date_utc": end_date,
                "capacity_reservation_id": reservation_id,
                "state": state,
                "cleanup_verified": True,
                "cleanup_attempted": True,
            }
        exact = self._reservation_matches_probe(item, reservation_id)
        return {
            "result": "success" if exact else "partial",
            "error_code": None if exact else "ReservationAttributesMismatch",
            "zone": zone or self.inputs.get("availability_zone"),
            "end_date_utc": end_date,
            "capacity_reservation_id": reservation_id,
            "state": state,
            "cleanup_verified": False if not exact else True,
        }

    def cancel_capacity(self, reservation_id, deadline):
        """Idempotently cancel one session reservation and confirm its terminal state."""
        current = self.describe_capacity_reservations(
            deadline, "capacity-reservation-before-cancel", reservation_id
        )
        if not current:
            return {"verified": True, "state": "absent", "cancel_requested": False}
        state = self._reservation_state(current[0])
        if state == "pending":
            settled = self._wait_reservation_out_of_pending(
                reservation_id,
                deadline,
                CAPACITY_RESERVATION_SETTLE_TIMEOUT_SECONDS,
                "capacity-reservation-cancel-pending-wait",
            )
            if settled is None:
                return {"verified": True, "state": "absent", "cancel_requested": False}
            current = [settled]
            state = self._reservation_state(settled)
            if state == "pending":
                return {"verified": False, "state": "pending", "cancel_requested": False}
        terminal = CAPACITY_RESERVATION_TERMINAL_STATES
        cancelable = {"active", "assessing", "delayed", "scheduled"}
        requested = False
        if state in cancelable:
            self.aws(
                "ec2",
                "cancel-capacity-reservation",
                [
                    "--capacity-reservation-id",
                    reservation_id,
                    "--cli-connect-timeout",
                    str(CAPACITY_CLI_CONNECT_TIMEOUT_SECONDS),
                    "--cli-read-timeout",
                    str(CAPACITY_CLI_READ_TIMEOUT_SECONDS),
                ],
                deadline,
                "capacity-reservation-cancel",
            )
            requested = True
        elif state not in terminal:
            return {"verified": False, "state": state or "unknown", "cancel_requested": False}
        after = self.describe_capacity_reservations(
            deadline, "capacity-reservation-after-cancel", reservation_id
        )
        final_state = str(after[0].get("State", "absent")).lower() if after else "absent"
        verified = not after or final_state in terminal
        return {"verified": verified, "state": final_state, "cancel_requested": requested}

    def cancel_session_capacity_reservations(self, deadline, record=None, reason="session_cleanup"):
        reservations = self.describe_capacity_reservations(
            deadline, "capacity-reservation-session-inventory"
        )
        clean = True
        for item in reservations:
            reservation_id = item.get("CapacityReservationId")
            state = self._reservation_state(item)
            if state not in CAPACITY_RESERVATION_TERMINAL_STATES:
                if not reservation_id:
                    clean = False
                    continue
                if record is not None:
                    record(
                        "capacity_reservation_cancel_started",
                        reason=reason,
                        capacity_reservation_id=reservation_id,
                        state=state,
                    )
                try:
                    outcome = self.cancel_capacity(reservation_id, deadline)
                    clean = clean and outcome["verified"]
                    if record is not None:
                        record(
                            "capacity_reservation_cancelled"
                            if outcome["verified"]
                            else "capacity_reservation_cancel_failed",
                            reason=reason,
                            capacity_reservation_id=reservation_id,
                            state=outcome["state"],
                            cancel_requested=outcome["cancel_requested"],
                            verified=outcome["verified"],
                        )
                except Exception as exc:
                    clean = False
                    if record is not None:
                        record(
                            "capacity_reservation_cancel_failed",
                            reason=reason,
                            capacity_reservation_id=reservation_id,
                            error=type(exc).__name__,
                            verified=False,
                        )
        return clean

    def preflight(self, plan, inputs, record=None):
        validate_reviewed_bundle(self.repo, inputs)
        relative_plugin = Path(inputs["session_manager_plugin_path"])
        if relative_plugin.is_absolute() or ".." in relative_plugin.parts:
            raise ValueError("session-manager-plugin path must be repo-relative")
        plugin = (self.repo / relative_plugin).resolve()
        try:
            plugin.relative_to(self.repo.resolve())
        except ValueError as exc:
            raise ValueError("session-manager-plugin path escapes the repository") from exc
        if not plugin.is_file():
            raise FileNotFoundError("pinned session-manager-plugin is missing")
        plugin_hash = sha(plugin.read_bytes())
        if plugin_hash != inputs["session_manager_plugin_sha256"]:
            raise ValueError("pinned session-manager-plugin SHA256 mismatch")
        plugin_version = (
            self.command([str(plugin), "--version"], self.now() + 30, "plugin-version")
            .decode("utf-8")
            .strip()
        )
        if not plugin_version:
            raise ValueError("session-manager-plugin --version returned no version line")
        aws_version = self.command(["aws", "--version"], self.now() + 30, "aws-version")
        aws_version = aws_version.decode("utf-8").strip()
        if not aws_version:
            raise ValueError("aws --version returned no version line")
        terraform_sha256 = sha(self.terraform.read_bytes())
        terraform_version = (
            self.command([str(self.terraform), "version"], self.now() + 30, "terraform-version")
            .decode("utf-8")
            .strip()
        )
        if not terraform_version:
            raise ValueError("terraform version returned no version line")
        self.preflight_toolchain = {
            "session_manager_plugin": {
                "path": relative_plugin.as_posix(),
                "sha256": plugin_hash,
                "version": plugin_version,
            },
            "aws_version": aws_version,
            "terraform": {
                "path": str(self.terraform),
                "sha256": terraform_sha256,
                "version": terraform_version,
            },
        }
        if record is not None:
            record("operator_toolchain", **self.preflight_toolchain)
        # Copy verified bytes once, fsync, and Apply ONLY this copy, never re-plan.
        with self.plan_path.open("xb") as stream:
            stream.write(plan)
            stream.flush()
            os.fsync(stream.fileno())
        document = json.loads(
            self.tf(["show", "-json", str(self.plan_path)], self.now() + 60, "saved-plan")
        )
        if document["variables"]["aws_region"]["value"] != inputs["region"]:
            raise ValueError("saved-plan region mismatch")
        if document["variables"]["aws_profile"]["value"] != inputs["aws_profile"]:
            raise ValueError("saved-plan AWS profile mismatch")
        if document["variables"]["availability_zone"]["value"] != inputs["availability_zone"]:
            raise ValueError("saved-plan Availability Zone differs from the capacity probe zone")
        changes = document.get("resource_changes", [])
        if any(item["change"]["actions"] != ["create"] for item in changes):
            raise ValueError("R1 plan must only create isolated session resources")
        instances = [x["change"]["after"] for x in changes if x["type"] == "aws_instance"]
        expected = {
            role: (inputs["gpu_type"] if role.startswith("gpu") else inputs["cpu_type"])
            for role in ROLES
        }
        if {x["tags"]["Role"]: x["instance_type"] for x in instances} != expected or len(
            instances
        ) != 4:
            raise ValueError("saved plan does not contain exact four-host topology")
        if any(x["tags"].get("Session") != inputs["session_id"] for x in instances):
            raise ValueError("saved-plan session tag mismatch")
        if Decimal(str(document["variables"]["m4_estimate_usd"]["value"])) != Decimal(
            str(inputs["m4_estimate_usd"])
        ):
            raise ValueError("saved-plan cost differs from exact reviewed inputs")
        for item in instances:
            gpu = item["tags"]["Role"].startswith("gpu")
            root = item["root_block_device"][0]
            if (
                item["ami"] != inputs["gpu_ami" if gpu else "cpu_ami"]
                or root["volume_size"] != (200 if gpu else 40)
                or root["volume_type"] != "gp3"
                or not root["encrypted"]
                or not root["delete_on_termination"]
                or root["iops"] != 3000
                or root["throughput"] != 125
            ):
                raise ValueError("saved-plan AMI/storage differs from registered topology")
            if gpu:
                reservation = item.get("capacity_reservation_specification") or []
                if (
                    len(reservation) != 1
                    or reservation[0].get("capacity_reservation_preference")
                    != "capacity-reservations-only"
                    or item.get("tenancy") != "default"
                ):
                    raise ValueError(
                        "saved GPU plan must require the matching default-tenancy capacity reservation"
                    )
        if (
            sha((self.repo / inputs["cache_secret_path"]).read_bytes())
            != inputs["cache_secret_sha256"]
        ):
            raise ValueError("reviewed cache salt secret changed")
        identity = self.aws("sts", "get-caller-identity", [], self.now() + 30, "identity-before")
        if sha(identity["Account"].encode()) != inputs["account_id_sha256"]:
            raise ValueError("AWS account differs from refreshed exact plan")
        if self.quota_denied_after():
            raise QuotaDenied("INF-057 denied before launch; paid work halted")
        self.fresh_footprint()
        state = json.loads(self.tf(["show", "-json"], self.now() + 60, "state-before"))
        if state.get("values", {}).get("root_module", {}).get("resources"):
            raise ValueError("R1 Terraform state must be empty before Apply")
        if self.verify_teardown(self.now() + 60):
            raise ValueError("existing session-tag inventory before Apply")

    def apply(self, plan, deadline, record):
        if sha(self.plan_path.read_bytes()) != self.inputs["plan_sha256"]:
            raise ValueError("consumed plan changed")
        from .terraform_apply_watchdog import bounded_apply

        apply_started = time.time()
        apply_start_utc = _utc_timestamp(apply_started)
        receipt = self.directory / "apply-watchdog.json"
        stdout = self.directory / "apply.stdout"
        stderr = self.directory / "apply.stderr"
        argv = self.apply_argv()
        seconds = min(
            float(getattr(self, "apply_watchdog_seconds", APPLY_WATCHDOG_SECONDS)),
            max(0.01, deadline - self.now()),
        )
        record("apply_started", watchdog_limit_s=seconds)
        try:
            code = bounded_apply(
                argv,
                receipt,
                seconds=seconds,
                grace=float(
                    getattr(self, "apply_interrupt_grace_s", APPLY_INTERRUPT_GRACE_SECONDS)
                ),
                cwd=self.repo,
                env=self.child_environment(),
                stdout_path=stdout,
                stderr_path=stderr,
            )
        except Exception as exc:
            raise InfrastructureAbort(
                {
                    "cause": "error",
                    "source": "apply_runner",
                    "capacity_event_count": 0,
                    "error_code": type(exc).__name__,
                    "availability_zone": self.inputs.get("availability_zone"),
                    "time_span_utc": {
                        "start_utc": apply_start_utc,
                        "end_utc": _utc_timestamp(time.time()),
                    },
                    "instance_type_counts": {},
                    "cloudtrail_lookup": "not_attempted",
                }
            ) from exc
        apply_end_utc = _utc_timestamp(time.time())
        if code == 0:
            record("apply_finished", exit_code=0)
            return
        watchdog = json.loads(receipt.read_bytes())
        output_capacity = bool(watchdog.get("capacity_error_observed"))
        cloudtrail = None
        lookup_status = "not_needed"
        source = (
            "apply_output"
            if output_capacity
            else ("watchdog" if watchdog.get("deadline_exceeded") else "apply_exit")
        )
        cause = (
            "capacity"
            if output_capacity
            else "timeout"
            if watchdog.get("deadline_exceeded")
            else "error"
        )
        if not output_capacity:
            lookup_status = "no_capacity_events"
            try:
                cloudtrail = self.lookup_capacity_events(apply_start_utc, apply_end_utc)
                if cloudtrail["capacity_event_count"]:
                    cause = "capacity"
                    source = "cloudtrail"
                    lookup_status = "capacity_events_found"
                else:
                    source = "watchdog" if watchdog.get("deadline_exceeded") else "apply_exit"
                    if cloudtrail.get("lookup_results_truncated"):
                        lookup_status = "no_capacity_match_in_truncated_page"
            except Exception as exc:
                # The Terraform output and process deadline remain authoritative when
                # the optional, bounded diagnostic is unavailable. Keep raw details private.
                lookup_status = "lookup_failed:" + type(exc).__name__
        if source == "cloudtrail" and cloudtrail is not None:
            summary = cloudtrail
        elif output_capacity:
            summary = self.apply_output_capacity_summary(watchdog, apply_start_utc, apply_end_utc)
        else:
            summary = {
                "capacity_event_count": 0,
                "error_code": None,
                "availability_zone": self.inputs.get("availability_zone"),
                "time_span_utc": {"start_utc": apply_start_utc, "end_utc": apply_end_utc},
                "instance_type_counts": {},
            }
        details = {
            "cause": cause,
            "source": source,
            **summary,
            "cloudtrail_lookup": lookup_status,
            "cloudtrail_event_count": cloudtrail["lookup_event_count"]
            if cloudtrail is not None
            else None,
            "cloudtrail_results_truncated": cloudtrail["lookup_results_truncated"]
            if cloudtrail is not None
            else None,
            "watchdog_limit_s": watchdog.get("wall_clock_limit_seconds"),
            "watchdog_elapsed_s": watchdog.get("elapsed_seconds"),
        }
        raise InfrastructureAbort(details)

    def apply_argv(self):
        return [
            str(self.terraform),
            "-chdir=" + str(self.stack),
            "apply",
            "-input=false",
            "-no-color",
            str(self.plan_path),
        ]

    def lookup_capacity_events(self, start_utc, end_utc):
        response = self.aws(
            "cloudtrail",
            "lookup-events",
            [
                "--lookup-attributes",
                "AttributeKey=EventName,AttributeValue=RunInstances",
                "--start-time",
                start_utc,
                "--end-time",
                end_utc,
                "--no-paginate",
                "--cli-connect-timeout",
                "5",
                "--cli-read-timeout",
                "10",
            ],
            self.now() + 15,
            "apply-capacity-cloudtrail",
        )
        return summarize_capacity_events(response, self.inputs.get("availability_zone"))

    def apply_output_capacity_summary(self, watchdog, start_utc, end_utc):
        codes = watchdog.get("capacity_error_codes", [])
        zones = watchdog.get("availability_zones", [])
        return {
            "capacity_event_count": watchdog.get("capacity_error_count", 0),
            "error_code": ",".join(codes) or "InsufficientInstanceCapacity",
            "availability_zone": ",".join(zones) or self.inputs.get("availability_zone"),
            "time_span_utc": {"start_utc": start_utc, "end_utc": end_utc},
            "instance_type_counts": {},
        }

    def fresh_footprint(self):
        limits = {}
        for family, code in (("gvt", "L-DB2E81BA"), ("standard", "L-1216C47A")):
            value = self.aws(
                "service-quotas",
                "get-service-quota",
                ["--service-code", "ec2", "--quota-code", code],
                self.now() + 30,
                "preapply-quota-" + family,
            )
            limits[family] = value["Quota"]["Value"]
        value = self.aws("ec2", "describe-instances", [], self.now() + 30, "preapply-all-instances")
        live = [
            x
            for r in value["Reservations"]
            for x in r["Instances"]
            if x["State"]["Name"] != "terminated"
        ]
        if any(
            any(
                t["Key"] == "Project" and t["Value"] == "multi-tenant-llm-inference-platform"
                for t in x.get("Tags", [])
            )
            for x in live
        ):
            raise PaidHalt(
                "unexpected existing project instances; all earlier hosts must be terminated"
            )
        used = {"gvt": 0, "standard": 0}
        if live:
            value = self.aws(
                "ec2",
                "describe-instance-types",
                ["--instance-types", *sorted({x["InstanceType"] for x in live})],
                self.now() + 30,
                "preapply-live-shapes",
            )
            vcpus = {
                x["InstanceType"]: x["VCpuInfo"]["DefaultVCpus"] for x in value["InstanceTypes"]
            }
            for x in live:
                if x["State"]["Name"] in {"pending", "running", "shutting-down"}:
                    used["gvt" if x["InstanceType"].startswith(("g", "vt")) else "standard"] += (
                        vcpus[x["InstanceType"]]
                    )
        if used["gvt"] + 8 > limits["gvt"] or used["standard"] + 16 > limits["standard"]:
            raise ValueError("fresh quota/usage cannot admit exact four-host footprint")

    def step(self, name, deadline):
        argv = self.inputs["commands"][name]
        if not argv or not all(isinstance(x, str) for x in argv):
            raise ValueError("missing reviewed lifecycle command: " + name)
        # Source-bound argv; no shell/string expansion. Absolute deadline propagated.
        return self.command(
            [*argv, "--deadline-unix-s", str(time.time() + max(0, deadline - self.now()))],
            deadline,
            name,
        )

    def ready(self, deadline, record):
        self.step("ready", deadline)

    def measure(self, deadline, record):
        self.step("measure", deadline)

    def wait_until(self, deadline):
        while self.now() < deadline:
            time.sleep(min(5, deadline - self.now()))

    def recover_measure(self, deadline, record):
        from .r1_cloud_operator import Operator

        # Separate process/channel from the failed measure subprocess. Give even
        # an already reached cutoff a short read budget, inside the export reserve.
        operator = Operator(
            self.repo,
            self.inputs,
            self.repo / self.inputs["runtime_directory"],
            time.time() + max(1, deadline - self.now()),
        )
        running = operator.monitor_measure()
        record("measure_state_confirmed", running=running, close_sent=False)
        return not running

    def close_admissions(self, deadline):
        self.step("close", deadline)

    def export(self, deadline):
        self.step("export", deadline)
        return True

    def readiness_diagnostics(self, deadline):
        from .r1_cloud_operator import Operator

        operator = Operator(
            self.repo,
            self.inputs,
            self.repo / self.inputs["runtime_directory"],
            time.time() + max(0.001, deadline - self.now()),
        )
        # Detailed host output stays in runtime; lifecycle receipt retains status only.
        return [
            {k: value[k] for k in ("role", "Status", "error") if k in value}
            for value in operator.readiness_diagnostics()
        ]

    def quota_denied_after(self):
        # Pending quota grants no capacity; a denial halts future paid work.
        request_id = self.inputs.get("inf057_request_id")
        if not request_id:
            return False
        item = self.aws(
            "service-quotas",
            "get-requested-service-quota-change",
            ["--request-id", request_id],
            self.now() + 15,
            "quota-decision",
        )
        quota = item["RequestedQuota"]
        if quota["Status"] == "DENIED":
            return True
        if quota["Status"] == "CASE_CLOSED":
            current = self.aws(
                "service-quotas",
                "get-service-quota",
                ["--service-code", "ec2", "--quota-code", "L-DB2E81BA"],
                self.now() + 15,
                "closed-case-current-quota",
            )
            return current["Quota"]["Value"] < quota["DesiredValue"]
        return False

    def destroy(self, deadline, record):
        self.tf(["destroy", "-auto-approve", "-input=false", "-no-color"], deadline - 30, "destroy")

    def verify_teardown(self, deadline):
        filters = [
            "Name=tag:Project,Values=multi-tenant-llm-inference-platform",
            "Name=tag:Session,Values=" + self.inputs["session_id"],
        ]
        inventories = (
            "instances",
            "volumes",
            "addresses",
            "network-interfaces",
            "security-groups",
            "subnets",
            "route-tables",
            "internet-gateways",
            "vpcs",
        )
        remaining = []
        for noun in inventories:
            value = self.aws(
                "ec2", "describe-" + noun, ["--filters", *filters], deadline, "inventory-" + noun
            )
            if noun == "instances":
                items = [
                    x
                    for r in value["Reservations"]
                    for x in r["Instances"]
                    if x["State"]["Name"] != "terminated"
                ]
            else:
                items = next(v for v in value.values() if isinstance(v, list))
            if items:
                remaining.append(noun)
        reservations = self.describe_capacity_reservations(
            deadline, "inventory-capacity-reservations"
        )
        if any(
            str(item.get("State", "")).lower() not in CAPACITY_RESERVATION_TERMINAL_STATES
            for item in reservations
        ):
            remaining.append("capacity-reservations")
        prefix = "r1-" + self.inputs["session_id"] + "-"
        for noun, key in (("roles", "Roles"), ("instance-profiles", "InstanceProfiles")):
            value = self.aws("iam", "list-" + noun, [], deadline, "inventory-iam-" + noun)
            if any(
                x["RoleName" if noun == "roles" else "InstanceProfileName"].startswith(prefix)
                for x in value[key]
            ):
                remaining.append("iam-" + noun)
        state = json.loads(self.tf(["show", "-json"], deadline, "state-after"))
        if state.get("values", {}).get("root_module", {}).get("resources"):
            remaining.append("terraform-state")
        return remaining


def committed_approval(repo, inputs_path):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args])

    def validate(inputs):
        if git("status", "--porcelain", "--untracked-files=no").strip():
            raise ValueError("paid execution requires a clean committed tree")
        review = git("show", "HEAD:REVIEW.md").decode("utf-8")
        span = review.split("\n## Claude review rounds\n", 1)[1].split("\n## Findings\n", 1)[0]
        rounds = list(re.finditer(r"(?m)^### Round (\d+)\b", span))
        latest = span[rounds[-1].end() :]
        markers = re.findall(
            r"(?m)^- R1 PAID PLAN APPROVED: plan_sha256=([0-9a-f]{64}); target=([0-9a-f]{40}); review_round=(\d+)\s*$",
            latest,
        )
        plan_hashes = frozenset(marker[0] for marker in markers)
        matching = [marker for marker in markers if marker[0] == inputs["plan_sha256"]]
        if (
            not 1 <= len(markers) <= 4
            or len(plan_hashes) != len(markers)
            or any(marker[2] != rounds[-1][1] for marker in markers)
            or len(matching) != 1
        ):
            raise ValueError("latest committed Claude exact R1 plan approval required")
        target = matching[0][1]
        git("merge-base", "--is-ancestor", target, "HEAD")
        source_head = inputs.get("source_head")
        if not isinstance(source_head, str) or not re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_head
        ):
            raise ValueError("invalid bound R1 source_head")
        git("merge-base", "--is-ancestor", source_head, target)
        relative = inputs_path.resolve().relative_to(repo.resolve()).as_posix()
        if git("show", target + ":" + relative) != inputs_path.read_bytes():
            raise ValueError("R1 inputs differ from Claude's exact target")
        for path, expected in inputs["source_sha256"].items():
            if (
                sha(git("show", "HEAD:" + path)) != expected
                or sha(git("show", target + ":" + path)) != expected
                or sha(git("show", source_head + ":" + path)) != expected
            ):
                raise ValueError("stale/unreviewed source: " + path)
        validate.review_round = int(rounds[-1][1])
        return plan_hashes

    return validate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--saved-plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument(
        "--apply", action="store_true", help="paid: requires committed Claude exact-plan approval"
    )
    operation.add_argument(
        "--recover",
        action="store_true",
        help="destroy/verify a durably consumed lifecycle; never Apply",
    )
    args = parser.parse_args()
    repo = args.repo.resolve()
    inputs_path = args.inputs.resolve()
    saved_plan_path = args.saved_plan.resolve()
    output = args.output.resolve()
    inputs = json.loads(inputs_path.read_bytes())
    validate_inputs_commands(repo, inputs_path, inputs)
    plan = saved_plan_path.read_bytes()

    runtime = (repo / inputs["runtime_directory"]).resolve()

    def same_or_within(path, directory):
        return path == directory or directory in path.parents

    def overlaps(path, directory):
        return same_or_within(path, directory) or same_or_within(directory, path)

    if overlaps(output, runtime):
        parser.error("--output must not equal, contain, or lie inside runtime_directory")

    protected_directories = (
        ("saved plan", saved_plan_path.parent),
        ("bundle", (repo / inputs["bundle_path"]).resolve().parent),
        (
            "session-manager-plugin",
            (repo / inputs["session_manager_plugin_path"]).resolve().parent,
        ),
        ("Terraform", (repo / inputs["terraform"]).resolve().parent),
    )
    for name, directory in protected_directories:
        if same_or_within(output, directory):
            parser.error(f"--output must not lie inside the pinned {name} directory")

    output.mkdir(parents=True, exist_ok=False)
    common = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "--git-common-dir"], text=True
    ).strip()
    common = Path(common) if Path(common).is_absolute() else repo / common
    gate = ConsumeGate(common / "r1-paid-consumption.sqlite3")
    if args.recover:
        binding = gate.recovery_inputs(inputs["plan_sha256"])
        reservation_id = binding.pop("_capacity_reservation_id", None)
        binding.pop("_approval_review_round", None)
        binding.pop("_approval_plan_sha256", None)
        if sha(plan) != inputs["plan_sha256"] or binding != inputs:
            raise ValueError("recovery inputs differ from durable consumed plan")
        adapter = Production(repo, inputs, output)
        end = adapter.now() + 300
        cancellation_attempts, cancellation_failed = [], False

        def cancel_for_recovery(reason):
            nonlocal cancellation_failed
            try:
                outcomes = []
                if reservation_id:
                    outcomes.append(adapter.cancel_capacity(reservation_id, end))
                clean = adapter.cancel_session_capacity_reservations(end)
                outcomes.append(
                    {
                        "verified": clean,
                        "state": "session-inventory-clean" if clean else "remaining",
                        "cancel_requested": False,
                    }
                )
                for outcome in outcomes:
                    cancellation_attempts.append({"reason": reason, **outcome})
                if any(not outcome.get("verified") for outcome in outcomes):
                    cancellation_failed = True
            except Exception as exc:
                cancellation_failed = True
                cancellation_attempts.append(
                    {"reason": reason, "verified": False, "error": type(exc).__name__}
                )

        cancel_for_recovery("recovery_start")
        cancel_for_recovery("before_destroy")
        try:
            adapter.destroy(end, lambda *args, **kwargs: None)
        finally:
            remaining = adapter.verify_teardown(end)
            if cancellation_failed:
                remaining.append("capacity-reservation-cancel-failed")
            verified = not remaining
            gate.finish(inputs["plan_sha256"], verified)
            (output / "recovery.json").write_bytes(
                encoded(
                    {
                        "remaining": remaining,
                        "verified": verified,
                        "capacity_reservation_cancel_attempts": cancellation_attempts,
                    }
                )
            )
        return int(not verified)
    result = execute(
        Production(repo, inputs, output),
        plan,
        inputs,
        gate,
        committed_approval(repo, inputs_path),
        output / "lifecycle.json",
        inputs_path=inputs_path,
    )
    return int(result["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
