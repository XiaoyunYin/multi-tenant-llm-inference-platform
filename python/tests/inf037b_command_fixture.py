"""Explicit synthetic deployment factory for the production command entry point."""

import os
import threading
from pathlib import Path
from types import SimpleNamespace

from inf037b_fitness_fixture import attach
from inf037b_observations_fixture import attach as observations
from inf037b_setup_fixture import creation_raw, fixture, inventory, scope
from test_inf037b_terminal import Backend, Capacity

from inference_platform import inf037b_setup_observations as exports
from inference_platform.inf037b_archive import Archive, encode, strict_json
from inference_platform.inf037b_command import CommandPorts
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_preparation import ConcurrentPreparation


def factory(config):
    # This factory is a command-wiring fixture, not row 5 evidence. Its
    # dedicated row 5 unit tests exercise the source predicates; keep this
    # subprocess test focused on passing/invoking the live composition port.
    from inference_platform import inf037b_row5, inf037b_setup_fitness
    from inference_platform.inf037b_requests import RequestJoin

    join_requests = inf037b_setup_fitness.fitness_request_joins

    def fixture_request_joins(rows, probe_offers, control_offers, capture_end_ms):
        probe, _ = join_requests(rows, probe_offers, [], capture_end_ms)
        controls = RequestJoin([], [], capture_end_ms)
        controls.expected = list(control_offers)
        return probe, controls

    inf037b_setup_fitness.fitness_request_joins = fixture_request_joins

    def validate_fixture_row5(evidence, offers, *, configuration_sha256, **_sources):
        expected = {
            "known0": 0,
            "known1": 5,
            "known2": 10,
            "unknown": "refuse",
            "expired": "refuse",
        }
        if (
            not isinstance(evidence, dict)
            or evidence.get("schema") != "inf037b-row5-evidence-v1"
            or evidence.get("configuration_sha256") != configuration_sha256
            or not isinstance(offers, list)
            or len(offers) != 16
        ):
            raise ValueError("test factory received incomplete row 5 callback evidence")
        return {"controls": expected, "command_fixture": True}

    inf037b_row5.validate_control_evidence = validate_fixture_row5
    root = Path(config["directory"])
    with (root / "factories").open("a") as stream:
        stream.write(str(os.getpid()) + "\n")
    value = observations(attach(fixture()), boot="host")
    maximum_path = value["maximum_fixture_proof"]["path"]
    maximum_file = Path(config["maximum_fixture"]["path"])
    if maximum_file.exists():
        value["artifacts"][maximum_path] = maximum_file.read_bytes()
        value["maximum_fixture_proof"]["sha256"] = config["maximum_fixture"]["sha256"]
    binding = value["binding"]
    now = [1000]
    if (root / "setup").exists() and "result" in DurableStore(root / "setup", {}).read().get(
        "preparation", {}
    ):
        now[0] = 513200
    late_clock = root / "late-result-clock"
    if late_clock.exists():
        now[0] = max(now[0], int(late_clock.read_text()))
    barrier = threading.Barrier(2)
    joined = [False]
    original_collect, original_facts = ConcurrentPreparation.__call__, exports.file_facts

    def collected(adapter, operation, stop):
        result = original_collect(adapter, operation, stop)
        if operation == "preparation":
            joined[0] = True
        return result

    def file_facts(path):
        if joined[0]:
            with (root / "post-join-facts").open("a") as stream:
                stream.write(str(path) + "\n")
        return original_facts(path)

    ConcurrentPreparation.__call__, exports.file_facts = collected, file_facts
    if config.get("late_result_write"):
        original_write = DurableStore.write

        def write(store, state):
            original_write(store, state)
            if "result" in state.get("preparation", {}) and not late_clock.exists():
                now[0] += 60001
                late_clock.write_text(str(now[0]))

        DurableStore.write = write

    def sample():
        return {"clock_id": "measurement", "boot_id": "host", "ms": [now[0]] * 2}

    plan = {
        "session_id": binding["session_id"],
        "plan_hash": "a" * 64,
        "capacity": {"group_arn": "setup-group"},
        "C": "1970-01-01T00:00:01Z",
        "D_session": "1970-01-01T05:00:01Z",
    }
    rows = [
        {"event": "bound", "data": [plan]},
        {"event": "billing_origin", "data": {"t0_ms": 1000}},
        {
            "event": "consumed",
            "data": {"session_id": binding["session_id"], "plan_hash": plan["plan_hash"]},
        },
        {"event": "acquire_intent", "data": {"token": "original-token"}},
        {"event": "applied", "index": 0, "data": True},
    ]
    backend = Backend(scope())
    backend.now = 513200

    class Creation:
        def create(self, key, stop, context, record):
            record("i-fixture")
            return creation_raw(
                binding, 1000, source_inventory=strict_json(value["export_raw"])["source"]
            )

        def inventory(self, request, stop):
            return {
                "application": request,
                "complete": not config.get("unknown_inventory", False),
                "settled": True,
                "instance_ids": ["i-fixture"],
            }

    def capture(stop):
        barrier.wait(timeout=2)
        now[0] = 513100
        raw = value["export_raw"]
        if case := config.get("semantic_export_error"):
            exported = strict_json(raw)
            artifacts = value["export_artifacts"]
            # Change the actual archive and reseal it, then recompute every
            # manifest fact. Hash consistency must not mask a semantic failure.
            source = Path(artifacts["source/registration.json"]).parent
            safe = Path(artifacts["sanitized/registration.json"]).parent
            target = source if case == "integrity" else safe
            (target / "SHA256SUMS").unlink()
            if case == "integrity":
                segment = target / "raw/controller.jsonl"
                with segment.open("ab") as stream:
                    stream.write(b"torn segment")
                segment.with_suffix(".receipt.json").unlink()
            elif case == "label":
                registration = strict_json((target / "registration.json").read_bytes())
                registration["sanitized"] = False
                (target / "registration.json").write_bytes(encode(registration))
            else:
                receipt_path = target / "source-integrity.receipt.json"
                receipt = strict_json(receipt_path.read_bytes())
                if case == "source":
                    receipt["source_manifest_sha256"] = "b" * 64
                elif case == "pending":
                    receipt["pending_sse_streams"] = 1
                else:
                    raise AssertionError(case)
                receipt_path.write_bytes(encode(receipt))
            Archive(target).seal()
            exported["source"] = exports.inventory(source)
            exported["sanitized"] = exports.inventory(safe)
            if case == "integrity":
                # The sanitizer provenance follows the newly sealed raw source.
                (safe / "SHA256SUMS").unlink()
                receipt_path = safe / "source-integrity.receipt.json"
                receipt = strict_json(receipt_path.read_bytes())
                receipt["source_manifest_sha256"] = exported["source"]["SHA256SUMS"]["sha256"]
                receipt_path.write_bytes(encode(receipt))
                Archive(safe).seal()
                exported["sanitized"] = exports.inventory(safe)
            for receipt in (exported["interrupted"], exported["resumed"]):
                receipt["source_manifest_sha256"] = exported["sanitized"]["SHA256SUMS"]["sha256"]
            raw = encode(exported)
        if config.get("bad_export_raw"):
            exported = strict_json(raw)
            exported["source"]["registration.json"]["sha256"] = "b" * 64
            raw = encode(exported)
        return raw, value["export_artifacts"]

    def row5_stage(name, stop_ns):
        from inference_platform.inf037b_row5_sequence import STAGES

        with (root / "row5-stage-invoked").open("a") as stream:
            stream.write(name + "\n")
        return [
            {
                "request_id": f"control-{STAGES.index(name) * 2 + index:02d}",
                "snapshot_id": name,
                "gateway_uid": gateway,
            }
            for index, gateway in enumerate(("gateway0", "gateway1"))
        ]

    def gpu(stop, row5_stage):
        barrier.wait(timeout=2)
        # The factory's raw fixture is a recorded-response test input. Every
        # collection time, including mapping rows, is >= this branch's start.
        now[0] = 513100
        fitness = strict_json(value["fitness_raw"])
        for row in fitness["raw"]:
            row["collector_boot_id"] = "host"
        value["fitness_raw"] = encode(fitness)
        # Synthetic transitions exercise the five registered hook positions.
        known_requests = []
        for name in ("known0", "known1", "known2", "cached_stop_known1", "cached_restore_known2"):
            known_requests.extend(row5_stage(name, stop * 1_000_000))
        value["row5_known_requests"] = known_requests
        return {
            k: v
            for k, v in {**value, "raw": encode(value["bundle"])}.items()
            if k not in {"export_raw", "export_artifacts"}
        }

    def row5_control(stop, prepared):
        base = strict_json(prepared["fitness_raw"])
        with (root / "row5-control-invoked").open("a") as stream:
            stream.write(str(os.getpid()) + "\n")
        requests = [
            {
                "request_id": f"outage-{index:02d}",
                "snapshot_id": name,
                "gateway_uid": gateway,
            }
            for index, (name, gateway) in enumerate(
                (name, gateway)
                for name in ("unknown", "expired", "post_outage_known2")
                for gateway in ("gateway0", "gateway1")
            )
        ]
        return {
            "fitness_raw": encode(
                {
                    "schema": base["schema"],
                    "session_id": base["session_id"],
                    "pins": base["pins"],
                    "t0_ms": base["t0_ms"],
                    "raw": [],
                }
            ),
            "row5_control_requests": requests,
            "row5_evidence": {
                "schema": "inf037b-row5-evidence-v1",
                "configuration_sha256": base["pins"]["configuration"],
            },
        }

    def advance():
        now[0] += 2

    port, _ = inventory(scope(), advance)

    def phases(operation, stop, context):
        return {"operation": operation, "pid": os.getpid()}

    return CommandPorts(
        controller=SimpleNamespace(
            journal=SimpleNamespace(read=lambda: rows, close=lambda: None),
            capacity=Capacity(backend),
        ),
        creation=Creation(),
        capture=capture,
        gpu=gpu,
        row5_stage=row5_stage,
        row5_control=row5_control,
        inventory=port,
        sample=sample,
        phases=phases,
        backend=backend,
    )
