"""Recorded-response transports and filesystem rig for accepted controller replays."""

import copy
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import test_inf037b_controller as legacy
from test_m5_infra_safety import plan_fixture

from inference_platform.inf037b_archive import encode, sha, strict_json
from inference_platform.inf037b_authority import FencedAuthority
from inference_platform.inf037b_controller import Controller
from inference_platform.inf037b_durable_ports import FileJournal
from inference_platform.inf037b_ports import (
    Authority,
    BackstopPort,
    CapacityPort,
    FileGate,
    PlanArtifact,
)

WIRE = json.loads((Path(__file__).parent / "fixtures/inf037b_ports_authority.json").read_bytes())
LegacyRig = legacy.Rig
RECOVERY_CASES = []
CANCEL_CASES = []
DELAYED_APPLY_CASES = []


def artifacts(plans):
    result = []
    for plan in plans:
        shown = plan_fixture()
        shown["output_changes"]["capacity_binding"]["after"].update(
            group_arn=plan.capacity.group_arn, zone=plan.capacity.zone
        )
        target = shown["resource_changes"][1]["change"]["after"][
            "capacity_reservation_specification"
        ][0]["capacity_reservation_target"][0]
        target["capacity_reservation_resource_group_arn"] = plan.capacity.group_arn
        if plan.capacity.zone == "us-east-1b":
            shown["configuration"]["root_module"]["resources"][0]["expressions"]["subnet_ids"][
                "references"
            ] = ['aws_subnet.m5["1"].id', 'aws_subnet.m5["1"]', "aws_subnet.m5", "local.gpu_subnet"]
        shown_bytes = encode(shown)
        payload = b"offline immutable source bundle fixture\n"
        source = "a" * 40
        pins = encode(
            {
                "source_commit": source,
                "plan_sha256": plan.plan_hash,
                "show_sha256": sha(shown_bytes),
                "payload_sha256": sha(payload),
                "runtime": "offline-runtime-pin",
                "ordered_plan_hashes": [p.plan_hash for p in plans],
            }
        )
        result.append(PlanArtifact(plan, shown_bytes, payload, pins, source, "c" * 40))
    return result


def review_bytes(items):
    # A synthetic parser input, never written into REVIEW or an approval artifact.
    markers = []
    for item in items:
        markers.append(
            "- M5 V4 "
            + "PLAN APPROVED: "
            + "; ".join(f"{key}={value}" for key, value in item.hashes().items())
            + "; review_round=1"
        )
    return (
        "fixture\n## Claude review rounds\n### Round 1\n- Review basis: **COMMITTED**\n- Verdict: **NO_BLOCKING_FINDINGS**\n"
        + "\n".join(markers)
        + "\n## Findings\n"
    ).encode()


class Responses:
    def __init__(self, world, root):
        self.world = world
        self.gate = legacy.FakeGate(world)
        self.capacity = legacy.FakeCapacity(world)
        self.backstop = legacy.FakeBackstop(world)
        self.records = []
        self.requests = []
        self.application_inputs = {}
        self.change = None
        self.cut_operation = None
        self.cut_mode = None
        self.lost_request = None
        self.attach(root, initialize=True)

    def attach(self, root, *, initialize=False):
        identities = {
            "gate": "offline-executor",
            "capacity": "offline-capacity",
            "backstop": "offline-backstop",
        }
        self.services = {
            name: FencedAuthority(
                root / ("authority-" + name),
                identity,
                name,
                effect=self.backend,
                read=self.backend,
                reconcile=self.reconciled,
                initialize=initialize,
            )
            for name, identity in identities.items()
        }

    def __call__(self, raw, timeout):
        request = strict_json(raw)
        self.requests.append(copy.deepcopy(request))
        operation, key, body = (request[k] for k in ("operation", "key", "body"))
        assert 0 < timeout <= 10_000
        fixture = WIRE["operations"].get(operation, {})
        if "request_fields" in fixture:
            assert set(body) == set(fixture["request_fields"])
        if "request_body" in fixture:
            assert body == fixture["request_body"]
        if operation == self.cut_operation:
            self.cut_operation = None
            self.lost_request = raw
            if self.cut_mode == "authority_death":
                # A real SIGKILL while the authority owns the OS lock, after
                # pending's fsync and before any provider callback.
                script = """
import os, signal, sys
from inference_platform.inf037b_authority import FencedAuthority
def die(*args):
    os.kill(os.getpid(), signal.SIGKILL)
a=FencedAuthority(sys.argv[1],sys.argv[2],sys.argv[3],effect=die,read=die,reconcile=die)
a(sys.stdin.buffer.read(),2000)
"""
                service = self.services[request["namespace"]]
                child = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        script,
                        str(service.store.path),
                        service.identity,
                        service.namespace,
                    ],
                    input=raw,
                    capture_output=True,
                    timeout=10,
                )
                assert child.returncode == -9, child.stderr.decode()
                assert service.store.read()["pending"]["operation"] == operation
            if self.cut_mode == "authority_death_after_effect":
                assert operation == "odcr.cancel"
                service = self.services["capacity"]
                provider_path = service.store.path / "offline-provider.json"
                snapshot = {
                    "now": self.world.now,
                    "capacity": {k: v for k, v in vars(self.capacity).items() if k != "world"},
                }
                provider_path.write_bytes(encode(snapshot))
                script = """
import json, os, signal, sys
from pathlib import Path
from inference_platform.inf037b_authority import FencedAuthority
from inference_platform.inf037b_archive import encode
from test_inf037b_controller import World, FakeCapacity

path = Path(sys.argv[2])
snapshot = json.loads(path.read_bytes())
world = World()
world.now = snapshot['now']
capacity = FakeCapacity(world)
vars(capacity).update(snapshot['capacity'])
def effect(operation, key, body):
    assert operation == 'odcr.cancel'
    capacity.cancel(key, body['group'])
    # This separately persisted synthetic provider survives the executor's death.
    snapshot['capacity'] = {k:v for k,v in vars(capacity).items() if k != 'world'}
    snapshot['now'], snapshot['effects'] = world.now, world.trace
    with path.open('wb') as stream:
        stream.write(encode(snapshot))
        stream.flush()
        os.fsync(stream.fileno())
    os.kill(os.getpid(), signal.SIGKILL)
a = FencedAuthority(sys.argv[1], 'offline-capacity', 'capacity',
                    effect=effect, read=effect, reconcile=effect)
a(sys.stdin.buffer.read(), 2000)
"""
                child = subprocess.run(
                    [sys.executable, "-c", script, str(service.store.path), str(provider_path)],
                    input=raw,
                    capture_output=True,
                    timeout=10,
                )
                assert child.returncode == -9, child.stderr.decode()
                snapshot = strict_json(provider_path.read_bytes())
                vars(self.capacity).update(snapshot["capacity"])
                self.world.now = snapshot["now"]
                self.world.trace.extend((name, value) for name, value in snapshot["effects"])
                assert service.store.read()["pending"]["operation"] == operation
                assert self.capacity.cancelled[key]["verified"] is False
            raise legacy.Crash("request_" + str(self.cut_mode))
        answer = strict_json(self.services[request["namespace"]](raw, timeout))
        if self.change:
            self.change(request, answer)
        reply = encode(answer)
        self.records.append(
            {
                "request_utf8": raw.decode(),
                "response_utf8": reply.decode(),
                "request_sha256": sha(raw),
                "response_sha256": sha(reply),
            }
        )
        return reply

    def backend(self, operation, key, body):
        if operation == "application.lookup":
            result = self.gate.application(key)
            if result is not None:
                result["artifacts"] = self.application_inputs.get(key)
        elif operation == "application.apply":
            self.application_inputs[key] = body["artifacts"]
            self.gate.apply_once(body["binding"])
            result = self.gate.application(key)
            result["artifacts"] = body["artifacts"]
        elif operation == "odcr.lookup":
            result = self.capacity.lookup(key)
        elif operation == "odcr.acquire":
            result = self.capacity.acquire(key, legacy.Binding(**body))
        elif operation == "odcr.add":
            self.capacity.add(body["group"], body["reservation_id"])
            result = body
        elif operation == "odcr.members":
            result = self.capacity.members(key)
        elif operation == "odcr.cancel":
            self.capacity.cancel(key, body["group"])
            result = self.capacity.cancellation(key)
        elif operation == "backstop.arm":
            ok = self.backstop.arm(key, body["deadline_ms"])
            if not ok:
                raise OSError("offline backstop absent")
            result = body
        else:
            deadline = self.backstop.armed.get(key)
            result = (
                None
                if deadline is None
                else {
                    "session_id": key,
                    "deadline_ms": deadline,
                    "armed": True,
                    "alive": self.backstop.confirm_ok,
                    "durable": True,
                    "arm_id": "offline-arm-proof",
                }
            )
            self.world.op("confirm", deadline)
        return result

    def reconciled(self, operation, key, body):
        known, result = False, None
        if operation == "application.apply":
            result = self.gate.application(key)
            known = result is not None
            if known:
                result["artifacts"] = body["artifacts"]
        elif operation == "odcr.acquire":
            known = key in self.capacity.results
            result = self.capacity.lookup(key)
        elif operation == "odcr.add":
            known = body["reservation_id"] in self.capacity.group
            result = body
        elif operation == "odcr.cancel":
            known = key in self.capacity.cancelled
            result = self.capacity.cancellation(key)
        elif operation == "backstop.arm":
            known = self.backstop.armed.get(key) == body["deadline_ms"]
            result = body
        # This synthetic world is serialized with the executor and retains every
        # effect; absence here is an explicit no-execution proof, not SDK absence.
        return {"known": True, "executed": known, "result": result if known else None}


class Journal:
    def __init__(self, path, world):
        self.path, self.world = path, world
        self.writer = None
        self.cut = None
        self.initialized = False

    def close(self):
        if self.writer is not None:
            self.writer.close()
            self.writer = None

    def get(self):
        if self.writer is None:
            self.writer = FileJournal(self.path, self.world.clock, initialize=not self.initialized)
            self.initialized = True
        return self.writer

    @property
    def rows(self):
        return self.get().read()

    def read(self):
        return self.rows

    def acknowledged(self, row):
        self.world.op("fsync", row)
        if len(self.rows) == self.cut:
            self.cut = None
            self.close()
            raise legacy.Crash("journal_cut")

    def append_fsync(self, row):
        result = self.get().append_fsync(row)
        self.acknowledged(row)
        return result

    def append_origin_fsync(self, row):
        result = self.get().append_origin_fsync(row)
        self.acknowledged(result["row"])
        return result


class Gate(FileGate):
    @property
    def markers(self):
        return {
            k.removeprefix("marker/"): v
            for k, v in self.store.read()["values"].items()
            if k.startswith("marker/")
        }

    @property
    def consumptions(self):
        return {
            k.removeprefix("consume/"): v
            for k, v in self.store.read()["values"].items()
            if k.startswith("consume/")
        }

    @property
    def applies(self):
        return self.authority.transport.gate.applies

    def marker(self, binding):
        before = binding["plan_hash"] in self.markers
        result = super().marker(binding)
        if not before:
            self.authority.transport.world.op("marker", result)
        return result

    def consume(self, binding, admission_check):
        before = self.consumption(binding["session_id"])
        result = super().consume(binding, admission_check)
        if before is None:
            self.authority.transport.world.op("consume", result)
        return result


class Capacity(CapacityPort):
    def __getattr__(self, key):
        return getattr(self.authority.transport.capacity, key)

    def __setattr__(self, key, value):
        if (
            "authority" in self.__dict__
            and hasattr(self.authority.transport.capacity, key)
            and not callable(getattr(self.authority.transport.capacity, key))
        ):
            setattr(self.authority.transport.capacity, key, value)
        else:
            super().__setattr__(key, value)


class Backstop(BackstopPort):
    def __setattr__(self, key, value):
        if key in {"arm_ok", "confirm_ok"} and "authority" in self.__dict__:
            setattr(self.authority.transport.backstop, key, value)
        else:
            super().__setattr__(key, value)

    @property
    def armed(self):
        return self.authority.transport.backstop.armed


class Rig:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="inf037b-real-ports-"))
        self.world = legacy.World()
        self.responses = Responses(self.world, self.root)
        self.plans = legacy.plans()
        self.journal = Journal(self.root / "journal", self.world)
        self.gate = None
        self.ports(initialize=True)

    def close(self):
        if hasattr(self, "journal"):
            self.journal.close()
        target = self.root.resolve()
        if target.parent != Path(tempfile.gettempdir()).resolve() or not target.name.startswith(
            "inf037b-real-ports-"
        ):
            raise ValueError("unsafe fixture cleanup path")
        shutil.rmtree(target, ignore_errors=True)

    def __del__(self):
        if hasattr(self, "root"):
            self.close()

    def ports(self, *, initialize=False):
        self.port_plans = copy.deepcopy(self.plans)
        self.items = artifacts(self.plans)
        text = review_bytes(self.items)
        self.gate = Gate(
            self.root / "gate",
            Authority("offline-executor", "gate", self.responses),
            self.items,
            lambda commit, source: text,
            initialize=initialize,
        )
        self.capacity = Capacity(
            self.root / "capacity",
            Authority("offline-capacity", "capacity", self.responses),
            2,
            initialize=initialize,
        )
        self.backstop = Backstop(
            self.root / "backstop",
            Authority("offline-backstop", "backstop", self.responses),
            self.world.clock,
            "offline-operator",
            initialize=initialize,
        )

    def open(self):
        if self.port_plans != self.plans and not self.journal.rows:
            self.ports()
        self.journal.close()
        return Controller(
            self.plans,
            journal=self.journal,
            gate=self.gate,
            capacity=self.capacity,
            backstop=self.backstop,
            clock=self.world.clock,
        )

    def run(self, *, consume=True):
        # Install ports before the accepted harness inspects gate/capacity state.
        if self.gate is None:
            self.ports()
        return LegacyRig.run(self, consume=consume)

    def __deepcopy__(self, memo):
        self.journal.close()
        result = Rig()
        shutil.copytree(self.root, result.root, dirs_exist_ok=True)
        copied = copy.deepcopy(
            {"world": self.world, "responses": self.responses, "plans": self.plans}, memo
        )
        result.world, result.responses, result.plans = (
            copied[k] for k in ("world", "responses", "plans")
        )
        result.responses.attach(result.root)
        result.journal = Journal(result.root / "journal", result.world)
        result.journal.initialized = self.journal.initialized
        result.journal.cut = self.journal.cut
        result.ports()
        return result
