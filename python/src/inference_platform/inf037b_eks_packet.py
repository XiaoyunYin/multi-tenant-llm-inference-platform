"""4c canonical evidence sealing/start and immutable campaign assembly.

No paid-session packet, saved plan, marker or Apply is produced here. Real final
pins/maximum/sizing and host/runtime authority remain explicit 4e/4d inputs.
"""

import copy
from pathlib import Path

from .inf037b_archive import (
    Archive,
    durable_write,
    encode,
    envelope,
    file_facts,
    inspect_segment,
    iter_segment_rows,
    safe_file,
    sha,
    strict_json,
    verify_archive,
)
from .inf037b_attempts import AttemptController
from .inf037b_campaign import materialize_bundle, sanitized_campaign
from .inf037b_contract import MAX_ATTEMPTS, REGISTRATION_ID
from .inf037b_controller import utc_ms
from .inf037b_eks_stores import RecoveryPorts, facts, serial
from .inf037b_maximum import load_maximum
from .inf037b_packet import source_manifest, verify_sources
from .inf037b_resolver import BOUNDS_MS, SessionDeadline, exact, require, resolve
from .inf037b_setup_observations import inventory


def references(value):
    if isinstance(value, dict):
        if "path" in value and "sha256" in value:
            yield value
        for child in value.values():
            yield from references(child)
    elif isinstance(value, list):
        for child in value:
            yield from references(child)


def read_parent(path):
    path = Path(path)
    raw = path.read_bytes()
    receipt, rows = inspect_segment(path)
    require(receipt["torn_tail_offset"] is None, "4c:parent_torn")
    return raw, rows


def outcomes(rows):
    # Read-only projection; never run AttemptController's recovering constructor.
    journal = object.__new__(AttemptController)
    journal.events = [row["payload"] for row in rows]
    return journal.report()


class CanonicalPacket:
    def __init__(self, *, repository, root, binding, pins, clock, hook=None):
        self.repository, self.root = repository, Path(root)
        self.binding, self.pins, self.clock = copy.deepcopy(binding), copy.deepcopy(pins), clock
        self.hook = hook or (lambda phase: None)
        self.journal = repository.journal
        exact(repository.binding["controller"], binding, "4c:packet_store_controller")
        exact(repository.binding["pins"], pins, "4c:packet_store_pins")
        self.deadline = SessionDeadline(binding["C_ms"], binding["D_session_ms"], binding["t0_ms"])
        require(
            self.root.resolve().is_relative_to(
                Path(repository.binding["recovery"]["root"]).resolve()
            ),
            "4c:packet_ownership",
        )
        with self.journal.lock():
            state = self.journal.read()
            initial = {
                "binding": binding,
                "pins": pins,
                "starts": {},
                "start_intents": {},
                "captures": {},
                "owners": [],
                "sequence_checkpoint": [],
                "refusals": [],
            }
            state.setdefault("4c_packet", initial)
            exact(state["4c_packet"]["binding"], binding, "4c:packet_original_binding")
            exact(state["4c_packet"]["pins"], pins, "4c:packet_original_pins")
            self.journal.write(state)

    def state(self):
        with self.journal.lock():
            return self.journal.read()["4c_packet"]

    def update(self, mutate):
        with self.journal.lock():
            state = self.journal.read()
            mutate(state["4c_packet"])
            self.journal.write(state)

    def refuse(self, error, parent_rows=()):
        slots = outcomes(parent_rows)["slots"]
        invalid = [
            dict(
                slot,
                measurement_valid=False,
                packet_invalidated=True,
                packet_refusal=type(error).__name__ + ":" + str(error),
            )
            for slot in slots
        ]
        self.update(
            lambda state: (
                state["refusals"].append(
                    {
                        "at_ms": self.clock(),
                        "reason": type(error).__name__ + ":" + str(error),
                        "invalidated_outcomes": invalid,
                    }
                ),
                state.update(invalidated=True),
            )
        )

    def time(self, stop, *, completed=False):
        now = self.clock()
        require(
            type(now) is int
            and type(stop) is int
            and self.binding["t0_ms"] <= now
            and (now <= stop if completed else now < stop)
            and stop <= self.deadline.effective_ms,
            "4c:deadline",
        )
        return now

    def seal(self, inputs, decision, stop):
        try:
            return self._seal(inputs, decision, stop)
        except Exception as exc:
            self.refuse(exc)
            raise

    def _seal(self, inputs, decision, stop):
        self.time(stop)
        state = self.state()
        require(not state.get("invalidated"), "4c:packet_invalidated")
        if state.get("sealed"):
            exact(state["intent"]["inputs"], serial(inputs), "4c:packet_inputs_immutable")
            self.revalidate(stop)
            exact(state["sealed"]["decision_sha256"], sha(encode(decision)), "4c:original_decision")
            return True
        require("intent" not in state, "4c:interrupted_barrier")
        self.update(
            lambda state: state.update(
                intent={"at_ms": self.clock(), "stop_ms": stop, "inputs": serial(inputs)}
            )
        )
        self.hook("intent")
        start = inputs["resolution_started_ms"]
        require(
            self.binding["t0_ms"] <= start <= self.clock()
            and stop <= start + BOUNDS_MS["resolution"],
            "4c:resolution_origin",
        )
        sources = {
            name: Path(path).read_bytes() for name, path in inputs["source_artifacts"].items()
        }
        manifest = source_manifest(sources)
        verify_sources(manifest, sources)
        for name, expected in self.pins.items():
            require(name in sources, "4c:pin_artifact_missing")
            exact(sha(sources[name]), expected, "4c:source_pin_join")
        rows = {name: row["evidence"] for name, row in decision["rows"].items()}
        exact(resolve(rows, pins=self.pins), decision, "4c:decision_reproduction")
        observed = inputs["observation_artifacts"]
        for row in rows.values():
            require(
                self.binding["t0_ms"]
                <= row["observation_ms"][0]
                <= row["selected_ms"]
                <= self.clock(),
                "4c:observation_origin",
            )
        for ref in references(rows):
            require(ref["path"] in observed, "4c:observation_missing")
            exact(
                file_facts(Path(observed[ref["path"]]))["sha256"],
                ref["sha256"],
                "4c:observation_hash",
            )
        plan = Path(inputs["saved_plan"])
        exact(file_facts(plan)["sha256"], self.binding["plan_hash"], "4c:plan_hash")
        marker = inputs["review_marker"]
        exact(marker["committed"], True, "4c:review_committed")
        exact(marker["binding"]["plan_hash"], self.binding["plan_hash"], "4c:review_plan")
        exact(marker["binding"]["session_id"], self.binding["session_id"], "4c:review_session")
        exact(utc_ms(marker["binding"]["C"]), self.binding["C_ms"], "4c:review_C")
        exact(
            utc_ms(marker["binding"]["D_session"]),
            self.binding["D_session_ms"],
            "4c:review_D_session",
        )
        require(
            type(marker["review_commit"]) is str
            and len(marker["review_commit"]) == 40
            and set(marker["review_commit"]) <= set("0123456789abcdef"),
            "4c:review_identity",
        )
        require(
            marker in [row["data"] for row in inputs["admission_rows"] if row["event"] == "marker"],
            "4c:review_journal",
        )
        maximum = load_maximum(inputs["maximum_fixture"], self.pins)
        exact(
            sum(value["bytes"] for value in maximum["fixture_inventory"].values()),
            rows["lifecycle"]["transfer"]["raw_bytes"],
            "4c:maximum_size_join",
        )
        proof_path = Path(inputs["maximum_fixture"]["path"])
        artifacts = {
            "sources/" + name: Path(path) for name, path in inputs["source_artifacts"].items()
        }
        artifacts.update({"observations/" + key: Path(path) for key, path in observed.items()})
        artifacts.update({"inputs/saved-plan": plan, "inputs/maximum.json": proof_path})
        input_manifest = facts(artifacts)
        self.root.mkdir(parents=True, exist_ok=True)
        copied = {}
        for key, path in artifacts.items():
            target = safe_file(self.root / "sealed-inputs", key)
            require(not target.exists(), "4c:packet_workspace_not_fresh")
            target.parent.mkdir(parents=True, exist_ok=True)
            with Path(path).open("rb") as source:
                durable_write(target, b"")
                while chunk := source.read(1048576):
                    self.time(stop)
                    durable_write(target, chunk, "ab")
            copied[key] = target
        exact(facts(copied), input_manifest, "4c:input_copy")
        artifacts = copied
        registration = {
            "schema": "inf037b-resolved-registration-v1",
            "registration_id": REGISTRATION_ID,
            "controller": self.binding,
            "pins": self.pins,
            "D_eff_ms": self.deadline.effective_ms,
            "source_manifest": manifest,
            "setup_manifest_sha256": sha(encode(input_manifest)),
            "decision_sha256": sha(encode(decision)),
            "allowances_ms": decision["allowances_ms"],
            "review_marker": marker,
            "admission_journal_sha256": sha(encode(inputs["admission_rows"])),
            "maximum_sha256": sha(encode(maximum)),
            "paid_ready": False,
        }
        documents = {
            "registration.json": registration,
            "setup-manifest.json": input_manifest,
            "decision.json": decision,
            "admission.json": inputs["admission_rows"],
        }
        for key, value in documents.items():
            path = self.root / key
            require(not path.exists(), "4c:packet_workspace_not_fresh")
            durable_write(path, encode(value))
            artifacts["packet/" + key] = path
        persisted_at = self.time(stop)
        receipt = self.repository.publish("canonical-packet", artifacts, stop)
        self.repository.access(receipt, stop)
        completed = self.time(stop, completed=True)
        require(
            completed <= persisted_at + 60000 and completed <= start + BOUNDS_MS["resolution"],
            "4c:durability_window",
        )
        self.hook("before_seal")
        exact(facts(artifacts), receipt["manifest"], "4c:post_seal_mutation")
        sealed = {
            "inventory": receipt["manifest"],
            "artifacts": serial(artifacts),
            "store_receipt": receipt,
            "packet_sha256": sha(encode(registration)),
            "manifest_sha256": sha(encode(input_manifest)),
            "decision_sha256": sha(encode(decision)),
            "completed_ms": completed,
            "maximum_fixture": {
                "path": str(copied["inputs/maximum.json"]),
                "sha256": input_manifest["inputs/maximum.json"]["sha256"],
            },
            "resolution_started_ms": start,
            "durability_started_ms": persisted_at,
        }
        self.update(lambda state: state.update(sealed=sealed))
        finished = self.time(stop, completed=True)
        require(
            finished <= persisted_at + 60000 and finished <= start + BOUNDS_MS["resolution"],
            "4c:durability_window",
        )
        return True

    def revalidate(self, stop):
        self.time(stop)
        state = self.state()
        require(not state.get("invalidated"), "4c:packet_invalidated")
        sealed = state.get("sealed")
        require(sealed is not None, "4c:packet_unsealed")
        exact(facts(sealed["artifacts"]), sealed["inventory"], "4c:post_seal_mutation")
        load_maximum(sealed["maximum_fixture"], self.pins)
        self.repository.access(sealed["store_receipt"], stop)
        self.time(stop, completed=True)
        return sealed

    def start(self, operation, attempt, parent_path, stop):
        rows = []
        try:
            raw, rows = read_parent(parent_path)
            sealed = self.revalidate(stop)
            require(type(attempt) is int and 1 <= attempt <= MAX_ATTEMPTS, "4c:attempt_index")
            allocated = [
                row
                for row in rows
                if row["payload"].get("event") == "attempt_start"
                and row["payload"].get("attempt") == attempt
            ]
            exact(len(allocated), 1, "4c:parent_allocation")
            require(
                not any(
                    row["payload"].get("event") == "attempt_end"
                    and row["payload"].get("attempt") == attempt
                    for row in rows
                ),
                "4c:attempt_already_ended",
            )
            request = {
                "allocation_sha256": sha(encode(allocated[0])),
                "packet_sha256": sealed["packet_sha256"],
                "manifest_sha256": sealed["manifest_sha256"],
                "decision_sha256": sealed["decision_sha256"],
            }
            state = self.state()
            old = state["starts"].get(str(attempt))
            if old is None:
                exact(
                    set(state["starts"]),
                    {str(n) for n in range(1, attempt)},
                    "4c:no_replacement_attempt",
                )
                require(str(attempt) not in state["start_intents"], "4c:interrupted_start")
                self.update(lambda state: state["start_intents"].update({str(attempt): request}))
                self.hook("before_start")
                self.update(lambda state: state["starts"].update({str(attempt): request}))
            else:
                exact(old, request, "4c:attempt_start_immutable")
            if operation == "attempt":
                require(
                    any(
                        row["payload"].get("event") == "traffic_start"
                        and row["payload"].get("attempt") == attempt
                        for row in rows
                    ),
                    "4c:traffic_not_ready",
                )
            self.time(stop, completed=True)
            return request
        except Exception as exc:
            self.refuse(exc, rows)
            raise

    def capture(self, operation, stop, context, parent_path):
        try:
            return self._capture(operation, stop, context, parent_path)
        except Exception as exc:
            try:
                _, rows = read_parent(parent_path)
            except Exception:
                rows = []
            self.refuse(exc, rows)
            raise

    def _capture(self, operation, stop, context, parent_path):
        attempt = context["input"]["attempt"]
        self.start(operation, attempt, parent_path, stop)
        raw, rows = read_parent(parent_path)
        state = self.state()
        key = context["operation_key"]
        require(key not in state["captures"], "4c:interrupted_capture")
        result = {
            "binding": self.binding,
            "sealed_hashes": {
                name: state["sealed"][name]
                for name in ("packet_sha256", "manifest_sha256", "decision_sha256")
            },
            "parent_journal_sha256": sha(raw),
            "parent_journal_bytes": len(raw),
            "sequence_checkpoint": state["sequence_checkpoint"],
        }
        if operation == "attempt_setup" and attempt > 1:
            resets = [row for row in rows if row["payload"]["event"] == "reset_start"]
            exact(len(resets), attempt - 1, "4c:reset_index")
            result["reset"] = {
                "index": attempt - 1,
                "begin_reset": resets[-1],
                "begin_reset_sha256": sha(encode(resets[-1])),
            }
        self.update(
            lambda state: state["captures"].update(
                {
                    key: {
                        "request": result,
                        "parent_prefix_hex": raw.hex(),
                        "operation": operation,
                        "attempt": attempt,
                    }
                }
            )
        )
        return result

    def materialize(
        self, operation, descriptor, owner_root, stop, context, parent_path, archive_inputs
    ):
        rows = []
        try:
            owner_root = Path(owner_root)
            raw, rows = read_parent(parent_path)
            self.revalidate(stop)
            state = self.state()
            key = context["operation_key"]
            capture = state["captures"][key]
            require(
                raw.startswith(bytes.fromhex(capture["parent_prefix_hex"])), "4c:parent_rewritten"
            )
            exact(descriptor["closed"], True, "4c:owner_not_closed")
            exact(descriptor["transport_clean"], True, "4c:owner_unclean")
            exact(inventory(owner_root), descriptor["files"], "4c:owner_files")
            require("result" not in capture, "4c:capture_already_materialized")
            checkpoint = {tuple(row["stream"]): row["next"] for row in state["sequence_checkpoint"]}
            for path in sorted((owner_root / "archive/raw").glob("*.jsonl")):
                for _, _, row in iter_segment_rows(path, source_errors=True):
                    stream = (row["source_kind"], row["source_identity"], row["source_generation"])
                    exact(row["source_seq"], checkpoint.get(stream, 0), "4c:continuous_sequence")
                    checkpoint[stream] = row["source_seq"] + 1
            entry = {
                "root": str(owner_root),
                "descriptor": descriptor,
                "operation": operation,
                "attempt": capture["attempt"],
            }
            owners = [*state["owners"], entry]
            result = self.aggregate(owners, raw, rows, archive_inputs, stop)
            next_sequence = [
                {"stream": list(stream), "next": value}
                for stream, value in sorted(checkpoint.items())
            ]

            def commit(state):
                state["owners"] = owners
                state["sequence_checkpoint"] = next_sequence
                state["captures"][key]["result"] = result

            self.update(commit)
            self.time(stop, completed=True)
            return result
        except Exception as exc:
            self.refuse(exc, rows)
            raise

    def aggregate(self, owners, parent_raw, parent_rows, inputs, stop):
        root = Path(inputs["aggregate_parent"]) / sha(encode([owners, sha(parent_raw)]))
        sealed = self.state()["sealed"]
        canonical = strict_json(Path(sealed["artifacts"]["packet/registration.json"]).read_bytes())
        registration = canonical["source_manifest"]
        for spec in inputs["specs"]:
            exact(spec["config_sha256"], self.pins["configuration"], "4c:aggregate_configuration")
        exact(
            inputs["registration"]["registration_id"],
            registration["registration_id"],
            "4c:aggregate_registration",
        )
        archive = Archive.create(root, registration)
        segment_index = 0
        for entry in owners:
            source = Path(entry["root"])
            exact(inventory(source), entry["descriptor"]["files"], "4c:owner_mutation")
            verified = verify_archive(source / "archive")
            require(
                not any(r["integrity_errors"] for r in verified["segments"].values()),
                "4c:owner_integrity",
            )
            for path in sorted((source / "archive/raw").glob("*.jsonl")):
                segment = archive.new_raw_segment(
                    path.name.split("-")[0].split(".")[0], segment_index
                )
                segment_index += 1
                with path.open("rb") as stream:
                    while chunk := stream.read(1048576):
                        self.time(stop)
                        durable_write(root / segment, chunk, "ab")
        durable_write(root / "attempts.jsonl", parent_raw, "wb")
        # Derived capture windows cite closed-owner receipts; preserve the exact
        # parent prefix and never open/recover the actual parent writer.
        for ordinal, entry in enumerate(e for e in owners if e["operation"] == "attempt"):
            spec = next(s for s in inputs["specs"] if s["attempt_index"] == entry["attempt"])
            end = entry["descriptor"]["close_start_ns"] // 1000000
            row = envelope(
                {
                    "event": "capture_window",
                    "attempt": entry["attempt"],
                    "now_ms": end,
                    "capture_start_ms": spec["capture_start_ms"],
                    "capture_end_ms": end,
                    "capture_descriptor_sha256": sha(encode(entry["descriptor"])),
                },
                seq=ordinal,
                attempt=entry["attempt"],
            )
            row.update(
                session_id=self.binding["session_id"],
                source_identity="4c-capture-window",
                record_id="capture-window-" + str(entry["attempt"]),
            )
            durable_write(root / "attempts.jsonl", encode(row), "ab")
        before = (root / "attempts.jsonl").read_bytes()
        result = materialize_bundle(root, inputs["specs"])
        exact((root / "attempts.jsonl").read_bytes(), before, "4c:aggregate_recovered_parent")
        self.time(stop, completed=True)
        attempt = max(
            (
                r["payload"].get("attempt", 0)
                for r in parent_rows
                if r["payload"]["event"] == "attempt_start"
            ),
            default=0,
        )
        report = root / "events" / f"attempt-{attempt:02d}.json"
        return {
            "root": str(root),
            "inventory": inventory(root),
            "attempt_report_sha256": file_facts(report)["sha256"],
            "parent_journal_sha256": sha(parent_raw),
            "controller_outcomes": outcomes(parent_rows),
            "materialized": result,
        }

    def post_session(self, parent_path, readback_stop):
        """Bounded evidence review after teardown; never a start/retry gate.

        readback_stop bounds this offline access, not a rebased session ceiling.
        No new measurement can be admitted by a review result.
        """
        rows = []
        try:
            _, rows = read_parent(parent_path)
            state = self.state()
            require(not state.get("invalidated"), "4c:packet_invalidated")
            sealed = state["sealed"]
            exact(facts(sealed["artifacts"]), sealed["inventory"], "4c:post_seal_mutation")
            self.repository.access(sealed["store_receipt"], readback_stop)
            require(
                any(row["payload"]["event"] == "campaign_stop" for row in rows),
                "4c:campaign_not_closed",
            )
            return {"packet_valid": True, "outcomes": outcomes(rows), "paid_ready": False}
        except Exception as exc:
            self.refuse(exc, rows)
            return {
                "packet_valid": False,
                "invalidated_outcomes": self.state()["refusals"][-1]["invalidated_outcomes"],
                "paid_ready": False,
            }


class PacketPorts:
    def __init__(self, factory):
        self.factory = factory

    def packet(self, name, stop):
        f = self.factory
        require(f.config.get("resolved_packet") is not None, "eks:unfinished:" + name)
        repository = RecoveryPorts(f).repository("4c_recovery_stores", stop)
        return CanonicalPacket(
            repository=repository,
            root=f.config["resolved_packet"],
            binding=f.binding,
            pins=f.config["pins"],
            clock=f.clock,
        )

    def barrier(self, stop, context):
        f = self.factory
        f.port.validate_context("packet_barrier", stop, context)
        packet = self.packet("4c_packet_barrier", stop)
        try:
            inputs = f.dependency("4e_packet_inputs")(stop)
            exact(inputs["maximum_fixture"], f.config["maximum_fixture"], "4c:original_maximum")
            markers = [
                row["data"]
                for row in f.admission_rows
                if row["event"] == "marker"
                and row["data"]["binding"]["session_id"] == f.binding["session_id"]
                and row["data"]["binding"]["plan_hash"] == f.binding["plan_hash"]
            ]
            require(len(markers) == 1, "4c:original_marker_required")
            inputs = {**inputs, "review_marker": markers[0], "admission_rows": f.admission_rows}
            return packet.seal(inputs, context["input"], stop)
        except Exception as exc:
            if not packet.state().get("invalidated"):
                packet.refuse(exc)
            raise

    def attempt_start(self, stop, context):
        f = self.factory
        packet = self.packet("4c_attempt_start", stop)
        return packet.start(
            context["operation_label"].split(":")[0],
            context["input"]["attempt"],
            f.config["attempts"],
            stop,
        )

    def capture(self, operation, stop, context):
        f = self.factory
        return self.packet("4c_campaign_capture", stop).capture(
            operation, stop, context, f.config["attempts"]
        )

    def materialize(self, operation, descriptor, root, stop, context):
        f = self.factory
        packet = self.packet("4c_campaign_materialize", stop)
        try:
            inputs = f.dependency("4d_campaign_archive_inputs")(stop)
            from .inf037b_eks_execution import join_execution

            join_execution(inputs, f, "4d_campaign_archive_inputs")
            return packet.materialize(
                operation, descriptor, root, stop, context, f.config["attempts"], inputs
            )
        except Exception as exc:
            if not packet.state().get("invalidated"):
                try:
                    _, rows = read_parent(f.config["attempts"])
                except Exception:
                    rows = []
                packet.refuse(exc, rows)
            raise

    def terminal_inputs(self, stop):
        f = self.factory
        packet = self.packet("4c_terminal_export_inputs", stop)
        rows = []
        try:
            raw, rows = read_parent(f.config["attempts"])
            packet.revalidate(stop)
            require(
                any(row["payload"]["event"] == "campaign_stop" for row in rows),
                "4c:campaign_not_closed",
            )
            inputs = f.dependency("4d_campaign_archive_inputs")(stop)
            from .inf037b_eks_execution import join_execution

            join_execution(inputs, f, "4d_campaign_archive_inputs")
            result = packet.aggregate(packet.state()["owners"], raw, rows, inputs, stop)
            source = Path(result["root"])
            sanitized = source.with_name(source.name + "-sanitized")
            key = Path(inputs["sanitizer_key"]).read_bytes()
            exact(sha(key), f.config["sanitizer_key_sha256"], "4c:sanitizer_pin")
            sanitized_campaign(source, sanitized, inputs["specs"], key=key)
            # The normalized archive is sanitized. Raw/index wire evidence is
            # retained unchanged in the secured stores, not silently omitted.
            catalog = f.dependency("4d_terminal_capture_inventory")(stop)
            join_execution(catalog, f, "4d_terminal_capture_inventory")
            exact(catalog["binding"], f.binding, "4c:terminal_capture_binding")
            exact(catalog["complete"], True, "4c:terminal_capture_incomplete")
            from .inf037b_eks_commands import capture_instance_schedule

            allowed = {
                row["owner_id"]
                for row in capture_instance_schedule()["logical_scopes"]
                if row["owner_id"]
            }
            ids = [entry["owner_id"] for entry in catalog["owners"]]
            require(len(ids) == len(set(ids)) and set(ids) <= allowed, "4c:terminal_owner_ids")
            known = {
                entry["root"]: entry["descriptor"]["files"] for entry in packet.state()["owners"]
            }
            supplied = {entry["root"]: entry["descriptor"]["files"] for entry in catalog["owners"]}
            exact(len(supplied), len(catalog["owners"]), "4c:terminal_owner_roots")
            require(
                known.keys() <= supplied.keys()
                and all(supplied[root] == files for root, files in known.items()),
                "4c:terminal_campaign_coverage",
            )
            retained = {}
            for entry in catalog["owners"]:
                exact(entry["descriptor"]["closed"], True, "4c:terminal_owner_not_closed")
                owner_root = Path(entry["root"])
                exact(
                    inventory(owner_root),
                    entry["descriptor"]["files"],
                    "4c:terminal_owner_mutation",
                )
                for name in entry["descriptor"]["files"]:
                    retained["retained-owners/" + entry["owner_id"] + "/" + name] = safe_file(
                        owner_root, name
                    )
            retained.update(
                {
                    "resolved-packet/" + name: Path(path)
                    for name, path in packet.state()["sealed"]["artifacts"].items()
                }
            )
            packet.time(stop, completed=True)
            return {
                "binding": f.binding,
                "sanitized": sanitized,
                "inventory": inventory(sanitized),
                "source": result,
                "retained_artifacts": retained,
                "retained_manifest": facts(retained),
                "capture_inventory_sha256": sha(encode(catalog)),
            }
        except Exception as exc:
            packet.refuse(exc, rows)
            raise
