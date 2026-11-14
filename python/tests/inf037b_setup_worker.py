"""Only offline test command reconstructs these synthetic ports. No live CLI."""

import json
import sys
from pathlib import Path

from inf037b_fitness_fixture import attach
from inf037b_observations_fixture import attach as observations
from inf037b_setup_fixture import creation_raw, fixture, inventory, scope

from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_setup import SetupCommands


class OfflineFixtureSetupCommands(SetupCommands):
    """The process test has no row 5 sources; production remains live-required."""

    def fitness_rows(self, collected, setup):
        from inference_platform.inf037b_setup_fitness import FitnessProducer

        producer = FitnessProducer(
            collected["fitness_raw"],
            binding=self.binding,
            artifacts=collected["artifacts"],
            setup=setup,
            allow_offline_fixture=True,
        )
        if producer.c.row(self.binding["pins"])["selected_ms"] > self.sample()["ms"][1]:
            raise IntegrityError("setup:fitness_future_source")
        return producer.produce()


def main():
    root, operation, failure = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    context = json.load(sys.stdin)
    clock_file = root / "clock.json"
    now = json.loads(clock_file.read_text())["now"] if clock_file.exists() else 1000

    def advance(at):
        nonlocal now
        now = at
        temporary = root / "clock.tmp"
        temporary.write_text(json.dumps({"now": now}))
        temporary.replace(clock_file)

    value = observations(attach(fixture()), boot="test-host")
    if failure.startswith("fitness_"):
        raw = strict_json(value["fitness_raw"])
        if failure == "fitness_signal":
            raw["signal_processes"]["0"]["events"][-1]["event"] = "heartbeat"
        if failure == "fitness_control":
            for row in raw["raw"]:
                if (
                    row["source_kind"] == "gateway"
                    and row["payload"].get("snapshot_id") == "known2"
                ):
                    row["payload"]["effective_b"] = 9
        value["fitness_raw"] = encode(raw)
    if failure == "cache":
        value["bundle"]["cases"][1]["cache"]["files"] = []
    if failure == "restoration":
        for row in value["bundle"]["raw"]:
            if row["payload"]["event"] == "live_set":
                row["payload"]["request_ids"] = ["still-active"]
    if failure == "release":
        for row in value["bundle"]["raw"]:
            if row["payload"]["event"] == "signal":
                row["source_time"]["value"] -= 1
    if failure == "proof":
        del value["artifacts"]["proof/kill_release.json"]
    fitness = strict_json(value["fitness_raw"])
    for row in fitness["raw"]:
        row["collector_boot_id"] = "test-host"
    value["fitness_raw"] = encode(fitness)

    def collect(op, stop):
        if op == "creation":
            advance(1801001 if failure == "creation" else 1000)
            return creation_raw(
                value["binding"],
                now,
                source_inventory=strict_json(value["export_raw"])["source"],
                boot="test-host",
            )
        if failure == "reconnect":
            advance(stop + 1)
            raise OSError("bounded reconnect exhausted")
        advance(513000)
        ready = {"clock_id": "measurement", "boot_id": "test-host", "ms": [1000] * 2}
        end = sample()
        value["preparation_receipt"] = {
            "binding": value["binding"],
            "ready": ready,
            "fork": ready,
            "branches": {
                name: {
                    "start": ready,
                    "end": end,
                    "success": True,
                    "durable_ack": True,
                    "sha256": sha(value[raw_name]),
                }
                for name, raw_name in (("export", "export_raw"), ("gpu", "fitness_raw"))
            },
            "join": end,
            "join_ack": True,
        }
        return {**value, "raw": encode(value["bundle"])}

    port, _ = inventory(scope(), lambda: advance(now + 2))

    def sample():
        return {"clock_id": "measurement", "boot_id": "test-host", "ms": [now, now]}

    producer = OfflineFixtureSetupCommands(
        store=DurableStore(root / "setup", {}, initialize=True),
        binding=value["binding"],
        collect=collect,
        inventory=port,
        scope=scope(),
        sample=sample,
    )
    if operation in ("creation", "preparation", "resolution"):
        result = producer(operation, context["measurement_deadline_ms"], context)
    elif operation in ("export", "cleanup"):
        terminal = root / "terminal.json"
        effects = json.loads(terminal.read_text()) if terminal.exists() else []
        effects.append(operation)
        terminal.write_text(json.dumps(effects))
        result = True
    elif operation == "attempt":
        advance(now + 10)
        result = {
            "measurement_valid": True,
            "reasons": [],
            "operational_outcomes": [],
            "replacement_usable_by_deadline": True,
            "measurement_end_ms": now,
        }
    else:
        result = True
    print(json.dumps(result))


if __name__ == "__main__":
    main()
