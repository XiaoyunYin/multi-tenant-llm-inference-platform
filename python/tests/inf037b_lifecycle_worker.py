"""Real-process crash fixture; no provider, network or paid command."""

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

from inference_platform import inf037b_lifecycle as lifecycle
from inference_platform.inf037b_archive import durable_write, encode, inspect_segment, strict_json
from inference_platform.inf037b_attempts import AttemptController
from inference_platform.inf037b_resolver import SessionDeadline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cut", type=int)
    parser.add_argument("--hold", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--scenario", default="normal")
    parser.add_argument("--restart-delay", type=int, default=0)
    parser.add_argument("--process-phase")
    parser.add_argument("--spawn-cut", choices=("before", "after", "acting", "orphan"))
    args = parser.parse_args()
    if args.source:
        exec(compile(args.source.read_text(), str(args.source), "exec"), lifecycle.__dict__)
    root = args.root
    root.mkdir(parents=True, exist_ok=True)
    state_path = root / "executor.json"
    state = (
        strict_json(state_path.read_bytes())
        if state_path.exists()
        else {"clock_ms": 17, "effects": {}, "order": []}
    )
    state["clock_ms"] += args.restart_delay
    cuts = []

    def hold_spawn():
        (root / "ready").touch()
        time.sleep(60)

    def point(kind, payload):
        cuts.append(
            {
                "kind": kind,
                "event": payload.get("event"),
                "key": payload.get("key"),
                "attempt": payload.get("attempt"),
            }
        )
        if len(cuts) == args.cut:
            (root / "cut.json").write_text(json.dumps(cuts))
            if args.hold:
                (root / "ready").touch()
                time.sleep(60)
            os.kill(os.getpid(), signal.SIGKILL)

    original = AttemptController._write

    def attempt_write(self, *a, **kw):
        original(self, *a, **kw)
        point("attempt", self.events[-1])

    AttemptController._write = attempt_write
    if hasattr(lifecycle, "LifecycleJournal"):
        append = lifecycle.LifecycleJournal.append

        def lifecycle_write(self, *a, **kw):
            target = a[0] == "spawned" and kw["key"].split(":")[0] == args.process_phase
            if target and args.spawn_cut == "before":
                hold_spawn()
            append(self, *a, **kw)
            point("lifecycle", self.rows[-1])
            if target and args.spawn_cut == "after":
                hold_spawn()

        lifecycle.LifecycleJournal.append = lifecycle_write

    def execute(operation, stop, context):
        modern = type(context) is dict and "operation_key" in context
        inner = context["input"] if modern else context
        key = (
            context["operation_label"]
            if modern
            else operation
            + (":" + str(inner["attempt"]) if type(inner) is dict and "attempt" in inner else "")
        )
        if key in state["effects"]:
            assert state["effects"][key]["context"] == context, "changed original request"
            return state["effects"][key]["value"]
        if operation in {"export", "cleanup"} and (root / "children.json").exists():
            ids = json.loads((root / "children.json").read_text())
            alive = []
            for pid in ids:
                path = Path(f"/proc/{pid}/stat")
                if path.exists() and path.read_text().rsplit(")", 1)[1].split()[0] not in {
                    "Z",
                    "X",
                }:
                    alive.append(pid)
            if alive:
                (root / "terminal-saw-live").write_text(json.dumps(alive))
        if args.scenario == "export_failure" and operation == "export":
            raise OSError("offline export fixture failure")
        if args.scenario == "cleanup_failure" and operation == "cleanup":
            raise OSError("offline cleanup fixture failure")
        state["clock_ms"] += 10
        if args.scenario == "creation_overrun" and operation == "creation":
            state["clock_ms"] = stop + 1
        if args.scenario == "delayed_preparation" and operation == "preparation":
            state["clock_ms"] = stop - 100
        value = {"offline_fixture": True} if operation == "resolution" else True
        if operation == "attempt":
            value = dict(
                measurement_valid=True,
                reasons=[],
                operational_outcomes=[],
                replacement_usable_by_deadline=True,
            )
            if hasattr(lifecycle, "valid_outcome"):
                value["measurement_end_ms"] = (
                    stop + 1 if args.scenario == "bad_end" else state["clock_ms"]
                )
            if args.scenario == "never_usable":
                value["replacement_usable_by_deadline"] = False
        if (
            args.scenario == "reset_failure"
            and operation == "attempt_setup"
            and inner["attempt"] == 2
        ):
            value = False
        state["effects"][key] = {"operation": operation, "context": context, "value": value}
        state["order"].append(key)
        durable_write(state_path, encode(state), "wb" if state_path.exists() else "xb")
        point("effect", {"event": operation, "key": key})
        return value

    path = root / "attempts.jsonl"
    # The legacy entry is used only in the isolated eed6531 negative control.
    attempts = path if hasattr(lifecycle, "LifecycleJournal") else AttemptController(path)
    driver = lifecycle.LifecycleDriver(
        deadline=SessionDeadline(50, 18_000_050, 17),
        clock=lambda: state["clock_ms"],
        execute=execute,
        attempts=attempts,
    )
    if args.process_phase:
        if args.spawn_cut == "orphan":
            original_fence = lifecycle.fence_child

            def hold_before_fence(identity, **kwargs):
                if kwargs.get("owned"):
                    hold_spawn()
                return original_fence(identity, **kwargs)

            lifecycle.fence_child = hold_before_fence
        descendant = (
            "import time,pathlib;time.sleep(1);pathlib.Path("
            + repr(str(root / "escaped"))
            + ").touch();time.sleep(30)"
        )
        target = (
            "import json,os,pathlib,subprocess,sys,time;root=pathlib.Path(" + repr(str(root)) + ");"
            "(root/'acted').touch();p=subprocess.Popen([sys.executable,'-c',"
            + repr(descendant)
            + "]);"
            "(root/'children.json').write_text(json.dumps([os.getpid(),p.pid]));"
            "(root/'ready').touch();time.sleep(30)"
        )
        if args.spawn_cut == "orphan":
            target = target.replace("(root/'ready').touch();time.sleep(30)", "print('true')")
        commands = dict.fromkeys(
            (
                "creation",
                "preparation",
                "resolution",
                "packet_barrier",
                "attempt_setup",
                "export",
                "cleanup",
            ),
            [sys.executable, "-c", "print('true')"],
        )
        commands["attempt"] = [
            sys.executable,
            "-c",
            "import json,sys;c=json.load(sys.stdin);print(json.dumps(dict(measurement_valid=True,reasons=[],operational_outcomes=[],replacement_usable_by_deadline=True,measurement_end_ms=17)))",
        ]
        commands[args.process_phase] = [sys.executable, "-c", target]
        driver.execute = lifecycle.ProcessCalls(commands, lambda: state["clock_ms"])
    result = driver.run()
    _, rows = inspect_segment(path)
    life = []
    if (root / "lifecycle.jsonl").exists():
        _, life = inspect_segment(root / "lifecycle.jsonl")
    print(
        json.dumps(
            {
                "result": result,
                "attempts": rows,
                "lifecycle": life,
                "effects": state["effects"],
                "effect_order": state["order"],
                "cuts": cuts,
            }
        )
    )


if __name__ == "__main__":
    main()
