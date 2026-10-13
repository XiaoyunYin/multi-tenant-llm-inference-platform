"""R1 v2 entrypoint: manifest validation, calibration and seven-slot bounded lifecycle."""

import argparse
import json
import subprocess
import time
from pathlib import Path

from .r1_analysis import candidate, eligible, noise, summarize, warm_rates
from .r1_fake import SCENARIOS, Fake
from .r1_manifest import load, trace, trace_profile
from .r1_metrics import FITNESS
from .r1_reset import PreparationFailed, Reset
from .r1_spec import FIXED, POLICIES, SPEC_COMMIT, digest, encoded, verify_spec

# Within the existing 330 s setup overhead allowance; see docs/R1_HARNESS.md.
CALIBRATION_IDLE_TIMEOUT_S = 15


class RealClock:
    @staticmethod
    def now():
        return time.perf_counter()

    @staticmethod
    def wall():
        return time.time()

    @staticmethod
    def sleep(seconds):
        time.sleep(max(0, seconds))


class Session:
    def __init__(self, io, manifest, output, session_seconds=18000, head=None):
        self.io, self.manifest, self.output = io, manifest, Path(output)
        self.head = head or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        self.start = io.clock.now()
        self.deadline = self.start + min(session_seconds, 18000)
        self.active_deadline = self.deadline - 900
        self.events, self.runs, self.calibration = [], [], []
        self.slots = [
            {"id": index + 1, "state": "not_started", "consumed": False, "conditional": index == 6}
            for index in range(7)
        ]
        self.output.mkdir(parents=True, exist_ok=True)
        self.event_file = (self.output / "events.jsonl").open("wb")

    def emit(self, value):
        value = {"session_elapsed_s": self.io.clock.now() - self.start, **value}
        self.events.append(value)
        self.event_file.write(encoded(value) + b"\n")
        self.event_file.flush()

    def phase(self, name, seconds, drain, **kwargs):
        end = min(self.active_deadline, self.io.clock.now() + seconds + drain + 5)
        if end < self.io.clock.now() + seconds:
            raise PreparationFailed("insufficient bounded lifecycle slack")
        result = self.io.phase(
            name,
            seconds,
            drain,
            deadline=end,
            request_deadline=self.active_deadline if "-warm-" in name else end,
            **kwargs,
        )
        if self.io.clock.now() > end:
            raise PreparationFailed("phase exceeded absolute deadline")
        path = self.output / (name + ".json")
        path.write_bytes(encoded(result) + b"\n")
        self.emit(
            {
                "event": "phase_record",
                "name": name,
                "sha256": digest(result),
                "path": path.name,
                "seconds": seconds,
            }
        )
        if name.startswith("staircase") and result["censored"]:
            raise PreparationFailed("staircase failed its 30 s drain")
        return result

    def prepare(self, pending, configure=None):
        self.io.begin_preparation(pending)
        # Leave the registered maximum warm/measure/drain/export/teardown slack.
        deadline = min(self.active_deadline, self.deadline - 600 - 600 - 120 - 900)
        cutoff = getattr(self.io, "preparation_cutoff", None)
        if cutoff is not None:
            deadline = min(deadline, cutoff)
        return Reset(self.io, self.emit, pending, deadline).run(configure)

    def calibrate(self):
        setup_start = self.io.clock.now()
        self.active_deadline = min(self.active_deadline, setup_start + 2700)
        self.emit(
            {"event": "runtime_fitness", "result": self.io.runtime_fitness(self.active_deadline)}
        )
        levels = []
        for level in FIXED["calibration_levels"]:
            result = self.phase(f"staircase-{level}", 90, 30, level=level)
            levels.append((level, result))
            self.calibration.append({"level": level, "eligible": eligible(result, level)})
        choices = [
            level
            for level, result in levels
            if eligible(result, level)
            and any(
                higher > level
                and all(
                    any(x > 0 for x in replica["waiting"])
                    for replica in candidate_result["replicas"]
                )
                for higher, candidate_result in levels
            )
        ]
        if not choices:
            raise PreparationFailed(
                "calibration incomplete: no eligible R with higher queue signal"
            )
        r = max(choices)
        self.prepare("setup")
        self.io.configure(
            "rr",
            r,
            1,
            2 * (r + 1),
            4242,
            deadline=min(self.active_deadline, self.io.clock.now() + FIXED["control_timeout_s"]),
        )
        warm = self.phase("calibration-corpus-warm", 600, 0, level=2 * r, block="b1")
        mu = sum(warm["last_60_replica_rates"])
        if mu <= 0:
            raise PreparationFailed("calibration RR final-60 rate unavailable")
        selected = None
        for w in (1, 2, 4):
            for factor in (1.05, 1.15, 1.25):
                b, q = 2 * (r + w), mu * factor
                name = f"candidate-W{w}-f{factor}"
                self.wait_for_calibration_idle(name)
                self.io.configure(
                    "rr",
                    r,
                    w,
                    b,
                    4242,
                    deadline=min(
                        self.active_deadline, self.io.clock.now() + FIXED["control_timeout_s"]
                    ),
                )
                result = self.phase(name, 60, 30, q=q, block="b1")
                valid = candidate(result, w, q)
                self.calibration.append({"W": w, "factor": factor, "q": q, "qualifies": valid})
                if valid:
                    selected = {"N": 2, "R": r, "W": w, "B": b, "q": q}
                    break
            if selected:
                break
        elapsed = self.io.clock.now() - setup_start
        if elapsed > 2700 or not selected:
            raise PreparationFailed("calibration incomplete/beyond 2700 s")
        self.emit(
            {
                "event": "calibration_frozen",
                "inputs": selected,
                "elapsed_s": elapsed,
                "record": self.calibration,
            }
        )
        # q is derived once. Hash finite traces BEFORE any comparison hit observation.
        profiles = {
            f"{phase}-{block}": trace_profile(trace(phase, block, selected["q"], seconds))
            for phase, seconds in (("warm", 600), ("measure", 600))
            for block in ("b1", "b2", "b3")
        }
        (self.output / "finite-traces.json").write_bytes(encoded(profiles) + b"\n")
        self.emit({"event": "finite_trace_profiles_frozen", "sha256": digest(profiles)})
        self.active_deadline = self.deadline - 900
        return selected

    def wait_for_calibration_idle(self, name):
        """Observe natural completion, without closing admission or resetting state."""
        started = self.io.clock.now()
        deadline = min(self.active_deadline, started + CALIBRATION_IDLE_TIMEOUT_S)
        consecutive, polls = 0, 0
        state, counts, identities = None, None, None
        values = []
        reason = None
        try:
            while self.io.clock.now() < deadline:
                values = self.io.snapshots(
                    deadline=min(deadline, self.io.clock.now() + FIXED["control_timeout_s"])
                )
                counts = [{"running": s["running"], "waiting": s["waiting"]} for s in values]
                current = [(s["generation"], s["engine"], s["model_name"]) for s in values]
                if len(values) != 2 or any(s["age_s"] > FIXED["freshness_s"] for s in values):
                    raise PreparationFailed("missing/stale replica sample")
                if identities is None:
                    identities = current
                if current != identities:
                    raise PreparationFailed("backend generation/identity changed")
                state = self.io.admission_state(
                    deadline=min(deadline, self.io.clock.now() + FIXED["control_timeout_s"])
                )
                polls += 1
                if self.io.clock.now() >= deadline:
                    break
                busy = any(state.values()) or any(s["running"] or s["waiting"] for s in counts)
                consecutive = 0 if busy else consecutive + 1
                if consecutive == 3:
                    return
                self.io.clock.sleep(min(FIXED["poll_s"], deadline - self.io.clock.now()))
            raise PreparationFailed("idle deadline exhausted")
        except (PreparationFailed, TimeoutError, OSError, ValueError) as exc:
            reason = f"calibration idle wait failed: {exc}; admission={state}; replicas={counts}"
            raise PreparationFailed(reason) from exc
        finally:
            self.emit(
                {
                    "event": "calibration_idle_wait",
                    "candidate": name,
                    "elapsed_s": self.io.clock.now() - started,
                    "limit_s": CALIBRATION_IDLE_TIMEOUT_S,
                    "deadline_s": deadline,
                    "polls": polls,
                    "consecutive_zero_polls": consecutive,
                    "admission": state,
                    "replicas": values,
                    "success": consecutive == 3 and reason is None,
                    "reason": reason,
                }
            )

    def compare(self, index, policy, block, frozen):
        slot = self.slots[index - 1]
        if self.deadline - self.io.clock.now() < 2340:
            raise PreparationFailed("not enough lifecycle slack to prepare another comparison")
        slot["state"] = "pending"
        original_deadline = self.active_deadline
        self.active_deadline = min(self.active_deadline, self.io.clock.now() + 1440)
        expected = {
            "policy": policy,
            "R": frozen["R"],
            "W": frozen["W"],
            "B": frozen["B"],
            "seed": FIXED["seeds"][int(block[1:]) - 1],
            "N": 2,
        }

        def configure(deadline):
            acknowledged = self.io.configure(
                policy, frozen["R"], frozen["W"], frozen["B"], expected["seed"], deadline=deadline
            )
            if acknowledged != expected:
                raise PreparationFailed("effective gateway inputs differ")

        baseline = self.prepare(index, configure)
        slot.update(state="started", consumed=True)
        self.emit(
            {
                "event": "comparison_started",
                "id": index,
                "policy": policy,
                "block": block,
                "slot_consumed": True,
                "configuration": expected,
                "baselines": baseline,
            }
        )
        rates_before, consecutive, windows = None, 0, []
        warm_invalid = False
        elapsed, offset = 0, 0
        while elapsed < 600:
            result = self.phase(
                f"run{index}-warm-{elapsed}", 30, 0, q=frozen["q"], block=block, offset=offset
            )
            offset += 30
            elapsed += 30
            rates, valid = warm_rates(result)
            warm_invalid |= not valid
            good = rates_before is not None and all(
                left is not None and right is not None and abs(left - right) <= 0.02
                for left, right in zip(rates_before, rates, strict=True)
            )
            consecutive = consecutive + 1 if good else 0
            windows.append(
                {"end_s": elapsed, "rates": rates, "adjacent_passes": consecutive, "valid": valid}
            )
            rates_before = rates
            if elapsed >= 120 and consecutive >= 3:
                break
        self.emit(
            {
                "event": "warmup_complete",
                "id": index,
                "seconds": elapsed,
                "label": "invalid"
                if warm_invalid
                else "stable"
                if consecutive >= 3
                else "valid-unstable",
                "windows": windows,
            }
        )
        result = self.phase(f"run{index}-measure", 600, 120, q=frozen["q"], block=block)
        summary = summarize(result, frozen["W"])
        if warm_invalid:
            summary["invalid_reasons"].append("warm-up collector/resource/delivery invalidity")
        run = {"id": index, "policy": policy, "block": block, "warm_s": elapsed, "summary": summary}
        self.runs.append(run)
        slot["state"] = "completed" if not summary["invalid_reasons"] else "invalid"
        self.emit({"event": "comparison_finished", **run, "slot_state": slot["state"]})
        self.active_deadline = original_deadline

    def run(self):
        error, frozen, analysis = None, None, None
        unexpected, exception_type = None, None
        try:
            frozen = self.calibrate()
            for index, policy in enumerate(POLICIES, 1):
                self.compare(index, policy, "b1" if index <= 3 else "b2", frozen)
            analysis = noise(self.runs)
            self.emit({"event": "noise_initial", "analysis": analysis})
            if analysis["conditional_policy"]:
                self.compare(7, analysis["conditional_policy"], "b3", frozen)
                analysis = noise(self.runs)
                analysis["repeat_executed"] = {"id": 7, "policy": self.runs[-1]["policy"]}
                analysis["repeat_remaining"] = 0
        except BaseException as exc:
            error = str(exc)
            exception_type = type(exc).__name__
            if not isinstance(exc, (PreparationFailed, ValueError, TimeoutError, OSError)):
                unexpected = exc
            for slot in self.slots:
                if slot["state"] == "pending":
                    slot["state"] = "not_started"
                elif slot["state"] == "started":
                    slot["state"] = "invalid"
        finally:
            try:
                finish = self.io.finish(deadline=self.deadline)
            except BaseException as exc:
                finish = {
                    "exported": False,
                    "error": str(exc),
                    "exception_type": type(exc).__name__,
                }
                if error is None:
                    error, exception_type, unexpected = str(exc), type(exc).__name__, exc
            self.emit(
                {
                    "event": "session_end",
                    "reason": error,
                    "exception_type": exception_type,
                    "slots": self.slots,
                    "finish": finish,
                }
            )
            self.event_file.close()
        output = {
            "spec_commit": SPEC_COMMIT,
            "spec_sha256": FIXED["spec_sha256"],
            "manifest_sha256": self.manifest["manifest_sha256"],
            "fitness": FITNESS,
            "head": self.head,
            "scenario": getattr(self.io, "scenario", None),
            "fake": isinstance(self.io, Fake),
            "error": error,
            "exception_type": exception_type,
            "slots": self.slots,
            "runs": self.runs,
            "frozen": frozen,
            "noise": analysis,
            "elapsed_s": self.io.clock.now() - self.start,
            "finish": finish,
            "events_sha256": __import__("hashlib")
            .sha256((self.output / "events.jsonl").read_bytes())
            .hexdigest(),
        }
        (self.output / "result.json").write_bytes(encoded(output) + b"\n")
        if unexpected is not None:
            raise unexpected.with_traceback(unexpected.__traceback__)
        return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec-commit", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--tokenizer-cache", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--http-rehearsal-compression", type=float, default=1)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--fake-scenario", choices=SCENARIOS)
    choice.add_argument("--http-config", type=Path)
    args = parser.parse_args()
    verify_spec(args.spec_commit)
    manifest, banks = load(args.manifest, args.spec_commit, args.tokenizer_cache)
    if args.fake_scenario:
        if args.http_rehearsal_compression != 1:
            raise ValueError("HTTP compression requires the loopback HTTP adapter")
        io = Fake(args.fake_scenario)
    else:
        from .r1_transport import HTTP

        io = HTTP(
            json.loads(args.http_config.read_bytes()),
            manifest,
            banks,
            args.output,
            args.tokenizer_cache,
            compression=args.http_rehearsal_compression,
        )
    result = Session(io, manifest, args.output).run()
    print(
        json.dumps({"output": str(args.output), "error": result["error"], "slots": result["slots"]})
    )
    # Expected failure rehearsals still return their recorded failure; verifier decides correctness.
    return int(result["error"] is not None and not args.fake_scenario)


if __name__ == "__main__":
    raise SystemExit(main())
