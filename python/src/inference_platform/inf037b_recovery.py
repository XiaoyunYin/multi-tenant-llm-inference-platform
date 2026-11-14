"""Fixed 30s, generation-local native-counter/latency recovery windows (:67–70)."""

import math
from statistics import median

from .inf037b_contract import GATEWAYS


def percentiles(values):
    ordered = sorted(values)
    result = {"n": len(ordered)}
    for label, p, minimum in (("p50", 0.5, 40), ("p95", 0.95, 400), ("p99", 0.99, 2000)):
        result[label] = (
            ordered[math.ceil(len(ordered) * p) - 1] if len(ordered) >= minimum else None
        )
        result[label + "_eligible"] = len(ordered) >= minimum
    return result


class RecoveryJoin:
    def __init__(self, rows, cohorts, *, pre_end_ms, usable_ms, capture_end_ms, replacement_uid):
        self.rows, self.cohorts = rows, cohorts
        self.pre_end, self.usable, self.end = pre_end_ms, usable_ms, capture_end_ms
        self.replacement = replacement_uid

    def window(self, start, end):
        errors, latencies, slots = [], {}, {}
        completed = [
            r
            for r in self.cohorts
            if r["outcome"] == "complete"
            and r.get("first_content_ms_bounds")
            and r.get("offer_ms_bounds")
            and r.get("terminal_ms_bounds")
            and r["offer_ms_bounds"][0] >= start
            and r["terminal_ms_bounds"][1] < end
        ]
        for gateway in GATEWAYS:
            cell = [
                r
                for r in completed
                if r["gateway_uid"] == gateway
                and r.get("ttft_ms_bounds") is not None
                and r.get("e2e_ms_bounds") is not None
            ]
            latencies[gateway] = {
                name: percentiles([r[field][1] for r in cell])
                for name, field in (("ttft", "ttft_ms_bounds"), ("e2e", "e2e_ms_bounds"))
            }
            if len(cell) < 40:
                errors.append("insufficient_latency_samples:" + gateway)
        for slot in (0, 1):
            samples = [
                r
                for r in self.rows
                if r["source_kind"] == "vllm"
                and r["payload"]["event"] == "sample"
                and r["payload"].get("slot") == slot
                and r["time_ms_bounds"]
            ]
            samples.sort(key=lambda r: r["time_ms_bounds"][0])
            before = [r for r in samples if r["time_ms_bounds"][1] <= start]
            after = [r for r in samples if r["time_ms_bounds"][0] >= end]
            a, b = (before[-1] if before else None), (after[0] if after else None)
            result = {
                "completions": sum(r["backend_slot"] == slot for r in completed),
                "query_delta": None,
                "hit_delta": None,
                "hit_fraction": None,
                "generation": None,
                "counter_brackets_ms": None,
                "raw_refs": [],
            }
            if a is None or b is None:
                errors.append("missing_counter_bracket:" + str(slot))
                slots[str(slot)] = result
                continue
            segment = [
                r
                for r in samples
                if a["time_ms_bounds"][0] <= r["time_ms_bounds"][0] <= b["time_ms_bounds"][0]
            ]

            def generation(r):
                return (
                    r["payload"].get("pod_uid"),
                    r["payload"].get("process_generation"),
                    r["payload"].get("reset_generation"),
                )

            result["generation"] = list(generation(a))
            if any(
                r["backend_slot"] == slot and r["backend_uid"] != generation(a)[0]
                for r in completed
            ):
                errors.append("completion_counter_generation_mismatch:" + str(slot))
            result["completions"] = sum(
                r["backend_slot"] == slot and r["backend_uid"] == generation(a)[0]
                for r in completed
            )
            result["counter_brackets_ms"] = [a["time_ms_bounds"], b["time_ms_bounds"]]
            result["raw_refs"] = [a["raw_ref"], b["raw_ref"]]
            result["source_sequence_range"] = [a["source_seq"], b["source_seq"]]
            result["sample_count"] = len(segment)
            bad = False
            if start - a["time_ms_bounds"][0] > 500 or b["time_ms_bounds"][1] - end > 500:
                errors.append("stale_counter_bracket:" + str(slot))
                bad = True
            if len({generation(r) for r in segment}) != 1 or any(v is None for v in generation(a)):
                errors.append("counter_generation_reset:" + str(slot))
                bad = True
            for x, y in zip(segment, segment[1:], strict=False):
                if y["time_ms_bounds"][1] - x["time_ms_bounds"][0] > 2000:
                    errors.append("counter_gap:" + str(slot))
                    bad = True
                if y["time_ms_bounds"][1] - x["time_ms_bounds"][0] > 1000:
                    errors.append("counter_stale:" + str(slot))
                    bad = True
                for field in (
                    "prefix_query_tokens_total",
                    "prefix_hit_tokens_total",
                    "preemptions_total",
                ):
                    if generation(x) != generation(y):
                        continue
                    if (
                        type(x["payload"].get(field)) is not int
                        or type(y["payload"].get(field)) is not int
                        or y["payload"][field] < x["payload"][field]
                    ):
                        errors.append("counter_decrease_or_missing:" + str(slot))
                        bad = True
            if not bad:
                q = (
                    b["payload"]["prefix_query_tokens_total"]
                    - a["payload"]["prefix_query_tokens_total"]
                )
                h = (
                    b["payload"]["prefix_hit_tokens_total"]
                    - a["payload"]["prefix_hit_tokens_total"]
                )
                result.update(query_delta=q, hit_delta=h)
                if q < 100 or not 0 <= h <= q or result["completions"] < 40:
                    errors.append("ineligible_native_counter_samples:" + str(slot))
                else:
                    result["hit_fraction"] = h / q
            slots[str(slot)] = result
        replacement_traffic = any(r["backend_uid"] == self.replacement for r in completed)
        return {
            "start_ms": start,
            "end_ms": end,
            "latencies": latencies,
            "slots": slots,
            "eligible": not errors,
            "replacement_traffic": replacement_traffic,
            "validity_reasons": sorted(set(errors)),
        }

    @staticmethod
    def within_latency(value, reference):
        return value == 0 if reference == 0 else abs(value - reference) <= reference / 5

    def report(self):
        baseline = [
            self.window(self.pre_end - 120_000 + i * 30_000, self.pre_end - 90_000 + i * 30_000)
            for i in range(4)
        ]
        valid_baseline = all(w["eligible"] for w in baseline)
        references = None
        unstable = []
        if valid_baseline:
            references = {
                "latencies": {
                    g: {
                        m: median(w["latencies"][g][m]["p50"] for w in baseline)
                        for m in ("ttft", "e2e")
                    }
                    for g in GATEWAYS
                },
                "slots": {
                    s: median(w["slots"][s]["hit_fraction"] for w in baseline) for s in ("0", "1")
                },
            }
            for i, window in enumerate(baseline):
                if not self._matches(window, references, replacement_required=False):
                    unstable.append(i)
        windows, streak, recovery, streak_start = [], 0, None, None
        if self.usable is not None:
            for i in range(20):
                start, end = self.usable + i * 30_000, self.usable + (i + 1) * 30_000
                if end > self.end:
                    break
                window = self.window(start, end)
                window["qualifies"] = bool(references and self._matches(window, references))
                if window["qualifies"]:
                    if streak == 0:
                        streak_start = start
                    streak += 1
                else:
                    streak, streak_start = 0, None
                window["streak"] = streak
                if streak == 3 and recovery is None:
                    recovery = {"bracket_ms": [streak_start, end], "confirmation_ms": end}
                windows.append(window)
        errors = [] if valid_baseline else ["inadequate_stage5_baseline"]
        capture_censored = (
            self.usable is not None and recovery is None and self.end < self.usable + 600_000
        )
        if capture_censored:
            errors.append("recovery_deadline_not_fully_captured")
        # A fully captured nonrecovering window may be ineligible due to sample
        # shortfall; only missing/reset source evidence makes stage data inadequate.
        missing = (
            "missing_counter",
            "stale_counter",
            "counter_gap",
            "counter_stale",
            "counter_decrease",
        )
        if any(reason.startswith(missing) for w in windows for reason in w["validity_reasons"]):
            errors.append("inadequate_stage5_counter_evidence")
        if any(
            any(
                reason.startswith("completion_counter_generation_mismatch")
                for reason in w["validity_reasons"]
            )
            and not any(
                reason.startswith("counter_generation_reset") for reason in w["validity_reasons"]
            )
            for w in windows
        ):
            errors.append("inadequate_stage5_generation_join")
        return {
            "baseline_windows": baseline,
            "baseline_references": references,
            "baseline_unstable_windows": unstable,
            "recovery_windows": windows,
            "recovery": recovery,
            "right_censored": recovery is None,
            "censor_reason": None
            if recovery is not None
            else "no_established_usable_endpoint"
            if self.usable is None
            else "recovery_deadline"
            if self.end >= self.usable + 600_000
            else "capture_end",
            "deadline_ms": self.usable + 600_000 if self.usable is not None else None,
            "validity_reasons": errors,
            "operational_outcomes": (["unstable_baseline"] if unstable else [])
            + (
                ["observed_counter_generation_change"]
                if any(
                    any(
                        reason.startswith("counter_generation_reset")
                        for reason in w["validity_reasons"]
                    )
                    for w in windows
                )
                else []
            )
            + (
                ["no_recovery"]
                if self.usable is not None and recovery is None and not capture_censored
                else []
            ),
        }

    def _matches(self, window, references, replacement_required=True):
        if not window["eligible"] or (replacement_required and not window["replacement_traffic"]):
            return False
        return all(
            self.within_latency(window["latencies"][g][m]["p50"], references["latencies"][g][m])
            for g in GATEWAYS
            for m in ("ttft", "e2e")
        ) and all(
            abs(window["slots"][s]["hit_fraction"] - references["slots"][s]) <= 0.05 + 1e-12
            for s in ("0", "1")
        )
