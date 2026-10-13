"""Deterministic virtual backend adapter. No simulated observation is GPU evidence."""

import math

from .r1_metrics import MODEL, NAMES, parse

SCENARIOS = (
    "success",
    "in_flight_refusal",
    "http200_false",
    "delayed_success",
    "exhaust_before_run1",
    "exhaust_between_runs",
    "late_counters",
    "positive_control_failure",
    "zero_hit_failure",
    "second_reset_cleanup",
    "idle_refusal",
    "timeout_uncertain",
    "three_refusals",
    "session_cutoff",
    "noise_repeat",
    "warm_unstable",
)


class VirtualClock:
    def __init__(self):
        self.value = 0.0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += max(0, seconds)

    def wall(self):
        return 1800000000 + self.value


class Fake:
    def __init__(self, scenario, uncached_request_s=0.27):
        if scenario not in SCENARIOS:
            raise ValueError("unknown rehearsal case")
        self.scenario, self.clock = scenario, VirtualClock()
        self.counters = [
            dict.fromkeys(("queries", "hits", "preemptions", "completions"), 0) for _ in range(2)
        ]
        self.cache = [False, False]
        self.updates = []
        self.pending = 0
        self.prep_start = 0
        self.work_until = 0
        self.posts = {}
        self.closed = True
        self.dispatch_while_closed = 0
        self.configurations = []
        self.floors = [{"queries": 0, "completions": 0} for _ in range(2)]
        self.preparing = False
        if not math.isfinite(uncached_request_s) or uncached_request_s <= 0:
            raise ValueError("uncached request service time must be finite and positive")
        self.uncached_request_s = uncached_request_s
        self.completion_times = [[], []]

    def begin_preparation(self, pending):
        self.preparing = True
        self.pending, self.prep_start = pending, self.clock.now()
        self.preparation_cutoff = (
            self.prep_start + 75 if self.scenario == "session_cutoff" and pending == 1 else None
        )
        if self.scenario in {"delayed_success", "session_cutoff"} and pending == 1:
            self.work_until = self.prep_start + 70
        if (self.scenario == "exhaust_before_run1" and pending == 1) or (
            self.scenario == "exhaust_between_runs" and pending == 2
        ):
            self.work_until = self.prep_start + 1000

    def runtime_fitness(self, deadline):
        return {"fixture": True, "native_tokens_match": True, "replicas": 2}

    def preparation_complete(self):
        self.preparing = False

    def close_admissions(self, deadline):
        self.closed = True

    def admission_state(self, deadline):
        work = sum(self.outstanding())
        return {"gateway_reservations": work, "coordinator_inflight": work}

    def outstanding(self):
        self.completion_times = [
            [end for end in replica if end > self.clock.now()] for replica in self.completion_times
        ]
        return [
            len(replica) + int(self.clock.now() < self.work_until)
            for replica in self.completion_times
        ]

    def snapshots(self, deadline):
        due = [item for item in self.updates if item[0] <= self.clock.now()]
        self.updates = [item for item in self.updates if item not in due]
        for _, backend, change in due:
            for key, value in change.items():
                self.counters[backend][key] += value
        results = []
        outstanding = self.outstanding()
        for backend in range(2):
            values = {
                **self.counters[backend],
                "running": int(outstanding[backend] > 0),
                "waiting": max(0, outstanding[backend] - 1),
            }
            lines = []
            for key, value in values.items():
                labels = f'model_name="{MODEL}",engine="0"'
                if key == "completions":
                    labels += ',finished_reason="length"'
                lines.append(f"{NAMES[key]}{{{labels}}} {value}")
            results.append(
                parse(
                    "\n".join(lines),
                    f"fake-generation-{backend}",
                    self.clock.now(),
                    self.clock.wall(),
                )
            )
        return results

    def counter_floors(self):
        return self.floors

    def probe(self, label, deadline):
        self.clock.sleep(0.2)
        for backend in range(2):
            self.floors[backend]["queries"] += 1024
            self.floors[backend]["completions"] += 1
            hit = 1008 if self.cache[backend] else 0
            if (
                self.scenario == "positive_control_failure"
                and label == "positive_control"
                and self.pending == 1
            ):
                hit = 0
            if self.scenario == "zero_hit_failure" and label == "zero_hit" and self.pending == 1:
                hit = 1008
            self.cache[backend] = True
            delay = 4 if self.scenario == "late_counters" else 0
            self.updates.append(
                (
                    self.clock.now() + delay,
                    backend,
                    {"queries": 1024, "hits": hit, "completions": 1},
                )
            )
        return [{"completed": True, "prompt_tokens": 1024, "completion_tokens": 1}] * 2

    def reset(self, backend, stage, deadline):
        self.reset_cache_state = {
            "fixture": True,
            "before": self.cache[backend],
            "after": self.cache[backend],
        }
        key = (self.pending, backend, stage)
        attempt = self.posts.get(key, 0) + 1
        self.posts[key] = attempt
        if backend == 0 and stage == "clear" and self.pending == 1:
            if self.scenario in {"in_flight_refusal", "http200_false"} and attempt == 1:
                self.work_until = self.clock.now() + 2
                return {"status": 200, "success": False}
            if self.scenario == "three_refusals":
                self.work_until = self.clock.now() + 0.5
                return {"status": 200, "success": False}
            if self.scenario == "idle_refusal":
                return {"status": 200, "success": False}
            if self.scenario == "timeout_uncertain" and attempt == 1:
                self.clock.sleep(deadline - self.clock.now())
                raise TimeoutError("uncertain POST outcome")
        self.cache[backend] = False
        self.reset_cache_state["after"] = False
        return {"status": 200, "success": True}

    def configure(self, policy, r, w, b, seed, deadline):
        if any(self.admission_state(deadline).values()):
            raise ValueError("configuration refused while work remains")
        value = {"policy": policy, "R": r, "W": w, "B": b, "seed": seed, "N": 2}
        self.configurations.append(value)
        return value

    def phase(
        self,
        name,
        seconds,
        drain,
        q=None,
        level=None,
        block="b1",
        offset=0,
        deadline=None,
        request_deadline=None,
    ):
        if self.preparing:
            raise ValueError("generator dispatch forbidden during reset preparation")
        self.closed = False
        before = self.snapshots(deadline)
        staircase = name.startswith("staircase")
        waiting = int(level > 8) if staircase else 1
        running = min(level, 8) if staircase else 8
        rate = 40 if q is None else q
        per_host = int(rate * seconds / 2)
        for counter in self.counters:
            counter["queries"] += per_host * 1024
            hit_per_request = 800
            if self.scenario == "warm_unstable" and "-warm-" in name:
                hit_per_request = 800 if int(name.rsplit("-", 1)[1]) // 30 % 2 == 0 else 300
            counter["hits"] += 0 if staircase else per_host * hit_per_request
            counter["completions"] += per_host
        for floor in self.floors:
            floor["queries"] += per_host * 1024
            floor["completions"] += per_host
        self.clock.sleep(seconds)
        # At the closed-loop stop boundary every worker still owns a request.
        # Each replica serves one at a time, at Round113's approximate uncached
        # service time. Stopping dispatch does not cancel those requests.
        tails = [(level + 1) // 2, level // 2] if level is not None else [0, 0]
        for backend, count in enumerate(tails):
            last = max([self.clock.now(), *self.completion_times[backend]])
            for worker in range(count):
                end = last + (worker + 1) * self.uncached_request_s
                self.completion_times[backend].append(end)
                self.updates.append(
                    (
                        end,
                        backend,
                        {
                            "queries": 1024,
                            "hits": 0 if staircase else 800,
                            "completions": 1,
                        },
                    )
                )
            self.floors[backend]["queries"] += count * 1024
            self.floors[backend]["completions"] += count
        last = max(
            [self.clock.now(), *[end for replica in self.completion_times for end in replica]]
        )
        self.clock.sleep(min(drain, last - self.clock.now()))
        after = self.snapshots(deadline)
        from .r1_metrics import delta

        replicas = [
            {
                "completed": per_host + tail - outstanding,
                "preemptions": 0,
                "running": [running] * int(seconds * 2),
                "waiting": [waiting] * int(seconds * 2),
                "load": [running + waiting] * int(seconds * 2),
                "interval_s": [0.5] * int(seconds * 2),
                "deltas": delta(a, z),
            }
            for a, z, tail, outstanding in zip(
                before, after, tails, self.outstanding(), strict=True
            )
        ]
        self.closed = True
        return {
            "name": name,
            "seconds": seconds,
            "q": q,
            "replicas": replicas,
            "before": before,
            "after": after,
            "resources_valid": True,
            "collector_gap_max_s": 0.5,
            "lateness_p95_s": 0,
            "fatal": False,
            "offered": 2 * per_host + sum(tails),
            "admitted": 2 * per_host + sum(tails),
            "completed": sum(replica["completed"] for replica in replicas),
            "failed": 0,
            "rejected": 0,
            "censored": sum(self.outstanding()),
            "delivered_rate": rate,
            "ttft_s": [0.03 if self.scenario == "noise_repeat" and name == "run4-measure" else 0.01]
            * 1000,
            "latency_s": [0.02] * 1000,
            "last_60_replica_rates": [20, 20],
            "fixture": True,
        }

    def finish(self, deadline):
        self.closed = True
        return {
            "fixture": True,
            "cache_empty": not any(self.cache),
            "dispatch_while_closed": self.dispatch_while_closed,
            "backend_generations": [f"fake-generation-{i}" for i in range(2)],
            "exported": True,
            "teardown_required": "future paid lifecycle; fake owns no hosts",
        }
