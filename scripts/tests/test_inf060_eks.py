"""CPU fixtures for the streaming EKS checkpoint. No AWS or cluster calls."""

import hashlib
import io
import json
import socket
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from inf060_eks_operator import execute_streaming, extract_verified, retrieve
from inf060_eks_remote import cancel_observations, diagnostic, scan_logs

from inference_platform.eks_deployment import VLLM_IMAGE
from inference_platform.inf060_eks_clock import (
    IDLE_TIMEOUT_SECONDS,
    PORT,
    ClockRefusal,
    ClockStream,
    bracket,
    serve_stream,
)
from inference_platform.inf060_eks_receipts import (
    CONDITIONS,
    FILES,
    build,
    payload,
    schedule_digest,
    verify,
)
from inference_platform.inf060_eks_resources import (
    CLIENT_LABELS,
    client_job,
    serving_resources,
)
from inference_platform.inf060_eks_schedule import (
    DRAIN_SECONDS,
    LEVELS,
    REQUEST_CAP_SECONDS,
    SETUP_PHASES,
    WARMUP_SECONDS,
    WINDOW_SECONDS,
    WINDOW_WAIT_SECONDS,
    canary,
    prompt_label,
    prompts,
    run_offers,
    schedule,
)
from inference_platform.inf060_streaming_probe import observe_stream
from inference_platform.m5_descriptive import resources
from inference_platform.m5_descriptive_client import client_resources
from inference_platform.stage_c_tokenizer import pinned_tokenizer


def event(content=None, finish=None):
    return (
        b"data: "
        + json.dumps(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": content} if content else {},
                        "finish_reason": finish,
                    }
                ]
            }
        ).encode()
        + b"\n\n"
    )


def conditions():
    return {
        **dict.fromkeys(CONDITIONS, "synthetic_fixture"),
        "schedule_sha256": schedule_digest(),
    }


def rows():
    windows = {}
    for level in LEVELS:
        windows[level] = {
            "requests": [{**row, "outcome": "missed"} for row in schedule(level)],
            "drain_ns": 0,
            "clocks": [{"generation": 1, "status": "clock_generation"}],
            "observers": {"suppression": "PASS"},
        }
    return windows


def abort_line(key, stamp="100.000010"):
    return f"{stamp} INFO [async_llm.py:698] Request chatcmpl-{key} aborted."


def realistic_rows():
    windows = rows()
    offset = 100 * 10**9
    before, after = (
        [
            {"c1": t, "c4": t + 1, "e2": offset + t, "e3": offset + t}
            for t in range(start, start + 100, 10)
        ]
        for start in (0, 20000)
    )
    mapping = [[offset, 2], [offset, 2]]
    bounds = bracket(before, after, mapping, same_generation=True)
    for window in windows.values():
        completed = set()
        cancels = []
        for row in window["requests"]:
            if row["cancel_assigned"] and len(cancels) < 4:
                key = f"req_{row['alias']:032x}"
                row.update(
                    outcome="cancelled",
                    generation=(1, 1, 1, 0)[len(cancels)],
                    private_request_id=key,
                    cancel_status="sent",
                    cancel_close_monotonic_ns=1000,
                )
                cancels.append(key)
            elif not row["cancel_assigned"] and row["tenant"] not in completed:
                row.update(
                    outcome="completed",
                    planned_ns=10,
                    dispatch_ns=11,
                    first_content_monotonic_ns=20,
                    terminal_ns=30,
                    completion_tokens=2,
                    content_events=[[0, 20], [1, 25]],
                    validated_done=True,
                    finish_reason="stop",
                )
                completed.add(row["tenant"])
        joined, orphans, non_cancel, unexpected = cancel_observations(
            window["requests"],
            {
                1: [
                    abort_line(cancels[0]),
                    abort_line(cancels[1]),
                    abort_line(cancels[1]),
                ]
            },
            {1: bounds},
        )
        window.update(
            cancels=joined,
            orphans=orphans,
            non_cancel_aborts=non_cancel,
            unexpected_abort_observations=unexpected,
            clocks=[
                {
                    "generation": 1,
                    "status": "bounded",
                    "same_generation": True,
                    "before": before,
                    "after": after,
                    "mapping": mapping,
                    "bounds": bounds,
                },
                {
                    "generation": 2,
                    "status": "clock_generation",
                    "same_generation": False,
                    "before": before,
                    "after": after,
                    "mapping": mapping,
                },
            ],
            gauges=[
                {
                    "generation": n,
                    "monotonic_ns": 1000,
                    "status": "sample",
                    "running": 1,
                    "kv_fraction": 0.25,
                }
                for n in (1, 2)
            ],
        )
    return windows


def write_rebound_member(directory, name, value):
    data = b"".join(map(payload, value)) if name.endswith(".jsonl") else payload(value)
    (directory / name).write_bytes(data)
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    manifest_path.write_bytes(payload(manifest))


def read_member(directory, name):
    data = (directory / name).read_bytes()
    return (
        [json.loads(line) for line in data.splitlines()]
        if name.endswith(".jsonl")
        else json.loads(data)
    )


class ClockProtocolTests(unittest.TestCase):
    def test_clock_idle_and_operator_wait_cover_the_window_and_drain(self):
        self.assertLessEqual(REQUEST_CAP_SECONDS, DRAIN_SECONDS)
        self.assertGreater(IDLE_TIMEOUT_SECONDS, WINDOW_SECONDS + DRAIN_SECONDS)
        self.assertGreater(WINDOW_WAIT_SECONDS, IDLE_TIMEOUT_SECONDS)

    def test_direct_tcp_keeps_one_connection_and_checks_uid(self):
        for expected_uid in ("engine-fixture", "other-fixture"):
            with self.subTest(expected_uid=expected_uid), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(3)
                address, port = listener.getsockname()
                failures = []

                def echo():
                    try:
                        peer, _ = listener.accept()
                        with peer, peer.makefile("rwb") as stream:
                            peer.settimeout(3)
                            serve_stream(stream, stream, ["engine-fixture", "a" * 32])
                    except (ClockRefusal, OSError) as error:
                        failures.append(error)

                thread = threading.Thread(target=echo)
                thread.start()
                try:
                    with patch("inference_platform.inf060_eks_clock.PORT", port):
                        if expected_uid == "other-fixture":
                            with self.assertRaisesRegex(
                                ClockRefusal, "clock_generation"
                            ):
                                ClockStream(address, expected_uid, time.monotonic() + 3)
                        else:
                            stream = ClockStream(
                                address, expected_uid, time.monotonic() + 3
                            )
                            try:
                                self.assertEqual(len(stream.exchange()), 10)
                                self.assertEqual(len(stream.exchange()), 10)
                                self.assertEqual(stream.sequence, 20)
                            finally:
                                stream.close()
                finally:
                    thread.join(timeout=4)
                self.assertFalse(thread.is_alive())
                if expected_uid == "engine-fixture":
                    self.assertEqual(failures, [])

    def test_twenty_samples_over_one_stream_and_wrong_sequence_refusal(self):
        source = io.BytesIO(b"".join(payload(i) for i in range(20)))
        sink = io.BytesIO()
        identity = ["pod-fixture", "f" * 32]
        sample = iter(range(100, 120))
        serve_stream(source, sink, identity, lambda: next(sample))
        records = list(map(json.loads, sink.getvalue().splitlines()))
        self.assertEqual(records, [identity] + [[i, 100 + i] for i in range(20)])
        for encoded in (b"1\n", b"not-json\n", b"\n", b""):
            with self.subTest(encoded=encoded), self.assertRaises(ClockRefusal):
                serve_stream(io.BytesIO(encoded), io.BytesIO(), identity)

    def test_narrowest_hull_and_refusals(self):
        def exchange(start, offset=1000):
            return [
                {"c1": t, "c4": t + i + 1, "e2": t + offset, "e3": t + offset}
                for i, t in enumerate(range(start, start + 100, 10))
            ]

        before, after = exchange(0), exchange(100)
        result = bracket(before, after, [(1000, 2), (1001, 2)], same_generation=True)
        self.assertEqual((result["before_index"], result["after_index"]), (0, 0))
        self.assertEqual(result["precision_floor_ns"], 1007)
        for a, b, samples, generation in (
            (before, after, [(1, 9)], False),
            (before[:-1], after, [(1, 9)], True),
            (before, after, [(1, 9), (6_000_000, 9)], True),
            (before, exchange(100, 500_000), [(1, 9)], True),
            (before, list(reversed(after)), [(1, 9)], True),
        ):
            with (
                self.subTest(generation=generation, samples=samples),
                self.assertRaises(ClockRefusal),
            ):
                bracket(a, b, samples, same_generation=generation)


class StreamingCheckpointTests(unittest.TestCase):
    def test_setup_and_windows_are_disjoint_with_pinned_tokenizer(self):
        tokenizer = pinned_tokenizer()
        seen_aliases, seen_canaries, seen_prompts = set(), set(), set()
        schedules = {level: schedule(level) for level in (*SETUP_PHASES, *LEVELS)}
        rendered_prompts = prompts(
            (row for scheduled in schedules.values() for row in scheduled), tokenizer
        )
        for level, scheduled in schedules.items():
            aliases = {row["alias"] for row in scheduled}
            canaries = {canary(prompt_label(row)) for row in scheduled}
            rendered = {payload(next(rendered_prompts)) for _ in scheduled}
            for previous, current in (
                (seen_aliases, aliases),
                (seen_canaries, canaries),
                (seen_prompts, rendered),
            ):
                self.assertEqual(len(current), len(scheduled), level)
                self.assertTrue(previous.isdisjoint(current), level)
                previous.update(current)
            if level == "warmup":
                self.assertEqual(
                    sum(row["shared_prefix"] for row in scheduled), WARMUP_SECONDS // 2
                )

    def test_rendering_isolated_clock_policy_and_client_label(self):
        namespace = "mti-m5-fixture"
        original = resources(namespace, VLLM_IMAGE)
        rendered = serving_resources(original, VLLM_IMAGE, "{}")
        policy = next(
            row for row in rendered["items"] if row["kind"] == "NetworkPolicy"
        )
        rule = policy["spec"]["ingress"][1]
        self.assertEqual(
            rule,
            {
                "ports": [{"protocol": "TCP", "port": PORT}],
                "from": [{"podSelector": {"matchLabels": CLIENT_LABELS}}],
            },
        )
        source = client_resources(namespace, VLLM_IMAGE, 2147483647)
        job = client_job(source, {"namespace": namespace})["items"][-1]
        self.assertEqual(job["spec"]["template"]["metadata"]["labels"], CLIENT_LABELS)
        self.assertFalse(any(x["kind"] == "NetworkPolicy" for x in original["items"]))

    def test_missed_offer_and_frozen_populations(self):
        self.assertEqual([len(schedule(x)) for x in LEVELS], [150, 600, 1800, 4800])
        self.assertEqual(
            [sum(row["cancel_assigned"] for row in schedule(x)) for x in LEVELS],
            [15, 60, 180, 480],
        )
        records = []
        run_offers(
            [{"slot_ns": 0}],
            lambda _: self.fail("missed slot must not dispatch"),
            records.append,
            end_ns=2,
            start_ns=0,
            now=lambda: 2,
            slots=1,
        )
        self.assertEqual(records[0]["outcome"], "missed")

    def test_eos_before_cancel_and_coalesced_content(self):
        chunks = [
            event("a"),
            event("b") + event("c"),
            event("d") + event(finish="stop"),
            b'data: {"choices":[],"usage":{"prompt_tokens":1024,"completion_tokens":4,"total_tokens":1028,"count_source":"runtime_usage"}}\n\ndata: [DONE]\n\n',
        ]
        observation = observe_stream(
            chunks,
            cancel_assigned=True,
            close=lambda: self.fail("EOS precedes cancel"),
            clock_ns=iter([100, 200, 300, 400]).__next__,
            details=True,
        )
        self.assertTrue(observation["validated_done"])
        self.assertEqual(observation["cancel_status"], "finished_before_cancel")
        self.assertEqual(observation["token_itl_ns"], [100])
        self.assertEqual(observation["transport_content_gaps_ns"], [100, 0])
        self.assertEqual(observation["done_ns"], 400)

    def test_duplicate_missing_and_orphan_abort(self):
        keys = ["req_" + ch * 32 for ch in "abc"]

        attempts = [
            {
                "alias": i,
                "generation": 1,
                "private_request_id": key,
                "cancel_status": "sent",
                "cancel_close_monotonic_ns": 1,
            }
            for i, key in enumerate(keys[:2])
        ]
        rows, orphan, non_cancel, unexpected = cancel_observations(
            attempts, {1: [abort_line(keys[0])] * 2 + [abort_line(keys[2])]}, {}
        )
        self.assertEqual(
            [row["abort_status"] for row in rows], ["duplicate_abort", "missing_abort"]
        )
        self.assertEqual(orphan, {1: 1})
        self.assertEqual(unexpected, [])
        self.assertTrue(all(key.encode() not in payload(rows) for key in keys))
        self.assertEqual(
            non_cancel, {"expected": 0, "matched": 0, "matched_by_reason": {}}
        )

    def test_deadline_close_abort_is_separate_from_true_orphan(self):
        deadline, orphan = ("req_" + ch * 32 for ch in "de")
        joined, counts, non_cancel, unexpected = cancel_observations(
            [
                {
                    "alias": 5,
                    "generation": 1,
                    "private_request_id": deadline,
                    "client_close_reason": "deadline",
                }
            ],
            {1: [abort_line(deadline), abort_line(orphan)]},
            {},
        )
        self.assertEqual(joined, [])
        self.assertEqual(counts, {1: 1})
        self.assertEqual(unexpected, [])
        self.assertEqual(
            non_cancel,
            {"expected": 1, "matched": 1, "matched_by_reason": {"deadline": 1}},
        )

    def test_partial_window_rates_are_unavailable_for_all_cohorts(self):
        for mode, reason in (
            ("clipped", "incomplete_window"),
            ("undrained", "missing_drain"),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                window = realistic_rows()["8"]
                if mode == "clipped":
                    window["requests"].pop()
                else:
                    window["drain_ns"] = None
                directory = Path(tmp) / "receipt"
                build(directory, conditions(), {"8": window}, {})
                levels = read_member(directory, "levels.json")
                summary = levels["8"]
                self.assertGreater(summary["output_tokens"], 0)
                for group in (
                    summary,
                    *summary["by_tenant"].values(),
                    *summary["by_cancel_cohort"].values(),
                ):
                    self.assertEqual(group["rate_unavailable_reason"], reason)
                    for key in ("elapsed_s", "output_tokens_per_s", "completed_per_s"):
                        self.assertIsNone(group[key])
                    self.assertIsNone(group["goodput"]["per_s"])
                self.assertEqual(
                    levels["0.25"]["rate_unavailable_reason"], "incomplete_window"
                )
                summary["completed_per_s"] = 0.25
                write_rebound_member(directory, "levels.json", levels)
                with self.assertRaisesRegex(ValueError, "streaming_summary_mismatch"):
                    verify(directory)

    def test_scheduled_abort_anomalies_are_counted_and_recounted(self):
        window = realistic_rows()["0.25"]
        completed = next(
            row for row in window["requests"] if row["outcome"] == "completed"
        )
        completed.update(generation=1, private_request_id="req_" + "d" * 32)
        cancelled = next(
            row for row in window["requests"] if row.get("cancel_status") == "sent"
        )
        joinable = abort_line(cancelled["private_request_id"])
        logs = {
            1: [joinable, abort_line(completed["private_request_id"])],
            2: [joinable, abort_line("req_" + "e" * 32)],
        }
        bounds = window["clocks"][0]["bounds"]
        joined, orphans, non_cancel, unexpected = cancel_observations(
            window["requests"], logs, {1: bounds}
        )
        self.assertEqual(orphans[2], 1)
        self.assertEqual(
            next(row for row in joined if row["request_alias"] == cancelled["alias"])[
                "abort_status"
            ],
            "joined",
        )
        self.assertEqual(
            unexpected,
            [
                {"request_alias": completed["alias"], "generation": 1},
                {"request_alias": cancelled["alias"], "generation": 2},
            ],
        )
        window.update(
            cancels=joined,
            orphans=orphans,
            non_cancel_aborts=non_cancel,
            unexpected_abort_observations=unexpected,
        )
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "receipt"
            build(directory, conditions(), {"0.25": window}, {})
            levels = read_member(directory, "levels.json")
            self.assertEqual(
                levels["0.25"]["unexpected_scheduled_aborts"], {"1": 1, "2": 1}
            )
            levels["0.25"]["unexpected_scheduled_aborts"]["2"] = 0
            write_rebound_member(directory, "levels.json", levels)
            with self.assertRaisesRegex(
                ValueError, "streaming_unexpected_abort_recount"
            ):
                verify(directory)

    def test_prompt_canary_refuses_and_diagnostic_projects_only_allowlist(self):
        marker = "INF060CANARY" + "a" * 20
        raw = f"100.000000 INFO [logger.py:20] {marker}\n".encode()
        lines, scan = scan_logs(raw)
        self.assertEqual(
            (lines, scan["status"], scan["canary_lines"]), ([], "REFUSED", 1)
        )
        projected = diagnostic("warmup", "unknown", raw=raw)
        self.assertNotIn(marker.encode(), payload(projected))
        self.assertEqual(projected["check"], "stream_receipt")

    def test_full_and_partial_contract_and_laptop_hash_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for complete in (False, True):
                source = root / str(complete)
                build(
                    source,
                    conditions(),
                    realistic_rows() if complete else {},
                    {},
                    complete=complete,
                )
                self.assertEqual(
                    {path.name for path in source.iterdir()}, FILES | {"manifest.json"}
                )
                self.assertIs(verify(source)["complete"], complete)
                if complete:
                    level = read_member(source, "levels.json")["8"]
                    self.assertEqual(level["goodput"]["G"], 2)
                    self.assertEqual(level["latency_ns"]["ttft"]["n"], 2)
                    self.assertEqual(level["latency_ns"]["tpot"]["n"], 2)
                    self.assertEqual(
                        level["timing_status"], {"bounded": 1, "unresolved": 3}
                    )
                    self.assertEqual(
                        level["abort_status"],
                        {
                            "joined": 1,
                            "missing_abort": 1,
                            "duplicate_abort": 1,
                            "unknown_generation": 1,
                        },
                    )
                archive = root / f"{complete}.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    for path in source.iterdir():
                        tar.add(path, arcname=path.name)
                expected = {
                    "bytes": archive.stat().st_size,
                    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "manifest_sha256": hashlib.sha256(
                        (source / "manifest.json").read_bytes()
                    ).hexdigest(),
                }
                self.assertIs(
                    extract_verified(archive, root / f"extract-{complete}", expected)[
                        "complete"
                    ],
                    complete,
                )
                with self.assertRaisesRegex(ValueError, "archive_digest"):
                    extract_verified(
                        archive, root / "corrupt", {**expected, "sha256": "0" * 64}
                    )

    def test_complete_receipt_refuses_rebound_observation_tampering(self):
        mutations = (
            ("requests.jsonl", "streaming_required_observation"),
            ("requests.jsonl", "streaming_missing_observation"),
            ("levels.json", "streaming_summary_mismatch"),
            ("cancels.jsonl", "streaming_cancel_population"),
            ("diagnostics.json", "streaming_private_field"),
            ("levels.json", "streaming_by_tenant_mismatch"),
            ("levels.json", "streaming_by_cancel_cohort_mismatch"),
            ("cancels.jsonl", "streaming_cancel_interval_mismatch"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "realistic"
            build(path, conditions(), realistic_rows(), {}, complete=True)
            for name, reason in mutations:
                with self.subTest(reason=reason):
                    original = read_member(path, name)
                    value = read_member(path, name)
                    if reason == "streaming_required_observation":
                        next(row for row in value if row["outcome"] == "completed").pop(
                            "validated_done"
                        )
                    elif reason == "streaming_missing_observation":
                        value[0]["outcome"] = "unresolved"
                    elif reason == "streaming_summary_mismatch":
                        value["8"]["scheduled"] += 1
                    elif reason == "streaming_cancel_population":
                        value.pop()
                    elif reason == "streaming_private_field":
                        value["fault"] = "INF060CANARY" + "a" * 20
                    elif reason == "streaming_by_tenant_mismatch":
                        value["8"]["by_tenant"]["inf060-a"]["scheduled"] = 999999
                    elif reason == "streaming_by_cancel_cohort_mismatch":
                        value["8"]["by_cancel_cohort"]["assigned"]["cancel_sent"] = 0
                    else:
                        next(
                            row
                            for row in value
                            if row.get("timing_status") == "bounded"
                        )["timing_interval_ns"] = [-5, 1]
                    write_rebound_member(path, name, value)
                    with self.assertRaisesRegex(ValueError, reason):
                        verify(path)
                    write_rebound_member(path, name, original)

    def test_missing_field_fails_even_when_rebound(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partial"
            build(path, conditions(), {}, {})
            manifest_path = path / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            del manifest["conditions"]["engine_version"]
            manifest["conditions_sha256"] = hashlib.sha256(
                payload(manifest["conditions"])
            ).hexdigest()
            manifest_path.write_bytes(payload(manifest))
            with self.assertRaisesRegex(ValueError, "streaming_conditions"):
                verify(path)

    def test_corrupt_chunk_refuses_before_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:

            class Host:
                def request(self, route, end):
                    return b"aaa", {"X-Chunk-SHA256": "wrong"}

            with patch("inf060_eks_operator.extract_verified") as extract:
                with self.assertRaisesRegex(ValueError, "chunk_binding"):
                    retrieve(Host(), "final", {"bytes": 3}, Path(tmp) / "results", 1)
                extract.assert_not_called()

    def test_retention_precedes_teardown_in_success_and_failure(self):
        calls = []

        class Host:
            def request(self, route, *, end):
                _, _, label, offset = route.split("/")
                if int(offset) == 0:
                    calls.append("fetch-" + label)
                data = self.archive[int(offset) : int(offset) + 65536]
                return data, {"X-Chunk-SHA256": hashlib.sha256(data).hexdigest()}

        class Ports:
            host = Host()
            end = time.time() + 3600
            manifest = {
                "account": "fixture",
                "timing": {
                    "one_retrieval_seconds": 150,
                    "retrieval_reserve_seconds": 300,
                    "cleanup_reserve_seconds": 300,
                },
                "forecast_basis": {"hourly_usd": 2, "fixed_other_usd": 0, "margin": 1},
                "descriptive": {
                    "streaming": {"gpu_hourly_usd": 1, "conditions": conditions()}
                },
            }

            def provision(self):
                calls.append("provision")

            def remote(self, phase):
                calls.append(phase)
                if phase == failure:
                    raise ValueError("fixture_failure")
                self.host.archive, binding = (
                    (complete_archive, complete_binding)
                    if phase == "stream-final"
                    else (partial_archive, partial_binding)
                )
                return binding

            def teardown(self):
                calls.append("teardown")
                return {"complete": True}

            def inventory(self):
                calls.append("inventory")
                return {"complete": True}

        def archive(root, complete):
            source = root / ("fixture-" + str(complete))
            build(
                source, conditions(), rows() if complete else {}, {}, complete=complete
            )
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                for member in source.iterdir():
                    tar.add(member, arcname=member.name)
            data = stream.getvalue()
            return data, {
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "manifest_sha256": hashlib.sha256(
                    (source / "manifest.json").read_bytes()
                ).hexdigest(),
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            partial_archive, partial_binding = archive(root, False)
            complete_archive, complete_binding = archive(root, True)
            for index, failure in enumerate((None, "stream-window-1")):
                calls.clear()
                path = Path(tmp) / str(index)
                if failure is None:
                    execute_streaming(Ports(), path)
                    self.assertIn("fetch-8", calls)
                    self.assertIn("stream-final", calls)
                else:
                    with self.assertRaisesRegex(ValueError, "fixture_failure"):
                        execute_streaming(Ports(), path)
                    self.assertIn("stream-partial", calls)
                self.assertEqual(calls[-3:], ["fetch-final", "teardown", "inventory"])
                receipt = json.loads(
                    (path / "results-final" / "teardown.json").read_bytes()
                )
                self.assertTrue(receipt["teardown_complete"])
                self.assertTrue(receipt["inventory_complete"])
