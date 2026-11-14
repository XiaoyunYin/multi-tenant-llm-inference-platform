"""Startup-to-sampler composition over real stdlib HTTP sockets; no cluster locally."""

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from inf037b_engine_fixture import cache_labels, pod

from inference_platform.inf037b_archive import (
    IntegrityError,
    encode,
    iter_segment_rows,
    strict_json,
)
from inference_platform.inf037b_composition import (
    MonotonicScheduler,
    RetainedStartupRows,
    SamplerComposition,
)
from inference_platform.inf037b_live import (
    HTTP,
    METRICS,
    KubernetesAdapter,
    LifecycleReceiptProducer,
    LiveRows,
    NodeLifecycleAdapter,
    VLLMAdapter,
)
from inference_platform.inf037b_sources import ClockMapper, carries_observation


class Clock:
    def __init__(self, on_wait=lambda target: None):
        self.now, self.on_wait = 0, on_wait

    def now_ns(self):
        return self.now

    def wait_until(self, target, stop):
        self.now = target
        self.on_wait(target)


class EngineServer:
    def __init__(self, clock, *, port=0, status=200, on_health=lambda: None, boot="process0"):
        self.clock, self.status, self.on_health = clock, status, on_health
        self.boot = boot
        self.requests, self.active, self.events = [], set(), b""
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                owner.active.add(self.connection)

            def finish(self):
                try:
                    super().finish()
                finally:
                    owner.active.discard(self.connection)

            def do_GET(self):
                status = owner.status
                if self.path.startswith("/events"):
                    offset = int(parse_qs(urlsplit(self.path).query)["offset"][0])
                    status, body = 200, owner.events[offset:]
                elif self.path == "/v1/models":
                    body = encode({"data": [{"max_model_len": 8192}]})
                elif self.path == "/health":
                    body = b"ok"
                    owner.on_health()
                else:
                    body = ("vllm:cache_config_info{" + cache_labels() + "} 1\n").encode()
                    body += "".join(f"{name} 0\n" for name in METRICS.values()).encode()
                owner.requests.append((owner.clock.now_ns(), self.path, status))
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                if self.path.startswith("/events"):
                    self.send_header("X-Capture-Boot", owner.boot)
                    self.send_header("X-Capture-Next", str(len(owner.events)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class CompositionTests(unittest.TestCase):
    def engine(self, clock, **kwargs):
        server = EngineServer(clock, **kwargs)
        self.addCleanup(server.close)
        return server

    def adapter(self, clock, url, *, uid="uid0", slot=0, boot="process0"):
        captured, calls = [], []
        rows = LiveRows("test", "collector", clock=clock.now_ns, sink=captured.append)
        lifecycle = LifecycleReceiptProducer()
        lifecycle.created(uid, slot)
        lifecycle.ingest(
            {
                "pod_uid": uid,
                "sequence": 0,
                "boot_id": boot,
                "mono_ns": 0,
                "event": "supervisor_start",
            }
        )
        rows.row(
            "kubernetes", "kubernetes", rows.boot, "pod_created", {"pod_uid": uid, "slot": slot}
        )
        obj = pod()
        obj["metadata"].update(uid=uid, name="vllm-" + str(slot))
        KubernetesAdapter(
            rows, None, "test", slot_names={"vllm-" + str(slot): slot}, lifecycle=lifecycle
        ).pod_observations(obj)

        class RecordedAdapter(VLLMAdapter):
            def engine_config(self):
                calls.append(("config", clock.now_ns()))
                return super().engine_config()

            def sample(self):
                calls.append(("sample", clock.now_ns()))
                return super().sample()

        adapter = RecordedAdapter(
            rows,
            HTTP(url, local_test=True, timeout=0.2),
            pod_uid=uid,
            slot=slot,
            process_generation=boot,
            model_sha256="a" * 64,
            runtime_sha256="b" * 64,
            semantics_sha256="c" * 64,
            lifecycle=lifecycle,
        )
        return adapter, captured, calls

    @staticmethod
    def startup(adapter, *, uid=None, error=None):
        return adapter.rows.row(
            "kubernetes",
            "kubernetes",
            adapter.rows.boot,
            "startup",
            {"pod_uid": uid or adapter.uid, "slot": adapter.slot},
            error=error,
        )

    def test_owner_poll_waits_for_startup_and_preserves_the_500_ms_grid(self):
        clock = Clock()
        server = self.engine(clock)
        adapter, rows, calls = self.adapter(clock, server.url)
        composition = SamplerComposition(
            {adapter.uid: adapter},
            {adapter.uid: rows},
            scheduler=clock,
            flush=lambda: self.fail("the CaptureOwner owns cooperative-mode flush"),
        )
        self.startup(adapter, uid="foreign")
        self.assertFalse(composition.poll(adapter.uid, deadline_ns=3000000000))
        self.assertFalse(server.requests)
        self.startup(adapter)
        clock.now = 500000000
        self.assertFalse(composition.poll(adapter.uid, deadline_ns=3000000000))
        self.assertEqual(calls, [("config", 500000000)])
        clock.now = 999999999
        self.assertFalse(composition.poll(adapter.uid, deadline_ns=3000000000))
        clock.now = 1000000000
        self.assertTrue(composition.poll(adapter.uid, deadline_ns=3000000000))
        self.assertEqual([call for call in calls if call[0] == "sample"], [("sample", 1000000000)])
        self.assertEqual(composition.samples, {"uid0": 1})
        with self.assertRaisesRegex(IntegrityError, "sampler_already_run"):
            composition.run(deadline_ns=3000000000)
        clock.now = 3000000000
        with self.assertRaisesRegex(IntegrityError, "sampler_startup_deadline"):
            composition.poll(adapter.uid, deadline_ns=3000000000)

    def test_owner_poll_keeps_refused_config_then_serving_recovery(self):
        clock = Clock()
        server = self.engine(clock, status=503)
        adapter, rows, _ = self.adapter(clock, server.url)
        composition = SamplerComposition(
            {adapter.uid: adapter},
            {adapter.uid: rows},
            scheduler=clock,
            flush=lambda: None,
        )
        self.startup(adapter)
        composition.poll(adapter.uid, deadline_ns=3000000000)
        clock.now = 500000000
        composition.poll(adapter.uid, deadline_ns=3000000000)
        server.status = 200
        clock.now = 1000000000
        composition.poll(adapter.uid, deadline_ns=3000000000)
        reports = [row for row in rows if row["payload"]["event"] == "engine_config"]
        self.assertTrue(reports[0]["payload"]["observation_error"])
        self.assertIsNone(reports[-1]["payload"].get("observation_error"))
        self.assertTrue(
            carries_observation([row for row in rows if row["payload"]["event"] == "sample"][-1])
        )

    def test_closed_port_then_503_then_serving_keeps_errors_and_serving_report(self):
        clock, stop, servers, flushed = Clock(), threading.Event(), [], []
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        adapter, rows, _ = self.adapter(clock, f"http://127.0.0.1:{port}")

        def advance(target):
            if target == 500_000_000:
                servers.append(self.engine(clock, port=port, status=503))
            elif target == 1_000_000_000:
                servers[0].status = 200
            else:
                stop.set()

        clock.on_wait = advance
        composition = SamplerComposition(
            {adapter.uid: adapter},
            {adapter.uid: [self.startup(adapter)]},
            scheduler=clock,
            flush=lambda: flushed.append(True),
        )
        self.assertEqual(composition.run(deadline_ns=2_000_000_000, stop=stop), {"uid0": 2})
        reports = [row for row in rows if row["payload"]["event"] == "engine_config"]
        self.assertEqual(len(reports), 3)
        self.assertTrue(all(row["payload"]["observation_error"] for row in reports[:2]))
        self.assertIsNone(reports[-1]["payload"].get("observation_error"))
        self.assertEqual(reports[-1]["payload"]["max_model_len"], 8192)
        samples = [row for row in rows if row["payload"]["event"] == "sample"]
        self.assertEqual(samples[0]["payload"]["observation_error"], "HTTPError")
        self.assertFalse(carries_observation(samples[0]))
        self.assertTrue(carries_observation(samples[-1]))
        self.assertEqual(flushed, [True])
        self.assertTrue(all(not thread.is_alive() for thread in composition.threads))

    def test_no_config_or_sample_before_same_uid_startup_then_exact_cadence(self):
        clock, flushed = Clock(), []
        server = self.engine(clock)
        adapter, rows, calls = self.adapter(clock, server.url)

        self.startup(adapter, uid="another-uid")
        self.startup(adapter, error="unmapped_startup")
        clock.on_wait = lambda target: self.startup(adapter) if target == 1_000_000_000 else None

        composition = SamplerComposition(
            {adapter.uid: adapter},
            {adapter.uid: rows},
            scheduler=clock,
            flush=lambda: flushed.append(True),
        )
        self.assertEqual(composition.run(deadline_ns=2_500_000_000), {"uid0": 2})
        self.assertEqual(calls[0], ("config", 1_000_000_000))
        self.assertEqual(
            [at for name, at in calls if name == "sample"], [1_500_000_000, 2_000_000_000]
        )
        self.assertTrue(all(at >= 1_000_000_000 for _, at in calls))
        self.assertTrue(all(at >= 1_000_000_000 for at, _, _ in server.requests))
        self.assertEqual(flushed, [True])
        events = [row["payload"]["event"] for row in rows]
        self.assertLess(events.index("pod_created"), events.index("container_state"))
        self.assertLess(events.index("startup"), events.index("engine_config"))

    def test_capture_alone_polls_real_events_while_sampler_reads_retained_rows(self):
        from inf037b_fitness_fixture import attach
        from inf037b_setup_fixture import fixture
        from test_inf037b_fitness import reorder

        from inference_platform.inf037b_setup import SetupCollector
        from inference_platform.inf037b_setup_fitness import FitnessProducer

        value = attach(fixture())
        bundle = strict_json(value["fitness_raw"])
        pins, uid = value["binding"]["pins"], "probe-uid0"
        config = strict_json(value["artifacts"]["fitness/config.json"])
        process = config["slots"]["0"]["process_generation"]
        stop, begin_polling = threading.Event(), threading.Event()

        class Scheduler(MonotonicScheduler):
            def wait_until(self, target, signal):
                begin_polling.set()
                super().wait_until(target, signal)

        scheduler, flushed, poll_threads, errors = Scheduler(), [], [], []
        server = self.engine(scheduler, boot=process, on_health=stop.set)
        history = [
            {
                "schema": "vllm-supervisor-v1",
                "pod_uid": uid,
                "node_boot_id": config["slots"]["0"]["boot_id"],
                "boot_id": process,
                "sequence": sequence,
                "mono_ns": (1000 + sequence) * 1_000_000,
                "event": event,
                "signal_data": {"start_ns": 1_000_000_000, "end_ns": 1_001_000_000},
            }
            for sequence, event in enumerate(("supervisor_start", "startup"))
        ]
        server.events = b"".join(json.dumps(event).encode() + b"\n" for event in history)
        lifecycle = LifecycleReceiptProducer()
        lifecycle.created(uid, 0)
        origin = time.monotonic_ns()
        with tempfile.TemporaryDirectory(prefix="r470-retained-") as directory:
            raw = Path(directory)

            def sink(row):
                with (raw / (row["source_kind"] + ".jsonl")).open("ab") as stream:
                    stream.write(encode(row))

            rows = LiveRows(
                value["binding"]["session_id"],
                bundle["raw"][0]["collector_boot_id"],
                attempt="setup",
                clock=lambda: 1_000_000_000 + time.monotonic_ns() - origin,
                sink=sink,
            )
            node = NodeLifecycleAdapter(
                rows,
                HTTP(server.url, local_test=True),
                uid,
                0,
                lifecycle,
                clocks=SimpleNamespace(map=lambda *args: [1001, 1001]),
            )
            adapter = VLLMAdapter(
                rows,
                HTTP(server.url, local_test=True),
                pod_uid=uid,
                slot=0,
                process_generation=process,
                model_sha256=pins["model"],
                runtime_sha256=pins["runtime"],
                semantics_sha256=pins["engine"],
                lifecycle=lifecycle,
            )
            original_poll = node.poll

            def poll():
                poll_threads.append(threading.current_thread().name)
                return original_poll()

            node.poll = poll

            def capture():
                try:
                    if not begin_polling.wait(5):
                        raise AssertionError("sampler never waited for retained startup")
                    while not stop.is_set():
                        node.poll()
                        stop.wait(0.02)
                except Exception as exc:
                    errors.append(exc)
                    stop.set()

            poller = threading.Thread(target=capture, name="capture-lifecycle-owner")
            poller.start()
            composition = SamplerComposition(
                {uid: adapter},
                {uid: RetainedStartupRows(raw, uid, rows.lock)},
                scheduler=scheduler,
                flush=lambda: flushed.append(True),
            )
            try:
                self.assertEqual(
                    composition.run(deadline_ns=scheduler.now_ns() + 5_000_000_000, stop=stop),
                    {uid: 1},
                )
            finally:
                stop.set()
                poller.join(5)
            self.assertFalse(poller.is_alive())
            self.assertEqual(errors, [])
            self.assertTrue(poll_threads)
            self.assertEqual(set(poll_threads), {"capture-lifecycle-owner"})
            actual = [
                row for path in sorted(raw.glob("*.jsonl")) for _, _, row in iter_segment_rows(path)
            ]
            startups = [row for row in actual if row["payload"]["event"] == "startup"]
            self.assertEqual(len(startups), 1)
            self.assertEqual(startups[0]["payload"]["reason"], "independent_supervisor")
            reports = [row for row in actual if row["payload"]["event"] == "engine_config"]
            self.assertEqual(len(reports), 1)
            self.assertTrue(all(not worker.is_alive() for worker in composition.threads))
            self.assertEqual(flushed, [True])
            # The actual retained startup/report must pass the existing producer,
            # alongside the rest of its accepted synthetic two-slot setup inputs.
            replace = {"startup", "engine_config"}
            bundle["raw"] = [
                row
                for row in bundle["raw"]
                if not (row["payload"].get("pod_uid") == uid and row["payload"]["event"] in replace)
            ]
            for row in startups + reports:
                row["stage"] = []
                bundle["raw"].append(row)
            # The synthetic companion rows share this actual Kubernetes stream
            # generation; keep its one-boot identity when joining the two inputs.
            for row in bundle["raw"]:
                if row["source_kind"] == "kubernetes":
                    row["source_generation"] = startups[0]["source_generation"]
            reorder(bundle)
            producer = FitnessProducer(
                encode(bundle),
                binding=value["binding"],
                artifacts=value["artifacts"],
                setup=SetupCollector(encode(value["bundle"]), **value["binding"]),
                allow_offline_fixture=True,
            )
            self.assertEqual(len(producer.engine_observations()), 2)

    def test_poll_callback_is_not_a_retained_row_view(self):
        adapter, _, _ = self.adapter(Clock(), "http://127.0.0.1:1")
        with self.assertRaisesRegex(IntegrityError, "fitness:sampler_uid_inventory"):
            SamplerComposition({"uid0": adapter}, {"uid0": lambda: []}, flush=lambda: None)

    def test_startup_wait_deadline_and_late_source_refuse_and_flush(self):
        for late in (False, True):
            with self.subTest(late=late):
                clock, flushed = Clock(), []
                adapter, _, calls = self.adapter(clock, "http://127.0.0.1:1")

                class Rows:
                    def __iter__(self, late=late, clock=clock, adapter=adapter):
                        if late:
                            clock.now = 1_000_000_001
                            return iter([CompositionTests.startup(adapter)])
                        return iter([])

                composition = SamplerComposition(
                    {"uid0": adapter},
                    {"uid0": Rows()},
                    scheduler=clock,
                    flush=lambda flushed=flushed: flushed.append(True),
                )
                with self.assertRaisesRegex(
                    IntegrityError, "fitness:sampler_startup_deadline:uid0"
                ):
                    composition.run(deadline_ns=1_000_000_000)
                self.assertEqual(calls, [])
                self.assertEqual(flushed, [True])
                self.assertTrue(all(not thread.is_alive() for thread in composition.threads))

    def test_each_uid_has_its_own_startup_and_worker(self):
        class ThreadClock:
            def __init__(self):
                self.local = threading.local()

            def now_ns(self):
                return getattr(self.local, "now", 0)

            def wait_until(self, target, stop):
                self.local.now = target

        clock, adapters, sources, flushed = ThreadClock(), {}, {}, []
        server = self.engine(clock)
        for slot in range(2):
            uid = f"uid{slot}"
            adapter, _, _ = self.adapter(clock, server.url, uid=uid, slot=slot)
            adapters[uid] = adapter
            sources[uid] = [self.startup(adapter)]
        composition = SamplerComposition(
            adapters, sources, scheduler=clock, flush=lambda: flushed.append(True)
        )
        self.assertEqual(composition.run(deadline_ns=1_500_000_000), {"uid0": 2, "uid1": 2})
        self.assertEqual(len(composition.threads), 2)
        self.assertTrue(all(not thread.is_alive() for thread in composition.threads))
        self.assertEqual(flushed, [True])

    def test_stop_joins_threads_flushes_rows_and_closes_http_sockets(self):
        clock, stop, flushed = Clock(), threading.Event(), []
        server = EngineServer(clock, on_health=stop.set)
        opened, connect = [], socket.create_connection

        def real_connection(*args, **kwargs):
            connection = connect(*args, **kwargs)
            opened.append(connection)
            return connection

        try:
            adapter, _, _ = self.adapter(clock, server.url)
            composition = SamplerComposition(
                {"uid0": adapter},
                {"uid0": [self.startup(adapter)]},
                scheduler=clock,
                flush=lambda: flushed.append(True),
            )
            with patch("socket.create_connection", side_effect=real_connection):
                self.assertEqual(composition.run(deadline_ns=5_000_000_000, stop=stop), {"uid0": 1})
            self.assertTrue(all(not thread.is_alive() for thread in composition.threads))
            self.assertEqual(flushed, [True])
            self.assertTrue(opened)
            self.assertTrue(all(connection.fileno() == -1 for connection in opened))
        finally:
            server.close()
        self.assertFalse(server.thread.is_alive())
        self.assertEqual(server.server.socket.fileno(), -1)
        self.assertFalse(server.active)

    def test_stop_interrupts_startup_scheduler_wait(self):
        waiting, stop, flushed = threading.Event(), threading.Event(), []

        class Scheduler(MonotonicScheduler):
            def wait_until(self, target, signal):
                waiting.set()
                super().wait_until(target, signal)

        scheduler = Scheduler()
        adapter, _, calls = self.adapter(scheduler, "http://127.0.0.1:1")
        composition = SamplerComposition(
            {"uid0": adapter},
            {"uid0": []},
            scheduler=scheduler,
            flush=lambda: flushed.append(True),
        )
        errors = []

        def run():
            try:
                composition.run(deadline_ns=scheduler.now_ns() + 60_000_000_000, stop=stop)
            except Exception as exc:
                errors.append(exc)

        runner = threading.Thread(target=run)
        runner.start()
        try:
            self.assertTrue(waiting.wait(5), "worker did not enter its scheduler wait")
        finally:
            stop.set()
            runner.join(5)
        self.assertFalse(runner.is_alive())
        self.assertTrue(all(not thread.is_alive() for thread in composition.threads))
        self.assertEqual((errors, calls, flushed), ([], [], [True]))


class HostCompositionTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("INF037B_COMPOSITION_HOST_CONFIG"), "pending AWS CPU host")
    def test_real_kubernetes_and_node_startup(self):
        config = json.loads(Path(os.environ["INF037B_COMPOSITION_HOST_CONFIG"]).read_bytes())

        def transport(spec):
            spec = dict(spec)
            token_file = spec.pop("token_file", None)
            return HTTP(
                **spec, token=(lambda: Path(token_file).read_text().strip()) if token_file else None
            )

        rows, lifecycle, captured = (
            LiveRows(config["session"], "composition-host"),
            LifecycleReceiptProducer(),
            [],
        )
        rows.sink = captured.append
        uid, slot = config["uid"], config["slot"]
        lifecycle.created(uid, slot)
        kube = KubernetesAdapter(
            rows,
            transport(config["kubernetes"]),
            config["namespace"],
            slot_names={config["pod_name"]: slot},
            lifecycle=lifecycle,
        )
        kube.snapshot()
        self.assertTrue(
            any(
                row["payload"].get("pod_uid") == uid
                and row["payload"].get("container_state") == "running"
                for row in captured
            )
        )
        node = NodeLifecycleAdapter(
            rows,
            transport(config["node"]),
            uid,
            slot,
            lifecycle,
            clocks=ClockMapper(config["clock_rows"]),
        )
        adapter = VLLMAdapter(
            rows,
            transport(config["engine"]),
            pod_uid=uid,
            slot=slot,
            process_generation=config["process_generation"],
            model_sha256=config["model_sha256"],
            runtime_sha256=config["runtime_sha256"],
            semantics_sha256=config["semantics_sha256"],
            lifecycle=lifecycle,
        )
        flushed = []
        composition = SamplerComposition(
            {uid: adapter}, {uid: captured}, flush=lambda: flushed.append(True)
        )
        stop = threading.Event()

        def capture():
            while not stop.is_set():
                node.poll()
                stop.wait(0.05)

        poller = threading.Thread(target=capture, name="capture-lifecycle-owner")
        poller.start()
        try:
            result = composition.run(deadline_ns=rows.clock() + 2_000_000_000, stop=stop)
        finally:
            stop.set()
            poller.join()
        self.assertGreaterEqual(result[uid], 1)
        startup = next(row for row in captured if row["payload"]["event"] == "startup")
        report = next(row for row in captured if row["payload"]["event"] == "engine_config")
        self.assertIsNone(report["payload"].get("observation_error"))
        self.assertLessEqual(startup["capture_end_mono_ns"], report["capture_start_mono_ns"])
        self.assertEqual(flushed, [True])
        self.assertTrue(all(not thread.is_alive() for thread in composition.threads))
