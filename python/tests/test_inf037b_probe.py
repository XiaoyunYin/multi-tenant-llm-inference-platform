"""Probe protocol/source controls; fake engine callbacks never claim GPU proof."""

import asyncio
import copy
import json
import os
import ssl
import subprocess
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform import inf037b_native as native
from inference_platform.inf037b_archive import IntegrityError, encode, sha
from inference_platform.inf037b_controls import (
    CONTROL_PAYLOADS,
    CONTROL_PAYLOADS_SHA256,
    book_probe,
    control_slot,
    control_tenants,
)
from inference_platform.inf037b_live import ClientSSEAdapter, ClockAdapter, GatewayAdapter, LiveRows
from inference_platform.inf037b_probe import NativeRequestAdapter, SingleProbe, capture_rows
from inference_platform.inf037b_sources import SourceJoin
from inference_platform.package_a_workload import test_tls_command


def origin():
    return {
        "pod_uid": "uid0",
        "boot_id": "process0",
        "node": "node0",
        "node_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "supervisor_pid": os.getpid(),
        "supervisor_start": Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19],
        "helper_sha256": native.digest(Path(native.__file__).read_bytes()),
        "manifest_sha256": "b" * 64,
        "model_sha256": "c" * 64,
        "runtime_sha256": "d" * 64,
    }


@unittest.skipUnless(os.name == "posix", "Linux native source/durable probe")
class NativeTests(unittest.TestCase):
    def emitter(self, root, manifest=None):
        binding = origin()
        if manifest is not None:
            binding["manifest_sha256"] = sha(encode(manifest))
        result = native.NativeEmitter(root, binding)
        self.addCleanup(result.close)
        return result

    def test_abort_is_native_processed_with_exact_cancel_cause_and_ack(self):
        for order in (
            "end-before-ack",
            "ack-before-end",
            "natural",
            "failed-submit",
            "other-caller",
            "non-rpc-abort",
        ):
            with self.subTest(order=order), TemporaryDirectory() as directory:
                emitter = self.emitter(Path(directory))
                emitter.observe("identity", "internal", "chatcmpl-gateway-id")
                emitter.observe("accept", "internal")

                class Core:
                    def abort_requests(self, request_ids, *, observer=emitter):
                        for request_id in request_ids:
                            observer.observe("terminal", request_id, "FINISHED_ABORTED")
                        return request_ids

                native.attach("core", Core, emitter)
                core = Core()

                class API:
                    async def abort(
                        self,
                        request_id,
                        internal=False,
                        *,
                        scenario=order,
                        observer=emitter,
                        core=core,
                    ):
                        self.calls.append((request_id, internal))
                        if scenario in ("end-before-ack", "failed-submit", "other-caller"):
                            core.abort_requests([request_id])
                        if scenario == "non-rpc-abort":
                            observer.observe("terminal", request_id, "FINISHED_ABORTED")
                        if scenario == "failed-submit":
                            raise RuntimeError("submit-lost")
                        return "original-result"

                    async def generate(self):
                        try:
                            raise asyncio.CancelledError()
                        except asyncio.CancelledError:
                            await self.abort("internal", internal=True)
                            raise

                    async def unrelated(self):
                        try:
                            raise asyncio.CancelledError()
                        except asyncio.CancelledError:
                            return await self.abort("internal", internal=True)

                if order == "natural":
                    emitter.observe("terminal", "internal", "FINISHED_LENGTH_CAPPED")
                native.attach("api", API, emitter)
                api = API()
                api.calls = []
                if order == "other-caller":
                    self.assertEqual(asyncio.run(api.unrelated()), "original-result")
                else:
                    with self.assertRaises(
                        RuntimeError if order == "failed-submit" else asyncio.CancelledError
                    ):
                        asyncio.run(api.generate())
                if order == "ack-before-end":
                    core.abort_requests(["internal"])
                self.assertEqual(api.calls, [("internal", True)])
                events = native.read_events(directory)["events"]
                reasons = [
                    event["terminal_reason"] for event in events if event["event"] == "terminal"
                ]
                self.assertEqual(
                    reasons,
                    ["client_cancel_abort"]
                    if order in ("end-before-ack", "ack-before-end")
                    else ["length"]
                    if order == "natural"
                    else [],
                )
                self.assertFalse(emitter.failed)

    def test_wrappers_keep_arguments_results_errors_and_sticky_observer_loss(self):
        with TemporaryDirectory() as directory:
            emitter = self.emitter(Path(directory))

            class Input:
                @staticmethod
                def assign_request_id(request):
                    request.external_req_id, request.request_id = request.request_id, "internal"
                    return request

            class Scheduler:
                def __init__(self):
                    self.requests, self.freed = {}, []

                def add_request(self, request):
                    self.requests[request.request_id] = request
                    return request

                def _free_request(self, request, delay_free_blocks=False):
                    self.freed.append((request, delay_free_blocks))
                    return request

            native.attach("input", Input, emitter)
            native.attach("scheduler", Scheduler, emitter)
            request = SimpleNamespace(
                request_id="chatcmpl-g",
                external_req_id=None,
                status=SimpleNamespace(name="FINISHED_STOPPED"),
            )
            self.assertIs(Input.assign_request_id(request), request)
            scheduler = Scheduler()
            self.assertIs(scheduler.add_request(request), request)
            self.assertIs(
                scheduler.add_request(request), request
            )  # Existing request is not accepted twice.
            self.assertIs(scheduler._free_request(request, True), request)
            self.assertEqual(scheduler.freed, [(request, True)])
            self.assertEqual(
                [e["event"] for e in native.read_events(directory)["events"]].count("accept"), 1
            )
            emitter.db.close()
            self.assertIs(
                scheduler.add_request(SimpleNamespace(request_id="second")),
                scheduler.requests["second"],
            )
            self.assertTrue((Path(directory) / "FAILED").is_file())
            with self.assertRaisesRegex(ValueError, "native:capture_lost"):
                native.read_events(directory)

    def test_fork_reopens_sqlite_and_rebinds_installed_process_lineage(self):
        with TemporaryDirectory() as directory:
            emitter = self.emitter(Path(directory))
            emitter.observe("installed", "scheduler", "e" * 64)
            emitter.observe("identity", "internal", "chatcmpl-g")
            with patch.object(native, "_emitter", emitter):
                native.register_fork()
                pid = os.fork()
                if pid == 0:
                    emitter.observe("accept", "internal")
                    os._exit(2 if emitter.failed else 0)
                deadline, status = time.monotonic() + 5, None
                while time.monotonic() < deadline:
                    done, result = os.waitpid(pid, os.WNOHANG)
                    if done:
                        status = result
                        break
                    time.sleep(0.01)
                if status is None:
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                    self.fail("native fork did not settle")
                self.assertEqual(status, 0)
            events = native.read_events(directory)["events"]
            child_events = [event for event in events if event["pid"] == pid]
            self.assertEqual([event["event"] for event in child_events], ["installed", "accept"])
            self.assertEqual(child_events[0]["ancestry"][-1]["pid"], os.getpid())
            emitter.observe("terminal", "internal", "FINISHED_STOPPED")
            self.assertFalse(emitter.failed)

    def test_overlay_pins_all_sources_and_disabled_install_has_no_side_effect(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            originals = {}
            for index, name in enumerate(native.BASE_FILES):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                data = f"# source {index}\n".encode()
                path.write_bytes(data)
                originals[name] = native.digest(data)
            with patch.dict(native.BASE_FILES, originals, clear=True):
                manifest = native.build_overlay(source, root / "overlay")
                self.assertEqual(manifest["base"], originals)
                self.assertEqual(set(manifest["files"]), set(originals))
                for kind, (name, cls) in native.TARGETS.items():
                    self.assertTrue(
                        (root / "overlay" / name)
                        .read_bytes()
                        .startswith((source / name).read_bytes())
                    )
                    self.assertIn(
                        f"{kind!r}, {cls}".encode(), (root / "overlay" / name).read_bytes()
                    )
                capture = root / "capture"
                capture.mkdir()
                (capture / "supervisor-origin.json").write_bytes(
                    encode(
                        {
                            k: origin()[k]
                            for k in ("pod_uid", "boot_id", "supervisor_pid", "supervisor_start")
                        }
                    )
                )
                environment = {
                    "INF037B_NATIVE_ROOT": str(capture / "native"),
                    "CAPTURE_ROOT": str(capture),
                    "INF037B_NATIVE_MANIFEST": str(root / "overlay/native-manifest.json"),
                    "POD_UID": "uid0",
                    "NODE_NAME": "node0",
                    "MODEL_SHA256": "c" * 64,
                    "RUNTIME_SHA256": "d" * 64,
                }

                class Input:
                    @staticmethod
                    def assign_request_id(request):
                        return request

                class API:
                    async def abort(self, request_id, internal=False):
                        pass

                    async def generate(self):
                        pass

                with patch.dict(os.environ, environment), patch.object(native, "_emitter", None):
                    native.install("input", Input, root / "overlay" / native.TARGETS["input"][0])
                    self.addCleanup(native._emitter.close)
                    untouched = root / "overlay/vllm/entrypoints/serve/engine/serving.py"
                    saved = untouched.read_bytes()
                    untouched.write_bytes(saved + b"# altered\n")
                    with self.assertRaisesRegex(ValueError, "native:runtime_sources"):
                        native.install("api", API, root / "overlay" / native.TARGETS["api"][0])
                    untouched.write_bytes(saved)
                    with patch.dict(os.environ, {"MODEL_SHA256": "f" * 64}):
                        with self.assertRaisesRegex(ValueError, "native:origin_changed"):
                            native.install("api", API, root / "overlay" / native.TARGETS["api"][0])
                path.write_bytes(b"tampered\n")
                with self.assertRaisesRegex(ValueError, "native:base_sources"):
                    native.build_overlay(source, root / "bad")
            with patch.dict(os.environ, {}, clear=True):
                native.install("scheduler", object, "does-not-exist")
            with self.assertRaisesRegex(ValueError, "native:emitter_missing"):
                native.read_events(root / "absent")

    def test_native_adapter_requires_source_lineage_cause_and_real_request_bijection(self):
        for fault, reason in (
            (None, None),
            ("clock", None),
            ("binding-race", None),
            ("origin", "probe:native_lineage"),
            ("source", "probe:native_source"),
            ("ancestry", "probe:native_process_lineage"),
            ("sequence", "probe:native_sequence"),
            ("cause", "probe:native_abort_cause"),
            ("status", "probe:native_abort_status"),
            ("path", "probe:native_abort_path"),
            ("reference", "probe:native_end_reference"),
        ):
            with self.subTest(fault=fault), TemporaryDirectory() as directory:
                manifest = {
                    "schema": "inf037b-native-overlay-v1",
                    "version": "0.29.0",
                    "base": native.BASE_FILES,
                    "files": {name: "e" * 64 for name in native.BASE_FILES},
                    "helper_sha256": native.digest(Path(native.__file__).read_bytes()),
                }
                emitter = self.emitter(Path(directory), manifest)
                for kind in native.TARGETS:
                    emitter.observe("installed", kind, "e" * 64)
                emitter.observe("identity", "internal", "chatcmpl-gateway-id")
                emitter.observe("accept", "internal")
                emitter.observe("abort_intent", "internal", "CancelledError")
                emitter.observe("abort_ack", "internal")
                emitter.abort_context.active = ("internal",)
                emitter.observe("terminal", "internal", "FINISHED_ABORTED")
                emitter.abort_context.active = ()
                raw = native.read_events(directory)["events"]
                first_ms = raw[0]["mono_ns"] // 1_000_000 - 1
                last_ms = raw[-1]["mono_ns"] // 1_000_000 + 2
                while time.monotonic_ns() < last_ms * 1_000_000:
                    time.sleep(0.001)
                clock = ClockAdapter(LiveRows("s", "collector"))
                before = clock.mapping(
                    "node:node0",
                    emitter.origin["node_boot_id"],
                    first_ms,
                    first_ms * 1_000_000,
                    first_ms * 1_000_000,
                )
                after = clock.mapping(
                    "node:node0",
                    emitter.origin["node_boot_id"],
                    last_ms,
                    last_ms * 1_000_000,
                    last_ms * 1_000_000,
                )
                clock_rows = [before] if fault == "clock" else [before, after]
                collected = []

                class HTTP:
                    def get(self, path, *, fault=fault, directory=directory):
                        bundle = native.read_events(directory, int(path.split("=")[-1]))
                        events = bundle["events"]
                        if fault == "origin":
                            bundle["origin"]["boot_id"] = "foreign"
                        elif fault == "source":
                            events[0]["source_sha256"] = "foreign"
                        elif fault == "ancestry":
                            events[0]["ancestry"][-1]["start"] = "foreign"
                        elif fault == "sequence":
                            events[0]["sequence"] += 1
                        elif fault == "cause":
                            events[:] = [
                                event for event in events if event["event"] != "abort_intent"
                            ]
                            for index, event in enumerate(events):
                                event["sequence"] = index
                            bundle["next"] = len(events) - 1
                        elif fault == "status":
                            for event in events:
                                if event["event"] == "native_end":
                                    event["status"] = "FINISHED_STOPPED"
                                elif event["event"] == "terminal":
                                    event["terminal"]["status"] = "FINISHED_STOPPED"
                        elif fault == "path":
                            for event in events:
                                if event["event"] == "native_end":
                                    event["abort_rpc"] = False
                                elif event["event"] == "terminal":
                                    event["terminal"]["abort_rpc"] = False
                        elif fault == "reference":
                            next(e for e in events if e["event"] == "terminal")["terminal"][
                                "mono_ns"
                            ] += 1
                        return encode(bundle), {}

                bindings = {"gateway0": {"gateway-id": "offered"}, "gateway1": {}}
                adapter = NativeRequestAdapter(
                    LiveRows("s", "collector", sink=collected.append),
                    HTTP(),
                    origin=emitter.origin,
                    manifest=manifest,
                    slot=0,
                    request_ids=bindings,
                    clock_rows=clock_rows,
                )
                if reason:
                    with self.assertRaisesRegex((IntegrityError, KeyError), reason):
                        adapter.ready()
                else:
                    if fault == "binding-race":
                        from inference_platform.inf037b_resolver import require as checked_require

                        reading, updated = threading.Event(), threading.Event()

                        def bind(reading=reading, bindings=bindings, updated=updated):
                            reading.wait(2)
                            bindings["gateway0"]["concurrent"] = "unused"
                            updated.set()

                        def checked(condition, reason, reading=reading, updated=updated):
                            if reason == "probe:ambiguous_native_request" and not updated.is_set():
                                reading.set()
                                self.assertTrue(updated.wait(2))
                            return checked_require(condition, reason)

                        writer = threading.Thread(target=bind)
                        writer.start()
                        try:
                            with patch(
                                "inference_platform.inf037b_probe.require", side_effect=checked
                            ):
                                adapter.ready()
                        finally:
                            reading.set()
                            writer.join(2)
                        self.assertTrue(updated.is_set())
                    else:
                        adapter.ready()
                    if fault == "clock":
                        self.assertEqual(adapter.accepted, set())
                        self.assertEqual(len(adapter.pending), 2)
                        clock_rows.append(after)
                        adapter.poll()
                    self.assertEqual(adapter.accepted, {"offered"})
                    self.assertEqual(adapter.ended, {"offered"})
                    self.assertEqual(SourceJoin(clock_rows + collected).errors, [])
                    self.assertEqual(adapter.poll(), [])


@unittest.skipUnless(os.name == "posix", "durable Linux probe")
class ProbeTests(unittest.TestCase):
    def test_gateway_waits_for_response_identity_without_repolling_or_loss(self):
        raw = encode(
            {
                "schema": "gateway-measurement-v1",
                "sequence": 0,
                "boot_id": "gboot",
                "mono_ns": 1,
                "event": "upstream_close",
                "data": {
                    "request_id": "g-id",
                    "reservation_id": "r",
                    "backend_uid": "uid",
                    "backend_name": "backend0",
                },
            }
        )

        class HTTP:
            offset = 0

            def get(self, path):
                body = raw if self.offset == 0 else b""
                self.offset += len(body)
                return body, {"X-Capture-Boot": "gboot", "X-Capture-Next": str(self.offset)}

        bindings = {}
        adapter = GatewayAdapter(
            LiveRows("s", "b"),
            HTTP(),
            "gateway0",
            slot_names={"backend0": 0},
            config_sha256="a" * 64,
            request_ids=bindings,
            defer_request_bindings=True,
        )
        self.assertEqual(adapter.poll(), [])
        self.assertEqual(adapter.offset, len(raw))
        bindings["g-id"] = "offered"
        rows = adapter.poll()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["request_id"], "offered")
        self.assertEqual(adapter.poll(), [])
        self.assertFalse(adapter.lost)

    def test_closed_clean_sealed_capture_is_required(self):
        for descriptor in ({}, {"closed": True}, {"closed": True, "transport_clean": False}):
            with self.assertRaisesRegex(IntegrityError, "probe:closed_clean_capture_required"):
                list(capture_rows(Path("unavailable"), descriptor))

    def protocol(
        self,
        root,
        *,
        emitter_missing=False,
        attempt="setup",
        detached_client=False,
        control_credentials=None,
    ):
        from test_inf037b_capture import CaptureTests

        fixture = CaptureTests()
        self.addCleanup(fixture.doCleanups)
        owner = fixture.owner(
            root,
            {
                "traffic": [
                    ["client", "client:gateway0", "kernel-boot"],
                    ["client", "client:gateway1", "kernel-boot"],
                    ["controller", "probe", "kernel-boot"],
                ]
            },
            attempt=attempt,
        )
        rows = owner.rows("traffic")
        calls, now, lock = [], [0], threading.Lock()
        endpoint = SimpleNamespace(accepted=set(), ended=set(), pending=[])

        def clock():
            with lock:
                return now[0]

        def sleep(seconds):
            with lock:
                now[0] += int(seconds * 1e9)
            time.sleep(0)  # Let dispatched fake I/O settle; this is not a wall-time receipt.

        class Client(ClientSSEAdapter):
            def request(self, url, payload, offer, **kwargs):
                rid = offer["request_id"]
                if rid in CONTROL_PAYLOADS:
                    fixture_payload = CONTROL_PAYLOADS[rid]
                    if (
                        payload != fixture_payload
                        or kwargs["credential"] != f"control-{control_slot(rid)}"
                    ):
                        raise AssertionError("control payload/tenant pin")
                elif payload["max_tokens"] != 1 or kwargs["credential"] != "credential":
                    raise AssertionError("registered trace changed")
                with lock:
                    calls.append((self.gateway, copy.deepcopy(offer), payload["max_tokens"]))
                    endpoint.accepted.add(offer["request_id"])
                    endpoint.ended.add(offer["request_id"])
                return [
                    {
                        "error": None,
                        "payload": {
                            "event": "cancel" if kwargs.get("cancel_after_content") else "terminal"
                        },
                    }
                ]

            def missed(self, offer):
                return super().missed(offer)

        class Source:
            pending = []
            lost = False
            accepted, ended = endpoint.accepted, endpoint.ended

            def ready(self):
                if emitter_missing:
                    raise IntegrityError("probe:native_emitter_missing")

            def poll(self):
                return []

        clients = {g: Client(rows, g, "a" * 64) for g in ("gateway0", "gateway1")}
        if detached_client:
            clients["gateway0"] = Client(LiveRows("s", "b", attempt="setup"), "gateway0", "a" * 64)
        payloads = {f"p{i:03}": {"max_tokens": 1, "stream": True} for i in range(384)}
        driver = SingleProbe(
            owner=owner,
            clients=clients,
            endpoints={g: "https://localhost/v1/chat/completions" for g in clients},
            credentials={g: lambda: "credential" for g in clients},
            control_credentials=control_credentials
            if control_credentials is not None
            else {slot: lambda slot=slot: f"control-{slot}" for slot in (0, 1)},
            contexts={g: ssl.create_default_context() for g in clients},
            tls={
                g: {"version": "TLSv1.3", "verified": True, "peer_sha256": "e" * 64}
                for g in clients
            },
            controller_rows=rows,
            payloads=payloads,
            payloads_sha256=sha(encode(payloads)),
            start_ns=91_000_000_000,
            stop_ns=246_000_000_000,
            native=[Source()],
            gateway_adapters={g: Source() for g in clients},
            clock=clock,
            sleep=sleep,
        )
        write = driver.store.write

        def persisted(state):
            self.assertFalse(driver.owner.lock._is_owned(), "probe state fsync holds owner lock")
            return write(state)

        driver.store.write = persisted
        return driver, calls, now

    def test_control_payload_pin_and_credential_inventory_refuse(self):
        with TemporaryDirectory() as directory:
            with patch("inference_platform.inf037b_probe.CONTROL_PAYLOADS_SHA256", "0" * 64):
                with self.assertRaisesRegex(IntegrityError, "probe:control_pin"):
                    self.protocol(Path(directory))
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IntegrityError, "probe:control_credentials"):
                self.protocol(Path(directory), control_credentials={})

    def test_controls_are_booked_before_start_inside_gpu_branch(self):
        booking = book_probe(
            branch_start_ns=0,
            ready_ns=1_000_000_000,
            branch_stop_ns=1_740_000_000_000,
            remaining_gpu_seconds=1499,
        )
        self.assertEqual(booking["start_ns"], 91_000_000_000)
        self.assertEqual(booking["stop_ns"], 241_000_000_000)
        self.assertEqual(booking["controls_allowance_seconds"], 90)
        for stop, remaining in ((1_740_000_000_000, 1500), (1_740_000_000_001, 0)):
            with self.assertRaisesRegex(IntegrityError, "probe:gpu_branch_booking"):
                book_probe(
                    branch_start_ns=0,
                    ready_ns=1_000_000_000,
                    branch_stop_ns=stop,
                    remaining_gpu_seconds=remaining,
                )
        with TemporaryDirectory() as directory:
            driver, calls, _ = self.protocol(Path(directory))
            driver.start_ns = 89_999_999_999
            with patch("inference_platform.inf037b_probe.require_group_leader"):
                with self.assertRaisesRegex(IntegrityError, "probe:control_allowance"):
                    driver.run()
            self.assertEqual(calls, [])
            self.assertNotIn("single_probe", driver.store.read())

    def test_probe_cannot_run_on_an_attempt_capture(self):
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IntegrityError, "probe:setup_owner"):
                self.protocol(Path(directory), attempt=1)

    def test_probe_rejects_client_rows_from_another_capture(self):
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IntegrityError, "probe:capture_row_owner"):
                self.protocol(Path(directory), detached_client=True)

    def test_probe_intent_serializes_with_capture_loss_on_the_same_store(self):
        with TemporaryDirectory() as directory:
            driver, _, _ = self.protocol(Path(directory), emitter_missing=True)
            entered, release, lost = threading.Event(), threading.Event(), threading.Event()
            failures = []
            write = driver.store.write

            def blocked(state):
                self.assertFalse(
                    driver.owner.lock._is_owned(), "probe state fsync holds owner lock"
                )
                if "single_probe" in state and not state["capture"].get("losses"):
                    entered.set()
                    release.wait(2)
                return write(state)

            def probe():
                try:
                    driver.run()
                except IntegrityError as exc:
                    if "probe:native_emitter_missing" not in str(exc):
                        failures.append(str(exc))

            def loss():
                try:
                    driver.owner.loss("forced-concurrent-loss")
                except Exception as exc:
                    failures.append(str(exc))
                finally:
                    lost.set()

            with (
                patch.object(driver.store, "write", side_effect=blocked),
                patch("inference_platform.inf037b_probe.require_group_leader"),
            ):
                probing = threading.Thread(target=probe)
                probing.start()
                self.assertTrue(entered.wait(2))
                losing = threading.Thread(target=loss)
                losing.start()
                try:
                    time.sleep(0.02)
                    self.assertFalse(lost.is_set())
                finally:
                    release.set()
                    probing.join(2)
                    losing.join(2)
            self.assertEqual(failures, [])
            self.assertIn("forced-concurrent-loss", driver.store.read()["capture"]["losses"])

    def test_single_fixed_probe_schedule_controls_and_irrevocable_intent(self):
        with TemporaryDirectory() as directory:
            driver, calls, now = self.protocol(Path(directory))
            with patch("inference_platform.inf037b_probe.require_group_leader"):
                result = driver.run()
                driver.start_ns = now[0] + 91_000_000_000
                driver.stop_ns = now[0] + 246_000_000_000
                with self.assertRaisesRegex(IntegrityError, "probe:already_allocated"):
                    driver.run()
            self.assertEqual(result["scheduled"], 1311)
            self.assertEqual(len(calls), 1317)
            self.assertEqual(result["replacements"], 0)
            self.assertGreaterEqual(now[0], 121_000_000_000)
            trace = sorted(
                (entry for _, entry, _ in calls if entry["request_id"].startswith("a1-pre-")),
                key=lambda row: row["offer_index"],
            )
            self.assertEqual(
                [row["gateway_uid"] for row in trace], [f"gateway{i % 2}" for i in range(1311)]
            )
            self.assertTrue(
                all(
                    tokens == (64 if row["request_id"] in CONTROL_PAYLOADS else 1)
                    for _, row, tokens in calls
                )
            )
            self.assertEqual(
                [row["scheduled_ms"] for row in trace],
                [91000 + i * 100000 // 1092 for i in range(1311)],
            )

    def test_one_missed_offer_needs_no_native_endpoint(self):
        with TemporaryDirectory() as directory:
            driver, calls, _ = self.protocol(Path(directory))
            semaphore = threading.BoundedSemaphore(328)
            acquire = semaphore.acquire
            first = [True]

            def admit(*args, **kwargs):
                if first[0]:
                    first[0] = False
                    return False
                return acquire(*args, **kwargs)

            with (
                patch("inference_platform.inf037b_probe.require_group_leader"),
                patch(
                    "inference_platform.inf037b_probe.threading.BoundedSemaphore",
                    return_value=semaphore,
                ),
                patch.object(semaphore, "acquire", side_effect=admit),
            ):
                result = driver.run()
            self.assertEqual(result["scheduled"], 1311)
            self.assertEqual(len(calls), 1316)
            descriptor = driver.owner.close()
            missed = [
                row
                for row in capture_rows(driver.owner.root, descriptor)
                if row["payload"]["event"] == "missed"
            ]
            self.assertEqual(len(missed), 1)
            self.assertNotIn(missed[0]["payload"]["request_id"], driver.native[0].ended)

    def test_control_deployment_policy_and_payload_pins(self):
        self.assertEqual(sha(encode(CONTROL_PAYLOADS)), CONTROL_PAYLOADS_SHA256)
        self.assertEqual(len(CONTROL_PAYLOADS), 6)
        policies = control_tenants({0: "a" * 64, 1: "b" * 64})
        config = json.loads(
            (Path(__file__).resolve().parents[2] / "deploy/eks/setup-controls.json").read_text()
        )
        self.assertEqual(config["payloads"], CONTROL_PAYLOADS)
        self.assertEqual(config["payloads_sha256"], CONTROL_PAYLOADS_SHA256)
        self.assertEqual(
            config["tenants"],
            control_tenants(
                {0: "CONTROL_SLOT0_CREDENTIAL_SHA256", 1: "CONTROL_SLOT1_CREDENTIAL_SHA256"}
            ),
        )
        self.assertIs(config["upstream_ignore_eos"], True)
        self.assertEqual(config["trace_tenant_max_output_tokens"], 1)
        self.assertEqual([p["max_output_tokens"] for p in policies], [64, 64])
        self.assertEqual([p["setup_backend_id"] for p in policies], ["vllm-0", "vllm-1"])
        for rid in CONTROL_PAYLOADS:
            self.assertEqual(
                CONTROL_PAYLOADS[rid]["max_tokens"],
                policies[control_slot(rid)]["max_output_tokens"],
            )

    def test_no_emitter_refuses_before_traffic_and_cannot_retry(self):
        with TemporaryDirectory() as directory:
            driver, calls, _ = self.protocol(Path(directory), emitter_missing=True)
            with patch("inference_platform.inf037b_probe.require_group_leader"):
                with self.assertRaisesRegex(IntegrityError, "probe:native_emitter_missing"):
                    driver.run()
                with self.assertRaisesRegex(IntegrityError, "probe:already_allocated"):
                    driver.run()
            self.assertEqual(calls, [])

    def test_tls_sse_cancel_and_already_finished_control_retain_original_bytes(self):
        from test_inf037b_capture import CaptureTests

        content = (
            b'data: {"choices":[{"index":0,"delta":{"content":"one"},"finish_reason":null}]}\n\n'
        )
        one_token = content.replace(b'"finish_reason":null', b'"finish_reason":"length"')
        tail = (
            b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2,"count_source":"runtime_usage"}}\n\n'
            b"data: [DONE]\n\n"
        )
        one_token_usage = tail[tail.index(b'data: {"choices":[]') :]
        tail = tail.replace(b'"delta":{}', b'"delta":{"content":"last"}').replace(
            b'"completion_tokens":1,"total_tokens":2', b'"completion_tokens":64,"total_tokens":65'
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([str(v) for v in test_tls_command(root)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(root / "tls.crt", root / "tls.key")
            client_context = ssl.create_default_context(cafile=str(root / "tls.crt"))
            state = {"mode": "complete", "posts": 0}
            cancelled_before_finish = threading.Event()

            class Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, *args):
                    pass

                def do_POST(self):
                    payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    mode = state["mode"]
                    if mode == "cancel":
                        assert payload["max_tokens"] == 64
                    state["posts"] += 1
                    self.send_response(200)
                    self.send_header("X-Request-ID", f"g-{state['posts']}")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    body = content + tail if mode in ("already-done", "unverified") else content
                    if mode == "one-token-finished":
                        body = one_token
                    role = b'data: {"choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'
                    self.wfile.write(f"{len(role):x}\r\n".encode() + role + b"\r\n")
                    self.wfile.flush()
                    time.sleep(0.002)
                    self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n")
                    if mode in ("already-done", "unverified"):
                        self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                    if mode == "complete":
                        time.sleep(0.03)
                        self.wfile.write(f"{len(tail):x}\r\n".encode() + tail + b"\r\n0\r\n\r\n")
                        self.wfile.flush()
                    if mode == "one-token-finished":
                        # Real v0.29 max_tokens=1: content and length in one read,
                        # usage/DONE only in a later read. Finish already forbids cancel.
                        time.sleep(0.03)
                        try:
                            usage = one_token_usage
                            self.wfile.write(
                                f"{len(usage):x}\r\n".encode() + usage + b"\r\n0\r\n\r\n"
                            )
                            self.wfile.flush()
                        except OSError:
                            pass
                    if mode == "cancel":
                        try:
                            self.connection.settimeout(0.5)
                            if self.connection.recv(1) == b"":
                                cancelled_before_finish.set()
                        except TimeoutError:
                            self.wfile.write(
                                f"{len(tail):x}\r\n".encode() + tail + b"\r\n0\r\n\r\n"
                            )
                            self.wfile.flush()

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            server.socket = server_context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            expected_peer = sha(ssl.PEM_cert_to_DER_cert((root / "tls.crt").read_text()))
            for mode in (
                "complete",
                "cancel",
                "already-done",
                "one-token-finished",
                "bad-peer",
                "unverified",
            ):
                with self.subTest(mode=mode):
                    state["mode"] = mode
                    case = root / mode
                    case.mkdir()
                    fixture = CaptureTests()
                    self.addCleanup(fixture.doCleanups)
                    owner = fixture.owner(
                        case,
                        {
                            "traffic": [
                                ["client", "client:gateway0", "kernel-boot"],
                                ["controller", "probe", "kernel-boot"],
                            ]
                        },
                    )
                    rows = owner.rows("traffic")
                    client = ClientSSEAdapter(
                        rows, "gateway0", "a" * 64, retain=owner.retainer("traffic")
                    )
                    last_raw = [bytearray()]
                    retain, sink = client.retain, rows.sink

                    def raw_first(start, end, body, metadata, retain=retain, last_raw=last_raw):
                        retain(start, end, body, metadata)
                        # Retention callbacks now describe completed protocol units;
                        # one socket read can complete several SSE frames.
                        if metadata.get("unit") == "sse_frame":
                            last_raw[0].extend(body)

                    def normalized(row, sink=sink, last_raw=last_raw):
                        if row["payload"]["event"] == "sse":
                            self.assertEqual(
                                bytes(last_raw[0]), bytes.fromhex(row["payload"]["chunk_hex"])
                            )
                            last_raw[0].clear()
                        return sink(row)

                    raw_first.barrier = retain.barrier
                    client.retain, rows.sink = raw_first, normalized
                    facts = []

                    def observed(tls, begin, end, *, mode=mode, facts=facts, rows=rows):
                        facts.append(tls)
                        self.assertEqual(tls["peer_sha256"], expected_peer)
                        if mode == "bad-peer":
                            raise IntegrityError("probe:tls_peer")
                        rows.row(
                            "controller",
                            "probe",
                            rows.boot,
                            "precondition",
                            {"name": "tls:test", "value": tls},
                            start_ns=begin,
                            end_ns=end,
                        )

                    context = (
                        client_context if mode != "unverified" else ssl._create_unverified_context()
                    )
                    offer = {
                        "request_id": mode,
                        "offer_index": 0,
                        "prefix_id": "p000",
                        "scheduled_ms": time.monotonic_ns() // 1_000_000,
                    }
                    before = state["posts"]
                    if mode == "unverified":
                        with self.assertRaisesRegex(ValueError, "client_requires_verified_tls"):
                            client.request(
                                f"https://localhost:{server.server_port}/v1/chat/completions",
                                {"max_tokens": 1},
                                offer,
                                credential="secret",
                                context=context,
                            )
                        self.assertEqual(state["posts"], before)
                        owner.close()
                        continue
                    output = client.request(
                        f"https://localhost:{server.server_port}/v1/chat/completions",
                        CONTROL_PAYLOADS["ingress-gateway0-0"]
                        if mode in ("complete", "cancel", "already-done")
                        else {"max_tokens": 1},
                        offer,
                        credential="secret",
                        context=context,
                        cancel_after_content=mode
                        in ("cancel", "already-done", "one-token-finished"),
                        tls_observer=observed,
                    )
                    if mode in ("complete", "cancel"):
                        self.assertEqual(
                            owner.fsync_count, 0, "client did synchronous wire barriers"
                        )
                        self.assertEqual(len(owner.client_completions), 1)
                    descriptor = owner.close()
                    if mode in ("complete", "cancel"):
                        self.assertTrue(descriptor["transport_clean"])
                        accepted = list(capture_rows(owner.root, descriptor))
                        self.assertTrue(accepted)
                        if mode == "cancel":
                            self.assertTrue(cancelled_before_finish.wait(1))
                            self.assertEqual(
                                sum(row["payload"]["event"] == "cancel" for row in output), 1
                            )
                            self.assertEqual(output[-1]["payload"]["outcome"], "right_censored")
                        else:
                            self.assertEqual(output[-1]["payload"]["outcome"], "complete")
                            first = next(
                                row
                                for row in output
                                if row["payload"].get("chunk_hex") == content.hex()
                            )
                            finish = next(
                                row
                                for row in output
                                if row["payload"].get("chunk_hex") == tail.hex()
                            )
                            self.assertLess(
                                first["capture_end_mono_ns"], finish["capture_start_mono_ns"]
                            )
                    else:
                        self.assertFalse(descriptor["transport_clean"])
                        with self.assertRaisesRegex(
                            IntegrityError, "probe:closed_clean_capture_required"
                        ):
                            list(capture_rows(owner.root, descriptor))
                        self.assertFalse(any(row["payload"]["event"] == "cancel" for row in output))
                        if mode == "bad-peer":
                            self.assertEqual(state["posts"], before)
                    wire = fixture.wire(owner)
                    original = b"".join(record["body"] for record in wire)
                    if mode != "bad-peer":
                        self.assertIn(
                            one_token if mode == "one-token-finished" else content, original
                        )
                    if mode == "one-token-finished":
                        self.assertTrue(
                            any(
                                r["metadata"].get("error") == "client_cancel_already_complete"
                                for r in wire
                            )
                        )
                    self.assertNotIn(b"secret", original)
                    self.assertEqual(len(facts), 1)
