"""Read-only cache witnesses and real subprocess/file-lock lifecycle races."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from inference_platform.inf037b_archive import IntegrityError
from inference_platform.inf037b_live import (
    HTTP,
    LifecycleReceiptProducer,
    LiveRows,
    NodeCacheAdapter,
    NodeLifecycleAdapter,
)
from inference_platform.inf037b_sources import ClockMapper, SourceJoin

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy/eks" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class RuntimeObservers(unittest.TestCase):
    def test_node_observer_reads_process_end_after_pod_server_stops(self):
        runtime = module("node_observer")
        supervisor_runtime = module("capture_runtime")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            uid = "pod-123"
            lifecycle_root = root / "lifecycle"
            spool = lifecycle_root / uid
            spool.mkdir(parents=True)
            supervisor = supervisor_runtime.Supervisor(spool, uid)

            binary = root / "crictl-fixture"
            binary.write_bytes(b"fixed-test-cli-bytes")
            manifest = json.dumps(
                {
                    "config.json": {
                        "sha256": hashlib.sha256(b"{}\n").hexdigest(),
                        "bytes": 3,
                    }
                }
            ).encode()
            observer = runtime.Observer(
                root=root / "models",
                lifecycle_root=lifecycle_root,
                manifest=manifest,
                manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                image="image",
                crictl=binary,
                crictl_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                node="worker",
                boot=supervisor.node_boot,
                runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, b'{"images":[]}', b""),
            )
            server = ThreadingHTTPServer(("127.0.0.1", 0), observer.handler())
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            clock_rows = []
            rows = LiveRows("test", "collector", sink=clock_rows.append)
            producer = LifecycleReceiptProducer()
            rows.on_loss = producer.loss
            producer.created(uid, 0)
            node_http = HTTP(f"http://127.0.0.1:{server.server_port}", local_test=True)
            cache = NodeCacheAdapter(rows, node_http, "worker")
            cache.clock()
            time.sleep(0.01)
            supervisor.record("process_end", pid=7, returncode=1)
            supervisor.file.close()
            time.sleep(0.01)
            cache.clock()
            clocks = ClockMapper(clock_rows)
            node = NodeLifecycleAdapter(
                rows,
                HTTP("http://127.0.0.1:1", local_test=True),
                uid,
                0,
                producer,
                clocks=clocks,
                clock_id="node:worker",
                clock_boot=supervisor.node_boot,
                spool_http=node_http,
            )
            ended = node.poll()
            self.assertEqual([r["payload"]["event"] for r in ended], ["process_end"])
            self.assertIsNone(ended[0]["error"])
            self.assertTrue(producer.pods[uid]["blocked"])
            joined = SourceJoin([*clock_rows, *ended])
            self.assertFalse(joined.errors, joined.errors)
            end_bounds = next(
                row["time_ms_bounds"]
                for row in joined.rows
                if row["payload"]["event"] == "process_end"
            )
            with self.assertRaisesRegex(IntegrityError, "receipt_refused"):
                producer.receipt(
                    rows,
                    uid,
                    producer.pods[uid]["last_ns"],
                    time_bounds=end_bounds,
                )

    def test_cache_witness_real_http_files_and_collector(self):
        runtime = module("node_observer")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "crictl-fixture"
            binary.write_bytes(b"fixed-test-cli-bytes")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            expected = {"config.json": {"sha256": hashlib.sha256(b"{}\n").hexdigest(), "bytes": 3}}
            manifest = json.dumps(expected).encode()

            def images(*args, **kwargs):
                return subprocess.CompletedProcess(
                    args[0], 0, b'{"images":[{"repoDigests":["image@sha256:test"]}]}', b""
                )

            observer = runtime.Observer(
                root=root / "models",
                manifest=manifest,
                manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                image="image@sha256:test",
                crictl=binary,
                crictl_sha256=digest,
                node="node",
                boot="kernel",
                runner=images,
            )
            server = ThreadingHTTPServer(("127.0.0.1", 0), observer.handler())
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                rows_list = []
                rows = LiveRows("test", "collector", sink=rows_list.append)
                adapter = NodeCacheAdapter(
                    rows, HTTP(f"http://127.0.0.1:{server.server_port}", local_test=True), "node"
                )
                adapter.clock()
                witness = adapter.capture()
                self.assertEqual(witness["image_cache_state"], "node_cached")
                self.assertEqual(witness["model_cache_state"], "cold")
                time.sleep(0.01)
                adapter.clock()
                mapper = ClockMapper(rows_list.copy())
                time.sleep(0.01)
                now = time.monotonic_ns() // 1_000_000
                row = adapter.for_pod("uid", 0, creation_bounds=[now, now], clocks=mapper)
                self.assertIsNone(row["error"])
                self.assertFalse(SourceJoin(rows_list).errors)
                snapshot = root / "models" / runtime.MODEL_REPO / "snapshots" / runtime.REVISION
                snapshot.mkdir(parents=True)
                (snapshot / "config.json").write_bytes(b"{}\n")
                self.assertEqual(observer.snapshot()["model_cache_state"], "node_cached")
                (snapshot / "config.json").write_bytes(b"changed")
                self.assertIsNone(observer.snapshot()["model_cache_state"])
                (snapshot / "config.json").unlink()
                self.assertIsNone(observer.snapshot()["model_cache_state"])
                with self.assertRaises(ValueError):
                    runtime.Observer(
                        root=root,
                        manifest=manifest,
                        manifest_sha256="0" * 64,
                        image="image",
                        crictl=binary,
                        crictl_sha256=digest,
                        node="node",
                        boot="kernel",
                        runner=images,
                    )
                invalid_manifest = json.dumps(
                    {"config.json": {"sha256": "z" * 64, "bytes": 3}}
                ).encode()
                with self.assertRaises(ValueError):
                    runtime.Observer(
                        root=root,
                        manifest=invalid_manifest,
                        manifest_sha256=hashlib.sha256(invalid_manifest).hexdigest(),
                        image="image",
                        crictl=binary,
                        crictl_sha256=digest,
                        node="node",
                        boot="kernel",
                        runner=images,
                    )
            finally:
                server.shutdown()
                server.server_close()

    def test_shared_startup_lock_prevents_unseen_startup_heartbeat(self):
        runtime = module("capture_runtime")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            supervisor = runtime.Supervisor(root, "uid")
            child = """import sys,time,os
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import capture_runtime as rt
root=Path(sys.argv[2])
time.sleep(.05)
with rt.startup_guard(root):
 rt.durable(root/'metrics-pending.json',{'mono_ns':time.monotonic_ns(),'pid':os.getpid()})
begin=time.monotonic_ns()
time.sleep(.05)
rt.durable(root/'metrics-started.json',{'start_ns':begin,'end_ns':time.monotonic_ns(),'pid':os.getpid()})
time.sleep(.5)
"""
            self.assertEqual(
                supervisor.run(
                    [
                        getattr(sys, "_base_executable", sys.executable),
                        "-c",
                        child,
                        str(ROOT / "deploy/eks"),
                        str(root),
                    ],
                    port=0,
                ),
                0,
            )
            records = [
                json.loads(line) for line in (root / "lifecycle.jsonl").read_bytes().splitlines()
            ]
            self.assertEqual([r["sequence"] for r in records], list(range(len(records))))
            pending = next(r for r in records if r["event"] == "metrics_pending")
            self.assertTrue(any(r["event"] == "startup" for r in records))
            self.assertEqual(records[-1]["event"], "process_end")
            self.assertTrue(
                all(
                    r["mono_ns"] < pending["signal_data"]["mono_ns"]
                    for r in records
                    if r["event"] == "heartbeat" and r["sequence"] < pending["sequence"]
                )
            )

    @unittest.skipUnless(
        os.name == "posix", "POSIX SIGTERM/fsync reentrancy; production runtime is Linux"
    )
    def test_sigterm_during_record_flush_cannot_deadlock(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = """import os,sys,signal,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import capture_runtime as rt
root=Path(sys.argv[2]);s=rt.Supervisor(root,'uid')
class InterruptFlush:
 def __init__(self,f): self.f=f;self.armed=False
 def write(self,data): return self.f.write(data)
 def fileno(self): return self.f.fileno()
 def close(self): return self.f.close()
 def flush(self):
  self.f.flush()
  if self.armed:
   self.armed=False
   os.kill(os.getpid(),signal.SIGTERM)
f=InterruptFlush(s.file);s.file=f
s.run([sys.executable,'-c','import time;time.sleep(5)'],port=0,on_ready=lambda:setattr(f,'armed',True))
rows=[json.loads(line) for line in (root/'lifecycle.jsonl').read_bytes().splitlines()]
assert any(r['event']=='signal' for r in rows)
assert rows[-1]['event']=='process_end'
"""
            result = subprocess.run(
                [sys.executable, "-c", code, str(ROOT / "deploy/eks"), tmp],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
