"""Real Operator + real bootstrap/spool, with a delayed, lossy, rate-limited TCP forward.

Host GPU/Session work is a fixture; HTTP control, action subprocesses, sealed
archives, channel retries, offsets, chunk hashes and reconstruction are real.
"""

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

from inference_platform.r1_cloud_operator import Operator, file_sha
from inference_platform.r1_spec import encoded
from inference_platform.session_stop import stop_forward

ROOT = Path(__file__).resolve().parents[1]


def large_json(path, random_bytes):
    # Incompressible base64 JSON: gzip output remains >= random_bytes.
    with path.open("wb") as out:
        out.write(b'{"fixture":"')
        for _ in range(random_bytes // (1024 * 1024)):
            out.write(base64.b64encode(os.urandom(1024 * 1024)))
        out.write(b'"}\n')


def host_action(action, directory, quick=False):
    if action == "measure":
        (directory / "session").mkdir(exist_ok=True)
        large_json(directory / "session/run1-measure.json", (8 if quick else 310) * 1024**2)
        # Earlier sealed slot transfers while a later comparison is still active.
        time.sleep(30 if quick else 700)
        large_json(directory / "session/run2-measure.json", (8 if quick else 45) * 1024**2)
        (directory / "session/result.json").write_bytes(encoded({"fixture": True, "complete": True}))
        (directory / "measure-terminal.json").write_bytes(encoded({"ended_unix_s": time.time()}))
    elif action == "close":
        running = not (directory / "measure-terminal.json").exists()
        (directory / "close-observed.json").write_bytes(encoded({"running": running}))
        if running:
            raise RuntimeError("close while host Session running")


def bootstrap(port, directory, bundle_hash, quick=False):
    spec = importlib.util.spec_from_file_location("bootstrap", ROOT / "scripts/r1-host-bootstrap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = subprocess.Popen

    def fixture_popen(argv, **kwargs):
        if "inference_platform.r1_cloud_host" in argv:
            action = argv[argv.index("--action") + 1]
            return original([sys.executable, __file__, "--host-action", action,
                             "--directory", str(directory), *(["--quick"] if quick else [])], **kwargs)
        return original(argv, **kwargs)

    module.subprocess.Popen = fixture_popen
    sys.argv = ["bootstrap", "--token", "fixture-control", "--bundle-sha256", bundle_hash,
                "--deadline-unix-s", str(time.time() + 1500), "--port", str(port),
                "--directory", str(directory)]
    module.main()


def relay(port, upstream, delay, counter):
    time.sleep(delay)
    lock = threading.Lock()
    total = [0]
    last = [0]

    def pipe(source, target, throttle):
        try:
            while True:
                data = source.recv(8192)
                if not data:
                    break
                if throttle:
                    time.sleep(len(data) / 500_000)
                target.sendall(data)
                if throttle:
                    with lock:
                        total[0] += len(data)
                        if total[0] - last[0] >= 1024**2:
                            counter.write_text(str(total[0]), encoding="ascii")
                            last[0] = total[0]
        except OSError:
            pass
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def connection(client):
        with client, socket.create_connection(("127.0.0.1", upstream)) as server:
            thread = threading.Thread(target=pipe, args=(client, server, False))
            thread.start()
            pipe(server, client, True)
            thread.join()

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
        listener.listen()
        while True:
            client, _ = listener.accept()
            threading.Thread(target=connection, args=(client,), daemon=True).start()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(output, quick=False):
    output.mkdir(parents=True, exist_ok=False)
    files = {}
    for path in (ROOT / "python/src/inference_platform").glob("*.py"):
        files["python/src/inference_platform/" + path.name] = path.read_bytes()
    files.update({"bin/uv": b"fixture-uv", "bin/gateway": b"fixture-gateway"})
    files["payload.json"] = encoded({"files": {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}})
    with (output / "bundle.tar.gz").open("wb") as stream, tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    bundle_hash = file_sha(output / "bundle.tar.gz")
    upstream = free_port()
    directory = output / "host"
    with (output / "bootstrap.log").open("wb") as log:
        host = subprocess.Popen([sys.executable, __file__, "--bootstrap", str(upstream),
                                 "--directory", str(directory), "--bundle-hash", bundle_hash,
                                 *(["--quick"] if quick else [])],
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    stage, helpers, kills = ["ready"], [], []
    inputs = {"bundle_path": str((output / "bundle.tar.gz").resolve()), "bundle_sha256": bundle_hash}
    operator = Operator(ROOT, inputs, output / "operator", time.time() + 100)
    binding = {"hosts": {"generator": {"id": "fixture-generator"}}, "control_token": "fixture-control"}

    def tunnel(_):
        port = free_port()
        counter = output / f"relay-{len(helpers)}.bytes"
        with (output / "relay.log").open("ab") as log:
            child = subprocess.Popen([sys.executable, __file__, "--relay", str(port),
                                      "--upstream", str(upstream), "--delay", "5.0",
                                      "--counter", str(counter)], stdout=log, stderr=subprocess.STDOUT,
                                     start_new_session=True)
        helpers.append((child, counter, stage[0], time.time()))
        return port, child

    operator.tunnel = tunnel  # Only SSM transport substituted; real RPC/retry code.
    stop = threading.Event()

    def fault():
        while not stop.wait(0.2):
            if not helpers:
                continue
            child, counter, phase, started = helpers[-1]
            if child.poll() is not None:
                continue
            count = int(counter.read_text() or "0") if counter.exists() else 0
            if phase == "measure" and "measure" not in kills and count > 5 * 1024**2:
                stop_forward(child)
                kills.append("measure")
            if phase == "export" and "export" not in kills and count > 5 * 1024**2:
                stop_forward(child)
                kills.append("export")

    worker = threading.Thread(target=fault, daemon=True)
    worker.start()
    try:
        operator.with_host("generator", "ready", binding)
        operator.context_path.write_bytes(encoded(binding))
        stage[0] = "measure"
        operator.deadline = time.time() + 1000
        measure_start = time.time()
        operator.with_host("generator", "measure")
        measure_elapsed = time.time() - measure_start
        stage[0] = "close"
        operator.deadline = time.time() + 30
        operator.with_host("generator", "close")
        stage[0] = "export"
        operator.deadline = time.time() + 600
        export_start = time.time()
        operator.with_host("generator", "export")
        export_elapsed = time.time() - export_start
        index = json.loads((directory / "incremental-index.json").read_bytes())
        archives = [{**item, "retrieved_sha256": file_sha(output / "operator/generator-segments" / item["name"])}
                    for item in index["segments"]]
        sources = {path.name: file_sha(path) for path in (directory / "session").iterdir()}
        retrieved = {path.name: file_sha(path) for path in (output / "operator/generator/session").iterdir()}
        channels = {}
        for action in ("measure", "export"):
            rows = [json.loads(line) for line in (output / f"operator/generator-{action}-channel.jsonl").read_bytes().splitlines()]
            channels[action] = {"reconnects": max(x["reconnects"] for x in rows),
                                "retrievals": [x for x in rows if x["event"] == "retrieved"]}
        receipt = {"fixture": True, "entrypoint": "Operator.with_host + real r1-host-bootstrap + Spool",
                   "aws_calls": 0, "quick_fixture": quick, "bind_delay_s": 5.0, "rate_limit_bps": 500_000,
                   "kills": kills, "measure_elapsed_s": measure_elapsed,
                   "export_elapsed_s": export_elapsed, "export_window_s": 600,
                   "archives": archives, "channels": channels, "source_files": sources,
                   "retrieved_files": retrieved, "byte_identical": sources == retrieved,
                   "close": json.loads((directory / "close-observed.json").read_bytes()),
                   "full_size_archive_bytes": max(x["bytes"] for x in archives),
                   "remaining_export_bytes": sum(x["bytes"] for x in channels["export"]["retrievals"]),
                   "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                   "source_sha256": {p: file_sha(ROOT / p) for p in ["scripts/r1-host-bootstrap.py",
                       "python/src/inference_platform/r1_cloud_operator.py", "python/src/inference_platform/r1_evidence.py"]}}
        if not quick:
            assert receipt["full_size_archive_bytes"] >= 300_000_000
        assert kills == ["measure", "export"] and sources == retrieved
        assert all(x["sha256"] == x["retrieved_sha256"] for x in archives)
        assert export_elapsed < 600 and not receipt["close"]["running"]
        (output / "receipt.json").write_bytes(encoded(receipt) + b"\n")
        print(json.dumps({k: receipt[k] for k in ["measure_elapsed_s", "export_elapsed_s", "full_size_archive_bytes", "remaining_export_bytes", "byte_identical", "close"]}))
    finally:
        stop.set()
        worker.join(timeout=2)
        for child, *_ in helpers:
            stop_forward(child)
        stop_forward(host)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--bootstrap", type=int)
    parser.add_argument("--bundle-hash")
    parser.add_argument("--host-action")
    parser.add_argument("--relay", type=int)
    parser.add_argument("--upstream", type=int)
    parser.add_argument("--delay", type=float)
    parser.add_argument("--counter", type=Path)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    if args.host_action:
        host_action(args.host_action, args.directory, args.quick)
    elif args.bootstrap:
        bootstrap(args.bootstrap, args.directory, args.bundle_hash, args.quick)
    elif args.relay:
        relay(args.relay, args.upstream, args.delay, args.counter)
    else:
        run(args.output.resolve(), args.quick)


if __name__ == "__main__":
    main()
