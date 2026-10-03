import hashlib
import http.client
import json
import os
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from inference_platform.fake_backend import FailureMode, FakeBackend, FakeBackendConfig

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _redis_command(sock: socket.socket, reader, *arguments: str) -> object:
    encoded = [argument.encode() for argument in arguments]
    payload = [f"*{len(encoded)}\r\n".encode()]
    for argument in encoded:
        payload.extend([f"${len(argument)}\r\n".encode(), argument, b"\r\n"])
    sock.sendall(b"".join(payload))
    prefix = reader.read(1)
    if prefix == b"*":
        count = int(reader.readline().rstrip(b"\r\n"))
        return [_redis_read_response(reader) for _ in range(count)]
    return _redis_read_response(reader, prefix)


def _redis_read_response(reader, prefix: bytes | None = None) -> object:
    prefix = prefix or reader.read(1)
    if prefix == b"$":
        length = int(reader.readline().rstrip(b"\r\n"))
        if length < 0:
            return None
        value = reader.read(length)
        reader.read(2)
        return value.decode()
    if prefix == b":":
        return int(reader.readline().rstrip(b"\r\n"))
    if prefix == b"+":
        return reader.readline().rstrip(b"\r\n").decode()
    if prefix == b"-":
        raise RuntimeError(reader.readline().rstrip(b"\r\n").decode())
    if prefix == b"*":
        count = int(reader.readline().rstrip(b"\r\n"))
        return [_redis_read_response(reader) for _ in range(count)]
    raise RuntimeError(f"unexpected Redis response prefix: {prefix!r}")


def _cleanup_redis_namespace(address: str, namespace: str) -> None:
    host, raw_port = address.rsplit(":", 1)
    connection = socket.create_connection((host, int(raw_port)), timeout=2)
    reader = connection.makefile("rb")
    try:
        cursor = "0"
        keys: list[str] = []
        while True:
            result = _redis_command(
                connection, reader, "SCAN", cursor, "MATCH", f"{namespace}:*", "COUNT", "100"
            )
            cursor, batch = result
            keys.extend(batch)
            if cursor == "0":
                break
        if keys:
            _redis_command(connection, reader, "DEL", *keys)
    finally:
        reader.close()
        connection.close()


class _RedisProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, upstream: tuple[str, int]) -> None:
        self.upstream = upstream
        self.enabled = True
        self.connection_lock = threading.Lock()
        self.connections: set[socket.socket] = set()
        super().__init__(("127.0.0.1", 0), _RedisProxyHandler)

    def track(self, *connections: socket.socket) -> None:
        with self.connection_lock:
            if not self.enabled:
                raise ConnectionError("proxy disabled")
            self.connections.update(connections)

    def untrack(self, *connections: socket.socket) -> None:
        with self.connection_lock:
            self.connections.difference_update(connections)

    def set_enabled(self, enabled: bool) -> None:
        with self.connection_lock:
            self.enabled = enabled
            connections = list(self.connections) if not enabled else []
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()


class _RedisProxyHandler(socketserver.BaseRequestHandler):
    server: _RedisProxyServer

    def handle(self) -> None:
        upstream = None
        try:
            upstream = socket.create_connection(self.server.upstream, timeout=1)
            self.server.track(self.request, upstream)
        except (ConnectionError, OSError):
            if upstream is not None:
                upstream.close()
            return
        try:
            sockets = [self.request, upstream]
            while True:
                readable, _, _ = select.select(sockets, [], [], 0.1)
                for source in readable:
                    destination = upstream if source is self.request else self.request
                    payload = source.recv(65_536)
                    if not payload:
                        return
                    destination.sendall(payload)
        except OSError:
            return
        finally:
            self.server.untrack(self.request, upstream)
            upstream.close()


class RedisFaultProxy:
    def __init__(self, address: str) -> None:
        host, raw_port = address.rsplit(":", 1)
        self.server = _RedisProxyServer((host, int(raw_port)))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def address(self) -> str:
        host, port = self.server.server_address
        return f"{host}:{port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.server.set_enabled(False)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class GatewayProcess:
    def __init__(
        self,
        test: unittest.TestCase,
        executable: Path,
        backend: FakeBackend,
        tenant_config: Path,
        redis_address: str,
        namespace: str,
        global_capacity: int,
    ) -> None:
        self.test = test
        self.port = _free_port()
        environment = os.environ.copy()
        environment.update(
            {
                "GATEWAY_HTTP_ADDR": f"127.0.0.1:{self.port}",
                "BACKENDS": f"{backend.config.backend_id}={backend.base_url}",
                "TENANT_CONFIG_PATH": str(tenant_config),
                "CACHE_SALT_SECRET_FILE": str(
                    REPOSITORY_ROOT / "deploy/local/cache-salt.secret.example"
                ),
                "ADMISSION_MODE": "redis",
                "REDIS_ADDR": redis_address,
                "ADMISSION_NAMESPACE": namespace,
                "ADMISSION_GLOBAL_CAPACITY": str(global_capacity),
                "ADMISSION_LEASE": "2500ms",
                "ADMISSION_TOMBSTONE_TTL": "3s",
                "GATEWAY_FIRST_ITEM_TIMEOUT": "1s",
                "GATEWAY_TOTAL_TIMEOUT": "2s",
                "GATEWAY_ADMISSION_TIMEOUT": "150ms",
                "GATEWAY_RELEASE_TIMEOUT": "100ms",
                "GATEWAY_SHUTDOWN_GRACE": "200ms",
                "GATEWAY_SHUTDOWN_HARD_STOP": "200ms",
            }
        )
        self.log_file = tempfile.TemporaryFile()
        self.process = subprocess.Popen(
            [str(executable)],
            cwd=REPOSITORY_ROOT,
            env=environment,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )
        self.output = ""
        self._wait_ready()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _wait_ready(self) -> None:
        # INF-013 adds tracing, cache-salt loading, and a metrics collector to
        # startup. Keep the bound finite but leave room for two gateways under
        # normal host contention, and include their output on every timeout.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self._collect_output()
                self.test.fail(f"gateway exited during startup: {self.output}")
            try:
                with urllib.request.urlopen(f"{self.url}/readyz", timeout=0.2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.02)
        # Stop a hung child before failing so a readiness timeout cannot leak a
        # gateway process into the next test or mask the original failure.
        self.stop()
        self.test.fail(f"gateway did not become ready within 10s: {self.output}")

    def _collect_output(self) -> None:
        if not self.log_file.closed:
            self.log_file.flush()
            self.log_file.seek(0)
            self.output = self.log_file.read().decode(errors="replace")
            self.log_file.close()

    def stop(self, *, kill: bool = False) -> None:
        if self.process.poll() is None:
            self.process.kill() if kill else self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self._collect_output()

    def terminal_logs(self) -> list[dict[str, object]]:
        records = []
        for line in self.output.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("msg") == "request terminal":
                records.append(record)
        return records


class AdmissionProcessIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.redis_address = os.environ.get("REDIS_TEST_ADDR")
        if not cls.redis_address:
            raise unittest.SkipTest("REDIS_TEST_ADDR is required for process admission tests")
        cls.temporary_directory = tempfile.TemporaryDirectory()
        temporary_path = Path(cls.temporary_directory.name)
        executable_name = "gateway.exe" if os.name == "nt" else "gateway"
        cls.gateway_executable = temporary_path / executable_name
        environment = os.environ.copy()
        environment.update(
            {
                "GOCACHE": str(REPOSITORY_ROOT / ".cache/go-build"),
                "GOMODCACHE": str(REPOSITORY_ROOT / ".cache/go-mod"),
                "GOTOOLCHAIN": "local",
            }
        )
        subprocess.run(
            ["go", "build", "-o", str(cls.gateway_executable), "./cmd/gateway"],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=True,
            capture_output=True,
        )
        cls.tenant_config = temporary_path / "tenants.json"
        cls.tenant_config.write_text(
            json.dumps(
                {
                    "tenants": [
                        cls._tenant("tenant-noisy", "token-noisy", rate=4, concurrent=2),
                        cls._tenant("tenant-quiet", "token-quiet", rate=20, concurrent=2),
                    ]
                }
            ),
            encoding="utf-8",
        )
        cls.soak_tenant_config = temporary_path / "soak-tenants.json"
        cls.soak_tenant_config.write_text(
            json.dumps(
                {
                    "tenants": [
                        cls._tenant("tenant-noisy", "token-noisy", rate=200, concurrent=4),
                        cls._tenant("tenant-quiet", "token-quiet", rate=200, concurrent=4),
                    ]
                }
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _tenant(
        tenant_id: str, credential: str, *, rate: int, concurrent: int
    ) -> dict[str, object]:
        return {
            "tenant_id": tenant_id,
            "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
            "models": ["test-model"],
            "max_request_bytes": 1_048_576,
            "max_output_tokens": 64,
            "request_rate_limit": rate,
            "request_rate_window_ms": 10_000,
            "max_concurrent": concurrent,
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary_directory.cleanup()

    def _namespace(self) -> str:
        return f"test:process:{os.getpid()}:{time.time_ns()}"

    @contextmanager
    def _gateways(
        self,
        backend: FakeBackend,
        *,
        capacity: int,
        redis_address: str | None = None,
        tenant_config: Path | None = None,
    ):
        namespace = self._namespace()
        processes = []
        try:
            for _ in range(2):
                processes.append(
                    GatewayProcess(
                        self,
                        self.gateway_executable,
                        backend,
                        tenant_config or self.tenant_config,
                        redis_address or self.redis_address,
                        namespace,
                        capacity,
                    )
                )
            yield processes
        finally:
            for process in processes:
                process.stop()
            _cleanup_redis_namespace(self.redis_address, namespace)

    @staticmethod
    def _payload() -> bytes:
        return json.dumps(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            }
        ).encode()

    def _request(
        self, gateway: GatewayProcess, credential: str, client_request_id: str = "repeat"
    ) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(
            f"{gateway.url}/v1/chat/completions",
            data=self._payload(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {credential}",
                "X-Request-ID": client_request_id,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                return response.status, dict(response.headers.items()), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers.items()), error.read()

    def _open_stream(
        self, gateway: GatewayProcess, credential: str
    ) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse, str]:
        connection = http.client.HTTPConnection("127.0.0.1", gateway.port, timeout=3)
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=self._payload(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {credential}",
                "X-Request-ID": "repeat",
            },
        )
        response = connection.getresponse()
        request_id = response.getheader("X-Request-ID")
        self.assertEqual(response.status, 200)
        self.assertIsNotNone(request_id)
        self.assertTrue(response.readline().startswith(b"data: "))
        return connection, response, str(request_id)

    @staticmethod
    def _metrics(gateway: GatewayProcess) -> dict[str, float]:
        with urllib.request.urlopen(f"{gateway.url}/metrics", timeout=1) as response:
            lines = response.read().decode().splitlines()
        metrics: dict[str, float] = {}
        for line in lines:
            if not line or line.startswith("#"):
                continue
            name, raw_value = line.rsplit(" ", 1)
            metrics[name] = float(raw_value)
        return metrics

    def _wait_inactive(self, gateways: list[GatewayProcess]) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if all(
                self._metrics(gateway)["inference_gateway_active_requests"] == 0
                for gateway in gateways
            ):
                return
            time.sleep(0.02)
        self.fail("gateway requests did not reconcile to zero active work")

    def test_two_gateways_isolate_noisy_tenant_and_reconcile_terminals(self) -> None:
        config = FakeBackendConfig(
            failure_mode=FailureMode.STALL_AFTER_CHUNKS,
            failure_after_chunks=0,
            stall_timeout_ms=5_000,
        )
        with FakeBackend(config) as backend:
            with self._gateways(backend, capacity=3) as gateways:
                first = self._open_stream(gateways[0], "token-noisy")
                second = self._open_stream(gateways[1], "token-noisy")
                noisy_denial = self._request(gateways[0], "token-noisy")
                quiet = self._open_stream(gateways[1], "token-quiet")
                global_denial = self._request(gateways[0], "token-quiet")

                self.assertEqual(noisy_denial[0], 429)
                self.assertIn(b"tenant_concurrency_limit", noisy_denial[2])
                self.assertEqual(global_denial[0], 429)
                self.assertIn(b"system_capacity", global_denial[2])
                server_ids = {
                    first[2],
                    second[2],
                    quiet[2],
                    noisy_denial[1]["X-Request-Id"],
                    global_denial[1]["X-Request-Id"],
                }
                self.assertEqual(len(server_ids), 5)
                for connection, response, _ in (first, second, quiet):
                    response.close()
                    connection.close()
                self._wait_inactive(gateways)
                snapshots = [self._metrics(gateway) for gateway in gateways]

            terminal_logs = [record for gateway in gateways for record in gateway.terminal_logs()]

        self.assertEqual(
            sum(item["inference_gateway_tenant_concurrency_limited_total"] for item in snapshots),
            1,
        )
        self.assertEqual(
            sum(item["inference_gateway_system_capacity_limited_total"] for item in snapshots),
            1,
        )
        self.assertEqual(len(terminal_logs), 5)
        self.assertEqual(len({item["request_id"] for item in terminal_logs}), 5)
        self.assertEqual(len({item["reservation_id"] for item in terminal_logs}), 5)
        self.assertEqual(
            sum(
                value
                for snapshot in snapshots
                for name, value in snapshot.items()
                if name.startswith("inference_gateway_terminal_total{")
            ),
            len(terminal_logs),
        )

    def test_rate_limit_is_shared_without_consuming_other_tenant_allowance(self) -> None:
        with FakeBackend(FakeBackendConfig()) as backend:
            with self._gateways(backend, capacity=4) as gateways:
                results = [self._request(gateways[index % 2], "token-noisy") for index in range(5)]
                quiet = self._request(gateways[1], "token-quiet")
                snapshots = [self._metrics(gateway) for gateway in gateways]

        self.assertEqual([result[0] for result in results], [200, 200, 200, 200, 429])
        self.assertIn(b"tenant_rate_limit", results[-1][2])
        self.assertEqual(quiet[0], 200)
        self.assertEqual(
            sum(item["inference_gateway_tenant_rate_limited_total"] for item in snapshots), 1
        )
        self.assertEqual(len({result[1]["X-Request-Id"] for result in [*results, quiet]}), 6)

    def test_coordinator_partition_fails_closed_then_recovers(self) -> None:
        with (
            RedisFaultProxy(self.redis_address) as proxy,
            FakeBackend(FakeBackendConfig()) as backend,
        ):
            with self._gateways(backend, capacity=2, redis_address=proxy.address) as gateways:
                proxy.server.set_enabled(False)
                unavailable = self._request(gateways[0], "token-quiet")
                self.assertEqual(unavailable[0], 503)
                self.assertIn(b"admission_unavailable", unavailable[2])
                self.assertNotIn("X-Inference-Backend", unavailable[1])
                proxy.server.set_enabled(True)
                deadline = time.monotonic() + 3
                while True:
                    recovered = self._request(gateways[1], "token-quiet")
                    if recovered[0] == 200 or time.monotonic() >= deadline:
                        break
                    self.assertEqual(recovered[0], 503)
                    time.sleep(0.05)
                self.assertEqual(recovered[0], 200)
                snapshots = [self._metrics(gateway) for gateway in gateways]

        self.assertGreaterEqual(
            sum(item["inference_gateway_admission_unavailable_total"] for item in snapshots),
            1,
        )

    def test_gateway_crash_recovers_capacity_only_after_lease_expiry(self) -> None:
        config = FakeBackendConfig(
            failure_mode=FailureMode.STALL_AFTER_CHUNKS,
            failure_after_chunks=0,
            stall_timeout_ms=8_000,
        )
        with FakeBackend(config) as backend:
            with self._gateways(backend, capacity=1) as gateways:
                connection, response, request_id = self._open_stream(gateways[0], "token-quiet")
                gateways[0].stop(kill=True)
                response.close()
                connection.close()
                observation = backend.wait_for_terminal(request_id, timeout=2)
                self.assertEqual(observation.terminal, "client_cancelled")
                blocked = self._request(gateways[1], "token-noisy")
                self.assertEqual(blocked[0], 429)
                self.assertIn(b"system_capacity", blocked[2])
                time.sleep(2.7)
                recovered_connection, recovered_response, _ = self._open_stream(
                    gateways[1], "token-noisy"
                )
                recovered_response.close()
                recovered_connection.close()
                self._wait_inactive([gateways[1]])

    def test_bounded_two_gateway_soak_reconciles_every_request(self) -> None:
        config = FakeBackendConfig(first_item_delay_ms=20, chunk_delay_ms=20)
        with FakeBackend(config) as backend:
            with self._gateways(
                backend,
                capacity=6,
                tenant_config=self.soak_tenant_config,
            ) as gateways:
                with ThreadPoolExecutor(max_workers=12) as executor:
                    futures = [
                        executor.submit(
                            self._request,
                            gateways[index % 2],
                            "token-noisy" if index % 3 else "token-quiet",
                            "repeated-soak-id",
                        )
                        for index in range(80)
                    ]
                    results = [future.result(timeout=10) for future in futures]
                self._wait_inactive(gateways)
                snapshots = [self._metrics(gateway) for gateway in gateways]

            terminal_logs = [record for gateway in gateways for record in gateway.terminal_logs()]

        statuses = [result[0] for result in results]
        accepted = statuses.count(200)
        rejected = statuses.count(429)
        self.assertEqual(accepted + rejected, 80)
        self.assertGreater(accepted, 0)
        self.assertGreater(rejected, 0)
        self.assertTrue(
            all(
                status == 200 or b"tenant_concurrency_limit" in body or b"system_capacity" in body
                for status, _, body in results
            )
        )
        self.assertEqual(
            sum(item["inference_gateway_completed_total"] for item in snapshots), accepted
        )
        self.assertEqual(
            sum(item["inference_gateway_rejected_total"] for item in snapshots), rejected
        )
        self.assertEqual(
            sum(item["inference_gateway_release_failures_total"] for item in snapshots), 0
        )
        self.assertEqual(len(terminal_logs), 80)
        self.assertEqual(len({item["request_id"] for item in terminal_logs}), 80)
        self.assertEqual(len({item["reservation_id"] for item in terminal_logs}), 80)


if __name__ == "__main__":
    unittest.main()
