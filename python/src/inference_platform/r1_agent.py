"""Small authenticated host agent for the later private four-host R1 topology."""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .process_metrics import process_snapshot
from .r1_launcher import backend_command, launch_gateways
from .r1_manifest import tenant_salt
from .r1_spec import FIXED, IMAGE, encoded
from .r1_transport import private_url, request


def redis_zcard(address, key, deadline):
    host, port = address.rsplit(":", 1)
    command = ["ZCARD", key]
    wire = f"*{len(command)}\r\n".encode() + b"".join(
        f"${len(value.encode())}\r\n".encode() + value.encode() + b"\r\n" for value in command
    )
    with socket.create_connection(
        (host, int(port)), timeout=max(0.001, deadline - time.perf_counter())
    ) as connection:
        connection.sendall(wire)
        with connection.makefile("rb") as file:
            reply = file.readline(1024)
        if not reply.startswith(b":"):
            raise ValueError("Redis observation failed")
        return int(reply[1:])


class Host:
    def __init__(self, config):
        self.config, self.role = config, config["role"]
        if self.role not in {"backend", "service", "generator"}:
            raise ValueError("unknown role")
        self.processes, self.receipts, self.namespace = [], [], None
        self.lock = threading.Lock()
        self.directory = Path(config["directory"]).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.prior_cpu, self.prior_nic, self.prior_time = None, None, None
        self.closing = False
        self.image_identity = None

    def identity(self, deadline):
        started = time.perf_counter()
        data = subprocess.check_output(
            ["docker", "inspect", self.config.get("container", "r1-vllm")],
            timeout=max(0.001, deadline - time.perf_counter()),
        )
        item = json.loads(data)[0]
        environment = dict(value.split("=", 1) for value in item["Config"]["Env"])
        command = backend_command(self.config["weight_cache"])
        expected = command[command.index(IMAGE) + 1 :]
        if (
            item["Config"]["Image"] != IMAGE
            or item["Config"]["Cmd"] != expected
            or environment.get("VLLM_SERVER_DEV_MODE") != "1"
            or not item["State"]["Running"]
        ):
            raise ValueError("actual backend launcher differs")
        image_cache_hit = self.image_identity is not None
        if self.image_identity is None:
            self.image_identity = json.loads(
                subprocess.check_output(
                    ["docker", "image", "inspect", IMAGE],
                    timeout=max(0.001, deadline - time.perf_counter()),
                )
            )[0]
        image = self.image_identity
        expected_environment = dict(value.split("=", 1) for value in image["Config"]["Env"])
        expected_environment["VLLM_SERVER_DEV_MODE"] = "1"
        if environment != expected_environment or item["Image"] != image["Id"]:
            raise ValueError("backend image/env differs from pinned launcher")
        return {
            "generation": hashlib.sha256(
                encoded([item["Id"], item["State"]["StartedAt"]])
            ).hexdigest(),
            "container_id": item["Id"],
            "started_at": item["State"]["StartedAt"],
            "fixed": FIXED,
            "VLLM_SERVER_DEV_MODE": "1",
            "launcher": command,
            "monotonic_s": time.perf_counter(),
            "wall_s": time.time(),
            "duration_s": time.perf_counter() - started,
            "image_inspect_cached": image_cache_hit,
        }

    def close(self):
        self.closing = True
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
        return {"admissions_closed": True}

    def state(self, deadline):
        active = 0
        for index, process in enumerate(self.processes):
            if process.poll() is None and not self.closing:
                _, data = request(f"http://127.0.0.1:{8080 + index}/metrics", deadline)
                match = re.search(r"^inference_gateway_active_requests (\d+)$", data.decode(), re.M)
                if match is None:
                    raise ValueError("missing gateway reservation metric")
                active += int(match[1])
        shared = (
            0
            if self.namespace is None
            else redis_zcard(
                self.config["redis"], self.namespace + ":{admission}:global:active", deadline
            )
        )
        return {
            "gateway_reservations": shared if self.closing else active,
            "coordinator_inflight": shared,
            "gateway_processes_draining": sum(p.poll() is None for p in self.processes)
            if self.closing
            else 0,
            "gateway_pids": [p.pid for p in self.processes if p.poll() is None],
        }

    def configure(self, value, deadline):
        started = time.perf_counter()
        if set(value) != {"N", "R", "W", "B", "policy", "seed"} or value["N"] != 2:
            raise ValueError("incompatible gateway inputs")
        state = self.state(deadline)
        if any(state[key] for key in ("gateway_reservations", "coordinator_inflight")):
            raise ValueError("configuration refused while work remains")
        self.close()
        for process in self.processes:
            process.wait(timeout=max(0.001, deadline - time.perf_counter()))
        inventory = []
        for index, (url, agent) in enumerate(
            zip(self.config["backends"], self.config["backend_agents"], strict=True)
        ):
            _, data = request(
                private_url(agent) + "/identity", deadline, token=self.config["token"]
            )
            identity = json.loads(data)
            if identity["fixed"] != FIXED:
                raise ValueError("backend configuration differs")
            inventory.append(
                {
                    "id": f"gpu-{index}",
                    "generation": identity["generation"],
                    "url": private_url(url),
                }
            )
        # Each B has its own registered configuration key; both gateways share it.
        # Reuse it across policies. Old B's reservations were checked before switching.
        self.namespace = self.config["namespace"] + f":B{value['B']}"
        secret = base64.urlsafe_b64decode(self.config["secret"] + "=")
        self.processes, receipts = launch_gateways(
            self.config["binary"],
            self.directory,
            inventory,
            self.config["redis"],
            self.namespace,
            self.config["credential"],
            secret,
            value["policy"],
            value["R"],
            value["W"],
            value["B"],
            value["seed"],
            deadline,
        )
        self.closing = False
        for index in range(2):
            while time.perf_counter() < deadline:
                try:
                    status, _ = request(f"http://127.0.0.1:{8080 + index}/readyz", deadline)
                    if status == 200:
                        break
                except OSError:
                    pass
                time.sleep(min(0.05, max(0, deadline - time.perf_counter())))
            else:
                raise TimeoutError("gateway ready deadline exhausted")
            with (self.directory / f"gateway-{index}.jsonl").open("rb") as log:
                log.seek(receipts[index]["log_start_offset"])
                startup_bytes = log.read(65536)
            starts = [json.loads(line) for line in startup_bytes.splitlines() if line.strip()]
            startup = next(
                (
                    row
                    for row in reversed(starts)
                    if row.get("msg") == "gateway started"
                    and row.get("pid") == self.processes[index].pid
                ),
                None,
            )
            if (
                startup is None
                or startup.get("routing_seed") != value["seed"]
                or startup.get("routing_policy")
                != receipts[index]["environment"]["GATEWAY_ROUTING_POLICY"]
                or startup["admission_configuration"]["global_capacity"] != value["B"]
            ):
                raise ValueError(
                    "actual gateway startup inputs differ; old binaries are incompatible"
                )
            receipts[index]["startup"] = startup
        result = {
            "configuration": value,
            "gateways": receipts,
            "cache_salt": tenant_salt(secret),
            "agent_duration_s": time.perf_counter() - started,
        }
        self.receipts.append(result)
        return result

    def resources(self, deadline):
        cpu = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
        nic = [
            int(Path(f"/sys/class/net/{self.config['nic']}/statistics/{name}").read_text())
            for name in ("rx_bytes", "tx_bytes")
        ]
        now = time.perf_counter()
        if self.prior_cpu is None:
            self.prior_cpu, self.prior_nic, self.prior_time = cpu, nic, now
            return self.resources_after_sample(deadline)
        total = sum(cpu) - sum(self.prior_cpu)
        idle = cpu[3] + cpu[4] - self.prior_cpu[3] - self.prior_cpu[4]
        budget = self.config["cpu_budget"]
        fraction = (total - idle) / total * os.cpu_count() / budget if total else 0
        rate = (
            max(a - b for a, b in zip(nic, self.prior_nic, strict=True))
            * 8
            / max(0.001, now - self.prior_time)
        )
        self.prior_cpu, self.prior_nic, self.prior_time = cpu, nic, now
        memory = int(re.search(r"MemTotal:\s+(\d+)", Path("/proc/meminfo").read_text())[1]) * 1024
        catalog_memory = self.config.get("catalog_memory_bytes", memory)
        if type(catalog_memory) is not int or catalog_memory <= 0:
            raise ValueError("invalid catalog memory capacity")
        if catalog_memory != memory and not self.config.get("memory_catalog_source"):
            raise ValueError("catalog memory capacity requires its actual host-shape source")
        tracking = subprocess.check_output(
            ["chronyc", "tracking"], text=True, timeout=max(0.001, deadline - time.perf_counter())
        )
        return {
            "cpu_budget": budget,
            "cpu_fraction": fraction,
            "memory_bytes": self.config.get("fixture_memory_bytes", catalog_memory),
            "memory_capacity_source": self.config.get("memory_catalog_source", "Linux MemTotal"),
            "observed_memory_bytes": memory,
            "observed_memory_available_bytes": int(
                re.search(r"MemAvailable:\s+(\d+)", Path("/proc/meminfo").read_text())[1]
            )
            * 1024,
            "processes": {
                str(pid): process_snapshot(pid)
                for pid in [
                    os.getpid(),
                    *(process.pid for process in self.processes),
                    *self.config.get("resource_pids", []),
                ]
            },
            "memory_fixture": "fixture_memory_bytes" in self.config,
            "nic_limit_bps": self.config["nic_limit_bps"],
            "nic_limit_source": self.config["nic_limit_source"],
            "nic_fraction": rate / self.config["nic_limit_bps"],
            "monotonic_s": now,
            "wall_s": time.time(),
            "clock_usable": bool(re.search(r"Leap status\s*:\s*Normal", tracking)),
            "clock_source": tracking,
            "role": self.role,
            "hostname": socket.gethostname(),
        }

    def resources_after_sample(self, deadline):
        time.sleep(min(0.05, max(0, deadline - time.perf_counter())))
        return self.resources(deadline)

    def handle(self, path, value, deadline):
        if path == "/identity" and self.role == "backend":
            return self.identity(deadline)
        if path == "/resources" and self.role in {"service", "generator"}:
            return self.resources(deadline)
        if self.role == "service":
            if path == "/export/link":
                if self.processes or self.namespace is not None or self.closing:
                    raise ValueError("physical export link must be set before calibration")
                core = {
                    k: v
                    for k, v in value.items()
                    if k not in {"measurement_sha256", "agent_config"}
                }
                if hashlib.sha256(encoded(core)).hexdigest() != value["measurement_sha256"]:
                    raise ValueError("physical export probe hash mismatch")
                floor = value["agent_config"]["export_minimum_bytes_per_second"]
                if type(floor) is not int or floor <= 0:
                    raise ValueError("invalid physical export floor")
                if floor != int(min(x["raw_bytes_per_second"] for x in value["samples"]) / 2):
                    raise ValueError(
                        "physical export floor differs from measured half-slowest rate"
                    )
                self.config.update(value["agent_config"])
                return {"physical_export_measurement_sha256": value["measurement_sha256"]}
            if path == "/export/probe":
                length = value["length"]
                if type(length) is not int or not 0 < length <= 1048576:
                    raise ValueError("invalid bounded export probe")
                # Same SHA/base64/JSON path and size as log chunks; no log state changes.
                content = bytes(range(256)) * (length // 256) + bytes(range(length % 256))
                return {
                    "offset": 0,
                    "size": length,
                    "bytes": length,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "base64": base64.b64encode(content).decode(),
                }
            if path == "/close":
                return self.close()
            if path == "/state":
                return self.state(deadline)
            if path == "/configure":
                return self.configure(value, deadline)
            if path == "/logs/manifest":
                if not self.closing:
                    raise ValueError("close admissions before freezing log export")
                for process in self.processes:
                    process.wait(timeout=max(0.001, deadline - time.perf_counter()))
                return {
                    "configurations": self.receipts,
                    "files": {
                        path.name: path.stat().st_size
                        for path in self.directory.glob("gateway-*.jsonl")
                    },
                    "minimum_bytes_per_second": self.config["export_minimum_bytes_per_second"],
                    "link_rate_source": self.config["export_link_rate_source"],
                }
            if path == "/logs/chunk":
                if not self.closing or value["name"] not in {"gateway-0.jsonl", "gateway-1.jsonl"}:
                    raise ValueError("invalid export file/state")
                offset, length = value["offset"], value["length"]
                if (
                    type(offset) is not int
                    or type(length) is not int
                    or offset < 0
                    or not 0 < length <= 1048576
                ):
                    raise ValueError("invalid bounded export chunk")
                file = self.directory / value["name"]
                with file.open("rb") as stream:
                    stream.seek(offset)
                    content = stream.read(length)
                return {
                    "offset": offset,
                    "size": file.stat().st_size,
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "base64": base64.b64encode(content).decode(),
                }
        raise ValueError("unsupported role/action")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--bind", required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_bytes())
    if "fixture_memory_bytes" in config:
        import ipaddress

        if not ipaddress.ip_address(args.bind.rsplit(":", 1)[0]).is_loopback:
            raise ValueError("simulated memory is restricted to loopback fixtures")
    if "replicas" in config:
        import ipaddress

        if not ipaddress.ip_address(args.bind.rsplit(":", 1)[0]).is_loopback:
            raise ValueError("multiplexed fixture agents require loopback")
        hosts = {prefix: Host(value) for prefix, value in config["replicas"].items()}
    else:
        hosts = {"": Host(config)}
    private_url("http://" + args.bind)

    class Handler(BaseHTTPRequestHandler):
        def dispatch(self):
            if not hmac.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + config["token"]
            ):
                self.send_error(403)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 65536:
                    raise ValueError("oversize control body")
                value = json.loads(self.rfile.read(length)) if length else None
                prefix = next(
                    (prefix for prefix in hosts if self.path.startswith(prefix + "/")), None
                )
                if prefix is None:
                    raise ValueError("unknown host prefix")
                host = hosts[prefix]
                deadline = time.perf_counter() + 4.5
                if not host.lock.acquire(timeout=4.5):
                    raise TimeoutError("agent lock deadline exhausted")
                try:
                    result = host.handle(self.path[len(prefix) :], value, deadline)
                finally:
                    host.lock.release()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(encoded(result))
            except (ValueError, OSError, TimeoutError, subprocess.SubprocessError) as exc:
                self.send_error(409, str(exc))

        do_GET = dispatch
        do_POST = dispatch

        def log_message(self, format, *args):
            pass

    address, port = args.bind.rsplit(":", 1)
    try:
        ThreadingHTTPServer((address, int(port)), Handler).serve_forever()
    finally:
        for host in hosts.values():
            host.close()


if __name__ == "__main__":
    main()
