"""Independent resource source, launched outside the measured cgroup.

Capacity documents are reviewed deployment inputs, not inferred observations.
The NIC document must pin a guaranteed baseline for the actual interface/boot.
Missing authority remains unresolved; neither link speed nor traffic supplies it.
"""

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from .eks_deployment import resource_agent_command
from .inf037b_archive import IntegrityError, sha, strict_json
from .inf037b_resolver import exact, require
from .inf037b_resources import ProcCounters, ResourceProducer, resource_handler

BOOT_ID = "/proc/sys/kernel/random/boot_id"


def file_identity(path):
    stat = Path(path).stat()
    return [stat.st_dev, stat.st_ino]


def pinned_json(reference, reason):
    require(type(reference) is dict and reference.get("path") and reference.get("sha256"), reason)
    try:
        raw = Path(reference["path"]).read_bytes()
        exact(sha(raw), reference["sha256"], reason + ":hash")
        return strict_json(raw)
    except IntegrityError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        raise IntegrityError(reason + ":unreadable") from exc


def cpu_capacity(target, root, millicores):
    """Cgroup v2: absent ancestor controllers impose no additional limit."""

    def optional(path):
        try:
            return path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return None

    def quota(value):
        amount, period = value.split()
        period = int(period)
        if period <= 0 or (amount != "max" and int(amount) <= 0):
            raise ValueError("invalid_cpu_max")
        return None if amount == "max" else int(amount) * 1000 // period

    try:
        leaf = optional(target / "cpu.max")
        require(leaf is not None, "resource:unresolved:cpu_capacity_authority")
        require(quota(leaf) is not None, "resource:unresolved:cpu_capacity_authority")
        current, cpuset = target, None
        while True:
            value = optional(current / "cpu.max")
            if value is not None:
                limit = quota(value)
                require(limit is None or limit >= millicores, "resource:cpu_capacity_changed")
            if cpuset is None:
                value = optional(current / "cpuset.cpus.effective")
                if value is not None:
                    cpuset = set()
                    for part in value.split(","):
                        span = [int(v) for v in part.split("-")]
                        if len(span) not in (1, 2) or span[0] < 0 or span[0] > span[-1]:
                            raise ValueError("invalid_cpuset")
                        cpuset.update(range(span[0], span[-1] + 1))
                    require(len(cpuset) * 1000 >= millicores, "resource:cpu_capacity_changed")
            if current == root:
                break
            current = current.parent
        require(cpuset is not None, "resource:unresolved:cpu_capacity_authority")
    except IntegrityError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        raise IntegrityError("resource:cgroup_unreadable") from exc


class PinnedCounters:
    """Revalidate the original paths, boot and capacity authority at every read."""

    def __init__(self, spec):
        self.spec = spec
        self.capacity = pinned_json(spec.get("capacity"), "resource:unresolved:capacity_authority")
        cap = self.capacity
        exact(cap["schema"], "inf037b-resource-capacity-v1", "resource:capacity_schema")
        for key in ("binding", "role", "generation", "boot_id"):
            exact(cap[key], spec[key], "resource:capacity_identity:" + key)
        self.budget = {
            "cpu_millicores": cap["cpu_millicores"],
            "nic_bytes_per_second": cap["nic_bytes_per_second"],
            "capacity_ref": spec["capacity"]["sha256"],
        }
        self.counters = ProcCounters(cap["cgroup"], cap["interface"], **self.budget)
        self.last = None
        self.verify()

    def verify(self):
        try:
            self._verify()
        except IntegrityError:
            raise
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise IntegrityError("resource:source_unreadable") from exc

    def _verify(self):
        cap, spec = self.capacity, self.spec
        exact(
            pinned_json(spec["capacity"], "resource:capacity_authority"),
            cap,
            "resource:capacity_changed",
        )
        boot = Path(spec.get("boot_id_path", BOOT_ID)).read_text(encoding="ascii").strip()
        exact(boot, spec["boot_id"], "resource:boot_changed")
        exact(
            cap["target_cgroup_relative"], spec["target_cgroup_relative"], "resource:target_cgroup"
        )
        exact(
            str(Path(cap["cgroup"]).resolve()),
            str((Path(cap["cgroup_root"]) / cap["target_cgroup_relative"].lstrip("/")).resolve()),
            "resource:cgroup_path",
        )
        for key in ("cgroup", "interface"):
            exact(file_identity(cap[key]), cap[key + "_identity"], "resource:" + key + "_changed")
        # Host-relative cgroup names are comparable only in the bound namespace.
        exact(
            file_identity(spec.get("cgroup_namespace_path", "/proc/self/ns/cgroup")),
            cap["cgroup_namespace_identity"],
            "resource:cgroup_namespace_changed",
        )
        root, target = Path(cap["cgroup_root"]).resolve(), Path(cap["cgroup"]).resolve()
        require(target.is_relative_to(root), "resource:cgroup_path")
        cpu_capacity(target, root, cap["cpu_millicores"])
        exact(
            int((Path(cap["interface"]) / "ifindex").read_text()),
            cap["ifindex"],
            "resource:interface_changed",
        )
        nic = pinned_json(cap.get("nic_authority"), "resource:unresolved:nic_capacity_authority")
        exact(nic["schema"], "inf037b-nic-capacity-v1", "resource:nic_schema")
        for key in ("binding", "boot_id", "interface_identity", "ifindex"):
            exact(nic[key], cap[key], "resource:nic_identity:" + key)
        exact(nic["basis"], "guaranteed_baseline", "resource:unresolved:nic_guaranteed_baseline")
        require(bool(nic["source_reference"]), "resource:unresolved:nic_capacity_authority")
        exact(nic["bytes_per_second"], cap["nic_bytes_per_second"], "resource:nic_capacity")
        own = Path(spec.get("emitter_cgroup_path", "/proc/self/cgroup")).read_text().strip()
        require(own.startswith("0::/"), "resource:emitter_cgroup_v2")
        target = spec["target_cgroup_relative"]
        require(target.startswith("/"), "resource:cgroup_path")
        require(
            own[3:] != target and not own[3:].startswith(target.rstrip("/") + "/"),
            "resource:emitter_not_independent",
        )

    def __call__(self):
        self.verify()
        try:
            result = self.counters()
        except IntegrityError:
            raise
        except (OSError, ValueError, KeyError) as exc:
            raise IntegrityError("resource:counters_unreadable") from exc
        require(
            self.last is None or all(result[k] >= self.last[k] for k in result),
            "resource:counter_regressed",
        )
        self.last = result
        return result


def producer_from_spec(spec):
    counters = PinnedCounters(spec)
    source = sha(Path(__file__).read_bytes().replace(b"\r\n", b"\n"))
    exact(source, spec["agent_sha256"], "resource:agent_source")
    producer = ResourceProducer(
        role=spec["role"],
        binding=spec["binding"],
        generation=spec["generation"],
        boot=spec["boot_id"],
        counters=counters,
        budget=counters.budget,
    )
    expected = sha(
        Path(sys.modules[ResourceProducer.__module__].__file__).read_bytes().replace(b"\r\n", b"\n")
    )
    exact(expected, spec["source_sha256"], "resource:producer_source")
    cap = counters.capacity
    producer.provenance = {
        "capacity_sha256": spec["capacity"]["sha256"],
        "agent_sha256": source,
        **{k: cap[k] for k in ("cgroup_identity", "interface_identity", "ifindex")},
    }
    return producer


class ResourceProcess:
    """Launch the same committed entry point used by the deployment command."""

    def __init__(self, spec_path, *, python=None, address=("127.0.0.1", 0), timeout=5):
        # Windows venv redirectors spawn another PID. Use the actual interpreter
        # for this stdlib-only source and explicitly supply its pinned package.
        python = python or (sys._base_executable if os.name == "nt" else sys.executable)
        self.argv = resource_agent_command(
            python=python, spec_path=spec_path, host=address[0], port=address[1]
        )
        self.timeout, self.process = timeout, None

    def start(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = (
            str(Path(__file__).resolve().parents[1]) + os.pathsep + env.get("PYTHONPATH", "")
        )
        self.process = subprocess.Popen(
            self.argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
        ready = queue.Queue()
        threading.Thread(
            target=lambda: ready.put(self.process.stdout.readline()), daemon=True
        ).start()
        try:
            raw = ready.get(timeout=self.timeout)
            require(bool(raw), "resource:agent_start_failed")
            self.receipt = strict_json(raw)
            exact(self.receipt["pid"], self.process.pid, "resource:agent_pid")
            require(self.receipt["pid"] != os.getpid(), "resource:agent_not_independent")
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=self.timeout)
            self.process.stdout.close()
            self.process.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    spec = strict_json(args.spec.read_bytes())
    producer = producer_from_spec(spec)
    token_path = Path(spec["token_path"])
    require(bool(token_path.read_text().strip()), "resource:token")
    with ThreadingHTTPServer(
        (args.host, args.port), resource_handler(producer, lambda: token_path.read_text().strip())
    ) as server:
        print(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "address": list(server.server_address),
                    "role": producer.role,
                    "boot_id": producer.boot,
                    "generation": producer.generation,
                    "budget": producer.budget,
                    "source_sha256": spec["source_sha256"],
                    "agent_sha256": spec["agent_sha256"],
                }
            ),
            flush=True,
        )
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
