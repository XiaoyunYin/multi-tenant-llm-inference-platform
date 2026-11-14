"""Step 5 three-attempt sanitized export sizing; no AWS and no paid allowance."""

import argparse
import ctypes
import gc
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from fractions import Fraction
from importlib.abc import MetaPathFinder
from importlib.machinery import PathFinder
from pathlib import Path

MANIFEST_SCHEMA = "inf037b-sizing-source-manifest-v1"
PINNED_HARNESS_FILES = (
    "scripts/size_inf037b_sanitized_export.py",
    "scripts/time_inf037b_three_attempts.py",
)
RESERVE_BYTES = 2 * 1024**3
HOST_GATE_SAMPLE_AGE_SECONDS = 300
HOST_GATE_CLOCK_SKEW_TOLERANCE_SECONDS = 30
HOST_GATE_MAX_SAMPLE_AGE_SECONDS = (
    HOST_GATE_SAMPLE_AGE_SECONDS + HOST_GATE_CLOCK_SKEW_TOLERANCE_SECONDS
)


def default_work_path(repo, *, platform=None):
    """Keep large Windows sizing fixtures on the repository's D: cache."""
    platform = platform or sys.platform
    return (
        Path(repo) / ".cache"
        if platform.startswith("win")
        else Path(tempfile.gettempdir())
    )


class SourceBindingError(RuntimeError):
    """Raised when source bytes are not bound to the host-created manifest."""


class InfeasibleOnHost(RuntimeError):
    """Raised when a container limit cannot fit in host or Docker VM memory."""

    status = "infeasible_on_host"


class HostGateFailed(RuntimeError):
    """Raised when currently available host memory is below the plan gate."""

    status = "host_gate_failed"


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def git_output(repo, *args):
    env = os.environ.copy()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise SourceBindingError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def head_commit(repo):
    return git_output(repo, "rev-parse", "HEAD").decode("ascii").strip()


def porcelain_bytes(repo):
    return git_output(
        repo,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )


def repo_relative_path(repo, source_path):
    repo = Path(repo).resolve()
    source_path = Path(source_path).resolve()
    try:
        return source_path.relative_to(repo).as_posix()
    except ValueError as exc:
        raise SourceBindingError(
            f"pinned source is outside the repository: {source_path}"
        ) from exc


def repo_module_path(repo, source_path):
    """Return a repo-relative module source, excluding only python/.venv/."""
    if not source_path:
        return None
    source_path = Path(source_path).resolve()
    try:
        relative = source_path.relative_to(Path(repo).resolve())
    except ValueError:
        return None
    if relative.parts[:2] == ("python", ".venv"):
        return None
    if source_path.suffix != ".py":
        raise SourceBindingError(
            f"cannot pin repo module with non-.py origin: {source_path}"
        )
    if not source_path.is_file():
        raise SourceBindingError(f"repo module source is missing: {source_path}")
    return relative.as_posix()


def imported_repo_sources(repo, modules=None):
    """Collect every loaded module backed by a repo file, except python/.venv."""
    modules = tuple(sys.modules.items()) if modules is None else tuple(modules.items())
    sources = {}
    for name, module in modules:
        source = (
            module
            if isinstance(module, (str, Path))
            else getattr(module, "__file__", None)
        )
        relative = repo_module_path(repo, source)
        if relative is not None:
            sources[name] = Path(repo).resolve() / Path(relative)
    return sources


def assert_file_matches_head(repo, commit, relative_path):
    repo = Path(repo).resolve()
    working_path = repo / Path(relative_path)
    if not working_path.is_file():
        raise SourceBindingError(f"pinned source is missing: {relative_path}")

    status = git_output(
        repo,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        relative_path,
    ).decode("utf-8", errors="replace")
    if status:
        raise SourceBindingError(
            f"pinned source appears in git status --porcelain: {relative_path}"
        )

    try:
        head_bytes = git_output(repo, "show", f"{commit}:{relative_path}")
    except SourceBindingError as exc:
        raise SourceBindingError(
            f"pinned source has no HEAD blob: {relative_path}"
        ) from exc
    working_bytes = working_path.read_bytes()
    if working_bytes != head_bytes:
        raise SourceBindingError(
            f"pinned source working bytes differ from HEAD blob: {relative_path}"
        )
    return hashlib.sha256(working_bytes).hexdigest()


def preflight_sources(repo, commit, imported_sources=None):
    pinned_paths = set(PINNED_HARNESS_FILES)
    for source_path in (imported_sources or {}).values():
        relative_path = repo_module_path(repo, source_path)
        if relative_path is not None:
            pinned_paths.add(relative_path)
    return {
        relative_path: assert_file_matches_head(repo, commit, relative_path)
        for relative_path in sorted(pinned_paths)
    }


def canonical_manifest_bytes(manifest):
    payload = {
        key: value for key, value in manifest.items() if key != "manifest_sha256"
    }
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def seal_manifest(manifest):
    sealed = dict(manifest)
    sealed["manifest_sha256"] = hashlib.sha256(
        canonical_manifest_bytes(sealed)
    ).hexdigest()
    return sealed


def source_manifest(repo, imported_sources, constrained_host=None):
    """Validate and hash every loaded repo module plus both sizing harness files."""
    repo = Path(repo).resolve()
    commit = head_commit(repo)
    modules = {}
    paths = set(PINNED_HARNESS_FILES)
    for name, source_path in sorted(imported_sources.items()):
        relative_path = repo_module_path(repo, source_path)
        if relative_path is None:
            continue
        modules[name] = relative_path
        paths.add(relative_path)
    if not modules:
        raise SourceBindingError("no repository-backed sizing modules were imported")

    file_sha256 = preflight_sources(repo, commit, imported_sources)
    if set(file_sha256) != paths:
        raise SourceBindingError("source manifest path set changed during preflight")
    porcelain = porcelain_bytes(repo)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "source_commit": commit,
        "modules": modules,
        "file_sha256": file_sha256,
        "host_binding": {
            "porcelain_sha256": hashlib.sha256(porcelain).hexdigest(),
            "porcelain_entry_count": sum(
                bool(line)
                for line in porcelain.decode("utf-8", errors="replace").splitlines()
            ),
        },
    }
    if constrained_host is not None:
        manifest["constrained_host"] = constrained_host
    if head_commit(repo) != commit:
        raise SourceBindingError("HEAD changed while verifying sizing source")
    return seal_manifest(manifest)


def write_source_manifest(repo, destination, manifest):
    repo = Path(repo).resolve()
    destination = Path(destination).resolve()
    try:
        destination.relative_to(repo)
    except ValueError:
        pass
    else:
        raise SourceBindingError(
            "source manifest must be outside the repository so porcelain stays stable"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, destination)


def read_source_manifest(path):
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceBindingError(f"cannot read source manifest: {exc}") from exc
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise SourceBindingError("unsupported source manifest schema")
    expected = hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()
    if manifest.get("manifest_sha256") != expected:
        raise SourceBindingError("source manifest SHA-256 does not match its contents")
    if not isinstance(manifest.get("modules"), dict) or not isinstance(
        manifest.get("file_sha256"), dict
    ):
        raise SourceBindingError("source manifest is missing module or file maps")
    for relative_path in PINNED_HARNESS_FILES:
        if relative_path not in manifest["file_sha256"]:
            raise SourceBindingError(
                f"source manifest omits harness file: {relative_path}"
            )
    return manifest


def verify_container_module(repo, manifest, module_name, source_path):
    relative_path = repo_module_path(repo, source_path)
    if relative_path is None:
        return
    expected_path = manifest["modules"].get(module_name)
    if expected_path is None:
        raise SourceBindingError(
            f"repo module is missing from source manifest: {module_name}"
        )
    if expected_path != relative_path:
        raise SourceBindingError(
            f"repo module path differs from source manifest: {module_name}"
        )
    expected_hash = manifest["file_sha256"].get(relative_path)
    if expected_hash is None:
        raise SourceBindingError(
            f"repo module file is missing from source manifest: {relative_path}"
        )
    actual_hash = hashlib.sha256(Path(source_path).resolve().read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise SourceBindingError(
            f"repo module bytes differ from source manifest: {module_name} ({relative_path})"
        )


def verify_container_sources(repo, manifest, imported_sources):
    for name, source_path in sorted(imported_sources.items()):
        verify_container_module(repo, manifest, name, source_path)
    for relative_path, expected_hash in manifest["file_sha256"].items():
        if relative_path not in PINNED_HARNESS_FILES:
            continue
        actual_hash = hashlib.sha256(
            (Path(repo) / relative_path).read_bytes()
        ).hexdigest()
        if actual_hash != expected_hash:
            raise SourceBindingError(
                f"pinned harness bytes differ from source manifest: {relative_path}"
            )
    return {
        "source_commit": manifest["source_commit"],
        "source_manifest_sha256": manifest["manifest_sha256"],
        "modules": manifest["modules"],
        "file_sha256": manifest["file_sha256"],
    }


class HeadBoundImportFinder(MetaPathFinder):
    """Reject dirty repo-local Python modules before Python executes their code."""

    def __init__(self, repo, commit):
        self.repo = Path(repo).resolve()
        self.commit = commit

    def find_spec(self, fullname, path=None, target=None):
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.origin is None:
            return None
        relative_path = repo_module_path(self.repo, spec.origin)
        if relative_path is not None:
            assert_file_matches_head(self.repo, self.commit, relative_path)
        return None


class ManifestBoundImportFinder(MetaPathFinder):
    """Verify every repo-local Python module before importing it in a container."""

    def __init__(self, repo, manifest):
        self.repo = Path(repo).resolve()
        self.manifest = manifest

    def find_spec(self, fullname, path=None, target=None):
        spec = PathFinder.find_spec(fullname, path)
        if spec is None or spec.origin is None:
            return None
        relative_path = repo_module_path(self.repo, spec.origin)
        if relative_path is not None:
            verify_container_module(self.repo, self.manifest, fullname, spec.origin)
        return None


def parse_memory_bytes(value):
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b?)\s*", value.lower())
    if not match:
        raise argparse.ArgumentTypeError(f"invalid Docker memory size: {value}")
    number = float(match.group(1))
    suffix = match.group(2)
    unit = suffix.rstrip("b").rstrip("i")
    power = {"": 0, "k": 1, "m": 2, "g": 3, "t": 4}[unit]
    return int(number * (1024**power))


def parse_docker_cpus(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid Docker CPU limit: {value}") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError(f"invalid Docker CPU limit: {value}")
    return number


def parse_docker_pids(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid Docker pids limit: {value}") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError(f"invalid Docker pids limit: {value}")
    return number


def _read_cgroup_value(cgroup_root, filename):
    path = Path(cgroup_root) / filename
    try:
        return path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise SourceBindingError(f"cannot read cgroup file {path}: {exc}") from exc


def _parse_cgroup_limit(value, filename):
    if value == "max":
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SourceBindingError(
            f"invalid cgroup value for {filename}: {value}"
        ) from exc
    if parsed < 0:
        raise SourceBindingError(f"invalid cgroup value for {filename}: {value}")
    return parsed


def _parse_cpu_max(value):
    parts = value.split()
    if len(parts) != 2:
        raise SourceBindingError(f"invalid cgroup value for cpu.max: {value}")
    quota = _parse_cgroup_limit(parts[0], "cpu.max")
    period = _parse_cgroup_limit(parts[1], "cpu.max")
    if period is None or period == 0:
        raise SourceBindingError(f"invalid cgroup value for cpu.max: {value}")
    return quota, period


def read_cgroup_limits(cgroup_root=Path("/sys/fs/cgroup")):
    """Read cgroup v2 limits without importing any repository modules."""
    observed = {
        filename: _read_cgroup_value(cgroup_root, filename)
        for filename in ("memory.max", "memory.swap.max", "pids.max", "cpu.max")
    }
    for filename in ("memory.max", "memory.swap.max", "pids.max"):
        _parse_cgroup_limit(observed[filename], filename)
    _parse_cpu_max(observed["cpu.max"])
    return observed


def verify_container_cgroup(manifest, cgroup_root=Path("/sys/fs/cgroup")):
    observed = read_cgroup_limits(cgroup_root)
    _validate_cgroup_limits(manifest.get("constrained_host"), observed)
    return observed


def _validate_cgroup_limits(constrained_host, observed):
    if not isinstance(observed, dict):
        raise SourceBindingError("raw receipt is missing observed cgroup limits")
    required_files = ("memory.max", "memory.swap.max", "pids.max", "cpu.max")
    if any(filename not in observed for filename in required_files):
        raise SourceBindingError("observed cgroup limits are incomplete")

    actual_memory = _parse_cgroup_limit(observed["memory.max"], "memory.max")
    actual_swap = _parse_cgroup_limit(observed["memory.swap.max"], "memory.swap.max")
    actual_pids = _parse_cgroup_limit(observed["pids.max"], "pids.max")
    actual_cpu, cpu_period = _parse_cpu_max(observed["cpu.max"])
    is_constrained = any(
        value is not None
        for value in (actual_memory, actual_swap, actual_pids, actual_cpu)
    )
    if constrained_host is None:
        if is_constrained:
            raise SourceBindingError(
                "container cgroup limits are constrained but manifest has no constrained_host"
            )
        return
    if not isinstance(constrained_host, dict):
        raise SourceBindingError("manifest constrained_host record is invalid")

    try:
        expected_memory = int(constrained_host["memory_limit_bytes"])
        expected_swap = (
            int(constrained_host["memory_swap_total_bytes"]) - expected_memory
        )
        expected_pids = int(constrained_host["docker_pids"])
        expected_cpus = float(constrained_host["docker_cpus"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SourceBindingError(
            "manifest constrained_host limits are incomplete"
        ) from exc
    if expected_memory <= 0 or expected_swap < 0 or expected_pids <= 0:
        raise SourceBindingError("manifest constrained_host limits are invalid")
    if not math.isfinite(expected_cpus) or expected_cpus <= 0:
        raise SourceBindingError("manifest constrained_host CPU limit is invalid")

    if actual_memory != expected_memory:
        raise SourceBindingError(
            f"container memory.max {observed['memory.max']} differs from manifest "
            f"{expected_memory}"
        )
    if actual_swap != expected_swap:
        raise SourceBindingError(
            f"container memory.swap.max {observed['memory.swap.max']} differs from manifest "
            f"{expected_swap}"
        )
    if actual_pids != expected_pids:
        raise SourceBindingError(
            f"container pids.max {observed['pids.max']} differs from manifest {expected_pids}"
        )
    if actual_cpu is None or Fraction(actual_cpu, cpu_period) != Fraction(
        str(expected_cpus)
    ):
        raise SourceBindingError(
            f"container cpu.max {observed['cpu.max']} differs from manifest "
            f"{expected_cpus} CPUs"
        )


def read_cgroup_memory_peak(cgroup_root=Path("/sys/fs/cgroup")):
    value = _read_cgroup_value(cgroup_root, "memory.peak")
    parsed = _parse_cgroup_limit(value, "memory.peak")
    if parsed is None:
        raise SourceBindingError("cgroup memory.peak cannot be max")
    return parsed


def read_cgroup_counters(cgroup_root, filename, required):
    try:
        values = dict(
            line.split()
            for line in _read_cgroup_value(cgroup_root, filename).splitlines()
        )
        result = {key: int(values[key]) for key in required}
        if any(value < 0 for value in result.values()):
            raise ValueError("negative counter")
        return result
    except (KeyError, ValueError) as exc:
        raise SourceBindingError("invalid_cgroup_counters:" + filename) from exc


def validate_memory_evidence(observed):
    events = observed.get("memory.events", {})
    if any(
        type(events.get(key)) is not int or events[key] < 0
        for key in ("low", "high", "max", "oom", "oom_kill")
    ):
        raise SourceBindingError("memory.events_missing_or_invalid")
    if events["oom_kill"] != 0:
        raise SourceBindingError("cgroup_oom_kill_nonzero")
    anon = observed.get("memory.stat.anon_peak_sampled_bytes")
    if type(anon) is not int or anon < 0:
        raise SourceBindingError("memory.stat.anon_peak_missing_or_invalid")
    limit = _parse_cgroup_limit(observed["memory.max"], "memory.max")
    expected = limit - anon if limit is not None else None
    if expected is not None and expected < 0:
        raise SourceBindingError("memory.stat.anon_peak_exceeds_limit")
    if observed.get("anon_headroom_bytes") != expected:
        raise SourceBindingError("anon_headroom_inconsistent")


class CgroupAnonSampler:
    """50 ms samples across construction, materialization and export; not an exact peak."""

    def __init__(self, root, enabled, progress_path=None):
        self.root, self.enabled = root, enabled
        self.progress_path = Path(progress_path) if progress_path is not None else None
        self.last_progress = float("-inf")
        self.peak, self.samples, self.error = 0, 0, None
        self.stop = threading.Event()

    def sample(self):
        anon = read_cgroup_counters(self.root, "memory.stat", ("anon",))["anon"]
        self.peak = max(self.peak, anon)
        self.samples += 1
        now = time.monotonic()
        if self.progress_path is not None and now - self.last_progress >= 10:
            self.progress_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.progress_path.with_suffix(".tmp")
            temporary.write_bytes(
                (
                    json.dumps(
                        {
                            "anon_peak_bytes": self.peak,
                            "sample_count": self.samples,
                            "sampled_at_utc": utc_now_iso(),
                            "monotonic_s": now,
                        }
                    )
                    + "\n"
                ).encode()
            )
            os.replace(temporary, self.progress_path)
            self.last_progress = now

    def monitor(self):
        try:
            while not self.stop.wait(0.05):
                self.sample()
        except Exception as exc:
            self.error = exc

    def __enter__(self):
        if self.enabled:
            self.sample()
            self.thread = threading.Thread(target=self.monitor)
            self.thread.start()
        return self

    def __exit__(self, *_args):
        if self.enabled:
            self.stop.set()
            self.thread.join()

    def finish(self):
        self.stop.set()
        self.thread.join()
        if self.error:
            raise self.error
        self.sample()
        return self.peak


def final_container_cgroup(
    provenance, cgroup_root=Path("/sys/fs/cgroup"), *, anon_peak=None
):
    """Recheck final cgroup limits and capture peak memory from a cgroup v2 root."""
    final_limits = read_cgroup_limits(cgroup_root)
    _validate_cgroup_limits(provenance.get("constrained_host"), final_limits)
    if final_limits != provenance.get("container_cgroup"):
        raise SourceBindingError("container cgroup limits changed during sizing")
    anon = read_cgroup_counters(cgroup_root, "memory.stat", ("anon",))["anon"]
    if anon_peak is not None:
        anon = max(anon, anon_peak)
    limit = _parse_cgroup_limit(final_limits["memory.max"], "memory.max")
    observed = {
        **final_limits,
        "memory.peak": read_cgroup_memory_peak(cgroup_root),
        "memory.events": read_cgroup_counters(
            cgroup_root, "memory.events", ("low", "high", "max", "oom", "oom_kill")
        ),
        "memory.stat.anon_peak_sampled_bytes": anon,
        "anon_headroom_bytes": limit - anon if limit is not None else None,
    }
    validate_memory_evidence(observed)
    return observed


def physical_memory_bytes():
    if os.name == "nt":

        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise OSError("GlobalMemoryStatusEx failed")
        return int(status.ullTotalPhys)
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    raise OSError("cannot determine host physical memory")


def available_memory_bytes():
    if os.name == "nt":

        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise OSError("GlobalMemoryStatusEx failed")
        return int(status.ullAvailPhys)
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise OSError("cannot determine available host memory")


def docker_vm_mem_total_bytes():
    result = subprocess.run(
        ["docker", "info", "--format", "{{.MemTotal}}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise SourceBindingError(
            f"docker info failed: {result.stderr.strip() or result.returncode}"
        )
    try:
        return int(result.stdout.strip())
    except ValueError as exc:
        raise SourceBindingError(
            f"docker info returned invalid MemTotal: {result.stdout.strip()}"
        ) from exc


def constrained_feasibility(memory_limit_bytes, host_total_bytes, vm_total_bytes):
    required = memory_limit_bytes + RESERVE_BYTES
    failures = []
    if required > host_total_bytes:
        failures.append("host_physical_memory")
    if required > vm_total_bytes:
        failures.append("docker_vm_mem_total")
    return {
        "status": "infeasible_on_host" if failures else "feasible",
        "required_bytes": required,
        "host_total_ram_bytes": host_total_bytes,
        "docker_vm_mem_total_bytes": vm_total_bytes,
        "exceeded_limits": failures,
    }


def host_gate_required_bytes(memory_limit_bytes, memory_swap_total_bytes):
    # Docker --memory-swap is the combined memory+swap ceiling, not swap alone.
    combined_ceiling = max(memory_limit_bytes, memory_swap_total_bytes)
    return combined_ceiling + RESERVE_BYTES


def run_if_feasible(
    memory_limit_bytes,
    host_total_bytes,
    vm_total_bytes,
    docker_runner,
):
    feasibility = constrained_feasibility(
        memory_limit_bytes, host_total_bytes, vm_total_bytes
    )
    if feasibility["status"] != "feasible":
        return feasibility
    return {"status": "ready", "result": docker_runner()}


def constrained_host_record(
    memory_limit_bytes, memory_swap_total_bytes, docker_cpus, docker_pids
):
    host_total = physical_memory_bytes()
    vm_total = docker_vm_mem_total_bytes()
    feasibility = constrained_feasibility(memory_limit_bytes, host_total, vm_total)
    if feasibility["status"] != "feasible":
        error = InfeasibleOnHost(
            "container memory limit plus 2 GiB exceeds host physical memory or Docker MemTotal"
        )
        error.details = feasibility
        raise error

    available = available_memory_bytes()
    available_sampled_at = utc_now_iso()
    required = host_gate_required_bytes(memory_limit_bytes, memory_swap_total_bytes)
    record = {
        **feasibility,
        "memory_limit_bytes": memory_limit_bytes,
        "memory_swap_total_bytes": memory_swap_total_bytes,
        "docker_cpus": docker_cpus,
        "docker_pids": docker_pids,
        "available_before_run_bytes": available,
        "available_before_run_mbytes": available // (1024**2),
        "available_sampled_at_utc": available_sampled_at,
        "host_gate_required_bytes": required,
        "host_gate_required_mbytes": (required + 1024**2 - 1) // (1024**2),
        "host_gate_status": "passed" if available >= required else "host_gate_failed",
    }
    if available < required:
        error = HostGateFailed(
            f"available host memory {record['available_before_run_mbytes']} MB "
            f"is below required {record['host_gate_required_mbytes']} MB"
        )
        error.details = record
        raise error
    return record


def assert_host_binding_unchanged(repo, manifest):
    repo = Path(repo).resolve()
    current_commit = head_commit(repo)
    if current_commit != manifest["source_commit"]:
        raise SourceBindingError(
            f"HEAD changed during constrained run: {manifest['source_commit']} -> {current_commit}"
        )
    porcelain = porcelain_bytes(repo)
    actual_porcelain_hash = hashlib.sha256(porcelain).hexdigest()
    expected_porcelain_hash = manifest["host_binding"]["porcelain_sha256"]
    if actual_porcelain_hash != expected_porcelain_hash:
        raise SourceBindingError(
            "git status --porcelain changed during constrained run"
        )
    for relative_path, expected_hash in manifest["file_sha256"].items():
        actual_hash = assert_file_matches_head(
            repo, manifest["source_commit"], relative_path
        )
        if actual_hash != expected_hash:
            raise SourceBindingError(
                f"pinned file SHA-256 changed during constrained run: {relative_path}"
            )


def _parse_utc_timestamp(value, field):
    if not isinstance(value, str) or not value:
        raise SourceBindingError(f"missing {field} timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceBindingError(f"invalid {field} timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise SourceBindingError(f"{field} timestamp must include UTC offset")
    return parsed


def host_gate_sample_gap_seconds(constrained_host, container_started_at_utc):
    if not isinstance(constrained_host, dict):
        raise SourceBindingError("manifest constrained_host record is invalid")
    sampled_at = _parse_utc_timestamp(
        constrained_host.get("available_sampled_at_utc"),
        "available_sampled_at_utc",
    )
    container_started_at = _parse_utc_timestamp(
        container_started_at_utc,
        "container_started_at_utc",
    )
    gap = (container_started_at - sampled_at).total_seconds()
    if gap < -HOST_GATE_CLOCK_SKEW_TOLERANCE_SECONDS:
        raise SourceBindingError(
            "host-gate sample age is negative beyond the 30-second clock-skew tolerance"
        )
    if gap > HOST_GATE_MAX_SAMPLE_AGE_SECONDS:
        raise SourceBindingError(
            f"host-gate sample age {gap:.3f}s exceeds the "
            f"{HOST_GATE_MAX_SAMPLE_AGE_SECONDS}s limit"
        )
    return gap


def finalize_container_receipt(repo, manifest_path, raw_receipt_path, output_path):
    manifest = read_source_manifest(manifest_path)
    assert_host_binding_unchanged(repo, manifest)
    try:
        receipt = json.loads(Path(raw_receipt_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceBindingError(f"cannot read raw container receipt: {exc}") from exc
    if receipt.get("source_commit") != manifest["source_commit"]:
        raise SourceBindingError(
            "container receipt source commit differs from manifest"
        )
    if receipt.get("source_manifest_sha256") != manifest["manifest_sha256"]:
        raise SourceBindingError(
            "container receipt manifest SHA-256 differs from manifest"
        )
    container_cgroup = receipt.get("container_cgroup")
    _validate_cgroup_limits(manifest.get("constrained_host"), container_cgroup)
    if not isinstance(container_cgroup, dict) or "memory.peak" not in container_cgroup:
        raise SourceBindingError("raw receipt is missing cgroup memory.peak")
    memory_peak = _parse_cgroup_limit(container_cgroup["memory.peak"], "memory.peak")
    if memory_peak is None:
        raise SourceBindingError("raw receipt cgroup memory.peak cannot be max")
    validate_memory_evidence(container_cgroup)
    if manifest.get("constrained_host") is not None:
        sample_gap = host_gate_sample_gap_seconds(
            manifest["constrained_host"],
            receipt.get("container_started_at_utc"),
        )
        receipt["constrained_host"] = manifest["constrained_host"]
        receipt["host_total_ram_bytes"] = manifest["constrained_host"][
            "host_total_ram_bytes"
        ]
        receipt["docker_vm_mem_total_bytes"] = manifest["constrained_host"][
            "docker_vm_mem_total_bytes"
        ]
        receipt["host_gate_sample_to_container_start_seconds"] = sample_gap
        receipt["host_gate_max_sample_age_seconds"] = HOST_GATE_MAX_SAMPLE_AGE_SECONDS
        receipt["host_gate_clock_skew_tolerance_seconds"] = (
            HOST_GATE_CLOCK_SKEW_TOLERANCE_SECONDS
        )
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return receipt


def import_sizing_modules(repo):
    repo = Path(repo).resolve()
    for directory in (
        repo / "scripts",
        repo / "python" / "src",
        repo / "python" / "tests",
    ):
        text = str(directory)
        if text not in sys.path:
            sys.path.insert(0, text)
    from time_inf037b_three_attempts import build  # noqa: F401

    from inference_platform.inf037b_archive import verify_archive  # noqa: F401
    from inference_platform.inf037b_campaign import (  # noqa: F401
        materialize_bundle,
        sanitized_campaign,
    )


def rss():
    if os.name == "nt":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t)
                for name in (
                    "peak",
                    "working",
                    "pq",
                    "q",
                    "pp",
                    "p",
                    "page",
                    "peakpage",
                )
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        if not psapi.GetProcessMemoryInfo(
            kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return counters.working
    return int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf(
        "SC_PAGE_SIZE"
    )


def execute_sizing(
    repo,
    args,
    provenance,
    container_mode,
    cgroup_root=Path("/sys/fs/cgroup"),
):
    if args.output is None:
        raise SourceBindingError("--output is required for a sizing run")

    from inference_platform.inf037b_archive import verify_archive
    from inference_platform.inf037b_campaign import (
        materialize_bundle,
        sanitized_campaign,
    )
    from time_inf037b_three_attempts import build

    args.output.parent.mkdir(parents=True, exist_ok=True)
    work_root = Path(args.work) if args.work is not None else default_work_path(repo)
    work_root.mkdir(parents=True, exist_ok=True)
    with (
        tempfile.TemporaryDirectory(dir=work_root) as directory,
        CgroupAnonSampler(
            cgroup_root,
            container_mode,
            progress_path=Path("/results/anon-progress.json")
            if container_mode
            else None,
        ) as anon_sampler,
    ):
        root = Path(directory) / "raw"
        print("constructing registered three-attempt archive", flush=True)
        specs, rows = build(root, reset_ms=300_000, include_reset_capture=True)
        print(json.dumps({"phase": "materialize", "rows": rows}), flush=True)
        materialize_bundle(root, specs)
        capture = None
        capture_mode = getattr(args, "capture_receipt", None) is not None
        if capture_mode:
            from inference_platform.package_a_capture import (
                compute_capture,
                stage_fixture,
            )

            staging = stage_fixture(root, Path(directory) / "staged", specs, rows)
            args.capture_receipt.write_text(
                json.dumps({"status": "IN_PROGRESS", "staging": staging}, indent=2)
                + "\n",
                encoding="utf-8",
            )
            root = Path(directory) / "staged"
        gc.collect()
        peak, stop = [rss()], threading.Event()

        def sample():
            while not stop.wait(0.05):
                peak[0] = max(peak[0], rss())

        monitor = threading.Thread(target=sample)
        monitor.start()
        native_bracket = {}

        def sanitize(source, destination):
            native_bracket["monotonic_start_ns"] = time.monotonic_ns()
            result = sanitized_campaign(
                source, destination, specs, key=b"step5-sizing-key-only" * 2
            )
            native_bracket["monotonic_end_ns"] = time.monotonic_ns()
            return result

        try:
            print(
                "measuring sanitized_campaign including immutable reproduction",
                flush=True,
            )
            if capture_mode:

                def bound_source():
                    observed = source_manifest(repo, imported_repo_sources(repo))
                    if observed["source_commit"] != provenance["source_commit"]:
                        raise SourceBindingError("capture source changed")
                    return observed

                result_holder = []

                def capture_sanitize(source, destination):
                    result_holder.append(sanitize(source, destination))

                try:
                    capture = compute_capture(
                        staging=staging,
                        source=root,
                        sanitized=Path(directory) / "sanitized",
                        destination=Path(directory) / "readback",
                        verify_source=bound_source,
                        sanitize=capture_sanitize,
                    )
                except Exception as exc:
                    args.capture_receipt.write_text(
                        json.dumps(
                            {"status": "FAILED", "staging": staging, "error": str(exc)},
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    raise
                result = result_holder[0]
            else:
                result = sanitize(root, Path(directory) / "sanitized")
            elapsed = (
                native_bracket["monotonic_end_ns"]
                - native_bracket["monotonic_start_ns"]
            ) / 1e9
            peak[0] = max(peak[0], rss())
        finally:
            stop.set()
            monitor.join()
        receipt = verify_archive(Path(directory) / "sanitized")
        raw_rows = sum(
            value["row_count"]
            for key, value in receipt["segments"].items()
            if key.startswith("raw/")
        )
        if raw_rows != rows or len(result["specs"]) != 3:
            raise RuntimeError("three_attempt_row_count_mismatch")

        if container_mode:
            verify_container_sources(repo, provenance, imported_repo_sources(repo))
        else:
            final_manifest = source_manifest(
                repo,
                imported_repo_sources(repo),
                provenance.get("constrained_host"),
            )
            if final_manifest["source_commit"] != provenance["source_commit"]:
                raise SourceBindingError("HEAD changed during sanitized export sizing")
            if (
                final_manifest["host_binding"]["porcelain_sha256"]
                != provenance["host_binding"]["porcelain_sha256"]
            ):
                raise SourceBindingError("git status --porcelain changed during sizing")
            provenance = final_manifest

        output = {
            "schema": "inf037b-sanitized-export-sizing-v3",
            "source_commit": provenance["source_commit"],
            "source_manifest_sha256": provenance["manifest_sha256"],
            "modules": provenance["modules"],
            "file_sha256": provenance["file_sha256"],
            "python": platform.python_version(),
            "platform": platform.platform(),
            "elapsed_seconds": elapsed,
            "peak_sampled_rss_bytes": peak[0],
            "memory_method": "process resident bytes sampled each 50ms during sanitized_campaign; includes retained source, excludes construction peak; not tracemalloc",
            "raw_rows": raw_rows,
            "attempts": 3,
            "scheduled_offers": [len(spec["expected_offers"]) for spec in specs],
            "source_manifest_sha256_from_export": result["source_manifest_sha256"],
            "export_bytes": sum(
                path.stat().st_size
                for path in (Path(directory) / "sanitized").rglob("*")
                if path.is_file()
            ),
            "scope": "three registered 1560s attempts and both full 300s resets with periodic capture; real sanitized_campaign with raw verification, joins, materialization and immutable reproduction; construction/materialization excluded from timed export",
            "step7": "fresh native and constrained Linux figure required if collector source changes",
            "limitations": "synthetic archive sizing on this host; not inference performance or a paid allowance",
        }
        if capture_mode:
            output.update(native_bracket)
            output["memory_method"] = (
                "process RSS sampled each 50ms over the whole bounded compute capture, including sanitizer, source checks, transfer and readback; conservative wider scope than native elapsed_seconds"
            )
            output["capture_reuse_scope"] = (
                "sanitized_campaign only; excludes staging, source checks, transfer and readback"
            )
            capture["host"] = {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "kernel": platform.release(),
            }
        if provenance.get("constrained_host") is not None:
            output["constrained_host"] = provenance["constrained_host"]
            output["host_total_ram_bytes"] = provenance["constrained_host"][
                "host_total_ram_bytes"
            ]
            output["docker_vm_mem_total_bytes"] = provenance["constrained_host"][
                "docker_vm_mem_total_bytes"
            ]
        if container_mode:
            output["container_started_at_utc"] = provenance["container_started_at_utc"]
            output["container_cgroup"] = final_container_cgroup(
                provenance, cgroup_root, anon_peak=anon_sampler.finish()
            )
            output["container_cgroup"]["anon_sample_count"] = anon_sampler.samples
            output["container_cgroup"]["anon_sampling_method"] = (
                "memory.stat anon sampled each 50ms across construction, materialization, export and verification; lower bound on peak, headroom is sample based"
            )
        args.output.write_text(
            json.dumps(output, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        if capture_mode:
            capture["native_receipt_sha256"] = hashlib.sha256(
                args.output.read_bytes()
            ).hexdigest()
            args.capture_receipt.write_text(
                json.dumps(capture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            if capture["status"] != "PASS":
                raise RuntimeError("capture_compute_exceeds_1650s_DEC041_item2")
        print(json.dumps(output), flush=True)


def prepare_host_manifest(
    repo,
    destination,
    memory_limit=None,
    memory_swap_total=None,
    docker_cpus=None,
    docker_pids=None,
):
    constrained_host = None
    if any(
        value is not None
        for value in (memory_limit, memory_swap_total, docker_cpus, docker_pids)
    ):
        if any(
            value is None
            for value in (memory_limit, memory_swap_total, docker_cpus, docker_pids)
        ):
            raise SourceBindingError(
                "--docker-memory, --docker-memory-swap, --docker-cpus and "
                "--docker-pids must be supplied together"
            )
        constrained_host = constrained_host_record(
            memory_limit, memory_swap_total, docker_cpus, docker_pids
        )

    commit = head_commit(repo)
    preflight_sources(repo, commit)
    sys.meta_path.insert(0, HeadBoundImportFinder(repo, commit))
    import_sizing_modules(repo)
    sources = imported_repo_sources(repo)
    manifest = source_manifest(repo, sources, constrained_host)
    if manifest["source_commit"] != commit:
        raise SourceBindingError("HEAD changed during host manifest creation")
    write_source_manifest(repo, destination, manifest)
    return manifest


def run_container_preflight(repo, manifest_path, cgroup_root=Path("/sys/fs/cgroup")):
    container_started_at = utc_now_iso()
    manifest = read_source_manifest(manifest_path)
    constrained_host = manifest.get("constrained_host")
    if constrained_host is not None:
        host_gate_sample_gap_seconds(constrained_host, container_started_at)
    container_cgroup = verify_container_cgroup(manifest, cgroup_root)
    sys.meta_path.insert(0, ManifestBoundImportFinder(repo, manifest))
    import_sizing_modules(repo)
    provenance = verify_container_sources(repo, manifest, imported_repo_sources(repo))
    provenance["constrained_host"] = manifest.get("constrained_host")
    provenance["container_cgroup"] = container_cgroup
    provenance["container_started_at_utc"] = container_started_at
    return manifest, provenance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write-source-manifest", type=Path)
    mode.add_argument("--container-mode", action="store_true")
    mode.add_argument("--finalize-container-receipt", type=Path)
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--capture-receipt", type=Path)
    parser.add_argument("--raw-receipt", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--docker-memory", type=parse_memory_bytes)
    parser.add_argument("--docker-memory-swap", type=parse_memory_bytes)
    parser.add_argument("--docker-cpus", type=parse_docker_cpus)
    parser.add_argument("--docker-pids", type=parse_docker_pids)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args(argv)
    if args.capture_receipt is not None and (
        args.container_mode
        or args.write_source_manifest
        or args.finalize_container_receipt
        or args.preflight_only
    ):
        parser.error("--capture-receipt requires a native sizing run")

    repo = Path(__file__).resolve().parents[1]
    try:
        if args.finalize_container_receipt is not None:
            if args.source_manifest is None or args.output is None:
                parser.error(
                    "--finalize-container-receipt requires --source-manifest and --output"
                )
            if args.raw_receipt is None:
                parser.error("--finalize-container-receipt requires --raw-receipt")
            receipt = finalize_container_receipt(
                repo,
                args.source_manifest,
                args.raw_receipt,
                args.output,
            )
            print(
                json.dumps(
                    {
                        "status": "receipt_finalized",
                        "source_commit": receipt["source_commit"],
                        "source_manifest_sha256": receipt["source_manifest_sha256"],
                        "output": str(args.output),
                    }
                ),
                flush=True,
            )
            return 0

        if args.write_source_manifest is not None:
            manifest = prepare_host_manifest(
                repo,
                args.write_source_manifest,
                args.docker_memory,
                args.docker_memory_swap,
                args.docker_cpus,
                args.docker_pids,
            )
            print(
                json.dumps(
                    {
                        "status": "preflight_ready",
                        "source_commit": manifest["source_commit"],
                        "source_manifest_sha256": manifest["manifest_sha256"],
                        "modules": manifest["modules"],
                        "constrained_host": manifest.get("constrained_host"),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            return 0

        if args.container_mode:
            if args.source_manifest is None:
                parser.error("--container-mode requires --source-manifest")
            if any(
                value is not None
                for value in (
                    args.docker_memory,
                    args.docker_memory_swap,
                    args.docker_cpus,
                    args.docker_pids,
                )
            ):
                parser.error("container mode reads limits from the source manifest")
            manifest, provenance = run_container_preflight(repo, args.source_manifest)
            if args.preflight_only:
                print(
                    json.dumps(
                        {
                            "status": "preflight_passed",
                            **provenance,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
                return 0
            execute_provenance = {
                **manifest,
                "container_cgroup": provenance["container_cgroup"],
                "container_started_at_utc": provenance["container_started_at_utc"],
            }
            execute_sizing(repo, args, execute_provenance, container_mode=True)
            return 0

        if args.source_manifest is not None:
            parser.error(
                "--source-manifest is only valid with container or finalizer mode"
            )
        if any(
            value is not None
            for value in (
                args.docker_memory,
                args.docker_memory_swap,
                args.docker_cpus,
                args.docker_pids,
            )
        ):
            parser.error(
                "Docker limit flags are only valid with --write-source-manifest"
            )
        commit = head_commit(repo)
        preflight_sources(repo, commit)
        sys.meta_path.insert(0, HeadBoundImportFinder(repo, commit))
        import_sizing_modules(repo)
        provenance = source_manifest(repo, imported_repo_sources(repo))
        if provenance["source_commit"] != commit:
            raise SourceBindingError("HEAD changed during native preflight")
        if args.preflight_only:
            print(
                json.dumps(
                    {
                        "status": "preflight_passed",
                        "source_commit": provenance["source_commit"],
                        "source_manifest_sha256": provenance["manifest_sha256"],
                        "modules": provenance["modules"],
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            return 0
        execute_sizing(repo, args, provenance, container_mode=False)
        return 0
    except (InfeasibleOnHost, HostGateFailed) as exc:
        print(
            json.dumps(
                {
                    "status": exc.status,
                    "detail": str(exc),
                    **getattr(exc, "details", {}),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        return 3
    except SourceBindingError as exc:
        parser.exit(2, f"Source binding failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
