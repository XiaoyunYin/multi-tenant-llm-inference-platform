"""Download and verify pinned Package A tools with a bounded retry window."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import subprocess
import sys
import tarfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ATTEMPTS = 3
RATE_BYTES_PER_SECOND = 1_000_000
OVERHEAD_S = 30
IDLE_TIMEOUT_S = 20
BACKOFF_S = 2


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def attempt_cap_s(
    byte_count: int,
    rate_bytes_per_second: int = RATE_BYTES_PER_SECOND,
    overhead_s: float = OVERHEAD_S,
) -> float:
    if byte_count < 0 or rate_bytes_per_second <= 0 or overhead_s < 0:
        raise ValueError("bootstrap_invalid_download_budget")
    return (
        byte_count + rate_bytes_per_second - 1
    ) // rate_bytes_per_second + overhead_s


def download_one(
    name: str,
    item: dict,
    downloads: Path,
    *,
    attempts: int = ATTEMPTS,
    rate_bytes_per_second: int = RATE_BYTES_PER_SECOND,
    overhead_s: float = OVERHEAD_S,
    idle_timeout_s: float = IDLE_TIMEOUT_S,
    deadline_epoch: float | None = None,
    runner=subprocess.run,
    now=time.time,
    sleep=time.sleep,
) -> Path:
    path = downloads / name
    if path.exists():
        verify_pin(name, item, path)
        return path
    partial = path.with_suffix(path.suffix + ".part")
    if attempts < 2:
        raise ValueError("bootstrap_attempts_below_minimum")
    cap_s = attempt_cap_s(item["bytes"], rate_bytes_per_second, overhead_s)
    for attempt in range(1, attempts + 1):
        if deadline_epoch is not None and now() + cap_s > deadline_epoch:
            remaining_s = deadline_epoch - now()
            raise RuntimeError(
                f"bootstrap_deadline:tool_download:{name}:attempt={attempt}:"
                f"cap_s={cap_s:g}:remaining_s={remaining_s:g}"
            )
        started = utc_now()
        attempt_started = time.perf_counter()
        print(
            f"step=tool_download:{name} attempt={attempt} cap_s={cap_s:g} start_utc={started}",
            flush=True,
        )
        partial.unlink(missing_ok=True)
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--idle-timeout-s",
            f"{idle_timeout_s:g}",
            "--fetch",
            item["url"],
            str(partial),
        ]
        try:
            result = runner(command, check=False, timeout=cap_s)
        except subprocess.TimeoutExpired:
            result = subprocess.CompletedProcess(command, 124)
        code = result.returncode
        ended = utc_now()
        elapsed_ms = round((time.perf_counter() - attempt_started) * 1000)
        print(
            f"step=tool_download:{name} attempt={attempt} cap_s={cap_s:g} "
            f"elapsed_ms={elapsed_ms} end_utc={ended} exit_code={code}",
            flush=True,
        )
        if code == 0:
            partial.replace(path)
            verify_pin(name, item, path)
            return path
        partial.unlink(missing_ok=True)
        if attempt == attempts:
            raise RuntimeError(
                f"bootstrap_retry_exhausted:tool_download:{name}:exit={code}"
            )
        sleep(BACKOFF_S)
    raise AssertionError("unreachable")


def verify_pin(name: str, item: dict, path: Path) -> None:
    if path.stat().st_size != item["bytes"]:
        raise ValueError(f"tool_sha256:{name}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != item["sha256"]:
        raise ValueError(f"tool_sha256:{name}")


def fetch(url: str, destination: Path, idle_timeout_s: float = IDLE_TIMEOUT_S) -> None:
    with (
        urllib.request.urlopen(url, timeout=idle_timeout_s) as src,
        destination.open("wb") as dst,
    ):
        while data := src.read(1024**2):
            dst.write(data)


def install(
    pins_path: Path,
    tools: Path,
    downloads: Path,
    *,
    deadline_epoch: float | None = None,
    attempts: int = ATTEMPTS,
    rate_bytes_per_second: int = RATE_BYTES_PER_SECOND,
    overhead_s: float = OVERHEAD_S,
    idle_timeout_s: float = IDLE_TIMEOUT_S,
    download_only: bool = False,
) -> None:
    pins = json.loads(pins_path.read_bytes())
    entries = [(name, item) for name, item in pins.items() if isinstance(item, dict)]
    downloads.mkdir(parents=True, exist_ok=True)
    started = utc_now()
    print(f"step=tool_pins start_utc={started}", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(entries)) as pool:
        futures = {
            pool.submit(
                download_one,
                name,
                item,
                downloads,
                attempts=attempts,
                rate_bytes_per_second=rate_bytes_per_second,
                overhead_s=overhead_s,
                idle_timeout_s=idle_timeout_s,
                deadline_epoch=deadline_epoch,
            ): (name, item)
            for name, item in entries
        }
        paths: dict[str, Path] = {}
        errors: list[Exception] = []
        for future, (name, _) in futures.items():
            try:
                paths[name] = future.result()
            except Exception as error:
                errors.append(error)
                print(
                    f"step=tool_download:{name} error={error}",
                    file=sys.stderr,
                    flush=True,
                )
    if errors:
        raise RuntimeError(
            f"bootstrap_tool_downloads_failed:{len(errors)}"
        ) from errors[0]
    if download_only:
        return
    tools.mkdir(parents=True, exist_ok=True)
    for name, item in entries:
        path = paths[name]
        if name in {"kind", "kubectl", "buildx"}:
            target = tools / name
            target.write_bytes(path.read_bytes())
            target.chmod(0o755)
        else:
            with tarfile.open(path) as archive:
                archive.extractall(tools, filter="data")
    ended = utc_now()
    print(f"step=tool_pins end_utc={ended} exit_code=0", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pins", type=Path, nargs="?")
    parser.add_argument("tools", type=Path, nargs="?")
    parser.add_argument("downloads", type=Path, nargs="?")
    parser.add_argument("--fetch", nargs=2, metavar=("URL", "DESTINATION"))
    parser.add_argument("--idle-timeout-s", type=float, default=IDLE_TIMEOUT_S)
    parser.add_argument("--deadline-epoch", type=float)
    parser.add_argument("--attempts", type=int, default=ATTEMPTS)
    parser.add_argument(
        "--rate-bytes-per-second", type=int, default=RATE_BYTES_PER_SECOND
    )
    parser.add_argument("--overhead-s", type=float, default=OVERHEAD_S)
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args()
    if args.fetch:
        try:
            fetch(args.fetch[0], Path(args.fetch[1]), args.idle_timeout_s)
        except TimeoutError:
            print("tool_download_idle_timeout", file=sys.stderr, flush=True)
            return 124
        return 0
    if args.pins is None or args.tools is None or args.downloads is None:
        parser.error("pins, tools and downloads are required")
    install(
        args.pins,
        args.tools,
        args.downloads,
        deadline_epoch=args.deadline_epoch,
        attempts=args.attempts,
        rate_bytes_per_second=args.rate_bytes_per_second,
        overhead_s=args.overhead_s,
        idle_timeout_s=args.idle_timeout_s,
        download_only=args.download_only,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
