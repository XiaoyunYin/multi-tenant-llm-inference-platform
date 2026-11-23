"""Check a sealed native probe's pinned image on the routine CPU host."""

import argparse
import shutil
import subprocess
import time
from pathlib import Path

from inference_platform.inf060_streaming_probe import ABORT_LINE

import inf060_probe_spec as spec
from inf060_probe_client import FORMAT, bracket, clock_exchange

PARSE = """\
import importlib.util
import json
import sys
from pathlib import Path

arm = sys.argv[1]
entry = json.loads(Path("/packet/engine.json").read_bytes())[arm]["argv"]
assert importlib.util.find_spec(entry[2]) is not None
from vllm.entrypoints.launchers.cli_args import make_arg_parser
from vllm.utils.argparse_utils import FlexibleArgumentParser

parsed = make_arg_parser(FlexibleArgumentParser()).parse_args(entry[3:])
assert parsed.enable_log_requests is (arm == "logged")
assert arm != "logged" or parsed.max_log_len == 0
print(json.dumps({"arm": arm, "enable_log_requests": parsed.enable_log_requests,
                  "max_log_len": parsed.max_log_len}))
"""

# The real formatter takes fileinfo from the calling frame. Give the synthetic
# abort the same source basename as the native call, without starting the engine.
LOG = """\
import logging
import vllm.logger

emit = 'logging.getLogger("vllm.v1.engine.async_llm").info(' \
       '"Request %s aborted.", "chatcmpl-req_" + 32 * "0")'
exec(compile(emit, "async_llm.py", "exec"))
"""

IMPORTS = """\
import sys
sys.path.insert(0, "/packet/scripts")
import inf060_probe_engine
import huggingface_hub
import transformers
print("inf060_probe_engine, huggingface_hub, transformers imported")
"""


def measure_clock(packet, image):
    container = subprocess.check_output(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--pull",
            "never",
            "--network",
            "none",
            "-v",
            f"{packet}:/packet:ro",
            "--entrypoint",
            spec.IMAGE_PYTHON,
            image,
            "-I",
            "-c",
            "import time; time.sleep(120)",
        ],
        timeout=30,
        text=True,
    ).strip()

    def capture():
        a = time.monotonic_ns()
        wall = time.time_ns()
        b = time.monotonic_ns()
        return {"mono_ns": (a + b) // 2, "wall_ns": wall, "sample_width_ns": b - a}

    try:
        argv = [
            "docker",
            "exec",
            "-i",
            container,
            spec.IMAGE_PYTHON,
            "-I",
            "/packet/scripts/inf060_probe_engine.py",
            "clock-server",
        ]
        observations = [capture()]
        before = clock_exchange(argv, time.time() + 30)
        after = clock_exchange(argv, time.time() + 30)
        observations.append(capture())
        result = bracket(before, after, observations)
        return {
            **result,
            "before_min_width_ns": min(row["width"] for row in before),
            "after_min_width_ns": min(row["width"] for row in after),
            "bracket_width_ns": result["offset_hi_ns"] - result["offset_lo_ns"],
        }
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container],
            timeout=30,
            check=True,
            stdout=subprocess.DEVNULL,
        )


def check_image(packet, exchange, root_gib):
    rehearsal = spec.load(exchange / "rehearsal.json")
    spec.check(rehearsal["supervisor_complete"], "image_check_rehearsal")
    for name in ("engine.json", "tools.json", spec.LOG_CONFIG):
        spec.check(
            spec.facts(packet / name) == rehearsal["image_inputs"][name],
            "image_check_artifact:" + name,
        )
    engine = spec.load(packet / "engine.json")
    spec.verify_engine(engine)
    image = spec.load(packet / "tools.json")["vllm"]
    spec.check(image == spec.VLLM_IMAGE, "image_check_digest")
    receipt_path = exchange / "real-image.json"
    docker_root = Path("/var/lib/docker")
    receipt = {
        "manifest_sha256": rehearsal["manifest_sha256"],
        "image_inputs": rehearsal["image_inputs"],
        "image": image,
        "root_gib": root_gib,
        "docker_free_before_bytes": shutil.disk_usage(docker_root).free,
        "pull_in_product_budget": False,
        "gpu_requested": False,
        "argument_parser_device": "cpu",
        "commands": [],
        "complete": False,
    }
    spec.save(receipt_path, receipt)

    def run(name, argv, timeout):
        start = time.monotonic()
        try:
            result = subprocess.run(
                argv, capture_output=True, timeout=timeout, check=False
            )
            exit_code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            exit_code, stdout, stderr = None, exc.stdout or b"", exc.stderr or b""
        row = {
            "name": name,
            "argv": argv,
            "exit_code": exit_code,
            "elapsed_s": time.monotonic() - start,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }
        receipt["commands"].append(row)
        spec.save(receipt_path, receipt)
        return row

    def container(name, entrypoint, args, env):
        argv = [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "-v",
            f"{packet}:/packet:ro",
        ]
        for key, value in env.items():
            argv.extend(("-e", f"{key}={value}"))
        return run(name, [*argv, "--entrypoint", entrypoint, image, *args], 120)

    spec.check(
        root_gib == 200 and receipt["docker_free_before_bytes"] >= 40 * 1024**3,
        "image_check_disk",
    )
    spec.check(
        run("pull", ["docker", "pull", image], 1500)["exit_code"] == 0, "image_pull"
    )
    receipt["docker_free_after_pull_bytes"] = shutil.disk_usage(docker_root).free
    version = ["-c", "import sys; print(sys.version)"]
    control = engine["control"]
    interpreter = container("interpreter", control["argv"][0], version, control["env"])
    spec.check(
        interpreter["exit_code"] == 0 and interpreter["stdout"].strip(),
        "image_interpreter",
    )

    # Even --help builds DeviceConfig before parsing flags. Use the pinned
    # image's built-in CPU platform selector for these parser-only processes.
    for name, arm in engine.items():
        command = arm["argv"]
        parser_env = {**arm["env"], "VLLM_TARGET_DEVICE": "cpu"}
        parsed = container("parse-" + name, command[0], ["-c", PARSE, name], parser_env)
        spec.check(parsed["exit_code"] == 0, "image_argparse:" + name)

    command = control["argv"]
    help_ = container(
        "entry-help",
        command[0],
        [*command[1:3], "--help"],
        {**control["env"], "VLLM_TARGET_DEVICE": "cpu"},
    )
    spec.check(
        help_["exit_code"] == 0
        and all(
            flag in help_["stdout"]
            for flag in (
                "--no-enable-log-requests",
                "--enable-log-requests",
                "--max-log-len",
            )
        ),
        "image_argparse_help",
    )

    logged = engine["logged"]
    log = container("logging", logged["argv"][0], ["-c", LOG], logged["env"])
    matches = [
        line for line in log["stdout"].splitlines() if ABORT_LINE.fullmatch(line)
    ]
    spec.check(
        log["exit_code"] == 0 and len(matches) == 1 and FORMAT.match(matches[0]),
        "image_abort_formatter",
    )
    imports = container("staging-imports", spec.IMAGE_PYTHON, ["-c", IMPORTS], {})
    spec.check(imports["exit_code"] == 0, "image_staging_imports")
    mutant = container("python-mutation", "python", version, control["env"])
    spec.check(
        mutant["exit_code"] not in (None, 0)
        and 'exec: "python": executable file not found' in mutant["stderr"],
        "image_python_mutation",
    )
    receipt["clock"] = measure_clock(packet, image)
    receipt["complete"] = True
    spec.save(receipt_path, receipt)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("exchange", type=Path)
    parser.add_argument("root_gib", type=int)
    args = parser.parse_args()
    check_image(args.packet, args.exchange, args.root_gib)
