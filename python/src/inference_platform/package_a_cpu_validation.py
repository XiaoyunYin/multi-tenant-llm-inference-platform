"""Fixed CPU-host validation commands in the existing Package A Runner."""

import json
import secrets
import shutil
from pathlib import Path

HOST_MODULES = tuple(
    "test_inf037b_" + s
    for s in (
        "capture_inventory",
        "eks_commands",
        "eks_fixture",
        "eks_observations",
        "eks_probe",
        "eks_setup",
        "command",
        "capture",
        "live",
        "composition",
        "probe",
        "maximum",
        "preparation",
        "sanitization_regressions",
        "bounded",
        "row5",
        "row5_diagnostic",
        "resources",
        "eks_campaign",
        "eks_supervisor",
        "eks_terminal",
        "terminal",
        "eks_stores",
        "eks_packet",
        "eks_placement",
        "placement",
        "eks_cluster",
        "row5_sequence",
        "eks_cluster_checks",
        "eks_provider",
        "eks_execution",
        "eks_host",
        "ports",
        "eks_r487",
        "4e_inputs",
        "observations",
        "row5_kind",
        "row5_live",
        "transfer",
    )
)
WEIGHT_DATA = json.loads(
    (Path(__file__).resolve().parents[3] / "deploy/package-a/cpu-test-weights.json").read_bytes()
)
SHARD_TEST_CEILINGS_S = tuple(WEIGHT_DATA["shard_test_ceilings_s"])
# Per stage: 300 s for packages and 60 s for source/cache copy + integrity.
# The collector uses its R349 Linux duration, rounded up to whole seconds.
# Every shard ceiling follows the committed measured weights and stated margin.
CGROUP_STAGE_TIMEOUT_S = 120
STAGE_OVERHEAD_S = 360
CPU_STAGE_TIMEOUTS = (
    30,
    600,
    120,
    120,
    120,
    300,
    120,
    120,
    120,
    120,
    *(s + STAGE_OVERHEAD_S for s in SHARD_TEST_CEILINGS_S),
    1800 + STAGE_OVERHEAD_S,
    120,
    120,
    300 + STAGE_OVERHEAD_S,
    *([30] * 7),
    CGROUP_STAGE_TIMEOUT_S,
)
READONLY_CASE = (
    "test_inf037b_eks_cluster.NativeReadonlyTests.test_linux_native_readonly_writer_states"
)
READONLY_RACE_CASE = (
    "test_inf037b_eks_cluster.NativeReadonlyTests.test_linux_native_single_close_race"
)
CASE_MANIFEST = "deploy/package-a/cpu-host-cases.json"
CGROUP_CASE = (
    "test_inf037b_resources.ResourceAgentTests.test_real_linux_boot_cgroup_and_interface_counters"
)


def json_receipts(text):
    """Read complete JSON objects even when unittest output precedes them."""
    decoder = json.JSONDecoder()
    for line in text.splitlines():
        start = 0
        while (start := line.find("{", start)) >= 0:
            try:
                value, size = decoder.raw_decode(line[start:])
            except ValueError:
                start += 1
                continue
            start += size
            if isinstance(value, dict):
                yield value


def summary(path, *, allow_failures=False):
    records = list(json_receipts(Path(path).read_text(encoding="utf-8", errors="replace")))
    rows = [row for row in records if "cpu_result" in row]
    if len(rows) != 1:
        raise ValueError("cpu_validation:missing_summary")
    row = rows[0]["cpu_result"]
    row["module_durations_s"] = [r for r in records if "module_finish" in r]
    row["assignment"] = [r for r in records if "shard" in r]
    if not allow_failures and (row["errors"] or row["failures"] or row["run"] <= 0):
        raise ValueError("cpu_validation:failed_cases")
    return row


def validate_required(result, required):
    if not set(required) <= set(result["passed"]):
        raise ValueError("cpu_validation:required_host_case_missing_or_skipped")


def run(runner, *, include_shards=True):
    from .package_a_cloud import GATE_A_MINIO_IMAGE, save

    output = runner.output / "cpu-validation"
    output.mkdir()
    name = "package-a-cpu-" + secrets.token_hex(6)
    minio = name + "-minio"
    data = output / "minio-data"
    data.mkdir()
    config = output / "config"
    config.mkdir()
    recovery = output / "recovery"
    recovery.mkdir()
    kubeconfig = config / "kubeconfig.secret"
    receipt = {
        "status": "STARTING",
        "stages": [],
        "cleanup": [],
        "substitutions": [],
        "go_network": "disabled",
        "shard_test_ceilings_s": list(SHARD_TEST_CEILINGS_S),
    }
    runner.env = dict(runner.env, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local")
    runner.receipt["cpu_validation"] = receipt

    def call(argv, label, timeout, **kw):
        result = runner.call(argv, "cpu-" + label, timeout=timeout, **kw)
        row = {"name": label, **result}
        receipt["stages"].append(row)
        return row

    def test_stage(argv, label, timeout, *, required=None, summarize=True, integrity=False):
        row = None
        try:
            row = call(argv, label, timeout, expected="any")
            if integrity:
                records = json_receipts((runner.output / row["log"]).read_text())
                records = [
                    record["cpu_stage_integrity"]
                    for record in records
                    if "cpu_stage_integrity" in record
                ]
                row["integrity"] = records[0] if len(records) == 1 else {"complete": False}
            if summarize:
                parsed = summary(runner.output / row["log"], allow_failures=True)
                row["tests"] = parsed
                if integrity and row["integrity"].get("complete") is not True:
                    raise ValueError("cpu_validation:tracked_file_integrity")
                if required is not None:
                    validate_required(parsed, required)
                if parsed["errors"] or parsed["failures"] or parsed["run"] <= 0:
                    raise ValueError("cpu_validation:failed_cases")
            if row["exit"] != 0:
                raise ValueError("cpu_validation:stage_exit:" + str(row["exit"]))
            row["status"] = "PASS"
        except Exception as exc:
            # A timeout, bad/missing summary or non-zero exit belongs to this
            # stage; independent test stages must still produce their evidence.
            if row is None:
                row = {"name": label}
                receipt["stages"].append(row)
            row.update(status="FAILED", error=type(exc).__name__ + ":" + str(exc))
            receipt.setdefault("error", row["error"])

    try:
        probe = call(
            [
                runner.python,
                "-c",
                "import json,sysconfig; print(json.dumps({'site':sysconfig.get_path('purelib')}))",
            ],
            "locked-site",
            30,
        )
        site = json.loads((runner.output / probe["log"]).read_bytes())["site"]
        if not Path(site).is_absolute():
            raise ValueError("cpu_validation:locked_site")
        call(
            [
                ".tools/kind",
                "create",
                "cluster",
                "--name",
                name,
                "--image",
                runner.manifest["pins"]["node_image"],
                "--config",
                "deploy/package-a/cpu-kind.yaml",
                "--kubeconfig",
                str(kubeconfig),
                "--wait",
                "120s",
            ],
            "kind-create",
            600,
        )
        call(["docker", "pull", GATE_A_MINIO_IMAGE], "minio-pull", 120)
        access, secret = "cpu-validation", secrets.token_hex(24)
        env = output / "host.env"
        env.write_text(
            "\n".join(
                [
                    "PYTHONPATH=/repo:/repo/scripts:/repo/python/src:/repo/python/tests:/locked-site",
                    "PYTHONDONTWRITEBYTECODE=1",
                    "AWS_DEFAULT_REGION=us-east-1",
                    "S3_ENDPOINT_URL=http://127.0.0.1:9000",
                    "S3_TEST_BUCKET=cpu-validation",
                    "AWS_ACCESS_KEY_ID=" + access,
                    "AWS_SECRET_ACCESS_KEY=" + secret,
                    "INF037B_EKS_HOST_TEST=1",
                    "RECOVERY_ROOT=" + str(recovery),
                    "INF037B_PLACEMENT_HOST_CONFIG=" + str(config / "placement.json"),
                    "INF037B_CLUSTER_HOST_CONFIG=" + str(config / "cluster.json"),
                    "REDIS_TEST_ADDR=127.0.0.1:26379",
                    "M5_PACKAGE_A_BIN=/repo/.cache/kind-build/gateway",
                    "ROW5_DIAGNOSTIC_BIN=" + str(output / "diagnostic"),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        env.chmod(0o600)
        minio_env = output / "minio.env"
        minio_env.write_text(
            f"MINIO_ROOT_USER={access}\nMINIO_ROOT_PASSWORD={secret}\n", encoding="utf-8"
        )
        minio_env.chmod(0o600)
        call(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                minio,
                "--publish",
                "127.0.0.1:9000:9000",
                "--env-file",
                str(minio_env),
                "--mount",
                f"type=bind,source={data},target=/data",
                GATE_A_MINIO_IMAGE,
                "server",
                "/data",
            ],
            "minio-start",
            120,
        )
        ready = [
            "sh",
            "-c",
            "i=0; until curl -fsS --max-time 2 "
            "http://127.0.0.1:9000/minio/health/ready; do i=$((i+1)); "
            "test $i -lt 30 || exit 1; sleep 1; done",
        ]
        call(ready, "minio-ready", 120)
        test_stage(
            [
                runner.python,
                "-m",
                "inference_platform.package_a_cpu_fixture",
                "--kubeconfig",
                str(kubeconfig),
                "--output",
                str(config),
                "--image",
                runner.manifest["pins"]["gateway_base_image"],
            ],
            "fixtures",
            300,
            summarize=False,
        )
        call(
            ["go", "build", "-o", str(output / "diagnostic"), "./cmd/row5-diagnostic"],
            "diagnostic-build",
            120,
        )
        call(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                name + "-redis",
                "--publish",
                "127.0.0.1:26379:6379",
                runner.manifest["pins"]["redis_image"],
            ],
            "redis-start",
            120,
        )
        call(
            [
                "sh",
                "-c",
                "i=0; until docker exec " + name + "-redis redis-cli ping | grep -qx PONG; "
                "do i=$((i+1)); test $i -lt 30 || exit 1; sleep 1; done",
            ],
            "redis-ready",
            120,
        )
        base = [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "--memory",
            "6656m",
            "--memory-swap",
            "6656m",
            "--cpus",
            "2",
            "--pids-limit",
            "256",
            "--mount",
            f"type=bind,source={runner.repo},target=/source,readonly",
            "--mount",
            "type=bind,source=/root/go/pkg/mod,target=/go-mod,readonly",
            "--mount",
            f"type=bind,source={site},target=/locked-site,readonly",
            "--mount",
            "type=bind,source=/opt/dec077/tools/go,target=/opt/dec077/tools/go,readonly",
            "--mount",
            f"type=bind,source={output},target={output}",
            "--env-file",
            str(env),
            "-w",
            "/repo",
        ]
        # Same distro-package prerequisites as package_a_bootstrap.sh. The base
        # image remains digest pinned; retain installed versions in each log.
        # The Python command retains its own ceiling in addition to the 300 s
        # package-setup ceiling. No shell program is supplied by the manifest.
        setup = (
            'timeout 300 sh -ec "apt-get update >/dev/null && '
            'apt-get install -y git gcc libc6-dev procps >/dev/null"; '
            "dpkg-query -W git gcc libc6-dev procps; "
            'export PATH=/opt/dec077/tools/go/bin:$PATH; exec "$@"'
        )

        def container_stage(command, label, ceiling, *, extra=(), required=None):
            worktree = output / ("worktree-" + label)
            worktree.mkdir()
            argv = (
                base
                + ["--mount", f"type=bind,source={worktree},target=/repo"]
                + list(extra)
                + [
                    runner.image,
                    "sh",
                    "-ec",
                    setup,
                    "cpu-validation",
                    "python",
                    "/source/scripts/package_a_cpu_stage.py",
                    "--source",
                    "/source",
                    "--work",
                    "/repo/tree",
                    "--module-cache",
                    "/go-mod",
                    "timeout",
                    str(ceiling),
                    "python",
                    *command,
                ]
            )
            try:
                test_stage(
                    argv, label, ceiling + STAGE_OVERHEAD_S, required=required, integrity=True
                )
            finally:
                shutil.rmtree(worktree)

        for index, ceiling in enumerate(SHARD_TEST_CEILINGS_S if include_shards else ()):
            container_stage(
                [
                    "scripts/run_python_tests.py",
                    "--index",
                    str(index),
                    "--count",
                    str(len(SHARD_TEST_CEILINGS_S)),
                    "--weighted",
                    "--ceiling",
                    str(ceiling),
                ],
                f"shard-{index}",
                ceiling,
                extra=[
                    "-e",
                    "INF037B_CLUSTER_HOST_CONFIG=",
                    "-e",
                    "INF037B_PLACEMENT_HOST_CONFIG=",
                ],
            )
        required = json.loads((runner.repo / CASE_MANIFEST).read_bytes())
        test_stage(
            [
                runner.python,
                "scripts/run_resource_cgroup_case.py",
                "--image",
                runner.image,
                "--repo",
                str(runner.repo),
                "--name",
                name + "-cgroup",
                "--state-root",
                str(output),
            ],
            "resource-cgroup",
            CGROUP_STAGE_TIMEOUT_S,
            required=required["cgroup"],
        )
        for phase in ("before", "after"):
            if phase == "after":
                call(["docker", "restart", minio], "minio-restart", 120)
                call(ready, "minio-ready-after", 120)
            container_stage(
                ["scripts/run_package_a_cpu_cases.py", "--phase", phase],
                "host-" + phase,
                1800 if phase == "before" else 300,
                extra=["-e", "TRANSFER_RESTART_PHASE=" + phase],
                required=required[phase],
            )
        receipt["status"] = "FAILED" if "error" in receipt else "PASS"
    except BaseException as exc:
        receipt.update(status="FAILED", error=type(exc).__name__ + ":" + str(exc))
        raise
    finally:
        # Capture evidence first; then remove only this branch's resources and verify.
        for label, argv in (
            (
                "kind-logs",
                [".tools/kind", "export", "logs", "--name", name, str(output / "kind-logs")],
            ),
            ("minio-logs", ["docker", "logs", minio]),
            ("kind-remove", [".tools/kind", "delete", "cluster", "--name", name]),
            ("minio-remove", ["docker", "rm", "-fv", minio]),
            ("redis-remove", ["docker", "rm", "-fv", name + "-redis"]),
        ):
            try:
                row = runner.call(argv, "cpu-" + label, timeout=30, expected="any")
                receipt["cleanup"].append({"name": label, **row})
                if label.endswith("remove") and row["exit"] != 0:
                    receipt["status"] = "FAILED"
            except Exception as exc:
                receipt["status"] = "FAILED"
                receipt["cleanup"].append({"name": label, "error": str(exc)})
        try:
            row = runner.call(
                ["docker", "ps", "-aq", "--filter", "name=" + name], "cpu-remaining", timeout=30
            )
            remaining = (runner.output / row["log"]).read_text().strip()
            receipt["remaining"] = remaining
            if remaining:
                receipt["status"] = "FAILED"
            else:
                # Preserve readback receipts, not the large test object data.
                for directory in (data, recovery):
                    receipt["cleanup"].append(
                        {
                            "name": "test-data-remove",
                            "path": str(directory),
                            "bytes": sum(
                                p.stat().st_size for p in directory.rglob("*") if p.is_file()
                            ),
                        }
                    )
                    shutil.rmtree(directory)
        finally:
            # Credentials are not part of frozen evidence.
            for path in (
                output / "host.env",
                output / "minio.env",
                config / "token.secret",
                kubeconfig,
                config / "ca.crt",
            ):
                path.unlink(missing_ok=True)
            save(runner.output / "runner.json", runner.receipt)
        if receipt["status"] != "PASS":
            raise ValueError("cpu_validation:failed_or_cleanup_unverified")


def result_record(result, passed):
    return {
        "run": result.testsRun,
        "passed": passed,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": [
            {
                "id": test.id(),
                "reason": reason,
                "classification": skip_classification(test.id(), reason),
            }
            for test, reason in result.skipped
        ],
    }


def skip_classification(identifier, reason):
    if identifier in (CGROUP_CASE, READONLY_CASE, READONLY_RACE_CASE):
        return "dedicated_host_cgroup_stage"
    if "DeviceLiveTests" in identifier:
        return "4e_02_real_gpu_kubelet_device_witness"
    for named in (
        "shallow_source_bundle_lacks_pinned_history",
        "non_windows_powershell_wrapper_unavailable",
    ):
        if reason.startswith(named):
            return named
    if "MinioRestart" in identifier:
        return "separate_explicit_restart_phase"
    if "timing_256" in identifier:
        return "opt_in_timing_receipt_not_a_correctness_assertion"
    if "HostCompositionTests" in identifier:
        return "4e_02_real_native_engine_and_node_producers_not_in_CPU_kind"
    if "HostClusterTests" in identifier or "HostPlacementTests" in identifier:
        return "shard_defers_mutating_API_cases_to_dedicated_host_stage"
    return "other_discovery_case: " + reason


def required_from_source(repo):
    """Discover explicit POSIX/API/host gates, and committed real-dependency cases."""
    import ast

    required = []
    for module in HOST_MODULES:
        tree = ast.parse((Path(repo) / "python/tests" / (module + ".py")).read_bytes())
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            class_gate = " ".join(ast.unparse(n) for n in cls.decorator_list)
            for method in (
                n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test")
            ):
                gate = class_gate + " ".join(ast.unparse(n) for n in method.decorator_list)
                if (
                    "os.name == 'posix'" in gate
                    or "S3_URL" in gate
                    or "INF037B_CLUSTER_HOST_CONFIG" in gate
                    or "INF037B_PLACEMENT_HOST_CONFIG" in gate
                    or "INF037B_EKS_HOST_TEST" in gate
                ):
                    required.append(module + "." + cls.name + "." + method.name)
    required.extend(
        [
            "test_inf037b_live.GatewayRedisEndToEnd.test_real_gateway_redis_sse_archive_sanitize_and_reproduce",
            "test_inf037b_transfer.TransferIntegrationTests.test_capture_tcp_resume_both_stores_retrieve_and_reopen",
            "test_inf037b_transfer.MinioRestartWriteTests.test_write_durable_two_store_restart_checkpoint",
        ]
    )
    # Opt-in timing measurements are not an ordinary CPU validation gate.
    required = [s for s in required if "timing_256" not in s and "MinioRestartReadTests" not in s]
    return {
        "before": sorted(set(required) - {CGROUP_CASE, READONLY_CASE, READONLY_RACE_CASE}),
        "cgroup": [CGROUP_CASE, READONLY_CASE, READONLY_RACE_CASE],
        "after": [
            "test_inf037b_transfer.MinioRestartReadTests.test_retrieve_both_stores_after_minio_container_restart"
        ],
    }
