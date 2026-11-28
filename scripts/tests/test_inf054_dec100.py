import base64
import hashlib
import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inf054_autoscaling import tape
from inf054_dec100 import ClusterWindow, Dec100Workload, overlapping_streams
from analyze_inf054_dcgm import coverage
from inf054_dcgm import FIELDS, FRESH, exported_metrics, require_dcgm
from inf054_eks_workload import run, write_rows
from inf054_kind_engine import Engine
from inf060_eks_cpu_plan import (
    HELM_MARKER,
    require_helm_session,
    require_helm_simulation,
)
from m5_descriptive_eks import require_review

from inference_platform.inf054_eks_client import (
    LONG_PROBE_CAP,
    LONG_PROBE_PROMPT,
    offer,
)
from inference_platform.m5_descriptive_cluster import ClusterPorts


class ClusterIO:
    namespace = "mti-m5-test"
    kubeconfig = "fixture"
    context = "fixture"
    gateway_image = "registry.invalid/gateway@sha256:" + "a" * 64
    client_image = "registry.invalid/client@sha256:" + "b" * 64

    def __init__(self):
        self.forwarders = []
        self.calls = []
        self.snapshot = b"fixture read from TSDB"
        self.raw_uid = "identifier-not-exported"
        self.client_node = "private-client-node"

    def k(self, *args, deadline, timeout=None):
        self.calls.append(args)
        prefix = args[:2]
        if prefix == ("get", "pods"):
            label = args[3]
            return json.dumps(
                {
                    "items": {
                        "job-name=load-client": [
                            {
                                "metadata": {"name": "private-pod"},
                                "spec": {"nodeName": self.client_node},
                            }
                        ],
                        "app=telemetry": [{"metadata": {"name": "private-prometheus"}}],
                        "app=vllm": [
                            {
                                "metadata": {"name": "vllm-0", "uid": self.raw_uid},
                                "spec": {"nodeName": "private-engine-node"},
                                "status": {"phase": "Running"},
                            },
                        ],
                    }[label]
                }
            )
        if prefix == ("get", "endpointslices"):
            return json.dumps(
                {
                    "items": [
                        {
                            "endpoints": [
                                {
                                    "conditions": {"ready": True},
                                    "targetRef": {"uid": self.raw_uid},
                                },
                            ]
                        }
                    ]
                }
            )
        if prefix == ("get", "hpa"):
            return json.dumps(
                {
                    "spec": {
                        "metrics": [
                            {
                                "external": {
                                    "target": {
                                        "type": "AverageValue",
                                        "averageValue": "2",
                                    },
                                    "metric": {"name": "prometheus-test"},
                                }
                            }
                        ],
                        "behavior": {"scaleDown": {"stabilizationWindowSeconds": 900}},
                    },
                    "status": {"desiredReplicas": 1},
                }
            )
        if prefix == ("get", "--raw"):
            return json.dumps({"items": [{"value": "0"}]})
        if prefix == ("get", "statefulset"):
            return json.dumps({"spec": {"replicas": 1}})
        if args[0] == "exec" and "--mode" in args:
            row = {
                "outcome": "completed",
                "http_status": 200,
                "uid": self.raw_uid,
                "dispatch_s": 0.1,
                "ttft_s": 0.2,
                "completed_s": 0.4,
                "completion_tokens": 64,
            }
            mode = args[args.index("--mode") + 1]
            if mode == "readiness":
                return json.dumps({"rows": [row]})
            return json.dumps(
                {
                    "start_epoch": time.time(),
                    "rows": [
                        {**row, "dispatch_s": 0.1 + slot["offset_ns"] / 1e9}
                        for slot in tape()
                    ],
                }
            )
        if "wc" in args:
            return str(len(self.snapshot))
        if "sha256sum" in args:
            return hashlib.sha256(self.snapshot).hexdigest() + "  snapshot"
        if args[0] == "exec":
            return base64.b64encode(self.snapshot).decode()
        return ""

    def call(self, argv, *, timeout):
        self.calls.append(tuple(argv))

    def forward(self, target, port, *, deadline=None):
        self.calls.append(("forward", target, port))
        return 49153

    def client_job(self):
        return {"items": [{"kind": "Job", "spec": {"template": {"spec": {}}}}]}

    def tenant_configuration(self):
        return {"tenants": []}

    def client_credentials(self):
        return {"token": "fixture"}


def build_dcgm_control(test, work, failure):
    nodes = ["node-a", "node-b"]
    addresses = ["192.0.2.10", "192.0.2.11"]
    clock = [0.0]
    state = {"poll": 0}

    class Fixture:
        cluster = SimpleNamespace(credential="")

        def get(self, end, kind, *args):
            if kind == "nodes":
                return {"items": [{"metadata": {"name": node}} for node in nodes]}
            if kind == "pods":
                state["poll"] += 1
                restarted = failure == "restart" and state["poll"] >= 2
                return {
                    "items": [
                        {
                            "metadata": {"name": f"dcgm-{i}", "uid": f"test-{i}"},
                            "spec": {"nodeName": node},
                            "status": {
                                "containerStatuses": [
                                    {
                                        "name": "dcgm-exporter",
                                        "restartCount": int(restarted),
                                        "state": {
                                            "running": {
                                                "startedAt": "1970-01-01T00:01:30Z"
                                                if failure == "uptime"
                                                else "1970-01-01T00:00:00Z",
                                            }
                                        },
                                        "lastState": {
                                            "terminated": {
                                                "reason": "OOMKilled",
                                                "exitCode": 137,
                                            }
                                        },
                                    }
                                ]
                            },
                        }
                        for i, node in enumerate(nodes)
                    ]
                }
            return {
                "items": [
                    {
                        "endpoints": [
                            {
                                "nodeName": node,
                                "targetRef": {"name": f"dcgm-{i}"},
                                "conditions": {"ready": True},
                                "addresses": [
                                    ip
                                    if failure != "old-endpoint" or state["poll"] == 1
                                    else "192.0.2.12"
                                ],
                            }
                            for i, (node, ip) in enumerate(
                                zip(nodes, addresses, strict=True)
                            )
                        ]
                    }
                ]
            }

        def query(self, end, expression):
            test.assertEqual(expression, FRESH)
            test.assertIn("abs(DCGM_FI_DEV_GPU_UTIL", expression)
            stamp = 99 if failure == "one-scrape" else 99 + clock[0]
            return [
                {
                    "metric": {"gate_field": field, "instance": f"{ip}:9400"},
                    "value": [100, str(stamp)],
                }
                for i, ip in enumerate(addresses)
                for field in FIELDS
                if not (
                    failure == "missing-fb" and i == 1 and field.endswith("FB_USED")
                )
            ]

        def k(self, end, *args):
            return "START 192.0.2.10 " + "x" * 9000 + " END"

        def targets(self, end):
            return [
                {"labels": {"job": "dcgm"}, "health": "down", "lastError": "192.0.2.10"}
            ]

    path = work / "dcgm.json"
    with (
        patch("inf054_dcgm.time.monotonic", side_effect=lambda: clock[0]),
        patch("inf054_dcgm.time.time", side_effect=lambda: 100 + clock[0]),
        patch(
            "inf054_dcgm.time.sleep",
            side_effect=lambda n: clock.__setitem__(0, clock[0] + n),
        ),
    ):
        if failure is None:
            test.assertTrue(require_dcgm(Fixture(), path, wait_s=15)["ready"])
            test.assertEqual(state["poll"], 2)
        else:
            with test.assertRaisesRegex(ValueError, "^inf054_dcgm_not_ready$"):
                require_dcgm(Fixture(), path, wait_s=15)
            log = json.loads(path.read_bytes())["snapshot"]["pods"][0]["previous_log"]
            test.assertTrue(log["head"].startswith("START [REDACTED]"))
            test.assertTrue(log["tail"].endswith(" END"))
            test.assertLessEqual(path.stat().st_size, 128 * 1024)


class Dec100Tests(unittest.TestCase):
    def test_dcgm_gate_runs_before_offers_in_later_cycle(self):
        with tempfile.TemporaryDirectory() as name:
            work = Path(name)
            cluster = ClusterIO()
            driver = Dec100Workload(
                cluster,
                "helm",
                work / "tape",
                "digest",
                work,
                cleanup_end=time.monotonic() + 30,
            )
            prepared = SimpleNamespace(
                work=work,
                name="test",
                arm="keda",
                cycle=2,
                engine_readiness_s=20,
                preparation_started=time.monotonic(),
            )
            with (
                patch.object(ClusterWindow, "readiness"),
                patch(
                    "inf054_dec100.require_dcgm",
                    side_effect=ValueError("inf054_dcgm_not_ready"),
                ) as gate,
                self.assertRaisesRegex(ValueError, "^inf054_dcgm_not_ready$"),
            ):
                with driver.backend(prepared, time.monotonic() + 30):
                    self.fail("offered without passing a later-cycle gate")
            self.assertEqual(gate.call_args.args[1], work / "dcgm-gate-keda-2.json")
            self.assertEqual(gate.call_args.kwargs["wait_s"], 45)

    def test_dcgm_requires_fresh_polls_without_a_restart_on_both_nodes(self):
        for failure in (
            None,
            "restart",
            "one-scrape",
            "missing-fb",
            "old-endpoint",
            "uptime",
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as name:
                build_dcgm_control(self, Path(name), failure)

    def test_per_instance_coverage_does_not_mask_missing_metrics(self):
        gauges = [{"sample_epoch_s": 1.0}, {"sample_epoch_s": 2.0}]
        receipt = {
            "expected_nodes": 2,
            "before_uninstall": {"nodes": [{"restart_count": 0}, {"restart_count": 0}]},
        }
        lines = [
            f'{{__name__="{field}", instance="{instance}", job="dcgm"}} {int(field == "up")} 999'
            for field in (*FIELDS, "up")
            for instance in ("one", "two")
        ]
        self.assertTrue(coverage(gauges, lines, receipt)["passes"])
        lines.append(f'{{__name__="{FIELDS[1]}", instance="two", job="dcgm"}} NaN 1999')
        result = coverage(gauges, lines, receipt)
        self.assertFalse(result["passes"])
        self.assertEqual([row["both_samples"] for row in result["instances"]], [2, 1])

    def test_cadvisor_filters_exporter_pod_and_treats_zero_as_absent(self):
        def metric(field, pod, value):
            return f'{field}{{container="dcgm-exporter",pod="{pod}"}} {value}'

        body = "\n".join(
            [
                metric("container_memory_max_usage_bytes", "wanted", 2048),
                metric("container_memory_max_usage_bytes", "other", 4096),
                metric("container_memory_working_set_bytes", "wanted", 1024),
                metric("container_oom_events_total", "wanted", 0),
            ]
        )
        self.assertEqual(
            exported_metrics(body, "wanted"),
            {
                "container_memory_max_usage_bytes": 2048,
                "container_memory_working_set_bytes": 1024,
                "container_oom_events_total": None,
            },
        )

    def test_gpu_like_sse_cap_overlaps_termination_and_removal(self):
        def duration(cap):
            clock = [0.0]
            engine = Engine.__new__(Engine)
            data = json.dumps(
                {"messages": [{"content": LONG_PROBE_PROMPT}], "max_tokens": cap}
            ).encode()
            engine.path = "/v1/chat/completions"
            engine.headers = {"Content-Length": str(len(data))}
            engine.rfile = io.BytesIO(data)
            engine.wfile = io.BytesIO()
            engine.event = Mock()
            engine.send_response = engine.send_header = engine.end_headers = Mock()
            with (
                patch.dict("os.environ", {"INF054_MOCK_LONG_STREAM": "1"}),
                patch(
                    "inf054_kind_engine.time.sleep",
                    side_effect=lambda s: clock.__setitem__(0, clock[0] + s),
                ),
            ):
                engine.do_POST()
            self.assertEqual(engine.event.call_count, cap + 2)
            return clock[0]

        for cap in (64, LONG_PROBE_CAP):
            length = duration(cap)
            rows = [
                {
                    "replica_ordinal": 1,
                    "outcome": "completed",
                    "dispatch_s": 0.0,
                    "ttft_s": 0.01,
                    "closed_s": length,
                }
            ]
            for instant in (45, 90):
                self.assertEqual(
                    bool(overlapping_streams(rows, instant)), cap == LONG_PROBE_CAP
                )
        self.assertGreaterEqual(duration(LONG_PROBE_CAP), 90)

    def test_gpu_probe_stops_only_after_endpoint_and_pod_removal(self):
        cluster = ClusterIO()
        client = {"metadata": {"name": "client"}, "spec": {"nodeName": "cpu"}}
        window = ClusterWindow(
            cluster, client, 49153, "fixture", "keda", long_downscale=True
        )
        signalled = threading.Event()
        order = []
        now = time.time()

        def probe(_end, mode):
            self.assertEqual(mode, "gpu-downscale")
            self.assertTrue(signalled.wait(12))
            return {"start_epoch": now, "rows": []}

        def get(_end, *_args):
            order.append("pod")
            if order.count("pod") < 3:
                return {
                    "metadata": {
                        "deletionTimestamp": "2026-11-27T10:00:45Z",
                        "deletionGracePeriodSeconds": 45,
                    }
                }
            return {}

        def slices(_end):
            order.append("slices")
            names = ["vllm-0", "vllm-1"] if order.count("slices") == 1 else ["vllm-0"]
            return [{"endpoints": [{"targetRef": {"name": name}} for name in names]}]

        def stop(_end, *args, **_kwargs):
            self.assertIn("touch", args)
            order.append("stop")
            signalled.set()
            return ""

        with (
            patch.object(window, "desired", return_value=1),
            patch.object(window, "get", side_effect=get),
            patch.object(window, "engine_slices", side_effect=slices),
            patch.object(window, "probe", side_effect=probe),
            patch.object(window, "k", side_effect=stop),
        ):
            result = window.downscale(time.monotonic() + 10)
        self.assertEqual(order, ["pod", "slices"] * 3 + ["stop"])
        self.assertTrue(result["removal_observed"])
        times = result["events_epoch"]
        self.assertEqual(
            times["pod_deletion_timestamp"] - times["termination_started_estimate"], 45
        )
        self.assertLess(times["desired_one"], times["endpoint_removed"])
        self.assertLess(times["endpoint_removed"], times["pod_gone"])

    def test_gpu_watcher_keeps_polling_after_the_client_has_finished(self):
        cluster = ClusterIO()
        client = {"metadata": {"name": "client"}, "spec": {"nodeName": "cpu"}}
        window = ClusterWindow(
            cluster, client, 49153, "fixture", "keda", long_downscale=True
        )
        results = {"start_epoch": time.time(), "rows": []}
        polls = iter(
            (
                [{"endpoints": [{"targetRef": {"name": "vllm-1"}}]}],
                [{"endpoints": [{"targetRef": {"name": "vllm-0"}}]}],
            )
        )
        with (
            patch.object(window, "desired", return_value=1),
            patch.object(
                window, "get", side_effect=[{"metadata": {"name": "vllm-1"}}, {}]
            ),
            patch.object(window, "engine_slices", side_effect=lambda _end: next(polls)),
            patch.object(window, "probe", return_value=results),
            patch.object(window, "k") as stop,
        ):
            result = window.downscale(time.monotonic() + 10)
        self.assertTrue(result["removal_observed"])
        self.assertIsNotNone(result["events_epoch"]["pod_gone"])
        stop.assert_not_called()

    def test_null_and_missing_endpoint_lists_then_ready(self):
        cluster = ClusterIO()
        client = {
            "metadata": {"name": "test"},
            "spec": {"nodeName": cluster.client_node},
        }
        window = ClusterWindow(cluster, client, 49153, "fixture", "keda")
        default = cluster.k
        slices = iter(
            [
                {"items": [{"endpoints": None, "ports": None}]},
                {"items": [{}]},
                {
                    "items": [
                        {
                            "endpoints": [
                                {"conditions": None, "targetRef": None},
                                {"conditions": {"ready": True}, "targetRef": None},
                            ]
                        }
                    ]
                },
            ]
        )

        def cluster_io(*args, deadline, timeout=None):
            if args[:2] == ("get", "endpointslices") and (page := next(slices, None)):
                return json.dumps(page)
            return default(*args, deadline=deadline, timeout=timeout)

        with tempfile.TemporaryDirectory() as name:
            trail = Path(name) / "readiness.jsonl"
            with patch.object(cluster, "k", side_effect=cluster_io):
                window.readiness(time.monotonic() + 40, trail=trail)
            rows = [json.loads(line) for line in trail.read_text().splitlines()]
        self.assertEqual(rows[0]["null_endpoint_slices"], 1)
        self.assertFalse(rows[0]["replicas"][0]["ready"])
        self.assertEqual(rows[1]["absent_endpoint_slices"], 1)
        self.assertFalse(rows[1]["replicas"][0]["ready"])
        self.assertFalse(rows[2]["replicas"][0]["ready"])
        self.assertTrue(rows[3]["replicas"][0]["ready"])
        self.assertEqual(rows[-1]["event"], "ready")
        self.assertEqual(rows[-1]["external_metric"]["series"], 1)

    def test_readiness_does_not_start_last_short_poll(self):
        client = {"metadata": {"name": "client"}, "spec": {"nodeName": "cpu"}}
        window = ClusterWindow(ClusterIO(), client, 49153, "fixture", "fixed-1")
        window.origin = 0
        clock = [175.5]

        def poll(end):
            self.assertEqual(end, 179.5)
            clock[0] = 179.8
            return []

        with tempfile.TemporaryDirectory() as name:
            trail = Path(name) / "readiness.jsonl"
            with (
                patch("inf054_dec100.time.monotonic", side_effect=lambda: clock[0]),
                patch("inf054_dec100.time.sleep"),
                patch.object(window, "membership", side_effect=poll) as membership,
            ):
                with self.assertRaisesRegex(
                    TimeoutError, "^inf054_ready_or_membership$"
                ):
                    window.readiness(180, trail=trail)
            membership.assert_called_once_with(179.5)
            rows = [json.loads(line) for line in trail.read_bytes().splitlines()]
        self.assertEqual(
            [row["event"] for row in rows], ["membership", "readiness_timeout"]
        )
        self.assertEqual(rows[-1]["expected"], 1)

    def test_null_hpa_status_and_pending_metrics(self):
        cluster = ClusterIO()
        client = {
            "metadata": {"name": "test"},
            "spec": {"nodeName": cluster.client_node},
        }
        window = ClusterWindow(cluster, client, 49153, "fixture", "keda")
        for hpa in ({"spec": None}, {"spec": {"metrics": None}, "status": None}):
            default = cluster.k

            def cluster_io(*args, deadline, timeout=None):
                if args[:2] == ("get", "hpa"):
                    return json.dumps(hpa)
                return default(*args, deadline=deadline, timeout=timeout)

            end = time.monotonic() + 10
            with patch.object(cluster, "k", side_effect=cluster_io):
                self.assertIsNone(window.external_metrics(end))
                with patch.object(window, "query", return_value=[]):
                    window.observe(end)
            self.assertIsNone(window.scale[-1]["hpa_desired"])

    def test_client_exec_uses_its_own_outer_deadline(self):
        with tempfile.TemporaryDirectory() as name:
            cluster = ClusterPorts()
            cluster.campaign = SimpleNamespace(kubectl="kubectl")
            cluster.kubeconfig = "fixture"
            cluster.context = "fixture"
            cluster.namespace = "mti-fixture"
            cluster.output = Path(name)
            cluster.commands = []
            client = {
                "metadata": {"name": "load-client"},
                "spec": {"nodeName": "client"},
            }

            cases = (
                ("window", None, 1080, 1090),
                ("window", 120, 300, 310),
                ("downscale", None, 350, 355),
                ("readiness", None, 0, 30),
            )
            for mode, burst, minimum, budget in cases:
                with self.subTest(mode=mode, rehearsal_burst=burst):
                    window = ClusterWindow(
                        cluster,
                        client,
                        49153,
                        "fixture",
                        "keda",
                        rehearsal_burst_s=burst,
                    )
                    with patch(
                        "subprocess.run",
                        return_value=SimpleNamespace(
                            returncode=0, stdout=b'{"rows":[]}', stderr=b""
                        ),
                    ) as command:
                        self.assertEqual(
                            window.probe(time.monotonic() + budget, mode), {"rows": []}
                        )
                    argv = command.call_args.args[0]
                    timeout = command.call_args.kwargs["timeout"]
                    self.assertGreaterEqual(timeout, minimum)
                    self.assertGreater(timeout, budget - 1)
                    self.assertLessEqual(timeout, budget)
                    self.assertEqual(argv[argv.index("--mode") + 1], mode)
                    if burst:
                        self.assertEqual(
                            argv[argv.index("--rehearsal-burst-seconds") + 1],
                            str(burst),
                        )

    def test_in_cluster_client_validates_sse_and_drops_content(self):
        response = Mock(status=200)
        response.getheader.return_value = "fixture-ordinal-uid"
        content = {
            "choices": [
                {"index": 0, "delta": {"content": "canary"}, "finish_reason": None}
            ]
        }
        finish = {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
        usage = {
            "choices": [],
            "usage": {
                "prompt_tokens": 1024,
                "completion_tokens": 1,
                "total_tokens": 1025,
                "count_source": "runtime_usage",
            },
        }
        response.read1.side_effect = [
            ("data: " + json.dumps(frame) + "\n\n").encode()
            for frame in (content, finish, usage)
        ] + [b"data: [DONE]\n\n", b""]
        session = Mock()
        session.getresponse.return_value = response
        with patch(
            "inference_platform.inf054_eks_client.http.client.HTTPSConnection",
            return_value=session,
        ):
            row = offer(
                8443, Mock(), "fixture", "model", "prompt", 64, time.monotonic() + 2
            )
        self.assertEqual(row["outcome"], "completed")
        self.assertEqual(row["completion_tokens"], 1)
        self.assertNotIn("canary", json.dumps(row))
        self.assertTrue(session.close.called)

    def test_real_driver_uses_same_context_for_sse_scale_and_snapshot(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            cluster = ClusterIO()
            offered = root / "offered.jsonl"
            write_rows(
                offered,
                ({**slot, "prompt": f"fixture {slot['seed']}"} for slot in tape()),
            )
            digest = hashlib.sha256(offered.read_bytes()).hexdigest()
            calls = []

            def helm(*args, timeout):
                calls.append(args)
                return SimpleNamespace(stdout="")

            def prometheus(url, deadline, *, post=False):
                self.assertIn("127.0.0.1:49153", url)
                if post:
                    self.assertIn("/api/v1/admin/tsdb/snapshot", url)
                    return {"name": "20261126T070000Z-a1"}
                return {"result": []}

            ports = Dec100Workload(
                cluster,
                "helm",
                offered,
                digest,
                root,
                cleanup_end=time.monotonic() + 12000,
                cpu=True,
                helm_invoke=helm,
            )
            output = root / "results"
            with patch("inf054_dec100.read_json", side_effect=prometheus):
                [record] = run(
                    ports,
                    offered,
                    digest,
                    output,
                    absolute_end=time.monotonic() + 11000,
                    cpu_proof=True,
                )
            self.assertEqual(record["offered"], 2760)
            self.assertTrue(record["complete"])
            self.assertEqual(record["windows"]["burst"]["outcomes"]["completed"], 2700)
            self.assertEqual(record["downscale"]["reason"], "no_scale_out")
            exported = output / "keda-1"
            lines = (exported / "offers.jsonl").read_text()
            self.assertNotIn(cluster.raw_uid, lines)
            self.assertEqual(json.loads(lines.splitlines()[0])["replica_ordinal"], 0)
            self.assertEqual(json.loads(lines.splitlines()[0])["arm"], "keda")
            forward_index = cluster.calls.index(("forward", "svc/telemetry", 9090))
            self.assertEqual(
                cluster.calls[forward_index - 1][:3],
                ("wait", "deployment/telemetry", "--for=condition=Available"),
            )
            self.assertTrue((exported / "scale.jsonl").read_text())
            self.assertEqual((exported / "tsdb.tar.gz").read_bytes(), cluster.snapshot)
            self.assertEqual(cluster.namespace, "mti-m5-test")
            self.assertEqual(
                [row[5] for row in calls], ["template", "install", "uninstall"]
            )
            self.assertTrue(
                any(
                    "external.metrics.k8s.io" in " ".join(map(str, row))
                    for row in cluster.calls
                )
            )

    def test_cpu_helm_marker_does_not_accept_cpu_clock_approval(self):
        source, digest = "a" * 40, "b" * 64
        manifest = {
            "source_commit": source,
            "descriptive": {
                "inf054_cpu_helm": {"tape_sha256": "c" * 64},
                "cpu_clock_rehearsal": True,
            },
        }
        content = (
            f"## Claude Round 441\n{HELM_MARKER} manifest={digest} source={source}\n"
        )
        require_review(content, manifest, digest)
        with self.assertRaisesRegex(ValueError, "exact_committed_review_required"):
            require_review(
                content.replace(HELM_MARKER, "CPU EKS REHEARSAL APPROVED"),
                manifest,
                digest,
            )

    def test_new_helm_session_must_be_in_the_cpu_helm_namespace(self):
        self.assertEqual(require_helm_session("m5-desc-r445-helm"), "m5-desc-r445-helm")
        for other in ("m5-desc-r420-cpu", "m5-desc-r423-gpu", "m5-desc-r445-helm/"):
            with self.subTest(other=other):
                with self.assertRaisesRegex(ValueError, "inf054_cpu_helm_session"):
                    require_helm_session(other)

    def test_unsealed_cpu_helm_draft_requires_policy_simulation(self):
        with self.assertRaisesRegex(ValueError, "inf054_policy_simulation_required"):
            require_helm_simulation(Path("."), {"files": {}})


if __name__ == "__main__":
    unittest.main()
