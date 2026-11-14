import copy
import hashlib
import json
import unittest
from pathlib import Path

from inference_platform.eks_deployment import (
    TEARDOWN_SCOPES,
    device_witness_resources,
    resource_agent_command,
    resources,
    smoke_snapshot,
    verify_teardown,
)

ROOT = Path(__file__).resolve().parents[2]
MODEL_MANIFEST = {"config.json": {"bytes": 3, "sha256": hashlib.sha256(b"{}\n").hexdigest()}}
MODEL_MANIFEST_SHA256 = hashlib.sha256(
    json.dumps(MODEL_MANIFEST, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
INPUTS = {
    "crictl_host_path": "/usr/bin/crictl",
    "crictl_sha256": "c" * 64,
    "model_manifest_sha256": MODEL_MANIFEST_SHA256,
    "model_manifest": MODEL_MANIFEST,
    "operator_cidrs": ["192.0.2.1/32"],
    "namespace": "mti-m5-test",
    "gateway_image": "example.invalid/gateway@sha256:" + "a" * 64,
    "config_sha256": "b" * 64,
    "tls_secret": "test-tls",
    "r": 4,
    "w": 1,
}


class DeploymentTests(unittest.TestCase):
    def test_setup_signal_pod_is_nonserving_and_on_its_target_node(self):
        from inference_platform.eks_deployment import setup_signal_pod

        source = (ROOT / "deploy/eks/capture_runtime.py").read_text()
        for slot in (0, 1):
            pod = setup_signal_pod(INPUTS, slot, "node" + str(slot), source)
            self.assertEqual(pod["spec"]["nodeName"], "node" + str(slot))
            self.assertNotIn("app", pod["metadata"]["labels"])
            container = pod["spec"]["containers"][0]
            self.assertEqual(container["args"], ["--setup-signal"])
            self.assertEqual(
                {e["name"]: e.get("value") for e in container["env"]}["NVIDIA_VISIBLE_DEVICES"],
                "void",
            )
            for kind in ("requests", "limits"):
                self.assertNotIn("nvidia.com/gpu", container["resources"][kind])
            self.assertEqual(
                pod["spec"]["volumes"][1]["hostPath"]["path"],
                "/var/lib/mti-m5/" + INPUTS["namespace"],
            )
            self.assertTrue(
                any(e.get("value") == "/capture-data/$(POD_UID)" for e in container["env"])
            )

    def test_fixed_actions_accept_the_rendered_pinned_controller_and_configuration(self):
        from inference_platform.inf037b_archive import encode, sha
        from inference_platform.inf037b_eks_actions import fixed_action_inputs

        source = (ROOT / "deploy/eks/capture_runtime.py").read_text()
        rendered = resources(INPUTS, source)["items"]
        controller = next(
            o for o in rendered if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
        )
        configmap = next(
            o
            for o in rendered
            if o["kind"] == "ConfigMap" and o["metadata"]["name"] == "streaming-ingress"
        )
        ns = INPUTS["namespace"]
        config = {
            "namespace": ns,
            "slots": {str(i): {"name": "vllm-" + str(i)} for i in (0, 1)},
            "objects": {
                "controller": {
                    "path": "/apis/apps/v1/namespaces/" + ns + "/statefulsets/vllm",
                    "sha256": sha(encode(controller)),
                },
                "ingress": {
                    "path": "/api/v1/namespaces/" + ns + "/configmaps/streaming-ingress",
                    "sha256": sha(encode(configmap)),
                },
            },
        }
        image = controller["spec"]["template"]["spec"]["containers"][0]["image"]
        plans = fixed_action_inputs(
            config,
            {"runtime": image.rsplit("sha256:", 1)[1]},
            {"name": "controller", "object": controller, "sha256": sha(encode(controller))},
            [{"name": "ingress", "object": configmap, "sha256": sha(encode(configmap))}],
        )
        self.assertEqual(
            plans["setup"]["steps"]["cold"]["actions"][0]["body"]["spec"]["replicas"], 1
        )
        self.assertEqual(
            plans["setup"]["steps"]["node_cached"]["actions"][0]["body"]["spec"]["template"],
            controller["spec"]["template"],
        )
        self.assertEqual(plans["setup"]["steps"]["begin"]["actions"][0]["body"], configmap)

    def test_native_overlay_mounts_only_pinned_sources_and_keeps_engine_argv(self):
        from inference_platform import inf037b_native as native

        manifest = {
            "base": native.BASE_FILES,
            "files": native.BASE_FILES,
            "version": "0.29.0",
            "helper_sha256": hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),
        }
        runtime = (ROOT / "deploy/eks/capture_runtime.py").read_text()
        plain = resources(INPUTS, runtime)
        overlay = {
            "manifest": manifest,
            "host_path": "/opt/m5/native-overlay",
            "runtime_site": "/usr/local/lib/python3.12/site-packages",
            "model_sha256": "a" * 64,
        }
        objects = resources({**INPUTS, "native_overlay": overlay}, runtime)

        def engine(objects):
            return next(
                o
                for o in objects["items"]
                if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
            )["spec"]["template"]["spec"]["containers"][0]

        original, changed = engine(plain), engine(objects)
        self.assertEqual(original["args"], changed["args"])
        mounts = [m for m in changed["volumeMounts"] if "subPath" in m]
        self.assertEqual({m["subPath"] for m in mounts}, set(native.BASE_FILES))
        self.assertTrue(all(m["readOnly"] for m in mounts))
        env = {e["name"]: e for e in changed["env"]}
        self.assertEqual(env["INF037B_NATIVE_ROOT"]["value"], "$(CAPTURE_ROOT)/native")
        self.assertIn("pod-index", env["BACKEND_SLOT"]["valueFrom"]["fieldRef"]["fieldPath"])
        manifest["helper_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "overlay_deployment_pin"):
            resources({**INPUTS, "native_overlay": overlay}, runtime)

    def test_device_witness_is_independent_host_pid_readonly_and_explicit(self):
        config = {
            "spec_configmap": "bound-spec",
            "nvidia_runtime_class": "bound-nvidia-utility",
            "report_names": ["device-node0", "device-node1"],
            "token_secret": "token",
            "tls_secret": "tls",
            "helper_host_path": "/opt/m5/podresources",
            "nvidia_smi_host_path": "/usr/bin/nvidia-smi",
            "driver_lib_host_path": "/usr/lib64",
            "crictl_host_path": "/usr/bin/crictl",
        }
        inputs = {**INPUTS, "device_witness": config}
        objects = device_witness_resources(inputs)
        pod = objects[1]["spec"]["template"]["spec"]
        self.assertTrue(pod["hostPID"])
        self.assertEqual(pod["runtimeClassName"], "bound-nvidia-utility")
        self.assertNotIn("nvidia.com/gpu", pod["containers"][0]["resources"]["limits"])
        self.assertIn(
            {"name": "NVIDIA_DRIVER_CAPABILITIES", "value": "utility"}, pod["containers"][0]["env"]
        )
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(all(m["readOnly"] for m in pod["containers"][0]["volumeMounts"]))
        self.assertTrue(pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"])
        self.assertTrue(
            any(
                v.get("hostPath", {}).get("path") == "/var/lib/kubelet/pod-resources"
                for v in pod["volumes"]
            )
        )
        self.assertEqual(device_witness_resources(INPUTS), [])
        with self.assertRaisesRegex(ValueError, "node_source_deployment"):
            device_witness_resources({**INPUTS, "device_witness": {}})

    def test_independent_resource_process_uses_explicit_deployment_inputs(self):
        self.assertEqual(
            resource_agent_command(
                python="/venv/bin/python",
                spec_path="/pins/resource.json",
                host="127.0.0.1",
                port=9103,
            ),
            [
                "/venv/bin/python",
                "-m",
                "inference_platform.inf037b_resource_agent",
                "--spec",
                "/pins/resource.json",
                "--host",
                "127.0.0.1",
                "--port",
                "9103",
            ],
        )
        with self.assertRaisesRegex(ValueError, "resource_agent_port"):
            resource_agent_command(
                python="python", spec_path="/pins/resource.json", host="127.0.0.1", port=-1
            )

    def test_smoke_steady_state_refuses_placement_runtime_and_public_boundary_failures(self):
        manifest = resources(INPUTS, "runtime-code")
        items = []
        for obj in manifest["items"]:
            if obj["kind"] == "Service":
                items.append(copy.deepcopy(obj))
            if obj["kind"] == "StatefulSet":
                name = obj["metadata"]["name"]
                for index in (0, 1):
                    pod = copy.deepcopy(obj["spec"]["template"])
                    pod.update(apiVersion="v1", kind="Pod")
                    pod["metadata"].update(
                        name=f"{name}-{index}",
                        namespace=INPUTS["namespace"],
                        uid=f"uid-{name}-{index}",
                    )
                    pod["spec"]["nodeName"] = f"gpu-{index}" if name == "vllm" else "cpu"
                    pod["status"] = {
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "containerStatuses": [
                            {"name": name, "imageID": pod["spec"]["containers"][0]["image"]}
                        ],
                    }
                    items.append(pod)
        for index in (0, 1):
            items.append(
                {
                    "kind": "Node",
                    "metadata": {"name": f"gpu-{index}", "labels": {"m5-role": "gpu"}},
                    "spec": {
                        "taints": [
                            {"key": "nvidia.com/gpu", "value": "true", "effect": "NoSchedule"}
                        ]
                    },
                    "status": {"allocatable": {"nvidia.com/gpu": "1"}},
                }
            )
        snapshot = {"items": items}
        result = smoke_snapshot(snapshot, INPUTS)
        self.assertTrue(result["manifest_smoke_passed"])
        self.assertFalse(result["serving_fitness"])
        for mode in ("colocate", "runtime", "admin", "not-ready", "third-node"):
            changed = copy.deepcopy(snapshot)
            backend = next(
                o
                for o in changed["items"]
                if o["kind"] == "Pod" and o["metadata"]["name"] == "vllm-1"
            )
            if mode == "colocate":
                backend["spec"]["nodeName"] = "gpu-0"
            elif mode == "runtime":
                backend["status"]["containerStatuses"][0]["imageID"] = "unbound"
            elif mode == "admin":
                next(
                    o
                    for o in changed["items"]
                    if o["kind"] == "Service" and o["metadata"]["name"] == "redis"
                )["spec"]["type"] = "NodePort"
            elif mode == "not-ready":
                backend["status"]["conditions"][0]["status"] = "False"
            else:
                changed["items"].append(
                    {
                        **copy.deepcopy(items[-1]),
                        "metadata": {"name": "gpu-extra", "labels": {"m5-role": "gpu"}},
                    }
                )
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                smoke_snapshot(changed, INPUTS)

    def test_gpu_placement_drain_discovery_and_private_boundaries(self):
        manifest = resources(INPUTS, (ROOT / "deploy/eks/capture_runtime.py").read_text())
        objects = {(o["kind"], o["metadata"]["name"]): o for o in manifest["items"]}
        vllm = objects["StatefulSet", "vllm"]["spec"]
        self.assertEqual(vllm["replicas"], 2)
        self.assertEqual(vllm["updateStrategy"], {"type": "OnDelete"})
        pod = vllm["template"]["spec"]
        self.assertEqual(pod["nodeSelector"], {"m5-role": "gpu"})
        self.assertEqual(pod["containers"][0]["resources"]["limits"]["nvidia.com/gpu"], "1")
        self.assertIn(
            "requiredDuringSchedulingIgnoredDuringExecution", pod["affinity"]["podAntiAffinity"]
        )
        self.assertGreaterEqual(pod["terminationGracePeriodSeconds"], 35)
        self.assertEqual(pod["containers"][0]["startupProbe"]["failureThreshold"], 1800)
        observer = objects["DaemonSet", "node-observer"]["spec"]["template"]["spec"]
        observer_container = observer["containers"][0]
        lifecycle_mount = next(
            m for m in observer_container["volumeMounts"] if m["name"] == "lifecycle"
        )
        lifecycle_volume = next(v for v in observer["volumes"] if v["name"] == "lifecycle")
        self.assertEqual(lifecycle_mount["mountPath"], "/lifecycle")
        self.assertTrue(lifecycle_mount["readOnly"])
        self.assertEqual(
            lifecycle_volume["hostPath"]["path"], "/var/lib/mti-m5/" + INPUTS["namespace"]
        )
        observer_env = {env["name"]: env.get("value") for env in observer_container["env"]}
        self.assertEqual(observer_env["MODEL_MANIFEST_SHA256"], INPUTS["model_manifest_sha256"])
        cache_manifest = objects["ConfigMap", "model-cache-manifest"]
        self.assertTrue(cache_manifest["immutable"])
        self.assertEqual(
            hashlib.sha256(cache_manifest["data"]["manifest.json"].encode()).hexdigest(),
            INPUTS["model_manifest_sha256"],
        )
        gateway = objects["StatefulSet", "gateway"]["spec"]["template"]["spec"]
        gateway_statefulset = objects["StatefulSet", "gateway"]["spec"]
        gateway_service = objects["Service", "gateway"]["spec"]
        peer_service = objects["Service", "gateway-peer"]["spec"]
        self.assertEqual(gateway_statefulset["serviceName"], "gateway-peer")
        self.assertEqual(gateway_service["type"], "ClusterIP")
        self.assertEqual(peer_service["clusterIP"], "None")
        env = {e["name"]: e.get("value") for e in gateway["containers"][0]["env"]}
        self.assertEqual(env["BACKEND_DISCOVERY_SERVICE"], "vllm")
        self.assertEqual(env["ADMISSION_CAPACITY_MODE"], "dynamic")
        self.assertEqual(env["ADMISSION_REPORT_TTL"], "8s")
        public = [
            o
            for o in manifest["items"]
            if o["kind"] == "Service" and o["spec"]["type"] != "ClusterIP"
        ]
        self.assertEqual([o["metadata"]["name"] for o in public], ["streaming-ingress"])
        self.assertEqual(public[0]["spec"]["loadBalancerClass"], "service.k8s.aws/nlb")
        self.assertEqual(public[0]["spec"]["loadBalancerSourceRanges"], ["192.0.2.1/32"])
        self.assertEqual(
            public[0]["metadata"]["annotations"][
                "service.beta.kubernetes.io/aws-load-balancer-listener-attributes.TCP-443"
            ],
            "tcp.idle_timeout.seconds=120",
        )
        proxy = objects["ConfigMap", "streaming-ingress"]["data"]["nginx.conf"]
        for directive in (
            "listen 8443 ssl",
            "proxy_buffering off",
            "proxy_request_buffering off",
            "proxy_next_upstream off",
            "proxy_read_timeout 45s",
            "location / { return 404;",
        ):
            self.assertIn(directive, proxy)

    def test_unresolved_inputs_refuse(self):
        for key, value in (
            ("gateway_image", "gateway:latest"),
            ("r", 0),
            ("w", True),
            ("namespace", "default"),
            ("config_sha256", "unresolved"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                resources({**INPUTS, key: value}, "runtime")
        for manifest in (
            {"../config.json": MODEL_MANIFEST["config.json"]},
            {"config.json": {"bytes": 3, "sha256": "z" * 64}},
        ):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                resources({**INPUTS, "model_manifest": manifest}, "runtime")
        with self.assertRaisesRegex(ValueError, "model_manifest_pin_mismatch"):
            resources({**INPUTS, "model_manifest_sha256": "0" * 64}, "runtime")

    def test_teardown_requires_every_fresh_complete_empty_inventory(self):
        receipt = {
            "schema": "m5-teardown-inventory-v1",
            "session_id": "test",
            "region": "us-east-1",
            "destroy_status": "succeeded",
            "inventories": {
                key: {
                    "complete": True,
                    "command": "fixture-read-only-query",
                    "observed_ms": 200,
                    "resources": [],
                    "error": None,
                }
                for key in TEARDOWN_SCOPES
            },
        }
        self.assertEqual(
            verify_teardown(receipt, session_id="test", after_ms=100)["inventory_count"], 19
        )
        for mode in ("missing", "old", "partial", "resource", "wrong-session"):
            changed = copy.deepcopy(receipt)
            if mode == "missing":
                changed["inventories"].pop("public_ips")
            elif mode == "old":
                changed["inventories"]["instances"]["observed_ms"] = 99
            elif mode == "partial":
                changed["inventories"]["bucket_versions"]["complete"] = False
            elif mode == "resource":
                changed["inventories"]["capacity_reservations"]["resources"] = ["remaining"]
            else:
                changed["session_id"] = "another"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                verify_teardown(changed, session_id="test", after_ms=100)
