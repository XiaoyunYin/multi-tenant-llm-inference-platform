"""Generate and check the Helm chart against the deployed INF-060 renderer."""

import argparse
import copy
import hashlib
import json
import os
import subprocess
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from types import SimpleNamespace

import yaml
from m5_descriptive_remote import EKSClusterPorts

from inference_platform.inf060_eks_resources import serving_resources
from inference_platform.kind_rollout import Campaign
from inference_platform.m5_descriptive import resources

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/inference-platform"
FIXTURE = ROOT / "scripts/fixtures/inf063/inf060.json"
NAMESPACE = "mti-m5-desc-inf060-r423"
GATEWAY = "registry.invalid/inf060-gateway@sha256:" + "a" * 64
CLIENT = "registry.invalid/inf060-client@sha256:" + "b" * 64
PINS = json.loads((CHART.parent / "tool-pins.json").read_bytes())


def composed():
    # Same code and startup setting as the sealed Round 423 source applied in
    # Round 424. Only the private ECR identity strings are substituted.
    base = EKSClusterPorts.render_manifest(
        SimpleNamespace(startup_seconds=640), resources(NAMESPACE, GATEWAY)
    )
    return serving_resources(
        base,
        CLIENT,
        (ROOT / "deploy/inf060/vllm-logging.json").read_text(encoding="utf-8"),
    )


def documents(stream):
    return [doc for doc in yaml.safe_load_all(stream) if doc]


def normalized(objects):
    objects = copy.deepcopy(objects)
    # Prometheus consumes YAML. Compare its config independently of formatting.
    for obj in objects:
        if obj["kind"] == "ConfigMap" and obj["metadata"]["name"] == "telemetry":
            obj["data"]["prometheus.yml"] = yaml.safe_load(
                obj["data"]["prometheus.yml"]
            )
    return sorted(
        objects,
        key=lambda o: (
            o["apiVersion"],
            o["kind"],
            o["metadata"].get("namespace", ""),
            o["metadata"]["name"],
        ),
    )


def command(*argv, input=None, env=None, timeout=360, check=True):
    return subprocess.run(
        argv,
        input=input,
        env=env,
        text=True,
        capture_output=True,
        check=check,
        timeout=timeout,
    )


def download(pin, path):
    with urllib.request.urlopen(pin["url"], timeout=90) as response:
        raw = response.read()
    if hashlib.sha256(raw).hexdigest() != pin["sha256"]:
        raise ValueError("tool archive checksum mismatch")
    path.write_bytes(raw)
    return path


def install_helm(work):
    system = "windows" if os.name == "nt" else "linux"
    pin = PINS["helm"][system + "-amd64"]
    archive = download(pin, work / "helm-archive")
    executable = work / ("helm.exe" if system == "windows" else "helm")
    if system == "windows":
        with zipfile.ZipFile(archive) as package:
            executable.write_bytes(package.read("windows-amd64/helm.exe"))
    else:
        with tarfile.open(archive) as package:
            executable.write_bytes(package.extractfile("linux-amd64/helm").read())
        executable.chmod(0o755)
    version = command(executable, "version", "--template", "{{.Version}}").stdout
    if version != PINS["helm"]["version"]:
        raise ValueError("Helm version mismatch")
    return executable


def check_value_overrides(helm, baseline):
    expected = copy.deepcopy(baseline)
    engine = next(
        o
        for o in expected
        if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
    )
    args = engine["spec"]["template"]["spec"]["containers"][0]["args"]
    index = args.index("--max-num-seqs") + 1
    args[index] = "32"
    gateway = next(
        o
        for o in expected
        if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "gateway"
    )
    gateway["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"][
        "memory"
    ] = "640Mi"
    values = yaml.safe_load((CHART / "values.yaml").read_bytes())
    values["engine"]["args"][index] = "32"
    override = yaml.safe_dump(
        {
            "engine": {"args": values["engine"]["args"]},
            "gateway": {"resources": {"limits": {"memory": "640Mi"}}},
        }
    )
    actual = normalized(
        documents(
            command(
                helm,
                "template",
                "inf063",
                CHART,
                "-f",
                "-",
                input=override,
            ).stdout
        )
    )
    if actual != expected:
        raise ValueError(
            "gateway memory and engine cap overrides must change exactly two fields"
        )


def chart_checks(helm):
    expected = normalized(composed()["items"])
    if normalized(json.loads(FIXTURE.read_bytes())["items"]) != expected:
        raise ValueError(
            "INF-060 golden fixture no longer matches the composed renderer"
        )
    actual = normalized(documents(command(helm, "template", "inf063", CHART).stdout))
    if actual != expected:
        bad = [o["metadata"]["name"] for a, o in zip(actual, expected) if a != o]
        raise ValueError(
            f"composed Helm golden diff: {bad}; counts {len(actual)}/{len(expected)}"
        )
    command(helm, "lint", CHART)
    check_value_overrides(helm, actual)
    options = [
        "--set",
        "autoscaling.enabled=true",
        "--set-string",
        "autoscaling.threshold=2",
    ]
    scaled = documents(command(helm, "template", "inf063", CHART, *options).stdout)
    engine = next(
        x
        for x in scaled
        if x["kind"] == "StatefulSet" and x["metadata"]["name"] == "vllm"
    )
    if "replicas" in engine["spec"] or not any(
        x["kind"] == "ScaledObject" for x in scaled
    ):
        raise ValueError("autoscaling must own vLLM replicas")
    dcgm = documents(
        command(helm, "template", "inf063", CHART, "--set", "dcgm.enabled=true").stdout
    )
    daemon = next(
        x
        for x in dcgm
        if x["kind"] == "DaemonSet" and x["metadata"]["name"] == "dcgm-exporter"
    )
    container = daemon["spec"]["template"]["spec"]["containers"][0]
    compose = yaml.safe_load((ROOT / "deploy/observability/compose.yaml").read_text())
    dcgm_compose = compose["services"]["dcgm-exporter"]
    if container["image"] != dcgm_compose["image"] or not container["image"].endswith(
        "@sha256:60d3b00ac80b4ae77f94dae2f943685605585ad9e92fdccda3154d009ae317cc"
    ):
        raise ValueError("DCGM image pin drift")
    setting = next(
        x["value"] for x in container["env"] if x["name"] == "DCGM_EXPORTER_INTERVAL"
    )
    if (
        setting != "1000"
        or dcgm_compose["environment"]["DCGM_EXPORTER_INTERVAL"] != "1000"
    ):
        raise ValueError("DCGM collection interval drift")
    if container["resources"] != {
        "requests": {"cpu": "100m", "memory": "1Gi"},
        "limits": {"cpu": "500m", "memory": "1Gi"},
    }:
        raise ValueError("DCGM exporter resources drift")
    if daemon["spec"]["template"]["spec"]["nodeSelector"] != {"m5-role": "gpu"}:
        raise ValueError("DCGM node placement")
    return {
        "golden_objects": len(expected),
        "golden_diff_empty": True,
        "lint": True,
        "isolated_value_overrides": ["engine max-num-seqs", "gateway memory limit"],
        "autoscaling_omits_replicas": True,
        "dcgm_offline_valid": True,
    }


def kind_checks(helm, work):
    campaign = Campaign(work)
    campaign.tools = work / "kind-tools"
    campaign.tools.mkdir()
    campaign.install_tools()
    kubeconfig = work / "kind.kubeconfig"
    env = {**os.environ, "KUBECONFIG": str(kubeconfig)}
    keda = download(PINS["keda"], work / "keda.tgz")
    # Install the actual version's CRD to exercise API validation. The operator
    # and external metrics behavior belong to the later T4 rehearsals.
    crds = documents(command(helm, "template", "keda", keda, "--include-crds").stdout)
    scaled_object = next(
        x
        for x in crds
        if x["kind"] == "CustomResourceDefinition"
        and x["metadata"]["name"] == "scaledobjects.keda.sh"
    )
    kind = campaign.kind
    kubectl = campaign.kubectl
    try:
        command(
            kind,
            "create",
            "cluster",
            "--name",
            "inf063",
            "--image",
            campaign.pins["node_image"],
            "--kubeconfig",
            kubeconfig,
            "--wait",
            "180s",
            env=env,
        )
        command(kubectl, "apply", "-f", "-", input=json.dumps(scaled_object), env=env)
        command(
            kubectl,
            "wait",
            "--for=condition=Established",
            "crd/scaledobjects.keda.sh",
            "--timeout=60s",
            env=env,
        )
        command(helm, "install", "inf063-fixed", CHART, "--wait=hookOnly", env=env)
        command(kubectl, "get", "statefulset", "vllm", "-n", NAMESPACE, env=env)
        command(helm, "uninstall", "inf063-fixed", "--wait", env=env)
        opts = [
            "--set",
            "autoscaling.enabled=true",
            "--set-string",
            "autoscaling.threshold=2",
        ]
        command(
            helm, "install", "inf063-scaled", CHART, "--wait=hookOnly", *opts, env=env
        )
        command(
            kubectl,
            "-n",
            NAMESPACE,
            "scale",
            "statefulset/vllm",
            "--replicas=2",
            env=env,
        )
        command(
            helm, "upgrade", "inf063-scaled", CHART, "--wait=hookOnly", *opts, env=env
        )
        readback = json.loads(
            command(
                kubectl,
                "-n",
                NAMESPACE,
                "get",
                "statefulset/vllm",
                "-o",
                "json",
                env=env,
            ).stdout
        )
        if readback["spec"]["replicas"] != 2:
            raise ValueError("Helm reset the scale-subresource value")
        transition = command(
            helm,
            "upgrade",
            "inf063-scaled",
            CHART,
            "--wait=hookOnly",
            "--set",
            "autoscaling.enabled=false",
            env=env,
            check=False,
        )
        if transition.returncode == 0:
            raise ValueError("Helm accepted replica ownership change during upgrade")
        if "change replica ownership" not in transition.stderr:
            raise ValueError(
                "Helm refused upgrade for a reason other than replica ownership"
            )
        command(helm, "uninstall", "inf063-scaled", "--wait", env=env)
        absent = command(kubectl, "get", "namespace", NAMESPACE, env=env, check=False)
        if absent.returncode == 0 or "NotFound" not in absent.stderr:
            raise ValueError("Helm uninstall did not remove managed resources")
    finally:
        command(kind, "delete", "cluster", "--name", "inf063", env=env)
    return {
        "install_uninstall": True,
        "keda_crd_validates": True,
        "scale_subresource_before_after": [2, 2],
        "ownership_change_refused": True,
        "scope": "kind API, KEDA CRD; no KEDA controller or GPU workloads",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("generate", "verify", "kind"))
    parser.add_argument("--work", type=Path)
    args = parser.parse_args()
    if args.mode == "generate":
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(
            json.dumps(composed(), indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        (CHART / "files/dcgm-exporter.json").write_bytes(
            (ROOT / "deploy/eks/dcgm-exporter.json").read_bytes()
        )
        return
    args.work.mkdir()
    helm = install_helm(args.work)
    result = chart_checks(helm)
    if args.mode == "kind":
        result["kind"] = kind_checks(helm, args.work)
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (args.work / "chart-receipt.json").write_text(output, encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
