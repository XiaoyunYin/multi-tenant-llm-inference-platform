"""Per-cycle R590 and KEDA Helm lifecycle on a plan-bound cluster context."""

import hashlib
import json
import re
import time
from contextlib import contextmanager

from inf054_autoscaling import keda_image_refs, keda_values
from inf063_chart import CHART, PINS, command, documents


class HelmReleases:
    def __init__(
        self,
        helm,
        config,
        context,
        work,
        namespace,
        backend,
        *,
        invoke=command,
        rendered=None,
    ):
        self.base = (str(helm), "--kubeconfig", str(config), "--kube-context", context)
        self.work = work
        self.namespace = namespace
        self.backend = backend
        self.invoke = invoke
        self.rendered = rendered

    def call(self, end, *args):
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError("inf054_helm_deadline")
        return self.invoke(*self.base, *args, timeout=left)

    @contextmanager
    def keda(self, archive, *, install_end, cleanup_end):
        pin = PINS["keda"]
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != pin["sha256"]:
            raise ValueError("inf054_keda_chart_digest")
        values = self.work / "keda-pins.json"
        with values.open("x", encoding="utf-8") as file:
            json.dump(keda_values(), file)
        args = ("keda", str(archive), "--namespace", "keda", "--values", str(values))
        rendered = documents(self.call(install_end, "template", *args).stdout)
        images = {
            container["image"]
            for obj in rendered
            if obj["kind"] == "Deployment"
            for container in obj["spec"]["template"]["spec"]["containers"]
        }
        if images != keda_image_refs():
            raise ValueError("inf054_keda_image_pins")
        started = time.monotonic()
        try:
            self.call(install_end, "install", *args, "--create-namespace", "--wait")
            yield {
                "status": "installed",
                "chart_sha256": digest,
                "images": sorted(images),
                "elapsed_s": time.monotonic() - started,
            }
        finally:
            self.call(
                cleanup_end,
                "uninstall",
                "keda",
                "--namespace",
                "keda",
                "--ignore-not-found",
                "--wait",
            )

    @contextmanager
    def release(self, arm, number, values, end):
        # The DEC-100 binding owns namespace creation, credentials and cleanup.
        # Namespaces differ across cycles so Redis and emptyDir state reset.
        with self.namespace(arm, number, end) as prepared:
            namespace = prepared.name
            if not re.fullmatch(r"mti-[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9])?", namespace):
                raise ValueError("inf054_release_namespace")
            overrides = self.work / (namespace + ".json")
            with overrides.open("x", encoding="utf-8") as out:
                json.dump(
                    {
                        **prepared.values,
                        **values,
                        "namespace": namespace,
                        "manageNamespace": False,
                    },
                    out,
                )
            args = (
                "inf054",
                str(CHART),
                "--namespace",
                namespace,
                "--values",
                str(overrides),
            )
            rendered = self.call(end, "template", *args)
            if self.rendered is not None:
                prepared.engine_readiness_s = self.rendered(documents(rendered.stdout))
            try:
                self.call(end, "install", *args, "--wait=hookOnly")
                with self.backend(prepared, end) as backend:
                    yield backend
            finally:
                self.call(
                    prepared.cleanup_end,
                    "uninstall",
                    "inf054",
                    "--namespace",
                    namespace,
                    "--ignore-not-found",
                    "--wait",
                )
