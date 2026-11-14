"""Read-only independent node witness. Also runnable as a standalone node agent.

No device-free inference from process exit, Pod readiness or a partial inventory.
The driver/image release binding is an explicit input; absent authority refuses.
The nvidia-smi hash detects session changes; it does not authenticate the binary.
"""

import argparse
import hashlib
import hmac
import http.server
import json
import os
import re
import ssl
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

CAP = 8_388_608
GPU = re.compile(r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


class DeviceReadError(ValueError):
    def __init__(self, message, records):
        super().__init__(message)
        self.records = records


def need(condition, reason):
    if not condition:
        raise ValueError("device:" + reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def command(argv, deadline):
    """Bound both pipes before joining bytes, with one absolute read deadline."""
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buffers, errors = [bytearray(), bytearray()], []

    def read(stream, buffer):
        try:
            while data := stream.read1(4096):
                remaining = CAP - len(buffer)
                buffer.extend(data[:remaining])
                need(len(data) <= remaining, "command_size")
        except BaseException as exc:
            errors.append(exc)
            process.kill()

    threads = [
        threading.Thread(target=read, args=(s, b))
        for s, b in zip((process.stdout, process.stderr), buffers, strict=True)
    ]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except BaseException as exc:
        errors.append(exc)
        process.kill()
        process.wait()
    finally:
        for thread in threads:
            thread.join(timeout=1)
            if thread.is_alive():
                errors.append(ValueError("device:command_unsettled"))
        process.stdout.close()
        process.stderr.close()
    if errors or process.returncode != 0 or buffers[1].strip():
        error = DeviceReadError(str(errors[0]) if errors else "device:command_failed_or_stderr", [])
        error.stdout, error.stderr = bytes(buffers[0]), bytes(buffers[1])
        raise error
    return bytes(buffers[0])


def smi_xml(raw, version):
    need(
        len(raw) <= CAP and b"<!ENTITY" not in raw and b"[" not in raw.split(b">", 2)[0],
        "xml_size_or_entity",
    )
    dtd = re.search(rb"<!DOCTYPE[^>]+>", raw)
    need(
        dtd is not None
        and dtd.group() == b'<!DOCTYPE nvidia_smi_log SYSTEM "nvsmi_device_v12.dtd">',
        "xml_layout",
    )
    try:
        root = ET.fromstring(raw)

        def single(parent, tag):
            nodes = parent.findall(tag)
            need(len(nodes) == 1, "xml_layout")
            return nodes[0]

        need(
            root.tag == "nvidia_smi_log" and single(root, "driver_version").text == version,
            "driver_version_or_layout",
        )
        gpus = root.findall("gpu")
        need(int(single(root, "attached_gpus").text) == len(gpus) and bool(gpus), "gpu_inventory")
        ids, processes = [], []
        for gpu in gpus:
            uid = single(gpu, "uuid").text
            need(type(uid) is str and GPU.fullmatch(uid) and uid not in ids, "device_id")
            need(
                single(single(gpu, "mig_mode"), "current_mig").text in ("Disabled", "N/A")
                and not gpu.findall(".//mig_device"),
                "mig_or_shared",
            )
            ids.append(uid)
            listing = single(gpu, "processes")
            need(
                listing is not None and not (listing.text or "").strip(),
                "process_inventory_unknown",
            )
            for item in listing:
                need(len({v.tag for v in item}) == len(item), "xml_layout")
                need(
                    item.tag == "process_info"
                    and {v.tag for v in item}
                    <= {
                        "gpu_instance_id",
                        "compute_instance_id",
                        "pid",
                        "type",
                        "process_name",
                        "used_memory",
                    },
                    "xml_layout",
                )
                need(item.findtext("type") in ("C", "G", "C+G", "O"), "process_type_or_sharing")
                need(
                    all(
                        item.findtext(k) in (None, "N/A")
                        for k in ("gpu_instance_id", "compute_instance_id")
                    ),
                    "mig_or_shared",
                )
                pid = int(item.findtext("pid"))
                need(
                    pid > 0 and item.findtext("process_name") is not None,
                    "process_inventory_unknown",
                )
                processes.append({"device_id": uid, "pid": pid, "type": item.findtext("type")})
        need(
            len({(p["device_id"], p["pid"]) for p in processes}) == len(processes),
            "process_duplicate",
        )
        return sorted(ids), sorted(processes, key=lambda p: (p["device_id"], p["pid"]))
    except (ET.ParseError, TypeError, AttributeError) as exc:
        raise ValueError("device:xml_layout") from exc


def process_start(proc, pid, boot):
    try:
        raw = (proc / str(pid) / "stat").read_text()
        need(int(raw.split("(", 1)[0]) == pid, "pid_identity")
        fields = raw.rsplit(")", 1)[1].split()
        need(fields[0] not in ("Z", "X") and int(fields[19]) > 0, "process_exited")
        return {"pid": pid, "start_ticks": int(fields[19]), "boot_id": boot}
    except (OSError, IndexError, TypeError) as exc:
        raise ValueError("device:process_unknown") from exc


def proc_identity(proc, pid, boot):
    try:
        identity = process_start(proc, pid, boot)
        groups = (proc / str(pid) / "cgroup").read_text()
        containers = set(re.findall(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", groups))
        need(len(containers) == 1, "process_unmapped")
        return {**identity, "container_id": containers.pop()}
    except (OSError, IndexError, TypeError) as exc:
        raise ValueError("device:process_unknown") from exc


class DeviceSource:
    def __init__(self, spec, *, run=command, clock=time.monotonic_ns):
        self.spec, self.run, self.clock = spec, run, clock

    def pinned(self, name):
        item = self.spec[name]
        need(digest(Path(item["path"]).read_bytes()) == item["sha256"], name + "_pin")
        return item["path"]

    def read(self):
        records = []

        def invoke(argv, deadline):
            try:
                raw = self.run(argv, deadline)
            except Exception as exc:
                records.append(
                    {
                        "argv": argv,
                        "stdout_hex": getattr(exc, "stdout", b"").hex(),
                        "stderr_hex": getattr(exc, "stderr", b"").hex(),
                    }
                )
                raise
            records.append({"argv": argv, "stdout_hex": raw.hex()})
            return raw

        try:
            return self._read(invoke)
        except Exception as exc:
            raise DeviceReadError(str(exc), records) from exc

    def first_contact(self):
        """Pre-measurement observation only, not device-free or binary authentication."""
        item = self.spec["nvidia_smi"]
        path = Path(item["path"])
        before = digest(path.read_bytes())
        raw = self.run([str(path), "-q", "-x"], time.monotonic() + 5)
        root = ET.fromstring(raw)
        version = root.findtext("driver_version")
        need(
            type(version) is str and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version),
            "driver_version_unknown",
        )
        smi_xml(raw, version)
        need(digest(path.read_bytes()) == before, "nvidia_smi_pin")
        return {
            "schema": "inf037b-driver-first-contact-v1",
            "node_uid": self.spec["node_uid"],
            "image_release": self.spec["node_image_release"],
            "nvidia_smi_path": str(path),
            "nvidia_smi_sha256": before,
            "driver_version": version,
            "raw_xml": raw.decode(),
            "raw_sha256": digest(raw),
        }

    def _read(self, invoke):
        spec = self.spec
        driver = spec.get("driver")
        need(
            type(driver) is dict and driver.get("image_release") and driver.get("version"),
            "unresolved:node_driver_binding",
        )
        evidence = driver.get("release_evidence")
        need(type(evidence) is dict, "unresolved:node_driver_binding")
        proof_raw = Path(evidence["path"]).read_bytes()
        need(digest(proof_raw) == evidence["sha256"], "driver_release_evidence")
        proof = json.loads(proof_raw)
        need(
            proof["image_release"] == driver["image_release"] == spec["node_image_release"]
            and proof["node_uid"] == spec["node_uid"]
            and proof["driver_version"] == driver["version"]
            and proof["nvidia_smi_sha256"] == spec["nvidia_smi"]["sha256"]
            and proof.get("nvidia_smi_path", spec["nvidia_smi"]["path"])
            == spec["nvidia_smi"]["path"],
            "driver_release_binding",
        )
        proc = Path(spec.get("proc", "/proc"))
        boot_path = proc / "sys/kernel/random/boot_id"
        boot = boot_path.read_text().strip()
        need(boot == spec["boot_id"], "boot_identity")
        # The deployment mounts host /proc separately and sets hostPID. A
        # private PID namespace may never relabel container PIDs as host PIDs.
        need(
            os.stat(proc / "1/ns/pid").st_ino
            == os.stat(spec.get("self_pid_namespace", "/proc/self/ns/pid")).st_ino,
            "pid_namespace",
        )
        begin = self.clock()
        deadline = time.monotonic() + 5
        helper, smi, cri = (self.pinned(n) for n in ("podresources", "nvidia_smi", "crictl"))
        before_raw = invoke([helper, "--socket", spec["podresources_socket"]], deadline)
        before = json.loads(before_raw)
        need(
            before["schema"] == "inf037b-podresources-v1" and before["complete"] is True,
            "allocation_incomplete",
        )
        xml = invoke([smi, "-q", "-x"], deadline)
        ids, processes = smi_xml(xml, driver["version"])
        need(
            ids == sorted(spec["device_ids"]) == sorted(before["device_ids"]),
            "device_inventory_join",
        )
        need(all(GPU.fullmatch(uid) for uid in ids), "device_id")
        base = [cri, "--runtime-endpoint", "unix:///run/containerd/containerd.sock"]
        listing_raw = invoke([*base, "ps", "-a", "--output", "json"], deadline)
        listing = json.loads(listing_raw)
        need(type(listing.get("containers")) is list, "cri_inventory_unknown")
        inspected, inspect_raw = {}, {}

        def inspect(cid):
            need(bool(re.fullmatch("[0-9a-f]{64}", cid)), "container_identity")
            if cid not in inspected:
                raw = invoke([*base, "inspect", "--output", "json", cid], deadline)
                status = json.loads(raw)["status"]
                need(status["id"] == cid, "cri_container_join")
                labels = status["labels"]
                need(
                    all(
                        labels.get(k)
                        for k in (
                            "io.kubernetes.pod.uid",
                            "io.kubernetes.pod.name",
                            "io.kubernetes.pod.namespace",
                        )
                    ),
                    "pod_identity",
                )
                inspected[cid], inspect_raw[cid] = status, raw.decode()
            return inspected[cid]

        allocations = []
        for item in before["allocations"]:
            need(item["device_id"] in ids, "allocation_device")
            matches = [
                c
                for c in listing["containers"]
                if c["labels"].get("io.kubernetes.pod.name") == item["pod"]
                and c["labels"].get("io.kubernetes.pod.namespace") == item["namespace"]
                and c["metadata"]["name"] == item["container"]
            ]
            need(len(matches) == 1, "allocation_unmapped")
            status = inspect(matches[0]["id"])
            need(
                status["labels"]["io.kubernetes.pod.name"] == item["pod"]
                and status["labels"]["io.kubernetes.pod.namespace"] == item["namespace"]
                and status["metadata"]["name"] == item["container"],
                "allocation_pod_join",
            )
            allocations.append(
                {
                    **item,
                    "pod_uid": status["labels"]["io.kubernetes.pod.uid"],
                    "container_id": status["id"],
                }
            )
        need(
            len({a["device_id"] for a in allocations}) == len(allocations),
            "replicated_or_time_sliced",
        )
        mapped = []
        for process in processes:
            original = proc_identity(proc, process["pid"], boot)
            status = inspect(original["container_id"])
            need(proc_identity(proc, process["pid"], boot) == original, "pid_reused")
            mapped.append(
                {**process, **original, "pod_uid": status["labels"]["io.kubernetes.pod.uid"]}
            )
        after_raw = invoke([helper, "--socket", spec["podresources_socket"]], deadline)
        after = json.loads(after_raw)
        need(after["schema"] == "inf037b-podresources-v1", "allocation_incomplete")
        need(
            (before["device_ids"], before["allocations"])
            == (after["device_ids"], after["allocations"])
            and after["complete"] is True,
            "allocation_changed",
        )
        xml_after = invoke([smi, "-q", "-x"], deadline)
        need(smi_xml(xml_after, driver["version"]) == (ids, processes), "process_inventory_changed")
        need(boot_path.read_text().strip() == boot, "boot_changed")
        for name in ("podresources", "nvidia_smi", "crictl"):
            self.pinned(name)
        return {
            "schema": "inf037b-device-raw-v1",
            "complete": True,
            "node_uid": spec["node_uid"],
            "producer_uid": spec["producer_uid"],
            "pins": spec["pins"],
            "device_ids": ids,
            "boot_id": boot,
            "clock_id": "device:" + spec["node_uid"],
            "observation_ns": [begin, self.clock()],
            "allocations": allocations,
            "processes": mapped,
            "source_sha256": digest(Path(__file__).read_bytes().replace(b"\r\n", b"\n")),
            "driver": {
                "path": smi,
                "sha256": spec["nvidia_smi"]["sha256"],
                "version": driver["version"],
                "image_release": driver["image_release"],
                "release_evidence_sha256": evidence["sha256"],
            },
            "raw": {
                "podresources_before": before_raw.decode(),
                "podresources_after": after_raw.decode(),
                "nvidia_smi": xml.decode(),
                "nvidia_smi_after": xml_after.decode(),
                "cri_list": listing_raw.decode(),
                "cri_inspect": inspect_raw,
            },
        }


class DeviceReleaseProducer:
    """Controller-side clock join and publication into the existing report path."""

    def __init__(self, *, owner, source, http, stop_ns):
        from .inf037b_capture import DeadlineHTTP

        self.owner, self.source = owner, source
        self.http = DeadlineHTTP(
            **http, stop_ns=stop_ns, retain=owner.retainer(source["capture_source"])
        )

    def produce(self):
        try:
            return self._produce()
        except Exception as exc:
            self.owner.loss("device:" + str(exc))
            raise

    def _produce(self):
        from .inf037b_archive import strict_json
        from .inf037b_live import ClockAdapter
        from .inf037b_sources import ClockMapper

        rows = self.owner.rows(self.source["capture_source"])

        def clock():
            lo = rows.clock()
            body, _ = self.http.get("/clock")
            hi = rows.clock()
            data = strict_json(body)
            ClockAdapter(rows).mapping(
                self.source["clock_id"], data["boot_id"], data["mono_ns"] // 1_000_000, lo, hi
            )

        clock()
        body, _ = self.http.get("/device")
        raw = strict_json(body)
        clock()
        need(
            raw["schema"] == "inf037b-device-raw-v1" and raw["complete"] is True,
            "report_incomplete",
        )
        for key in (
            "node_uid",
            "producer_uid",
            "pins",
            "device_ids",
            "source_sha256",
            "boot_id",
            "clock_id",
        ):
            need(raw[key] == self.source[key], "report_identity:" + key)
        lower, upper = raw["observation_ns"]
        need(type(lower) is int and type(upper) is int and 0 <= lower <= upper, "observation_clock")
        mapped = ClockMapper(self.owner.clock_rows).map(
            raw["clock_id"], raw["boot_id"], lower // 1_000_000, (upper + 999999) // 1_000_000
        )
        need(mapped is not None, "observation_clock")
        return {
            "schema": "inf037b-device-release-v1",
            **{
                k: raw[k]
                for k in (
                    "node_uid",
                    "producer_uid",
                    "pins",
                    "device_ids",
                    "allocations",
                    "processes",
                    "complete",
                )
            },
            "observation_ms": mapped,
            "raw_sha256": digest(body),
            "source_sha256": raw["source_sha256"],
            "driver": raw["driver"],
        }

    def publish(self, api, path, stop):
        need(path == self.source["report_path"], "report_path")
        report = self.produce()
        current = api.request("GET", path, stop)
        need(
            current["metadata"].get("resourceVersion") and current["metadata"].get("uid"),
            "report_object",
        )
        need(current["metadata"]["uid"] == self.source["report_uid"], "report_object_identity")
        encoded = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
        body = {**current, "data": {"receipt.json": encoded}}
        try:
            api.request("PUT", path, stop, body)
        except (OSError, ValueError):
            pass  # Settle below without repeating the write or physical read.
        settled = api.request("GET", path, stop)
        need(
            settled["metadata"]["uid"] == current["metadata"]["uid"]
            and settled.get("data", {}).get("receipt.json") == encoded,
            "report_publish_unknown",
        )
        return report


def handler(source, token):
    class Handler(http.server.BaseHTTPRequestHandler):
        timeout = 2

        def setup(self):
            # accept() only wraps; an idle TLS peer must occupy one bounded
            # handler thread, never the server's accept loop.
            self.request.settimeout(self.timeout)
            if isinstance(self.request, ssl.SSLSocket):
                self.request.do_handshake()
            super().setup()

        def log_message(self, *args):
            pass

        def do_GET(self):
            try:
                current = token()
                need(bool(current), "token")
                if not hmac.compare_digest(
                    self.headers.get("Authorization", ""), "Bearer " + current
                ):
                    self.send_error(403)
                    return
                if self.path == "/clock":
                    value = {
                        "boot_id": Path(
                            source.spec.get("proc", "/proc"), "sys/kernel/random/boot_id"
                        )
                        .read_text()
                        .strip(),
                        "mono_ns": source.clock(),
                    }
                elif self.path == "/first-contact":
                    value = source.first_contact()
                else:
                    need(self.path in ("/device", "/ready"), "path")
                    value = source.read()
                body = (json.dumps(value, sort_keys=True) + "\n").encode()
                need(len(body) <= CAP, "http_size")
            except DeviceReadError as exc:
                body = (
                    json.dumps(
                        {
                            "schema": "inf037b-device-error-v1",
                            "complete": False,
                            "error": str(exc),
                            "records": exc.records,
                        }
                    )
                    + "\n"
                ).encode()
                truncated = len(body) > CAP
                body = body[:CAP]
                self.send_response(503)
                self.send_header("X-Capture-Truncated", str(truncated).lower())
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            except Exception as exc:
                self.send_error(503, str(exc))
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def token_reader(path):
    def read():
        value = Path(path).read_text().strip()
        need(bool(value), "token")
        return value

    read()  # Refuse before binding/listening, and again on every request.
    return read


def device_server(spec, address=("0.0.0.0", 9103)):
    token = token_reader(spec["token_path"])
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(spec["tls_cert"], spec["tls_key"])
    server = http.server.ThreadingHTTPServer(address, handler(DeviceSource(spec), token))
    try:
        server.socket = tls.wrap_socket(
            server.socket, server_side=True, do_handshake_on_connect=False
        )
    except BaseException:
        server.server_close()
        raise
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_bytes())
    need(spec["node_name"] == os.environ["NODE_NAME"], "node_identity")
    spec["producer_uid"] = os.environ["POD_UID"]
    with device_server(spec) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
