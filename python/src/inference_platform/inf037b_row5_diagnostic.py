"""Run the separate row 5 diagnostic under the retained capture owner.

The caller must obtain both gateway configurations from independently verified
live sources and prove the measured-tenant inventory before invoking this port.
This adapter alone is not an equivalence or readiness decision.
"""

import copy
import ipaddress
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from .inf037b_archive import IntegrityError, encode, sha, strict_json
from .inf037b_bounded import diagnostic_process
from .inf037b_row5 import check_reservation_partition

DIAGNOSTIC_PROCESS_TIMEOUT_S = 5


def parse_dial_addr(value):
    if not isinstance(value, str) or not value:
        raise IntegrityError("fitness:diagnostic_dial_addr")
    try:
        parsed = urlsplit("//" + value)
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise IntegrityError("fitness:diagnostic_dial_addr") from exc
    if (
        not host
        or not _valid_dial_host(host)
        or port is None
        or not 1 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise IntegrityError("fitness:diagnostic_dial_addr")
    return host, port


def _valid_dial_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    hostname = host[:-1] if host.endswith(".") else host
    if not hostname or len(hostname) > 253:
        return False
    for label in hostname.split("."):
        if (
            not 1 <= len(label) <= 63
            or not label.isascii()
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (char.isalnum() or char == "-") for char in label)
        ):
            return False
    return True


def validate_receipt(receipt, reservation_id):
    if (
        not isinstance(receipt, dict)
        or set(receipt) != {"reservation_id", "decision", "capacity", "released"}
        or receipt["reservation_id"] != reservation_id
        or receipt["decision"]
        not in (
            "allowed",
            "system_capacity",
            "tenant_rate_limit",
            "tenant_concurrency_limit",
            "capacity_reports_expired",
        )
        or type(receipt["capacity"]) is not int
        or receipt["capacity"] < 0
        or type(receipt["released"]) is not bool
        or receipt["released"] != (receipt["decision"] == "allowed")
    ):
        raise IntegrityError("fitness:diagnostic_receipt")
    check_reservation_partition([], [receipt])
    return receipt


def diagnostic_receipts_from_capture(
    root,
    descriptor,
    *,
    expected_binding,
    expected_operation,
    expected_descriptor_sha256,
    source,
    source_generation,
    binary_sha256,
    gateway_configs,
):
    """Verify the closed spool and its process receipts against trusted inputs.

    The caller obtains the operation and descriptor hash from the durable store
    and derives gateway_configs independently from live gateway configuration.
    """
    from .inf037b_capture import wire_records
    from .inf037b_probe import capture_rows

    if (
        not isinstance(descriptor, dict)
        or not isinstance(expected_binding, dict)
        or not expected_binding
        or not isinstance(expected_operation, dict)
        or not expected_operation
        or not isinstance(expected_descriptor_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_descriptor_sha256) is None
        or sha(encode(descriptor)) != expected_descriptor_sha256
        or not isinstance(descriptor.get("sources"), dict)
        or descriptor.get("closed") is not True
        or descriptor.get("transport_clean") is not True
        or descriptor.get("binding") != expected_binding
        or descriptor.get("operation") != expected_operation
        or descriptor.get("attempt") != "setup"
        or not isinstance(source, str)
        or not source
        or not isinstance(source_generation, str)
        or not source_generation
        or descriptor["sources"].get(source) != [["controller", "operator", source_generation]]
        or not isinstance(expected_operation.get("body"), dict)
        or expected_operation["body"].get("binding") != expected_binding
        or not isinstance(expected_operation["body"].get("capture"), dict)
        or expected_operation["body"]["capture"].get("sources") != descriptor["sources"]
        or expected_operation["body"]["capture"].get("attempt") != "setup"
        or expected_operation["body"]["capture"].get("boot_id") != descriptor.get("boot_id")
        or not isinstance(binary_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", binary_sha256) is None
        or not isinstance(gateway_configs, dict)
        or set(gateway_configs) != {"gateway0", "gateway1"}
    ):
        raise IntegrityError("fitness:diagnostic_capture_descriptor")
    for _ in capture_rows(Path(root), descriptor):
        pass
    records = [
        (record, body)
        for record, body in wire_records(Path(root) / "wire")
        if record.get("source") == source
    ]
    if not records or len(records) % 2:
        raise IntegrityError("fitness:diagnostic_capture_incomplete")
    receipts = []
    previous_end = -1
    previous_sequence = -1
    offset = 0
    for index in range(0, len(records), 2):
        intent, terminal = records[index : index + 2]
        for record, body in (intent, terminal):
            if (
                record.get("operation_sha256") != sha(encode(expected_operation))
                or type(record.get("sequence")) is not int
                or record["sequence"] <= previous_sequence
                or type(record.get("start_ns")) is not int
                or type(record.get("end_ns")) is not int
                or not previous_end <= record["start_ns"] <= record["end_ns"]
                or record.get("offset") != offset
                or record.get("length") != len(body)
                or record.get("sha256") != sha(body)
                or not isinstance(record.get("metadata"), dict)
            ):
                raise IntegrityError("fitness:diagnostic_capture_incomplete")
            previous_sequence, previous_end = record["sequence"], record["end_ns"]
            offset += len(body)
        im, tm = intent[0]["metadata"], terminal[0]["metadata"]
        if (
            im.get("event") != "diagnostic_intent"
            or im.get("binary_sha256") != binary_sha256
            or tm.get("event") != "diagnostic_terminal"
            or tm.get("returncode") != 0
            or tm.get("error")
            or tm.get("stderr_hex") != ""
            or terminal[0]["end_ns"] - terminal[0]["start_ns"] > 5_000_000_000
            or len(intent[1]) > 16_384
            or len(terminal[1]) > 16_384
        ):
            raise IntegrityError("fitness:diagnostic_capture_incomplete")
        request, receipt = strict_json(intent[1]), strict_json(terminal[1])
        if not isinstance(request, dict) or set(request) != {
            "config",
            "gateway0",
            "gateway1",
            "dial_addr",
            "reservation_id",
        }:
            raise IntegrityError("fitness:diagnostic_config_mismatch")
        try:
            parse_dial_addr(request["dial_addr"])
        except IntegrityError as exc:
            raise IntegrityError("fitness:diagnostic_config_mismatch") from exc
        if (
            request["gateway0"] != gateway_configs["gateway0"]
            or request["gateway1"] != gateway_configs["gateway1"]
            or request["config"] != gateway_configs["gateway0"]
            or request["config"] != gateway_configs["gateway1"]
            or im.get("dial_addr") != request["dial_addr"]
        ):
            raise IntegrityError("fitness:diagnostic_config_mismatch")
        validate_receipt(receipt, request["reservation_id"])
        receipts.append(
            {
                **receipt,
                "intent_sha256": sha(intent[1]),
                "receipt_sha256": sha(terminal[1]),
                "process_start_ns": terminal[0]["start_ns"],
                "process_end_ns": terminal[0]["end_ns"],
            }
        )
    check_reservation_partition([], receipts)
    return receipts


class DiagnosticProcess:
    """Bound the actual command and retain its intent and terminal receipt."""

    def __init__(
        self,
        *,
        binary,
        binary_sha256,
        capture,
        source,
        redis,
        dial_addr,
        clock=time.monotonic_ns,
    ):
        self.binary, self.binary_sha256 = Path(binary), binary_sha256
        parse_dial_addr(dial_addr)
        self.capture, self.source, self.redis, self.dial_addr, self.clock = (
            capture,
            source,
            redis,
            dial_addr,
            clock,
        )
        self.receipts = []
        self.receipt_hashes = {}
        self.used = set()

    def run_from_captures(
        self, *, config, gateway_captures, measured_tenants, reservation_id, deadline_ns
    ):
        """Join both retained gateway configurations before running a diagnostic.

        Each capture argument contains independently trusted operation/binding
        pins, the descriptor and its durable-store hash, and the source boot.
        """
        from .inf037b_row5_capture import gateway_resolved_config_from_capture

        config, gateway_captures, measured_tenants = copy.deepcopy(
            (config, gateway_captures, measured_tenants)
        )
        if not isinstance(gateway_captures, dict) or set(gateway_captures) != {
            "gateway0",
            "gateway1",
        }:
            raise IntegrityError("fitness:diagnostic_config_mismatch")
        configurations = {}
        boots, operations, bindings = [], [], []
        for gateway in ("gateway0", "gateway1"):
            item = gateway_captures[gateway]
            if not isinstance(item, dict) or set(item) != {
                "root",
                "descriptor",
                "expected_binding",
                "expected_operation",
                "expected_descriptor_sha256",
                "source",
                "gateway_boot",
            }:
                raise IntegrityError("fitness:diagnostic_config_mismatch")
            configurations[gateway] = gateway_resolved_config_from_capture(
                item["root"],
                item["descriptor"],
                expected_binding=item["expected_binding"],
                expected_operation=item["expected_operation"],
                expected_descriptor_sha256=item["expected_descriptor_sha256"],
                source=item["source"],
                gateway_uid=gateway,
                gateway_boot=item["gateway_boot"],
            )
            boots.append(item["gateway_boot"])
            operations.append(item["expected_operation"])
            bindings.append(item["expected_binding"])
        if boots[0] == boots[1] or operations[0] != operations[1] or bindings[0] != bindings[1]:
            raise IntegrityError("fitness:diagnostic_config_mismatch")
        return self._run(
            config=config,
            gateway_configs=configurations,
            measured_tenants=measured_tenants,
            reservation_id=reservation_id,
            deadline_ns=deadline_ns,
        )

    def _run(self, *, config, gateway_configs, measured_tenants, reservation_id, deadline_ns):
        check_reservation_partition([], [{"reservation_id": reservation_id}])
        if reservation_id in self.used:
            raise IntegrityError("fitness:diagnostic_receipt_duplicate")
        if (
            not isinstance(measured_tenants, (list, tuple, set))
            or not measured_tenants
            or any(not isinstance(t, str) or not t for t in measured_tenants)
            or "row5-diagnostic" in measured_tenants
        ):
            raise IntegrityError("fitness:diagnostic_tenant_overlap")
        if (
            not isinstance(config, dict)
            or not isinstance(gateway_configs, dict)
            or set(gateway_configs) != {"gateway0", "gateway1"}
            or any(gateway_configs[g] != config for g in gateway_configs)
        ):
            raise IntegrityError("fitness:diagnostic_config_mismatch")
        keys = {
            "redis_addr",
            "namespace",
            "global_capacity",
            "lease_ms",
            "tombstone_ms",
            "running",
            "waiting",
            "ttl_ms",
            "hold_ms",
            "capture",
        }
        if (
            set(config) != keys
            or any(
                not isinstance(config[k], str) or not config[k] for k in ("redis_addr", "namespace")
            )
            or any(
                type(config[k]) is not int or config[k] <= 0
                for k in ("global_capacity", "lease_ms", "tombstone_ms")
            )
            or any(config[k] > 86_400_000 for k in ("lease_ms", "tombstone_ms"))
            or any(type(config[k]) is not int for k in ("running", "waiting", "ttl_ms", "hold_ms"))
            or (
                config["running"],
                config["waiting"],
                config["ttl_ms"],
                config["hold_ms"],
                config["capture"],
            )
            != (4, 1, 8000, 2000, True)
            or type(config["capture"]) is not bool
        ):
            raise IntegrityError("fitness:diagnostic_config_mismatch")
        if (
            not isinstance(self.binary_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.binary_sha256) is None
            or not self.binary.is_file()
            or sha(self.binary.read_bytes()) != self.binary_sha256
        ):
            raise IntegrityError("fitness:diagnostic_binary")
        now = self.clock()
        if type(deadline_ns) is not int or now >= deadline_ns:
            raise IntegrityError("fitness:diagnostic_deadline")
        payload = encode(
            {
                "config": config,
                "gateway0": gateway_configs["gateway0"],
                "gateway1": gateway_configs["gateway1"],
                "dial_addr": self.dial_addr,
                "reservation_id": reservation_id,
            }
        )
        # Persist the unique intent before execution. Any ambiguous error is
        # terminal for this process instance and must never be retried.
        self.used.add(reservation_id)
        self.capture.complete(
            self.source,
            now,
            self.clock(),
            payload,
            {
                "event": "diagnostic_intent",
                "binary_sha256": self.binary_sha256,
                "dial_addr": self.dial_addr,
            },
        )
        start = self.clock()
        if start >= deadline_ns:
            raise IntegrityError("fitness:diagnostic_deadline")
        try:
            result = diagnostic_process(
                [str(self.binary)],
                input=payload,
                timeout=min(DIAGNOSTIC_PROCESS_TIMEOUT_S, (deadline_ns - start) / 1_000_000_000),
                capture=self.capture,
                source=self.source,
                clock=self.clock,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            end = self.clock()
            output = getattr(exc, "stdout", None) or b""
            stderr = getattr(exc, "stderr", None) or b""
            self.capture.complete(
                self.source,
                start,
                end,
                output,
                {
                    "event": "diagnostic_terminal",
                    "error": type(exc).__name__,
                    "stderr_hex": stderr.hex(),
                },
            )
            raise IntegrityError("fitness:diagnostic_process") from exc
        end = self.clock()
        self.capture.complete(
            self.source,
            start,
            end,
            result.stdout,
            {
                "event": "diagnostic_terminal",
                "returncode": result.returncode,
                "stderr_hex": result.stderr.hex(),
            },
        )
        if (
            end > deadline_ns
            or end - start > DIAGNOSTIC_PROCESS_TIMEOUT_S * 1_000_000_000
            or result.returncode != 0
            or len(result.stdout) > 16384
        ):
            raise IntegrityError("fitness:diagnostic_process")
        receipt = validate_receipt(strict_json(result.stdout), reservation_id)
        self.receipt_hashes[reservation_id] = sha(result.stdout)
        self.redis.register_diagnostic(receipt)
        self.receipts.append(copy.deepcopy(receipt))
        return copy.deepcopy(receipt)
