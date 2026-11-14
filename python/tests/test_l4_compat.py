"""$0 packet, timing, evidence and independent hard-stop checks; no model smoke."""

import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.inf037b_controls import CONTROL_PAYLOADS, control_slot
from inference_platform.l4_compat import (
    CAP_USD,
    DEADLINE_S,
    HOST_TIMER_S,
    measured_booking,
    native_summary,
    read_summary,
    requests,
    worksheet,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
if os.environ.get("L4_SCRIPT_OVERLAY"):
    sys.path.insert(0, os.environ["L4_SCRIPT_OVERLAY"])
from l4_compat_controller import execute, preflight  # noqa: E402
from l4_compat_deadline import supervise  # noqa: E402
from l4_compat_service import L4Host  # noqa: E402


def stream_reads():
    def frame(delta, finish=None):
        return (
            "data: "
            + json.dumps({"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]})
            + "\n\n"
        ).encode()

    bodies = [
        frame({"content": "one"}),
        frame({"content": " two"}),
        frame({}, "length"),
        b'data: {"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":256,"total_tokens":257,"count_source":"runtime_usage"}}\n\n',
        b"data: [DONE]\n\n",
    ]
    return [
        {"bracket_ns": [i * 1_000_000_000, i * 1_000_000_000 + 100], "hex": b.hex()}
        for i, b in enumerate(bodies, 1)
    ]


def native_events(cancel=True):
    rows = [
        {"event": "identity", "internal": "i", "external": "chatcmpl-g"},
        {"event": "accept", "internal": "i", "mono_ns": 1},
    ]
    if cancel:
        rows += [
            {"event": "abort_intent", "internal": "i", "mono_ns": 3, "cause": "CancelledError"},
            {"event": "abort_ack", "internal": "i", "mono_ns": 5},
        ]
    end = {
        "event": "native_end",
        "internal": "i",
        "mono_ns": 4,
        "status": "FINISHED_ABORTED" if cancel else "FINISHED_LENGTH_CAPPED",
        "abort_rpc": cancel,
    }
    return rows + [
        end,
        {
            "event": "terminal",
            "internal": "i",
            "mono_ns": 6,
            "terminal": end,
            "terminal_reason": "client_cancel_abort" if cancel else "length",
        },
    ]


class PacketTests(unittest.TestCase):
    def test_overlay_matches_canonical_release_bytes_from_lf_and_crlf_checkouts(self):
        from inference_platform import inf037b_native as native

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classes = {name: cls for name, cls in native.TARGETS.values()}
            canonical = {
                name: ("class " + classes.get(name, "Serving") + ":\n    pass\n").encode()
                for name in native.BASE_FILES
            }
            pins = {name: hashlib.sha256(data).hexdigest() for name, data in canonical.items()}
            manifests = []
            with patch.dict(native.BASE_FILES, pins, clear=True):
                for ending in ("lf", "crlf"):
                    source = root / ending
                    for name, data in canonical.items():
                        path = source / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(data if ending == "lf" else data.replace(b"\n", b"\r\n"))
                    output = root / (ending + "-overlay")
                    manifests.append(native.build_overlay(source, output))
                    for name in canonical:
                        self.assertNotIn(b"\r\n", (output / name).read_bytes())
                self.assertEqual(manifests[0], manifests[1])
                first = next(iter(canonical))
                (root / "lf" / first).write_bytes(b"changed\n")
                with self.assertRaisesRegex(ValueError, "base_sources"):
                    native.build_overlay(root / "lf", root / "bad-overlay")

    def test_execution_owner_hash_refuses_before_review_or_provider_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "terraform").mkdir()
            (root / "terraform/create.tfplan").write_bytes(b"sealed")
            plan = hashlib.sha256(b"sealed").hexdigest()
            (root / "manifest.json").write_text(
                json.dumps({"sealed_plans": {"create_sha256": plan}})
            )
            args = SimpleNamespace(
                directory=root, owner_approved_hash="wrong", review_target="unapproved"
            )
            with (
                patch(
                    "l4_compat_controller.validate_review_marker",
                    side_effect=AssertionError("review reached"),
                ),
                patch("l4_compat_controller.L4Ports") as ports,
            ):
                with self.assertRaisesRegex(ValueError, "owner_exact_hash"):
                    execute(args)
                ports.assert_not_called()

    def test_future_preflight_enforces_shape_inventory_quota_and_complete_price_ceiling(self):
        from inference_platform.l4_compat import PINS

        answers = {
            "ami": {"Images": [{"ImageId": PINS["ami"], "State": "available"}]},
            "shape": {
                "InstanceTypes": [
                    {
                        "InstanceType": "g6.xlarge",
                        "VCpuInfo": {"DefaultVCpus": 4},
                        "GpuInfo": {"Gpus": [{"Name": "L4", "Count": 1}]},
                    }
                ]
            },
            "offerings": {
                "InstanceTypeOfferings": [{"Location": PINS["zone"], "InstanceType": "g6.xlarge"}]
            },
            "quota": {"Quota": {"Value": 4}},
            "instances": {"Reservations": []},
        }
        for name, unit, price in (
            ("compute", "Hrs", 0.8048),
            ("gp3", "GB-Mo", 0.08),
            ("ipv4", "Hrs", 0.005),
        ):
            answers[name] = {
                "PriceList": [
                    json.dumps(
                        {
                            "terms": {
                                "OnDemand": {
                                    "sku": {
                                        "priceDimensions": {
                                            "rate": {
                                                "unit": unit,
                                                "pricePerUnit": {"USD": str(price)},
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    )
                ]
            }
        manifest = {
            "preflight_queries": {name: [name, "read"] for name in answers},
            "hourly_all_resources_usd": 2,
        }
        with tempfile.TemporaryDirectory() as directory:
            ports = SimpleNamespace(
                runtime=Path(directory), aws=lambda service, operation, args: answers[service]
            )
            preflight(ports, manifest)
            self.assertLess(
                json.loads((ports.runtime / "preflight-result.json").read_bytes())["hourly_usd"], 2
            )
            with self.assertRaisesRegex(ValueError, "price_ceiling"):
                preflight(ports, {**manifest, "hourly_all_resources_usd": 0.01})
            answers["quota"]["Quota"]["Value"] = 3
            with self.assertRaisesRegex(ValueError, "gvt_quota"):
                preflight(ports, manifest)

    def test_exact_seven_requests_preserve_controls_and_sequential_slot_aliases(self):
        rows = requests()
        self.assertEqual(len(rows), 7)
        self.assertEqual(sum(r.get("refusal", False) for r in rows), 1)
        self.assertEqual(sum(r["cancel"] and not r.get("refusal") for r in rows), 2)
        self.assertEqual(sum(not r["cancel"] for r in rows), 4)
        for row in rows:
            if not row.get("refusal"):
                self.assertEqual(row["payload"], CONTROL_PAYLOADS[row["id"]])
                self.assertEqual(row["slot"], control_slot(row["id"]))
        self.assertEqual([r["slot"] for r in rows], [0] * 5 + [1] * 2)

    def test_deadline_books_startup_freeze_export_and_cleanup_under_cost_cap(self):
        value = worksheet(3_000_000)
        self.assertEqual(value["forecast_wall_seconds"], 3946)
        self.assertEqual(value["deadline_seconds"], DEADLINE_S)
        self.assertLessEqual(
            value["forecast_wall_seconds"] - value["cleanup_seconds"], HOST_TIMER_S
        )
        self.assertLess(value["forecast_usd"], CAP_USD)
        self.assertEqual(value["export_seconds"], 196)
        with self.assertRaisesRegex(ValueError, "upload_reserve"):
            worksheet(1024**3)
        with patch("inference_platform.l4_compat.CAP_USD", 1):
            with self.assertRaisesRegex(ValueError, "cost_cap"):
                worksheet(3_000_000)

    def test_separate_reads_keep_brackets_and_decode_measurement(self):
        result = read_summary(stream_reads(), completed=True, tokens=256)
        self.assertTrue(result["decoder"]["complete"])
        self.assertEqual(result["decode_tokens_per_second"], 127.5)
        self.assertLess(result["first_content_ns"][1], result["finish_ns"][0])
        self.assertLess(result["first_content_ns"][1], result["done_ns"][0])

    def test_coalesced_finish_or_overlapping_brackets_refuse(self):
        rows = stream_reads()
        rows[0]["hex"] += rows[1]["hex"] + rows[2]["hex"]
        del rows[1:3]
        with self.assertRaisesRegex(ValueError, "separate_content_finish"):
            read_summary(rows, completed=True, tokens=256)
        rows = stream_reads()
        rows[1]["bracket_ns"][0] = rows[0]["bracket_ns"][1] - 1
        with self.assertRaisesRegex(ValueError, "read_order"):
            read_summary(rows, completed=True, tokens=256)

    def test_native_abort_requires_api_intent_ack_rpc_and_actual_scheduler_free(self):
        result = native_summary(native_events(), external="chatcmpl-g", cancel_ns=2)
        self.assertEqual(result["cancellation_to_native_abort_ms"], 0.000002)
        self.assertEqual(
            native_summary(native_events(False), external="chatcmpl-g")["events"]["native_end"][
                "status"
            ],
            "FINISHED_LENGTH_CAPPED",
        )
        for kind in ("abort_intent", "abort_ack", "native_end", "terminal"):
            with self.subTest(missing=kind):
                with self.assertRaisesRegex(ValueError, "native_end|native_api_abort"):
                    native_summary(
                        [e for e in native_events() if e["event"] != kind],
                        external="chatcmpl-g",
                        cancel_ns=2,
                    )
        for field, value in (("status", "FINISHED_LENGTH_CAPPED"), ("abort_rpc", False)):
            rows = native_events()
            rows[-2][field] = value
            with self.assertRaisesRegex(ValueError, "native_abort_rpc_free"):
                native_summary(rows, external="chatcmpl-g", cancel_ns=2)

    def test_native_pid_start_source_ancestry_and_roles_are_joined(self):
        from inference_platform.inf037b_native import TARGETS

        origin = {"supervisor_pid": 10, "supervisor_start": "1"}
        manifest = {"files": {path: "a" * 64 for path, _ in TARGETS.values()}}
        rows = [
            {"event": "installed", "kind": role, "source_sha256": "a" * 64} for role in TARGETS
        ] + native_events()
        for row in rows:
            row.update(
                pid=11,
                process_start="2",
                ancestry=[{"pid": 11, "start": "2"}, {"pid": 10, "start": "1"}],
            )
        native_summary(rows, external="chatcmpl-g", cancel_ns=2, manifest=manifest, origin=origin)
        for fault in ("pid", "source", "ancestry"):
            broken = copy.deepcopy(rows)
            if fault == "pid":
                broken[4]["process_start"] = "3"
            elif fault == "source":
                broken[0]["source_sha256"] = "b" * 64
            else:
                broken[-1]["ancestry"][-1]["start"] = "wrong"
            with self.assertRaisesRegex(ValueError, "native_ancestry|native_source|native_role"):
                native_summary(
                    broken, external="chatcmpl-g", cancel_ns=2, manifest=manifest, origin=origin
                )

    def test_control_length_decision_uses_measurements_without_a_second_request_set(self):
        self.assertTrue(measured_booking([3, 4, 5, 6, 0.2, 0.3])["fits_request_timeout"])
        self.assertFalse(measured_booking([20, 19, 18, 17, 0.2, 0.3])["fits_request_timeout"])
        with self.assertRaisesRegex(ValueError, "control_durations"):
            measured_booking([float("nan")] * 6)

    def test_complete_export_never_truncates_a_large_evidence_file(self):
        with tempfile.TemporaryDirectory() as directory:
            host = L4Host(directory, "token", "a" * 64, time.time() + 60, origin=time.time())
            with self.assertRaisesRegex(ValueError, "complete_export_only"):
                host._write_archive(
                    Path(directory) / "a.tar.gz", [], truncated=[{"path": "native.sqlite"}]
                )

    def test_transfer_stage_verifies_hashes_and_refuses_traversal_and_reuse(self):
        for fault in (None, "hash", "traversal", "source"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                host = L4Host(root, "token", "a" * 64, time.time() + 60, origin=time.time())
                body = b"source\n"
                manifest = {
                    "source.py": {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                }
                with tarfile.open(host.partial, "w:gz") as archive:
                    for name, data in (
                        (
                            "../escape" if fault == "traversal" else "source.py",
                            b"wrong!\n" if fault == "source" else body,
                        ),
                        ("sources.json", json.dumps(manifest).encode()),
                    ):
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
                host.manifest = {
                    "bundle_sha256": "f" * 64
                    if fault == "hash"
                    else hashlib.sha256(host.partial.read_bytes()).hexdigest()
                }
                if fault:
                    with self.assertRaisesRegex(
                        ValueError, "payload_hash|payload_inventory|staged_sources"
                    ):
                        host.dispatch("/stage", b"", {})
                else:
                    self.assertTrue(host.dispatch("/stage", b"", {})["staged"])
                    with self.assertRaisesRegex(ValueError, "stage_once"):
                        host.dispatch("/stage", b"", {})

    def test_independent_deadline_stops_controller_and_runs_cleanup_then_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "cleanup.json"
            commands = {
                "controller": [sys.executable, "-c", "import time; time.sleep(60)"],
                "cleanup": [
                    sys.executable,
                    "-c",
                    "import json,os,pathlib; pathlib.Path("
                    + repr(str(marker))
                    + ").write_text(json.dumps({'origin':os.environ['L4_T0_EPOCH']}))",
                ],
                "inventory": [
                    sys.executable,
                    "-c",
                    "import pathlib; assert pathlib.Path(" + repr(str(marker)) + ").is_file()",
                ],
            }
            result = supervise(commands, root / "result", work_seconds=0.2, cleanup_seconds=4)
            self.assertTrue(result["cutoff"])
            self.assertEqual(result["cleanup_exit"], 0)
            self.assertEqual(result["inventory_exit"], 0)
            self.assertFalse(result["complete"])
            from inference_platform.session_stop import pid_is_running

            alive = pid_is_running(result["controller_pid"])
            try:
                self.assertFalse(alive, "controller survived independent stop")
            finally:
                if alive:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/PID", str(result["controller_pid"]), "/T", "/F"],
                            capture_output=True,
                        )
                    else:
                        import signal

                        os.killpg(result["controller_pid"], signal.SIGKILL)
            self.assertEqual(float(json.loads(marker.read_bytes())["origin"]), result["t0_epoch"])
            self.assertLess(result["elapsed_seconds"], 4.2)

    def test_independent_inventory_runs_when_cleanup_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "inventory"
            result = supervise(
                {
                    "controller": [sys.executable, "-c", "pass"],
                    "cleanup": [sys.executable, "-c", "raise SystemExit(3)"],
                    "inventory": [
                        sys.executable,
                        "-c",
                        "import pathlib; pathlib.Path(" + repr(str(marker)) + ").touch()",
                    ],
                },
                root / "result",
                work_seconds=3,
                cleanup_seconds=3,
            )
            self.assertEqual(result["cleanup_exit"], 3)
            self.assertEqual(result["inventory_exit"], 0)
            self.assertTrue(marker.is_file())
            self.assertFalse(result["complete"])


if __name__ == "__main__":
    unittest.main()
