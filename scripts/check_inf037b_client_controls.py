"""Round278 mutation sweep: new/changed controls and client durability only."""

import argparse
import json
import tempfile
from pathlib import Path

from check_inf037b_capture import hashes
from check_inf037b_command import ROOT, SOURCE, run
from check_inf037b_probe_go import run as go_run

PROBE = "test_inf037b_probe.ProbeTests."
CAPTURE = "test_inf037b_capture.CaptureTests."
SOCKET = (
    PROBE + "test_tls_sse_cancel_and_already_finished_control_retain_original_bytes"
)
WATERMARK = (
    CAPTURE + "test_group_barrier_watermarks_do_not_hold_owner_lock_or_lose_appends"
)
ORDER = (
    CAPTURE + "test_archive_slot_and_rejected_row_barriers_precede_completion_and_loss"
)
SCHEDULE = PROBE + "test_single_fixed_probe_schedule_controls_and_irrevocable_intent"


def cases():
    yield (
        "inf037b_probe.py",
        "probe intent fsync under owner lock",
        "\n        with self.owner.io_lock, self.store.lock():",
        "\n        with self.owner.lock, self.store.lock():",
        [PROBE + "test_probe_intent_serializes_with_capture_loss_on_the_same_store"],
    )
    yield (
        "inf037b_probe.py",
        "probe completion fsync under owner lock",
        "\n            with self.owner.io_lock, self.store.lock():",
        "\n            with self.owner.lock, self.store.lock():",
        [SCHEDULE],
    )
    for reason, original in (
        (
            "control credential inventory",
            'exact(set(control_credentials), {0, 1}, "probe:control_credentials")',
        ),
        (
            "control payload hash pin",
            'exact(sha(encode(self.control_payloads)), CONTROL_PAYLOADS_SHA256, "probe:control_pin")',
        ),
    ):
        yield (
            "inf037b_probe.py",
            reason + " removed",
            original,
            "pass",
            [PROBE + "test_control_payload_pin_and_credential_inventory_refuse"],
        )
    yield (
        "inf037b_capture.py",
        "unregistered client group spacing refusal restored",
        "                    self.group_barrier()\n                    last, tick",
        '                    require(now - last <= 250_000_000, "capture:client_barrier_cadence")\n                    self.group_barrier()\n                    last, tick',
        [CAPTURE + "test_owner_records_client_group_tick_gap_without_refusal"],
    )
    yield (
        "inf037b_probe.py",
        "controls reuse p000 trace",
        'self.control_payloads[offer["request_id"]]',
        'self.payloads["p000"]',
        [SCHEDULE],
    )
    yield (
        "inf037b_probe.py",
        "controls reuse trace credentials",
        'self.control_credentials[control_slot(offer["request_id"])]',
        "self.credentials[gateway]",
        [SCHEDULE],
    )
    yield (
        "inf037b_probe.py",
        "missed IDs restored to native expected",
        "                dispatched\n",
        '                (dispatched | {planned["request_id"] for planned in trace})\n',
        [PROBE + "test_one_missed_offer_needs_no_native_endpoint"],
    )
    yield (
        "inf037b_live.py",
        "cancel after finish before DONE",
        "if decoder.finish:",
        'if decoder.report()["complete"]:',
        [SOCKET],
    )
    yield (
        "inf037b_live.py",
        "raw client bytes discarded",
        'self.retain(start, self.rows.clock(), chunk, {"status": status})',
        "pass",
        [SOCKET],
    )
    yield (
        "inf037b_live.py",
        "per chunk wire fsync restored",
        'self.retain(start, self.rows.clock(), chunk, {"status": status})',
        'self.retain(start, self.rows.clock(), chunk, {"status": status})\n                    getattr(self.retain, "barrier", lambda: None)()',
        [SOCKET],
    )
    yield (
        "inf037b_live.py",
        "per request completion barrier restored",
        'getattr(retain, "client_complete", lambda *args: None)',
        'getattr(retain, "complete", lambda *args: None)',
        [SOCKET],
    )
    yield (
        "inf037b_capture.py",
        "wire fsync under owner lock",
        "def barrier(self, source):\n        with self.io_lock:",
        "def barrier(self, source):\n        with self.lock, self.io_lock:",
        [WATERMARK],
    )
    yield (
        "inf037b_capture.py",
        "archive fsync under owner lock",
        "def archive_barrier(self):\n        with self.io_lock:",
        "def archive_barrier(self):\n        with self.lock, self.io_lock:",
        [WATERMARK],
    )
    yield (
        "inf037b_capture.py",
        "client group completion before archive barrier",
        """            self.archive_barrier()
            for source, args in completions:
                self.retain(source, *args)""",
        """            for source, args in completions:
                self.retain(source, *args)
            self.archive_barrier()""",
        [ORDER],
    )
    yield (
        "inf037b_capture.py",
        "group completion watermark taken after fsync",
        """            with self.lock:
                completions, self.client_completions = self.client_completions, []
            self.archive_barrier()""",
        """            self.archive_barrier()
            with self.lock:
                completions, self.client_completions = self.client_completions, []""",
        [WATERMARK],
    )
    yield (
        "inf037b_capture.py",
        "group wire barrier omitted",
        """            for source in self.sources:
                self.barrier(source)

    def join(self):""",
        "            pass\n\n    def join(self):",
        [WATERMARK],
    )
    yield (
        "inf037b_capture.py",
        "owner client tick omitted",
        "                    self.group_barrier()\n",
        "                    pass\n",
        [CAPTURE + "test_owner_tick_settles_client_without_per_request_barrier"],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go", action="store_true")
    args = parser.parse_args()
    before = hashes()
    summary = {
        "schema": "inf037b-round278-mutations-v1",
        "inputs_lf_sha256": before,
        "mutants": [],
    }
    with tempfile.TemporaryDirectory() as directory:
        overlay = Path(directory)
        package = overlay / "inference_platform"
        package.mkdir()
        (package / "__init__.py").write_text(f"__path__.append({str(SOURCE)!r})\n")
        if args.go:
            # Reuse the summary runner but select only this new check.
            import check_inf037b_probe_go

            check_inf037b_probe_go.TESTS = (
                "TestSetupControlsPinSlotLengthAndEOSWithoutChangingTrace"
            )
            baseline = go_run()
            assert (
                baseline["exit_code"] == 0
                and baseline["pass"] == 1
                and baseline["skip"] == 0
            ), baseline
            summary["baseline"] = baseline
            for label, original, replacement in (
                (
                    "omit deterministic slot policy",
                    "candidate.Backend.ID == tenant.SetupBackendID",
                    "true",
                ),
                (
                    "omit forced ignore_eos",
                    'outbound.IgnoreEOS = tenant.SetupBackendID != ""',
                    "outbound.IgnoreEOS = false",
                ),
                (
                    "controls perturb trace router",
                    "return NewBackendSelectionBoundary(NewRoundRobinRouter(), nil).Select(filtered)",
                    "candidates = filtered",
                ),
            ):
                path = ROOT / "internal/gateway/handler.go"
                source = path.read_text()
                assert source.count(original) == 1
                target = overlay / "handler.go"
                target.write_text(source.replace(original, replacement))
                config = overlay / "overlay.json"
                config.write_text(json.dumps({"Replace": {str(path): str(target)}}))
                result = go_run(config)
                killed = (
                    result["exit_code"] != 0
                    and bool(result["failures"])
                    and result["skip"] == 0
                )
                summary["mutants"].append(
                    {
                        "label": label,
                        "original": original,
                        "replacement": replacement,
                        "killed": killed,
                        **result,
                    }
                )
        else:
            selected = list(cases())
            baseline = run(
                overlay, sorted({t for *_, tests in selected for t in tests})
            )
            print(baseline["output"], flush=True)
            assert baseline["exit_code"] == 0 and "skipped=" not in baseline["output"]
            baseline.pop("output")
            summary["baseline"] = baseline
            for filename, label, original, replacement, tests in selected:
                source = (SOURCE / filename).read_text()
                assert source.count(original) == 1, (label, source.count(original))
                changed = source.replace(original, replacement)
                compile(changed, filename, "exec")
                path = package / filename
                path.write_text(changed)
                try:
                    result = run(overlay, tests)
                finally:
                    path.unlink()
                output = result.pop("output")
                assert "ImportError" not in output and "SyntaxError" not in output
                killed = result["exit_code"] != 0
                summary["mutants"].append(
                    {
                        "file": filename,
                        "label": label,
                        "original": original,
                        "replacement": replacement,
                        "killed": killed,
                        "failure_summary": [
                            line
                            for line in output.splitlines()
                            if line.startswith(("FAIL:", "ERROR:", "Ran ", "FAILED"))
                        ],
                        **result,
                    }
                )
                print(label, "KILLED" if killed else "SURVIVED", flush=True)
    summary["killed"] = sum(m["killed"] for m in summary["mutants"])
    summary["survivors"] = len(summary["mutants"]) - summary["killed"]
    summary["inputs_unchanged"] = hashes() == before
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    assert summary["survivors"] == 0 and summary["inputs_unchanged"]


if __name__ == "__main__":
    main()
