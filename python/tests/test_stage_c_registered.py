import copy
import gzip
import hashlib
import json
import random
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deflate_structure import blocks
from remainder_fixtures import fixture

from inference_platform import failure_taxonomy
from inference_platform.calibration import _recorder_error_body_code
from inference_platform.stage_c_checkpoint import seal_run
from inference_platform.stage_c_digest import measurement_digest, seal_digest
from inference_platform.stage_c_registered import (
    C_FIELDS,
    C_MAX,
    GATEWAY_CODES,
    RetentionError,
    decode_failures,
    encoded,
    failure_codebook,
    from_base64,
    median,
    recover_registered,
    screen_fields,
)
from inference_platform.stage_c_wire import lengths, member, unpadded


class RegisteredDigestTest(unittest.TestCase):
    def test_final_metadata_overflow_has_durable_refusal(self):
        from inference_platform.disk_records import write_json
        from inference_platform.stage_c_session import export

        with tempfile.TemporaryDirectory() as temp:
            session = Path(temp)
            sealed = session / "sealed-runs"
            sealed.mkdir()
            write_json(
                sealed / "run-4.digest.receipt.json",
                dict(
                    registration="stage-c-remainder-v1",
                    sha256="a" * 64,
                    bytes=1048576,
                    per_request_count=14259,
                    event_lag_status="unestablished",
                ),
            )
            manifest = session / "staging-manifest.json"
            write_json(manifest, dict(entropy=random.Random(47).randbytes(80000).hex()))
            with self.assertRaisesRegex(ValueError, "final export exceeds"):
                export(session, manifest)
            receipt = json.loads(
                (session / "export-retention.failure.json").read_text(encoding="utf-8")
            )
            self.assertGreater(receipt["attempted_count"], 32000)
            self.assertFalse(receipt["full_measured_session_acceptance"])
            self.assertFalse((session / "evidence.tar.gz").exists())

    def test_literal_blocks_are_single_dynamic_and_stock_gzip_recovers(self):
        rng = random.Random(470150)
        a, b = unpadded(rng.randbytes(884058)), unpadded(rng.randbytes(14848))
        spans = [
            ("prefix", b'{"a":"', False),
            ("a", a, True),
            ("middle", b'","b":"', False),
            ("b", b, True),
            ("suffix", b'"}', False),
        ]
        data, report = member(spans)
        self.assertEqual(gzip.decompress(data), b"".join(row[1] for row in spans))
        parsed = blocks(data)
        self.assertEqual([row["kind"] for row in parsed], [0, 2, 0, 2, 0])
        self.assertEqual([row["data"] for row in parsed], [row[1] for row in spans])
        self.assertLessEqual(report["sections"]["a"]["literal_charge_bytes"], 886361)
        self.assertLessEqual(report["sections"]["b"]["literal_charge_bytes"], 14888)

    def test_package_merge_is_optimal_and_handles_pathological_skew(self):
        # Four symbols: enumerate every complete tree of depth <=3 independently.
        weights = {0: 1, 1: 2, 2: 3, 3: 20}
        import itertools

        best = min(
            sum(w * size for w, size in zip(weights.values(), candidate, strict=True))
            for candidate in itertools.product(range(1, 4), repeat=4)
            if sum(2**-size for size in candidate) == 1
        )
        actual = lengths(weights, 3)
        self.assertEqual(sum(weights[key] * size for key, size in actual.items()), best)
        frequencies = {i: 1 << i for i in range(65)}
        actual = lengths(frequencies)
        self.assertLessEqual(max(actual.values()), 15)
        self.assertEqual(sum(1 << (15 - size) for size in actual.values()), 1 << 15)

    def test_gateway_fixed_and_dynamic_terminal_codes_are_explicit(self):
        root = Path(__file__).resolve().parents[2]
        files = sorted(
            path
            for path in root.rglob("*.go")
            if ".cache" not in path.parts and not path.name.endswith("_test.go")
        )
        constructors, assignments, decision_returns = [], [], []
        codes = set()
        for path in files:
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"requestTerminal\s*\{([^}]*)\}", text, flags=re.S):
                constructors.append((str(path.relative_to(root)), match.group(1)))
                code = re.search(r'\bcode\s*:\s*("[^"]*"|\w+)', match.group(1))
                self.assertIsNotNone(code, constructors[-1])
                if code[1].startswith('"'):
                    codes.add(json.loads(code[1]))
                else:
                    self.assertEqual(code[1], "code", "unhandled dynamic constructor")
            assignments.extend(re.findall(r"\bterminal\.code\s*=\s*([^\n]+)", text))
            for match in re.finditer(
                r"func \(decision Decision\) Code\(\) string \{(.*?)\n\}", text, flags=re.S
            ):
                body = match[1]
                decision_returns.extend(re.findall(r'\breturn\s+("[^"]*")', body))
                self.assertEqual(len(re.findall(r"\breturn\b", body)), len(decision_returns))
        handler = (root / "internal/gateway/handler.go").read_text(encoding="utf-8")
        # Every assignment branch feeding the single dynamic terminal assignment.
        self.assertEqual(assignments, ["code"])
        branches = re.findall(
            r'\b(?:status,\s*)?code\s*(?::=|=)\s*(?:http\.\w+,\s*)?("[^"]*")', handler
        )
        self.assertEqual(
            set(map(json.loads, branches)),
            {"invalid_request", "request_too_large", "unsupported_parameter"},
        )
        codes.update(map(json.loads, branches))
        self.assertEqual(
            set(map(json.loads, decision_returns)),
            {
                "allowed",
                "tenant_rate_limit",
                "tenant_concurrency_limit",
                "system_capacity",
                "capacity_reports_expired",
                "",
            },
        )
        self.assertRegex(
            handler,
            r"if admissionResult\.Decision != admission\.Allowed \{\s*code := admissionResult\.Decision\.Code\(\)",
        )
        self.assertRegex(handler, r'if code == "" \{[^}]*code: "admission_unavailable"')
        codes.update(
            json.loads(value)
            for value in decision_returns
            if json.loads(value) not in ("allowed", "capacity_reports_expired", "")
        )
        # Discovery and expiry outcomes are outside the fixed static Stage C
        # path; its emitted terminal vocabulary must remain registration-bound.
        # The three slice 3a additions are also included in the producer scan.
        self.assertEqual(len(constructors), 42)
        self.assertEqual(
            codes - {"discovery_unknown", "capacity_reports_expired"},
            set(GATEWAY_CODES),
        )
        unavailable = re.search(
            r"func postAdmissionUnavailableCode\([^)]*\) string \{(.*?)\n\}",
            handler,
            flags=re.S,
        )
        self.assertIsNotNone(unavailable)
        self.assertEqual(
            set(re.findall(r'return "([^"]+)"', unavailable[1])),
            {
                "no_healthy_backend",
                "discovery_unknown_after_admit",
                "backend_membership_changed_after_admit",
            },
        )

    def test_static_health_flip_row_is_accepted_by_stage_c_encoder(self):
        root = Path(__file__).resolve().parents[2]
        completed = subprocess.run(
            [
                "go",
                "test",
                "./internal/gateway",
                "-run",
                "^TestFixedModeStaticHealthFlipProducesStageCRow$",
                "-count=1",
                "-v",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        status_match = re.search(r"R224_STAGEC_STATUS=(\d+)", completed.stdout)
        body_match = re.search(r"R224_STAGEC_BODY=([^\r\n]+)", completed.stdout)
        terminal_match = re.search(r"R224_STAGEC_TERMINAL=(\{[^\r\n]+\})", completed.stdout)
        self.assertIsNotNone(status_match, completed.stdout)
        self.assertIsNotNone(body_match, completed.stdout)
        self.assertIsNotNone(terminal_match, completed.stdout)
        body = json.loads(body_match[1])
        terminal = json.loads(terminal_match[1])
        self.assertEqual(terminal.get("msg"), "request terminal")
        record = {
            "gateway_request_id": terminal["request_id"],
            "http_status": int(status_match[1]),
            "error_body_code": _recorder_error_body_code(body),
            "outcome": "rejected",
            "dispatch_offset_ns": 0,
        }
        run = {"concurrency": 1, "records": [record]}
        with tempfile.TemporaryDirectory() as directory:
            gateway_log = Path(directory) / "gateway.log"
            gateway_log.write_text(json.dumps(terminal) + "\n", encoding="utf-8")
            failure_taxonomy.add_failure_splits(run, gateway_log)
        self.assertEqual(run["unmatched_dispatched_request_count"], 0)
        joined = run["failure_split"][0]
        row = (
            joined["http_status"],
            joined["gateway_terminal_code"],
            joined["class"],
            joined["client_error_body_code"],
            joined["upstream_error_body_code"],
        )
        book, ids = failure_codebook([row])
        decoded = decode_failures(book)[ids[0]]
        expected = (
            503,
            "no_healthy_backend",
            "gateway_no_healthy_backend",
            "no_healthy_backend",
            0,
        )
        self.assertEqual(decoded, expected)
        self.assertEqual(decoded[3], "no_healthy_backend")

    def test_median_has_no_request_sample_minimum(self):
        for n in (1, 2, 29, 30, 40):
            values = list(reversed(range(n)))
            self.assertEqual(median(values), (n - 1) // 2)
        self.assertIsNone(median([]))

    def test_codebook_keeps_integer_zero_distinct_from_null_and_string(self):
        tuples = [
            (200, "completed", "completed", value, upstream)
            for value, upstream in ((None, None), (0, 0), ("0", 0), (0, None))
        ]
        book, ids = failure_codebook(tuples)
        decoded = decode_failures(book)
        self.assertEqual([decoded[i] for i in ids], tuples)
        self.assertEqual(len(set(ids)), 4)

    def test_766_byte_registered_row_bound(self):
        row = dict(zip(C_FIELDS, C_MAX, strict=True))
        row["concurrency"] = 64
        row["sampler_started_before_load"] = False
        self.assertEqual(len(encoded(row)), 766)

    def test_source_bound_seal_and_gzip_only_recovery(self):
        for number in (3, 4):
            with self.subTest(number=number), tempfile.TemporaryDirectory() as temp:
                session = Path(temp)
                (session / "gateway.log").write_text("", encoding="utf-8")
                source = fixture(number)
                receipt = seal_run(session, number, source)
                data = (session / "sealed-runs" / f"run-{number}.digest.json.gz").read_bytes()
                recovered = recover_registered(data)
                self.assertEqual(
                    receipt["measurement_digest"]["sha256"], hashlib.sha256(data).hexdigest()
                )
                self.assertEqual(recovered["source_binding"], source["source_binding"])
                if number == 3:
                    for name in ("requests", "lags", "membership"):
                        self.assertEqual(recovered[name], source[name])
                    self.assertEqual(
                        encoded(recovered["protected"]),
                        encoded(source["rewarm_convergence_compact"]),
                    )
                else:
                    self.assertEqual(recovered["native_counters"], source["native_counters"])
                    self.assertEqual(recovered["level_aggregates"], source["level_aggregates"])
                    self.assertEqual(
                        [row["outcome"] for row in recovered["requests"]],
                        [row["outcome"] for row in source["requests"]],
                    )
                    for row in recovered["level_aggregates"]:
                        for field, value in screen_fields(recovered["requests"], row).items():
                            self.assertEqual(row[field], value)
                    for old, new, failure in zip(
                        source["requests"],
                        recovered["requests"],
                        source["failure_tuples"],
                        strict=True,
                    ):
                        for key in (
                            "per_request_index",
                            "level_index",
                            "dispatch_ns",
                            "first_content_ns",
                            "terminal_ns",
                            "censor_ns",
                            "event_lag_status",
                            "event_lag_ns",
                            "validity_flags",
                        ):
                            self.assertEqual(old[key], new[key])
                        self.assertEqual(new["failure_tuple"], failure)

    def test_recovery_rejects_administrative_outcome_ids_above_nine(self):
        run = fixture(4)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "digest.gz"
            seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
            text = gzip.decompress(path.read_bytes()).decode("ascii")
            decoder = json.JSONDecoder()
            first, end = decoder.raw_decode(text)
            second = json.loads(text[end:])
            data = bytearray(from_base64(first["a"]))
            data[61] = (data[61] & 15) | (10 << 4)
            first["a"] = unpadded(data).decode("ascii")
            corrupt = gzip.compress(encoded(first) + b"\n" + encoded(second), mtime=0)
            with self.assertRaisesRegex(RetentionError, "administrative_outcome_id"):
                recover_registered(corrupt)

    def test_recovery_recomputes_every_screen_field_from_recovered_requests(self):
        run = fixture(4)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "digest.gz"
            seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
            text = gzip.decompress(path.read_bytes()).decode("ascii")
            decoder = json.JSONDecoder()
            first, end = decoder.raw_decode(text)
            second = json.loads(text[end:])
            first["c"][0]["screen_completion_n"] += 1
            corrupt = gzip.compress(encoded(first) + b"\n" + encoded(second), mtime=0)
            with self.assertRaisesRegex(RetentionError, "recovered.screen_completion_n"):
                recover_registered(corrupt)

    def test_screen_rejects_outcome_changed_after_c_row_was_built(self):
        run = fixture(4)
        target = next(
            row
            for row in run["requests"]
            if row["outcome"] == "completed" and row["level_index"] == 0
        )
        target["outcome"] = "partial"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "digest.gz"
            with self.assertRaisesRegex(RetentionError, "screen_completion_n"):
                seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
            failure = json.loads(
                path.with_name(path.name + ".failure.json").read_text(encoding="utf-8")
            )
            self.assertEqual(failure["flag"], "retention_conservation_failure")
            self.assertFalse(failure["full_measured_session_acceptance"])
            self.assertFalse(path.exists())

    def test_run3_per_run_identity_constants_refuse_variation_durably(self):
        def vary_prompt(run):
            row = run["requests"][1]
            value = "f" * 64
            row["prompt_identity_sha256"] = value
            run["lags"][1]["prompt_identity_sha256"] = value

        for mutate, table in (
            (vary_prompt, "run3_prompt_identity_constant"),
            (
                lambda run: run["membership"][0].__setitem__("token_block_digest", "f" * 64),
                "run3_membership_constants",
            ),
            (
                lambda run: run["membership"][0].__setitem__("native_cached_key", "f" * 128),
                "run3_membership_constants",
            ),
            (
                lambda run: run["lags"][0].__setitem__("matched_token_block_digests", ["f" * 64]),
                "run3_lag_matched_digest_subset",
            ),
        ):
            with self.subTest(table=table), tempfile.TemporaryDirectory() as temp:
                run = fixture(3)
                mutate(run)
                path = Path(temp) / "digest.gz"
                receipt = seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
                failure = json.loads(
                    path.with_name(path.name + ".failure.json").read_text(encoding="utf-8")
                )
                recovered = recover_registered(path.read_bytes())
                self.assertEqual(failure["table"], table)
                self.assertEqual(failure["flag"], "retention_join_failure")
                self.assertEqual(receipt["per_request_count"], 0)
                self.assertEqual(recovered["exact_lag_status"], "unavailable")
                self.assertEqual(
                    encoded(recovered["protected"]),
                    encoded(run["rewarm_convergence_compact"]),
                )

    def test_run3_raw_schema_exception_still_returns_protected_only(self):
        run = fixture(3)
        run.pop("gateway_cpu_ticks_per_second")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "run-3.digest.json.gz"
            receipt = seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
            failure_path = path.with_name(path.name + ".failure.json")
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            recovered = recover_registered(path.read_bytes())
        self.assertEqual(failure["failure_type"], "KeyError")
        self.assertEqual(failure["flag"], "retention_schema_overflow")
        self.assertEqual(failure["table"], "registered_source")
        self.assertEqual(receipt["per_request_count"], 0)
        self.assertEqual(recovered["exact_lag_status"], "unavailable")
        self.assertEqual(
            encoded(recovered["protected"]),
            encoded(run["rewarm_convergence_compact"]),
        )

    def test_failures_are_durable_before_deflate_and_do_not_salvage_a_subset(self):
        for mutate, expected in (
            (
                lambda run: run["failure_tuples"].__setitem__(
                    0, (99, None, "completed", None, None)
                ),
                "failure_code_overflow",
            ),
            (
                lambda run: run["requests"][0].__setitem__("dispatch_ns", 2**64),
                "retention_field_overflow",
            ),
            (
                lambda run: run["requests"][0].__setitem__("level_index", 29),
                "retention_field_overflow",
            ),
            (
                lambda run: run["native_counters"][0].__setitem__("counter_status", 4),
                "retention_field_overflow",
            ),
            (
                lambda run: run["failure_tuples"].__setitem__(
                    0, (200, "completed", "completed", "!", None)
                ),
                "failure_code_overflow",
            ),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temp:
                run = fixture(4)
                mutate(run)
                path = Path(temp) / "digest.gz"
                with patch(
                    "inference_platform.stage_c_registered.member",
                    side_effect=AssertionError("DEFLATE reached"),
                ):
                    with self.assertRaises(RetentionError):
                        seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
                failure = json.loads(
                    path.with_name(path.name + ".failure.json").read_text(encoding="utf-8")
                )
                self.assertEqual(failure["flag"], expected)
                self.assertFalse(failure["full_measured_session_acceptance"])
                self.assertFalse(path.exists())
                self.assertFalse(path.with_suffix(".pending").exists())

    def test_ninth_tuple_refuses_before_deflate(self):
        run = fixture(4)
        run["failure_tuples"] = [
            (200, "completed", "completed", i % 9, 0) for i in range(len(run["requests"]))
        ]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "digest.gz"
            original = copy.deepcopy(run["failure_tuples"])
            with patch(
                "inference_platform.stage_c_registered.member",
                side_effect=AssertionError("DEFLATE reached"),
            ):
                with self.assertRaises(RetentionError):
                    seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
            failure = json.loads(
                path.with_name(path.name + ".failure.json").read_text(encoding="utf-8")
            )
            self.assertEqual(failure["attempted_count"], 9)
            self.assertEqual(run["failure_tuples"], original)

    def test_extension_stored_fallback_and_binding_check(self):
        run = fixture(4)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "digest.gz"
            with patch(
                "inference_platform.stage_c_registered.compressed_sections",
                return_value=(bytes(40901), {}),
            ):
                receipt = seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
            self.assertTrue(receipt["sections"]["member2"]["stored_fallback"])
            self.assertLessEqual(receipt["sections"]["member2"]["gzip_bytes"], 40900)
            self.assertEqual(
                recover_registered(path.read_bytes())["native_counters"], run["native_counters"]
            )
            text = gzip.decompress(path.read_bytes()).decode("ascii")
            decoder = json.JSONDecoder()
            first, end = decoder.raw_decode(text)
            second = json.loads(text[end:])
            second["source_binding"]["source_sha256"] = "f" * 64
            corrupt = gzip.compress(encoded(first) + b"\n" + encoded(second), mtime=0)
            with self.assertRaises(RetentionError):
                recover_registered(corrupt)

    def test_run3_protected_survives_all_registered_degradation_causes(self):
        for mutate in (
            lambda r: r["requests"].__imul__(13),
            lambda r: r["native_counters"][0].__setitem__("counter_status", 4),
            lambda r: r["lags"][0].__setitem__("event_sequence", 2**64),
            lambda r: r["requests"][0].pop("dispatch_ns"),
        ):
            run = fixture(3)
            protected = encoded(run["rewarm_convergence_compact"])
            mutate(run)
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "digest.gz"
                receipt = seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
                recovered = recover_registered(path.read_bytes())
                self.assertEqual(encoded(recovered["protected"]), protected)
                self.assertEqual(receipt["event_lag_status"], "unavailable")
                self.assertFalse(receipt["full_measured_session_acceptance"])
                self.assertTrue(path.with_name(path.name + ".failure.json").exists())

    def test_empty_phase_has_explicit_measurement_and_witness_slots(self):
        run = fixture(4)
        keep = [i for i, r in enumerate(run["requests"]) if r["level_index"] != 24]
        for table in ("requests", "lags", "failure_tuples"):
            run[table] = [run[table][i] for i in keep]
        for i, (request, lag) in enumerate(zip(run["requests"], run["lags"], strict=True)):
            request["per_request_index"] = lag["per_request_index"] = i
        c = run["level_aggregates"][24]
        for field in (
            "dispatch_n",
            "screen_dispatch_n",
            "screen_completion_n",
            "screen_ttft_success_n",
            "screen_unsuccessful_n",
            "censored_ttft_n",
        ):
            c[field] = 0
        for field in (
            "duration_ns",
            "screen_exposure_start_ns",
            "screen_exposure_end_ns",
            "screen_ttft_p50_ns",
            "preemption_delta",
            "running_peak",
            "waiting_peak",
        ):
            c[field] = None
        c.update(
            row_status=2,
            screen_status=2,
            diagnostic_status=2,
            diagnostic_valid_n=0,
            diagnostic_invalid_n=0,
        )
        native = run["native_counters"][24]
        for field in native:
            native[field] = 0 if field.endswith("_n") else None
        native.update(counter_status=2, preemptions_status=2)
        source = run["measurement_sources"][24]
        source.update(gateway_samples=[], eviction_bins=[])
        source["lookup"]["missing"] = source["tokenize"]["missing"] = True
        run["exposures"][24]["samples"] = {key: [] for key in run["exposures"][24]["samples"]}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "digest.gz"
            seal_digest(path, measurement_digest(Path(temp), run, Path(temp)))
            got = recover_registered(path.read_bytes())
            self.assertEqual(len(got["measurements"]), 29)
            self.assertEqual(got["measurements"][24]["gateway"]["status"], 2)
            self.assertIsNone(got["measurements"][24]["gateway"]["rss_max"])
            self.assertEqual(got["lag_witnesses"][24], dict(level_index=24, present=False))
            self.assertEqual(got["snapshot_counts"][0]["status"], 2)
            self.assertEqual(got["snapshot_counts"][0]["presence_bitmap"], 0)


if __name__ == "__main__":
    unittest.main()
