import concurrent.futures
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from inference_platform.r1_lifecycle import (
    ConsumeGate,
    admit,
    committed_approval,
    execute,
    main,
    sha,
    validate_inputs_commands,
)
from inference_platform.r1_lifecycle_rehearsal import Virtual, fixture_inputs


class MultizoneApprovalTests(unittest.TestCase):
    def test_latest_round_marker_sets_and_matching_target_binding(self):
        a, b, c, d, e = (char * 64 for char in "abcde")
        for hashes, rounds, accepted in (
            ([b], [109], True),
            ([a, b, c], [109] * 3, True),
            ([a, b, c, d], [109] * 4, True),
            ([a, b, b], [109] * 3, False),
            ([a, b, c], [108, 109, 109], False),
            ([a, b, c, d, e], [109] * 5, False),
            ([a, c], [109] * 2, False),
            ([], [], False),
        ):
            with self.subTest(hashes=hashes, rounds=rounds), tempfile.TemporaryDirectory() as tmp:
                repo = Path(tmp)
                path = repo / "inputs.json"
                inputs = {
                    "plan_sha256": b,
                    "source_head": "1" * 40,
                    "source_sha256": {"source.py": sha(b"source")},
                }
                path.write_bytes(json.dumps(inputs).encode())
                targets = [str(index + 1) * 40 for index in range(len(hashes))]
                markers = "\n".join(
                    f"- R1 PAID PLAN APPROVED: plan_sha256={digest}; "
                    f"target={target}; review_round={number}"
                    for digest, target, number in zip(hashes, targets, rounds, strict=True)
                )
                review = (
                    "\n## Claude review rounds\n### Round 108\n"
                    f"- R1 PAID PLAN APPROVED: plan_sha256={b}; target={'f' * 40}; "
                    "review_round=108\n### Round 109\n" + markers + "\n## Findings\n"
                )
                calls = []

                def git(argv, calls=calls, review=review, path=path):
                    calls.append(argv[3:])
                    if argv[3] in {"status", "merge-base"}:
                        return b""
                    if argv[-1] == "HEAD:REVIEW.md":
                        return review.encode()
                    if argv[-1].endswith(":inputs.json"):
                        return path.read_bytes()
                    return b"source"

                approval = committed_approval(repo, path)
                with patch(
                    "inference_platform.r1_lifecycle.subprocess.check_output", side_effect=git
                ):
                    if accepted:
                        self.assertEqual(approval(inputs), frozenset(hashes))
                        self.assertEqual(approval.review_round, 109)
                        matching_target = targets[hashes.index(b)]
                        self.assertIn(
                            ["merge-base", "--is-ancestor", matching_target, "HEAD"], calls
                        )
                        self.assertIn(["show", matching_target + ":inputs.json"], calls)
                        self.assertIn(["show", matching_target + ":source.py"], calls)
                        self.assertIn(["show", "1" * 40 + ":source.py"], calls)
                    else:
                        with self.assertRaisesRegex(ValueError, "latest committed Claude"):
                            approval(inputs)
                        self.assertFalse(any(call[0] == "merge-base" for call in calls))

    def test_verified_sibling_retires_round_but_new_round_can_consume(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = ConsumeGate(Path(tmp) / "consume.sqlite3")
            siblings = {"a" * 64, "b" * 64}
            gate.consume("a" * 64, {}, siblings)
            gate.finish("a" * 64, True)
            with self.assertRaisesRegex(ValueError, "sibling plans retired"):
                gate.consume("b" * 64, {}, siblings)
            self.assertIsNone(gate.plan_status("b" * 64))
            gate.consume("c" * 64, {}, {"c" * 64, "d" * 64})
            self.assertEqual(gate.plan_status("c" * 64), "consumed")

    def test_any_sibling_status_refuses_and_rolls_back(self):
        for status in ("consumed", "uncertain", "verified"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                gate = ConsumeGate(Path(tmp) / "consume.sqlite3")
                gate.consume("a" * 64)
                with gate.connect() as db:
                    db.execute("UPDATE plans SET status=?", (status,))
                with self.assertRaisesRegex(ValueError, "sibling plans retired"):
                    gate.consume("b" * 64, {}, {"a" * 64, "b" * 64})
                self.assertIsNone(gate.plan_status("b" * 64))

    def test_concurrent_siblings_have_one_winner_even_after_verified_teardown(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "consume.sqlite3"
            ConsumeGate(path)
            siblings = {"a" * 64, "b" * 64}

            def attempt(digest):
                gate = ConsumeGate(path)
                try:
                    gate.consume(digest, {}, siblings)
                except ValueError:
                    return False
                gate.finish(digest, True)
                return True

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sum(pool.map(attempt, siblings)), 1)

    def test_execute_records_round_and_full_set_and_refuses_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, inputs = fixture_inputs("success")
            sibling_plan = plan + b" "
            sibling_inputs = {**inputs, "plan_sha256": sha(sibling_plan)}
            siblings = {inputs["plan_sha256"], sibling_inputs["plan_sha256"]}

            def approval(_inputs):
                return siblings

            approval.review_round = 109
            gate = ConsumeGate(Path(tmp) / "consume.sqlite3")
            result = execute(
                Virtual("success"), plan, inputs, gate, approval, Path(tmp) / "receipt"
            )
            self.assertEqual(result["apply_count"], 1)
            binding = gate.recovery_inputs(inputs["plan_sha256"])
            self.assertEqual(binding["_approval_review_round"], 109)
            self.assertEqual(binding["_approval_plan_sha256"], sorted(siblings))
            result = execute(
                Virtual("success"),
                sibling_plan,
                sibling_inputs,
                gate,
                approval,
                Path(tmp) / "sibling-receipt",
            )
            self.assertEqual(result["apply_count"], 0)
            self.assertIn("sibling plans retired", result["error"])
            self.assertIsNone(gate.plan_status(sibling_inputs["plan_sha256"]))

    def test_self_reference_refuses_before_admission_callback_or_aws(self):
        for argv in (
            ["operator", "--inputs", "docs/other.json"],
            ["operator"],
            ["operator", "--inputs"],
            ["operator", "--inputs", "docs/R1_SESSION_INPUTS.json", "--inputs", "other"],
        ):
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as tmp:
                plan, inputs = fixture_inputs("success")
                inputs["commands"]["measure"] = argv
                approval = Mock()
                with self.assertRaisesRegex(ValueError, "--inputs"):
                    admit(plan, inputs, approval)
                approval.assert_not_called()
                adapter = Virtual("success")
                gate = ConsumeGate(Path(tmp) / "consume.sqlite3")
                with (
                    patch.object(adapter, "preflight") as preflight,
                    patch.object(adapter, "reserve_capacity") as reserve,
                ):
                    result = execute(adapter, plan, inputs, gate, approval, Path(tmp) / "receipt")
                self.assertEqual(result["apply_count"], 0)
                preflight.assert_not_called()
                reserve.assert_not_called()
                self.assertIsNone(gate.plan_status(inputs["plan_sha256"]))

    def test_main_refuses_other_inputs_before_gate_output_or_any_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            path = repo / "zone.json"
            path.write_text(json.dumps({"commands": {"ready": ["op", "--inputs", "other.json"]}}))
            output = repo / "output"
            argv = [
                "lifecycle",
                "--repo",
                str(repo),
                "--inputs",
                str(path),
                "--saved-plan",
                str(repo / "absent-plan"),
                "--output",
                str(output),
                "--apply",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("inference_platform.r1_lifecycle.ConsumeGate") as gate,
                patch("inference_platform.r1_lifecycle.Production") as production,
                patch("inference_platform.r1_lifecycle.subprocess.check_output") as subprocess,
            ):
                with self.assertRaisesRegex(ValueError, "own --inputs file"):
                    main()
            gate.assert_not_called()
            production.assert_not_called()
            subprocess.assert_not_called()
            self.assertFalse(output.exists())

    def test_normalized_repo_path_matches_zone_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            path = repo / "docs/zone-1d.json"
            inputs = {"commands": {"ready": ["op", "--inputs", "docs/./zone-1d.json"]}}
            validate_inputs_commands(repo, path, inputs)


if __name__ == "__main__":
    unittest.main()
