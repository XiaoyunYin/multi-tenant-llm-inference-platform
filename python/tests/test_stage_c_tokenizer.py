import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.calibration import CalibrationConfig, _stream_request, run_calibration
from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.stage_c_prompts import exact_prompt, prompt_bank, prompt_footprint
from inference_platform.stage_c_tokenizer import pinned_tokenizer, verified_files


class RealTokenizerTest(unittest.TestCase):
    def test_pre_header_transport_failure_keeps_outcome_without_inventing_gateway_join(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prompts.jsonl"
            path.touch()
            config = CalibrationConfig(
                url="http://unused",
                token="test",
                tenant_id="test",
                model="test",
                run_id="no-header",
                decision_prompt_export_path=str(path),
            )
            with patch(
                "inference_platform.calibration.deadline_urlopen",
                side_effect=urllib.error.URLError("connect failed"),
            ):
                record = _stream_request(
                    config,
                    "0" * 64,
                    0,
                    [{"role": "system", "content": "id"}, {"role": "user", "content": "test"}],
                )
            self.assertEqual(record["outcome"], "failed_before_content")
            self.assertEqual(record["error_code"], "transport_error")
            self.assertFalse(record["gateway_request_id_observed"])
            self.assertEqual(
                record["decision_prompt_export_status"], "not_recorded_no_gateway_request_id"
            )
            self.assertEqual(path.read_bytes(), b"")

    def test_live_probe_and_legacy_first_block_regression_without_network(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("offline only")):
            tokenize = pinned_tokenizer()
            self.assertEqual(len(tokenize("stage-c tokenizer preflight")), 34)
            config = SimpleNamespace(model="test", tokenize_url="offline")

            def legacy(messages):
                return tokenize(
                    [{"role": "user", "content": messages[0]["content"] + messages[1]["content"]}]
                )

            for target in (1024, 6144):
                with self.assertRaisesRegex(RuntimeError, "distinct first full blocks"):
                    prompt_bank(config, "legacy", 2, target, None, tokenize_fn=legacy)
                tokens = []
                bank = prompt_bank(
                    config, "fixed", 2, target, None, tokenize_fn=tokenize, tokenizations=tokens
                )
                self.assertTrue(all(prompt[0]["role"] == "system" for prompt in bank))
                self.assertTrue(all(len(row) == target for row in tokens))
                self.assertEqual(prompt_footprint(tokens)["prompt_blocks"], 2 * target // 16)
                self.assertEqual(prompt_footprint(tokens)["shared_prefix_blocks"], 0)

    def test_hash_verification_and_missing_fake_template_fail_closed(self):
        files = verified_files()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in files.items():
                (root / name).write_bytes(data)
            (root / "tokenizer_config.json").write_bytes(b"{}")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                pinned_tokenizer(cache=root)
            with patch.dict("os.environ", {"INF011_TOKENIZER_CACHE": directory}):
                with FakeBackend(FakeBackendConfig()) as backend:
                    request = urllib.request.Request(
                        backend.base_url + "/tokenize",
                        method="POST",
                        data=json.dumps(
                            {
                                "model": "test",
                                "messages": [{"role": "user", "content": "test"}],
                                "add_generation_prompt": True,
                            }
                        ).encode(),
                        headers={"Content-Type": "application/json"},
                    )
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(request, timeout=2)
                    self.assertEqual(error.exception.code, 503)
                    self.assertIn(b"pinned_chat_tokenizer_unavailable", error.exception.read())

    def test_fake_tokenize_matches_real_template_and_explicit_identity(self):
        tokenize = pinned_tokenizer()
        with FakeBackend(FakeBackendConfig()) as backend:
            prompt, tokens = exact_prompt(backend.base_url, "test", "identity", 1024, None)
            self.assertEqual(tokens, tokenize(prompt))
            self.assertEqual(prompt[0]["role"], "system")

    def test_message_prompt_is_streamed_and_hashed_in_outcome(self):
        with FakeBackend(FakeBackendConfig(runtime_shaped_metrics=True)) as backend:
            prompt, _ = exact_prompt(backend.base_url, "test", "record-identity", 1024, None)
            config = CalibrationConfig(
                url=backend.base_url,
                token="test",
                tenant_id="test",
                model="test",
                run_id="message-record",
                gateway_mode=False,
                max_tokens=1,
                sample_interval_ms=5,
                timeout_seconds=5,
            )
            result = run_calibration(config, (1,), prompt_factory=lambda *_: prompt)
            record = result["levels"][0]["records"][0]
            self.assertEqual(record["outcome"], "completed")
            self.assertEqual(record["prompt_tokens"], 1024)
            self.assertEqual(len(record["prompt_sha256"]), 64)

    def test_kv_footprints_share_only_identical_prefix_context(self):
        # Same suffix bytes with different parent identities are different KV blocks.
        self.assertEqual(
            prompt_footprint([list(range(32)), [99] * 16 + list(range(16, 32))]),
            {"prompt_blocks": 4, "total_full_blocks": 4, "shared_prefix_blocks": 0},
        )
        self.assertEqual(prompt_footprint([list(range(32)), list(range(32))])["prompt_blocks"], 2)
