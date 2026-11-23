import itertools
import json
import logging
import unittest
from pathlib import Path
from unittest.mock import Mock

from inference_platform.inf060_streaming_probe import (
    SentCancel,
    join_abort_rows,
    observe_stream,
    summarize_same_read_by_level,
)

GATEWAY_REQUEST_ID = "req_00112233445566778899aabbccddeeff"
# Synthetic fixture based on v0.29.0 commit 98dff2a81d747d1dba01a47f939f48c3526d4206:
# logger.py L22-L26 (stock), L156-L201 (config), utils/system_utils.py L201-L211 (prefix),
# entrypoints/launchers/api_server/entry.py L166 and v1/engine/async_llm.py L694-L698.
STAMP = "1795100000.125732"
ABORT_LINE = (
    f"(APIServer pid=42) {STAMP} INFO [async_llm.py:698] "
    f"Request chatcmpl-{GATEWAY_REQUEST_ID} aborted."
)
STOCK_ABORT_LINE = (
    f"(APIServer pid=42) INFO 11-19 13:35:18 [async_llm.py:698] "
    f"Request chatcmpl-{GATEWAY_REQUEST_ID} aborted."
)
CANCEL = SentCancel(7, 1, GATEWAY_REQUEST_ID, 90_000_000)


def event(value):
    return b"data: " + json.dumps(value).encode() + b"\r\n\r\n"


def choice(delta, finish=None):
    return event({"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]})


def terminal(n):
    yield choice({}, "stop")
    yield event(
        {
            "choices": [],
            "usage": {
                "completion_tokens": n,
                "prompt_tokens": 1024,
                "total_tokens": 1024 + n,
                "count_source": "runtime_usage",
            },
        }
    )
    yield b"data: [DONE]\n\n"


def observe(chunks, *, assigned=False, close=None):
    return observe_stream(
        chunks,
        cancel_assigned=assigned,
        close=close if close is not None else Mock(),
        clock_ns=itertools.count(start=10_000_000, step=10_000_000).__next__,
    )


class StreamingProbeClientTests(unittest.TestCase):
    def test_coalesced_content_reports_only_transport_intervals(self):
        two_tokens = choice({"content": "one two"})
        rows = observe(
            [
                b": keepalive\r\n\r\n",
                choice({"role": "assistant"}),
                two_tokens[:15],
                two_tokens[15:],
                choice({"content": " three"}),
                *terminal(3),
            ]
        )
        self.assertTrue(rows["complete"])
        self.assertEqual(rows["content_event_count"], 2)
        self.assertEqual(rows["completion_tokens"], 3)
        self.assertFalse(rows["token_itl_eligible"])
        self.assertEqual(rows["token_itl_ns"], [])
        self.assertEqual(rows["transport_content_gaps_ns"], [10_000_000])

    def test_one_content_event_per_token_is_eligible(self):
        finish, usage, done = terminal(2)
        row = observe(
            [
                choice({"content": "one"}),
                choice({"content": " two"}),
                finish + usage[:10],
                usage[10:] + done,
            ]
        )
        self.assertTrue(row["token_itl_eligible"])
        self.assertEqual(row["first_content_monotonic_ns"], 10_000_000)
        self.assertEqual(row["token_itl_ns"], [10_000_000])
        self.assertEqual(row["transport_content_gaps_ns"], [])

    def test_same_read_gaps_are_transport_only_and_counted_per_level(self):
        a, b, c, d = (choice({"content": letter}) for letter in "ABCD")
        mixed = observe([a, b + c, d, *terminal(4)])
        self.assertTrue(mixed["token_itl_eligible"])
        self.assertEqual(mixed["token_itl_ns"], [10_000_000])  # C to D
        self.assertEqual(mixed["transport_content_gaps_ns"], [10_000_000, 0])  # A to B, B to C
        self.assertEqual(mixed["same_read_content_pairs"], 1)
        self.assertEqual(mixed["coalesced_read_excluded_gaps"], 2)

        all_same = observe([a + b + c, *terminal(3)])
        self.assertFalse(all_same["token_itl_eligible"])
        self.assertEqual(all_same["token_itl_ns"], [])
        self.assertEqual(all_same["transport_content_gaps_ns"], [0, 0])

        separate = observe([choice({"content": "one"}), choice({"content": " two"}), *terminal(2)])
        self.assertEqual(
            summarize_same_read_by_level({3: [mixed, separate, all_same], 8: [separate]}),
            {
                3: {
                    "same_read_content_pairs": 3,
                    "same_read_affected_requests": 2,
                    "coalesced_read_excluded_gaps": 4,
                },
                8: {
                    "same_read_content_pairs": 0,
                    "same_read_affected_requests": 0,
                    "coalesced_read_excluded_gaps": 0,
                },
            },
        )

    def test_finish_before_cancel_preserves_assignment(self):
        for n, same_read in ((3, False), (4, True)):
            with self.subTest(n=n, same_read=same_read):
                content = [choice({"content": str(i)}) for i in range(n)]
                if same_read:
                    chunks = [*content[:-1], content[-1] + b"".join(terminal(n))]
                else:
                    chunks = [*content, *terminal(n)]
                close = Mock()
                row = observe(chunks, assigned=True, close=close)
                close.assert_not_called()
                self.assertTrue(row["complete"])
                self.assertTrue(row["cancel_assigned"])
                self.assertEqual(row["cancel_status"], "finished_before_cancel")
                self.assertIsNone(row["cancel_close_monotonic_ns"])

    def test_client_close_without_a_finish_is_recorded(self):
        close = Mock()
        row = observe([choice({"content": str(i)}) for i in range(4)], assigned=True, close=close)
        close.assert_called_once_with()
        self.assertTrue(row["cancel_assigned"])
        self.assertEqual(row["cancel_status"], "sent")
        self.assertEqual(row["cancel_close_monotonic_ns"], 50_000_000)
        self.assertFalse(row["complete"])
        self.assertFalse(row["token_itl_eligible"])


class StreamingProbeAbortJoinTests(unittest.TestCase):
    def test_gateway_response_header_joins_prefixed_abort(self):
        headers = {"X-Request-ID": GATEWAY_REQUEST_ID}
        sent = SentCancel(7, 1, headers["X-Request-ID"], 90_000_000)
        [row], orphans = join_abort_rows([sent], {1: [ABORT_LINE]})
        self.assertEqual(orphans, {1: 0})
        self.assertEqual(
            row,
            {
                "request_alias": 7,
                "backend_generation": 1,
                "cancel_close_monotonic_ns": 90_000_000,
                "abort_status": "joined",
                "abort_log_stamp": STAMP,
            },
        )

    def test_duplicate_abort_remains_unresolved(self):
        [row], orphans = join_abort_rows([CANCEL], {1: [ABORT_LINE, ABORT_LINE]})
        self.assertEqual(row["abort_status"], "duplicate_abort")
        self.assertIsNone(row["abort_log_stamp"])
        self.assertEqual(orphans, {1: 0})

    def test_missing_abort_with_other_generation_and_internal_message(self):
        internal = ABORT_LINE.split(" Request ")[0] + " Aborted request(s) engine-internal."
        [row], orphans = join_abort_rows([CANCEL], {1: [internal], 2: [ABORT_LINE]})
        self.assertEqual(row["abort_status"], "missing_abort")
        self.assertIsNone(row["abort_log_stamp"])
        self.assertEqual(orphans, {1: 0, 2: 1})

    def test_stock_timestamp_does_not_join(self):
        [row], orphans = join_abort_rows([CANCEL], {1: [STOCK_ABORT_LINE]})
        self.assertEqual(row["abort_status"], "missing_abort")
        self.assertIsNone(row["abort_log_stamp"])
        self.assertEqual(orphans, {1: 0})

    def test_orphan_abort_exports_only_generation_count(self):
        orphan_id = "req_" + "f" * 32
        orphan = ABORT_LINE.replace(GATEWAY_REQUEST_ID, orphan_id)
        rows, orphans = join_abort_rows([CANCEL], {1: [orphan, ABORT_LINE], 2: []})
        self.assertEqual(rows[0]["abort_status"], "joined")
        self.assertEqual(orphans, {1: 1, 2: 0})
        exported = json.dumps((rows, orphans))
        self.assertNotIn(orphan_id, exported)
        self.assertNotIn(GATEWAY_REQUEST_ID, exported)

    def test_epoch_logging_config_renders_joinable_stamp(self):
        config_path = Path(__file__).resolve().parents[2] / "deploy/inf060/vllm-logging.json"
        config = json.loads(config_path.read_bytes())
        handler = config["handlers"]["vllm"]
        self.assertEqual(handler["class"], "logging.StreamHandler")
        self.assertEqual(handler["level"], "INFO")
        self.assertEqual(handler["stream"], "ext://sys.stdout")
        formatter = config["formatters"][handler["formatter"]]
        self.assertNotIn("datefmt", formatter)
        record = logging.LogRecord(
            "vllm.v1.engine.async_llm",
            logging.INFO,
            "async_llm.py",
            698,
            "Request %s aborted.",
            (f"chatcmpl-{GATEWAY_REQUEST_ID}",),
            None,
        )
        record.fileinfo = record.filename  # The INFO branch of the upstream formatter.
        record.created = float(STAMP)
        line = logging.Formatter(formatter["format"]).format(record)
        self.assertEqual(f"(APIServer pid=42) {line}", ABORT_LINE)
        [row], orphans = join_abort_rows([CANCEL], {1: [line]})
        self.assertEqual(row["abort_log_stamp"], STAMP)
        self.assertEqual(orphans, {1: 0})

    def test_export_drops_raw_request_ids_prompt_text_and_token_ids(self):
        prompt = (
            f"(APIServer pid=42) {STAMP} DEBUG [request_logger.py:54] "
            f"Request chatcmpl-{GATEWAY_REQUEST_ID} details: prompt: 'fixture prompt sentinel', "
            "prompt_token_ids: [991128, 884271], prompt_embeds shape: None."
        )
        forged = ABORT_LINE + " fixture prompt sentinel"
        [row], orphans = join_abort_rows([CANCEL], {1: [prompt, forged, ABORT_LINE]})
        self.assertEqual(row["abort_status"], "joined")
        exported = json.dumps((row, orphans))
        for forbidden in (
            GATEWAY_REQUEST_ID,
            "fixture prompt sentinel",
            "991128",
            "884271",
            "pid=",
        ):
            self.assertNotIn(forbidden, exported)


if __name__ == "__main__":
    unittest.main()
