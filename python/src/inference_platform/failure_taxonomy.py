"""Join recorder HTTP outcomes to terminal evidence; never infer a backend rejection."""

import json
from collections import Counter

from .disk_records import DiskList, jsonl_rows


def classification(record, terminal):
    code = terminal.get("code") if terminal else None
    shape = terminal.get("upstream_error_shape") if terminal else None
    native = terminal.get("upstream_error_code") if terminal else None
    if code == "no_healthy_backend":
        return "gateway_no_healthy_backend"
    if native and shape == "http_error":
        return "vllm_pre_content_rejection"
    if native and shape == "sse_error":
        return "vllm_in_stream_error"
    if code == "upstream_protocol_error" or (
        code == "stream_interrupted" and terminal.get("cause") == "upstream_protocol_error"
    ):
        return "gateway_protocol_rejection"
    return "completed" if record.get("outcome") == "completed" else "other_or_unestablished"


def add_failure_splits(run, gateway_log):
    index = DiskList()
    index.db.execute("create table terminals(id text primary key, value text)")
    for row in jsonl_rows(gateway_log):
        if row.get("msg") == "request terminal":
            index.db.execute(
                "insert into terminals values (?,?)", (row["request_id"], json.dumps(row))
            )

    def visit(value):
        if isinstance(value, dict):
            if "records" in value and "concurrency" in value:
                counts = Counter()
                missing = 0
                for record in value["records"]:
                    key = record.get("gateway_request_id") or record.get("request_id")
                    found = index.db.execute(
                        "select value from terminals where id=?", (key,)
                    ).fetchone()
                    terminal = json.loads(found[0]) if found else None
                    missing += terminal is None and record.get("dispatch_offset_ns") is not None
                    counts[
                        (
                            record.get("http_status"),
                            terminal.get("code") if terminal else None,
                            classification(record, terminal),
                            record.get("error_body_code"),
                            terminal.get("upstream_error_code") if terminal else None,
                        )
                    ] += 1
                value["failure_split"] = [
                    {
                        "http_status": key[0],
                        "gateway_terminal_code": key[1],
                        "class": key[2],
                        "client_error_body_code": key[3],
                        "upstream_error_body_code": key[4],
                        "count": count,
                    }
                    for key, count in counts.items()
                ]
                value["unmatched_dispatched_request_count"] = missing
                value["failure_split_basis"] = (
                    "Exact request-ID join; source-shaped native error metadata, not traceback counts; health failures separate"
                )
            for key, child in value.items():
                if key not in ("records", "metrics"):
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(run)
    index.close()
