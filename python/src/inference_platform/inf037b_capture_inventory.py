"""Capture wire layout and a fail-closed catalogue for the later EKS factory.

No missing adapter, UID-generation inventory, call count or metadata bound is
inferred from the schedule. A catalogue with gaps is not a deployed sizing proof.
The generic capture owner and the 4e report share the actual filenames/encoder.
"""

import ast
from functools import cache
from pathlib import Path

from .inf037b_archive import IntegrityError, encode, sha, strict_json
from .inf037b_contract import (
    ATTEMPT_MS,
    GATEWAYS,
    MAX_ATTEMPTS,
    MAX_RESETS,
    RESET_MS,
    SESSION_ENVELOPE_MS,
)
from .inf037b_producer_limits import (
    CLIENT_DENIAL_BYTES,
    CLIENT_PENDING_BYTES,
    RESP_ARRAY_ELEMENTS,
    RESP_BULK_BYTES,
    RESP_LINE_BYTES,
    resp_contract,
)
from .inf037b_resolver import exact, require

ROOT = Path(__file__).resolve().parents[3]
BASE = "python/src/inference_platform/"
GATE_A = {"objects": 14, "raw_bytes": 1_618_864_547, "index_bytes": 9_119_066}
POD_RETAINERS = frozenset(
    family + ":" + scope
    for family in ("metrics", "native", "lifecycle")
    for scope in ("slot0", "slot1")
) | {"lifecycle:setup"}


def wire_files(sources):
    """The owner creates both files, including for a source with no records."""
    return {
        name: {
            kind: "wire/" + sha(name.encode()) + suffix
            for kind, suffix in (("data", ".bin"), ("index", ".jsonl"))
        }
        for name in sources
    }


def wire_index_record(
    *, source, operation_sha256, start_ns, end_ns, sequence, offset, length, sha256, metadata
):
    """Exact existing wire index encoding; timestamps and metadata are unchanged."""
    return encode(
        {
            "source": source,
            "operation_sha256": operation_sha256,
            "start_ns": start_ns,
            "end_ns": end_ns,
            "sequence": sequence,
            "offset": offset,
            "length": length,
            "sha256": sha256,
            "metadata": metadata,
        }
    )


def validate_source_inventory(sources, inventory):
    if inventory.get("schema") != "inf037b-capture-inventory-v1":
        raise IntegrityError("capture_inventory:schema")
    expected = {entry["name"] for entry in inventory["sources"]}
    if set(sources) != expected or inventory["wire_files"] != sorted(
        path for files in wire_files(sources).values() for path in files.values()
    ):
        raise IntegrityError("capture_inventory:source_set")


def validate_capture_budgets(sources, budgets):
    """Operational limits, pinned per owner/source; never registered numbers."""
    if type(budgets) is not dict or set(budgets) != set(sources):
        raise IntegrityError("capture:budgets:source_set")
    for source, budget in budgets.items():
        if (
            type(budget) is not dict
            or set(budget) != {"raw_bytes", "index_bytes", "records"}
            or any(type(n) is not int or n < 0 for n in budget.values())
        ):
            raise IntegrityError("capture:budgets:invalid:" + source)


def require_eks_capture_binding(binding, sources):
    """Mandatory factory boundary; legacy generic owners remain optional."""
    for key in ("capture_inventory", "capture_budgets"):
        if key not in binding:
            raise IntegrityError("capture:eks_missing:" + key)
    validate_source_inventory(sources, binding["capture_inventory"])
    validate_capture_budgets(sources, binding["capture_budgets"])
    return binding


@cache
def _method(file, qualified):
    path = ROOT / BASE / file
    node = ast.parse(path.read_text(encoding="utf-8"))
    for name in qualified.split("."):
        found = [item for item in node.body if getattr(item, "name", None) == name]
        if len(found) != 1:
            raise IntegrityError("capture_inventory:source_symbol_changed:" + qualified)
        node = found[0]
    return node


def code_ref(file, qualified):
    path = ROOT / BASE / file
    return {
        "path": BASE + file,
        "line": _method(file, qualified).lineno,
        "symbol": qualified,
        "source_lf_sha256": sha(path.read_bytes().replace(b"\r\n", b"\n")),
    }


def _number(node):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.BinOp):
        left, right = _number(node.left), _number(node.right)
        if isinstance(node.op, ast.Pow):
            return left**right
        if isinstance(node.op, ast.Sub):
            return left - right
    raise IntegrityError("capture_inventory:cap_expression_changed")


def _call_cap(file, qualified, call, *, keyword=None):
    node = _method(file, qualified)
    matches = [
        x
        for x in ast.walk(node)
        if isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == call
    ]
    if len(matches) != 1:
        raise IntegrityError("capture_inventory:cap_call_changed")
    found = matches[0]
    expression = (
        next(k.value for k in found.keywords if k.arg == keyword) if keyword else found.args[0]
    )
    if (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "min"
    ):
        expression = expression.args[0]
    return {**code_ref(file, qualified), "line": expression.lineno, "value": _number(expression)}


def read_caps():
    """Extract current literal caps from the readers, not a second numeric policy."""
    response = _call_cap("inf037b_capture.py", "DeadlineHTTP.get", "chunks", keyword="limit")
    watch = _call_cap("inf037b_capture.py", "DeadlineHTTP.lines", "chunks", keyword="limit")
    client = _call_cap("inf037b_live.py", "ClientSSEAdapter.request", "read1")
    denial = {
        **code_ref("inf037b_live.py", "ClientSSEAdapter.request"),
        "value": CLIENT_DENIAL_BYTES + 1,
    }
    redis = _call_cap("inf037b_live.py", "RedisWire.capture_read", "read1")
    rbac = _call_cap("inf037b_row5.py", "BoundedRBACHTTP.json_request", "read1")
    diagnostic = _call_cap("inf037b_bounded.py", "diagnostic_process.read", "read1")
    diagnostic_ceiling = next(
        node.comparators[0].value
        for node in ast.walk(_method("inf037b_bounded.py", "diagnostic_process.read"))
        if isinstance(node, ast.Compare)
        and isinstance(node.comparators[0], ast.Constant)
        and type(node.comparators[0].value) is int
    )
    length = next(
        x.value
        for x in ast.walk(_method("inf037b_capture.py", "DeadlineHTTP.chunks"))
        if isinstance(x, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "length" for t in x.targets)
    )
    reserve = _number(length.args[1].right)
    lines = _method("inf037b_capture.py", "DeadlineHTTP.lines")
    line_default = next(
        default
        for arg, default in zip(lines.args.kwonlyargs, lines.args.kw_defaults, strict=True)
        if arg.arg == "max_line"
    )
    return {
        "http_chunk": {
            **code_ref("inf037b_capture.py", "DeadlineHTTP.chunks"),
            "line": length.args[0].lineno,
            "value": _number(length.args[0]),
            "unit": "one retained read1 chunk",
        },
        "watch_line": {
            **code_ref("inf037b_capture.py", "DeadlineHTTP.lines"),
            "line": line_default.lineno,
            "value": _number(line_default),
            "unit": "normalized line only; oversized partial chunks are retained before refusal",
        },
        "get": {
            **response,
            "unit": "response body",
            "retained_oversize_bytes": reserve,
            "retained_body_cap": response["value"] + reserve,
        },
        "watch": {
            **watch,
            "unit": "one watch response body",
            "retained_oversize_bytes": reserve,
            "retained_body_cap": watch["value"] + reserve,
            "note": "Finite 2**63 ceiling is not a practical deployed sizing envelope; read batches/metadata still need bounds.",
        },
        "client_chunk": {**client, "unit": "one read1 chunk; no response total/read-count cap"},
        "client_denial": {**denial, "unit": "one denial body, including oversize byte"},
        "redis_chunk": {
            **redis,
            "unit": "one read1 chunk; recursive RESP reply has no aggregate cap",
        },
        "diagnostic_output": {
            **diagnostic,
            "value": diagnostic["value"] + diagnostic_ceiling,
            "joined_pipe_bytes": diagnostic_ceiling,
            "read_chunk_bytes": diagnostic["value"],
            "unit": "bounded partial/error body; successful receipt retains its original terminal format",
        },
        "rbac_chunk": {
            **rbac,
            "unit": "one response chunk; request JSON is bounded before encoding by the remaining owner raw budget and existing 8 MiB transport ceiling",
        },
    }


GAPS = (
    (
        "resource_bindings",
        "controller",
        [10, 36],
        "inf037b_resources.py",
        "ResourceAdapter.poll",
        "Independent cgroup/NIC producer and HTTP transport exist; deployment must bind each role's cgroup, interface, source generation, endpoint and proven CPU/NIC capacity.",
    ),
    (
        "gpu_device_release",
        "kubernetes",
        [41, 44],
        "inf037b_setup.py",
        "startup_row",
        "The device producer binds API-retained device report/producer/node/pin joins. The actual independent node producer, secured source/clock mapping and deployed capture source closure remain 4e_device_release_inputs; Pod/process exit or Ready never proves GPU-free.",
    ),
    (
        "placement_api",
        "controller",
        [76, 104, 106],
        "inf037b_placement.py",
        "check_placement",
        "The placement checker implements authoritative Job/Pod/Node/full-census capture with the single checker; final node/Job/image/clock/RBAC and retainer bindings remain 4e_export_placement_inputs.",
    ),
    (
        "controller_phase_capture",
        "controller",
        [42, 50, 60, 64],
        "inf037b_lifecycle.py",
        "LifecycleJournal.append",
        "Local journals/observation producers exist; the complete EKS command-to-capture and cleanup-inventory routing is not built.",
    ),
)


def wire_record_families(profiles):
    """Possible raw families, not a periodic-only count or deployed closure."""
    families = {
        "owner.periodic_completion",
        "owner.scheduled_error",
        "owner.action_completion",
        "owner.action_error",
        "owner.lineage_admission",
        "owner.rejected_normalization",
    }
    for profile in profiles:
        if profile in {"get", "watch", "rbac_chunk"}:
            families.update(
                {
                    "http.response_headers",
                    "http.rejected_headers",
                    "http.completed_body",
                    "http.eof",
                    "http.partial_error",
                    "producer.limit_refusal",
                }
            )
        if profile == "watch":
            families.update({"watch.batch_completion", "watch.cutoff", "watch.partial_line_error"})
        elif profile == "rbac_chunk":
            families.add("http.conditional_request_json")
        elif profile in {"client_chunk", "client_denial"}:
            families.update(
                {
                    "client.request_json",
                    "client.tls_observation",
                    "client.response_headers",
                    "client.rejected_headers",
                    "client.rejected_error_text",
                    "client.denial_body",
                    "client.sse_frames",
                    "client.eof_cancel_error",
                    "client.request_end",
                    "producer.limit_refusal",
                }
            )
        elif profile == "redis_chunk":
            families.update({"redis.completed_reply", "redis.partial_error"})
            families.add("producer.limit_refusal")
        elif profile == "diagnostic_output":
            families.update(
                {
                    "diagnostic.input",
                    "diagnostic.stdout_stderr",
                    "diagnostic.partial_timeout_error",
                    "diagnostic.exit_receipt",
                }
            )
    return sorted(families)


def producer_limit_audit():
    """Finite census is pinned; complete per-owner byte partitions still stop."""
    from .inf037b_eks_placement import census_bound

    return {
        "status": "partial_sourced_allowance_stop",
        "refusal": "capture:unresolved:producer_limits",
        "known_read_caps": read_caps(),
        "sourced_contract_rows": producer_contracts(),
        "census": {role: census_bound(role) for role in ("cpu", "gpu")},
        "census_source": code_ref("inf037b_eks_placement.py", "census_bound"),
        "missing": [
            {
                "family": "complete_scope_source_and_index_shapes",
                "bytes_upper": None,
                "records_upper": None,
                "reason": "D2-prime partition is not admitted: unresolved producer/index metadata shapes remain explicit in partition_proposal.",
            }
        ],
    }


def producer_contracts():
    """Partial sourced rows; none certifies a whole-owner budget."""
    from .inf037b_live import REDIS_SNAPSHOT

    return {
        "client_denial": {
            "body_bytes": CLIENT_DENIAL_BYTES,
            "rejected_read_bytes": CLIENT_DENIAL_BYTES + 1,
            "source": code_ref("inf037b_live.py", "ClientSSEAdapter.request"),
            "authority": "Existing denial acceptance ceiling (Round 365 source).",
        },
        "client_sse_pending": {
            "pending_bytes": CLIENT_PENDING_BYTES,
            "source": code_ref("inf037b_requests.py", "SSEDecoder.feed"),
            "authority": "Existing normalized SSE pending-buffer ceiling; not a frame-count or response-total bound.",
        },
        "resp_element": {
            "bulk_bytes": RESP_BULK_BYTES,
            "line_bytes": RESP_LINE_BYTES,
            "array_elements": RESP_ARRAY_ELEMENTS,
            "source": code_ref("inf037b_live.py", "RedisWire.read"),
            "authority": "Existing per-bulk/read-line/per-array acceptance ceilings; not a generic aggregate contract.",
        },
        "resp_fixed_commands": {
            "AUTH": resp_contract(("AUTH",), REDIS_SNAPSHOT),
            "TIME": resp_contract(("TIME",), REDIS_SNAPSHOT),
            "snapshot": resp_contract(("EVAL", REDIS_SNAPSHOT), REDIS_SNAPSHOT),
            "source": code_ref("inf037b_producer_limits.py", "resp_contract"),
            "snapshot_source": code_ref("inf037b_live.py", "RedisAdapter.snapshot"),
            "time_source": code_ref("inf037b_live.py", "ClockAdapter.redis"),
            "authority": "Fixed AUTH scalar, TIME pair and pinned snapshot cjson scalar, including error-scalar alternative; existing element ceilings bound byte lengths.",
        },
        "census_candidate": census_candidate(),
        "audit_candidate": audit_candidate(),
        "round367": sourced_reading_contracts(),
    }


def audit_candidate():
    from .inf037b_producer_contracts import ADMIT_FIELDS, AUDIT_COUNT, audit_reply_contract

    return {
        **audit_reply_contract(),
        "entries_per_reply": AUDIT_COUNT,
        "field_elements_per_entry": 2 * len(ADMIT_FIELDS),
        "source": code_ref("inf037b_live.py", "RedisAdapter.operations"),
        "status": "enforced_pinned_schema_not_a_whole_owner_budget",
    }


def sourced_reading_contracts():
    from .inf037b_producer_contracts import (
        ERROR_TEXT_BYTES,
        FIXED_POD_GENERATIONS,
        HEADER_BYTES,
        HEADER_COUNT,
        HEADER_NAME_BYTES,
        HEADER_REJECTED_BYTES,
        HEADER_VALUE_BYTES,
        POD_TRANSITIONS,
        WATCH_EVENTS,
        client_contract,
        redis_scope_contract,
    )

    return {
        "source_record": "docs/INF037B_PRODUCER_CONTRACT_SOURCES.json",
        "trace": client_contract(1),
        "control": client_contract(64),
        "client_headers": {
            "count": HEADER_COUNT,
            "name_bytes": HEADER_NAME_BYTES,
            "value_bytes": HEADER_VALUE_BYTES,
            "bytes": HEADER_BYTES,
            "rejected_bytes": HEADER_REJECTED_BYTES,
        },
        "client_error_bytes": ERROR_TEXT_BYTES,
        "watch": {
            "per_pod_events": POD_TRANSITIONS,
            "pod_generations": FIXED_POD_GENERATIONS,
            "events": WATCH_EVENTS,
            "connections_formula": "1+floor(T/7200)+5+3*5+2",
        },
        "redis_uncomposed": redis_scope_contract(),
        "census_node_pod_limit": None,
    }


def sourced_scope_envelopes():
    """Candidate component uppers, with unbound deadlines never set to session T.

    Complete scope/index totals stay unknown where control/page/source metadata
    is unresolved. These are not observed demand or accepting owner budgets.
    """
    from .inf037b_eks_collectors import (
        CLOCK_POLL_MS,
        GATEWAY_POLL_MS,
        KUBERNETES_POLL_MS,
        LIFECYCLE_POLL_MS,
        METRICS_POLL_MS,
        NATIVE_POLL_MS,
        PROBE_OWNER_MS,
        RESOURCE_POLL_MS,
        SCOPE_WINDOWS_MS,
        STARTUP_MS,
        ScopeWindow,
        redis_counts,
    )
    from .inf037b_eks_commands import capture_instance_schedule
    from .inf037b_producer_contracts import audit_reply_contract, client_contract
    from .inf037b_redis_shapes import fixed_contract

    rows = []
    for scope in capture_instance_schedule()["logical_scopes"]:
        name = scope["scope"]
        if not scope["max_owners"]:
            rows.append(
                {
                    "scope": name,
                    "owner_id": scope["owner_id"],
                    "shared_with": scope.get("shared_with"),
                    "families": [],
                    "reason": scope["reason"],
                }
            )
            continue
        duration = (
            ATTEMPT_MS
            if name.startswith("attempt:")
            else STARTUP_MS
            if name in ("cold_startup", "cached_startup")
            else PROBE_OWNER_MS
            if name == "fitness_probe_and_signal"
            else RESET_MS
            if name in ("attempt_setup:2", "attempt_setup:3")
            else SCOPE_WINDOWS_MS.get(name)
        )
        window = (
            None
            if duration is None
            else ScopeWindow(name, 0, duration * 1000000, "registered-or-booked-scope-upper")
        )
        # Fixed effect plan and inline row5 calls have separate source authority;
        # the known subtotal below does NOT silently bound either by periodic T.
        calls = redis_counts(window) if window else None
        offers = window.traffic() if window else 0
        controls = (
            window.controls() if window else 10 if name == "row5_controls_and_restoration" else 0
        )
        families = []

        def add(source, family, count, cap, units, reason, *, contiguous=False, families=families):
            raw = None if count is None else count * cap
            records = None if count is None else count * units
            # Metadata for this particular body/reply family is fixed. A header,
            # request, error or owner marker is a SEPARATE unresolved row below.
            meta = (
                {"protocol": "RESP2", "unit": "resp_reply", "read_count": 2**63 - 1}
                if contiguous
                else {"unit": "sse_frame", "status": 200, "read_count": 2**63 - 1}
            )
            frame = strict_json(
                wire_index_record(
                    source=source,
                    operation_sha256="f" * 64,
                    start_ns=-(2**63),
                    end_ns=-(2**63),
                    sequence=-(2**63),
                    offset=-(2**63),
                    length=-(2**63),
                    sha256="f" * 64,
                    metadata=meta,
                )
            )
            frame.update(physical_spans=[[-(2**63), -(2**63)]], read_count=2**63 - 1)
            index = None if records is None else records * len(encode(frame))
            # Shared concurrent HTTP connections can interleave one physical
            # span per byte. This is space, not another record per TCP read.
            if index is not None and not contiguous:
                index += raw * len(encode([-(2**63), -(2**63)]))
            if not contiguous and not source.startswith("client:"):
                index = None  # Full path/UID/process-generation metadata binding is unresolved.
            families.append(
                {
                    "source": source,
                    "family": family,
                    "calls_upper": count,
                    "raw_bytes_upper": raw,
                    "records_upper": records,
                    "index_bytes_upper": index,
                    "argument": reason,
                    "exceeds_raw_allowance": raw is not None and raw > GATE_A["raw_bytes"],
                    "exceeds_index_allowance": index is not None and index > GATE_A["index_bytes"],
                    "index_basis": "fixed reply/status metadata +int64 counters and physical spans"
                    if index is not None
                    else "UNRESOLVED: path/UID/process metadata binding",
                }
            )

        for source in scope["known_sources"]:
            if source == "redis":
                for kind in ("AUTH", "TIME", "snapshot", "audit"):
                    cap = (audit_reply_contract() if kind == "audit" else fixed_contract(kind))[
                        "bytes"
                    ] + 1
                    add(
                        source,
                        "redis.response." + kind,
                        None if calls is None else calls[kind],
                        cap,
                        2,
                        "ComposedCollectors periodic + initial boundary only; fixed-effect boundary and row5 inline calls remain separately unresolved",
                        contiguous=True,
                    )
            elif source.startswith("client:"):
                for kind, count, tokens in (("trace", offers, 1), ("controls", controls, 64)):
                    contract = client_contract(tokens)
                    add(
                        source,
                        "client.sse_frames." + kind,
                        count,
                        contract["body_bytes"] + 65536,
                        contract["frames"] + 1,
                        "registered 600s pre +960s event, or 120s probe; six probe /ten row5 controls, all-offers-per-gateway conservative upper",
                    )
            elif source == "kubernetes":
                add(
                    source,
                    "http.kubernetes_snapshot_bodies",
                    None if not window else 2 * window.slots(KUBERNETES_POLL_MS),
                    8388609,
                    2,
                    "KubernetesAdapter.snapshot opens two GETs per composed 250ms tick",
                )
            elif source.startswith(("gateway", "native:", "metrics:", "lifecycle:", "resource:")):
                period = (
                    GATEWAY_POLL_MS
                    if source.startswith("gateway")
                    else METRICS_POLL_MS
                    if source.startswith("metrics:")
                    else NATIVE_POLL_MS
                    if source.startswith("native:")
                    else LIFECYCLE_POLL_MS
                    if source.startswith("lifecycle:")
                    else RESOURCE_POLL_MS
                )
                multiplicity = 4 if source.startswith("metrics:") else 1
                # First engine config needs metrics +models; sample metrics +health.
                count = None if not window else multiplicity * window.slots(period)
                if count is not None and source.startswith(("gateway", "lifecycle:")):
                    count += window.slots(CLOCK_POLL_MS)
                if name == "fitness_probe_and_signal" and (
                    source.startswith("gateway") or source.startswith("native:")
                ):
                    add(
                        source,
                        "http.probe_settle_bodies",
                        602,
                        8388609,
                        2,
                        "SingleProbe.run ready/settle only: at most 1 initial +floor(30s/50ms)+1 terminal poll; does NOT call Redis",
                    )
                add(
                    source,
                    "http.periodic_bodies",
                    count,
                    8388609,
                    2,
                    "ComposedCollectors callback cadence; metrics allows engine two GETs +sample/health two; node/gateway clock uses 1000ms",
                )
            families.append(
                {
                    "source": source,
                    "family": "remaining_record_families",
                    "raw_bytes_upper": None,
                    "index_bytes_upper": None,
                    "records_upper": None,
                    "reason": "headers/requests/errors/owner/lineage/watch/page/fixed-effect and row5-inline fanout require the pinned complete source and scope bindings; census cardinality is finite but raw producer/index shapes remain unresolved",
                }
            )
        known = [f for f in families if f["raw_bytes_upper"] is not None]
        rows.append(
            {
                "scope": name,
                "owner_id": scope["owner_id"],
                "duration_upper_s": None if duration is None else duration // 1000,
                "duration_basis": "own registered/booked deadline upper"
                if window
                else "UNRESOLVED: no source-pinned scope window; no session fallback",
                "connections": {
                    "redis": 1 if window else None,
                    "http": "one fresh connection per GET/client call; watch lifetime in WatchBudget; source-specific control calls unresolved",
                },
                "offers_upper_per_gateway": offers,
                "controls_upper_per_gateway": controls,
                "periodic_redis_calls": calls,
                "fixed_action_count": None,
                "families": families,
                "bounded_family_subtotal": {
                    k: sum(f[k] for f in known if f[k] is not None)
                    for k in ("raw_bytes_upper", "index_bytes_upper", "records_upper")
                },
                "whole_scope_raw_bytes_upper": None,
                "whole_scope_index_bytes_upper": None,
                "status": "STOP_allowance_exceeded_and_incomplete"
                if any(
                    f.get("exceeds_raw_allowance") or f.get("exceeds_index_allowance")
                    for f in known
                )
                else "STOP_incomplete",
            }
        )
    return rows


def allowance_holder(rows=None):
    """The slice plan has no per-scope split: one whole-run allowance holder."""
    rows = sourced_scope_envelopes() if rows is None else rows
    partial = {
        key: sum(row.get("bounded_family_subtotal", {}).get(key, 0) for row in rows)
        for key in ("raw_bytes_upper", "index_bytes_upper", "records_upper")
    }
    return {
        "holder": "whole session; INF037B_4E_02_03_SLICES.md 02-E/shared constraints",
        "allowance": GATE_A,
        "known_component_subtotal": partial,
        "whole_raw_bytes_upper": None,
        "whole_index_bytes_upper": None,
        "status": "STOP_allowance_exceeded_and_source_incomplete"
        if partial["raw_bytes_upper"] > GATE_A["raw_bytes"]
        or partial["index_bytes_upper"] > GATE_A["index_bytes"]
        else "STOP_source_incomplete",
    }


def census_candidate():
    """Existing loose guards yield a conservative raw bound, not owner fitness.

    A canonical JSON size ceiling does not cap whitespace in the raw response.
    Header/index sizes and repeated control calls remain unresolved. Do not
    reduce this candidate to fit Gate A or present it as measured demand.
    """

    def ceiling(file, method, expression):
        found = [
            n
            for n in ast.walk(_method(file, method))
            if isinstance(n, ast.Compare)
            and ast.unparse(n.left) == expression
            and len(n.comparators) == 1
            and isinstance(n.comparators[0], ast.Constant)
        ]
        if len(found) != 1:
            raise IntegrityError("capture_inventory:census_cap_changed:" + expression)
        return _number(found[0].comparators[0])

    from .inf037b_eks_placement import census_bound

    guards = [
        n
        for n in ast.walk(_method("inf037b_eks_placement.py", "PlacementAPI.census"))
        if isinstance(n, ast.Compare) and ast.unparse(n) == "len(pages) <= limit"
    ]
    require(len(guards) == 1, "capture_inventory:census_cap_changed:len(pages)")
    # Even non-full/empty continuation pages count; never assume the API fills
    # every requested 100-Pod page. N continuations plus one final page.
    pages = max(census_bound(role)["N"] for role in ("cpu", "gpu")) + 1
    normalized = ceiling("inf037b_eks_placement.py", "PlacementAPI.census", "total_bytes")
    body = ceiling("inf037b_row5.py", "BoundedRBACHTTP.json_request", "total")
    return {
        "pages": pages,
        "canonical_json_bytes": normalized,
        "body_bytes_per_page": body,
        # A first excess byte refuses the invocation; it cannot recur on every
        # page within one successfully continuing census.
        "raw_bytes_upper_including_rejected_read": pages * body + 1,
        "source": code_ref("inf037b_eks_placement.py", "PlacementAPI.census"),
        "reader_source": code_ref("inf037b_row5.py", "BoundedRBACHTTP.json_request"),
        "status": "non_binding_reader_context_not_a_shape_or_owner_budget",
        "historical_non_binding_context": {
            "pages": 10000,
            "raw_bytes_upper_including_rejected_read": 10000 * body + 1,
            "source_commit": "8159808",
        },
    }


def source_inventory(
    *,
    origins=(),
    nodes=("node0", "node1"),
    generations_complete=False,
    slots=(0, 1),
    separate_setup=False,
    source_names=None,
    resource_roles=(),
):
    """Physical retainers follow scope slots; UID lineage never changes paths.

    Origins/generations_complete remain compatibility inputs for lineage data,
    not cardinality authority. All records on pod retainers carry both identities.
    source_names selects a declared scope's transports, including empty files.
    """
    from .inf037b_resources import RESOURCE_ROLES
    from .inf037b_row5_kind import row5_runtime_sources

    require_roles = tuple(resource_roles)
    if len(require_roles) != len(set(require_roles)) or not set(require_roles) <= set(
        RESOURCE_ROLES
    ):
        raise IntegrityError("capture_inventory:resource_roles")

    nodes, origins = tuple(nodes), tuple(dict(origin) for origin in origins)
    slots = tuple(slots)
    if (
        any(type(slot) is not int or slot not in (0, 1) for slot in slots)
        or len(slots) != len(set(slots))
        or type(separate_setup) is not bool
    ):
        raise IntegrityError("capture_inventory:slots")
    if (
        len(nodes) != 2
        or len(nodes) != len(set(nodes))
        or any(type(n) is not str or not n for n in nodes)
    ):
        raise IntegrityError("capture_inventory:nodes")
    if type(generations_complete) is not bool or any(
        set(p) != {"uid", "slot", "node", "process_generation"} for p in origins
    ):
        raise IntegrityError("capture_inventory:origins")
    if len({p["uid"] for p in origins}) != len(origins) or any(
        type(p["slot"]) is not int
        or p["slot"] not in (0, 1)
        or p["node"] not in nodes
        or any(type(p[k]) is not str or not p[k] for k in ("uid", "node", "process_generation"))
        for p in origins
    ):
        raise IntegrityError("capture_inventory:origins")
    base = row5_runtime_sources(dict.fromkeys(GATEWAYS, "unbound"), "unbound")
    entries = []
    adapter_refs = {
        "ResourceAdapter.poll": [
            ("inf037b_resources.py", "ResourceAdapter.poll"),
            ("inf037b_resources.py", "ProcCounters"),
            ("inf037b_resource_agent.py", "PinnedCounters"),
            ("inf037b_resource_agent.py", "producer_from_spec"),
            ("inf037b_nic.py", "nic_capacity_documents"),
        ],
        "GatewayAdapter.poll": [("inf037b_live.py", "GatewayAdapter.poll")],
        "ClientSSEAdapter.request": [("inf037b_live.py", "ClientSSEAdapter.request")],
        "RedisAdapter + RedisWire": [
            ("inf037b_live.py", "RedisAdapter.operations"),
            ("inf037b_live.py", "RedisWire.read"),
        ],
        "DiagnosticProcess.run_from_captures/_run": [
            ("inf037b_row5_diagnostic.py", "DiagnosticProcess._run"),
            ("inf037b_bounded.py", "diagnostic_process"),
        ],
        "RoleControl + BoundedRBACHTTP": [
            ("inf037b_row5.py", "RoleControl"),
            ("inf037b_row5.py", "BoundedRBACHTTP.json_request"),
        ],
        "ClockAdapter + KindRow5Ports.poll_clocks": [
            ("inf037b_live.py", "ClockAdapter"),
            ("inf037b_row5_kind.py", "KindRow5Ports.poll_clocks"),
        ],
        "KubernetesAdapter.snapshot/watch_pods": [
            ("inf037b_live.py", "KubernetesAdapter.snapshot"),
            ("inf037b_live.py", "KubernetesAdapter.watch_pods"),
        ],
        "NodeCacheAdapter.capture/clock": [
            ("inf037b_live.py", "NodeCacheAdapter.capture"),
            ("inf037b_live.py", "NodeCacheAdapter.clock"),
        ],
        "VLLMAdapter.sample/engine_config": [
            ("inf037b_live.py", "VLLMAdapter.sample"),
            ("inf037b_live.py", "VLLMAdapter.engine_config"),
        ],
        "NativeRequestAdapter.poll": [("inf037b_probe.py", "NativeRequestAdapter._poll")],
        "NodeLifecycleAdapter.poll/clock": [
            ("inf037b_live.py", "NodeLifecycleAdapter.poll"),
            ("inf037b_live.py", "NodeLifecycleAdapter.clock"),
        ],
    }

    def describe(name, kinds, scope, adapter, transport, profile, lines, period=None):
        return {
            "name": name,
            "source_kinds": kinds,
            "scope": scope,
            "owner": "CaptureOwner",
            "retainer": f"owner.retainer({name!r}, uid=pod_uid, process_generation=process_generation)"
            if name in POD_RETAINERS
            else f"owner.retainer({name!r})",
            "adapter": adapter,
            "transport": transport,
            "read_cap_profiles": profile,
            "wire_record_families": wire_record_families(profile),
            "nonwire_artifacts": [
                "normalized_rows",
                "loss_journal",
                "close_descriptor",
                "hash_readback_and_barriers",
            ],
            "adapter_code_refs": [code_ref(*ref) for ref in adapter_refs[adapter]],
            "owner_code_ref": code_ref("inf037b_capture.py", "CaptureOwner.retainer"),
            "registration": {"path": "docs/INF037B_REGISTRATION_V4_R315.md", "lines": lines},
            "schedule": {
                "session_ms_upper": SESSION_ENVELOPE_MS,
                "period_ms": period,
                "scheduled_slots_upper": (SESSION_ENVELOPE_MS + period - 1) // period
                if period
                else None,
                "formula": "ceil(session_ms / period_ms); excludes unscheduled/control/page reads",
                "total_read_count_cap": None,
            },
            "wire_files": list(wire_files([name])[name].values()),
            "can_be_empty": True,
        }

    def add(*args):
        entries.append(describe(*args))

    for name, triples in base.items():
        if name in GATEWAYS:
            args = ("GatewayAdapter.poll", "DeadlineHTTP GET", ["get"], [10, 37, 38], 250)
        elif name in {"client:" + g for g in GATEWAYS}:
            args = (
                "ClientSSEAdapter.request",
                "verified HTTP/SSE",
                ["client_chunk", "client_denial"],
                [10, 36, 40],
                None,
            )
        elif name == "redis":
            args = ("RedisAdapter + RedisWire", "RESP/TLS", ["redis_chunk"], [10, 37, 38], 250)
        elif name == "diagnostic":
            args = (
                "DiagnosticProcess.run_from_captures/_run",
                "subprocess stdin/stdout/stderr",
                ["diagnostic_output"],
                [37],
                None,
            )
        elif name == "rbac":
            args = (
                "RoleControl + BoundedRBACHTTP",
                "HTTPS request/response",
                ["rbac_chunk"],
                [37],
                None,
            )
        elif name == "clocks":
            args = (
                "ClockAdapter + KindRow5Ports.poll_clocks",
                "gateway HTTPS/Redis TIME + local clocks",
                ["get", "redis_chunk"],
                [39],
                1000,
            )
        else:
            raise IntegrityError("capture_inventory:unclassified_source:" + name)
        scope = {"gateways": list(GATEWAYS), "slots": [0, 1], "uids": "all bound generations"}
        if name in GATEWAYS or name.startswith("client:"):
            scope = {"gateways": [name.removeprefix("client:")]}
        elif name == "rbac":
            scope = {
                "gateways": list(GATEWAYS),
                "role": "packet-bound reviewed EndpointSlice authorization",
            }
        elif name == "clocks":
            scope = {"gateways": list(GATEWAYS), "redis": True, "measurement": "local mapping"}
        add(
            name,
            sorted({t[0] for t in triples}),
            scope,
            *args,
        )
    add(
        "kubernetes",
        ["kubernetes"],
        {"slots": [0, 1], "uids": "all bound origins"},
        "KubernetesAdapter.snapshot/watch_pods",
        "API GET + owned watch",
        ["get", "watch"],
        [10, 36, 39, 40, 41],
        250,
    )
    for node in nodes:
        add(
            "node-cache:" + node,
            ["kubernetes", "clocks"],
            {"node": node},
            "NodeCacheAdapter.capture/clock",
            "node HTTPS /snapshot + /clock",
            ["get"],
            [39, 41, 44],
        )
    uid_families = (
        (
            "metrics:",
            ["vllm"],
            "VLLMAdapter.sample/engine_config",
            "native /metrics /health /v1/models",
            500,
        ),
        (
            "native:",
            ["vllm"],
            "NativeRequestAdapter.poll",
            "supervisor /native/events pagination",
            None,
        ),
        (
            "lifecycle:",
            ["kubernetes", "vllm", "clocks"],
            "NodeLifecycleAdapter.poll/clock",
            "supervisor /events + /clock",
            None,
        ),
    )
    for scope in [*("slot" + str(slot) for slot in slots), *(["setup"] if separate_setup else [])]:
        for prefix, kinds, adapter, transport, period in uid_families:
            if scope == "setup" and prefix != "lifecycle:":
                continue  # Separate signal process, not another model/native emitter.
            add(
                prefix + scope,
                kinds,
                {
                    "slot": int(scope[-1]) if scope.startswith("slot") else None,
                    "separate_setup_process": scope == "setup",
                    "adapter_index_metadata_required": ["uid", "process_generation"],
                    "owner_record_exemption": {"owner_record": True},
                    "normalized_lineage": "vllm:<uid>",
                    "uids": "all observed generations; not a file-count multiplier",
                },
                adapter,
                transport,
                ["get"],
                [10, 36, 39, 40, 41],
                period,
            )
    for role in require_roles:
        add(
            "resource:" + role,
            ["controller", "clocks"],
            {"role": role},
            "ResourceAdapter.poll",
            "independent role agent HTTPS /resources; cgroup CPU and NIC counters",
            ["get"],
            [10, 36, 39],
            500,
        )
    if source_names is not None:
        selected = set(source_names)
        if not selected <= {entry["name"] for entry in entries}:
            raise IntegrityError("capture_inventory:scope_sources")
        entries = [entry for entry in entries if entry["name"] in selected]
    names = [e["name"] for e in entries]
    if len(names) != len(set(names)):
        raise IntegrityError("capture_inventory:duplicate_source")
    gaps = [
        {
            "source": name,
            "source_kind": kind,
            "v4_lines": lines,
            "existing_consumer": code_ref(file, consumer),
            "reason": reason,
            "wire_files": None,
        }
        for name, kind, lines, file, consumer, reason in GAPS
    ]
    gaps.append(
        {
            "source": "normalized_row_routing",
            "v4_lines": [32, 39],
            "reason": "Round 337 implements owner-local Kubernetes UID admission and shared vllm UID/generation sequencing across physical retainers. Full controller-phase source routing remains in the campaign/terminal slices; no complete deployed routing is asserted.",
            "wire_files": None,
        }
    )
    files = sorted(p for entry in entries for p in entry["wire_files"])
    return {
        "schema": "inf037b-capture-inventory-v1",
        "count_scope": "slot-keyed known-adapter catalogue for one owner; full run is the explicit owner table",
        "sources": entries,
        "wire_files": files,
        "known_wire_file_count": len(files),
        "wire_file_count": None,
        "complete": False,
        "gaps": gaps,
        "unbound_uid_families": [],
        "slots": list(slots),
        "separate_setup": separate_setup,
        "bound_origins_for_lineage_only": list(origins),
        "other_artifacts": [
            "archive/raw/*.jsonl (shared normalized archive)",
            "capture-store/state.json and operation journals (separate from wire objects)",
        ],
    }


def _bound(value):
    if value is not None and (type(value) is not int or value < 0):
        raise IntegrityError("capture_inventory:nonnegative_integer_bound")
    return value


def _product(a, b):
    a, b = _bound(a), _bound(b)
    return 0 if a == 0 or b == 0 else None if a is None or b is None else a * b


def source_envelope(
    name, components=(), *, integer_abs_upper=None, budget=None, owner_records=None
):
    """Bounds for explicitly enforced contracts, never default missing caps to zero.

    metadata_json_bytes includes encode(metadata)'s newline. The counter bound
    covers every source's global sequence/offset/length and both timestamps.
    The negative extreme conservatively pays a sign byte as well as the digits.
    """
    if budget is not None:
        validate_capture_budgets([name], {name: budget})
        records = budget["records"] if owner_records is None else _bound(owner_records)
        if records < budget["records"]:
            raise IntegrityError("capture_inventory:counter_bound")
        return {
            "source": name,
            "status": "bounded",
            "formula": "pre-write CaptureOwner.retain raw/index/record budgets",
            "components": list(components),
            "raw_bytes_upper": budget["raw_bytes"],
            "index_bytes_upper": budget["index_bytes"],
            "records_upper": budget["records"],
            "integer_abs_upper": max(2**63, budget["raw_bytes"], records),
            "budget": dict(budget),
        }
    upper = _bound(integer_abs_upper)
    result = []
    for component in components:
        cap, count = _bound(component["read_cap_bytes"]), _bound(component["max_reads"])
        metadata = _bound(component["metadata_json_bytes"])
        if metadata is not None and metadata < len(encode({})):
            raise IntegrityError("capture_inventory:metadata_encoding_bound")
        raw = _product(cap, count)
        if count == 0:
            index, frame = 0, None
        elif metadata is None or upper is None:
            index, frame = None, None
        else:
            if (raw is not None and raw > upper) or (count is not None and count > upper):
                raise IntegrityError("capture_inventory:counter_bound")
            frame = (
                len(
                    wire_index_record(
                        source=name,
                        operation_sha256="f" * 64,
                        start_ns=-upper,
                        end_ns=-upper,
                        sequence=-upper,
                        offset=-upper,
                        length=-upper,
                        sha256="f" * 64,
                        metadata={},
                    )
                )
                - len(encode({}))
                + metadata
            )
            index = _product(frame, count)
        result.append(
            {
                **component,
                "raw_bytes_upper": raw,
                "index_record_bytes_upper": frame,
                "index_bytes_upper": index,
            }
        )

    def total(key):
        return None if any(r[key] is None for r in result) else sum(r[key] for r in result)

    raw, index = total("raw_bytes_upper"), total("index_bytes_upper")
    return {
        "source": name,
        "status": "unbounded" if raw is None or index is None else "bounded",
        "formula": "sum(read_cap_bytes * max_reads); index uses actual encoder + bounded metadata/counters",
        "components": result,
        "raw_bytes_upper": raw,
        "index_bytes_upper": index,
    }


def partition_proposal():
    """D2-prime: pinned producer maxima at 1x; captured shapes would use 4x.

    No capture or index framing is invented for unresolved families.
    """
    from .inf037b_producer_contracts import audit_reply_contract, client_contract
    from .inf037b_redis_shapes import ERROR_LINE_BYTES, fixed_contract

    rows = []
    for scope in sourced_scope_envelopes():
        for family in scope.get("families", []):
            name = family["family"]
            count = family.get("calls_upper")
            shape = None
            source = None
            aggregate = None
            audit_entries = None
            if name.startswith("redis.response.") and not name.endswith("audit"):
                shape = fixed_contract(name.rsplit(".", 1)[1])["bytes"]
                source = "python/src/inference_platform/inf037b_redis_shapes.py:fixed_contract"
            elif name == "redis.response.audit" and count is not None:
                audit = audit_reply_contract()
                shape = audit["valid_reply_bytes"]
                source = "inf037b_producer_contracts.audit_reply_contract; inf037b_eks_collectors.producer_entries/redis_counts"
                # A cursor drains each entry at most once in this owner, but a
                # later owner can start at zero and drain earlier stream data.
                # The full lifetime entry ceiling is already pinned; no 4x
                # factor and no one-full-batch-per-empty-poll multiplication.
                audit_entries = min(scope["periodic_redis_calls"]["entries"], count * 1000)
                aggregate = audit_entries * audit["entry_bytes"] + count * max(
                    ERROR_LINE_BYTES, audit["valid_reply_bytes"] - 1000 * audit["entry_bytes"]
                )
            elif name.startswith("client.sse_frames."):
                if name.endswith("trace") and count is not None:
                    # Each CampaignCaptureScope traffic action selects its own
                    # alternating gateway half. The older worst-case table paid
                    # all offers at BOTH gateways; do not reuse that in D2.
                    count = (count + 1) // 2
                shape = client_contract(64 if name.endswith("controls") else 1)["body_bytes"]
                source = "python/src/inference_platform/inf037b_sse_shapes.py:client_contract"
            raw = None if count is None or shape is None else count * shape
            if aggregate is not None:
                raw = aggregate
            rows.append(
                {
                    "scope": scope["scope"],
                    "source": family["source"],
                    "family": name,
                    "schedule_count": count,
                    "schedule_source": "inf037b_eks_collectors.ScopeWindow/redis_counts; v4-r315:36,39,48,57,58",
                    "unit_raw_bytes": shape,
                    "shape_source": source,
                    "headroom": 1 if shape is not None else 4,
                    "basis": "pinned_maximum"
                    if shape is not None
                    else "missing_same_version_shape_or_capture",
                    "raw_partition_bytes": raw,
                    **(
                        {
                            "entries_upper": audit_entries,
                            "aggregation": "one-drain-per-owner entry ceiling plus per-call framing/error bound",
                        }
                        if aggregate is not None
                        else {}
                    ),
                    "index_partition_bytes": None,
                    "status": "STOP_missing_shape_or_schedule" if raw is None else "sized_raw_only",
                    "missing": "Need a pinned complete producer/index-metadata shape or largest committed capture of this exact producer; body read caps are not measured shapes.",
                }
            )
    raw = sum(r["raw_partition_bytes"] or 0 for r in rows)
    reserve = {k: max(1, GATE_A[k] // 100) for k in ("raw_bytes", "index_bytes")}
    return {
        "schema": "inf037b-partition-proposal-v1",
        "headroom": {"pinned_maximum": 1, "same_version_capture": 4},
        "reserve": reserve,
        "allowance": GATE_A,
        "known_raw_plus_reserve": raw + reserve["raw_bytes"],
        "rows": rows,
        "status": "STOP_known_exceeds_allowance"
        if raw + reserve["raw_bytes"] > GATE_A["raw_bytes"]
        else "STOP_missing_families",
        "admitted": False,
        "worst_case_context": "sourced_scope_envelopes remains non-binding; no 18,000s fallback and no admitted per-source budget",
    }


def admit_partition(proposal):
    exact(proposal, partition_proposal(), "capture_inventory:partition_provenance")
    require(
        proposal["known_raw_plus_reserve"] <= GATE_A["raw_bytes"],
        "capture_inventory:partition_allowance",
    )
    require(
        all(
            r["raw_partition_bytes"] is not None and r["index_partition_bytes"] is not None
            for r in proposal["rows"]
        ),
        "capture_inventory:partition_missing_shape",
    )
    require(
        sum(r["index_partition_bytes"] for r in proposal["rows"])
        + proposal["reserve"]["index_bytes"]
        <= GATE_A["index_bytes"],
        "capture_inventory:partition_allowance",
    )
    require(proposal["admitted"] is True, "capture_inventory:partition_not_admitted")
    return True


def capture_envelope(*, capture_budgets=None, **bindings):
    from .inf037b_eks_commands import capture_instance_schedule

    inventory, caps = source_inventory(**bindings), read_caps()
    owner_table = capture_instance_schedule()
    names = [entry["name"] for entry in inventory["sources"]]
    if capture_budgets is not None:
        validate_capture_budgets(names, capture_budgets)
    owner_records = sum(b["records"] for b in capture_budgets.values()) if capture_budgets else 0
    sources = []
    for entry in inventory["sources"]:
        profiles = entry["read_cap_profiles"]
        components = [
            {
                "kind": profile,
                "read_cap_bytes": caps[profile].get("retained_body_cap", caps[profile]["value"]),
                "max_reads": None,
                "metadata_json_bytes": None,
            }
            for profile in profiles
        ]
        components.extend(
            [
                {
                    "kind": "additional control/page/request/terminal reads; bounded readers still require aggregate owner budgets",
                    "read_cap_bytes": None,
                    "max_reads": None,
                    "metadata_json_bytes": None,
                },
                {
                    "kind": "error/completion/rejected-normalization records",
                    "read_cap_bytes": None,
                    "max_reads": None,
                    "metadata_json_bytes": None,
                },
            ]
        )
        source = source_envelope(
            entry["name"],
            components,
            budget=None if capture_budgets is None else capture_budgets[entry["name"]],
            owner_records=owner_records,
        )
        source.update(entry)
        source["unbounded_reasons"] = (
            [
                "Missing producer-derived aggregate payload/read-count/metadata bounds; measurements validate bounds, not originate them."
            ]
            if capture_budgets is None
            else []
        )
        source["empty_index_frame_bytes_not_a_bound"] = len(
            wire_index_record(
                source=entry["name"],
                operation_sha256="f" * 64,
                start_ns=0,
                end_ns=0,
                sequence=0,
                offset=0,
                length=0,
                sha256="f" * 64,
                metadata={},
            )
        )
        sources.append(source)
    return {
        "schema": "inf037b-capture-envelope-v1",
        "producer_limit_audit": producer_limit_audit(),
        "sourced_scope_envelopes": sourced_scope_envelopes(),
        "partition_proposal": partition_proposal(),
        "allowance_holder": allowance_holder(),
        "status": "unbounded_and_incomplete"
        if capture_budgets is None
        else "budgeted_known_owner_incomplete",
        "inventory": inventory,
        "resource_sources": [
            entry
            for entry in source_inventory(
                resource_roles=(
                    "measurement",
                    "generator",
                    "gateway0",
                    "gateway1",
                    "node0",
                    "node1",
                )
            )["sources"]
            if entry["name"].startswith("resource:")
        ],
        "capture_owner_table": owner_table,
        "read_caps": caps,
        "sources": sources,
        "unbound_source_envelopes": [
            {
                **family,
                "status": "unbounded",
                "raw_bytes_upper": None,
                "index_bytes_upper": None,
                "reason": "UID generations, count caps and metadata/counter bounds are not bound.",
            }
            for family in inventory["unbound_uid_families"]
        ],
        "schedule": {
            "session_ms_upper": SESSION_ENVELOPE_MS,
            "attempts": MAX_ATTEMPTS,
            "attempt_ms": ATTEMPT_MS,
            "resets": MAX_RESETS,
            "reset_ms": RESET_MS,
            "v4_lines": [10, 36, 39, 48, 57, 58, 62],
        },
        "totals": {
            "count_scope": inventory["count_scope"],
            "raw_bytes_upper": None,
            "index_bytes_upper": None,
            "known_wire_file_count": inventory["known_wire_file_count"],
            "wire_file_count": owner_table["whole_run_wire_file_count"],
            "whole_run_known_wire_file_count": owner_table["known_wire_file_count"],
            "whole_run_wire_file_count_expression": owner_table["wire_file_count_expression"],
        },
        "known_owner_spool_objects": [
            {
                "source": name,
                "path": path,
                "bytes_upper": None if capture_budgets is None else capture_budgets[name][key],
            }
            for name, files in wire_files(names).items()
            for kind, path in files.items()
            for key in ["raw_bytes" if kind == "data" else "index_bytes"]
        ],
        "known_owner_budget_totals": None
        if capture_budgets is None
        else {
            key: sum(b[key] for b in capture_budgets.values())
            for key in ("raw_bytes", "index_bytes", "records")
        },
        "gate_a_comparison_data_only": {
            "session4": GATE_A,
            "known_object_count_difference": inventory["known_wire_file_count"] - GATE_A["objects"],
            "raw_bytes_difference": None,
            "index_bytes_difference": None,
            "fit_verdict": None,
        },
        "remeasurement_inputs": {
            "at_4e_only": True,
            "minimum_spool_raw_bytes": 1_615_101_807,
            "raw_bytes_required": None,
            "index_bytes_required": None,
            "object_count_required": owner_table["whole_run_wire_file_count"],
            "object_count_expression": owner_table["wire_file_count_expression"],
            "missing": "Finish only the owner-table rows with unresolved live source sets. At 4e measure full cadence plus margin, pin slot-keyed per-source budgets and sum all separately rooted objects. UID generations do not multiply files; no packet or rerun here.",
        },
        "code_refs": [
            code_ref("inf037b_eks_commands.py", "capture_instance_schedule"),
            code_ref("inf037b_capture.py", "CaptureOwner.retain"),
            code_ref("inf037b_capture.py", "CaptureOwner.rows"),
            code_ref("inf037b_capture.py", "CaptureOwner.periodic"),
            code_ref("inf037b_capture_inventory.py", "wire_index_record"),
            code_ref("inf037b_probe.py", "NativeRequestAdapter._poll"),
            code_ref("inf037b_row5_diagnostic.py", "DiagnosticProcess._run"),
        ],
    }
