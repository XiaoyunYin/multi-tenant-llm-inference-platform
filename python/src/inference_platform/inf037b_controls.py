"""Frozen setup-only payload/policy. The registered trace tenant is separate."""

from .inf037b_live import REQUEST_TIMEOUT_SECONDS
from .inf037b_resolver import require

CONTROL_TOKENS = 64
# Two gateway workers run concurrently; each has three serial requests.
CONTROL_ALLOWANCE_SECONDS = 3 * REQUEST_TIMEOUT_SECONDS


def book_probe(*, branch_start_ns, ready_ns, branch_stop_ns, remaining_gpu_seconds):
    """Factory contract: book all controls, trace and drain inside the GPU branch.

    ready_ns follows native/client readiness. No late controls shift start_ns.
    Other GPU work and close/seal/descriptor costs belong in remaining_gpu_seconds.
    """
    require(
        all(type(v) is int for v in (branch_start_ns, ready_ns, branch_stop_ns))
        and branch_start_ns <= ready_ns < branch_stop_ns
        and branch_stop_ns - branch_start_ns <= 1_740_000_000_000
        and type(remaining_gpu_seconds) is int
        and remaining_gpu_seconds >= 0,
        "probe:gpu_branch_booking",
    )
    start_ns = ready_ns + CONTROL_ALLOWANCE_SECONDS * 1_000_000_000
    stop_ns = start_ns + (120 + REQUEST_TIMEOUT_SECONDS) * 1_000_000_000
    require(
        stop_ns + remaining_gpu_seconds * 1_000_000_000 <= branch_stop_ns,
        "probe:gpu_branch_booking",
    )
    return {
        "controls_ready_ns": ready_ns,
        "controls_allowance_seconds": CONTROL_ALLOWANCE_SECONDS,
        "start_ns": start_ns,
        "stop_ns": stop_ns,
    }


CONTROL_MODEL = "Qwen/Qwen2.5-7B-Instruct"
CONTROL_PAYLOADS = {
    rid: {
        "model": CONTROL_MODEL,
        "messages": [{"role": "user", "content": "Count upwards, one number at a time. " + rid}],
        "stream": True,
        "temperature": 0,
        "max_tokens": CONTROL_TOKENS,
    }
    for gateway in ("gateway0", "gateway1")
    for rid in (f"ingress-{gateway}-0", f"ingress-{gateway}-1", f"cancel-{gateway}")
}
CONTROL_PAYLOADS_SHA256 = "d2ee104137a4e9ad66a2479e7a0f420acfa134a97770a658154b00cad8f52c50"


def control_slot(request_id):
    return 1 if request_id.endswith("-1") else 0


def control_tenants(credential_sha256):
    """Merge these two separately credentialed policies into gateway-config.

    A pinned tenant forces ignore_eos upstream and filters by stable pod name.
    Never modify the registered trace tenant or reuse its credential.
    """
    return [
        {
            "tenant_id": f"setup-control-{slot}",
            "credential_sha256": credential_sha256[slot],
            "models": [CONTROL_MODEL],
            "max_request_bytes": 4096,
            "max_output_tokens": CONTROL_TOKENS,
            "request_rate_limit": 20,
            "request_rate_window_ms": 60000,
            "max_concurrent": 2,
            "setup_backend_id": f"vllm-{slot}",
        }
        for slot in (0, 1)
    ]
