"""CPU-only execution of the committed INF-048 prediction; no serving or weights."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import inspect
import json
import platform
from pathlib import Path
from types import SimpleNamespace as NS

import torch

from vllm.config import (
    CacheConfig,
    ObservabilityConfig,
    ParallelConfig,
    SchedulerConfig,
)
from vllm.sampling_params import SamplingParams
from vllm.v1.core.sched.scheduler import Scheduler
from vllm.v1.core.single_type_kv_cache_manager import register_all_kvcache_specs
from vllm.v1.kv_cache_interface import (
    FullAttentionSpec,
    KVCacheConfig,
    KVCacheGroupSpec,
)
from vllm.v1.outputs import ModelRunnerOutput
from vllm.v1.request import Request
from vllm.v1.structured_output import StructuredOutputManager

REGISTRATION = "208cd03f619d9b63a34da30027c5a323b449a9f7"


def make_scheduler() -> Scheduler:
    # Only model metadata is synthetic: there is no model/tokenizer download.
    model = NS(
        skip_tokenizer_init=True,
        uses_mrope=False,
        uses_xdrope=False,
        is_encoder_decoder=False,
        is_diffusion=False,
        max_model_len=8192,
        enable_return_routed_experts=False,
        return_sampling_mask=False,
    )
    config = NS(
        model_config=model,
        scheduler_config=SchedulerConfig(
            max_num_seqs=16,
            max_num_batched_tokens=131072,
            max_num_scheduled_tokens=131072,
            max_model_len=8192,
            is_encoder_decoder=False,
            enable_chunked_prefill=False,
            scheduler_reserve_full_isl=True,
            async_scheduling=False,
            policy="fcfs",
            watermark=0.0,
        ),
        cache_config=CacheConfig(block_size=16, enable_prefix_caching=False),
        parallel_config=ParallelConfig(),
        observability_config=ObservabilityConfig(),
        structured_outputs_config=NS(enable_in_reasoning=False),
        lora_config=None,
        kv_events_config=None,
        kv_transfer_config=None,
        ec_transfer_config=None,
        speculative_config=None,
        ec_manager_config=NS(get_encoder_cache_manager_obj=lambda: None),
        num_speculative_tokens=0,
        num_lookahead_tokens=0,
        max_in_flight_tokens=8192,
        max_concurrent_batches=1,
        is_mm_encoder_only=False,
        use_v2_model_runner=False,
    )
    config.cache_config.num_gpu_blocks = 3891
    cache = KVCacheConfig(
        num_blocks=3891,
        kv_cache_tensors=[],
        kv_cache_groups=[
            KVCacheGroupSpec(
                ["layer"],
                FullAttentionSpec(
                    block_size=16, num_kv_heads=1, head_size=1, dtype=torch.float32
                ),
            )
        ],
    )
    register_all_kvcache_specs(config)
    return Scheduler(
        vllm_config=config,
        kv_cache_config=cache,
        structured_output_manager=StructuredOutputManager(config),
        block_size=16,
        mm_registry=NS(supports_multimodal_inputs=lambda _: False),
        log_stats=False,
    )


def request(index: int, length: int) -> Request:
    return Request(
        request_id=f"r{index:02}",
        prompt_token_ids=[index + 1] * length,
        sampling_params=SamplingParams(max_tokens=512, ignore_eos=True),
        pooling_params=None,
        arrival_time=float(index),
    )


def snapshot(scheduler: Scheduler) -> dict:
    manager = scheduler.kv_cache_manager
    pool = manager.block_pool
    resident = {
        rid: len(manager.get_blocks(rid).blocks[0]) for rid in scheduler.requests
    }
    free = pool.get_num_free_blocks()
    # No prefix sharing/caching: exactly one owner per non-null live block.
    ids = [
        block.block_id
        for rid in scheduler.requests
        for block in manager.get_blocks(rid).blocks[0]
    ]
    assert len(set(ids)) == len(ids)
    assert 0 not in ids and pool.null_block.is_null
    assert free + len(ids) + 1 == 3891
    assert sum(b.ref_cnt > 0 for b in pool.blocks if not b.is_null) == len(ids)
    return {
        "free": free,
        "resident": resident,
        "computed": {
            rid: r.num_computed_tokens for rid, r in scheduler.requests.items()
        },
        "generated": {
            rid: r.num_output_tokens for rid, r in scheduler.requests.items()
        },
        "running": [r.request_id for r in scheduler.running],
        "waiting": [r.request_id for r in scheduler.waiting],
    }


def instrument(scheduler: Scheduler, trace: list) -> None:
    manager = scheduler.kv_cache_manager
    allocate = manager.allocate_slots
    preempt = scheduler._preempt_request
    free = manager.free

    def allocation(req, num_new_tokens, *args, **kwargs):
        before = snapshot(scheduler)
        result = allocate(req, num_new_tokens, *args, **kwargs)
        trace.append(
            {
                "event": "allocation",
                "step": scheduler.current_step,
                "request": req.request_id,
                "new_tokens": num_new_tokens,
                "computed_before": req.num_computed_tokens,
                "success": result is not None,
                "free_before": before["free"],
                "free_after": snapshot(scheduler)["free"],
                "resident_after": len(manager.get_blocks(req.request_id).blocks[0]),
            }
        )
        return result

    def release(req, *args, **kwargs):
        before = snapshot(scheduler)
        result = free(req, *args, **kwargs)
        trace.append(
            {
                "event": "free",
                "step": scheduler.current_step,
                "request": req.request_id,
                "blocks_before": before["resident"][req.request_id],
                "free_before": before["free"],
                "free_after": snapshot(scheduler)["free"],
            }
        )
        return result

    def preemption(req, *args, **kwargs):
        before = snapshot(scheduler)
        trace.append(
            {
                "event": "preempt_begin",
                "step": scheduler.current_step,
                "request": req.request_id,
                "before": before,
            }
        )
        result = preempt(req, *args, **kwargs)
        trace.append(
            {
                "event": "preempt_end",
                "step": scheduler.current_step,
                "request": req.request_id,
                "status": req.status.name,
                "preemptions": req.num_preemptions,
                "after": snapshot(scheduler),
            }
        )
        return result

    manager.allocate_slots = allocation
    manager.free = release
    scheduler._preempt_request = preemption


def mock_output(scheduler: Scheduler, output) -> None:
    ids = list(output.num_scheduled_tokens)
    # Model computation alone is mocked; the actual scheduler consumes the result.
    scheduler.update_from_output(
        output,
        ModelRunnerOutput(
            req_ids=ids,
            req_id_to_index={rid: i for i, rid in enumerate(ids)},
            sampled_token_ids=[[100] for _ in ids],
        ),
    )


def allocator_case(length: int) -> dict:
    scheduler = make_scheduler()
    trace = []
    instrument(scheduler, trace)
    for index in range(16):
        req = request(index, length)
        scheduler.requests[req.request_id] = req
        result = scheduler.kv_cache_manager.allocate_slots(req, length)
        if result is None:
            break
    return {"length": length, "trace": trace, "final": snapshot(scheduler)}


def scheduler_case(length: int, count: int, growth: int) -> dict:
    scheduler = make_scheduler()
    trace = []
    instrument(scheduler, trace)
    for index in range(count):
        scheduler.add_request(request(index, length))
    output = scheduler.schedule()
    initial = snapshot(scheduler)
    trace.append(
        {
            "event": "step",
            "step": scheduler.current_step,
            "scheduled": output.num_scheduled_tokens,
            "state": initial,
        }
    )
    if growth:
        mock_output(scheduler, output)
        for _ in range(growth):
            output = scheduler.schedule()
            trace.append(
                {
                    "event": "step",
                    "step": scheduler.current_step,
                    "scheduled": output.num_scheduled_tokens,
                    "state": snapshot(scheduler),
                }
            )
            mock_output(scheduler, output)
            if any(event["event"] == "preempt_end" for event in trace):
                break
    return {
        "length": length,
        "submitted": count,
        "growth_limit": growth,
        "initial": initial,
        "trace": trace,
        "final": snapshot(scheduler),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert metadata.version("vllm") == "0.29.0+cpu"
    assert not torch.cuda.is_available() and torch.version.cuda is None
    cases = {
        "allocator_6144": allocator_case(6144),
        "allocator_6272": allocator_case(6272),
        "scheduler_6144": scheduler_case(6144, 16, 0),
        "scheduler_6272": scheduler_case(6272, 16, 0),
        "growth_ten": scheduler_case(6144, 10, 128),
        "growth_eight": scheduler_case(6144, 8, 128),
    }
    packages = []
    for dist in sorted(
        metadata.distributions(), key=lambda d: d.metadata["Name"].lower()
    ):
        packages.append(
            {
                "name": dist.metadata["Name"],
                "version": dist.version,
                "record_sha256": hashlib.sha256(
                    (dist.read_text("RECORD") or "").encode()
                ).hexdigest(),
            }
        )
    import vllm

    package = Path(vllm.__file__).parent
    sources = {}
    for name in [
        "core/block_pool.py",
        "core/kv_cache_manager.py",
        "core/kv_cache_coordinator.py",
        "core/single_type_kv_cache_manager.py",
        "core/kv_cache_utils.py",
        "core/sched/scheduler.py",
        "core/sched/request_queue.py",
        "request.py",
        "kv_cache_interface.py",
    ]:
        sources[f"vllm/v1/{name}"] = hashlib.sha256(
            (package / "v1" / name).read_bytes()
        ).hexdigest()
    result = {
        "registration_commit": REGISTRATION,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "torch": torch.__version__,
            "cuda_available": torch.cuda.is_available(),
            "torch_cuda": torch.version.cuda,
            "vllm": metadata.version("vllm"),
            "packages": packages,
            "executed_sources": sources,
            "scheduler_class_source": inspect.getfile(Scheduler),
        },
        "cases": cases,
    }
    args.output.write_text(json.dumps(result, separators=(",", ":")) + "\n")
    print(
        json.dumps(
            {
                name: {
                    "steps": len([e for e in case["trace"] if e["event"] == "step"]),
                    "initial_running": len(case.get("initial", {}).get("running", [])),
                    "allocation_failures": sum(
                        e["event"] == "allocation" and not e["success"]
                        for e in case["trace"]
                    ),
                    "preemptions": sum(
                        e["event"] == "preempt_end" for e in case["trace"]
                    ),
                }
                for name, case in cases.items()
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
