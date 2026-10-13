"""Reproduce the source-domain conflict before any observational producer ships.

Exact Apache-2.0 upstream bodies are in the pinned fixture. CPU storage and the
non-stopping decode case are supplied by this harness; no model, GPU, actual
corpus, actual salt or serving-image result is implied.
"""

import ast
import copy
import hashlib
import json
import pickle
import subprocess
import sys
import types
import unittest
from dataclasses import dataclass
from pathlib import Path

import msgspec

PIN = "98dff2a81d747d1dba01a47f939f48c3526d4206"
ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name("fixtures") / "observer_decode_source.json"


def source_fixture():
    return json.loads(FIXTURE.read_bytes())


def cpu_module():
    module = types.ModuleType("observer_pinned_decode_fixture")
    sys.modules[module.__name__] = module
    ns = module.__dict__
    ns.update(
        hashlib=hashlib,
        pickle=pickle,
        dataclass=dataclass,
        msgspec=msgspec,
        BlockHash=bytes,
        BlockHashWithGroupId=bytes,
        ExternalBlockHash=bytes | int,
        MEDIUM_GPU="GPU",
        envs=types.SimpleNamespace(VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=True),
        check_stop=lambda request, maximum: False,
    )
    snippets = {
        name: snippet["text"]
        for source in source_fixture()["files"].values()
        for name, snippet in source["snippets"].items()
    }

    def execute(source):
        exec("from __future__ import annotations\n" + source, ns)

    for name in (
        "sha256",
        "_gen_mm_extra_hash_keys",
        "_gen_lora_extra_hash_keys",
        "_gen_prompt_embeds_extra_hash_keys",
        "generate_block_hash_extra_keys",
        "hash_block_tokens",
        "get_request_block_hasher",
        "make_block_hash_with_group_id",
        "maybe_convert_block_hash",
        "resolve_block_hashes",
        "KVCacheBlock",
        "BlockHashToBlockMap",
        "KVCacheEvent",
        "BlockStored",
    ):
        execute(snippets[name])
    ns["NONE_HASH"] = ns["sha256"]("vllm-none-hash")
    for cls, base, methods in (
        ("Request", "", ("append_output_token_ids", "update_block_hashes", "num_tokens")),
        ("BlockPool", "", ("cache_full_blocks", "_build_block_stored_event", "_insert_block_hash")),
        ("SingleTypeKVCacheManager", "", ("cache_blocks", "reachable_block_mask")),
        ("FullAttentionManager", "(SingleTypeKVCacheManager)", ("cache_blocks",)),
        ("Scheduler", "", ("_update_request_with_output",)),
        ("AsyncScheduler", "(Scheduler)", ("_update_request_with_output",)),
    ):
        execute(f"class {cls}{base}:\n" + "\n".join(snippets[cls + "." + m] for m in methods))
    return module


def request_and_scheduler(module, *, prompt_tokens=6144):
    request = module.Request()
    request.request_id = "synthetic-source-stop-request"
    request._all_token_ids = [100 + i % 127 for i in range(prompt_tokens)]
    request.all_token_ids = request._all_token_ids
    request._output_token_ids = []
    request.num_prompt_tokens = prompt_tokens
    request.shared_prefix_boundary = 0
    request.mm_features = []
    request.lora_request = request.prompt_embeds = None
    request.cache_salt = "synthetic-cpu-salt-not-session-material"
    request.block_hashes = []
    request._block_hasher = module.get_request_block_hasher(16, module.sha256)
    request.update_block_hashes()
    module.RequestStatus = types.SimpleNamespace(RUNNING=1)
    request.status = module.RequestStatus.RUNNING

    pool = module.BlockPool()
    pool.hash_block_size = 16
    pool.enable_kv_cache_events = True
    pool.cached_block_hash_to_block = module.BlockHashToBlockMap()
    pool.cached_block_hashes_by_block = {}
    pool.kv_event_queue = []

    manager = module.FullAttentionManager()
    manager.block_pool = pool
    manager.block_size = 16
    manager.kv_cache_group_id = 0
    manager.num_cached_block = {}
    manager.cache_hit_alignment_tokens = None
    manager.kv_cache_spec = object()  # Dense base mask ignores this object.
    manager.use_eagle = False
    manager.req_to_blocks = {request.request_id: [module.KVCacheBlock(i) for i in range(512)]}
    manager.cache_blocks(request, prompt_tokens)
    pool.kv_event_queue.clear()

    scheduler = module.AsyncScheduler()
    scheduler.max_model_len = 8192
    scheduler.kv_cache_manager = manager
    return request, scheduler, pool


def decode(request, scheduler, tokens):
    for token in tokens:
        request.num_computed_tokens = request.num_prompt_tokens + len(request._output_token_ids)
        request.num_output_placeholders = 1
        scheduler._update_request_with_output(request, [token])


class DecodeDomainSourceStopTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = cpu_module()

    def test_fixture_pin_hashes_and_syntax(self):
        fixture = source_fixture()
        self.assertEqual(fixture["source_commit"], PIN)
        self.assertIn("Apache-2.0", fixture["license"])
        for source in fixture["files"].values():
            self.assertEqual(len(source["source_sha256"]), 64)
            for name, snippet in source["snippets"].items():
                self.assertEqual(
                    hashlib.sha256(snippet["text"].encode()).hexdigest(), snippet["sha256"]
                )
                text = "class Source:\n" + snippet["text"] if "." in name else snippet["text"]
                ast.parse(text)

    def test_exact_cached_pin_matches_every_committed_fragment_when_available(self):
        checkout = ROOT / ".cache/inf047-vllm-v0.29.0"
        if not checkout.exists():
            self.skipTest(
                "No local pinned checkout; self-contained bodies still execute in other tests"
            )
        self.assertEqual(
            subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"])
            .decode()
            .strip(),
            PIN,
        )
        for path, source in source_fixture()["files"].items():
            data = subprocess.check_output(["git", "-C", str(checkout), "show", PIN + ":" + path])
            self.assertEqual(hashlib.sha256(data).hexdigest(), source["source_sha256"])
            lines = data.decode().splitlines(keepends=True)
            for snippet in source["snippets"].values():
                first, last = snippet["lines"]
                self.assertEqual("".join(lines[first - 1 : last]), snippet["text"])

    def test_full_generated_hash_boundary_is_not_disabled_by_equal_block_sizes(self):
        request, scheduler, pool = request_and_scheduler(self.module)
        frozen = tuple(request.block_hashes)
        self.assertEqual(len(frozen), 384)
        decode(request, scheduler, range(2000, 2015))
        self.assertEqual(tuple(request.block_hashes), frozen)
        decode(request, scheduler, [2015])
        self.assertEqual(len(request.block_hashes), 385)
        self.assertNotIn(request.block_hashes[-1], frozen)
        self.assertEqual(pool.kv_event_queue, [])  # Sixteenth output not computed yet.
        decode(request, scheduler, [2016])
        self.assertEqual(len(pool.kv_event_queue), 1)
        event = pool.kv_event_queue[0]
        self.assertIs(type(event), self.module.BlockStored)
        self.assertEqual(event.token_ids, list(range(2000, 2016)))
        self.assertEqual(
            event.block_hashes, [self.module.maybe_convert_block_hash(request.block_hashes[-1])]
        )
        self.assertEqual(scheduler.kv_cache_manager.num_cached_block[request.request_id], 385)

    def test_two_future_suffixes_same_prefrozen_prompt_produce_different_native_keys(self):
        left, ls, lp = request_and_scheduler(self.module)
        right, rs, rp = request_and_scheduler(self.module)
        self.assertEqual(left.block_hashes, right.block_hashes)
        frozen = set(left.block_hashes)
        decode(left, ls, [2000] * 17)
        decode(right, rs, [3000] * 17)
        self.assertNotEqual(left.block_hashes[-1], right.block_hashes[-1])
        self.assertNotIn(left.block_hashes[-1], frozen)
        self.assertNotIn(right.block_hashes[-1], frozen)
        self.assertNotEqual(lp.kv_event_queue[-1].block_hashes, rp.kv_event_queue[-1].block_hashes)

    def test_registered_128_output_limit_allows_seven_cached_generated_blocks(self):
        request, scheduler, pool = request_and_scheduler(self.module)
        prompt_keys = {self.module.maybe_convert_block_hash(v) for v in request.block_hashes}
        decode(request, scheduler, [2000 + i for i in range(128)])
        emitted = [key for event in pool.kv_event_queue for key in event.block_hashes]
        self.assertEqual(len(emitted), 7)
        self.assertTrue(prompt_keys.isdisjoint(emitted))
        self.assertEqual(len(request.block_hashes), 392)
        self.assertEqual(scheduler.kv_cache_manager.num_cached_block[request.request_id], 391)

    def test_single_output_reference_does_not_create_a_full_generated_block(self):
        request, scheduler, pool = request_and_scheduler(self.module, prompt_tokens=1024)
        frozen = copy.copy(request.block_hashes)
        decode(request, scheduler, [2000])
        self.assertEqual(request.block_hashes, frozen)
        self.assertEqual(pool.kv_event_queue, [])


if __name__ == "__main__":
    unittest.main()
