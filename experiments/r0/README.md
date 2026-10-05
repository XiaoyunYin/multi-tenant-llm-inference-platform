# R0 public evidence

Reviewed evidence. Verified in private independent review (Rounds 72–74) and checked by a fresh-context agent claim audit. INF-047 remains incomplete: the release plan's Stage C items (instrumentation contract, re-warm curve, further event-lag capture) are not yet measured.

## GPU conditions and provenance

Attempt 7: one g6.xlarge / NVIDIA L4, On-Demand us-east-1b; Qwen/Qwen2.5-7B-Instruct revision `a09a35458c702b33eeacc393d103063234e8bc28`; vLLM 0.29.0 Linux amd64 image `sha256:082ca6f035279109041ffd3fe0695cb568b29bc580b35c4f297a66a08b216c1b`. [Chart data](chart-data.json) retains the original source commit, original private paths, compressed SHA-256 pins, JSON pointers and denominators. Paths in provenance are historical identifiers; local copies are [run 1](attempt7/run-1.digest.json.gz), [run 2](attempt7/run-2.digest.json.gz) and [run 4](attempt7/run-4.digest.json.gz), byte-identical to `f2fe3c68a571b450c386915cb350854ea230c777`. Caption settings are cited constants, not newly measured observations.

S: distinct first-block identity, 6,144-token prompt including template, max 128 output; 90-second closed-loop load at tested concurrency levels, minimum cycle 2 seconds, then up to 120 seconds drain. Runs 1/4 peak at 10 running from concurrency 12 and 31 waiting from 32; first tested pre-content rejection is at 48. At 48/64 both complete 61 against 781/1,501 dispatched. Matched-level completions differ by at most 2. Completion includes drain, not throughput; running/waiting peaks are separate maxima, not simultaneous occupancy. No confidence interval, safe concurrency or SLO is established. The client saw both backend failure classes as 502 before content; their distinction is whether vLLM's 503 arrived before or inside the upstream stream.

![Aggregate GPU chart](r0-saturation-reference.png)

Panels A-C equally space tested levels and shift run 1 left / run 4 right by 0.08 display units to expose coincident values. The recorded concurrency values are unchanged.

## Reference replay

C: distinct 1,024-token prefixes, max 1 output, fixed concurrency 4, 16-token native blocks. Runs 2/4 give identical replay counters: last nonzero-hit candidate 60 prefixes / 3,840 prompt-span blocks, first zero-hit 68 / 4,352. Native capacity reports 3,891 blocks. The bracket is schedule-specific; hit/query tokens are not per-request hit proof, exact reusable capacity or a universal eviction threshold. Panel D plots only tested points, without an interpolated hit curve.

## CPU explanation

Separately pinned at `78a1ecdb1e224cbb654dee68cd9c84e99ae4554b`: [trace](cpu-chain/trace.json), [comparison](cpu-chain/comparison.json), [environment](cpu-chain/environment.json) and [dependency lock](cpu-chain/requirements.lock.txt). These files preserve their original bytes. Harness `b9ca85b` was executed under registration `208cd03`. Private independent review (Round 72) verified that the registration preceded harness implementation and dependency setup; the parentless snapshot does not itself establish that historical order. The official `0.29.0+cpu` build's core allocator/scheduler files hash-match the release tag. With a configured 3,891-block pool, the real null reservation leaves 3,890 allocatable blocks. Cold full-input 6,144-token requests admit 10; 6,272-token requests admit 9. Ten growing requests trigger allocation refusal/free/reset/requeue/successful retry; eight grow by 128 computed KV tokens without preemption. Private independent review (Round 72) independently reproduced all six case traces. This is attributed corroboration in the private review record, not public raw reviewer data.

Controls: model computation mocked, no GPU, full-input reservation, prefix caching/chunked prefill off, sequence cap 16, token budget 131,072, watermark zero, blocks of 16 tokens. This tests a project-specific plateau hypothesis. It supports KV shortage as a plausible mechanism, without proving each live preemption's cause, live timing, gateway admission, fairness, safe R/W/B for other lengths or R1 settings. CPU synthetic states and GPU aggregate measurements are not pooled.

Reproduce the CPU chain in a fresh Linux environment with uv and Docker. The [harness](../../scripts/inf048_kv_chain.py), [source pins](../../scripts/inf048_kv_source_pins.py) and [verifier](../../scripts/verify_inf048_trace.py) ship in the snapshot. Use Python 3.12, the digest-pinned `python@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f`, libnuma1 2.0.19-1, libgomp1 14.2.0-19 and uv 0.9.5. Install with `uv pip install --python <fresh-python> --torch-backend cpu --require-hashes -r experiments/r0/cpu-chain/requirements.lock.txt`, then disconnect the container's network. Run `HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 PYTHONDONTWRITEBYTECODE=1 <fresh-python> -B scripts/inf048_kv_chain.py --output /tmp/trace.json`, copy the trace out, then `python scripts/verify_inf048_trace.py <trace> --output <comparison>`. Compare case traces and prediction results, not host/path-dependent metadata. Inspect the failure/free/requeue transition directly. No new CPU experiment is run for this layout change.

## Chart reproduction

The [renderer](../../scripts/render_r0_packet.py) and [lock](../../scripts/render_r0_packet.py.lock) ship in the snapshot. Run directly from the snapshot root, choosing a new output directory:

```powershell
uv run --locked --script scripts/render_r0_packet.py --output-dir <dir>
```

The parentless snapshot has no historical evidence commit. The renderer reads the three local compressed digests and enforces the same SHA-256 pins before decompression. Compare every JSON section except `render` against `chart-data.json`; platform metadata/PNG bytes may vary. The committed private verification helper additionally rejects changed or missing digests and proves that a present historical commit never silently falls back. No private-target file copy or Git history is needed for chart reproduction.

## Limits

- TTFT exists only as vLLM histogram buckets;
- lag under load includes queueing and prefill;
- "every replayed prefix hit" is an inference from counters;
- Section 2.5 per-sample validation and warm-up convergence are unassessed.

Per-request detail lost at teardown remains lost. [SHA256SUMS](SHA256SUMS) covers this bounded evidence layout. This page adds no measurement.
