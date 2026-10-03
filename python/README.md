# Python tooling

This package contains the deterministic workload generator, request/outcome record types, and CPU-only controllable streaming backends used by the experiment harness. Transport clients are added with the HTTP streaming tasks.

Validate the checked-in example without writing output:

```powershell
uv run --project python --locked python -m inference_platform.workload --config experiments/examples/workload-config.json --validate-only
```

Generate canonical JSON Lines by adding `--output <path>`. Timing fields in outcome records are integer nanosecond offsets from one load-generator process's monotonic run origin; they are never derived by subtracting timestamps from different machines.

Run the example fake backend with:

```powershell
uv run --project python --locked python -m inference_platform.stage_c_tokenizer --fetch --fetch-only
uv run --project python --locked python -m inference_platform.fake_backend --config deploy/local/fake-backend-a.json --host 127.0.0.1 --port 8001
```

The fake uses the pinned Qwen chat template and token IDs. Without verified local tokenizer files it returns 503; the prerequisite downloads only two public tokenizer files. Use `INF011_TOKENIZER_CACHE` to select their cache parent when launching from another directory.

Its behavior and failure modes are documented in `deploy/local/README.md`.
