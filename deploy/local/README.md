# Local deployment

The pinned Redis service used by shared admission is loopback-only and intentionally ephemeral:

```powershell
docker compose -f deploy/local/compose.yaml up -d redis
docker compose -f deploy/local/compose.yaml ps
```

It disables persistence because local integration state must not survive a clean test teardown. The gateway fails startup when the default Redis coordinator cannot be reached. Stop and remove it with `docker compose -f deploy/local/compose.yaml down`; do not use the local no-auth configuration on a shared host.

INF-005 provides a CPU-only fake streaming backend without Docker:

```powershell
uv run --project python --locked python -m inference_platform.fake_backend --config deploy/local/fake-backend-a.json --host 127.0.0.1 --port 8001
```

Run a copied configuration with `backend_id: fake-backend-b` on port `8002` for the second `.env.example` backend. The gateway's `BACKENDS=id=url,...` IDs must match the fake backends' health identities. Use `--host 0.0.0.0` only when the process must be reachable from another local container. Omitting `--host` and `--port` retains the test-safe `127.0.0.1` and ephemeral-port defaults. `--ready-file` publishes selected identity/URL atomically for harnesses.

The gateway loads `deploy/local/tenants.json` by default. That file stores only the SHA-256 digest of the non-secret local credential `local-dev-token`, permits `test-model`, and applies local request/output/rate/concurrency caps. Send `Authorization: Bearer local-dev-token` on inference requests. Never reuse this credential outside development; production credentials must be high entropy and their plaintext values must come from secret management. Tenant configuration is strict and startup fails closed for unknown fields, duplicate IDs or credentials, malformed digests, empty model allowlists, invalid limits, or files larger than 1 MiB.

Before starting the gateway locally, create its ignored cache-salt secret from the predictable test-only example:

```powershell
Copy-Item deploy/local/cache-salt.secret.example deploy/local/cache-salt.secret
```

`CACHE_SALT_SECRET_FILE` must contain exactly one canonical, unpadded base64url encoding of 32 bytes, with an optional final newline. Production deployments must generate this value with a cryptographic random-number generator, distribute the same value to every gateway replica through secret management, and never log or commit it. The example exists only for deterministic local tests.

`GET /health` exposes stable identity. `POST /v1/chat/completions` accepts length-delimited or bounded chunked JSON bodies and emits role, content, finish, optional usage, and `[DONE]` SSE events. The gateway requests upstream usage with `stream_options.include_usage`; the backend usage object deliberately omits the gateway-owned `count_source`. Set `emit_usage: false` to exercise missing-usage handling.

`GET /metrics` exposes deterministic vLLM-shaped `vllm:num_requests_running`, `vllm:num_requests_waiting`, and `vllm:kv_cache_usage_perc` gauges. Running reflects active fake requests; waiting and KV occupancy remain zero because the CPU fixture does not model a scheduler or cache. These gauges validate collector mechanics and freshness only, not real GPU behavior.

The default `stream_framing: vllm` shape emits an initial `role` plus empty `content` delta and may attach `finish_reason` to the final content chunk. `stream_framing: separate_finish` retains the earlier explicit finish-event shape. The strict JSON configuration also supports first-item/inter-chunk delays and `http_error`, `invalid_content_type`, `close_before_first_item`, `malformed_first_item`, `invalid_first_item`, `malformed_after_chunks`, `close_after_chunks`, and `stall_after_chunks` failure modes. Duplicate request IDs return `409` rather than merging observations. Backend shutdown and client cancellation have distinct terminals. These responses are deterministic test fixtures, not performance evidence; the exact pinned vLLM bytes are still rechecked in INF-011.
