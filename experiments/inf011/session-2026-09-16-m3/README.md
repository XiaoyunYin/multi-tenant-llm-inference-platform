# INF-011 measured M3 session — 2026-09-16

This directory records the sanitized evidence from the single approved `DEC-014` session. The reviewed plan was applied to one `g6.xlarge` in `us-west-2`, then the instance and all supporting resources were destroyed and independently verified empty.

## Evidence

- `manifest.json` contains the pinned environment, measured compatibility/cache/telemetry observations, fit boundary, and explicit claim limits.
- `runtime-evidence.json` contains timestamped request outcomes, metric snapshots, the bounded calibration result, final host snapshot, and teardown result.
- `captures/` contains sanitized exports of the retained SSM response, cache/fit/telemetry/timer/startup/calibration excerpts, the real vLLM 0.29.0 SSE stream, and the complete 57-command inventory. `captures/SHA256SUMS.txt` is the integrity record.

The session exercised the three planned M3 classes: compatibility/fit, cache reset and salt isolation, and a bounded calibration burst. The calibration launcher was invoked with eight concurrent `max_tokens=512` workers for 30.054 seconds; per-request outcomes were not recorded, and the SSM metric sampler arrived after completion. Therefore this record deliberately does not claim throughput, latency, a safe running-request target `R`, a positive waiting allowance `W`, or a preliminary global bound `B`. The cache capture records a runtime KV-cache ceiling of 62,256 tokens and `kv_cache_max_concurrency=7.5996`, which is not a measured safe `R`.

The successful launch followed eight capacity rejections at `2026-09-16T17:00:30Z`; the first response arrived at `17:34:05Z`, and the instance terminated at `18:19:37Z` (4,747 seconds of runtime). Claude's Round 10 estimate is approximately `$1.10`; actual AWS billing and cumulative phase spend remain pending. The estimate is not a billing claim.

Startup evidence is intentionally split: `captures/startup-vllm.txt` retains a warm post-reboot weight-loading line of `120.663043` seconds, while the cold launch-to-first-response interval was 2,015 seconds. Retained progress showed approximately 273-324 seconds per checkpoint shard, with 3 of 4 shards still loading at 15m21s; image pull, volume restore, and aggregate shard time were not separately isolated.

The calibration launcher ran eight concurrent workers for 30.054 seconds but discarded per-request status/body data; its sampler arrived after the burst and observed idle gauges. No throughput, latency, safe `R`, positive `W`, or `B` claim is made. The five failed SSM debug attempts are listed in `runtime-evidence.json` and the command inventory. Local parser failures and the first non-TTY Destroy prompt are retained in the BUILD_LOG narrative.

The capture export was retrieved with `aws ssm get-command-invocation`, normalized/redacted by hand, and committed with SHA-256 checksums. Credentials, account identifiers, public addresses, raw salts, and large prompt bodies are intentionally omitted. Future sessions should route SSM output to durable object storage before teardown.
