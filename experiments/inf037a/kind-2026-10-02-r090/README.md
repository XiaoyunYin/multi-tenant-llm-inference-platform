# INF-037a R090 run with a capture invocation error

CPU scope: **Kubernetes (kind, local, mock vLLM backends)**. Same measurement
source hashes and 30 s/staggered-worker conditions as the clean follow-up
`kind-2026-10-02-r090-confirmed`. Preserve this attempt rather than overwrite it.

The complete raw gateway/backend events, environment, source hashes, logs and
teardown were exported. Independent recount passes: gateway **16 completed /
0 failed / 0 partial**, backend **24 / 0 / 0**, zero false completions and zero
reservations afterwards. Gateway SIGTERM live counts were **4 and 4** (post-signal
intervals 18.304–20.303 s / 13.918–16.717 s); backend **5**, also reported by its
native counter (21.842–24.644 s to gateway terminal). Native drain acknowledgments
were 20.303 / 16.717 / 24.660 s. All three victims had positive coverage.

All durations fall in [30,31) s: gateway **30.008–30.028 s**, backend
**30.008–30.030 s**. The longest first-frame times were 24.115 / 25.844 ms;
initial response delay explains most of those small excesses over the configured
stream length. No failure or partial stream was dropped. analysis.json recounts
the rows and all per-pod intervals, with no small-sample percentile claim.

The invocation `powershell ... > .cache/r090-kind-campaign.private.log 2>&1`
returned **1**: outer PowerShell 5.1 redirection emitted NativeCommandError on
Docker's normal build stderr. The measurement process nevertheless reached both
coverage checks and complete export/teardown. Do not call this invocation PASS.
The cluster is absent with **0 remaining containers**. The clean repeat used
subprocess capture, exited 0 and is the authoritative handoff campaign. Original
raw evidence is retained, not rewritten or pooled into a latency claim.
