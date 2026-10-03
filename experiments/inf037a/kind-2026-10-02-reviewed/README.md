# Final-source local kind INF-037a evidence

This is the authoritative 2026-10-02 CPU-only M5 stage 1 campaign, pending Claude review. Reproduce with `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/m5-stage1.ps1 -OutputDirectory experiments/inf037a/<new-run-id>`. Tools, images, source-file hashes and clock semantics are in `environment.json` and `source-hashes.json`. Every sanitized evidence file is covered by `SHA256SUMS.txt`; strict JSON/LF and committed Git blob checks are required.

| Event | Completed | Failed | Partial | False completions | Reservation sets / active keys after |
|---|---:|---:|---:|---:|---|
| Gateway Deployment rollout | 16 | 0 | 0 | 0 | 0 / 0 / 0 |
| One backend replacement | 24 | 0 | 0 | 0 | 0 / 0 / 0 |

Before each mutation, eight reservations and eight routed streams were active with delivered SSE content; both gateways participated (5/3) and both backends participated (5/3). Gateway event clients completed two waves of eight; the backend event ran three waves of eight. Every completion has all 24 expected content chunks (206 bytes), exactly one stop finish, usage count 24, a trailing DONE, successful EOF/transport and the corresponding gateway `completed` terminal. Counts were independently recounted from JSONL, not copied from a PASS banner. Reservations were read back without modification immediately after clients ended, well before the 180s lease could act as cleanup. Global set, tenant set and all active reservation keys each reached zero.

## Distributions and outliers inspected by Codex

Gateway durations: 12,011.336-12,060.844ms, empirical median 12,038.960ms (n=16). Backend durations: 12,012.823-12,038.073ms, empirical median 12,026.927ms (n=24). The complete individual durations and five longest requests are retained. The longest gateway row (12,060.844ms) completed through an original gateway to fake-0; the longest backend row (12,038.073ms) completed through a surviving gateway to fake-0. All outliers are complete and differ from the configured 12s chunk pacing by tens of milliseconds, with no timeout/cancellation/error population hidden. These observations are local mock scheduling/transport measurements, not inference performance. p95 is null because neither sample meets PLAN's n*(1-p)>=20 rule; empirical medians are descriptive sample summaries, not tail estimates.

First SSE-event delays were 5.079-51.403ms for the gateway event and 5.356-29.589ms for the backend event. These are initial role-frame delays, not GPU TTFT or time to first content. The harness waits two seconds after initial routing before mutation so the half-second content stream is already flowing. The measurement exercises ~12s streams; the configured 120s execution ceiling was not saturated.

The backend split was 9/7 in the gateway event and 17/7 in the backend event. The latter is explained exactly by wave counts: initial 5/3, eight requests to the surviving fake-0 while fake-1 was absent, then 4/4 after replacement. NodePort selected gateways 16/8 during the backend event; stochastic gateway distribution and independent router cursors need not produce equal small-sample counts. No serving backend capacity or GPU-placement claim follows from these counts.

## Event stages (seconds after the mutation trigger)

| Old pod | Endpoint unavailable observed | SIGTERM logged | Last stream terminal logged | Drain acknowledged |
|---|---:|---:|---:|---:|
| gateway-5c7d46db96-fx275 | 4.290061 | 7.182086 | 9.632149 | 9.632263 |
| gateway-5c7d46db96-q8wrg | 8.406628 | 11.149362 | 9.633653 | 11.149409 |
| fake-1 | 0.560802 | 3.191318 | 9.672667 | 9.684476 |

`analysis.json` retains exact nanoseconds for actual last terminal and drain acknowledgment separately. The second old gateway's drain acknowledgment was only 0.047798ms after SIGTERM because its last stream finished 1.515709s before SIGTERM, during the three-second preStop sleep. It was live at the rollout trigger; it had no stream left when SIGTERM arrived. The first old gateway had work for another 2.450s after SIGTERM; fake-1 drained for 6.493s after SIGTERM. No hard-stop cancellation or grace expiry occurred. Terminal timing is the gateway's fully finalized request observation (including release); fake drain acknowledgment polls active backend observations every 20ms. It is an acknowledgment that no stream remains, rather than evidence that a stream necessarily finished at that exact instant.

Gateway EndpointSlices became unavailable 2.892s/2.743s before SIGTERM. Backend removal was observed 2.631s before its SIGTERM; both surviving gateways logged removal of its old generation at trigger +0.279s/+0.264s. This ordering is expected: deletion triggers EndpointSlice readiness/termination changes while preStop runs. External EndpointSlice observation brackets are 0.478-0.561s wide; those brackets and the actual per-gateway discovery log timestamps are retained. No later route to the removed backend generation appears in either gateway's logs.

| Replacement | Ready first observed | First request routed |
|---|---:|---:|
| gateway-7dfbfff845-n26hr | 2.539935 | 9.737026 |
| gateway-7dfbfff845-9kqht | 6.729769 | 9.750177 |
| fake-1, new UID | 14.964752 | 21.908781 |

The 3.020-7.197s gateway ready-to-first-route delays and 6.944s backend delay come from the closed-loop workers: all eight clients wait for their existing ~12s streams before making the next request. They are not asserted as discovery latency or replacement warm-up time. Ready timings are controller samples, not an instantaneous application-ready transition; exact raw readiness observations are retained. Gateway summaries list both event-wide replacements under each old gateway, without claiming one-to-one controller ancestry.

Observed topology peaked at four total gateway pods including terminating drainers, three nondeleting gateways, and two backend pods. Deployment maxSurge=1 limits nonterminating replicas; terminating drainers can remain beyond that count. Desired steady state is two gateways. The backend StatefulSet partition replaced only fake-1 without surge; fake-0 kept one unchanged generation for the entire campaign. The backend event temporarily served through one backend. PDBs cover voluntary eviction, while rollout strategies bound controller updates.

## Evidence limits and review boundary

Pod/gateway lifecycle logs and controller observations use UTC wall time on one local Docker host; client durations use perf_counter_ns. Endpoint and ready samples retain observation uncertainty; this is not a cross-host clock-synchronization experiment. Unit/race tests additionally cover removal, unknown/unready/terminating endpoints, flapping, duplicated readiness conflicts, generation isolation, API errors/timeouts and recovery. Zero observed stream loss applies to these two finite mock events and does not guarantee arbitrary rollout timing, GPU behavior or 120s stream drain under every failure.

Credentials, cache salts, prompts, IPs, kubeconfig, raw API responses and reservation IDs are absent from the export. Public image/tool/source digests are preserved. `teardown.json` records cluster absent and zero remaining cluster containers. No AWS API call, operational PlanPaid/Apply, registry push or GPU resource was used. Stage C payloads must be re-pinned before a future PlanPaid because gateway source changed. Full EKS/GPU M5, INF-037b cache recovery and public claim gates remain pending.
