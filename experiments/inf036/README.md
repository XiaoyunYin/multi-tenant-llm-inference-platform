# INF-036 local CPU gateway profiling

INF-036 is READY_FOR_REVIEW after full all/race validation on committed target `0226b3701b62ed63e9264eb4830490224b83986d`; acceptance remains Claude's decision. This measures the default round-robin/static shared gateway pipeline on local mock SSE, not vLLM inference, hash-affinity/tokenizer overhead, GPU/EKS capacity or an INF-022 SLO freeze. No AWS calls or operational PlanPaid/Apply.

The highest qualified tested sustainable rate is **1600 requests/s across two gateways**. The first tested error/latency-knee rate is **3200 requests/s**, giving a conservative tested bracket [1600,3200); no exact interpolated maximum or indefinite soak guarantee. Both primary and supplementary protocols agree on this bracket. Three qualified supplementary pairs at 1600 give added p50 **2.4582-2.9872ms**, added p99 **4.8533-5.5053ms** versus direct-to-fake. The upper bound is the maximum observed paired quantile difference, not a percentile of individual overhead or a population confidence bound. It is below the registered 10ms added-p99 screen at this point; no claim that overhead is immaterial for unmeasured policies/GPU loads.

## Conditions and run counts

Windows, 32 logical CPUs, Go 1.26.6, Python 3.12.7, uv 0.9.5; exact OS/versions, binary/source hashes and existing-container count are in each environment.json. Two separate native gateway processes, each GOMAXPROCS=2 (Go scheduling budget, not hard CPU affinity); one native fake process with two independently addressed backend endpoints and GOMAXPROCS=4; native generator GOMAXPROCS=4. Owned pinned Redis 8.2.9-alpine digest 30abb90e62f14b737010746def3ba99cc79fe19dcdb3d37b41f21fc62e7da19d, Docker Linux containers, --cpus=2, persistence disabled. All listeners are loopback. Unrelated host workloads were preserved; their complete CPU timeline was not measured.

Each mock stream has a 5ms first-content delay, fixed hello world output and validated usage 4 prompt/2 completion/6 total tokens; six vLLM-shaped SSE events and EOF. No real model or tokenizer. HTTP/1.1 keep-alive, two front ends alternated evenly. Normal auth/cache salt/admission/validation/metadata rewriting/logging stay enabled; quotas are 100000 req/s, tenant/global concurrency 1024, local gateway 512. Owned Redis is flushed only between quiescent cases to remove prior tombstones. Every case ends with zero global/tenant reservations and zero release-failure increments.

Primary: two full 45-case campaigns (42 rate cases plus three profile cases each), three alternating direct/gateway pairs per 100/200/400/800/1600/3200/6400 offered req/s, 2s excluded warmup, max(12s,2400/rate) measurement. Each campaign plans 921600 rate-measurement arrivals; warmups remain separately counted. Before source 6563897, measured candidate adfdf4f; fake/controller/source hashes and conditions match exactly. Candidate combines a Redis TTL-zero correctness fix and default reader pooling, so no separate latency attribution to either change. Gateway runtime has no subsequent change except a comment correction.

Supplement: source 07c1723, fixed 24 cases (400/800/1600/3200, three pairs each, 12s, no profiles), optional busy-wait dispatch using up to one generator core. It improves matched attribution at 1600 but changes the input condition; do not call a cross-protocol difference a code speedup. All earlier scheduling failures remain visible. In total 114 fully captured/audited cases plus a preserved rejected 42-case original campaign. Profiles: one run per concurrency 1/16/64 per source version, 20s each with both gateways' 15s CPU profiles and heap/alloc snapshots (12 CPU and 12 heap files). Profiles never enter unprofiled latency headlines.

Percentiles use nearest rank only for n*(1-p)>=20 in the stated completed population: p50 n>=40, p99 n>=2000. Failed/partial/undispatched counts stay separate. For example after primary 6400 block2 has only 1711 completions and p99 is null. Per-run quantiles are not averaged and labeled pooled p99.

## Primary outcome table

Counts below sum the three gateway measurement repeats only, excluding separately recorded warmup. C/F/P/ND means completed/failed/partial/not-dispatched. Every direct primary control completes its planned requests, but several have excessive dispatch lag and remain inconclusive for overhead attribution.

| Offered req/s | Before C/F/P/ND | After C/F/P/ND | Interpretation |
|---|---|---|---|
| 100 | 7181/19/0/0 | 7200/0/0/0 | TTL defect before; no candidate errors |
| 200 | 7187/13/0/0 | 7200/0/0/0 | TTL defect before; no candidate errors |
| 400 | 14385/15/0/0 | 14400/0/0/0 | TTL defect before; no candidate errors |
| 800 | 28780/20/0/0 | 28800/0/0/0 | TTL defect before; no candidate errors |
| 1600 | 57546/54/0/0 | 57600/0/0/0 | TTL defect before; no candidate errors |
| 3200 | 77654/37546/0/0 | 91309/23891/0/0 | Knee/capacity rejects |
| 6400 | 25373/138749/0/66278 | 25565/138991/0/65844 | Transport/generator collapse; not gateway-only |

Before has 121 admission failures through 1600, after zero. The deterministic real-Redis PTTL response replay fails the original guard at zero below/at quota and passes the fix while negative states remain errors. Live after Redis errorstats have no invalid-state increments. At overload, admission timeouts remain possible; the expiry fix does not erase them. Primary 3200 has p99 513-562ms before and 464-503ms after, but this is a combined-change observation under noisy controls, not an isolated speedup claim.

## Qualified supplementary latency at 1600

| Paired block | Direct p50/p99 ms | Gateway p50/p99 ms | Added p50/p99 ms |
|---|---|---|---|
| 1 | 5.2533/6.1789 | 8.2405/11.0909 | 2.9872/4.9120 |
| 2 | 5.2519/6.0784 | 7.7101/11.5837 | 2.4582/5.5053 |
| 3 | 5.3920/6.1527 | 8.1924/11.0060 | 2.8004/4.8533 |

Each run has 19200 complete streams, zero errors/partials/undispatched. All six dispatch-lag p99 values are below 1ms. At 3200, direct p99 remains 6.62-6.84ms while gateway p99 is 130.401/55.3902/358.5747ms; all cross the registered knee. Only block3 has 89 local gateway_capacity rejections. Mean gateway CPU is about 1.83-1.96 cores each at that boundary, while fake/generator retain headroom under their four-thread budgets. This supports a local gateway/Windows I/O boundary; it does not establish a platform-independent Go capacity. Lower-rate controls still fail the lag rule. The primary has only one fully qualified pair within its sustainable cells (400 block1: +2.6156/+9.2655ms); do not extend that single-run bound to the whole range.

## CPU and memory inspection

Native CPU is CPU-seconds/wall-second (1=one core). RSS below is the sampled maximum in decimal MB for gateway0/gateway1; it is not just Go heap. Each profile condition has one run/version, no confidence interval or performance headline.

| Concurrency | Before cores 0/1 | After cores 0/1 | Before max RSS MB 0/1 | After max RSS MB 0/1 |
|---|---|---|---|---|
| 1 | 0.096/0.112 | 0.093/0.116 | 65.42/73.01 | 71.50/77.59 |
| 16 | 1.316/1.350 | 1.424/1.409 | 38.56/38.49 | 43.73/44.05 |
| 64 | 1.959/1.939 | 1.952/1.953 | 42.58/42.61 | 48.51/49.49 |

Concurrency64 gateway0 CPU profile contains 29.13 CPU seconds/15 wall seconds before, consistent with native CPU. Codex-reported cumulative WSASend is 56.30%, including downstream immediate SSE flushing and Redis/HTTP writes; nested cumulative percentages cannot be added. Allocation profile totals at the final snapshot: 23844141434 bytes before, 11696045278 after. Focused stream-reader allocations: 12595896212 versus 117461284 sampled bytes (about 99.1% lower). These are cumulative process-lifetime allocation traffic across different outcome populations under identical offered traces, not retained bytes or 15s allocation rates. See reader-allocation-focus.txt.

Pooling retains capacity: RSS at concurrency64 increases about 6-7MB; maximum private bytes are roughly 85-87MB in both versions. The concurrency1 RSS maximum exceeds higher-concurrency maxima because these ordered profiles follow the overload sweep. After gateway0 starts that run near 67.71MB and ends near 40.05MB; do not treat these samples as a fresh-process memory curve. Heap snapshots request GC around 18s while load is still live. memory-inspection.json preserves maximum/minimum timing and first/last RSS. Lower allocation traffic does not imply lower RSS. The pool resets upstream references; custom event bounds retain their original path. Large valid/oversized/retained payload/concurrent isolation pass under race.

## Outliers and accounting limits

Codex inspected every run's histogram and five longest completed rows, both first-content and post-content intervals, control scheduling lag, resources and failure codes. Full lists are in primary-analysis.json and matched-analysis.json. In supplementary 1600, only 6 of 57600 gateway completions exceed 20ms; the longest is 23.5501ms (20.9156ms to first content plus 2.6345ms afterwards), with 0.1878ms dispatch lag. It completed the full protocol. At 3200, long tails are spread before and after first content rather than just one first-token delay; block3's longest is 538.2175ms and local 512-request replica admission rejects 89 arrivals during the transient backlog.

Primary 6400 exhibits client transport/deadline collapse and filled 4096-slot generator capacity, hence tens of thousands of explicitly undispatched arrivals. Multisecond successes approach the 3s client deadline; warmup failures are separately retained. This is not evidence of falsely completed client streams or an attributable gateway-only capacity. Gateway successful-write completion is not an acknowledgement of client receipt. Excess server completion counts are retained as indeterminate (61 before full campaign; 58/11 after overload cases; 52 in the original rejected capture), never credited to client completion. Aggregate bounds cannot identify these individual requests. Client completion requires exact content, finish, usage, DONE and EOF; no error or partial is silently promoted.

The after concurrency16 profile has 16 synchronized ~100ms outliers around measurement 5.661-5.766s; the longest is 105.3798ms. All complete, and this is far below 1% of that profile population. It does not coincide with the later heap GC request. Native 250ms sampling cannot isolate a common host/fake/Redis/client scheduling or transport pause, so its cause remains unassigned; it is excluded from unprofiled headlines. Lower-rate scheduling outliers remain visible even with busy dispatch. No claim of an empty outlier distribution or perfect control at every rate.

The rejected original capture is preserved in before-2026-10-02, including failure/teardown and raw final-case rows. Its invalid server/client equality assertion halted profile collection; a full baseline reran with the observer guard corrected. The strict committed guard later caught CRLF in a manually derived aborted-case audit; only that derived note's line endings and its checksum were corrected, with raw captures unchanged.

## Reproduction and review

Default primary: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/inf036.ps1 -OutputDirectory experiments/inf036/<fresh-id>`; use the recorded source revisions for historical versions. Supplement: same entrypoint with `-MatchedDispatchCheck`. Each creates the owned Redis/processes, preflights all four APIs, measures/exports checksummed evidence and deletes owned resources. Existing output or busy ports is refused.

Recount the primary: `uv run --project python --locked python scripts/inf036_review.py --before experiments/inf036/baseline-2026-10-02 --after experiments/inf036/after-2026-10-02 --output <new-analysis.json>`. Supplement: `--capture experiments/inf036/matched-dispatch-2026-10-02 --output <new-analysis.json>`. Reproduction yields new timing data, not byte-identical results. Raw gzip outcomes, source/binary identities, resource samples, profiles, checksums and cleanup are committed; fixtures contain no real tenant content or credentials.

Full all/race PASS: 161 Python tests, zero skips and real pinned Redis; explicit race PASS. [Validation receipt](../../docs/evidence/inf036-validation-2026-10-02.json) and [committed handoff](../../REVIEW.md). R090 stays OPEN; CPU M5 stage1 remains DONE from Claude Round44 at 3d40dfa. Full M5, INF-020/021 EKS/GPU and INF-037b remain TODO. Future PlanPaid requires new payload pins because gateway/source inventory changed; no historical paid pin or approval marker was altered. Public claims remain behind Claude review and PLAN claim gates.
