# Verified kind stream coverage

This follow-up checks live-stream coverage in the local deployment.



The entrypoint exited **0** in **234.328 s**, including local builds, cluster
creation, both events, evidence export and deletion. Images were built locally
and loaded into kind; no registry push, AWS call, PlanPaid or Apply occurred.
Pins and exact normalized source/image hashes are in environment.json and
source-hashes.json. The eight workers start 0.4 s apart and must all be live
before mutation. Each validated stream has 24 chunks delayed 1250 ms (~30 s),
well inside the unchanged 120 s bound. The three-second preStop remains intact.

| Event / terminated pod | Live at deletion observation | Live at SIGTERM | Time to terminal after SIGTERM | Native drain acknowledgment after SIGTERM |
|---|---:|---:|---:|---:|
| Gateway `gateway-5c7d46db96-2t88j` | 5 | 5 | 13.468–15.877 s | 15.877 s |
| Gateway `gateway-5c7d46db96-zw795` | 3 | 3 | 19.052–20.256 s | 20.256 s |
| Backend `fake-1` | 4 | 4 | 21.900–23.910 s | 23.920 s |

The backend's own active counter at SIGTERM was also **4**, agreeing with the
gateway-observed intervals. Stage records preserve each covered request ID and
its individual post-signal duration, deletion observation bracket, SIGTERM,
endpoint/discovery removal, drain acknowledgment, replacement ready and first
replacement-route times. Deletion here is the first observed deleting snapshot;
it has a 0.455–0.744 s observation bracket, not an invented exact initiation time.
Backend per-request intervals end at the gateway terminal record; the native
counter and separate backend drain acknowledgment distinguish its own lifecycle.

Gateway event: **16 completed / 0 failed / 0 partial**. Backend event:
**24 / 0 / 0**. Both had **0 false completions** and zero global/tenant active
reservation sets and active reservation keys afterwards. Each terminated pod
passes the mandatory nonzero-SIGTERM coverage check. A zero count fails even if
all streams complete and reservations reach zero; failed summaries/raw rows are
preserved before that check raises. The untargeted fake-0 generation is unchanged.

The recount inspected every row, all per-pod intervals, histograms and the five longest
streams per event, and independently recounted them with the committed
`scripts/inspect_kind_rollout.py` into analysis.json. Gateway durations range
**30.009–30.024 s**, empirical median **30.010 s**; backend durations range
**30.007–30.028 s**, empirical median **30.009 s**. Every duration falls in
[30,31) s. The longest gateway/backend rows had first-frame times **19.209 ms /
22.441 ms**; these initial delays explain most of their small excess over the
configured stream length, rather than a long post-content stall. The first frame
can be the role frame; it is not a GPU TTFT metric. The cause of the remaining
few milliseconds is not isolated on this shared Windows/Docker host. Populations
16 and 24 are too small for PLAN's percentile claims; report empirical medians
and ranges only.

The event counts are two and three request waves of eight workers, respectively,
not one stream per victim pod. Gateway assignment was 5/3 at SIGTERM; the backend
had four, rather than a required fixed fraction. Default per-gateway round-robin
and frontend placement do not guarantee exact per-pod balancing. Replacement
fake-1's first route was **24.988 s after its first observed ready snapshot**.
Both gateways had discovered its new generation about 0.10–0.14 s before that
snapshot; all second-wave requests were already running on fake-0. Third-wave
requests supplied its first traffic. The gap is closed-loop worker occupancy,
not evidence of a discovery delay or a retry to another backend. Exact stage
timestamps and assignments remain in the raw evidence for inspection.

Teardown reports cluster absent and **0 remaining cluster containers**. The
earlier same-code run, `kind-2026-10-02-r090`, is retained separately: its raw
measurements/cleanup completed but outer PowerShell stderr redirection returned
1. It is not substituted for this clean entrypoint result.

Reproduce from the repository root without PowerShell native-stderr redirection:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/m5-stage1.ps1 -OutputDirectory experiments/inf037a/<new-run-id>
uv run --project python --locked python scripts/inspect_kind_rollout.py --run experiments/inf037a/<new-run-id>
```

If capturing to a file, use subprocess stdout/stderr pipes; Windows PowerShell
5.1 can turn expected native stderr into a NativeCommandError in the outer
redirection. analysis.json and this note are included in SHA256SUMS.txt. Public
The measurement supports the local CPU run conditions.

## Review annotation - 2026-10-03

The final coverage repair was independently verified. Measured captures and timings are preserved.
