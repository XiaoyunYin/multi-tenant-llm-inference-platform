# Streaming under load on two L4s

One fixed-size EKS deployment in us-east-1d ran Qwen2.5-7B-Instruct
(revision `a09a35458c702b33eeacc393d103063234e8bc28`) with stock vLLM
0.29.0. Two Go gateways shared Redis admission and used round robin.
Each L4 served one engine with a 16-sequence cap. The workload used
1,024-token prompts, 32/64/128 output caps, two equal-share tenants
and 10% scheduled cancellations. Smoke and warm-up preceded four
sequential 600 s offer windows, with observed drain included in rates.

| Scheduled req/s | Offers | Completions | Sent cancels | HTTP 429 | Other failures | SLO completions / ordinary scheduled |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.25 | 150 | 135 | 15 | 0 | 0 | 135/135 |
| 1 | 600 | 540 | 60 | 0 | 0 | 540/540 |
| 3 | 1,800 | 1,620 | 180 | 0 | 0 | 1,620/1,620 |
| 8 | 4,800 | 2,507 | 271 | 1,979 | 43 | 863/4,320 |

SLO completion requires first content within 1 s and validated DONE
within 15 s of dispatch. At 8 req/s the 429s were 41.23% of offers
with 5.901 ms median dispatch-to-terminal latency. Both engines
reached 16 running sequences. The rejection class is derived from
the admission configuration; the frozen request rows record HTTP
status and outcome.

All 526 sent cancels joined vLLM frontend abort submission. Of
735 assigned cancels, 209 were unsent and 30 of the sent cancels
had unresolved timing bounds. The evidence measures frontend abort
submission. Per-request scheduler removal and KV release are unmeasured.

These are single-run observations at the tested rates. See the
[capacity and cost analysis](../capacity-cost/README.md) and the separate
[deployment and replacement session](deployment.md).

## Frozen inputs

- [Request rows](requests.jsonl.gz) and [cancel rows](cancels.jsonl.gz).
- [Engine samples](gauges.jsonl.gz), [level summaries](levels.json) and [clock brackets](clocks.json).
- [Uncompressed row hashes](row-bindings.json) and [public artifact checksums](SHA256SUMS).

The compressed streams retain the exact sanitized frozen row bytes
after decompression. The source commit for the serving session was
`1ef519bba6bc48de3d1593e4fec19b9d3d62448d`.
