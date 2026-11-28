# Replica autoscaling on two fixed L4 nodes

One Qwen2.5-7B-Instruct BF16 and vLLM 0.29.0 session replayed the
same offer tape for three cycles per arm on two fixed L4 nodes.
Each cycle scheduled 60 offers at 1 req/s, then 2,700 offers at
3 req/s over 15 minutes. KEDA scaled from one to two warm-cache
replicas using the engine-waiting metric.

| Arm | SLO completions / scheduled offers | SLO attainment |
| --- | ---: | ---: |
| Fixed-1 | 221 / 8,280 | 2.67% |
| KEDA 1→2 | 6,530 / 8,280 | 78.86% |
| Fixed-2 | 8,280 / 8,280 | 100% |

The denominator includes the 1-minute baseline in each cycle.
The SLO required first content within 1 s and validated completion
within 15 s. The second replica first completed a request
194–210 s after burst onset across the three KEDA cycles.
The two GPU nodes stayed fixed throughout the session. The
comparison measures replica elasticity on this pair of nodes.
Cost and node autoscaling are outside this result.
