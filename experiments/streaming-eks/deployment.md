# EKS deployment and pod replacement

A separate descriptive run on two fixed L4 nodes in us-east-1c used
Qwen2.5-7B-Instruct and vLLM 0.29.0, two gateways and shared Redis.
An in-cluster TLS client ran a one-output-token workload. One gateway
rolling restart and one in-place vLLM pod replacement took place
under load.

The gateway restart window completed all 5,890 scheduled requests.
The engine replacement window completed 7,892 of 7,894, with two
admission-unknown outcomes. The old engine endpoint was excluded
0.530 s after deletion. Its replacement reached Ready after 180.408 s.
These are one-session deployment observations for a short-output
workload.

[Frozen rollout readback](rollouts.json)
