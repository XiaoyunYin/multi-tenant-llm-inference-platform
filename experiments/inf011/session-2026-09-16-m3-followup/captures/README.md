# Follow-up capture set

These are sanitized exports from the bounded DEC-015 calibration session. `calibration-run.json` retains each recorder outcome and every sampled Prometheus body with its `raw_sha256`; `gateway-terminal-log.jsonl` retains the gateway terminal records used for one-to-one correlation. `dcgm-metrics.txt` and `host-evidence.txt` redact host- and device-specific identifiers while preserving the observed model, driver, utilization, memory, timer, and service facts. `SHA256SUMS.txt` is the checksum index for the seven data captures.

One malformed pre-run smoke request was rejected before calibration but its terminal record was not retained; it is excluded from the 27-request summary. The local gateway used `memory-test` admission because Redis was not running locally, so this capture set does not claim multi-gateway Redis behavior.
