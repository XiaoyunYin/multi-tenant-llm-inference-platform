# Local observability stack

This opt-in stack runs immutable Prometheus 3.13.0 LTS, Grafana 13.2.2, and OpenTelemetry Collector Contrib 0.160.0 images. All published ports bind to loopback. It does not start automatically with the local Redis fixture.

Start the CPU services after the gateway and backends are listening on the documented local ports:

```powershell
docker compose -f deploy/observability/compose.yaml up -d prometheus grafana otel-collector
$env:OTEL_TRACES_EXPORTER='otlp'
$env:OTEL_EXPORTER_OTLP_TRACES_ENDPOINT='http://127.0.0.1:4318/v1/traces'
go run ./cmd/gateway
```

Prometheus is at `http://127.0.0.1:9090` and the provisioned read-only Grafana dashboard is at `http://127.0.0.1:3000`. The collector's debug exporter writes received span summaries to its container log; it is a transport/shape check, not durable trace storage.

On a Linux NVIDIA host with the Container Toolkit installed, add the explicit GPU profile:

```powershell
docker compose -f deploy/observability/compose.yaml --profile gpu up -d
```

DCGM Exporter requires access to all GPUs plus `SYS_ADMIN`; do not enable that profile on a shared host without reviewing the privilege boundary. Prometheus scrapes `dcgm-exporter:9400` and the dashboard displays GPU utilization and framebuffer use. The M3 paid pilot must verify the pinned exporter on the selected L4 host before treating these signals as evidence.

Stop and remove the ephemeral stack with:

```powershell
docker compose -f deploy/observability/compose.yaml down --volumes
```
