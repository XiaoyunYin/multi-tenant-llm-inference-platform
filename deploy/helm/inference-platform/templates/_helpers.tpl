{{- define "inference.ns" -}}
{{- $ns := .Values.namespace -}}
{{- if not (regexMatch "^mti-m5-[a-z0-9-]{1,40}$" $ns) -}}
  {{- fail "namespace must match the composed renderer contract" -}}
{{- end -}}
{{- $ns -}}
{{- end -}}

{{- define "inference.labels" -}}
m5-session: {{ include "inference.ns" . }}
{{- end -}}

{{- define "inference.metadata" -}}
{{- $root := index . 0 -}}
name: {{ index . 1 }}
namespace: {{ include "inference.ns" $root }}
labels: {{- include "inference.labels" $root | nindent 2 }}
{{- end -}}

{{- define "inference.digestImage" -}}
{{- if not (regexMatch "@sha256:[0-9a-f]{64}$" .) -}}
  {{- fail "images require digest pins" -}}
{{- end -}}
{{- . | quote -}}
{{- end -}}

{{- define "inference.replicaOwnership" -}}
{{- $auto := .Values.autoscaling.enabled -}}
{{- if and (not $auto) (not (has (int .Values.engineReplicas) (list 1 2))) -}}
  {{- fail "engineReplicas must be 1 or 2" -}}
{{- end -}}
{{- if .Release.IsUpgrade -}}
  {{- $live := lookup "apps/v1" "StatefulSet" (include "inference.ns" .) "vllm" -}}
  {{- if $live -}}
    {{- $prior := dig "metadata" "annotations" "inference-platform/autoscaling" "false" $live -}}
    {{- if ne $prior (toString $auto) -}}
      {{- fail "install a fresh release to change replica ownership" -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- end -}}

{{- define "inference.probe" -}}
{{- $probe := deepCopy (index . 0) -}}
{{- $_ := set (index $probe (index . 1)) "port" (int (index . 2)) -}}
{{- toYaml $probe -}}
{{- end -}}

{{- define "inference.gatewayEnv" -}}
{{- $env := tpl (toYaml .Values.gateway.env) . | fromYamlArray -}}
{{- if .Values.firstItemTimeout -}}
  {{- $env = append $env (dict "name" "GATEWAY_FIRST_ITEM_TIMEOUT" "value" .Values.firstItemTimeout) -}}
{{- end -}}
{{- if ne (int .Values.ports.gateway) 8080 -}}
  {{- $env = append $env (dict "name" "GATEWAY_HTTP_ADDR" "value" (printf ":%d" (int .Values.ports.gateway))) -}}
{{- end -}}
{{- toYaml $env -}}
{{- end -}}

{{- define "inference.prometheusArgs" -}}
{{- $args := .Values.telemetry.args -}}
{{- if ne (int .Values.ports.telemetry) 9090 -}}
  {{- $args = append $args (printf "--web.listen-address=:%d" (int .Values.ports.telemetry)) -}}
{{- end -}}
{{- if .Values.snapshotAdminAPI -}}
  {{- $args = without $args "--storage.tsdb.retention.time=4h" "--storage.tsdb.retention.size=512MB" -}}
  {{- $args = concat $args (list "--web.enable-admin-api" "--storage.tsdb.retention.time=24h" "--storage.tsdb.retention.size=2GB") -}}
{{- end -}}
{{- toYaml $args -}}
{{- end -}}

{{- define "inference.redisArgs" -}}
{{- $args := .Values.redis.args -}}
{{- if ne (int .Values.ports.redis) 6379 -}}
  {{- $args = concat $args (list "--port" (toString .Values.ports.redis)) -}}
{{- end -}}
{{- toYaml $args -}}
{{- end -}}

{{- define "inference.redisReadiness" -}}
{{- $probe := deepCopy .Values.redis.readinessProbe -}}
{{- if ne (int .Values.ports.redis) 6379 -}}
  {{- $_ := set $probe.exec "command" (concat (list "redis-cli" "-p" (toString .Values.ports.redis)) (rest $probe.exec.command)) -}}
{{- end -}}
{{- toYaml $probe -}}
{{- end -}}

{{- define "inference.prometheusConfig" -}}
{{- $gateway := list -}}
{{- range until (int .Values.gateway.replicas) -}}
  {{- $gateway = append $gateway (printf "gateway-%d.gateway-peer:%d" . (int $.Values.ports.gateway)) -}}
{{- end -}}
{{- $engine := list -}}
{{- $replicas := ternary 2 (int .Values.engineReplicas) .Values.autoscaling.enabled -}}
{{- range until $replicas -}}
  {{- $engine = append $engine (printf "vllm-%d.vllm:%d" . (int $.Values.ports.engine)) -}}
{{- end -}}
{{- $jobs := list
  (dict "job_name" "gateway" "static_configs" (list (dict "targets" $gateway)))
  (dict "job_name" "vllm" "static_configs" (list (dict "targets" $engine))) -}}
{{- if .Values.autoscaling.enabled -}}
  {{- $jobs = append $jobs (dict "job_name" "keda" "static_configs" (list (dict "targets" (list .Values.autoscaling.kedaMetricsTarget)))) -}}
{{- end -}}
{{- if .Values.dcgm.enabled -}}
  {{- $jobs = append $jobs (dict "job_name" "dcgm" "scrape_interval" "500ms" "scrape_timeout" "400ms"
    "dns_sd_configs" (list (dict "names" (list (printf "dcgm-exporter.%s.svc" (include "inference.ns" .))) "type" "A" "port" 9400))) -}}
{{- end -}}
{{- dict "global" (dict "scrape_interval" .Values.telemetry.scrapeInterval) "scrape_configs" $jobs | toYaml -}}
{{- end -}}
