package gateway

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"
)

var routingTokenizeDurationBounds = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5}
var routingLookupDurationBounds = [...]float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1}

type Metrics struct {
	requests                 atomic.Uint64
	active                   atomic.Int64
	completed                atomic.Uint64
	failed                   atomic.Uint64
	partial                  atomic.Uint64
	rejected                 atomic.Uint64
	cancelled                atomic.Uint64
	timeouts                 atomic.Uint64
	tenantRateLimited        atomic.Uint64
	tenantConcurrencyLimited atomic.Uint64
	systemCapacityLimited    atomic.Uint64
	admissionUnavailable     atomic.Uint64
	releaseFailures          atomic.Uint64
	terminals                [terminalCauseCount]atomic.Uint64
	routingDecisions         [len(routingPolicies)][len(fallbackReasons)]atomic.Uint64
	routingLookupCount       atomic.Uint64
	routingLookupNanos       atomic.Uint64
	routingLookupBuckets     [len(routingLookupDurationBounds)]atomic.Uint64
	routingTokenizeCount     atomic.Uint64
	routingTokenizeFailures  atomic.Uint64
	routingTokenizeNanos     atomic.Uint64
	routingTokenizeBuckets   [len(routingTokenizeDurationBounds)]atomic.Uint64
	routingTokenizeMu        sync.RWMutex
	routingTokenizeAttempts  map[string]*atomic.Uint64
	routingTokenizeBackends  []string
	backendMetrics           *BackendMetricsCollector
}

type RoutingDecisionMetric struct {
	Policy         RoutingPolicy
	FallbackReason FallbackReason
	Count          uint64
}

type RoutingTokenizeAttemptMetric struct {
	BackendID string
	Count     uint64
}

type MetricsSnapshot struct {
	Requests                 uint64
	Active                   int64
	Completed                uint64
	Failed                   uint64
	Partial                  uint64
	Rejected                 uint64
	Cancelled                uint64
	Timeouts                 uint64
	TenantRateLimited        uint64
	TenantConcurrencyLimited uint64
	SystemCapacityLimited    uint64
	AdmissionUnavailable     uint64
	ReleaseFailures          uint64
	Terminals                map[string]uint64
	RoutingDecisions         []RoutingDecisionMetric
	RoutingLookupCount       uint64
	RoutingLookupSeconds     float64
	RoutingLookupBuckets     [len(routingLookupDurationBounds)]uint64
	RoutingTokenizeCount     uint64
	RoutingTokenizeFailures  uint64
	RoutingTokenizeSeconds   float64
	RoutingTokenizeBuckets   [len(routingTokenizeDurationBounds)]uint64
	RoutingTokenizeAttempts  []RoutingTokenizeAttemptMetric
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	snapshot := MetricsSnapshot{
		Requests:                 m.requests.Load(),
		Active:                   m.active.Load(),
		Completed:                m.completed.Load(),
		Failed:                   m.failed.Load(),
		Partial:                  m.partial.Load(),
		Rejected:                 m.rejected.Load(),
		Cancelled:                m.cancelled.Load(),
		Timeouts:                 m.timeouts.Load(),
		TenantRateLimited:        m.tenantRateLimited.Load(),
		TenantConcurrencyLimited: m.tenantConcurrencyLimited.Load(),
		SystemCapacityLimited:    m.systemCapacityLimited.Load(),
		AdmissionUnavailable:     m.admissionUnavailable.Load(),
		ReleaseFailures:          m.releaseFailures.Load(),
		RoutingTokenizeCount:     m.routingTokenizeCount.Load(),
		RoutingTokenizeFailures:  m.routingTokenizeFailures.Load(),
		RoutingTokenizeSeconds:   float64(m.routingTokenizeNanos.Load()) / float64(time.Second),
		Terminals:                make(map[string]uint64, terminalCauseCount),
		RoutingDecisions:         make([]RoutingDecisionMetric, 0, len(routingPolicies)*len(fallbackReasons)),
		RoutingTokenizeAttempts:  make([]RoutingTokenizeAttemptMetric, 0, len(m.routingTokenizeBackends)),
		RoutingLookupCount:       m.routingLookupCount.Load(),
		RoutingLookupSeconds:     float64(m.routingLookupNanos.Load()) / float64(time.Second),
	}
	m.routingTokenizeMu.RLock()
	for _, backendID := range m.routingTokenizeBackends {
		snapshot.RoutingTokenizeAttempts = append(snapshot.RoutingTokenizeAttempts, RoutingTokenizeAttemptMetric{
			BackendID: backendID, Count: m.routingTokenizeAttempts[backendID].Load(),
		})
	}
	m.routingTokenizeMu.RUnlock()
	for cause := terminalCause(0); cause < terminalCauseCount; cause++ {
		snapshot.Terminals[cause.String()] = m.terminals[cause].Load()
	}
	for index := range routingTokenizeDurationBounds {
		snapshot.RoutingTokenizeBuckets[index] = m.routingTokenizeBuckets[index].Load()
	}
	for index := range routingLookupDurationBounds {
		snapshot.RoutingLookupBuckets[index] = m.routingLookupBuckets[index].Load()
	}
	for policyIndex, policy := range routingPolicies {
		for reasonIndex, reason := range fallbackReasons {
			if count := m.routingDecisions[policyIndex][reasonIndex].Load(); count > 0 {
				snapshot.RoutingDecisions = append(snapshot.RoutingDecisions, RoutingDecisionMetric{
					Policy: policy, FallbackReason: reason, Count: count,
				})
			}
		}
	}
	return snapshot
}

// registerRoutingTokenizeBackends fixes the metric label set to the configured
// backend inventory; requests cannot create new per-replica time series.
func (m *Metrics) registerRoutingTokenizeBackends(backendIDs []string) {
	m.routingTokenizeMu.Lock()
	defer m.routingTokenizeMu.Unlock()
	if m.routingTokenizeAttempts == nil {
		m.routingTokenizeAttempts = make(map[string]*atomic.Uint64, len(backendIDs))
	}
	for _, backendID := range backendIDs {
		if _, exists := m.routingTokenizeAttempts[backendID]; exists {
			continue
		}
		m.routingTokenizeAttempts[backendID] = &atomic.Uint64{}
		m.routingTokenizeBackends = append(m.routingTokenizeBackends, backendID)
	}
	sort.Strings(m.routingTokenizeBackends)
}

func (m *Metrics) recordRoutingTokenizeAttempts(backendIDs []string) {
	for _, backendID := range backendIDs {
		if counter, exists := m.routingTokenizeAttempts[backendID]; exists {
			counter.Add(1)
		}
	}
}

func (m *Metrics) recordRoutingTokenizeDuration(duration time.Duration, failed bool) {
	if duration < 0 {
		duration = 0
	}
	seconds := duration.Seconds()
	m.routingTokenizeCount.Add(1)
	m.routingTokenizeNanos.Add(uint64(duration))
	if failed {
		m.routingTokenizeFailures.Add(1)
	}
	for index, bound := range routingTokenizeDurationBounds {
		if seconds <= bound {
			m.routingTokenizeBuckets[index].Add(1)
		}
	}
}

func (m *Metrics) recordRoutingLookupDuration(duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	seconds := duration.Seconds()
	m.routingLookupCount.Add(1)
	m.routingLookupNanos.Add(uint64(duration))
	for index, bound := range routingLookupDurationBounds {
		if seconds <= bound {
			m.routingLookupBuckets[index].Add(1)
		}
	}
}

func (m *Metrics) recordRoutingDecision(decision BackendDecision) {
	if decision.Backend == nil {
		return
	}
	policyIndex, policyOK := routingPolicyIndex(decision.Policy)
	reasonIndex, reasonOK := fallbackReasonIndex(decision.FallbackReason)
	if policyOK && reasonOK {
		m.routingDecisions[policyIndex][reasonIndex].Add(1)
	}
}

func (m *Metrics) recordAdmissionDenial(decision admission.Decision) {
	switch decision {
	case admission.TenantRateLimited:
		m.tenantRateLimited.Add(1)
	case admission.TenantConcurrencyLimited:
		m.tenantConcurrencyLimited.Add(1)
	case admission.SystemCapacityLimited:
		m.systemCapacityLimited.Add(1)
	}
}

func (m *Metrics) recordTerminal(cause terminalCause) {
	if cause >= 0 && cause < terminalCauseCount {
		m.terminals[cause].Add(1)
	}
}

func (m *Metrics) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	snapshot := m.Snapshot()
	response.Header().Set("Content-Type", "text/plain; version=0.0.4")
	writeMetricMetadata(response)
	fmt.Fprintf(response, "inference_gateway_requests_total %d\n", snapshot.Requests)
	fmt.Fprintf(response, "inference_gateway_active_requests %d\n", snapshot.Active)
	fmt.Fprintf(response, "inference_gateway_completed_total %d\n", snapshot.Completed)
	fmt.Fprintf(response, "inference_gateway_failed_total %d\n", snapshot.Failed)
	fmt.Fprintf(response, "inference_gateway_partial_streams_total %d\n", snapshot.Partial)
	fmt.Fprintf(response, "inference_gateway_rejected_total %d\n", snapshot.Rejected)
	fmt.Fprintf(response, "inference_gateway_cancelled_total %d\n", snapshot.Cancelled)
	fmt.Fprintf(response, "inference_gateway_timeouts_total %d\n", snapshot.Timeouts)
	fmt.Fprintf(response, "inference_gateway_tenant_rate_limited_total %d\n", snapshot.TenantRateLimited)
	fmt.Fprintf(response, "inference_gateway_tenant_concurrency_limited_total %d\n", snapshot.TenantConcurrencyLimited)
	fmt.Fprintf(response, "inference_gateway_system_capacity_limited_total %d\n", snapshot.SystemCapacityLimited)
	fmt.Fprintf(response, "inference_gateway_admission_unavailable_total %d\n", snapshot.AdmissionUnavailable)
	fmt.Fprintf(response, "inference_gateway_release_failures_total %d\n", snapshot.ReleaseFailures)
	for cause := terminalCause(0); cause < terminalCauseCount; cause++ {
		fmt.Fprintf(response, "inference_gateway_terminal_total{cause=%q} %d\n", cause.String(), snapshot.Terminals[cause.String()])
	}
	for _, decision := range snapshot.RoutingDecisions {
		fmt.Fprintf(response, "inference_gateway_routing_decisions_total{policy=%q,fallback_reason=%q} %d\n",
			decision.Policy, decision.FallbackReason, decision.Count)
	}
	for index, bound := range routingTokenizeDurationBounds {
		fmt.Fprintf(response, "inference_gateway_routing_tokenize_duration_seconds_bucket{le=%q} %d\n", fmt.Sprintf("%g", bound), snapshot.RoutingTokenizeBuckets[index])
	}
	fmt.Fprintf(response, "inference_gateway_routing_tokenize_duration_seconds_bucket{le=\"+Inf\"} %d\n", snapshot.RoutingTokenizeCount)
	fmt.Fprintf(response, "inference_gateway_routing_tokenize_duration_seconds_sum %.9g\n", snapshot.RoutingTokenizeSeconds)
	fmt.Fprintf(response, "inference_gateway_routing_tokenize_duration_seconds_count %d\n", snapshot.RoutingTokenizeCount)
	fmt.Fprintf(response, "inference_gateway_routing_tokenize_failures_total %d\n", snapshot.RoutingTokenizeFailures)
	for index, bound := range routingLookupDurationBounds {
		fmt.Fprintf(response, "inference_gateway_routing_lookup_duration_seconds_bucket{le=%q} %d\n", fmt.Sprintf("%g", bound), snapshot.RoutingLookupBuckets[index])
	}
	fmt.Fprintf(response, "inference_gateway_routing_lookup_duration_seconds_bucket{le=\"+Inf\"} %d\n", snapshot.RoutingLookupCount)
	fmt.Fprintf(response, "inference_gateway_routing_lookup_duration_seconds_sum %.9g\n", snapshot.RoutingLookupSeconds)
	fmt.Fprintf(response, "inference_gateway_routing_lookup_duration_seconds_count %d\n", snapshot.RoutingLookupCount)
	for _, attempt := range snapshot.RoutingTokenizeAttempts {
		fmt.Fprintf(response, "inference_gateway_routing_tokenize_requests_total{backend_id=%q} %d\n", attempt.BackendID, attempt.Count)
	}
	if m.backendMetrics == nil {
		return
	}
	for _, backend := range m.backendMetrics.Snapshots(time.Now()) {
		fmt.Fprintf(response, "inference_gateway_backend_metrics_up{backend_id=%q} %d\n", backend.BackendID, boolMetric(backend.Up))
		fmt.Fprintf(response, "inference_gateway_backend_metrics_fresh{backend_id=%q} %d\n", backend.BackendID, boolMetric(backend.Fresh))
		fmt.Fprintf(response, "inference_gateway_backend_metrics_scrape_duration_seconds{backend_id=%q} %.9g\n", backend.BackendID, backend.ScrapeDuration.Seconds())
		fmt.Fprintf(response, "inference_gateway_backend_metrics_scrape_errors_total{backend_id=%q} %d\n", backend.BackendID, backend.ScrapeErrors)
		if backend.HasSample {
			fmt.Fprintf(response, "inference_gateway_backend_metrics_sample_age_seconds{backend_id=%q} %.9g\n", backend.BackendID, backend.SampleAge.Seconds())
			fmt.Fprintf(response, "inference_gateway_backend_requests_running{backend_id=%q} %.9g\n", backend.BackendID, backend.Running)
			fmt.Fprintf(response, "inference_gateway_backend_requests_waiting{backend_id=%q} %.9g\n", backend.BackendID, backend.Waiting)
			fmt.Fprintf(response, "inference_gateway_backend_kv_cache_usage_ratio{backend_id=%q} %.9g\n", backend.BackendID, backend.KVUsage)
		}
	}
}

func writeMetricMetadata(response http.ResponseWriter) {
	metadata := []struct {
		name, metricType, help string
	}{
		{"inference_gateway_requests_total", "counter", "Requests that acquired execution ownership."},
		{"inference_gateway_active_requests", "gauge", "Requests currently owned by this gateway process."},
		{"inference_gateway_completed_total", "counter", "Requests that completed with a valid terminal stream."},
		{"inference_gateway_failed_total", "counter", "Requests that failed before or after stream commitment."},
		{"inference_gateway_partial_streams_total", "counter", "Committed streams that did not complete."},
		{"inference_gateway_rejected_total", "counter", "Requests rejected before backend execution."},
		{"inference_gateway_cancelled_total", "counter", "Requests cancelled by the client."},
		{"inference_gateway_timeouts_total", "counter", "Requests terminated by a gateway timeout."},
		{"inference_gateway_tenant_rate_limited_total", "counter", "Requests denied by tenant rate policy."},
		{"inference_gateway_tenant_concurrency_limited_total", "counter", "Requests denied by tenant concurrency policy."},
		{"inference_gateway_system_capacity_limited_total", "counter", "Requests denied by the shared admission bound."},
		{"inference_gateway_admission_unavailable_total", "counter", "Requests denied because admission state was unavailable."},
		{"inference_gateway_release_failures_total", "counter", "Reservation releases that exhausted bounded retries."},
		{"inference_gateway_terminal_total", "counter", "Request terminals by mutually exclusive cause."},
		{"inference_gateway_routing_decisions_total", "counter", "Backend selections by effective routing policy and load-fallback reason."},
		{"inference_gateway_routing_tokenize_duration_seconds", "histogram", "Time spent obtaining routing tokens from pinned vLLM replicas."},
		{"inference_gateway_routing_tokenize_failures_total", "counter", "Routing-token calls that failed and used least-loaded fallback."},
		{"inference_gateway_routing_tokenize_requests_total", "counter", "Routing-token endpoint attempts by configured backend replica."},
		{"inference_gateway_routing_lookup_duration_seconds", "histogram", "Time spent in the backend-selection boundary, excluding model tokenization."},
		{"inference_gateway_backend_metrics_up", "gauge", "Whether the most recent backend metrics scrape succeeded."},
		{"inference_gateway_backend_metrics_fresh", "gauge", "Whether a successful backend sample is within the configured maximum age."},
		{"inference_gateway_backend_metrics_scrape_duration_seconds", "gauge", "Duration of the most recent backend metrics scrape."},
		{"inference_gateway_backend_metrics_scrape_errors_total", "counter", "Failed or invalid backend metrics scrapes."},
		{"inference_gateway_backend_metrics_sample_age_seconds", "gauge", "Age of the most recent valid backend metrics sample."},
		{"inference_gateway_backend_requests_running", "gauge", "vLLM requests in model execution batches."},
		{"inference_gateway_backend_requests_waiting", "gauge", "vLLM requests waiting to be processed."},
		{"inference_gateway_backend_kv_cache_usage_ratio", "gauge", "Fraction of vLLM KV-cache blocks in use."},
	}
	for _, item := range metadata {
		fmt.Fprintf(response, "# HELP %s %s\n# TYPE %s %s\n", item.name, item.help, item.name, item.metricType)
	}
}

func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}
