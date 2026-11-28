package gateway

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"sync/atomic"
)

// The underscore prefix is outside the configured tenant alias syntax.
const unknownMetricTenant = "__unknown__"

var admissionMetricOutcomes = [...]string{
	"allowed", "tenant_rate_limit", "tenant_concurrency_limit",
	"system_capacity", "capacity_reports_expired", "credential_denied",
	"unavailable", "not_attempted", "other",
}

var rejectionMetricCodes = [...]string{
	"invalid_request", "shutting_down", "unauthenticated",
	"unsupported_media_type", "model_not_allowed", "discovery_unknown",
	"gateway_capacity", "admission_unavailable", "tenant_rate_limit",
	"tenant_concurrency_limit", "system_capacity", "capacity_reports_expired",
	"post_admission_unavailable", "other",
}

type tenantCounter struct {
	requests  atomic.Uint64
	admission [len(admissionMetricOutcomes)]atomic.Uint64
	reject    [len(rejectionMetricCodes)]atomic.Uint64
}

type tenantCounters struct {
	aliases []string
	byAlias map[string]*tenantCounter
}

func newTenantCounters(registry *TenantRegistry) tenantCounters {
	result := tenantCounters{byAlias: make(map[string]*tenantCounter, len(registry.byTenant)+1)}
	result.aliases = append(result.aliases, unknownMetricTenant)
	for alias := range registry.byTenant {
		result.aliases = append(result.aliases, alias)
	}
	sort.Strings(result.aliases)
	for _, alias := range result.aliases {
		result.byAlias[alias] = &tenantCounter{}
	}
	return result
}

func (c tenantCounters) record(alias, outcome string, terminal requestTerminal) {
	bucket := c.byAlias[alias]
	if bucket == nil {
		bucket = c.byAlias[unknownMetricTenant]
	}
	bucket.requests.Add(1)
	index := slices.Index(admissionMetricOutcomes[:], outcome)
	if index < 0 {
		index = len(admissionMetricOutcomes) - 1
	}
	bucket.admission[index].Add(1)
	if terminal.cause == terminalRejected {
		index = slices.Index(rejectionMetricCodes[:], terminal.code)
		if index < 0 {
			index = len(rejectionMetricCodes) - 1
		}
		bucket.reject[index].Add(1)
	}
}

func (c tenantCounters) write(out io.Writer) {
	fmt.Fprint(out, "# HELP inference_gateway_requests_by_tenant_total Finished chat handler attempts by configured tenant or the unknown bucket.\n# TYPE inference_gateway_requests_by_tenant_total counter\n")
	fmt.Fprint(out, "# HELP inference_gateway_admission_by_tenant_total Admission outcomes for finished chat handler attempts.\n# TYPE inference_gateway_admission_by_tenant_total counter\n")
	fmt.Fprint(out, "# HELP inference_gateway_rejections_by_tenant_total Gateway rejections by configured tenant and bounded error code.\n# TYPE inference_gateway_rejections_by_tenant_total counter\n")
	for _, alias := range c.aliases {
		bucket := c.byAlias[alias]
		fmt.Fprintf(out, "inference_gateway_requests_by_tenant_total{tenant=%q} %d\n", alias, bucket.requests.Load())
		for i, outcome := range admissionMetricOutcomes {
			fmt.Fprintf(out, "inference_gateway_admission_by_tenant_total{tenant=%q,outcome=%q} %d\n", alias, outcome, bucket.admission[i].Load())
		}
		for i, code := range rejectionMetricCodes {
			fmt.Fprintf(out, "inference_gateway_rejections_by_tenant_total{tenant=%q,code=%q} %d\n", alias, code, bucket.reject[i].Load())
		}
	}
}
