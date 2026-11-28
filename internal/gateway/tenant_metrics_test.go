package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"multi-tenant-llm-inference-platform/internal/admission"
)

func TestTenantMetricsBoundedLabels(t *testing.T) {
	metrics := Metrics{tenantCounters: newTenantCounters(testTenantRegistry(t))}
	for i := range 100 {
		untrusted := fmt.Sprintf("untrusted-%d", i)
		metrics.tenantCounters.record(untrusted, untrusted, requestTerminal{cause: terminalRejected, code: untrusted})
	}
	metrics.tenantCounters.record("tenant-test", "allowed", requestTerminal{cause: terminalCompleted})
	response := httptest.NewRecorder()
	metrics.ServeHTTP(response, nil)
	body := response.Body.String()
	for _, series := range []string{
		"inference_gateway_requests_total 0",
		`inference_gateway_requests_by_tenant_total{tenant="__unknown__"} 100`,
		`inference_gateway_requests_by_tenant_total{tenant="tenant-test"} 1`,
		`inference_gateway_admission_by_tenant_total{tenant="__unknown__",outcome="other"} 100`,
		`inference_gateway_rejections_by_tenant_total{tenant="__unknown__",code="other"} 100`,
	} {
		if !strings.Contains(body, series+"\n") {
			t.Fatalf("missing series %q", series)
		}
	}
	if strings.Contains(body, "untrusted-") {
		t.Fatal("untrusted values became labels")
	}
	want := 2 * (1 + len(admissionMetricOutcomes) + len(rejectionMetricCodes))
	if got := strings.Count(body, "{tenant="); got != want {
		t.Fatalf("tenant series %d, want %d", got, want)
	}
}

func TestTenantMetricsAuthenticationAndDenial(t *testing.T) {
	coordinator := &scriptedCoordinator{result: admission.Result{Decision: admission.TenantConcurrencyLimited}}
	gateway, server := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), coordinator, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("denied request reached the backend")
	}))
	unknown := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(unknown, httptest.NewRequest("POST", "/v1/chat/completions", nil))
	if unknown.Code != 401 {
		t.Fatalf("unknown request: %d", unknown.Code)
	}
	response := requestGateway(t, server.Client(), server.URL)
	response.Body.Close()
	if response.StatusCode != 429 {
		t.Fatalf("authenticated request: %d", response.StatusCode)
	}
	scrape := httptest.NewRecorder()
	gateway.metrics.ServeHTTP(scrape, nil)
	for _, sample := range []string{
		`inference_gateway_rejections_by_tenant_total{tenant="__unknown__",code="unauthenticated"} 1`,
		`inference_gateway_admission_by_tenant_total{tenant="__unknown__",outcome="not_attempted"} 1`,
		`inference_gateway_rejections_by_tenant_total{tenant="tenant-test",code="tenant_concurrency_limit"} 1`,
		`inference_gateway_rejected_total 2`,
	} {
		if !strings.Contains(scrape.Body.String(), sample+"\n") {
			t.Fatalf("missing sample %q", sample)
		}
	}
}
