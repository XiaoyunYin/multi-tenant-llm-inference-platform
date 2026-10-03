package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"
)

type scriptedCoordinator struct {
	mu            sync.Mutex
	result        admission.Result
	admitErr      error
	releaseErrors []error
	admitCalls    []admission.Request
	releaseCalls  [][2]string
}

func (c *scriptedCoordinator) Admit(_ context.Context, request admission.Request) (admission.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.admitCalls = append(c.admitCalls, request)
	return c.result, c.admitErr
}

func (c *scriptedCoordinator) Release(_ context.Context, tenantID, reservationID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.releaseCalls = append(c.releaseCalls, [2]string{tenantID, reservationID})
	if len(c.releaseErrors) == 0 {
		return nil
	}
	err := c.releaseErrors[0]
	c.releaseErrors = c.releaseErrors[1:]
	return err
}

func (c *scriptedCoordinator) calls() ([]admission.Request, [][2]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]admission.Request(nil), c.admitCalls...), append([][2]string(nil), c.releaseCalls...)
}

func TestGatewayMapsAdmissionDenialsWithoutContactingUpstream(t *testing.T) {
	tests := []struct {
		name     string
		decision admission.Decision
		code     string
	}{
		{name: "rate", decision: admission.TenantRateLimited, code: "tenant_rate_limit"},
		{name: "concurrency", decision: admission.TenantConcurrencyLimited, code: "tenant_concurrency_limit"},
		{name: "global", decision: admission.SystemCapacityLimited, code: "system_capacity"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			var contacts atomic.Int32
			upstream := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				contacts.Add(1)
				response.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(response, roleEvent+finishEvent+usageEvent+doneEvent)
			})
			coordinator := &scriptedCoordinator{result: admission.Result{Decision: testCase.decision, RetryAfter: 1500 * time.Millisecond}}
			gateway, server := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), coordinator, upstream)
			response := requestGateway(t, server.Client(), server.URL)
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusTooManyRequests || !containsBytes(body, testCase.code) || response.Header.Get("Retry-After") != "2" {
				t.Fatalf("denial mismatch: status=%d retry=%q body=%s", response.StatusCode, response.Header.Get("Retry-After"), body)
			}
			if contacts.Load() != 0 {
				t.Fatal("denied request contacted upstream")
			}
			admits, releases := coordinator.calls()
			if len(admits) != 1 || len(releases) != 0 || admits[0].TenantID != "tenant-test" || admits[0].Limits.MaxConcurrent != 128 {
				t.Fatalf("coordinator calls mismatch: admits=%+v releases=%+v", admits, releases)
			}
			snapshot := gateway.Metrics()
			if snapshot.Rejected != 1 {
				t.Fatalf("denial metric missing: %+v", snapshot)
			}
		})
	}
}

func TestGatewayUnknownAdmissionFailsClosedAndTombstonesReservation(t *testing.T) {
	var contacts atomic.Int32
	upstream := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacts.Add(1) })
	coordinator := &scriptedCoordinator{admitErr: context.DeadlineExceeded}
	gateway, server := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), coordinator, upstream)
	response := requestGateway(t, server.Client(), server.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || !containsBytes(body, "admission_unavailable") || contacts.Load() != 0 {
		t.Fatalf("unknown admission did not fail closed: status=%d contacts=%d body=%s", response.StatusCode, contacts.Load(), body)
	}
	admits, releases := coordinator.calls()
	if len(admits) != 1 || len(releases) != 1 || releases[0][0] != "tenant-test" || releases[0][1] != admits[0].ReservationID {
		t.Fatalf("unknown admission was not tombstoned: admits=%+v releases=%+v", admits, releases)
	}
	if gateway.Metrics().AdmissionUnavailable != 1 {
		t.Fatalf("admission availability metric missing: %+v", gateway.Metrics())
	}
}

func TestGatewayReleasesAfterExecutionAndRetriesIdempotently(t *testing.T) {
	upstream := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent+contentEvent+finishEvent+usageEvent+doneEvent)
	})
	coordinator := &scriptedCoordinator{
		result:        admission.Result{Decision: admission.Allowed},
		releaseErrors: []error{errors.New("temporary one"), errors.New("temporary two"), nil},
	}
	var logs discardWriter
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	gateway, server := newTestGatewayWithAdmission(t, DefaultConfig(), logger, testTenantRegistry(t), coordinator, upstream)
	response := requestGateway(t, server.Client(), server.URL)
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("successful request failed: %d", response.StatusCode)
	}
	admits, releases := coordinator.calls()
	if len(admits) != 1 || len(releases) != 3 {
		t.Fatalf("release retry mismatch: admits=%d releases=%d", len(admits), len(releases))
	}
	for _, release := range releases {
		if release[1] != admits[0].ReservationID {
			t.Fatalf("release changed reservation identity: admits=%+v releases=%+v", admits, releases)
		}
	}
	if snapshot := gateway.Metrics(); snapshot.ReleaseFailures != 0 || snapshot.Completed != 1 || snapshot.Active != 0 {
		t.Fatalf("terminal accounting mismatch: %+v", snapshot)
	}
}

func TestGatewayLocalCapacityRejectsBeforeAdmission(t *testing.T) {
	release := make(chan struct{})
	upstream := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent)
		response.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(response, finishEvent+usageEvent+doneEvent)
	})
	config := DefaultConfig()
	config.MaxConcurrent = 1
	coordinator := &scriptedCoordinator{result: admission.Result{Decision: admission.Allowed}}
	gateway, server := newTestGatewayWithAdmission(t, config, nil, testTenantRegistry(t), coordinator, upstream)
	first := requestGateway(t, server.Client(), server.URL)
	defer first.Body.Close()
	second := requestGateway(t, server.Client(), server.URL)
	secondBody, _ := io.ReadAll(second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests || !containsBytes(secondBody, "gateway_capacity") {
		t.Fatalf("local capacity mismatch: %d %s", second.StatusCode, secondBody)
	}
	admits, releases := coordinator.calls()
	if len(admits) != 1 || len(releases) != 0 {
		t.Fatalf("local capacity contacted coordinator: admits=%d releases=%d", len(admits), len(releases))
	}
	close(release)
	_, _ = io.Copy(io.Discard, first.Body)
	if snapshot := gateway.Metrics(); snapshot.Rejected != 1 {
		t.Fatalf("local capacity rejection metric mismatch: %+v", snapshot)
	}
}

type discardWriter struct{}

func (*discardWriter) Write(payload []byte) (int, error) { return len(payload), nil }

func containsBytes(body []byte, value string) bool {
	for index := 0; index+len(value) <= len(body); index++ {
		if string(body[index:index+len(value)]) == value {
			return true
		}
	}
	return false
}
