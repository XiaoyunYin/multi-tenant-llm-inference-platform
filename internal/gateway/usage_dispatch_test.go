package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"multi-tenant-llm-inference-platform/internal/admission"
)

func TestMeterDispatchRefusesRecoveredBackendWithoutIntent(t *testing.T) {
	store, readback, client := meterCoordinators(t)
	progress := strings.TrimSuffix(store.CredentialKey(""), "credential:") + "usage:progress"
	var contacts atomic.Int32
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			contacts.Add(1)
			if count, err := client.HLen(r.Context(), progress).Result(); err != nil || count == 0 {
				t.Errorf("inference arrived without a progress row: count=%d error=%v", count, err)
			}
		}
		streamHandler(contentEvent+finishEvent+usageEvent+doneEvent)(w, r)
	})
	g, _ := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), store, backend)
	var checks atomic.Int32
	g.canDispatch = func(*Registry, *Backend) bool {
		// The old split guard skipped intent on false, then sent on true.
		return checks.Add(1) > 1
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(managedBody))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testCredential)
	recorder := httptest.NewRecorder()
	g.Handler().ServeHTTP(recorder, request)
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 503 || !strings.Contains(string(body), "backend_membership_changed_after_admit") {
		t.Fatalf("first failed check did not take the post-admission 503 path: status=%d error=%v", response.StatusCode, err)
	}
	if checks.Load() != 1 || contacts.Load() != 0 || g.Metrics().BackendChangedAfterAdmit != 1 {
		t.Fatalf("dispatch escaped the first check: checks=%d contacts=%d", checks.Load(), contacts.Load())
	}
	report := meterReport(t, readback)
	if report.Admitted != 1 || report.Terminal != 1 || len(report.Rows) != 1 ||
		len(report.Discrepancies) != 0 {
		t.Fatalf("refused attempt did not reconcile: %+v", report)
	}
	row := report.Rows[0]
	if row.Outcome != "rejected" || row.DispatchIntent || row.StreamCommitted {
		t.Fatalf("unexpected refusal terminal: %+v", row)
	}
	for _, count := range []admission.UsageCount{row.Prompt, row.Completion} {
		if count.Classification != "exact" || count.Source != "no_dispatch" || count.Tokens == nil || *count.Tokens != 0 {
			t.Fatalf("refused attempt did not settle at exact zero: %+v", count)
		}
	}
}

type observedUsageAcknowledgement struct {
	*admission.RedisCoordinator
	loseReply bool
	ack       atomic.Pointer[admission.UsageAttempt]
}

func (s *observedUsageAcknowledgement) BeginUsageDispatch(ctx context.Context, attempt admission.UsageAttempt, pins admission.UsagePins) error {
	if err := s.RedisCoordinator.BeginUsageDispatch(ctx, attempt, pins); err != nil {
		return err
	}
	if s.loseReply {
		return errors.New("fixture intent reply lost after commit")
	}
	s.ack.Store(&attempt)
	return nil
}

func TestMeterDispatchRequiresAcknowledgedIntent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		loseReply bool
		status    int
		contacts  int32
		outcome   string
		count     string
	}{
		{"acknowledged", false, 200, 3, "completed", "exact"},
		{"lost_reply", true, 503, 0, "rejected", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, readback, client := meterCoordinators(t)
			progress := strings.TrimSuffix(store.CredentialKey(""), "credential:") + "usage:progress"
			observed := &observedUsageAcknowledgement{RedisCoordinator: store, loseReply: tc.loseReply}
			var contacts atomic.Int32
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					contacts.Add(1)
					attempt := observed.ack.Load()
					if attempt == nil || attempt.RequestID != r.Header.Get("X-Request-ID") {
						t.Error("inference arrived without acknowledgement for its request ID")
					} else if count, err := client.HExists(r.Context(), progress, attempt.TenantID+":"+attempt.ReservationID).Result(); err != nil || !count {
						t.Errorf("acknowledgement lacked the durable progress row: %v", err)
					}
				}
				streamHandler(contentEvent+finishEvent+usageEvent+doneEvent)(w, r)
			})
			_, server := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), observed, backend)
			for range 3 {
				if status := managedRequest(t, server.URL, testCredential, managedBody); status != tc.status {
					t.Fatalf("status=%d, want %d", status, tc.status)
				}
			}
			if contacts.Load() != tc.contacts {
				t.Fatalf("inference contacts=%d, want %d", contacts.Load(), tc.contacts)
			}
			report := meterReport(t, readback)
			if report.Admitted != 3 || report.Terminal != 3 || len(report.Rows) != 3 || len(report.Discrepancies) != 0 {
				t.Fatalf("dispatch cohort did not reconcile: %+v", report)
			}
			for _, row := range report.Rows {
				if !row.DispatchIntent || row.Outcome != tc.outcome ||
					row.Prompt.Classification != tc.count || row.Completion.Classification != tc.count {
					t.Fatalf("unexpected terminal after intent: %+v", row)
				}
			}
		})
	}
}
