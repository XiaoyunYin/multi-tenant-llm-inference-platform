package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"

	"github.com/redis/go-redis/v9"
)

func TestMeterRuntimeUsagePresence(t *testing.T) {
	for _, tt := range []struct {
		name, fields string
		valid        bool
	}{
		{"explicit zero", `"prompt_tokens":0,"completion_tokens":0,"total_tokens":0`, true},
		{"missing prompt", `"completion_tokens":0,"total_tokens":0`, false},
		{"null completion", `"prompt_tokens":0,"completion_tokens":null,"total_tokens":0`, false},
		{"fraction", `"prompt_tokens":1.5,"completion_tokens":1,"total_tokens":2.5`, false},
		{"invalid sum", `"prompt_tokens":4,"completion_tokens":1,"total_tokens":6`, false},
		{"invalid negative", `"prompt_tokens":-1,"completion_tokens":1,"total_tokens":0`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if value := meteredRuntimeUsage([]byte(`{"usage":{` + tt.fields + `}}`)); (value != nil) != tt.valid {
				t.Fatalf("parsed %+v, want valid=%v", value, tt.valid)
			}
		})
	}
}

func meterCoordinators(t *testing.T) (*admission.RedisCoordinator, *admission.RedisCoordinator, *redis.Client) {
	t.Helper()
	client, config := gatewayRedis(t)
	config.Metering = true
	first, err := admission.NewRedisCoordinator(client, config)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("METERING_TEST_DURABILITY") == "1" {
		if err := admission.CheckUsageDurability(context.Background(), client); err != nil {
			t.Fatal(err)
		}
	}
	second, err := admission.NewRedisCoordinator(client, config)
	if err != nil {
		t.Fatal(err)
	}
	return first, second, client
}

func meterGrant(t *testing.T, store *admission.RedisCoordinator) admission.UsageAttempt {
	t.Helper()
	attempt := admission.UsageAttempt{
		TenantID: "tenant-test", RequestID: newID("req"), ReservationID: newID("rsv"), OwnerEpoch: newID("owner"),
	}
	value, err := store.Admit(context.Background(), admission.Request{
		TenantID: attempt.TenantID, ReservationID: attempt.ReservationID, RequestID: attempt.RequestID,
		Limits: admission.Limits{RequestLimit: 10000, RequestWindow: time.Second, MaxConcurrent: 128},
	})
	if err != nil || value.Decision != admission.Allowed {
		t.Fatalf("admit: %+v %v", value, err)
	}
	return attempt
}

func meterReport(t *testing.T, store *admission.RedisCoordinator) admission.UsageReconciliation {
	t.Helper()
	result, err := store.ReconcileUsage(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestMeterTerminalRaces(t *testing.T) {
	one, two, _ := meterCoordinators(t)
	ctx := context.Background()
	pins := admission.UsagePins{Model: "test-model"}
	attempt := meterGrant(t, one)
	if err := one.BeginUsageDispatch(ctx, attempt, pins); err != nil {
		t.Fatal(err)
	}
	point := admission.UsageCheckpoint{Sequence: 1, Runtime: &admission.UsageTokens{Prompt: 17, Completion: 4}}
	if err := one.CheckpointUsage(ctx, attempt, point); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for _, job := range []struct {
		outcome string
		store   *admission.RedisCoordinator
	}{{"completed", one}, {"client_cancelled", two}, {"timeout", two}, {"completed", two}} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := job.store.FinalizeUsage(ctx, attempt, pins, job.outcome, true)
			if err != nil && !errors.Is(err, admission.ErrUsageConflict) {
				t.Errorf("terminal %s: %v", job.outcome, err)
			}
		}()
	}
	close(start)
	workers.Wait()
	report := meterReport(t, two)
	if report.Admitted != 1 || report.Terminal != 1 || len(report.Rows) != 1 || len(report.Discrepancies) != 2 {
		t.Fatalf("race: %+v", report)
	}
	winner := report.Rows[0]
	if winner.Version != 1 || winner.AdmittedUnixMS == nil || *winner.AdmittedUnixMS <= 0 || winner.Prompt.Tokens == nil || *winner.Prompt.Tokens != 17 ||
		(winner.Prompt.Classification == "exact") != (winner.Outcome == "completed") {
		t.Fatalf("unexpected race winner: %+v", winner)
	}
	replay, err := one.FinalizeUsage(ctx, attempt, pins, winner.Outcome, true)
	if err != nil || !reflect.DeepEqual(replay, winner) || !reflect.DeepEqual(report, meterReport(t, one)) {
		t.Fatalf("race winner replay: %+v %v", replay, err)
	}
}

func TestMeterDuplicateReplay(t *testing.T) {
	one, two, _ := meterCoordinators(t)
	ctx := context.Background()
	attempt := meterGrant(t, one)
	pins := admission.UsagePins{Model: "test-model", ModelPin: strings.Repeat("a", 40), Engine: "sha256:" + strings.Repeat("b", 64), Tokenizer: strings.Repeat("c", 40)}
	for _, store := range []*admission.RedisCoordinator{one, two} {
		if err := store.BeginUsageDispatch(ctx, attempt, pins); err != nil {
			t.Fatal(err)
		}
	}
	points := []admission.UsageCheckpoint{
		{Sequence: 1, Estimate: &admission.UsageTokens{Prompt: 12, Completion: 2}},
		{Sequence: 2, Runtime: &admission.UsageTokens{Prompt: 12, Completion: 1}, Estimate: &admission.UsageTokens{Prompt: 12, Completion: 1}},
	}
	for _, point := range points {
		if err := one.CheckpointUsage(ctx, attempt, point); err != nil {
			t.Fatal(err)
		}
	}
	conflict := points[1]
	conflict.Estimate = &admission.UsageTokens{Prompt: 999, Completion: 999}
	if err := two.CheckpointUsage(ctx, attempt, conflict); !errors.Is(err, admission.ErrUsageConflict) {
		t.Fatalf("conflicting checkpoint: %v", err)
	}
	result, err := one.FinalizeUsage(ctx, attempt, pins, "completed", true)
	if err != nil || result.Checkpoint == nil || !reflect.DeepEqual(*result.Checkpoint, points[1]) || result.Pins != pins {
		t.Fatalf("final: %+v %v", result, err)
	}
	before := meterReport(t, one)
	if len(before.Discrepancies) != 1 || before.Discrepancies[0].Cause != "event_payload_conflict" {
		t.Fatalf("discrepancies: %+v", before.Discrepancies)
	}
	total := before.Totals[attempt.TenantID]
	if total.Prompt.ExactTokens != 12 || total.Completion.ExactTokens != 1 ||
		total.Prompt.EstimateTokens != 12 || total.Completion.EstimateTokens != 1 {
		t.Fatalf("totals: %+v", total)
	}
	for _, point := range points {
		if err := two.CheckpointUsage(ctx, attempt, point); err != nil {
			t.Fatal(err)
		}
	}
	replayed, err := two.FinalizeUsage(ctx, attempt, pins, "completed", true)
	if err != nil || !reflect.DeepEqual(result, replayed) || !reflect.DeepEqual(before, meterReport(t, two)) {
		t.Fatalf("replay changed totals or rows: %+v %v", replayed, err)
	}
	mismatched := meterGrant(t, two)
	if err := two.BeginUsageDispatch(ctx, mismatched, pins); err != nil {
		t.Fatal(err)
	}
	point := admission.UsageCheckpoint{
		Sequence: 1, Runtime: &admission.UsageTokens{Prompt: 10, Completion: 2},
		Estimate: &admission.UsageTokens{Prompt: 11, Completion: 2},
	}
	if err := two.CheckpointUsage(ctx, mismatched, point); err != nil {
		t.Fatal(err)
	}
	quarantined, err := two.FinalizeUsage(ctx, mismatched, pins, "completed", true)
	if err != nil || quarantined.Prompt.Classification != "quarantined" {
		t.Fatalf("estimate mismatch was counted as exact: %+v %v", quarantined, err)
	}
	totals := meterReport(t, one).Totals[attempt.TenantID]
	if totals.Prompt.ExactTokens != 12 || totals.Prompt.ObservedPartialTokens != 0 ||
		totals.Prompt.QuarantinedRows != 1 || totals.Prompt.QuarantinedTokens != 10 ||
		totals.Prompt.EstimateTokens != 23 || totals.Discrepancies != 2 {
		t.Fatalf("estimate mismatch totals: %+v", totals)
	}
}

func TestMeterPartialUsage(t *testing.T) {
	missing := strings.Replace(usageEvent, `"completion_tokens":1,`, "", 1)
	missing = strings.Replace(missing, `"total_tokens":5`, `"total_tokens":4`, 1)
	invalid := strings.Replace(usageEvent, `"total_tokens":5`, `"total_tokens":6`, 1)
	for _, tt := range []struct {
		name, stream, outcome, classification string
	}{
		{"split UTF-8", strings.Replace(contentEvent, "hello", "héllo", 1) + finishEvent + usageEvent + doneEvent, "completed", "exact"},
		{"usage before first content", usageEvent + doneEvent, "upstream_protocol_error", "unknown"},
		{"missing count", contentEvent + finishEvent + missing + doneEvent, "completed", "unknown"},
		{"invalid sum", contentEvent + finishEvent + invalid + doneEvent, "upstream_protocol_error", "unknown"},
		{"error before first content", "", "upstream_failure", "unknown"},
		{"usage before EOF", contentEvent + finishEvent + usageEvent, "stream_interrupted", "observed_partial"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			one, two, _ := meterCoordinators(t)
			backend := streamHandler(tt.stream)
			if tt.name == "split UTF-8" {
				backend = func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/health" {
						w.WriteHeader(http.StatusOK)
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					cut := strings.Index(tt.stream, "é") + 1
					_, _ = io.WriteString(w, tt.stream[:cut])
					w.(http.Flusher).Flush()
					_, _ = io.WriteString(w, tt.stream[cut:])
				}
			}
			_, a := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), one, backend)
			_, b := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), two, backend)
			for _, url := range []string{a.URL, b.URL} {
				resp := requestGateway(t, http.DefaultClient, url)
				_, err := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			report := meterReport(t, two)
			if report.Admitted != 2 || report.Terminal != 2 || len(report.Rows) != 2 || len(report.Discrepancies) != 0 {
				t.Fatalf("two-gateway cohort: %+v", report)
			}
			for _, row := range report.Rows {
				if row.Outcome != tt.outcome || !row.DispatchIntent || row.Prompt.Classification != tt.classification || row.Completion.Classification != tt.classification {
					t.Fatalf("terminal: %+v, want %s / %s", row, tt.outcome, tt.classification)
				}
			}
		})
	}
}

type withheldUsageIntent struct{ *admission.RedisCoordinator }

func (withheldUsageIntent) BeginUsageDispatch(context.Context, admission.UsageAttempt, admission.UsagePins) error {
	return errors.New("fixture refused dispatch intent")
}

func TestMeterCohortReconciliation(t *testing.T) {
	one, two, client := meterCoordinators(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		var request chatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error("bad fixture request", err)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, contentEvent)
		w.(http.Flusher).Flush()
		if request.Model == "m" {
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, finishEvent+usageEvent)
		if request.MaxTokens == nil || *request.MaxTokens != 7 {
			_, _ = io.WriteString(w, doneEvent)
		}
	})
	g1, a := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), one, backend)
	g2, b := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), two, backend)
	for _, url := range []string{a.URL, b.URL} {
		resp := requestGateway(t, http.DefaultClient, url)
		_, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	partial := postBody(t, http.DefaultClient, b.URL, "application/json",
		`{"model":"test-model","messages":[{"role":"user","content":"fixture"}],"stream":true,"max_tokens":7}`)
	_, partialErr := io.Copy(io.Discard, partial.Body)
	partial.Body.Close()
	if partialErr != nil {
		t.Fatal(partialErr)
	}
	// Disconnect after the first content event. Wait for the handler terminal
	// through its active-attempt boundary rather than sleeping for Redis.
	reqCtx, disconnect := context.WithCancel(ctx)
	defer disconnect()
	request, err := http.NewRequestWithContext(reqCtx, http.MethodPost, a.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"fixture"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testCredential)
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	// One byte establishes that the response reached the client.
	_, err = io.ReadFull(resp.Body, make([]byte, 1))
	disconnect()
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g1.Shutdown(time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := g2.Shutdown(time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	// A failed intent must not contact an upstream and leaves a known-zero row.
	_, stopped := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), withheldUsageIntent{one},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				t.Error("forwarded before recording intent")
			}
			w.WriteHeader(http.StatusOK)
		}))
	if status := managedRequest(t, stopped.URL, testCredential, managedBody); status != 503 {
		t.Fatalf("intent refusal status %d", status)
	}
	original := make(chan admission.Request, 1)
	lost := afterGrant{one, func(_ context.Context, request admission.Request) error {
		original <- request
		return errors.New("fixture lost reply after journal commit")
	}}
	_, lostServer := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), lost, backend)
	if status := managedRequest(t, lostServer.URL, testCredential, managedBody); status != 503 {
		t.Fatalf("lost reply status %d", status)
	}
	firstAttempt := <-original
	retried := make(chan admission.Request, 1)
	retry := afterGrant{two, func(_ context.Context, request admission.Request) error {
		retried <- request
		return nil
	}}
	_, retryServer := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), retry, backend)
	if status := managedRequest(t, retryServer.URL, testCredential, managedBody); status != 200 {
		t.Fatalf("client retry status %d", status)
	}
	secondAttempt := <-retried
	if firstAttempt.ReservationID == secondAttempt.ReservationID || firstAttempt.RequestID == secondAttempt.RequestID {
		t.Fatal("client retry reused a server attempt")
	}
	report := meterReport(t, two)
	sums := report.Totals["tenant-test"]
	if report.Admitted != 7 || report.Terminal != 7 || len(report.Rows) != 7 || len(report.Discrepancies) != 0 ||
		sums.Prompt.ExactTokens != 12 || sums.Completion.ExactTokens != 3 ||
		sums.Prompt.UnknownRows != 1 || sums.Prompt.KnownZeroRows != 2 ||
		sums.Prompt.ObservedPartialTokens != 4 || sums.Completion.ObservedPartialTokens != 1 {
		t.Fatalf("closed cohort: %+v", report)
	}
	var sawCancel, sawLostReply, sawRetry bool
	for _, row := range report.Rows {
		sawCancel = sawCancel || row.Outcome == "client_cancelled" && row.StreamCommitted && row.DispatchIntent
		sawLostReply = sawLostReply || row.ReservationID == firstAttempt.ReservationID &&
			row.RequestID == firstAttempt.RequestID && row.Prompt.Source == "no_dispatch"
		sawRetry = sawRetry || row.ReservationID == secondAttempt.ReservationID &&
			row.RequestID == secondAttempt.RequestID && row.Outcome == "completed" && row.DispatchIntent
	}
	if !sawCancel || !sawLostReply || !sawRetry {
		t.Fatalf("missing cancellation or retry row: %+v", report.Rows)
	}
	unsettled := meterGrant(t, two)
	prefix := strings.TrimSuffix(two.CredentialKey(""), "credential:")
	first := report.Rows[0]
	key := first.TenantID + ":" + first.ReservationID
	first.TenantID = "other-tenant"
	mutated, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.HSet(ctx, prefix+"usage:terminal", key, mutated,
		"tenant-test:"+newID("rsv"), mutated).Err(); err != nil {
		t.Fatal(err)
	}
	disputed := meterReport(t, two)
	causes := make(map[string]string)
	for _, item := range disputed.Discrepancies {
		causes[item.Cause] = item.AttemptKey
	}
	if len(disputed.Rows) != 6 || len(disputed.Discrepancies) != 3 || len(disputed.Orphaned) != 1 ||
		causes["terminal_tenant_mismatch"] != key || causes["terminal_without_admission"] != disputed.Orphaned[0] ||
		causes["terminal_missing_without_intent"] != unsettled.TenantID+":"+unsettled.ReservationID {
		t.Fatalf("mutated cohort: %+v", disputed)
	}
}
