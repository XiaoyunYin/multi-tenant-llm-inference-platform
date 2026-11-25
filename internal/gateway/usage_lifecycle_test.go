package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"
)

func fixtureMeterAttempt(tenant, reservation, owner string) admission.UsageAttempt {
	return admission.UsageAttempt{TenantID: tenant, RequestID: newID("req"), ReservationID: reservation, OwnerEpoch: owner}
}

func fixtureMeterRequest(attempt admission.UsageAttempt) admission.Request {
	return admission.Request{
		TenantID: attempt.TenantID, ReservationID: attempt.ReservationID, RequestID: attempt.RequestID,
		Limits: admission.Limits{RequestLimit: 10000, RequestWindow: time.Second, MaxConcurrent: 128},
	}
}

func fixtureMeterGrant(t *testing.T, store *admission.RedisCoordinator, attempt admission.UsageAttempt) {
	t.Helper()
	result, err := store.Admit(context.Background(), fixtureMeterRequest(attempt))
	if err != nil || result.Decision != admission.Allowed {
		t.Fatalf("cannot grant fixture attempt: %+v %v", result, err)
	}
}

func fixtureSettlement(t *testing.T, store *admission.RedisCoordinator, attempt admission.UsageAttempt, point *admission.UsageCheckpoint) admission.UsageTerminal {
	t.Helper()
	ctx := context.Background()
	pins := admission.UsagePins{Model: "test-model"}
	if err := store.BeginUsageDispatch(ctx, attempt, pins); err != nil {
		t.Fatal(err)
	}
	if point != nil {
		if err := store.CheckpointUsage(ctx, attempt, *point); err != nil {
			t.Fatal(err)
		}
	}
	row, err := store.FinalizeUsage(ctx, attempt, pins, "completed", true)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func fixtureCorrection(attempt admission.UsageAttempt, version int, sequence, prompt, output int64) admission.UsageCorrection {
	return admission.UsageCorrection{
		UsageAttempt: attempt, ExpectedVersion: version, EvidenceSHA256: strings.Repeat("b", 64),
		Reason: "verified_engine_usage",
		Checkpoint: admission.UsageCheckpoint{Sequence: sequence, Runtime: &admission.UsageTokens{
			Prompt: prompt, Completion: output,
		}},
	}
}

func TestMeterLateReconciliation(t *testing.T) {
	one, two, client := meterCoordinators(t)
	ctx := context.Background()
	first := fixtureMeterAttempt("tenant-one", newID("rsv"), newID("owner"))
	second := fixtureMeterAttempt("tenant-two", newID("rsv"), newID("owner"))
	fixtureMeterGrant(t, one, first)
	fixtureMeterGrant(t, two, second)
	pins := admission.UsagePins{Model: "test-model"}
	if err := one.BeginUsageDispatch(ctx, first, pins); err != nil {
		t.Fatal(err)
	}
	point := admission.UsageCheckpoint{Sequence: 2, Runtime: &admission.UsageTokens{Prompt: 12, Completion: 2}}
	if err := one.CheckpointUsage(ctx, first, point); err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []int64{1, 2} {
		stale := admission.UsageCheckpoint{Sequence: sequence, Runtime: &admission.UsageTokens{Prompt: 99, Completion: 99}}
		if err := two.CheckpointUsage(ctx, first, stale); !errors.Is(err, admission.ErrUsageConflict) {
			t.Fatalf("stale or conflicting checkpoint accepted: %v", err)
		}
	}
	original, err := one.FinalizeUsage(ctx, first, pins, "completed", true)
	if err != nil {
		t.Fatal(err)
	}
	fixtureSettlement(t, two, second, nil)

	firstKey, secondKey := first.TenantID+":"+first.ReservationID, second.TenantID+":"+second.ReservationID
	// Offset each stored deadline relative to Redis TIME. The production
	// arrival clock and the 24-hour comparison remain unchanged.
	shiftUsageDeadline(t, client, one, firstKey, -24*time.Hour+time.Minute, false)
	early := fixtureCorrection(first, 1, 3, 14, 3)
	version2, err := two.CorrectUsage(ctx, early)
	if err != nil || version2.Version != 2 || version2.Correction == nil || version2.AdmissionDeadlineUnixMS == nil ||
		version2.Correction.ArrivalUnixMS > *version2.AdmissionDeadlineUnixMS+(24*time.Hour).Milliseconds() ||
		!reflect.DeepEqual(version2.History, []admission.UsageTerminal{original}) {
		t.Fatalf("correction on the open side: %+v %v", version2, err)
	}
	replay, err := one.CorrectUsage(ctx, early)
	if err != nil || !reflect.DeepEqual(replay, version2) {
		t.Fatalf("correction replay: %+v %v", replay, err)
	}
	conflict := fixtureCorrection(first, 1, 3, 99, 4)
	if _, err := one.CorrectUsage(ctx, conflict); !errors.Is(err, admission.ErrUsageConflict) {
		t.Fatalf("conflicting prior version accepted: %v", err)
	}
	next := fixtureCorrection(first, 2, 4, 15, 4)
	next.Reason = "verified_usage_recount"
	version3, err := one.CorrectUsage(ctx, next)
	version2.History = nil
	if err != nil || version3.Version != 3 || version3.Correction == nil ||
		version3.Correction.Reason != next.Reason ||
		!reflect.DeepEqual(version3.History, []admission.UsageTerminal{original, version2}) {
		t.Fatalf("history and reason at version 3: %+v %v", version3, err)
	}

	shiftUsageDeadline(t, client, one, secondKey, -24*time.Hour-time.Minute, false)
	late := fixtureCorrection(second, 1, 1, 19, 5)
	if _, err := two.CorrectUsage(ctx, late); !errors.Is(err, admission.ErrUsageWindowClosed) {
		t.Fatalf("correction on the closed side: %v", err)
	}
	a := meterReport(t, one)
	b := meterReport(t, two)
	// Independent fixture expectations at the admission identity boundary.
	want := map[string]admission.UsageTotals{
		first.TenantID: {
			Prompt:        admission.UsageFieldTotals{ExactTokens: 15, ExactRows: 1},
			Completion:    admission.UsageFieldTotals{ExactTokens: 4, ExactRows: 1},
			Discrepancies: 3,
		},
		second.TenantID: {
			Prompt:        admission.UsageFieldTotals{UnknownRows: 1},
			Completion:    admission.UsageFieldTotals{UnknownRows: 1},
			Discrepancies: 1,
		},
	}
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a.Totals, want) ||
		a.Admitted != 2 || a.Terminal != 2 || len(a.Rows) != 2 ||
		a.Rows[0].UsageAttempt != first || a.Rows[1].UsageAttempt != second ||
		a.Rows[1].Version != 1 {
		t.Fatalf("independent admission cohort and replayed totals differ: %+v", a)
	}

	archive, digest, err := one.ExportUsageCohort(ctx, 128)
	if err != nil || len(archive) == 0 {
		t.Fatalf("cohort export: %v", err)
	}
	changed := late
	changed.Checkpoint.Runtime = &admission.UsageTokens{Prompt: 20, Completion: 5}
	if _, err := two.CorrectUsage(ctx, changed); !errors.Is(err, admission.ErrUsageWindowClosed) {
		t.Fatalf("second late arrival: %v", err)
	}
	if _, err := two.RetireUsageCohort(ctx, archive, digest); !errors.Is(err, admission.ErrUsageConflict) {
		t.Fatalf("stale export did not fence retirement: %v", err)
	}
	archive, digest, err = one.ExportUsageCohort(ctx, 128)
	if err != nil || len(archive) == 0 {
		t.Fatalf("re-export including late arrival: %v", err)
	}
	checkExportedUsage(t, archive, secondKey, 1, 2)
	if _, err := two.RetireUsageCohort(ctx, archive, strings.Repeat("e", 64)); !errors.Is(err, admission.ErrUsageBinding) {
		t.Fatalf("wrong archive digest did not refuse: %v", err)
	}
	path := filepath.Join(t.TempDir(), "cohort.json")
	if err := os.WriteFile(path, archive, 0600); err != nil {
		t.Fatal(err)
	}
	retrieved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := two.RetireUsageCohort(ctx, retrieved, digest); err != nil || n != 1 {
		t.Fatalf("verified cohort retirement: %d %v", n, err)
	}
	// Remove the old lease and ordinary release tombstone to isolate the
	// permanent retired identity fence from the short-lived reservation state.
	if err := two.Release(ctx, second.TenantID, second.ReservationID); err != nil {
		t.Fatal(err)
	}
	prefix := strings.TrimSuffix(two.CredentialKey(""), "credential:")
	if err := client.Del(ctx, prefix+"tenant:"+second.TenantID+":reservation:"+second.ReservationID).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := one.Admit(ctx, fixtureMeterRequest(second)); !errors.Is(err, admission.ErrReservationReleased) {
		t.Fatalf("retired key reopened admission: %v", err)
	}
	if _, err := one.CorrectUsage(ctx, late); !errors.Is(err, admission.ErrUsageWindowClosed) {
		t.Fatalf("retired cohort accepted a correction: %v", err)
	}
	post, postDigest, err := two.ExportUsageCohort(ctx, 128)
	if err != nil || len(post) == 0 {
		t.Fatalf("post-retirement exceptions export: %v", err)
	}
	checkExportedUsage(t, post, "", 0, 2)
	if n, err := two.RetireUsageCohort(ctx, post, postDigest); err != nil || n != 0 {
		t.Fatalf("archiving post-retirement exceptions: %d %v", n, err)
	}
	active := meterReport(t, one)
	if active.Admitted != 1 || active.Terminal != 1 || !reflect.DeepEqual(active.Totals[first.TenantID], want[first.TenantID]) {
		t.Fatalf("retirement altered the other tenant: %+v", active)
	}
	shiftUsageDeadline(t, client, one, firstKey, -24*time.Hour-time.Minute, false)
	correctedArchive, correctedDigest, err := one.ExportUsageCohort(ctx, 1)
	if err != nil || len(correctedArchive) == 0 {
		t.Fatalf("corrected history export: %v", err)
	}
	checkExportedUsage(t, correctedArchive, firstKey, 2, 3)
	var export admission.UsageArchive
	var journal [][][]string
	var archived admission.UsageTerminal
	if json.Unmarshal(correctedArchive, &export) != nil || json.Unmarshal([]byte(export.Journal), &journal) != nil ||
		json.Unmarshal([]byte(journal[0][0][5]), &archived) != nil || !reflect.DeepEqual(archived, version3) {
		t.Fatalf("export did not retain corrected history: %+v", archived)
	}
	if n, err := one.RetireUsageCohort(ctx, correctedArchive, correctedDigest); err != nil || n != 1 {
		t.Fatalf("corrected cohort retirement: %d %v", n, err)
	}
}

func checkExportedUsage(t *testing.T, data []byte, key string, eventCount, discrepancyCount int) {
	t.Helper()
	var archive admission.UsageArchive
	var journal [][][]string
	if json.Unmarshal(data, &archive) != nil || json.Unmarshal([]byte(archive.Journal), &journal) != nil ||
		len(journal) != 3 || len(journal[1]) != eventCount || len(journal[2]) != discrepancyCount {
		t.Fatalf("archive omits expected journal material: %+v", journal)
	}
	wantRows := 0
	if key != "" {
		wantRows = 1
	}
	if len(journal[0]) != wantRows || (wantRows == 1 && journal[0][0][0] != key) {
		t.Fatalf("archive retired the wrong cohort: %+v", journal)
	}
}

func TestMeterIsolationAndStoreFailure(t *testing.T) {
	r := newPersistedMeterRedis(t)
	config := crashMeterConfig(newID("isolation"))
	one := meterStore(t, r.client, config)
	two := meterStore(t, r.client, config)
	ctx := context.Background()
	suffix, owner := newID("rsv"), newID("owner")
	a, b := fixtureMeterAttempt("tenant-one", suffix, owner), fixtureMeterAttempt("tenant-two", suffix, owner)
	point := admission.UsageCheckpoint{Sequence: 1, Runtime: &admission.UsageTokens{Prompt: 5, Completion: 2}}
	for _, attempt := range []admission.UsageAttempt{a, b} {
		fixtureMeterGrant(t, one, attempt)
		fixtureSettlement(t, two, attempt, &point)
		if err := one.Release(ctx, attempt.TenantID, attempt.ReservationID); err != nil {
			t.Fatal(err)
		}
		point.Runtime = &admission.UsageTokens{Prompt: 8, Completion: 3}
	}
	before := meterReport(t, one)
	if before.Admitted != 2 || before.Terminal != 2 ||
		before.Totals[a.TenantID].Prompt.ExactTokens != 5 || before.Totals[b.TenantID].Prompt.ExactTokens != 8 {
		t.Fatalf("cross-tenant shared suffix changed totals: %+v", before)
	}
	var dispatches atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			dispatches.Add(1)
		}
		streamHandler(contentEvent+finishEvent+usageEvent+doneEvent)(w, r)
	})
	gatewayConfig := DefaultConfig()
	gatewayConfig.ReleaseTimeout = 50 * time.Millisecond
	_, replica1 := newTestGatewayWithAdmission(t, gatewayConfig, nil, testTenantRegistry(t), one, backend)
	_, replica2 := newTestGatewayWithAdmission(t, gatewayConfig, nil, testTenantRegistry(t), two, backend)
	dockerMeter(t, "stop", "--time", "1", r.name)
	for _, gateway := range []string{replica1.URL, replica2.URL} {
		if status := managedRequest(t, gateway, testCredential, managedBody); status != 503 {
			t.Fatalf("Redis outage status %d", status)
		}
	}
	if n := dispatches.Load(); n != 0 {
		t.Fatalf("failed durable admissions contacted the backend %d times", n)
	}
	dockerMeter(t, "start", r.name)
	r.ready(t)
	wrong := fixtureCorrection(a, 1, 2, 99, 99)
	wrong.RequestID = b.RequestID
	if _, err := two.CorrectUsage(ctx, wrong); !errors.Is(err, admission.ErrUsageBinding) {
		t.Fatalf("cross-tenant correction accepted: %v", err)
	}
	if after := meterReport(t, two); !reflect.DeepEqual(after, before) {
		t.Fatalf("durable rows or totals changed across outage: %+v", after)
	}
}
