package admission

import (
	"context"
	"errors"
	"testing"
	"time"
)

func reservationID(value byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, 32)
	for index := range encoded {
		encoded[index] = digits[int(value)%len(digits)]
	}
	return "rsv_" + string(encoded)
}

func testRequest(tenant string, reservation byte) Request {
	return Request{
		TenantID: tenant, ReservationID: reservationID(reservation),
		Limits: Limits{RequestLimit: 2, RequestWindow: time.Second, MaxConcurrent: 1},
	}
}

func TestMemoryCoordinatorEnforcesAtomicLimitsAndIdempotency(t *testing.T) {
	coordinator, err := NewMemoryCoordinator(2)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(100, 0)
	coordinator.now = func() time.Time { return clock }
	ctx := context.Background()

	first := testRequest("tenant-a", 1)
	result, err := coordinator.Admit(ctx, first)
	if err != nil || result.Decision != Allowed || result.Idempotent {
		t.Fatalf("first admission mismatch: %+v %v", result, err)
	}
	result, err = coordinator.Admit(ctx, first)
	if err != nil || result.Decision != Allowed || !result.Idempotent {
		t.Fatalf("idempotent admission mismatch: %+v %v", result, err)
	}
	second := testRequest("tenant-a", 2)
	result, err = coordinator.Admit(ctx, second)
	if err != nil || result.Decision != TenantConcurrencyLimited {
		t.Fatalf("tenant concurrency mismatch: %+v %v", result, err)
	}
	if err := coordinator.Release(ctx, first.TenantID, first.ReservationID); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Release(ctx, first.TenantID, first.ReservationID); err != nil {
		t.Fatalf("duplicate release failed: %v", err)
	}
	if _, err := coordinator.Admit(ctx, first); !errors.Is(err, ErrReservationReleased) {
		t.Fatalf("release tombstone did not block delayed admission: %v", err)
	}
	result, err = coordinator.Admit(ctx, second)
	if err != nil || result.Decision != Allowed {
		t.Fatalf("released capacity was not reusable: %+v %v", result, err)
	}
	if err := coordinator.Release(ctx, second.TenantID, second.ReservationID); err != nil {
		t.Fatal(err)
	}
	third := testRequest("tenant-a", 3)
	result, err = coordinator.Admit(ctx, third)
	if err != nil || result.Decision != TenantRateLimited || result.RetryAfter != time.Second {
		t.Fatalf("fixed-window rate mismatch: %+v %v", result, err)
	}
	clock = clock.Add(time.Second)
	result, err = coordinator.Admit(ctx, third)
	if err != nil || result.Decision != Allowed {
		t.Fatalf("rate window did not reset: %+v %v", result, err)
	}
}

func TestMemoryCoordinatorSharesGlobalCapacityAndScopesReservations(t *testing.T) {
	coordinator, _ := NewMemoryCoordinator(1)
	ctx := context.Background()
	first := testRequest("tenant-a", 1)
	second := testRequest("tenant-b", 2)
	if result, err := coordinator.Admit(ctx, first); err != nil || result.Decision != Allowed {
		t.Fatalf("first admission mismatch: %+v %v", result, err)
	}
	if result, err := coordinator.Admit(ctx, second); err != nil || result.Decision != SystemCapacityLimited {
		t.Fatalf("global capacity mismatch: %+v %v", result, err)
	}
	if err := coordinator.Release(ctx, "tenant-b", first.ReservationID); err != nil {
		t.Fatal(err)
	}
	if result, err := coordinator.Admit(ctx, second); err != nil || result.Decision != SystemCapacityLimited {
		t.Fatalf("cross-tenant release freed another tenant: %+v %v", result, err)
	}
	if err := coordinator.Release(ctx, first.TenantID, first.ReservationID); err != nil {
		t.Fatal(err)
	}
	if result, err := coordinator.Admit(ctx, second); err != nil || result.Decision != Allowed {
		t.Fatalf("valid release did not free global capacity: %+v %v", result, err)
	}
}

func TestAdmissionValidationAndResponseParsingFailClosed(t *testing.T) {
	valid := testRequest("tenant-a", 1)
	invalid := []Request{
		{TenantID: "bad tenant", ReservationID: valid.ReservationID, Limits: valid.Limits},
		{TenantID: valid.TenantID, ReservationID: "client-value", Limits: valid.Limits},
		{TenantID: valid.TenantID, ReservationID: valid.ReservationID, Limits: Limits{}},
	}
	for _, request := range invalid {
		if err := validateRequest(request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
	for _, response := range []any{
		nil, "allowed", []any{"allowed"}, []any{"allowed", int64(0)},
		[]any{int64(1), int64(0), int64(0)}, []any{"unknown", int64(0), int64(0)},
		[]any{"allowed", int64(0), int64(2)}, []any{"allowed", int64(1 << 62), int64(0)},
	} {
		if _, err := parseAdmissionResult(response); err == nil {
			t.Fatalf("invalid response accepted: %#v", response)
		}
	}
	result, err := parseAdmissionResult([]any{"allowed", int64(0), int64(1)})
	if err != nil || result.Decision != Allowed || !result.Idempotent {
		t.Fatalf("valid response rejected: %+v %v", result, err)
	}
}
