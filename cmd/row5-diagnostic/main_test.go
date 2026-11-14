package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
	"multi-tenant-llm-inference-platform/internal/admission"
)

func TestExecuteUsesProductionAdmissionAndReleases(t *testing.T) {
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("REDIS_TEST_ADDR missing")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, Protocol: 2, MaxRetries: -1})
	defer client.Close()
	ctx := context.Background()
	ns := fmt.Sprintf("diagcli:%x", time.Now().UnixNano())
	t.Cleanup(func() {
		keys, _ := client.Keys(ctx, ns+":*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	})
	cfg := config{Addr: "redis:6379", Namespace: ns, GlobalCapacity: 10, LeaseMS: 60000, TombstoneMS: 60000, Running: 4, Waiting: 1, TTLMS: 8000, HoldMS: 2000, Capture: true}
	gateway, err := admission.NewRedisCoordinator(client, admission.RedisConfig{MeasurementCapture: true, Namespace: ns, GlobalCapacity: 10, LeaseDuration: time.Minute, TombstoneTTL: time.Minute, DynamicCapacity: &admission.DynamicCapacityConfig{Running: 4, Waiting: 1, ReportTTL: 8 * time.Second, HoldDown: 2 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"gateway-0", "gateway-1"} {
		if err = gateway.ReportHealthy(ctx, id, 2, true); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(2100 * time.Millisecond)
	in := input{Config: cfg, Gateway0: cfg, Gateway1: cfg, DialAddr: addr, ReservationID: "rsv_d1a6" + strings.Repeat("a", 28)}
	out, err := execute(ctx, in)
	if err != nil || out.Decision != "allowed" || out.Capacity != 10 || !out.Released {
		t.Fatalf("receipt %+v: %v", out, err)
	}
	if n, err := client.ZCard(ctx, ns+":{admission}:global:active").Result(); err != nil || n != 0 {
		t.Fatalf("active=%d %v", n, err)
	}
	in.Gateway1.LeaseMS++
	if _, err = execute(ctx, in); err == nil || err.Error() != "row5:gateway_config_mismatch" {
		t.Fatalf("mismatch %v", err)
	}
	in.Gateway1 = cfg
	in.Config.LeaseMS = 0
	in.Gateway0 = in.Config
	in.Gateway1 = in.Config
	if _, err = execute(ctx, in); err == nil || err.Error() != "row5:invalid_duration" {
		t.Fatalf("duration %v", err)
	}
	in.Config = cfg
	in.Gateway0 = cfg
	in.Gateway1 = cfg
	in.ReservationID = "bad"
	if _, err = execute(ctx, in); !errors.Is(err, admission.ErrRow5DiagnosticID) {
		t.Fatalf("id %v", err)
	}
}

func TestExecuteRequiresDialAddrAndPreservesGatewayConfigEquality(t *testing.T) {
	cfg := config{Addr: "redis:6379"}
	in := input{Config: cfg, Gateway0: cfg, Gateway1: cfg}
	if _, err := execute(context.Background(), in); err == nil || err.Error() != "row5:invalid_dial_addr" {
		t.Fatalf("empty dial_addr error=%v", err)
	}
	in.DialAddr = "127.0.0.1:6379"
	in.Gateway1.Addr = "other-redis:6379"
	if _, err := execute(context.Background(), in); err == nil || err.Error() != "row5:gateway_config_mismatch" {
		t.Fatalf("gateway config mismatch error=%v", err)
	}
	in.Gateway1 = cfg
	for _, address := range []string{"bad host:6379", "bad_host:6379", "127.0.0.1:0"} {
		in.DialAddr = address
		if _, err := execute(context.Background(), in); err == nil || err.Error() != "row5:invalid_dial_addr" {
			t.Errorf("dial_addr %q error=%v", address, err)
		}
	}
}

type releaseFailure struct{}

func (releaseFailure) Admit(context.Context, string) (admission.Result, error) {
	return admission.Result{Decision: admission.Allowed, Capacity: 10}, nil
}
func (releaseFailure) Release(context.Context, string) error { return errors.New("connection lost") }
func TestExecuteRequestRefusesFailedRelease(t *testing.T) {
	result, err := executeRequest(context.Background(), releaseFailure{}, "rsv_d1a6"+strings.Repeat("1", 28))
	if err == nil || !strings.Contains(err.Error(), "row5:release_failed") || result.Released {
		t.Fatalf("receipt %+v error %v", result, err)
	}
}

func TestDecodeInputRejectsExtraUnknownAndOversize(t *testing.T) {
	for _, data := range []string{"{} {}", `{"unknown":1}`, strings.Repeat(" ", 16385), "{"} {
		if _, err := decodeInput(strings.NewReader(data)); err == nil || err.Error() != "row5:invalid_input" {
			t.Fatalf("input len=%d error=%v", len(data), err)
		}
	}
	if _, err := decodeInput(strings.NewReader("{}")); err != nil {
		t.Fatal(err)
	}
}

type admissionFailure struct{}

func (admissionFailure) Admit(context.Context, string) (admission.Result, error) {
	return admission.Result{}, errors.New("connection lost")
}
func (admissionFailure) Release(context.Context, string) error { panic("unexpected release") }
func TestExecuteRequestRetainsIdentityOnAmbiguousAdmit(t *testing.T) {
	id := "rsv_d1a6" + strings.Repeat("1", 28)
	result, err := executeRequest(context.Background(), admissionFailure{}, id)
	if err == nil || result.ReservationID != id || result.Decision != "unknown" || result.Released {
		t.Fatalf("receipt %+v error %v", result, err)
	}
}
