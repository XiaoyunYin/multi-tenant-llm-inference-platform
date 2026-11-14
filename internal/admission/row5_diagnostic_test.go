package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRow5DiagnosticUsesProductionCoordinatorAndIsolatedRateKey(t *testing.T) {
	client := redisIntegrationClient(t)
	ctx := context.Background()
	ns := fmt.Sprintf("row5test:%x", time.Now().UnixNano())
	cfg := RedisConfig{Namespace: ns, GlobalCapacity: 10, LeaseDuration: time.Minute, TombstoneTTL: time.Minute,
		MeasurementCapture: true, DynamicCapacity: &DynamicCapacityConfig{Running: 4, Waiting: 1, ReportTTL: 8 * time.Second, HoldDown: 2 * time.Second}}
	t.Cleanup(func() {
		keys, _ := client.Keys(ctx, ns+":*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	})
	c, err := NewRedisCoordinator(client, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.ReportHealthy(ctx, "gateway-0", 2, true); err != nil {
		t.Fatal(err)
	}
	if err = c.ReportHealthy(ctx, "gateway-1", 2, true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond) // Allow the real Lua increase hold to elapse.
	d, err := NewRow5Diagnostic(c, cfg)
	if err != nil {
		t.Fatal(err)
	}
	id := "rsv_d1a6" + strings.Repeat("1", 28)
	result, err := d.Admit(ctx, id)
	if err != nil || result.Decision != Allowed || result.Capacity != 10 {
		t.Fatalf("admit: %+v %v", result, err)
	}
	if err = d.Release(ctx, id); err != nil {
		t.Fatal(err)
	}
	prefix := ns + ":{admission}:"
	if n, err := client.Get(ctx, prefix+"tenant:row5-diagnostic:rate").Int64(); err != nil || n != 1 {
		t.Fatalf("diagnostic rate=%d err=%v", n, err)
	}
	if n, err := client.Exists(ctx, prefix+"tenant:measured:rate").Result(); err != nil || n != 0 {
		t.Fatalf("measured rate=%d err=%v", n, err)
	}
	if n, err := client.ZCard(ctx, prefix+"global:active").Result(); err != nil || n != 0 {
		t.Fatalf("active=%d err=%v", n, err)
	}
	rows, err := client.XRange(ctx, prefix+"global:active:capture", "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.Values["event"] == "admit" && row.Values["reservation_id"] == id {
			found = true
			if row.Values["gateway_uid"] != "" {
				t.Fatalf("gateway_uid=%v", row.Values["gateway_uid"])
			}
		}
	}
	if !found {
		t.Fatal("missing capture")
	}
	if _, err = d.Admit(ctx, "rsv_"+strings.Repeat("0", 32)); !errors.Is(err, ErrRow5DiagnosticID) {
		t.Fatalf("invalid ID: %v", err)
	}
	if err = d.Release(ctx, "bad"); !errors.Is(err, ErrRow5DiagnosticID) {
		t.Fatalf("invalid release: %v", err)
	}
	mismatch := cfg
	mismatch.LeaseDuration = 2 * time.Minute
	if _, err = NewRow5Diagnostic(c, mismatch); !errors.Is(err, ErrRow5DiagnosticConfig) {
		t.Fatalf("configuration: %v", err)
	}
	otherCfg := cfg
	otherCfg.TombstoneTTL = 2 * time.Minute
	other, err := NewRedisCoordinator(client, otherCfg)
	if err != nil {
		t.Fatal(err)
	}
	otherDiagnostic, err := NewRow5Diagnostic(other, otherCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = otherDiagnostic.Admit(ctx, "rsv_d1a6"+strings.Repeat("2", 28)); !errors.Is(err, ErrConfigurationMismatch) {
		t.Fatalf("redis config mismatch: %v", err)
	}
}
