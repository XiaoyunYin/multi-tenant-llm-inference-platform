package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
	"multi-tenant-llm-inference-platform/internal/admission"
)

type discoveryRaceCoordinator struct {
	admission.Coordinator
	after func()
	calls atomic.Int64
}

func (c *discoveryRaceCoordinator) Admit(ctx context.Context, r admission.Request) (admission.Result, error) {
	c.calls.Add(1)
	result, err := c.Coordinator.Admit(ctx, r)
	if err == nil && result.Decision == admission.Allowed && c.after != nil {
		c.after()
	}
	return result, err
}

func TestRedisDiscoveryUnknownAdmissionAccounting(t *testing.T) {
	address := os.Getenv("REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("REDIS_TEST_ADDR is not set")
	}
	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: address, Protocol: 2, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	namespace := fmt.Sprintf("gateway-test:%x", time.Now().UnixNano())
	prefix := namespace + ":{admission}:"
	t.Cleanup(func() {
		keys, err := client.Keys(ctx, namespace+":*").Result()
		if err == nil && len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	})
	coordinator, err := admission.NewRedisCoordinator(client, admission.RedisConfig{Namespace: namespace, GlobalCapacity: 16, LeaseDuration: time.Minute, TombstoneTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &discoveryRaceCoordinator{Coordinator: coordinator}
	var contacts atomic.Int64
	tenants, err := NewTenantRegistry([]TenantSpec{{TenantID: "tenant-test", CredentialSHA256: CredentialSHA256(testCredential), Models: []string{"test-model"}, MaxRequestBytes: 1 << 20, MaxOutputTokens: 128, RequestRateLimit: 10000, RateWindowMS: 60000, MaxConcurrent: 128}}, testCacheSaltSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	g, server := newTestGatewayWithAdmission(t, DefaultConfig(), nil, tenants, wrapped, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		contacts.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, roleEvent+finishEvent+usageEvent+doneEvent)
	}))
	// Keep real nonempty rate/concurrency keys, so an accidental release/renewal
	// or increment is detectable, rather than just comparing missing keys.
	seed := admission.Request{TenantID: "tenant-test", ReservationID: "rsv_00000000000000000000000000000001", Limits: admission.Limits{RequestLimit: 10000, RequestWindow: time.Minute, MaxConcurrent: 128}}
	got, err := coordinator.Admit(ctx, seed)
	if err != nil || got.Decision != admission.Allowed {
		t.Fatalf("seed: %+v %v", got, err)
	}
	dump := func() []string {
		t.Helper()
		var values []string
		for _, key := range []string{prefix + "tenant:tenant-test:rate", prefix + "tenant:tenant-test:active", prefix + "global:active"} {
			value, err := client.Dump(ctx, key).Result()
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, value)
		}
		return values
	}
	before := dump()
	g.registry.replaceMembership(nil, true)
	const count = 8
	for range count {
		response := requestGateway(t, server.Client(), server.URL)
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusServiceUnavailable || !containsBytes(body, "discovery_unknown") || containsBytes(body, "after_admit") {
			t.Fatalf("pre-admit: %d %s", response.StatusCode, body)
		}
	}
	if !reflect.DeepEqual(before, dump()) || wrapped.calls.Load() != 0 || contacts.Load() != 0 {
		t.Fatal("pre-admit unknown changed Redis or called Admit/upstream")
	}
	if g.Metrics().DiscoveryUnknown != count || g.Metrics().DiscoveryUnknownAfterAdmit != 0 {
		t.Fatalf("pre-admit counts: %+v", g.Metrics())
	}
	t.Logf("N=%d code=discovery_unknown Admit=0 rate/tenant-active/global-active DUMP byte-identical", count)
	// Recreate a known eligible membership, then deterministically lose it inside
	// Admit after Redis commits but before the handler gets its successful reply.
	backend, _ := NewBackend("race", "http://127.0.0.1:1", "uid-new")
	g.registry.ReplaceBackends([]*Backend{backend})
	backend.healthy.Store(true)
	backend.ready.Store(true)
	wrapped.after = func() { g.registry.replaceMembership(nil, true) }
	response := requestGateway(t, server.Client(), server.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || !containsBytes(body, "discovery_unknown_after_admit") || containsBytes(body, "no_healthy_backend") {
		t.Fatalf("post-admit: %d %s", response.StatusCode, body)
	}
	if client.Get(ctx, prefix+"tenant:tenant-test:rate").Val() != "2" || client.ZCard(ctx, prefix+"tenant:tenant-test:active").Val() != 1 || client.ZCard(ctx, prefix+"global:active").Val() != 1 || contacts.Load() != 0 {
		t.Fatal("post-admit rate entry refunded, concurrency leaked or upstream called")
	}
	snapshot := g.Metrics()
	if snapshot.DiscoveryUnknown != count || snapshot.DiscoveryUnknownAfterAdmit != 1 || wrapped.calls.Load() != 1 {
		t.Fatalf("counts by code: %+v", snapshot)
	}
	t.Log("code=discovery_unknown_after_admit count=1 rate=2 (seed+attempt); tenant-active=1 global-active=1 (seed only); no_healthy_backend=0")
	if err := coordinator.Release(ctx, seed.TenantID, seed.ReservationID); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryCapacityReportUnknownKnownZeroAndHealthFreshness(t *testing.T) {
	registry, err := NewDiscoveryRegistry(&http.Client{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var counts []int64
	var states []bool
	registry.SetCapacityReporter(func(_ context.Context, n int64, known bool) error {
		counts = append(counts, n)
		states = append(states, known)
		return nil
	})
	report := func() {
		t.Helper()
		if err := registry.ReportCapacity(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	report() // starts unknown
	registry.ReplaceBackends(nil)
	report() // real known zero
	b, _ := NewBackend("slot", "http://127.0.0.1:1", "uid-a")
	registry.ReplaceBackends([]*Backend{b})
	b.healthy.Store(true)
	b.ready.Store(true)
	report() // no independent health sample: withhold, not known zero
	b.checked.Store(time.Now().UnixNano())
	report()
	b.checked.Store(time.Now().Add(-registry.HealthFreshnessWindow() - time.Second).UnixNano())
	report()
	registry.replaceMembership(nil, true)
	report()
	if !reflect.DeepEqual(counts, []int64{0, 0, 0, 1, 0, 0}) || !reflect.DeepEqual(states, []bool{false, true, false, true, true, false}) {
		t.Fatalf("counts=%v known=%v", counts, states)
	}
	if registry.CanDispatch(b) {
		t.Fatal("unknown routed stale pointer")
	}
	newUID, _ := NewBackend("slot", "http://127.0.0.1:1", "uid-b")
	registry.ReplaceBackends([]*Backend{newUID})
	if registry.CanDispatch(b) || newUID.checked.Load() != 0 || newUID.Healthy() {
		t.Fatal("reused IP inherited old UID health or routed old pointer")
	}
}

func TestUnknownClosesRoutingDuringInFlightReport(t *testing.T) {
	b, _ := NewBackend("slot", "http://127.0.0.1:1", "uid-a")
	r, _ := NewRegistry([]*Backend{b}, &http.Client{}, time.Second)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r.SetCapacityReporter(func(context.Context, int64, bool) error { close(entered); <-release; return nil })
	go func() { _ = r.ReportCapacity(context.Background()); close(done) }()
	<-entered
	cleared := make(chan struct{})
	go func() { r.replaceMembership(nil, true); close(cleared) }()
	deadline := time.After(time.Second)
	for !r.DiscoveryUnknown() {
		select {
		case <-deadline:
			close(release)
			t.Fatal("unknown blocked on publication")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if r.CanDispatch(b) || len(r.Backends()) != 0 {
		close(release)
		t.Fatal("pending report retained routes")
	}
	close(release)
	<-done
	<-cleared
}
