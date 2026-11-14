package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
	"multi-tenant-llm-inference-platform/internal/admission"
)

func TestRedisDiscoveryStartAndRecoveryWithholdUnsampled(t *testing.T) {
	address := os.Getenv("REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("REDIS_TEST_ADDR is not set")
	}
	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: address, Protocol: 2, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	namespace := fmt.Sprintf("gateway-recovery:%x", time.Now().UnixNano())
	t.Cleanup(func() {
		keys := client.Keys(ctx, namespace+":*").Val()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	})
	coordinator, err := admission.NewRedisCoordinator(client, admission.RedisConfig{Namespace: namespace, GlobalCapacity: 99, LeaseDuration: time.Minute, TombstoneTTL: time.Minute, DynamicCapacity: &admission.DynamicCapacityConfig{Running: 2, Waiting: 1, ReportTTL: time.Second, HoldDown: 40 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	var unhealthy atomic.Bool
	var unready atomic.Bool
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if unhealthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		fmt.Fprintf(w, `{"healthy":true,"ready":%v}`, !unready.Load())
	}))
	defer health.Close()
	// Discovery still validates real Pod IPs; only the health socket is directed
	// to the local fixture. Poll, HTTP checks, registry and Redis are production.
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, health.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	healthClient := &http.Client{Transport: transport}
	payload := slicePayload(podEndpoint("fake-0", "uid-a", "10.0.0.2", true, false), podEndpoint("fake-1", "uid-b", "10.0.0.3", true, false))
	status := http.StatusOK
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status); fmt.Fprint(w, payload) }))
	defer api.Close()
	type publication struct {
		n     int64
		known bool
	}
	last := make(map[string]publication)
	newGateway := func(id string) (*Registry, *EndpointSliceDiscovery) {
		t.Helper()
		r, _ := NewDiscoveryRegistry(healthClient, 250*time.Millisecond)
		r.SetCapacityReporter(func(ctx context.Context, n int64, known bool) error {
			last[id] = publication{n, known}
			if known && n == 0 && status == http.StatusOK && strings.Contains(payload, "uid-a") && !unhealthy.Load() {
				t.Errorf("gateway %s published synthetic known zero before health samples", id)
			}
			t.Logf("gateway=%s report N=%d known=%v", id, n, known)
			return coordinator.ReportHealthy(ctx, id, n, known)
		})
		d, err := NewEndpointSliceDiscovery(DiscoveryConfig{"test", "fake", 250 * time.Millisecond}, r, api.Client(), api.URL, func() (string, error) { return "token", nil }, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r, d
	}
	b, db := newGateway("b")
	if err := db.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	b.Poll(ctx)
	time.Sleep(60 * time.Millisecond)
	var serial int
	probe := func(phase string, want int64, code string) {
		t.Helper()
		// The unaffected gateway keeps its independently sampled view fresh.
		b.Poll(ctx)
		serial++
		request := admission.Request{TenantID: "recovery", ReservationID: fmt.Sprintf("rsv_%032x", serial), Limits: admission.Limits{RequestLimit: 1000, RequestWindow: time.Minute, MaxConcurrent: 100}}
		got, err := coordinator.Admit(ctx, request)
		if err != nil || got.Capacity != want || got.Decision.Code() != code {
			t.Fatalf("%s: B=%d code=%s err=%v; want B=%d/%s", phase, got.Capacity, got.Decision.Code(), err, want, code)
		}
		if got.Decision == admission.Allowed {
			if err := coordinator.Release(ctx, request.TenantID, request.ReservationID); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%s B=%d code=%s", phase, got.Capacity, got.Decision.Code())
	}
	probe("other gateway steady", 6, "allowed")
	a, da := newGateway("a")
	wrapped := &discoveryRaceCoordinator{Coordinator: coordinator}
	g, gatewayServer := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), wrapped, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unsampled request dispatched") }))
	g.registry = a
	checkLocalGate := func() {
		t.Helper()
		response := requestGateway(t, gatewayServer.Client(), gatewayServer.URL)
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 503 || !containsBytes(body, "discovery_unknown") || containsBytes(body, "after_admit") || wrapped.calls.Load() != 0 {
			t.Fatalf("unsampled gate: status=%d body=%s Admit calls=%d", response.StatusCode, body, wrapped.calls.Load())
		}
	}
	sample := func(phase string) {
		t.Helper()
		members := a.Backends()
		if len(members) != 2 || !a.DiscoveryUnknown() || members[0].checked.Load() != 0 || members[1].checked.Load() != 0 {
			t.Fatal("membership inherited health or opened unsampled gate")
		}
		// A completed unhealthy sample alone must not open partial recovery.
		unhealthy.Store(true)
		a.check(ctx, members[0])
		unhealthy.Store(false)
		if !a.DiscoveryUnknown() || a.CanDispatch(members[0]) {
			t.Fatal("partial unhealthy sample opened gate")
		}
		checkLocalGate()
		// Healthy alone is insufficient while the other member is unsampled.
		unready.Store(true)
		a.check(ctx, members[0])
		unready.Store(false)
		if !a.DiscoveryUnknown() || a.CanDispatch(members[0]) {
			t.Fatal("partial healthy-but-unready sample opened gate")
		}
		checkLocalGate()
		a.check(ctx, members[0])
		if err := a.ReportCapacity(ctx); err != nil {
			t.Fatal(err)
		}
		if a.DiscoveryUnknown() || !a.CanDispatch(members[0]) || last["a"].known {
			t.Fatal("partial healthy sample must open local gate while withholding report")
		}
		probe(phase+" partial samples", 6, "allowed")
		a.check(ctx, members[1])
		if err := a.ReportCapacity(ctx); err != nil {
			t.Fatal(err)
		}
		if a.DiscoveryUnknown() {
			t.Fatal("gate stayed closed after all completed samples")
		}
		if last["a"] != (publication{2, true}) {
			t.Fatalf("sampled count: %+v", last["a"])
		}
		probe(phase+" all sampled", 6, "allowed")
	}
	if err := da.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	checkLocalGate()
	probe("gateway start unsampled", 6, "allowed")
	sample("start")
	status = http.StatusForbidden
	if err := da.Poll(ctx); err == nil {
		t.Fatal("failed poll accepted")
	}
	if len(a.Backends()) != 0 {
		t.Fatal("unknown retained routes")
	}
	probe("one failed poll", 6, "allowed")
	status = http.StatusOK
	if err := da.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	checkLocalGate()
	probe("recovery unsampled", 6, "allowed")
	sample("recovery")
	payload = slicePayload()
	if err := da.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if a.DiscoveryUnknown() {
		t.Fatal("known empty treated as unknown")
	}
	if last["a"] != (publication{0, true}) {
		t.Fatalf("empty count: %+v", last["a"])
	}
	probe("known empty real zero", 0, "system_capacity")
	payload = slicePayload(podEndpoint("fake-0", "uid-a", "10.0.0.2", true, false), podEndpoint("fake-1", "uid-b", "10.0.0.3", true, false))
	unhealthy.Store(true)
	if err := da.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	a.Poll(ctx)
	if a.DiscoveryUnknown() {
		t.Fatal("completed unhealthy samples treated as unknown")
	}
	if last["a"] != (publication{0, true}) {
		t.Fatalf("unhealthy count: %+v", last["a"])
	}
	probe("completed unhealthy real zero", 0, "system_capacity")
}

func TestHealthHungPeerDoesNotStaleHealthyReplica(t *testing.T) {
	for _, discovery := range []bool{false, true} {
		for _, hungFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("discovery=%v/hungFirst=%v", discovery, hungFirst), func(t *testing.T) {
				hung := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
				defer hung.Close()
				healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{}`) }))
				defer healthy.Close()
				x, _ := NewBackend("hung", hung.URL)
				y, _ := NewBackend("healthy", healthy.URL)
				members := []*Backend{y, x}
				if hungFirst {
					members = []*Backend{x, y}
				}
				interval := 500 * time.Millisecond
				var r *Registry
				if discovery {
					interval = 250 * time.Millisecond
					r, _ = NewDiscoveryRegistry(&http.Client{}, interval)
					r.ReplaceBackends(members)
				} else {
					r, _ = NewRegistry(members, &http.Client{}, interval)
				}
				var mu sync.Mutex
				knownReports := 0
				var maxAge time.Duration
				r.SetCapacityReporter(func(_ context.Context, n int64, known bool) error {
					mu.Lock()
					defer mu.Unlock()
					if known {
						knownReports++
						age := time.Since(time.Unix(0, y.checked.Load()))
						maxAge = max(maxAge, age)
						if n != 1 {
							t.Errorf("known N=%d want1; healthy age=%s bound=%s", n, age, r.HealthFreshnessWindow())
						}
					}
					return nil
				})
				r.Start(context.Background())
				// Publish during checks as discovery does, as well as at batch end.
				deadline := time.Now().Add(2500 * time.Millisecond)
				for time.Now().Before(deadline) {
					time.Sleep(25 * time.Millisecond)
					if err := r.ReportCapacity(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				r.Close()
				mu.Lock()
				if knownReports < 10 {
					t.Fatalf("too few known reports: %d", knownReports)
				}
				t.Logf("known reports=%d all N=1; max healthy age=%s registered bound=%s", knownReports, maxAge, r.HealthFreshnessWindow())
				// A genuinely stale completed sample is still excluded.
				y.checked.Store(time.Now().Add(-r.HealthFreshnessWindow() - time.Second).UnixNano())
				mu.Unlock()
				r.SetCapacityReporter(func(_ context.Context, n int64, known bool) error {
					if !known || n != 0 {
						t.Errorf("stale control N=%d known=%v", n, known)
					}
					t.Logf("stale control N=%d known=%v", n, known)
					return nil
				})
				_ = r.ReportCapacity(context.Background())
			})
		}
	}
}

// Exercise the live health loop while the new member's first check is in flight.
func TestDiscoveryMemberAdditionKeepsServingWithholdsReports(t *testing.T) {
	var contacts atomic.Int64
	upstream := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/health" {
			fmt.Fprint(w, `{}`)
			return
		}
		contacts.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, roleEvent+contentEvent+finishEvent+usageEvent+doneEvent)
	})
	g, server := newTestGateway(t, DefaultConfig(), upstream, upstream)
	r, _ := NewDiscoveryRegistry(&http.Client{}, 250*time.Millisecond)
	r.ReplaceBackends(g.registry.Backends())
	r.Poll(context.Background())
	g.registry = r
	members := r.Backends()
	if r.DiscoveryUnknown() || len(members) != 2 || members[0].checked.Load() == 0 || members[1].checked.Load() == 0 {
		t.Fatal("initial members were not sampled")
	}
	entered, release, resumed := make(chan struct{}, 1), make(chan struct{}), make(chan struct{}, 1)
	var releaseOnce sync.Once
	joiningServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/health" {
			t.Error("unsampled member received dispatch")
			return
		}
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
			fmt.Fprint(w, `{}`)
		case <-request.Context().Done():
		}
	}))
	defer joiningServer.Close()
	defer func() { releaseOnce.Do(func() { close(release) }); r.Close() }()
	joining, _ := NewBackend("joining", joiningServer.URL, "uid-new")
	r.Start(context.Background())
	r.ReplaceBackends(append(members, joining))
	var withheld atomic.Int64
	r.SetCapacityReporter(func(_ context.Context, n int64, known bool) error {
		if joining.checked.Load() == 0 {
			if known {
				t.Errorf("addition published a partial known count N=%d", n)
			}
			withheld.Add(1)
		} else if known {
			if n != 3 {
				t.Errorf("completed addition N=%d want3", n)
			}
			select {
			case resumed <- struct{}{}:
			default:
			}
		}
		return nil
	})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("new member health check did not start")
	}
	const requests = 20
	for range requests {
		if joining.checked.Load() != 0 {
			t.Fatal("addition window ended before request assertions")
		}
		response := requestGateway(t, server.Client(), server.URL)
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 200 || !containsBytes(body, "[DONE]") {
			t.Fatalf("addition interrupted healthy request: status=%d body=%s", response.StatusCode, body)
		}
		if err := r.ReportCapacity(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if withheld.Load() < requests || contacts.Load() != requests || g.Metrics().DiscoveryUnknown != 0 || g.Metrics().DiscoveryUnknownAfterAdmit != 0 {
		t.Fatalf("addition counts: withheld=%d contacts=%d metrics=%+v", withheld.Load(), contacts.Load(), g.Metrics())
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-resumed:
	case <-time.After(3 * time.Second):
		t.Fatal("completed addition did not resume known reports")
	}
	t.Logf("addition: %d successful requests, unknown counters=0, withheld reports=%d, resumed N=3", requests, withheld.Load())
}

func TestDiscoveryAdditionAfterSelectionDispatchesRetainedMember(t *testing.T) {
	var contacts atomic.Int64
	g, server := newTestGateway(t, DefaultConfig(), http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/health" {
			fmt.Fprint(w, `{}`)
			return
		}
		contacts.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, roleEvent+contentEvent+finishEvent+usageEvent+doneEvent)
	}))
	r, _ := NewDiscoveryRegistry(&http.Client{}, 250*time.Millisecond)
	r.ReplaceBackends(g.registry.Backends())
	r.Poll(context.Background())
	g.registry = r
	var selected *Backend
	g.backendSelection.router = &revalidationRaceRouter{after: func(b *Backend) {
		selected = b
		joining, _ := NewBackend("joining", "http://127.0.0.1:1", "uid-new")
		r.ReplaceBackends(append(r.Backends(), joining))
	}}
	response := requestGateway(t, server.Client(), server.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || !containsBytes(body, "[DONE]") || contacts.Load() != 1 || !r.CanDispatch(selected) || g.Metrics().DiscoveryUnknownAfterAdmit != 0 || g.Metrics().BackendChangedAfterAdmit != 0 {
		t.Fatalf("addition after selection interrupted retained dispatch: status=%d body=%s contacts=%d metrics=%+v", response.StatusCode, body, contacts.Load(), g.Metrics())
	}
	t.Log("addition after selection: retained member dispatched, HTTP200/DONE, unknown-after-admit=0")
}

type revalidationRaceRouter struct{ after func(*Backend) }

func (*revalidationRaceRouter) PolicyName() RoutingPolicy   { return RoutingPolicyRoundRobin }
func (*revalidationRaceRouter) NeedsFreshBackendLoad() bool { return false }
func (r *revalidationRaceRouter) Select(c []BackendCandidate, _ *TieBreaker) (BackendDecision, error) {
	b := c[0].Backend
	r.after(b)
	return BackendDecision{Backend: b}, nil
}

func TestAfterAdmitRevalidationCausesCounted(t *testing.T) {
	for _, cause := range []string{"removed", "replaced_uid", "unhealthy", "unready"} {
		t.Run(cause, func(t *testing.T) {
			var contacts atomic.Int64
			g, server := newTestGateway(t, DefaultConfig(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacts.Add(1) }))
			g.backendSelection.router = &revalidationRaceRouter{after: func(b *Backend) {
				switch cause {
				case "removed":
					g.registry.ReplaceBackends(nil)
				case "replaced_uid":
					next, _ := NewBackend(b.ID, b.URL.String(), "new-uid")
					g.registry.ReplaceBackends([]*Backend{next})
				case "unhealthy":
					b.healthy.Store(false)
				case "unready":
					b.ready.Store(false)
				}
			}}
			response := requestGateway(t, server.Client(), server.URL)
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 503 || !containsBytes(body, "backend_membership_changed_after_admit") {
				t.Fatalf("%d %s", response.StatusCode, body)
			}
			if contacts.Load() != 0 || g.Metrics().BackendChangedAfterAdmit != 1 || g.Metrics().DiscoveryUnknownAfterAdmit != 0 {
				t.Fatalf("dispatch or wrong counters: %+v", g.Metrics())
			}
			metrics := httptest.NewRecorder()
			g.metrics.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if !strings.Contains(metrics.Body.String(), "inference_gateway_backend_membership_changed_after_admit_total 1\n") {
				t.Fatal("counter not exported")
			}
			t.Logf("cause=%s code=backend_membership_changed_after_admit count=1 upstream=0", cause)
		})
	}
}

func TestFixedModeStaticHealthFlipProducesStageCRow(t *testing.T) {
	var contacts atomic.Int64
	var logs bytes.Buffer
	config := DefaultConfig()
	config.FixedModeTerminalCodes = true
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	g, server := newTestGatewayWithLogger(t, config, logger, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacts.Add(1) }))
	g.backendSelection.router = &revalidationRaceRouter{after: func(b *Backend) { b.healthy.Store(false) }}
	response := requestGateway(t, server.Client(), server.URL)
	status := response.StatusCode
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("fixed-mode health flip returned HTTP status %d; want %d", status, http.StatusServiceUnavailable)
	}
	if contacts.Load() != 0 || g.Metrics().BackendChangedAfterAdmit != 1 {
		t.Fatalf("dispatch or wrong counters: contacts=%d metrics=%+v", contacts.Load(), g.Metrics())
	}
	var terminal map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse gateway log row %q: %v", line, err)
		}
		if entry["msg"] == "request terminal" {
			terminal = entry
			break
		}
	}
	if terminal == nil {
		t.Fatalf("request terminal row missing from logs: %s", logs.String())
	}
	t.Logf("R224_STAGEC_STATUS=%d", status)
	t.Logf("R224_STAGEC_BODY=%s", strings.TrimSpace(string(body)))
	terminalRow, err := json.Marshal(terminal)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("R224_STAGEC_TERMINAL=%s", terminalRow)
}
