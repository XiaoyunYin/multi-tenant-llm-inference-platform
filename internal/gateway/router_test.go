package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"
)

type fixedBackendRouter struct {
	backendID string
}

func (*fixedBackendRouter) NeedsFreshBackendLoad() bool { return false }

func (*fixedBackendRouter) PolicyName() RoutingPolicy { return RoutingPolicyHashAffinity }

func (r *fixedBackendRouter) Select(candidates []BackendCandidate, _ *TieBreaker) (BackendDecision, error) {
	for _, candidate := range candidates {
		if candidate.Backend.ID == r.backendID {
			return BackendDecision{Backend: candidate.Backend}, nil
		}
	}
	return BackendDecision{}, ErrNoHealthyBackend
}

func routerTestBackend(t *testing.T, id string, healthy, ready bool, load BackendMetricsSnapshot) BackendCandidate {
	t.Helper()
	backend, err := NewBackend(id, fmt.Sprintf("http://%s.example.test", id))
	if err != nil {
		t.Fatal(err)
	}
	backend.healthy.Store(healthy)
	backend.ready.Store(ready)
	return BackendCandidate{Backend: backend, Healthy: healthy, Ready: ready, Load: load}
}

func freshRouterLoad(id string, running, waiting float64) BackendMetricsSnapshot {
	return BackendMetricsSnapshot{
		BackendID: id, HasSample: true, Up: true, Fresh: true,
		Running: running, Waiting: waiting,
	}
}

func TestBackendSelectionRoundRobinUsesHealthyReadyCandidates(t *testing.T) {
	candidates := []BackendCandidate{
		routerTestBackend(t, "backend-a", true, true, BackendMetricsSnapshot{}),
		routerTestBackend(t, "backend-b", false, true, freshRouterLoad("backend-b", 0, 0)),
		routerTestBackend(t, "backend-c", true, false, freshRouterLoad("backend-c", 0, 0)),
		routerTestBackend(t, "backend-d", true, true, BackendMetricsSnapshot{}),
	}
	selection := NewBackendSelectionBoundary(NewRoundRobinRouter(), NewSeededTieBreaker(7))
	want := []string{"backend-a", "backend-d", "backend-a", "backend-d"}
	for _, expected := range want {
		decision, err := selection.Select(candidates)
		if err != nil || decision.Backend.ID != expected {
			t.Fatalf("selection = %v, %v; want %s", decision, err, expected)
		}
	}
}

func TestBackendSelectionReturnsNoBackendWhenNoneAreHealthyAndReady(t *testing.T) {
	candidates := []BackendCandidate{
		routerTestBackend(t, "unhealthy", false, true, BackendMetricsSnapshot{}),
		routerTestBackend(t, "unready", true, false, BackendMetricsSnapshot{}),
	}
	selection := NewBackendSelectionBoundary(NewRoundRobinRouter(), NewSeededTieBreaker(1))
	if decision, err := selection.Select(candidates); decision.Backend != nil || err != ErrNoHealthyBackend {
		t.Fatalf("selection = %v, %v; want no eligible backend", decision, err)
	}
}

func TestLoadAwareSelectionFallsBackForStaleOrMissingTelemetry(t *testing.T) {
	stale := freshRouterLoad("backend-b", 0, 0)
	stale.Fresh = false
	missing := freshRouterLoad("backend-b", 0, 0)
	missing.HasSample = false
	down := freshRouterLoad("backend-b", 0, 0)
	down.Up = false
	tests := []struct {
		name           string
		load           BackendMetricsSnapshot
		fallbackReason FallbackReason
	}{
		{name: "stale", load: stale, fallbackReason: FallbackReasonStale},
		{name: "missing", load: missing, fallbackReason: FallbackReasonMissing},
		{name: "scrape down", load: down, fallbackReason: FallbackReasonDown},
		{name: "identity mismatch", load: BackendMetricsSnapshot{BackendID: "unexpected", HasSample: true, Up: true, Fresh: true}, fallbackReason: FallbackReasonIdentityMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidates := []BackendCandidate{
				routerTestBackend(t, "backend-a", true, true, freshRouterLoad("backend-a", 0, 0)),
				routerTestBackend(t, "backend-b", true, true, test.load),
				routerTestBackend(t, "unhealthy", false, true, freshRouterLoad("unhealthy", 0, 0)),
				routerTestBackend(t, "unready", true, false, freshRouterLoad("unready", 0, 0)),
			}
			selection := NewBackendSelectionBoundary(NewLeastLoadedRouter(), NewSeededTieBreaker(3))
			for _, expected := range []string{"backend-a", "backend-b"} {
				decision, err := selection.Select(candidates)
				if err != nil || decision.Backend.ID != expected {
					t.Fatalf("fallback selection = %v, %v; want %s", decision, err, expected)
				}
				if decision.Policy != RoutingPolicyRoundRobin {
					t.Fatalf("fallback policy = %q; want %q", decision.Policy, RoutingPolicyRoundRobin)
				}
				if decision.FallbackReason != test.fallbackReason {
					t.Fatalf("fallback reason = %q; want %q", decision.FallbackReason, test.fallbackReason)
				}
			}
		})
	}
}

func TestLeastLoadedSelectionUsesFreshSamplesAndLowestLoad(t *testing.T) {
	busyLoad := freshRouterLoad("busy", 3, 1)
	idleLoad := freshRouterLoad("idle", 1, 0)
	busyLoad.KVUsage = 0
	idleLoad.KVUsage = 0.99
	candidates := []BackendCandidate{
		routerTestBackend(t, "busy", true, true, busyLoad),
		routerTestBackend(t, "idle", true, true, idleLoad),
	}
	selection := NewBackendSelectionBoundary(NewLeastLoadedRouter(), NewSeededTieBreaker(5))
	decision, err := selection.Select(candidates)
	if err != nil || decision.Backend.ID != "idle" {
		t.Fatalf("selection = %v, %v; want idle backend", decision, err)
	}
	if decision.Policy != RoutingPolicyLeastLoaded || decision.FallbackReason != FallbackReasonNone {
		t.Fatalf("fresh selection decision = %+v; want least_loaded/none", decision)
	}
}

func TestEqualBackendLoadTieBreakIsDeterministicForSeed(t *testing.T) {
	tieALoad := freshRouterLoad("tie-a", 2, 1)
	tieBLoad := freshRouterLoad("tie-b", 1, 2)
	tieALoad.KVUsage = 0.99
	tieBLoad.KVUsage = 0.01
	candidates := []BackendCandidate{
		routerTestBackend(t, "tie-a", true, true, tieALoad),
		routerTestBackend(t, "tie-b", true, true, tieBLoad),
		routerTestBackend(t, "busy", true, true, freshRouterLoad("busy", 4, 0)),
	}
	firstSelection := NewBackendSelectionBoundary(NewLeastLoadedRouter(), NewSeededTieBreaker(42))
	secondSelection := NewBackendSelectionBoundary(NewLeastLoadedRouter(), NewSeededTieBreaker(42))
	seen := make(map[string]bool)
	for index := 0; index < 32; index++ {
		first, err := firstSelection.Select(candidates)
		if err != nil {
			t.Fatal(err)
		}
		second, err := secondSelection.Select(candidates)
		if err != nil {
			t.Fatal(err)
		}
		if first.Backend.ID != second.Backend.ID {
			t.Fatalf("same seeded tie-break produced %q and %q", first.Backend.ID, second.Backend.ID)
		}
		if first.Policy != RoutingPolicyLeastLoaded || first.FallbackReason != FallbackReasonNone {
			t.Fatalf("tie selection decision = %+v; want least_loaded/none", first)
		}
		seen[first.Backend.ID] = true
	}
	if len(seen) != 2 {
		t.Fatalf("seeded tie-break did not randomize among equal-load backends: %v", seen)
	}
}

func TestRoundRobinPreservesNextMemberAcrossEligibilityChanges(t *testing.T) {
	a := routerTestBackend(t, "backend-a", true, true, BackendMetricsSnapshot{})
	b := routerTestBackend(t, "backend-b", true, true, BackendMetricsSnapshot{})
	c := routerTestBackend(t, "backend-c", true, true, BackendMetricsSnapshot{})
	selection := NewBackendSelectionBoundary(NewRoundRobinRouter(), NewSeededTieBreaker(2))
	selectID := func(candidates []BackendCandidate, expected string) {
		t.Helper()
		decision, err := selection.Select(candidates)
		if err != nil || decision.Backend.ID != expected {
			t.Fatalf("selection = %v, %v; want %s", decision, err, expected)
		}
	}

	selectID([]BackendCandidate{a, b}, "backend-a")
	selectID([]BackendCandidate{a, b, c}, "backend-b")
	a.Ready = false
	a.Backend.ready.Store(false)
	selectID([]BackendCandidate{a, b, c}, "backend-c")
	a.Ready = true
	a.Backend.ready.Store(true)
	selectID([]BackendCandidate{a, b, c}, "backend-b")
}

func TestRegistryKeepsHealthSeparateFromReadiness(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"backend_id":"not-ready","healthy":true,"ready":false}`)
	}))
	defer server.Close()
	backend, err := NewBackend("not-ready", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]*Backend{backend}, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	registry.Poll(context.Background())
	if !backend.Healthy() || backend.Ready() {
		t.Fatalf("health/readiness collapsed: healthy=%t ready=%t", backend.Healthy(), backend.Ready())
	}
	if !registry.AnyHealthy() || registry.AnyEligible() {
		t.Fatalf("registry eligibility mismatch: anyHealthy=%t anyEligible=%t", registry.AnyHealthy(), registry.AnyEligible())
	}
	if selected, err := registry.Select(); selected != nil || err != ErrNoHealthyBackend {
		t.Fatalf("unready backend selected: %v %v", selected, err)
	}
}

func TestGatewayUsesConfiguredRouterThroughSelectionBoundary(t *testing.T) {
	firstStream := roleEvent + strings.Replace(contentEvent, "hello", "first", 1) + finishEvent + usageEvent + doneEvent
	secondStream := roleEvent + strings.Replace(contentEvent, "hello", "second", 1) + finishEvent + usageEvent + doneEvent
	firstServer := httptest.NewServer(streamHandler(firstStream))
	secondServer := httptest.NewServer(streamHandler(secondStream))
	t.Cleanup(firstServer.Close)
	t.Cleanup(secondServer.Close)
	firstBackend, err := NewBackend("backend-0", firstServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	secondBackend, err := NewBackend("backend-1", secondServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]*Backend{firstBackend, secondBackend}, &http.Client{Timeout: time.Second}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := admission.NewMemoryCoordinator(10_000)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(DefaultConfig(), registry, &http.Client{}, nil,
		WithTenantRegistry(testTenantRegistry(t)),
		WithAdmissionCoordinator(coordinator),
		WithRouter(&fixedBackendRouter{backendID: "backend-1"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	response := requestGateway(t, server.Client(), server.URL)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"content":"second"`)) {
		t.Fatalf("configured router did not select backend-1: status=%d body=%s", response.StatusCode, body)
	}
}

func TestGatewayRecordsEffectivePolicyAndFallbackReason(t *testing.T) {
	stream := roleEvent + contentEvent + finishEvent + usageEvent + doneEvent
	tests := []struct {
		name         string
		staleBackend string
		wantBackend  string
		wantPolicy   RoutingPolicy
		wantFallback FallbackReason
		backendLoads map[string]float64
	}{
		{
			name:         "stale sample falls back to round robin",
			staleBackend: "backend-a",
			wantBackend:  "backend-a",
			wantPolicy:   RoutingPolicyRoundRobin,
			wantFallback: FallbackReasonStale,
			backendLoads: map[string]float64{"backend-a": 4, "backend-b": 1},
		},
		{
			name:         "all fresh samples use the configured policy",
			wantBackend:  "backend-b",
			wantPolicy:   RoutingPolicyLeastLoaded,
			wantFallback: FallbackReasonNone,
			backendLoads: map[string]float64{"backend-a": 4, "backend-b": 1},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			firstServer := httptest.NewServer(streamHandler(stream))
			secondServer := httptest.NewServer(streamHandler(stream))
			t.Cleanup(firstServer.Close)
			t.Cleanup(secondServer.Close)
			firstBackend, err := NewBackend("backend-a", firstServer.URL)
			if err != nil {
				t.Fatal(err)
			}
			secondBackend, err := NewBackend("backend-b", secondServer.URL)
			if err != nil {
				t.Fatal(err)
			}
			backends := []*Backend{firstBackend, secondBackend}
			registry, err := NewRegistry(backends, &http.Client{Timeout: time.Second}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			collector, err := NewBackendMetricsCollector(backends, &http.Client{Timeout: time.Second}, time.Second, 100*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			for _, backend := range backends {
				collectedAt := time.Now()
				if backend.ID == test.staleBackend {
					collectedAt = collectedAt.Add(-time.Second)
				}
				collector.states[backend.ID].sample.Store(&backendLoadSample{
					collectedAt: collectedAt, running: test.backendLoads[backend.ID],
				})
				collector.states[backend.ID].up.Store(true)
			}
			coordinator, err := admission.NewMemoryCoordinator(10_000)
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			gateway, err := New(DefaultConfig(), registry, &http.Client{Timeout: time.Second},
				slog.New(slog.NewJSONHandler(&logs, nil)),
				WithTenantRegistry(testTenantRegistry(t)),
				WithAdmissionCoordinator(coordinator),
				WithBackendMetricsCollector(collector),
				WithRouter(NewLeastLoadedRouter()),
			)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(gateway.Handler())
			defer server.Close()
			response := requestGateway(t, server.Client(), server.URL)
			_, readErr := io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.StatusCode != http.StatusOK || response.Header.Get("X-Inference-Backend") != test.wantBackend {
				t.Fatalf("response status=%d backend=%q; want backend %q", response.StatusCode, response.Header.Get("X-Inference-Backend"), test.wantBackend)
			}
			var terminal map[string]any
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var entry map[string]any
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					t.Fatalf("parse terminal log %q: %v", line, err)
				}
				if entry["msg"] == "request terminal" {
					terminal = entry
				}
			}
			if terminal == nil || terminal["router_policy"] != string(test.wantPolicy) || terminal["router_fallback_reason"] != string(test.wantFallback) {
				t.Fatalf("terminal route fields = %v; want %s/%s", terminal, test.wantPolicy, test.wantFallback)
			}
			if decisionAt, ok := terminal["router_decision_unix_ns"].(float64); !ok || decisionAt <= 0 {
				t.Fatalf("terminal router decision timestamp = %v; want positive Unix nanoseconds", terminal["router_decision_unix_ns"])
			}

			metricsResponse, err := server.Client().Get(server.URL + "/metrics")
			if err != nil {
				t.Fatal(err)
			}
			metricsBody, readErr := io.ReadAll(metricsResponse.Body)
			metricsResponse.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			metricLine := fmt.Sprintf("inference_gateway_routing_decisions_total{policy=%q,fallback_reason=%q} 1", test.wantPolicy, test.wantFallback)
			if !strings.Contains(string(metricsBody), metricLine) {
				t.Fatalf("routing decision metric %q missing from /metrics", metricLine)
			}
			if !strings.Contains(string(metricsBody), "inference_gateway_routing_lookup_duration_seconds_count 1") {
				t.Fatalf("routing lookup duration missing from /metrics:\n%s", metricsBody)
			}
		})
	}
}

func TestConcurrentBackendSelectionIsRaceSafe(t *testing.T) {
	tests := []struct {
		name   string
		router Router
	}{
		{name: "round-robin", router: NewRoundRobinRouter()},
		{name: "least-loaded", router: NewLeastLoadedRouter()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidates := []BackendCandidate{
				routerTestBackend(t, "backend-a", true, true, freshRouterLoad("backend-a", 2, 1)),
				routerTestBackend(t, "backend-b", true, true, freshRouterLoad("backend-b", 1, 2)),
			}
			selection := NewBackendSelectionBoundary(test.router, NewSeededTieBreaker(29))
			var wait sync.WaitGroup
			var selections atomic.Int64
			var invalid atomic.Bool
			for range 24 {
				wait.Add(1)
				go func() {
					defer wait.Done()
					for range 200 {
						decision, err := selection.Select(candidates)
						if err != nil || decision.Backend == nil || (decision.Backend.ID != "backend-a" && decision.Backend.ID != "backend-b") {
							invalid.Store(true)
							return
						}
						selections.Add(1)
					}
				}()
			}
			wait.Wait()
			if invalid.Load() || selections.Load() != 24*200 {
				t.Fatalf("concurrent selections invalid=%t count=%d", invalid.Load(), selections.Load())
			}
		})
	}
}
