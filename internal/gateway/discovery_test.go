package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func slicePayload(endpoints ...map[string]any) string {
	value := map[string]any{"items": []any{map[string]any{
		"metadata":    map[string]any{"labels": map[string]string{"kubernetes.io/service-name": "fake"}},
		"addressType": "IPv4", "ports": []any{map[string]any{"name": "http", "port": 8000, "protocol": "TCP"}}, "endpoints": endpoints,
	}}}
	data, _ := json.Marshal(value)
	return string(data)
}

func podEndpoint(name, uid, ip string, ready, terminating bool) map[string]any {
	return map[string]any{"addresses": []string{ip}, "conditions": map[string]bool{"ready": ready, "terminating": terminating}, "targetRef": map[string]string{"kind": "Pod", "namespace": "test", "name": name, "uid": uid}}
}

func TestEndpointSliceMembershipAndFailSafe(t *testing.T) {
	payload, status := "", 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/discovery.k8s.io/v1/namespaces/test/endpointslices" || r.URL.Query().Get("labelSelector") != "kubernetes.io/service-name=fake" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("incorrect API scope or credential")
		}
		w.WriteHeader(status)
		fmt.Fprint(w, payload)
	}))
	defer server.Close()
	registry, _ := NewDiscoveryRegistry(server.Client(), time.Millisecond)
	discovery, _ := NewEndpointSliceDiscovery(DiscoveryConfig{"test", "fake", time.Millisecond}, registry, server.Client(), server.URL, func() (string, error) { return "test-token", nil }, nil)
	a := podEndpoint("fake-0", "uid-a", "10.0.0.2", true, false)
	b := podEndpoint("fake-1", "uid-b", "10.0.0.3", true, false)
	for _, tc := range []struct {
		name, body  string
		code, count int
	}{
		{"add", slicePayload(a, b), 200, 2},
		{"remove", slicePayload(a), 200, 1},
		{"unready", slicePayload(podEndpoint("fake-0", "uid-a", "10.0.0.2", false, false), b), 200, 1},
		{"terminating-even-if-ready", slicePayload(podEndpoint("fake-0", "uid-a", "10.0.0.2", true, true)), 200, 0},
		{"flap-up", slicePayload(a), 200, 1},
		{"flap-down", slicePayload(), 200, 0},
		{"flap-up-again", slicePayload(a), 200, 1},
		{"api-error", "denied", 403, 0},
		{"recover", slicePayload(a), 200, 1},
		{"invalid-json", "{", 200, 0},
		{"duplicate-delivery", slicePayload(a, a), 200, 1},
		{"draining-duplicate-wins", slicePayload(a, podEndpoint("fake-0", "uid-a", "10.0.0.2", true, true)), 200, 0},
		{"unready-duplicate-wins", slicePayload(a, podEndpoint("fake-0", "uid-a", "10.0.0.2", false, false)), 200, 0},
		{"conflicting-incarnations", slicePayload(a, podEndpoint("fake-0", "uid-new", "10.0.0.4", true, false)), 200, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, status = tc.body, tc.code
			err := discovery.Poll(context.Background())
			if tc.count > 0 && err != nil {
				t.Fatal(err)
			}
			if got := len(registry.Backends()); got != tc.count {
				t.Fatalf("got %d backends want %d", got, tc.count)
			}
			if tc.count == 0 && registry.AnyEligible() {
				t.Fatal("empty discovery still admits")
			}
			for _, backend := range registry.Backends() {
				if !strings.HasPrefix(backend.URL.Host, "10.0.0.") || backend.Generation == "0" {
					t.Fatal("not direct pod address/generation")
				}
			}
		})
	}
	// A missing Ready condition is unknown, not ready.
	delete(a["conditions"].(map[string]bool), "ready")
	payload = slicePayload(a)
	if err := discovery.Poll(context.Background()); err != nil || len(registry.Backends()) != 0 {
		t.Fatalf("unknown readiness accepted: %v", err)
	}
}

func TestDiscoveryGenerationAndConcurrentRecovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			fmt.Fprint(w, `{"healthy":true}`)
			return
		}
		fmt.Fprint(w, "vllm:num_requests_running 1\nvllm:num_requests_waiting 0\nvllm:kv_cache_usage_perc 0.2\n")
	}))
	defer server.Close()
	r, _ := NewDiscoveryRegistry(server.Client(), time.Millisecond)
	metrics, _ := NewDiscoveryMetricsCollector(r, server.Client(), time.Millisecond, time.Second)
	install := func(gen string) { b, _ := NewBackend("fake-0", server.URL, gen); r.ReplaceBackends([]*Backend{b}) }
	install("old")
	r.Poll(context.Background())
	metrics.Poll(context.Background())
	old := r.Backends()[0]
	install("old")
	if r.Backends()[0] != old || !r.AnyEligible() {
		t.Fatal("unchanged pod lost health")
	}
	install("new")
	if r.AnyEligible() {
		t.Fatal("new generation inherited old health")
	}
	if snapshots := metrics.Snapshots(time.Now()); snapshots[0].HasSample {
		t.Fatal("new generation inherited old load")
	}
	r.Poll(context.Background())
	if candidates := r.Candidates([]BackendMetricsSnapshot{{BackendID: "fake-0", Generation: "old", Fresh: true}}); candidates[0].Load.Fresh {
		t.Fatal("old in-flight metric leaked")
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Go(func() {
			for i := 0; i < 50; i++ {
				r.Poll(context.Background())
				metrics.Poll(context.Background())
				_ = r.Candidates(metrics.Snapshots(time.Now()))
				_, _ = r.Select()
			}
		})
	}
	for i := 0; i < 50; i++ {
		r.ReplaceBackends(nil)
		install(fmt.Sprintf("gen-%d", i))
	}
	wg.Wait()
	r.Poll(context.Background())
	metrics.Poll(context.Background())
	if !r.AnyEligible() || !metrics.Snapshots(time.Now())[0].Fresh {
		t.Fatal("did not recover")
	}
}

func TestDiscoveryTimeoutClearsPreviouslyReadySet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	registry, _ := NewDiscoveryRegistry(server.Client(), time.Millisecond)
	b, _ := NewBackend("fake-0", "http://10.0.0.2:8000", "uid")
	registry.ReplaceBackends([]*Backend{b})
	b.healthy.Store(true)
	b.ready.Store(true)
	discovery, _ := NewEndpointSliceDiscovery(DiscoveryConfig{"test", "fake", time.Millisecond}, registry, &http.Client{Timeout: 20 * time.Millisecond}, server.URL, func() (string, error) { return "token", nil }, nil)
	if err := discovery.Poll(context.Background()); err == nil || registry.AnyEligible() {
		t.Fatalf("timeout did not fail closed: %v", err)
	}
}
