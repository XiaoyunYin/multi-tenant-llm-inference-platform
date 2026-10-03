package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseBackendLoadMetrics(t *testing.T) {
	payload := []byte(`# HELP vllm:num_requests_running running
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{model_name="model with space"} 3
vllm:num_requests_waiting{model_name="model with space"} 2 1234
vllm:kv_cache_usage_perc{model_name="model with space"} 0.625
unrelated_metric 99
`)
	running, waiting, kvUsage, err := parseBackendLoadMetrics(payload)
	if err != nil || running != 3 || waiting != 2 || kvUsage != 0.625 {
		t.Fatalf("parsed metrics mismatch: running=%v waiting=%v kv=%v err=%v", running, waiting, kvUsage, err)
	}

	invalid := []string{
		"vllm:num_requests_running 1\nvllm:num_requests_waiting 0\n",
		"vllm:num_requests_running 1\nvllm:num_requests_running 1\nvllm:num_requests_waiting 0\nvllm:kv_cache_usage_perc 0.2\n",
		"vllm:num_requests_running 1.5\nvllm:num_requests_waiting 0\nvllm:kv_cache_usage_perc 0.2\n",
		"vllm:num_requests_running 1\nvllm:num_requests_waiting -1\nvllm:kv_cache_usage_perc 0.2\n",
		"vllm:num_requests_running 1\nvllm:num_requests_waiting 0\nvllm:kv_cache_usage_perc 1.1\n",
		"vllm:num_requests_running{model_name=\"broken} 1\nvllm:num_requests_waiting 0\nvllm:kv_cache_usage_perc 0.2\n",
	}
	for index, candidate := range invalid {
		if _, _, _, err := parseBackendLoadMetrics([]byte(candidate)); err == nil {
			t.Fatalf("invalid metrics payload %d was accepted", index)
		}
	}
}

func TestBackendMetricsCollectorSeparatesFreshStaleAndFailedBackends(t *testing.T) {
	metrics := "vllm:num_requests_running 4\nvllm:num_requests_waiting 2\nvllm:kv_cache_usage_perc 0.75\n"
	var failGood atomic.Bool
	goodServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/metrics" {
			http.NotFound(response, request)
			return
		}
		if failGood.Load() {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(response, metrics)
	}))
	defer goodServer.Close()
	badServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer badServer.Close()
	good, _ := NewBackend("gpu-a", goodServer.URL)
	bad, _ := NewBackend("gpu-b", badServer.URL)
	collector, err := NewBackendMetricsCollector([]*Backend{good, bad}, goodServer.Client(), 10*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	collector.Poll(context.Background())
	snapshots := collector.Snapshots(time.Now())
	if len(snapshots) != 2 || !snapshots[0].Up || !snapshots[0].Fresh || !snapshots[0].HasSample {
		t.Fatalf("healthy snapshot mismatch: %+v", snapshots)
	}
	if snapshots[0].Running != 4 || snapshots[0].Waiting != 2 || snapshots[0].KVUsage != 0.75 {
		t.Fatalf("load values mismatch: %+v", snapshots[0])
	}
	if snapshots[1].Up || snapshots[1].Fresh || snapshots[1].HasSample || snapshots[1].ScrapeErrors != 1 {
		t.Fatalf("failed snapshot mismatch: %+v", snapshots[1])
	}
	failGood.Store(true)
	collector.Poll(context.Background())
	lastGood := collector.Snapshots(time.Now())[0]
	if lastGood.Up || lastGood.Fresh || !lastGood.HasSample || lastGood.Running != 4 || lastGood.ScrapeErrors != 1 {
		t.Fatalf("failed scrape did not preserve a diagnostic-only last-good value: %+v", lastGood)
	}
	stale := collector.Snapshots(time.Now().Add(time.Second))[0]
	if stale.Fresh || stale.SampleAge < time.Second {
		t.Fatalf("stale sample was treated as fresh: %+v", stale)
	}
}

func TestBackendMetricsCollectorRejectsOversizedAndMalformedResponses(t *testing.T) {
	responses := []string{
		strings.Repeat("x", maxBackendMetricsBytes+1),
		"vllm:num_requests_running 1\nvllm:num_requests_waiting 0\nvllm:kv_cache_usage_perc NaN\n",
	}
	for index, body := range responses {
		t.Run(fmt.Sprintf("response-%d", index), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(response, body)
			}))
			defer server.Close()
			backend, _ := NewBackend("gpu", server.URL)
			collector, _ := NewBackendMetricsCollector([]*Backend{backend}, server.Client(), time.Second, 2*time.Second)
			collector.Poll(context.Background())
			snapshot := collector.Snapshots(time.Now())[0]
			if snapshot.Up || snapshot.HasSample || snapshot.ScrapeErrors != 1 {
				t.Fatalf("invalid scrape was trusted: %+v", snapshot)
			}
		})
	}
}
