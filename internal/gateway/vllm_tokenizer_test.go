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
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"
)

func tokenizerCandidate(t *testing.T, id string, server *httptest.Server, healthy, ready bool) BackendCandidate {
	t.Helper()
	backend, err := NewBackend(id, server.URL, "gen-1")
	if err != nil {
		t.Fatal(err)
	}
	return BackendCandidate{Backend: backend, Healthy: healthy, Ready: ready}
}

func tokenizerSuccessHandler(t *testing.T, wantModel string, wantMessages []RoutingMessage) http.HandlerFunc {
	t.Helper()
	return func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/tokenize" {
			t.Errorf("tokenizer path=%q; want /tokenize", request.URL.Path)
		}
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("tokenizer request method/content-type = %q/%q", request.Method, request.Header.Get("Content-Type"))
		}
		var body struct {
			Model               string           `json:"model"`
			Messages            []RoutingMessage `json:"messages"`
			AddGenerationPrompt bool             `json:"add_generation_prompt"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode tokenize request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Model != wantModel || !reflect.DeepEqual(body.Messages, wantMessages) || !body.AddGenerationPrompt {
			t.Errorf("tokenize request=%+v; want pinned model/messages with generation prompt", body)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"count":6,"max_model_len":8192,"tokens":[11,12,13,14,15,16]}`)
	}
}

func newTestVLLMTokenizer(t *testing.T, client *http.Client, timeout time.Duration, maxTokenIDs int) *VLLMRoutingKeyTokenizer {
	t.Helper()
	tokenizer, err := NewVLLMRoutingKeyTokenizer(client, timeout, maxTokenIDs)
	if err != nil {
		t.Fatal(err)
	}
	return tokenizer
}

func TestVLLMRoutingKeyTokenizerUsesPinnedChatTemplateAndCapsIDs(t *testing.T) {
	model := "Qwen/Qwen2.5-3B-Instruct"
	messages := []RoutingMessage{{Role: "system", Content: "Be concise."}, {Role: "user", Content: "hello"}}
	server := httptest.NewServer(tokenizerSuccessHandler(t, model, messages))
	t.Cleanup(server.Close)
	candidate := tokenizerCandidate(t, "backend-a", server, true, true)
	tokenizer := newTestVLLMTokenizer(t, server.Client(), time.Second, 4)
	tokenization, err := tokenizer.TokenizeChat(context.Background(), "request-one", model, messages, []BackendCandidate{candidate})
	if err != nil {
		t.Fatal(err)
	}
	tokens := tokenization.TokenIDs
	want := []uint32{11, 12, 13, 14}
	if !reflect.DeepEqual(tokens, want) {
		t.Fatalf("token IDs=%v; want first configured token span %v", tokens, want)
	}
}

func TestVLLMRoutingKeyTokenizerRetriesHTTPErrorInDeterministicOrder(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	makeServer := func(id string, status int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			mu.Lock()
			calls = append(calls, id)
			mu.Unlock()
			if status != http.StatusOK {
				response.WriteHeader(status)
				return
			}
			_, _ = io.WriteString(response, `{"count":2,"max_model_len":8192,"tokens":[7,8]}`)
		}))
	}
	first := makeServer("backend-a", http.StatusServiceUnavailable)
	second := makeServer("backend-b", http.StatusOK)
	disabled := makeServer("backend-disabled", http.StatusOK)
	t.Cleanup(first.Close)
	t.Cleanup(second.Close)
	t.Cleanup(disabled.Close)
	candidates := []BackendCandidate{
		tokenizerCandidate(t, "backend-b", second, true, true),
		tokenizerCandidate(t, "backend-disabled", disabled, false, true),
		tokenizerCandidate(t, "backend-a", first, true, true),
	}
	tokenizer := newTestVLLMTokenizer(t, &http.Client{Timeout: time.Second}, time.Second, 8)
	requestID := "request-a-first"
	for firstCandidateIndex(requestID, 2) != 0 {
		requestID += "-a"
	}
	result, err := tokenizer.TokenizeChat(context.Background(), requestID, "model", []RoutingMessage{{Role: "user", Content: "hello"}}, candidates)
	if err != nil || !reflect.DeepEqual(result.TokenIDs, []uint32{7, 8}) {
		t.Fatalf("tokenization after HTTP error=%v err=%v", result.TokenIDs, err)
	}
	mu.Lock()
	gotCalls := append([]string(nil), calls...)
	mu.Unlock()
	if len(gotCalls) != 2 || gotCalls[0] != "backend-a" || gotCalls[1] != "backend-b" {
		t.Fatalf("tokenizer attempt order=%v; want backend-a first then backend-b fallback", gotCalls)
	}
	if !reflect.DeepEqual(result.AttemptedBackendIDs, gotCalls) {
		t.Fatalf("recorded attempt IDs=%v; want actual attempts %v", result.AttemptedBackendIDs, gotCalls)
	}
}

func TestVLLMRoutingKeyTokenizerRetriesAfterPerReplicaTimeout(t *testing.T) {
	var firstCalls, secondCalls atomic.Int64
	first := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		firstCalls.Add(1)
		time.Sleep(150 * time.Millisecond)
	}))
	second := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		secondCalls.Add(1)
		_, _ = io.WriteString(response, `{"count":1,"max_model_len":8192,"tokens":[9]}`)
	}))
	t.Cleanup(first.Close)
	t.Cleanup(second.Close)
	candidates := []BackendCandidate{
		tokenizerCandidate(t, "backend-b", second, true, true),
		tokenizerCandidate(t, "backend-a", first, true, true),
	}
	tokenizer := newTestVLLMTokenizer(t, &http.Client{}, 20*time.Millisecond, 8)
	result, err := tokenizer.TokenizeChat(context.Background(), "request-timeout", "model", []RoutingMessage{{Role: "user", Content: "hello"}}, candidates)
	if err != nil || !reflect.DeepEqual(result.TokenIDs, []uint32{9}) {
		t.Fatalf("tokenization after timeout=%v err=%v", result.TokenIDs, err)
	}
	if firstCalls.Load() != 1 || secondCalls.Load() != 1 {
		t.Fatalf("tokenizer calls after timeout: first=%d second=%d; want one attempt per replica", firstCalls.Load(), secondCalls.Load())
	}
}

func TestVLLMRoutingKeyTokenizerReturnsErrorAfterAllEndpointErrors(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	servers := make([]*httptest.Server, 0, 2)
	candidates := make([]BackendCandidate, 0, 2)
	for _, id := range []string{"backend-b", "backend-a"} {
		id := id
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			calls = append(calls, id)
			mu.Unlock()
			response.WriteHeader(http.StatusInternalServerError)
		}))
		servers = append(servers, server)
		candidates = append(candidates, tokenizerCandidate(t, id, server, true, true))
	}
	for _, server := range servers {
		t.Cleanup(server.Close)
	}
	tokenizer := newTestVLLMTokenizer(t, &http.Client{Timeout: time.Second}, time.Second, 8)
	if _, err := tokenizer.TokenizeChat(context.Background(), "request-all-error", "model", []RoutingMessage{{Role: "user", Content: "hello"}}, candidates); err == nil {
		t.Fatal("tokenization succeeded after every healthy ready endpoint returned an error")
	}
	mu.Lock()
	gotCalls := append([]string(nil), calls...)
	mu.Unlock()
	sort.Strings(gotCalls)
	if !reflect.DeepEqual(gotCalls, []string{"backend-a", "backend-b"}) {
		t.Fatalf("all-error attempts=%v; want one call to each healthy backend", gotCalls)
	}
}

func TestVLLMRoutingKeyTokenizerSpreadsFirstAttemptsAndRetriesInStableOrder(t *testing.T) {
	var aCalls, bCalls atomic.Int64
	makeServer := func(counter *atomic.Int64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			counter.Add(1)
			_, _ = io.WriteString(response, `{"count":1,"max_model_len":8192,"tokens":[7]}`)
		}))
	}
	aServer := makeServer(&aCalls)
	bServer := makeServer(&bCalls)
	t.Cleanup(aServer.Close)
	t.Cleanup(bServer.Close)
	candidates := []BackendCandidate{
		tokenizerCandidate(t, "backend-b", bServer, true, true),
		tokenizerCandidate(t, "backend-a", aServer, true, true),
	}
	tokenizer := newTestVLLMTokenizer(t, &http.Client{Timeout: time.Second}, time.Second, 8)
	const requestCount = 256
	for index := 0; index < requestCount; index++ {
		requestID := fmt.Sprintf("spread-%03d", index)
		result, err := tokenizer.TokenizeChat(context.Background(), requestID, "model", []RoutingMessage{{Role: "user", Content: "hello"}}, candidates)
		if err != nil || !reflect.DeepEqual(result.TokenIDs, []uint32{7}) || len(result.AttemptedBackendIDs) != 1 {
			t.Fatalf("request %q result=%+v err=%v", requestID, result, err)
		}
	}
	aCount, bCount := aCalls.Load(), bCalls.Load()
	if aCount < requestCount*40/100 || bCount < requestCount*40/100 {
		t.Fatalf("first attempts were not spread across both replicas: a=%d b=%d", aCount, bCount)
	}

	failedA := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	healthyB := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, `{"count":1,"max_model_len":8192,"tokens":[9]}`)
	}))
	t.Cleanup(failedA.Close)
	t.Cleanup(healthyB.Close)
	fallbackCandidates := []BackendCandidate{
		tokenizerCandidate(t, "backend-b", healthyB, true, true),
		tokenizerCandidate(t, "backend-a", failedA, true, true),
	}
	requestID := "fallback-a-first"
	for firstCandidateIndex(requestID, 2) != 0 {
		requestID += "-a"
	}
	result, err := tokenizer.TokenizeChat(context.Background(), requestID, "model", []RoutingMessage{{Role: "user", Content: "hello"}}, fallbackCandidates)
	if err != nil || !reflect.DeepEqual(result.TokenIDs, []uint32{9}) {
		t.Fatalf("fallback tokenization result=%+v err=%v", result, err)
	}
	if !reflect.DeepEqual(result.AttemptedBackendIDs, []string{"backend-a", "backend-b"}) {
		t.Fatalf("fallback order=%v; want failed first attempt then stable-ID fallback", result.AttemptedBackendIDs)
	}
}

func TestVLLMRoutingKeyTokenizerReturnsErrorWhenAllReplicasAreDown(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	t.Cleanup(server.Close)
	candidates := []BackendCandidate{
		tokenizerCandidate(t, "backend-a", server, false, true),
		tokenizerCandidate(t, "backend-b", server, true, false),
	}
	tokenizer := newTestVLLMTokenizer(t, server.Client(), time.Second, 8)
	if _, err := tokenizer.TokenizeChat(context.Background(), "request-no-healthy", "model", []RoutingMessage{{Role: "user", Content: "hello"}}, candidates); err == nil {
		t.Fatal("tokenization succeeded with no healthy ready replicas")
	}
	if calls.Load() != 0 {
		t.Fatalf("tokenizer called %d unhealthy or unready replicas", calls.Load())
	}
}

func TestGatewayTokenizationFailureUsesLeastLoadedAndRecordsReasonAndLatency(t *testing.T) {
	stream := roleEvent + contentEvent + finishEvent + usageEvent + doneEvent
	backendHandler := func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/tokenize" {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		streamHandler(stream).ServeHTTP(response, request)
	}
	firstServer := httptest.NewServer(http.HandlerFunc(backendHandler))
	secondServer := httptest.NewServer(http.HandlerFunc(backendHandler))
	t.Cleanup(firstServer.Close)
	t.Cleanup(secondServer.Close)
	firstBackend, err := NewBackend("backend-a", firstServer.URL, "generation-a")
	if err != nil {
		t.Fatal(err)
	}
	secondBackend, err := NewBackend("backend-b", secondServer.URL, "generation-b")
	if err != nil {
		t.Fatal(err)
	}
	backends := []*Backend{firstBackend, secondBackend}
	registry, err := NewRegistry(backends, &http.Client{Timeout: time.Second}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewBackendMetricsCollector(backends, &http.Client{Timeout: time.Second}, 100*time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	collector.states[firstBackend.ID].sample.Store(&backendLoadSample{collectedAt: time.Now(), running: 0})
	collector.states[firstBackend.ID].up.Store(true)
	collector.states[secondBackend.ID].sample.Store(&backendLoadSample{collectedAt: time.Now(), running: 2})
	collector.states[secondBackend.ID].up.Store(true)
	tenantRegistry := testTenantRegistry(t)
	coordinator, err := admission.NewMemoryCoordinator(100)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	router := newHashAffinityTestRouter(t, 1, 8, 0)
	tokenizer := newTestVLLMTokenizer(t, &http.Client{Timeout: time.Second}, 250*time.Millisecond, router.MaxTokenIDs())
	service, err := New(DefaultConfig(), registry, &http.Client{Timeout: time.Second}, slog.New(slog.NewJSONHandler(&logs, nil)),
		WithTenantRegistry(tenantRegistry), WithAdmissionCoordinator(coordinator),
		WithBackendMetricsCollector(collector), WithRouter(router), WithRoutingKeyTokenizer(tokenizer),
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.Handler())
	t.Cleanup(server.Close)
	response := requestGateway(t, server.Client(), server.URL)
	_, readErr := io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Inference-Backend") != firstBackend.ID {
		t.Fatalf("fallback response status=%d backend=%q; want least-loaded %s", response.StatusCode, response.Header.Get("X-Inference-Backend"), firstBackend.ID)
	}
	var terminal map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["msg"] == "request terminal" {
			terminal = entry
		}
	}
	if terminal == nil || terminal["router_policy"] != string(RoutingPolicyLeastLoaded) ||
		terminal["router_fallback_reason"] != string(FallbackReasonRoutingKeyUnavailable) || terminal["backend_generation"] != "generation-a" {
		t.Fatalf("terminal decision=%v; want least_loaded/routing_key_unavailable with selected generation", terminal)
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
	for _, expected := range []string{
		`inference_gateway_routing_decisions_total{policy="least_loaded",fallback_reason="routing_key_unavailable"} 1`,
		"inference_gateway_routing_tokenize_duration_seconds_count 1",
		"inference_gateway_routing_tokenize_failures_total 1",
		"inference_gateway_routing_lookup_duration_seconds_count 1",
		`inference_gateway_routing_tokenize_requests_total{backend_id="backend-a"} 1`,
		`inference_gateway_routing_tokenize_requests_total{backend_id="backend-b"} 1`,
	} {
		if !strings.Contains(string(metricsBody), expected) {
			t.Fatalf("metrics omitted %q:\n%s", expected, metricsBody)
		}
	}
}
