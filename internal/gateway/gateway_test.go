package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	"multi-tenant-llm-inference-platform/internal/admission"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

const (
	testCredential  = "test-credential"
	testCacheSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	roleEvent       = `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}` + "\n\n"
	contentEvent    = `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}` + "\n\n"
	finishEvent     = `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n"
	usageEvent      = `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","model":"test-model","choices":[],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}` + "\n\n"
	doneEvent       = "data: [DONE]\n\n"
)

func testTenantRegistry(t *testing.T) *TenantRegistry {
	t.Helper()
	cacheSaltSecret := testCacheSaltSecret(t)
	registry, err := NewTenantRegistry([]TenantSpec{{
		TenantID: "tenant-test", CredentialSHA256: CredentialSHA256(testCredential),
		Models: []string{"test-model", "m"}, MaxRequestBytes: 1 << 20, MaxOutputTokens: 128,
		RequestRateLimit: 10_000, RateWindowMS: 1000, MaxConcurrent: 128,
	}}, cacheSaltSecret)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func testCacheSaltSecret(t *testing.T) CacheSaltSecret {
	t.Helper()
	secret, err := LoadCacheSaltSecret(strings.NewReader(testCacheSecret))
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func newTestGateway(t *testing.T, config Config, upstreams ...http.Handler) (*Gateway, *httptest.Server) {
	return newTestGatewayWithPolicies(t, config, nil, testTenantRegistry(t), upstreams...)
}

func newTestGatewayWithLogger(t *testing.T, config Config, logger *slog.Logger, upstreams ...http.Handler) (*Gateway, *httptest.Server) {
	return newTestGatewayWithPolicies(t, config, logger, testTenantRegistry(t), upstreams...)
}

func newTestGatewayWithPolicies(t *testing.T, config Config, logger *slog.Logger, tenants *TenantRegistry, upstreams ...http.Handler) (*Gateway, *httptest.Server) {
	coordinator, err := admission.NewMemoryCoordinator(10_000)
	if err != nil {
		t.Fatal(err)
	}
	return newTestGatewayWithAdmission(t, config, logger, tenants, coordinator, upstreams...)
}

func newTestGatewayWithAdmission(t *testing.T, config Config, logger *slog.Logger, tenants *TenantRegistry, coordinator admission.Coordinator, upstreams ...http.Handler) (*Gateway, *httptest.Server) {
	t.Helper()
	backends := make([]*Backend, 0, len(upstreams))
	servers := make([]*httptest.Server, 0, len(upstreams))
	for index, handler := range upstreams {
		server := httptest.NewServer(handler)
		servers = append(servers, server)
		backend, err := NewBackend(fmt.Sprintf("backend-%d", index), server.URL)
		if err != nil {
			t.Fatal(err)
		}
		backends = append(backends, backend)
	}
	t.Cleanup(func() {
		for _, server := range servers {
			server.Close()
		}
	})
	registry, err := NewRegistry(backends, &http.Client{Timeout: time.Second}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(config, registry, &http.Client{}, logger, WithTenantRegistry(tenants), WithAdmissionCoordinator(coordinator))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	t.Cleanup(server.Close)
	return gateway, server
}

func requestGateway(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	body := `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`
	return postBody(t, client, url, "application/json", body)
}

func postBody(t *testing.T, client *http.Client, url, contentType, body string) *http.Response {
	return postBytes(t, client, url, contentType, []byte(body))
}

func postBytes(t *testing.T, client *http.Client, url, contentType string, body []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Authorization", "Bearer "+testCredential)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func streamHandler(stream string) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/health" {
			response.WriteHeader(http.StatusOK)
			return
		}
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, stream)
	}
}

func TestGatewayStreamsBeforeCompletionAndAddsUsageProvenance(t *testing.T) {
	release := make(chan struct{})
	firstSent := make(chan struct{})
	upstream := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode upstream request: %v", err)
		}
		options := body["stream_options"].(map[string]any)
		if options["include_usage"] != true {
			t.Error("gateway did not request upstream usage")
		}
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent)
		response.(http.Flusher).Flush()
		close(firstSent)
		<-release
		_, _ = io.WriteString(response, contentEvent+finishEvent+usageEvent+doneEvent)
	})
	gateway, server := newTestGateway(t, DefaultConfig(), upstream)

	response := requestGateway(t, server.Client(), server.URL)
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	<-firstSent
	select {
	case <-release:
		t.Fatal("backend unexpectedly completed")
	default:
	}
	close(release)
	remainder, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	body := first + string(remainder)

	if response.StatusCode != http.StatusOK || response.Header.Get("X-Inference-Backend") != "backend-0" {
		t.Fatalf("unexpected response identity: %d %q", response.StatusCode, response.Header.Get("X-Inference-Backend"))
	}
	if response.Header.Get("X-Request-ID") == "" || response.Header.Get("X-Trace-ID") == "" {
		t.Fatal("request or trace correlation header missing")
	}
	if !strings.Contains(body, `"count_source":"runtime_usage"`) || !strings.Contains(body, "[DONE]") {
		t.Fatalf("missing usage provenance or completion: %s", body)
	}
	if snapshot := gateway.Metrics(); snapshot.Completed != 1 || snapshot.Active != 0 {
		t.Fatalf("unexpected metrics: %+v", snapshot)
	}
}

func TestGatewayPropagatesW3CTraceContextUpstream(t *testing.T) {
	previousPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(previousPropagator) })
	const traceParent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	type observedTraceContext struct {
		traceparent string
		baggage     string
		tracestate  string
	}
	observed := make(chan observedTraceContext, 1)
	upstream := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observed <- observedTraceContext{
			traceparent: request.Header.Get("traceparent"),
			baggage:     request.Header.Get("baggage"),
			tracestate:  request.Header.Get("tracestate"),
		}
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent+finishEvent+usageEvent+doneEvent)
	})
	_, server := newTestGateway(t, DefaultConfig(), upstream)
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testCredential)
	request.Header.Set("traceparent", traceParent)
	request.Header.Set("baggage", "tenant_id=tenant-b,client=true")
	request.Header.Set("tracestate", "evil=1")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	serverTraceID := response.Header.Get("X-Trace-ID")
	if response.StatusCode != http.StatusOK || serverTraceID == "" || serverTraceID == "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace response mismatch: status=%d trace=%q", response.StatusCode, response.Header.Get("X-Trace-ID"))
	}
	propagated := <-observed
	parts := strings.Split(propagated.traceparent, "-")
	if len(parts) != 4 || parts[1] != serverTraceID || propagated.traceparent == traceParent {
		t.Fatalf("gateway did not propagate its server-owned trace context: %+v, server=%q", propagated, serverTraceID)
	}
	if propagated.baggage != "" || propagated.tracestate != "" {
		t.Fatalf("untrusted client trace metadata crossed the backend boundary: %+v", propagated)
	}
}

func TestGatewayUnauthenticatedTraceContextIsServerOwned(t *testing.T) {
	const clientTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	upstream := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		t.Fatal("unauthenticated request reached the backend")
	})
	_, server := newTestGateway(t, DefaultConfig(), upstream)
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("traceparent", "00-"+clientTraceID+"-00f067aa0ba902b7-01")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("X-Trace-ID") == clientTraceID || response.Header.Get("X-Trace-ID") == "" {
		t.Fatalf("unauthenticated trace context was trusted: status=%d trace=%q", response.StatusCode, response.Header.Get("X-Trace-ID"))
	}
}

func TestGatewayPreCommitProtocolFailuresReturnJSON(t *testing.T) {
	oversized := "data: " + strings.Repeat("x", 256) + "\n\n"
	cases := []struct {
		name        string
		contentType string
		stream      string
		maxEvent    int
	}{
		{name: "malformed first item", contentType: "text/event-stream", stream: "data: {not-json}\n\n", maxEvent: 1024},
		{name: "invalid first item", contentType: "text/event-stream", stream: `data: {"object":"wrong","choices":[]}` + "\n\n", maxEvent: 1024},
		{name: "invalid first role", contentType: "text/event-stream", stream: strings.Replace(roleEvent, `"assistant"`, `"user"`, 1), maxEvent: 1024},
		{name: "unsupported non-null delta", contentType: "text/event-stream", stream: strings.Replace(roleEvent, `"role":"assistant"`, `"role":"assistant","tool_calls":[]`, 1), maxEvent: 1024},
		{name: "duplicate first member", contentType: "text/event-stream", stream: strings.Replace(roleEvent, `"object":`, `"object":"chat.completion.chunk","object":`, 1), maxEvent: 1024},
		{name: "invalid content type", contentType: "application/json", stream: `{}`, maxEvent: 1024},
		{name: "oversized event", contentType: "text/event-stream", stream: oversized, maxEvent: 64},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			upstream := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", testCase.contentType)
				_, _ = io.WriteString(response, testCase.stream)
			})
			config := DefaultConfig()
			config.MaxEventBytes = testCase.maxEvent
			_, server := newTestGateway(t, config, upstream)
			response := requestGateway(t, server.Client(), server.URL)
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusBadGateway || !bytes.Contains(body, []byte("upstream_protocol_error")) {
				t.Fatalf("unexpected response: %d %s", response.StatusCode, body)
			}
		})
	}
}

func TestGatewayNormalizesVLLMCompatibleFraming(t *testing.T) {
	role := strings.Replace(roleEvent, `data: `, `data:`, 1)
	role = strings.Replace(role, `"role":"assistant"`, `"role":"assistant","content":"","refusal":null`, 1)
	finishWithContent := `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":{"content":" final","refusal":null},"logprobs":null,"finish_reason":"stop","stop_reason":null}]}` + "\n\n"
	stream := ": keepalive\n\n" + role + finishWithContent + usageEvent + doneEvent
	gateway, server := newTestGateway(t, DefaultConfig(), streamHandler(stream))
	response := requestGateway(t, server.Client(), server.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("[DONE]")) {
		t.Fatalf("vLLM-shaped stream failed: %d %s", response.StatusCode, body)
	}
	var chunks []map[string]any
	for _, line := range bytes.Split(body, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("data: ")) || bytes.Equal(line, []byte("data: [DONE]")) {
			continue
		}
		var chunk map[string]any
		if err := json.Unmarshal(bytes.TrimPrefix(line, []byte("data: ")), &chunk); err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, chunk)
	}
	if len(chunks) != 4 {
		t.Fatalf("expected role, content, canonical finish, and usage chunks: %s", body)
	}
	contentChoice := chunks[1]["choices"].([]any)[0].(map[string]any)
	finishChoice := chunks[2]["choices"].([]any)[0].(map[string]any)
	if contentChoice["finish_reason"] != nil || contentChoice["delta"].(map[string]any)["content"] != " final" {
		t.Fatalf("combined content was not preserved: %#v", contentChoice)
	}
	if finishChoice["finish_reason"] != "stop" || len(finishChoice["delta"].(map[string]any)) != 0 {
		t.Fatalf("finish was not canonicalized: %#v", finishChoice)
	}
	if gateway.Metrics().Completed != 1 {
		t.Fatalf("vLLM-shaped stream not completed: %+v", gateway.Metrics())
	}
}

func TestGatewayDropsUpstreamOnlyFields(t *testing.T) {
	fixture, err := os.ReadFile("testdata/vllm-0.29.0-stream.sse")
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	for _, line := range strings.Split(string(fixture), "\n") {
		if strings.HasPrefix(line, "data: ") {
			events = append(events, line)
		}
	}
	stream := strings.Join(events, "\n\n") + "\n\n"
	_, server := newTestGateway(t, DefaultConfig(), streamHandler(stream))
	response := requestGateway(t, server.Client(), server.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("[DONE]")) {
		t.Fatalf("upstream-only field stream failed: %d %s", response.StatusCode, body)
	}
	requestID := response.Header.Get("X-Request-ID")
	if requestID == "" {
		t.Fatal("gateway did not return a request id")
	}
	for _, line := range bytes.Split(body, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("data: ")) || bytes.Equal(line, []byte("data: [DONE]")) {
			continue
		}
		var chunk map[string]any
		if err := json.Unmarshal(bytes.TrimPrefix(line, []byte("data: ")), &chunk); err != nil {
			t.Fatal(err)
		}
		if got, want := chunk["id"], "chatcmpl_"+requestID; got != want {
			t.Fatalf("stream chunk id was not gateway-owned: got %#v want %q", got, want)
		}
		if got, want := chunk["model"], "test-model"; got != want {
			t.Fatalf("stream chunk model leaked upstream identity: got %#v want %q", got, want)
		}
		for key := range chunk {
			switch key {
			case "id", "object", "created", "model", "choices", "usage":
			default:
				t.Fatalf("upstream-only top-level field leaked: %q in %#v", key, chunk)
			}
		}
		if usage, ok := chunk["usage"].(map[string]any); ok {
			for key := range usage {
				if key != "prompt_tokens" && key != "completion_tokens" && key != "total_tokens" && key != "count_source" {
					t.Fatalf("upstream-only usage field leaked: %q in %#v", key, usage)
				}
			}
		}
		if choices, ok := chunk["choices"].([]any); ok && len(choices) == 1 {
			choice := choices[0].(map[string]any)
			for key := range choice {
				if key != "index" && key != "delta" && key != "finish_reason" {
					t.Fatalf("upstream-only choice field leaked: %q in %#v", key, choice)
				}
			}
		}
	}
}

func TestGatewayRejectsInvalidPublicRequestsBeforeUpstream(t *testing.T) {
	var contacts atomic.Int32
	upstream := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		contacts.Add(1)
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent+finishEvent+usageEvent+doneEvent)
	})
	config := DefaultConfig()
	config.MaxRequestBytes = 128
	_, server := newTestGateway(t, config, upstream)
	cases := []struct {
		name        string
		contentType string
		body        string
		status      int
		code        string
	}{
		{name: "wrong media type", contentType: "text/plain", body: `{}`, status: 415, code: "unsupported_media_type"},
		{name: "unknown field", contentType: "application/json", body: `{"model":"m","messages":[{"role":"user","content":"x"}],"stream":true,"foo":1}`, status: 400, code: "invalid_request"},
		{name: "recognized unsupported field", contentType: "application/json", body: `{"model":"m","messages":[{"role":"user","content":"x"}],"stream":true,"n":2}`, status: 400, code: "unsupported_parameter"},
		{name: "client cache salt", contentType: "application/json", body: `{"model":"m","messages":[{"role":"user","content":"x"}],"stream":true,"cache_salt":"attacker-controlled"}`, status: 400, code: "unsupported_parameter"},
		{name: "duplicate field", contentType: "application/json", body: `{"model":"m","model":"other","messages":[{"role":"user","content":"x"}],"stream":true}`, status: 400, code: "invalid_request"},
		{name: "too large", contentType: "application/json", body: `{"model":"` + strings.Repeat("x", 200) + `","messages":[],"stream":true}`, status: 413, code: "request_too_large"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			response := postBody(t, server.Client(), server.URL, testCase.contentType, testCase.body)
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != testCase.status || !bytes.Contains(body, []byte(testCase.code)) {
				t.Fatalf("unexpected rejection: %d %s", response.StatusCode, body)
			}
		})
	}
	if contacts.Load() != 0 {
		t.Fatalf("invalid requests contacted upstream %d times", contacts.Load())
	}
	invalidUTF8 := []byte(`{"model":"m","messages":[{"role":"user","content":"`)
	invalidUTF8 = append(invalidUTF8, 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}],"stream":true}`)...)
	response := postBytes(t, server.Client(), server.URL, "application/json", invalidUTF8)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || !bytes.Contains(body, []byte("invalid_request")) {
		t.Fatalf("invalid UTF-8 accepted: %d %s", response.StatusCode, body)
	}
}

func TestGatewayFirstItemAndIdleTimeouts(t *testing.T) {
	cases := []struct {
		name         string
		writeFirst   bool
		delayHeaders bool
	}{
		{name: "first item timeout"},
		{name: "response header timeout", delayHeaders: true},
		{name: "idle timeout after commitment", writeFirst: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			upstream := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if testCase.delayHeaders {
					time.Sleep(75 * time.Millisecond)
					response.WriteHeader(http.StatusOK)
					return
				}
				response.Header().Set("Content-Type", "text/event-stream")
				response.WriteHeader(http.StatusOK)
				response.(http.Flusher).Flush()
				if testCase.writeFirst {
					_, _ = io.WriteString(response, roleEvent)
					response.(http.Flusher).Flush()
				}
				<-request.Context().Done()
			})
			config := DefaultConfig()
			config.FirstItemTimeout = 25 * time.Millisecond
			config.StreamIdleTimeout = 25 * time.Millisecond
			gateway, server := newTestGateway(t, config, upstream)
			response := requestGateway(t, server.Client(), server.URL)
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if testCase.writeFirst {
				if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("event: error")) {
					t.Fatalf("idle timeout mismatch: %d %s", response.StatusCode, body)
				}
			} else if response.StatusCode != http.StatusGatewayTimeout || !bytes.Contains(body, []byte("upstream_timeout")) {
				t.Fatalf("first timeout mismatch: %d %s", response.StatusCode, body)
			}
			snapshot := gateway.Metrics()
			if snapshot.Timeouts != 1 || snapshot.Terminals["timeout"] != 1 {
				t.Fatalf("timeout terminal was not classified: %+v", snapshot)
			}
		})
	}
}

func TestGatewayNoHealthyBackend(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/health" {
			response.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer upstream.Close()
	backend, _ := NewBackend("unhealthy", upstream.URL)
	registry, _ := NewRegistry([]*Backend{backend}, upstream.Client(), time.Second)
	registry.Poll(context.Background())
	coordinator, _ := admission.NewMemoryCoordinator(10_000)
	gateway, _ := New(DefaultConfig(), registry, &http.Client{}, nil, WithTenantRegistry(testTenantRegistry(t)), WithAdmissionCoordinator(coordinator))
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	response := requestGateway(t, server.Client(), server.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || !bytes.Contains(body, []byte("no_healthy_backend")) {
		t.Fatalf("unexpected no-backend response: %d %s", response.StatusCode, body)
	}
	ready, err := server.Client().Get(server.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	ready.Body.Close()
	if ready.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("gateway remained ready without a healthy backend: %d", ready.StatusCode)
	}
}

func TestGatewayCommittedFailuresEmitErrorWithoutDone(t *testing.T) {
	cases := []struct {
		name   string
		stream string
	}{
		{name: "malformed", stream: roleEvent + "data: {not-json}\n\n"},
		{name: "truncated", stream: roleEvent + contentEvent},
		{name: "missing usage", stream: roleEvent + finishEvent + doneEvent},
		{name: "upstream provenance", stream: roleEvent + finishEvent + strings.Replace(usageEvent, `"total_tokens":5`, `"total_tokens":5,"count_source":"untrusted"`, 1) + doneEvent},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			gateway, server := newTestGateway(t, DefaultConfig(), streamHandler(testCase.stream))
			response := requestGateway(t, server.Client(), server.URL)
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("event: error")) || bytes.Contains(body, []byte("[DONE]")) {
				t.Fatalf("unexpected committed failure: %d %s", response.StatusCode, body)
			}
			if gateway.Metrics().Partial != 1 {
				t.Fatalf("partial metric not recorded: %+v", gateway.Metrics())
			}
			expectedCause := "upstream_protocol_error"
			if testCase.name == "truncated" {
				expectedCause = "stream_interrupted"
			}
			if gateway.Metrics().Terminals[expectedCause] != 1 {
				t.Fatalf("committed failure cause mismatch: %+v", gateway.Metrics())
			}
		})
	}
}

func TestGatewayAllowsEmptySuccessfulCompletion(t *testing.T) {
	stream := roleEvent + finishEvent + usageEvent + doneEvent
	gateway, server := newTestGateway(t, DefaultConfig(), streamHandler(stream))
	response := requestGateway(t, server.Client(), server.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("[DONE]")) || bytes.Contains(body, []byte(`"content"`)) {
		t.Fatalf("empty completion mismatch: %d %s", response.StatusCode, body)
	}
	if gateway.Metrics().Completed != 1 {
		t.Fatalf("empty completion not counted: %+v", gateway.Metrics())
	}
}

func TestRegistryRoundRobinAndHealth(t *testing.T) {
	healthy := streamHandler(roleEvent + finishEvent + usageEvent + doneEvent)
	unhealthy := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/health" {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		healthy(response, request)
	})
	first := httptest.NewServer(healthy)
	second := httptest.NewServer(unhealthy)
	defer first.Close()
	defer second.Close()
	firstBackend, _ := NewBackend("first", first.URL)
	secondBackend, _ := NewBackend("second", second.URL)
	registry, _ := NewRegistry([]*Backend{firstBackend, secondBackend}, &http.Client{Timeout: time.Second}, time.Second)
	if selected, _ := registry.Select(); selected.ID != "first" {
		t.Fatal("first round-robin selection mismatch")
	}
	if selected, _ := registry.Select(); selected.ID != "second" {
		t.Fatal("second round-robin selection mismatch")
	}
	registry.Poll(context.Background())
	for range 4 {
		selected, err := registry.Select()
		if err != nil || selected.ID != "first" {
			t.Fatalf("unhealthy backend selected: %v %v", selected, err)
		}
	}
}

func TestRegistryRejectsDuplicateURLsAndHealthIdentityMismatch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/health" {
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"backend_id":"actual-backend","healthy":true}`)
			return
		}
	}))
	defer upstream.Close()
	first, _ := NewBackend("configured-backend", upstream.URL)
	duplicate, _ := NewBackend("other-backend", upstream.URL)
	if _, err := NewRegistry([]*Backend{first, duplicate}, upstream.Client(), time.Second); err == nil {
		t.Fatal("duplicate backend URL was accepted")
	}
	registry, err := NewRegistry([]*Backend{first}, upstream.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	registry.Poll(context.Background())
	if first.Healthy() {
		t.Fatal("health identity mismatch remained healthy")
	}
}

func TestGatewayRejectsUpstreamIdentityMismatch(t *testing.T) {
	upstream := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		response.Header().Set("X-Inference-Backend", "unexpected")
		_, _ = io.WriteString(response, roleEvent+finishEvent+usageEvent+doneEvent)
	})
	_, server := newTestGateway(t, DefaultConfig(), upstream)
	response := requestGateway(t, server.Client(), server.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || !bytes.Contains(body, []byte("upstream_protocol_error")) {
		t.Fatalf("identity mismatch was accepted: %d %s", response.StatusCode, body)
	}
}

func TestGatewayCancellationReachesUpstream(t *testing.T) {
	cancelled := make(chan struct{})
	var once sync.Once
	var logs bytes.Buffer
	upstream := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent)
		response.(http.Flusher).Flush()
		<-request.Context().Done()
		once.Do(func() { close(cancelled) })
	})
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	gateway, server := newTestGatewayWithLogger(t, DefaultConfig(), logger, upstream)
	ctx, cancel := context.WithCancel(context.Background())
	body := strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/chat/completions", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testCredential)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(response.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	cancel()
	response.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("upstream did not observe cancellation")
	}
	deadline := time.Now().Add(time.Second)
	for gateway.Metrics().Terminals["client_cancelled"] != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshot := gateway.Metrics()
	if snapshot.Cancelled != 1 || snapshot.Failed != 0 || snapshot.Partial != 0 || snapshot.Terminals["client_cancelled"] != 1 {
		t.Fatalf("client cancellation was misclassified: %+v", snapshot)
	}
	if !bytes.Contains(logs.Bytes(), []byte(`"cause":"client_cancelled"`)) || !bytes.Contains(logs.Bytes(), []byte(`"backend_id":"backend-0"`)) {
		t.Fatalf("client cancellation terminal log missing correlation: %s", logs.String())
	}
}

func TestGatewayShutdownGraceExpiryCancelsAndWaits(t *testing.T) {
	cancelled := make(chan struct{})
	upstream := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent)
		response.(http.Flusher).Flush()
		<-request.Context().Done()
		close(cancelled)
	})
	gateway, server := newTestGateway(t, DefaultConfig(), upstream)
	response := requestGateway(t, server.Client(), server.URL)
	result, err := gateway.Shutdown(20*time.Millisecond, time.Second)
	if err != nil || !result.GraceExpired {
		t.Fatalf("shutdown result mismatch: %+v %v", result, err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	select {
	case <-cancelled:
	default:
		t.Fatal("shutdown returned before upstream cancellation")
	}
	if !bytes.Contains(body, []byte("event: error")) || !bytes.Contains(body, []byte("gateway shutting down")) || bytes.Contains(body, []byte("[DONE]")) {
		t.Fatalf("shutdown stream mismatch: %s", body)
	}
	if snapshot := gateway.Metrics(); snapshot.Active != 0 || snapshot.Terminals["shutdown"] != 1 {
		t.Fatalf("shutdown left active ownership: %+v", snapshot)
	}
}

func TestGatewayTotalTimeoutInterruptsActiveStream(t *testing.T) {
	upstream := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent)
		response.(http.Flusher).Flush()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-request.Context().Done():
				return
			case <-ticker.C:
				_, _ = io.WriteString(response, contentEvent)
				response.(http.Flusher).Flush()
			}
		}
	})
	config := DefaultConfig()
	config.TotalTimeout = 40 * time.Millisecond
	config.StreamIdleTimeout = time.Second
	_, server := newTestGateway(t, config, upstream)
	response := requestGateway(t, server.Client(), server.URL)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("event: error")) || bytes.Contains(body, []byte("[DONE]")) {
		t.Fatalf("total timeout mismatch: %d %s", response.StatusCode, body)
	}
}

func TestGatewayBoundsConcurrentRequestsAndDrains(t *testing.T) {
	release := make(chan struct{})
	upstream := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent)
		response.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(response, finishEvent+usageEvent+doneEvent)
	})
	config := DefaultConfig()
	config.MaxConcurrent = 1
	gateway, server := newTestGateway(t, config, upstream)
	first := requestGateway(t, server.Client(), server.URL)
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	invalid := postBody(t, server.Client(), server.URL, "application/json", `{}`)
	invalidBody, _ := io.ReadAll(invalid.Body)
	invalid.Body.Close()
	if invalid.StatusCode != http.StatusBadRequest || !bytes.Contains(invalidBody, []byte("invalid_request")) {
		t.Fatalf("invalid request was masked by capacity: %d %s", invalid.StatusCode, invalidBody)
	}
	wrongMedia := postBody(t, server.Client(), server.URL, "text/plain", `{}`)
	wrongMedia.Body.Close()
	if wrongMedia.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("media error was masked by capacity: %d", wrongMedia.StatusCode)
	}
	second := requestGateway(t, server.Client(), server.URL)
	secondBody, _ := io.ReadAll(second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests || !bytes.Contains(secondBody, []byte("gateway_capacity")) {
		t.Fatalf("capacity was not bounded: %d %s", second.StatusCode, secondBody)
	}
	close(release)
	released = true
	_, _ = io.Copy(io.Discard, first.Body)
	first.Body.Close()
	gateway.SetDraining(true)
	draining := requestGateway(t, server.Client(), server.URL)
	drainingBody, _ := io.ReadAll(draining.Body)
	draining.Body.Close()
	if draining.StatusCode != http.StatusServiceUnavailable || !bytes.Contains(drainingBody, []byte("shutting_down")) {
		t.Fatalf("draining response mismatch: %d %s", draining.StatusCode, drainingBody)
	}
	if snapshot := gateway.Metrics(); snapshot.Active != 0 || snapshot.Rejected != 4 {
		t.Fatalf("resources did not reconcile: %+v", snapshot)
	}
}

func TestGatewaySoakLeavesNoActiveRequests(t *testing.T) {
	stream := roleEvent + contentEvent + finishEvent + usageEvent + doneEvent
	gateway, server := newTestGateway(t, DefaultConfig(), streamHandler(stream))
	client := server.Client()
	for range 200 {
		response := requestGateway(t, client, server.URL)
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("soak request failed: %d", response.StatusCode)
		}
	}
	snapshot := gateway.Metrics()
	if snapshot.Active != 0 || snapshot.Completed != 200 || snapshot.Failed != 0 {
		t.Fatalf("soak resources did not reconcile: %+v", snapshot)
	}
	metrics, err := client.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metricsBody, _ := io.ReadAll(metrics.Body)
	metrics.Body.Close()
	if !bytes.Contains(metricsBody, []byte("inference_gateway_completed_total 200")) {
		t.Fatalf("metrics endpoint missing completion count: %s", metricsBody)
	}
	if !bytes.Contains(metricsBody, []byte("# TYPE inference_gateway_terminal_total counter")) || !bytes.Contains(metricsBody, []byte("# HELP inference_gateway_backend_metrics_fresh")) {
		t.Fatalf("metrics endpoint missing Prometheus metadata: %s", metricsBody)
	}
}

type deadlineWriter struct {
	header   http.Header
	deadline time.Time
	writeErr error
}

func (w *deadlineWriter) Header() http.Header { return w.header }
func (w *deadlineWriter) WriteHeader(int)     {}
func (w *deadlineWriter) Write(payload []byte) (int, error) {
	return len(payload), w.writeErr
}
func (w *deadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}
func (w *deadlineWriter) FlushError() error { return nil }

func TestGatewayAppliesClientWriteDeadline(t *testing.T) {
	writeErr := errors.New("slow client")
	writer := &deadlineWriter{header: make(http.Header), writeErr: writeErr}
	config := DefaultConfig()
	config.ClientWriteTimeout = 50 * time.Millisecond
	gateway := &Gateway{config: config}
	started := time.Now()
	err := gateway.writeRaw(writer, []byte("payload"))
	if !errors.Is(err, writeErr) {
		t.Fatalf("write error not returned: %v", err)
	}
	if writer.deadline.Before(started.Add(40*time.Millisecond)) || writer.deadline.After(started.Add(200*time.Millisecond)) {
		t.Fatalf("write deadline not applied: %v", writer.deadline)
	}
}

func TestHTTPServerGracefulShutdownWaitsForActiveStream(t *testing.T) {
	release := make(chan struct{})
	upstream := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent)
		response.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(response, finishEvent+usageEvent+doneEvent)
	})
	gateway, _ := newTestGateway(t, DefaultConfig(), upstream)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: gateway.Handler()}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	response := requestGateway(t, &http.Client{}, "http://"+listener.Addr().String())
	gateway.SetDraining(true)
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- server.Shutdown(context.Background()) }()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before stream drained: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if err := <-shutdownDone; err != nil {
		t.Fatal(err)
	}
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("unexpected serve result: %v", err)
	}
}
