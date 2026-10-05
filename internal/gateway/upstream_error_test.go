package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeErrorShapesKeepSanitizedTerminalMetadata(t *testing.T) {
	body := `{"error":{"message":"sensitive-upstream-message","type":"Service Unavailable","code":503,"param":null}}`
	for _, tc := range []struct {
		name, stream, shape, terminal string
		status, client                int
	}{
		{"http", body, "http_error", "upstream_failure", 503, 502},
		{"sse-before", "data: " + body + "\n\n" + doneEvent, "sse_error", "upstream_protocol_error", 200, 502},
		{"sse-after", contentEvent + "data: " + body + "\n\n" + doneEvent, "sse_error", "stream_interrupted", 200, 200},
		{"malformed", "data: {broken\n\n", "", "upstream_protocol_error", 200, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.stream)
			})
			_, server := newTestGatewayWithLogger(t, DefaultConfig(), slog.New(slog.NewJSONHandler(&logs, nil)), upstream)
			response := requestGateway(t, server.Client(), server.URL)
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != tc.client {
				t.Fatalf("status %d; body %s", response.StatusCode, data)
			}
			// The owner-release log follows the client response; wait for accounting via HTTP
			// handler completion rather than racing the buffer. Server.Close waits for handlers.
			server.Close()
			if strings.Contains(logs.String(), "sensitive-upstream-message") {
				t.Fatal("upstream text leaked")
			}
			var terminal map[string]any
			for _, line := range strings.Split(logs.String(), "\n") {
				var row map[string]any
				if json.Unmarshal([]byte(line), &row) == nil && row["msg"] == "request terminal" {
					terminal = row
				}
			}
			if terminal["code"] != tc.terminal || terminal["upstream_error_shape"] != tc.shape {
				t.Fatalf("terminal %v", terminal)
			}
			if tc.shape != "" && (terminal["upstream_error_code"] != float64(503) || terminal["upstream_error_type"] != "Service Unavailable") {
				t.Fatalf("native metadata %v", terminal)
			}
		})
	}
}

func TestHealthPollLogsTimeoutLatencyAndRecoveryWithoutAddress(t *testing.T) {
	var slow atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slow.Load() {
			time.Sleep(80 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"healthy":true,"ready":true}`)
	}))
	defer server.Close()
	backend, err := NewBackend("health-fixture", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]*Backend{backend}, &http.Client{Timeout: 30 * time.Millisecond}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	registry.SetHealthLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	registry.Poll(context.Background())
	slow.Store(true)
	registry.Poll(context.Background())
	slow.Store(false)
	registry.Poll(context.Background())
	rows := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(rows) != 3 || strings.Contains(logs.String(), server.URL) {
		t.Fatalf("health log %s", logs.String())
	}
	for i, line := range rows {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if i == 1 && (row["healthy_before"] != true || row["healthy_after"] != false || row["error_class"] != "transport" || row["latency_ms"].(float64) < 20) {
			t.Fatalf("timeout row %v", row)
		}
		if i == 2 && (row["healthy_before"] != false || row["healthy_after"] != true) {
			t.Fatalf("recovery row %v", row)
		}
	}
}

func TestNativeErrorMetadataRejectsArbitraryTypesDuplicatesAndOversize(t *testing.T) {
	for _, body := range []string{`{"error":{"code":503,"type":"secret-host-name"}}`, `{"error":{"code":503,"code":500,"type":"Service Unavailable"}}`, strings.Repeat("x", 8193)} {
		code, kind := nativeErrorMetadata([]byte(body))
		if code != 0 || kind != "" {
			t.Fatalf("accepted %d/%s", code, kind)
		}
	}
}
