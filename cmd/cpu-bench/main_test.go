package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDispatchModesRetainEveryArrivalAndNeverDispatchEarly(t *testing.T) {
	stream := `data: {"choices":[{"delta":{"content":"hello world"},"finish_reason":"stop"}]}` + "\n\n" + `data: {"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}` + "\n\n" + "data: [DONE]\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, stream)
	}))
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	for _, precise := range []bool{false, true} {
		rows, _ := openLoop(client, []string{server.URL, server.URL}, "measurement", 1000, .02, precise)
		if len(rows) != 20 {
			t.Fatalf("arrival loss: %d", len(rows))
		}
		for i, row := range rows {
			if row.Ordinal != i || row.Outcome != "completed" || row.DispatchNS < row.PlannedNS {
				t.Fatalf("arrival mismatch (precise=%v): %+v", precise, row)
			}
		}
	}
}

func TestCompletionRequiresEntireValidSSEAndEOF(t *testing.T) {
	stream := `data: {"choices":[{"delta":{"content":"hello world"},"finish_reason":"stop"}]}` + "\n\n" + `data: {"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}` + "\n\n" + "data: [DONE]\n\n"
	_, ok, _ := consume(strings.NewReader(stream))
	if !ok {
		t.Fatal("valid completion rejected")
	}
	for _, broken := range []string{strings.ReplaceAll(stream, "hello world", "truncated"), strings.ReplaceAll(stream, "data: [DONE]\n\n", ""), stream + "data: [DONE]\n\n", strings.ReplaceAll(stream, `"completion_tokens":2`, `"completion_tokens":1`), stream + "data: {\"error\":{}}\n\n"} {
		_, ok, _ := consume(strings.NewReader(broken))
		if ok {
			t.Fatal("false completion")
		}
	}
}

func TestPercentileUsesStatedPopulationTailRule(t *testing.T) {
	if quantile(make([]float64, 1999), .99) != nil || quantile(make([]float64, 39), .5) != nil {
		t.Fatal("underpowered percentile")
	}
	values := make([]float64, 2000)
	for i := range values {
		values[i] = float64(i + 1)
	}
	if quantile(values, .99) != float64(1980) {
		t.Fatal("nearest rank or sample boundary")
	}
}

func TestZeroRelativeDispatchIsStillDispatched(t *testing.T) {
	result := summary([]row{{Outcome: "completed", Status: 200, PlannedNS: 0, DispatchNS: 0, EndNS: 5000000, FirstContentNS: 5000000}})
	lag := result["dispatch_lag_ms"].(map[string]any)
	if lag["n"] != 1 || lag["min"] != float64(0) {
		t.Fatal("valid zero-offset dispatch omitted from denominator")
	}
}
