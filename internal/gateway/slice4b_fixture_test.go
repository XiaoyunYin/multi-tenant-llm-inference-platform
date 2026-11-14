package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Capture only the gateway's client response, including its usage provenance and
// interruption event. Future runs compare every byte except generated request IDs.
func TestGatewaySlice4bClientFixtures(t *testing.T) {
	captured := map[string]string{}
	for _, name := range []string{"complete", "interrupted"} {
		upstream := roleEvent + contentEvent
		if name == "complete" {
			upstream += finishEvent + usageEvent + doneEvent
		}
		_, server := newTestGateway(t, DefaultConfig(), streamHandler(upstream))
		response := requestGateway(t, server.Client(), server.URL)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("%s response: status=%d err=%v", name, response.StatusCode, err)
		}
		captured[name] = string(body)
		captured[name+"_request_id"] = response.Header.Get("X-Request-ID")
		if captured[name+"_request_id"] == "" {
			t.Fatal("missing gateway-owned request identity")
		}
	}
	if !strings.Contains(captured["complete"], "\"count_source\":\"runtime_usage\"") ||
		!strings.HasSuffix(captured["complete"], doneEvent) ||
		!strings.Contains(captured["interrupted"], "event: error\n") ||
		!strings.Contains(captured["interrupted"], "\"code\":\"stream_interrupted\"") ||
		strings.Contains(captured["interrupted"], "[DONE]") {
		t.Fatalf("incorrect client contract: %+v", captured)
	}
	if output := os.Getenv("INF037B_GATEWAY_SSE_CAPTURE"); output != "" {
		data, err := json.MarshalIndent(captured, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "python", "tests", "fixtures", "inf037b_gateway_sse.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]string
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"complete", "interrupted"} {
		actual := strings.ReplaceAll(captured[name], captured[name+"_request_id"], fixture[name+"_request_id"])
		if actual != fixture[name] {
			t.Fatalf("%s gateway bytes differ from the slice4b fixture:\n%s", name, actual)
		}
	}
}
