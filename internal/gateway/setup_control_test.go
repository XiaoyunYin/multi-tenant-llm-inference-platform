package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSetupControlsPinSlotLengthAndEOSWithoutChangingTrace(t *testing.T) {
	specs := []TenantSpec{{TenantID: "trace", CredentialSHA256: CredentialSHA256("trace"), Models: []string{"test-model"}, MaxRequestBytes: 4096, MaxOutputTokens: 1, RequestRateLimit: 1000, RateWindowMS: 1000, MaxConcurrent: 10}}
	for slot := range 2 {
		spec := specs[0]
		spec.TenantID = fmt.Sprintf("control-%d", slot)
		spec.CredentialSHA256 = CredentialSHA256(spec.TenantID)
		spec.SetupBackendID = fmt.Sprintf("backend-%d", slot)
		spec.MaxOutputTokens = 256
		specs = append(specs, spec)
	}
	tenants, err := NewTenantRegistry(specs, testCacheSaltSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	backend := func(slot int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body upstreamRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			want := 1
			if body.IgnoreEOS {
				want = 256
			}
			if body.MaxTokens == nil || *body.MaxTokens != want {
				t.Errorf("length clamped: %+v", body)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, roleEvent+contentEvent+finishEvent+usageEvent+doneEvent)
		})
	}
	g, server := newTestGatewayWithPolicies(t, DefaultConfig(), nil, tenants, backend(0), backend(1))
	post := func(credential, expected string, status int) {
		t.Helper()
		r, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"count"}],"stream":true,"max_tokens":256}`))
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Content-Type", "application/json")
		resp, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != status || resp.Header.Get("X-Inference-Backend") != expected {
			t.Fatalf("%s: status %d backend %q, want %d/%s", credential, resp.StatusCode, resp.Header.Get("X-Inference-Backend"), status, expected)
		}
	}
	// Arbitrary earlier routing advances RR parity. Fixed controls remain exact.
	for i := range 7 {
		post("trace", fmt.Sprintf("backend-%d", i%2), 200)
		post("control-0", "backend-0", 200)
		post("control-1", "backend-1", 200)
	}
	g.registry.Backends()[1].healthy.Store(false)
	post("control-0", "backend-0", 200)
	post("control-1", "", 503)
	g.registry.Backends()[1].healthy.Store(true)
	g.registry.Backends()[0].healthy.Store(false)
	post("control-1", "backend-1", 200)
	post("control-0", "", 503)
}
