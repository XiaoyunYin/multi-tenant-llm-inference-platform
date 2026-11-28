package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"
)

func TestINF061StageCRedisArms(t *testing.T) {
	const global, bPeak = 20, 8
	for _, arm := range []struct {
		name, aCode, bCode string
		aOffers, aQuota    int
	}{
		{name: "b_alone", aQuota: 12},
		{name: "a_at_quota", aOffers: 12, aQuota: 12},
		{name: "a_flood_quota", aOffers: 20, aQuota: 12, aCode: "tenant_concurrency_limit"},
		{name: "a_flood_lifted", aOffers: 20, aQuota: 20, bCode: "system_capacity"},
	} {
		t.Run(arm.name, func(t *testing.T) {
			client, config := gatewayRedis(t)
			config.GlobalCapacity = global
			config.LeaseDuration = 30 * time.Second
			config.TombstoneTTL = time.Minute
			coordinator, err := admission.NewRedisCoordinator(client, config)
			if err != nil {
				t.Fatal(err)
			}
			spec := func(alias string, concurrency int) TenantSpec {
				return TenantSpec{
					TenantID: alias, CredentialSHA256: CredentialSHA256("inf061-fixture-" + alias),
					Models: []string{"test-model"}, MaxRequestBytes: 4096, MaxOutputTokens: 128,
					RequestRateLimit: 1000, RateWindowMS: 1000, MaxConcurrent: int64(concurrency),
				}
			}
			tenants, err := NewTenantRegistry([]TenantSpec{spec("a", arm.aQuota), spec("b", bPeak)}, testCacheSaltSecret(t))
			if err != nil {
				t.Fatal(err)
			}
			arrival := make(chan struct{}, global)
			release := make(chan struct{})
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					w.WriteHeader(200)
					return
				}
				arrival <- struct{}{}
				select {
				case <-release:
					streamHandler(contentEvent+finishEvent+usageEvent+doneEvent)(w, r)
				case <-r.Context().Done():
				}
			})
			_, server := newTestGatewayWithAdmission(t, DefaultConfig(), nil, tenants, coordinator, upstream)
			defer closeUnlessClosed(release)
			pending := make([]<-chan string, 0, global)
			offer := func(alias, code string) {
				result := make(chan string, 1)
				go func() {
					result <- inf061Offer(server.Client(), server.URL, alias)
				}()
				if code != "" {
					select {
					case got := <-result:
						if got != code {
							t.Fatalf("%s denial %q, want %q", alias, got, code)
						}
					case <-arrival:
						t.Fatalf("denied %s offer reached the backend", alias)
					case <-time.After(3 * time.Second):
						t.Fatalf("no response for denied %s offer", alias)
					}
					return
				}
				select {
				case <-arrival:
					pending = append(pending, result)
				case got := <-result:
					t.Fatalf("%s offer never dispatched: %q", alias, got)
				case <-time.After(3 * time.Second):
					t.Fatalf("no dispatch for %s", alias)
				}
			}
			for i := range arm.aOffers {
				code := ""
				if i >= arm.aQuota {
					code = arm.aCode
				}
				offer("a", code)
			}
			for range bPeak {
				offer("b", arm.bCode)
			}
			close(release)
			for _, result := range pending {
				select {
				case got := <-result:
					if got != "completed" {
						t.Fatal(got)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("admitted request did not complete")
				}
			}
			t.Logf("fixture: global=%d B_scheduled=%d A_scheduled=%d A_denial=%q B_denial=%q completed=%d",
				global, bPeak, arm.aOffers, arm.aCode, arm.bCode, len(pending))
		})
	}
}

func closeUnlessClosed(channel chan struct{}) {
	select {
	case <-channel:
	default:
		close(channel)
	}
}

func inf061Offer(client *http.Client, origin, alias string) string {
	body := bytes.NewBufferString(`{"model":"test-model","messages":[{"role":"user","content":"fixture"}],"stream":true}`)
	req, err := http.NewRequest("POST", origin+"/v1/chat/completions", body)
	if err != nil {
		return err.Error()
	}
	req.Header.Set("Authorization", "Bearer inf061-fixture-"+alias)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return err.Error()
	}
	defer response.Body.Close()
	if response.StatusCode == 200 {
		data, err := io.ReadAll(response.Body)
		if err == nil && strings.Contains(string(data), "data: [DONE]") {
			return "completed"
		}
		return "missing DONE"
	}
	if response.StatusCode != 429 {
		return fmt.Sprintf("unexpected HTTP %d", response.StatusCode)
	}
	var envelope struct {
		Error struct{ Code string } `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return err.Error()
	}
	return envelope.Error.Code
}
