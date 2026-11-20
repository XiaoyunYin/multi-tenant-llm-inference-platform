package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"multi-tenant-llm-inference-platform/internal/admission"
)

func gatewayRedis(t *testing.T) (*redis.Client, admission.RedisConfig) {
	t.Helper()
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("REDIS_TEST_ADDR is required for the shared Redis fixture")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, Protocol: 2, MaxRetries: -1, ReadTimeout: time.Second, WriteTimeout: time.Second, ContextTimeoutEnabled: true})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	namespace := fmt.Sprintf("test:gateway:%x", time.Now().UnixNano())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		keys, err := client.Keys(ctx, namespace+":*").Result()
		if err == nil && len(keys) > 0 {
			err = client.Del(ctx, keys...).Err()
		}
		if err != nil {
			t.Error(err)
		}
		client.Close()
	})
	return client, admission.RedisConfig{Namespace: namespace, GlobalCapacity: 20, LeaseDuration: time.Second, TombstoneTTL: 2 * time.Second}
}

func managedFixture(t *testing.T) (*redis.Client, *CredentialStore, *TenantRegistry, *admission.RedisCoordinator, *admission.RedisCoordinator) {
	t.Helper()
	client, config := gatewayRedis(t)
	config.ManagedCredentials = true
	first, err := admission.NewRedisCoordinator(client, config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := admission.NewRedisCoordinator(client, config)
	if err != nil {
		t.Fatal(err)
	}
	store := NewCredentialStore(client, first)
	specs := []TenantSpec{
		{TenantID: "tenant-a", SetupBackendID: "backend-0", Models: []string{"test-model"}, MaxRequestBytes: 4096, MaxOutputTokens: 128, RequestRateLimit: 20, RateWindowMS: 60000, MaxConcurrent: 2},
		{TenantID: "tenant-b", SetupBackendID: "backend-1", Models: []string{"test-model", "private-model"}, MaxRequestBytes: 4096, MaxOutputTokens: 128, RequestRateLimit: 20, RateWindowMS: 60000, MaxConcurrent: 2},
	}
	registry, err := newTenantRegistry(specs, testCacheSaltSecret(t), store)
	if err != nil {
		t.Fatal(err)
	}
	return client, store, registry, first, second
}

func issueTestKey(t *testing.T, store *CredentialStore, tenant string) string {
	t.Helper()
	value, err := store.issueFixture(context.Background(), tenant, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestIssueStoresSaltedVerifier(t *testing.T) {
	client, store, registry, coordinator, _ := managedFixture(t)
	key := issueTestKey(t, store, "tenant-a")
	secondKey := issueTestKey(t, store, "tenant-a")
	id, secret, _ := strings.Cut(key, ".")
	secondID, _, _ := strings.Cut(secondKey, ".")
	row, err := client.HGetAll(context.Background(), coordinator.CredentialKey(id)).Result()
	if err != nil {
		t.Fatal(err)
	}
	secondSalt, err := client.HGet(context.Background(), coordinator.CredentialKey(secondID), "salt").Result()
	if err != nil {
		t.Fatal(err)
	}
	if row["key_id"] != id || row["tenant"] != "tenant-a" || row["role"] != "inference" ||
		row["generation"] != "1" || row["revoked_ms"] != "0" || row["active_ms"] == "" || row["expiry_ms"] == "" ||
		len(row["salt"]) != 32 || len(row["verifier"]) != 64 || row["salt"] == secondSalt {
		t.Fatal("invalid stored credential record")
	}
	for _, field := range row {
		if field == key || field == secret {
			t.Fatal("plaintext credential persisted")
		}
	}
	_, _, err = registry.authenticateRequest(context.Background(), []string{"Bearer " + id + "." + strings.Repeat("0", 64)})
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("wrong verifier accepted")
	}
}

func managedRequest(t *testing.T, url, key, body string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("X-Tenant-ID", "tenant-b")
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}

const managedBody = `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`

func TestCrossTenantPrincipalBinding(t *testing.T) {
	client, store, registry, first, second := managedFixture(t)
	keyA := issueTestKey(t, store, "tenant-a")
	keyB := issueTestKey(t, store, "tenant-b")
	type dispatch struct {
		backend int
		salt    string
	}
	dispatched := make(chan dispatch, 8)
	backend := func(slot int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				var body upstreamRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				dispatched <- dispatch{slot, body.CacheSalt}
				if r.Header.Get("X-Tenant-ID") != "" || r.Header.Get("Authorization") != "" {
					t.Error("forwarded client identity")
				}
			}
			streamHandler(contentEvent+finishEvent+doneEvent)(w, r)
		}
	}
	_, a := newTestGatewayWithAdmission(t, DefaultConfig(), nil, registry, first, backend(0), backend(1))
	_, b := newTestGatewayWithAdmission(t, DefaultConfig(), nil, registry, second, backend(0), backend(1))
	for _, endpoint := range []string{a.URL, b.URL} {
		for i, key := range []string{keyA, keyB} {
			if status := managedRequest(t, endpoint, key, managedBody); status != http.StatusOK {
				t.Fatalf("status %d", status)
			}
			tenant := []string{"tenant-a", "tenant-b"}[i]
			if len(dispatched) != 1 || <-dispatched != (dispatch{i, registry.byTenant[tenant].cacheSalt}) {
				t.Fatalf("wrong upstream namespace for %s", tenant)
			}
		}
		forged := strings.Replace(managedBody, `"stream":true`, `"stream":true,"cache_salt":"forged"`, 1)
		for _, body := range []string{forged, strings.Replace(managedBody, "test-model", "private-model", 1)} {
			if status := managedRequest(t, endpoint, keyA, body); status < 400 {
				t.Fatal("accepted forged tenant input")
			}
		}
	}
	keys, err := client.Keys(context.Background(), strings.TrimSuffix(first.CredentialKey(""), "credential:")+"tenant:*:rate").Result()
	if err != nil || len(keys) != 2 || len(dispatched) != 0 {
		t.Fatalf("wrong Redis tenant accounting: %v, %d", err, len(keys))
	}
	for _, key := range keys {
		if count, err := client.Get(context.Background(), key).Int(); err != nil || count != 2 {
			t.Fatalf("wrong tenant rate counter: %d %v", count, err)
		}
	}
}

func TestCredentialAuthorityUnavailable(t *testing.T) {
	_, store, registry, first, _ := managedFixture(t)
	key := issueTestKey(t, store, "tenant-a")
	unavailable := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0", MaxRetries: -1})
	defer unavailable.Close()
	registry.managed = NewCredentialStore(unavailable, first)
	var dispatch atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			dispatch.Add(1)
		}
		w.WriteHeader(200)
	})
	_, server := newTestGatewayWithAdmission(t, DefaultConfig(), nil, registry, first, backend)
	if status := managedRequest(t, server.URL, key, managedBody); status != http.StatusServiceUnavailable {
		t.Fatalf("status %d", status)
	}
	if status := managedRequest(t, server.URL, testCredential, managedBody); status != http.StatusUnauthorized || dispatch.Load() != 0 {
		t.Fatal("fallback or dispatch while unavailable")
	}
}

type revokeBeforeGrant struct {
	*admission.RedisCoordinator
	revoke func(context.Context) error
}

func (r revokeBeforeGrant) Admit(ctx context.Context, req admission.Request) (admission.Result, error) {
	if err := r.revoke(ctx); err != nil {
		return admission.Result{}, err
	}
	return r.RedisCoordinator.Admit(ctx, req)
}

func TestCredentialRevokedBeforeAdmission(t *testing.T) {
	client, store, registry, first, second := managedFixture(t)
	key := issueTestKey(t, store, "tenant-a")
	id, _, _ := strings.Cut(key, ".")
	revoke := func(ctx context.Context) error {
		return client.HSet(ctx, first.CredentialKey(id), "revoked_ms", time.Now().UnixMilli()).Err()
	}
	var dispatch atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			dispatch.Add(1)
		}
		w.WriteHeader(200)
	})
	_, a := newTestGatewayWithAdmission(t, DefaultConfig(), nil, registry, revokeBeforeGrant{first, revoke}, backend)
	_, b := newTestGatewayWithAdmission(t, DefaultConfig(), nil, registry, second, backend)
	for _, endpoint := range []string{a.URL, b.URL} {
		if status := managedRequest(t, endpoint, key, managedBody); status != http.StatusUnauthorized {
			t.Fatalf("status %d", status)
		}
	}
	if dispatch.Load() != 0 {
		t.Fatal("dispatched only after revocation")
	}
	count, err := client.Exists(context.Background(), strings.Replace(first.CredentialKey(id), "credential:"+id, "tenant:tenant-a:rate", 1)).Result()
	if err != nil || count != 0 {
		t.Fatalf("admitted after revocation: %d, %v", count, err)
	}
}
