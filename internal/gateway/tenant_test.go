package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAdmissionLimitsSnapshotUsesLoadedPolicyAndExcludesSecrets(t *testing.T) {
	registry, err := NewTenantRegistry(tenantSpecs(), testCacheSaltSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := registry.AdmissionLimits()
	if len(snapshot) != 2 || snapshot["tenant-a"]["max_concurrent"] != 128 || snapshot["tenant-a"]["request_rate_limit"] != 100 || snapshot["tenant-a"]["request_rate_window_ms"] != 1000 {
		t.Fatalf("unexpected effective limits: %+v", snapshot)
	}
	if len(snapshot["tenant-a"]) != 3 {
		t.Fatal("unexpected fields in non-secret snapshot")
	}
	snapshot["tenant-a"]["max_concurrent"] = 1
	if registry.AdmissionLimits()["tenant-a"]["max_concurrent"] != 128 {
		t.Fatal("snapshot mutated effective policy")
	}
}

func tenantSpecs() []TenantSpec {
	return []TenantSpec{
		{TenantID: "tenant-a", CredentialSHA256: CredentialSHA256("token-a"), Models: []string{"model-a"}, MaxRequestBytes: 1024, MaxOutputTokens: 5, RequestRateLimit: 100, RateWindowMS: 1000, MaxConcurrent: 128},
		{TenantID: "tenant-b", CredentialSHA256: CredentialSHA256("token-b"), Models: []string{"model-b"}, MaxRequestBytes: 256, MaxOutputTokens: 10, RequestRateLimit: 50, RateWindowMS: 1000, MaxConcurrent: 128},
	}
}

func TestCacheSaltSecretLoadingAndTenantDerivation(t *testing.T) {
	for _, valid := range []string{testCacheSecret, testCacheSecret + "\n", testCacheSecret + "\r\n"} {
		secret, err := LoadCacheSaltSecret(strings.NewReader(valid))
		if err != nil || secret != testCacheSaltSecret(t) {
			t.Fatalf("valid cache-salt secret rejected: %v", err)
		}
	}
	for _, invalid := range []string{
		"", "short", testCacheSecret + "=", " " + testCacheSecret,
		testCacheSecret + " ", testCacheSecret + "\n\n", strings.Repeat("A", 44),
	} {
		if _, err := LoadCacheSaltSecret(strings.NewReader(invalid)); err == nil {
			t.Fatalf("invalid cache-salt secret accepted (length %d)", len(invalid))
		}
	}

	first, err := NewTenantRegistry(tenantSpecs(), testCacheSaltSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTenantRegistry(tenantSpecs(), testCacheSaltSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	policyA, _ := first.Authenticate("Bearer token-a")
	policyAAgain, _ := second.Authenticate("Bearer token-a")
	policyB, _ := first.Authenticate("Bearer token-b")
	if len(policyA.cacheSalt) != 43 || policyA.cacheSalt != policyAAgain.cacheSalt {
		t.Fatalf("cache salt is not a stable 256-bit base64url value: %q %q", policyA.cacheSalt, policyAAgain.cacheSalt)
	}
	if policyA.cacheSalt == policyB.cacheSalt || policyA.cacheSalt == policyA.ID || strings.Contains(policyA.cacheSalt, policyA.ID) {
		t.Fatal("tenant cache salts are not isolated from tenant identity")
	}
	differentSecret := testCacheSaltSecret(t)
	differentSecret[0] ^= 0xff
	rotated, err := NewTenantRegistry(tenantSpecs(), differentSecret)
	if err != nil {
		t.Fatal(err)
	}
	rotatedA, _ := rotated.Authenticate("Bearer token-a")
	if rotatedA.cacheSalt == policyA.cacheSalt {
		t.Fatal("rotating the master secret did not rotate derived cache salts")
	}
}

func TestTenantRegistryLoadsStrictHashedConfiguration(t *testing.T) {
	document := map[string]any{"tenants": tenantSpecs()}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := LoadTenantRegistry(bytes.NewReader(payload), testCacheSaltSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := registry.Authenticate("Bearer token-a")
	if err != nil || policy.ID != "tenant-a" || !policy.AllowsModel("model-a") || policy.AllowsModel("model-b") {
		t.Fatalf("tenant policy mismatch: %+v %v", policy, err)
	}
	if policy, err := registry.Authenticate("bearer token-b"); err != nil || policy.ID != "tenant-b" {
		t.Fatalf("case-insensitive bearer scheme was rejected: %+v %v", policy, err)
	}
	for _, header := range []string{"", "Basic token-a", "Bearer", "Bearer ", "Bearer unknown", "Bearer token-a extra"} {
		if _, err := registry.Authenticate(header); err != ErrUnauthenticated {
			t.Fatalf("invalid credential %q was accepted: %v", header, err)
		}
	}

	invalidDocuments := []string{
		`{"tenants":[],"unexpected":true}`,
		`{"tenants":[],"tenants":[]}`,
		`{"tenants":[{"tenant_id":"tenant-a","credential_sha256":"bad","models":["m"],"max_request_bytes":1,"max_output_tokens":1}]}`,
		strings.Repeat(" ", (1<<20)+1),
	}
	for _, invalid := range invalidDocuments {
		if _, err := LoadTenantRegistry(strings.NewReader(invalid), testCacheSaltSecret(t)); err == nil {
			t.Fatalf("invalid tenant configuration accepted: %s", invalid)
		}
	}
	duplicateID := append(tenantSpecs(), tenantSpecs()[0])
	if _, err := NewTenantRegistry(duplicateID, testCacheSaltSecret(t)); err == nil {
		t.Fatal("duplicate tenant ID was accepted")
	}
	duplicateCredential := tenantSpecs()
	duplicateCredential[1].CredentialSHA256 = duplicateCredential[0].CredentialSHA256
	if _, err := NewTenantRegistry(duplicateCredential, testCacheSaltSecret(t)); err == nil {
		t.Fatal("duplicate credential was accepted")
	}
	invalidSpecs := []TenantSpec{
		{TenantID: "invalid tenant", CredentialSHA256: CredentialSHA256("one"), Models: []string{"m"}, MaxRequestBytes: 1, MaxOutputTokens: 1, RequestRateLimit: 1, RateWindowMS: 1, MaxConcurrent: 1},
		{TenantID: "tenant", CredentialSHA256: CredentialSHA256("two"), Models: nil, MaxRequestBytes: 1, MaxOutputTokens: 1, RequestRateLimit: 1, RateWindowMS: 1, MaxConcurrent: 1},
		{TenantID: "tenant", CredentialSHA256: CredentialSHA256("three"), Models: []string{"m", "m"}, MaxRequestBytes: 1, MaxOutputTokens: 1, RequestRateLimit: 1, RateWindowMS: 1, MaxConcurrent: 1},
		{TenantID: "tenant", CredentialSHA256: CredentialSHA256("four"), Models: []string{"m"}, MaxRequestBytes: 0, MaxOutputTokens: 1, RequestRateLimit: 1, RateWindowMS: 1, MaxConcurrent: 1},
		{TenantID: "tenant", CredentialSHA256: CredentialSHA256("five"), Models: []string{"m"}, MaxRequestBytes: 1, MaxOutputTokens: -1, RequestRateLimit: 1, RateWindowMS: 1, MaxConcurrent: 1},
		{TenantID: "tenant", CredentialSHA256: CredentialSHA256("six"), Models: []string{"m"}, MaxRequestBytes: 1, MaxOutputTokens: 1, RequestRateLimit: 0, RateWindowMS: 1, MaxConcurrent: 1},
		{TenantID: "tenant", CredentialSHA256: CredentialSHA256("seven"), Models: []string{"m"}, MaxRequestBytes: 1, MaxOutputTokens: 1, RequestRateLimit: 1, RateWindowMS: 0, MaxConcurrent: 1},
		{TenantID: "tenant", CredentialSHA256: CredentialSHA256("eight"), Models: []string{"m"}, MaxRequestBytes: 1, MaxOutputTokens: 1, RequestRateLimit: 1, RateWindowMS: 1, MaxConcurrent: 0},
	}
	for _, invalid := range invalidSpecs {
		if _, err := NewTenantRegistry([]TenantSpec{invalid}, testCacheSaltSecret(t)); err == nil {
			t.Fatalf("invalid tenant spec accepted: %+v", invalid)
		}
	}
}

func TestGatewayKeepsConcurrentTenantPoliciesSeparate(t *testing.T) {
	tenants, err := NewTenantRegistry(tenantSpecs(), testCacheSaltSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	var mismatches atomic.Int32
	upstream := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			Model     string `json:"model"`
			MaxTokens int    `json:"max_tokens"`
			CacheSalt string `json:"cache_salt"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			mismatches.Add(1)
		}
		if (body.Model == "model-a" && body.MaxTokens != 5) || (body.Model == "model-b" && body.MaxTokens != 10) {
			mismatches.Add(1)
		}
		policy, _ := tenants.Authenticate(map[string]string{"model-a": "Bearer token-a", "model-b": "Bearer token-b"}[body.Model])
		if policy == nil || body.CacheSalt != policy.cacheSalt {
			mismatches.Add(1)
		}
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent+finishEvent+usageEvent+doneEvent)
	})
	_, server := newTestGatewayWithPolicies(t, DefaultConfig(), nil, tenants, upstream)

	const requestCount = 40
	start := make(chan struct{})
	var wait sync.WaitGroup
	var failures atomic.Int32
	for index := range requestCount {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			token, model := "token-a", "model-a"
			if index%2 == 1 {
				token, model = "token-b", "model-b"
			}
			payload := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hello"}],"stream":true}`, model)
			request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader(payload))
			if err != nil {
				failures.Add(1)
				return
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+token)
			response, err := server.Client().Do(request)
			if err != nil {
				failures.Add(1)
				return
			}
			_, copyErr := io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusOK || copyErr != nil {
				failures.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if failures.Load() != 0 || mismatches.Load() != 0 {
		t.Fatalf("concurrent tenant separation failed: requests=%d policies=%d", failures.Load(), mismatches.Load())
	}
}

func TestTenantRegistryIsSafeForConcurrentAuthentication(t *testing.T) {
	registry, err := NewTenantRegistry(tenantSpecs(), testCacheSaltSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	var failures atomic.Int32
	for index := range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			credential, expected := "token-a", "tenant-a"
			if index%2 == 1 {
				credential, expected = "token-b", "tenant-b"
			}
			policy, err := registry.Authenticate("Bearer " + credential)
			if err != nil || policy.ID != expected {
				failures.Add(1)
			}
		}()
	}
	wait.Wait()
	if failures.Load() != 0 {
		t.Fatalf("concurrent authentication failures: %d", failures.Load())
	}
}

func TestGatewayEnforcesTenantAuthenticationAuthorizationAndLimits(t *testing.T) {
	tenants, err := NewTenantRegistry(tenantSpecs(), testCacheSaltSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	var contacts atomic.Int32
	var forwardedMaxTokens atomic.Int32
	upstream := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		contacts.Add(1)
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode upstream request: %v", err)
		}
		forwardedMaxTokens.Store(int32(body["max_tokens"].(float64)))
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, roleEvent+finishEvent+usageEvent+doneEvent)
	})
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	_, server := newTestGatewayWithPolicies(t, DefaultConfig(), logger, tenants, upstream)

	request := func(token, model string, maxTokens *int, padding string) *http.Response {
		body := map[string]any{
			"model": model, "messages": []map[string]string{{"role": "user", "content": "hello" + padding}}, "stream": true,
		}
		if maxTokens != nil {
			body["max_tokens"] = *maxTokens
		}
		payload, _ := json.Marshal(body)
		httpRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", bytes.NewReader(payload))
		httpRequest.Header.Set("Content-Type", "application/json")
		if token != "" {
			httpRequest.Header.Set("Authorization", token)
		}
		response, err := server.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	for _, authorization := range []string{"", "Basic token-a", "Bearer unknown"} {
		response := request(authorization, "model-a", nil, "")
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized || !bytes.Contains(body, []byte("unauthenticated")) {
			t.Fatalf("authentication failure mismatch: %d %s", response.StatusCode, body)
		}
	}
	denied := request("Bearer token-a", "model-b", nil, "")
	deniedBody, _ := io.ReadAll(denied.Body)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden || !bytes.Contains(deniedBody, []byte("model_not_allowed")) {
		t.Fatalf("model denial mismatch: %d %s", denied.StatusCode, deniedBody)
	}
	crossTenant := request("Bearer token-b", "model-a", nil, "")
	crossTenant.Body.Close()
	if crossTenant.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-tenant model policy bypassed: %d", crossTenant.StatusCode)
	}
	tooLarge := request("Bearer token-b", "model-b", nil, strings.Repeat("x", 512))
	tooLargeBody, _ := io.ReadAll(tooLarge.Body)
	tooLarge.Body.Close()
	if tooLarge.StatusCode != http.StatusRequestEntityTooLarge || !bytes.Contains(tooLargeBody, []byte("request_too_large")) {
		t.Fatalf("tenant byte limit mismatch: %d %s", tooLarge.StatusCode, tooLargeBody)
	}
	requested := 99
	allowed := request("Bearer token-a", "model-a", &requested, "")
	_, _ = io.Copy(io.Discard, allowed.Body)
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK || forwardedMaxTokens.Load() != 5 || contacts.Load() != 1 {
		t.Fatalf("tenant policy forwarding mismatch: status=%d max=%d contacts=%d", allowed.StatusCode, forwardedMaxTokens.Load(), contacts.Load())
	}
	defaulted := request("Bearer token-a", "model-a", nil, "")
	_, _ = io.Copy(io.Discard, defaulted.Body)
	defaulted.Body.Close()
	if defaulted.StatusCode != http.StatusOK || forwardedMaxTokens.Load() != 5 {
		t.Fatalf("missing max_tokens was not capped: status=%d max=%d", defaulted.StatusCode, forwardedMaxTokens.Load())
	}
	lowerLimit := 3
	preserved := request("Bearer token-a", "model-a", &lowerLimit, "")
	_, _ = io.Copy(io.Discard, preserved.Body)
	preserved.Body.Close()
	if preserved.StatusCode != http.StatusOK || forwardedMaxTokens.Load() != 3 || contacts.Load() != 3 {
		t.Fatalf("lower client max_tokens was not preserved: status=%d max=%d contacts=%d", preserved.StatusCode, forwardedMaxTokens.Load(), contacts.Load())
	}
	policyA, _ := tenants.Authenticate("Bearer token-a")
	if bytes.Contains(logs.Bytes(), []byte("token-a")) || bytes.Contains(logs.Bytes(), []byte(testCacheSecret)) || bytes.Contains(logs.Bytes(), []byte(policyA.cacheSalt)) || !bytes.Contains(logs.Bytes(), []byte(`"tenant_id":"tenant-a"`)) {
		t.Fatalf("credential leaked or tenant correlation missing: %s", logs.String())
	}
}
