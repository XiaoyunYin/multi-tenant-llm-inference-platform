package main

import (
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/gateway"
)

func TestParseBackendsUsesStableExplicitIdentities(t *testing.T) {
	backends, err := parseBackends("gpu-a@gen-7=http://127.0.0.1:8001,gpu-b=http://127.0.0.1:8002")
	if err != nil {
		t.Fatal(err)
	}
	if len(backends) != 2 || backends[0].ID != "gpu-a" || backends[1].ID != "gpu-b" {
		t.Fatalf("unexpected backends: %+v", backends)
	}
	if backends[0].Generation != "gen-7" || backends[1].Generation != "0" {
		t.Fatalf("unexpected backend generations: %q, %q", backends[0].Generation, backends[1].Generation)
	}
	if _, err := parseBackends("http://127.0.0.1:8001"); err == nil {
		t.Fatal("positional backend configuration was accepted")
	}
	if _, err := parseBackends("invalid backend=http://127.0.0.1:8001"); err == nil {
		t.Fatal("metric-unsafe backend identity was accepted")
	}
}

func TestCheckConfigUsesLaunchParser(t *testing.T) {
	t.Setenv("BACKEND_DISCOVERY", "")
	t.Setenv("TENANT_CONFIG_PATH", "../../deploy/local/tenants.json")
	t.Setenv("CACHE_SALT_SECRET_FILE", "../../deploy/local/cache-salt.secret.example")
	t.Setenv("ADMISSION_MODE", "memory-test")
	t.Setenv("ALLOW_UNSAFE_TEST_ADMISSION", "true")
	t.Setenv("OTEL_SDK_DISABLED", "true")
	t.Setenv("BACKENDS", "vllm0@http://127.0.0.1:8000")
	if got := runWithMode(true); got != 2 {
		t.Fatalf("Round 32 malformed backend returned %d, want 2", got)
	}
	t.Setenv("BACKENDS", "vllm0=http://127.0.0.1:8000")
	if got := runWithMode(true); got != 0 {
		t.Fatalf("reviewed backend returned %d, want 0", got)
	}
	t.Setenv("ADMISSION_LEASE", "1s")
	if got := runWithMode(true); got != 2 {
		t.Fatalf("invalid full environment returned %d, want 2", got)
	}
}

func TestDiscoveryOptInLeavesStaticValidationUnchanged(t *testing.T) {
	t.Setenv("BACKEND_DISCOVERY", "")
	t.Setenv("BACKEND_DISCOVERY_NAMESPACE", "invalid namespace")
	t.Setenv("BACKEND_DISCOVERY_INTERVAL", "bad-duration")
	t.Setenv("BACKENDS", "vllm0=http://127.0.0.1:8000")
	b, c, err := backendConfiguration()
	if err != nil || c != nil || len(b) != 1 {
		t.Fatalf("default changed: %v", err)
	}
	t.Setenv("BACKENDS", "vllm0@http://127.0.0.1:8000")
	if _, _, err := backendConfiguration(); err == nil {
		t.Fatal("static parser weakened")
	}
	t.Setenv("BACKEND_DISCOVERY", "endpointslices")
	if _, _, err := backendConfiguration(); err == nil {
		t.Fatal("invalid discovery config accepted")
	}
	t.Setenv("BACKEND_DISCOVERY_NAMESPACE", "test")
	t.Setenv("BACKEND_DISCOVERY_SERVICE", "fake")
	t.Setenv("BACKEND_DISCOVERY_INTERVAL", "250ms")
	t.Setenv("TENANT_CONFIG_PATH", "../../deploy/local/tenants.json")
	t.Setenv("CACHE_SALT_SECRET_FILE", "../../deploy/local/cache-salt.secret.example")
	t.Setenv("ADMISSION_MODE", "memory-test")
	t.Setenv("ALLOW_UNSAFE_TEST_ADMISSION", "true")
	t.Setenv("OTEL_SDK_DISABLED", "true")
	if got := runWithMode(true); got != 0 {
		t.Fatalf("offline discovery config check contacted cluster or failed: %d", got)
	}
}

func TestRouterForPolicySupportsDevelopmentRoutingPolicies(t *testing.T) {
	t.Setenv("GATEWAY_HASH_AFFINITY_BLOCK_SIZE", "8")
	t.Setenv("GATEWAY_HASH_AFFINITY_MAX_BLOCKS", "12")
	t.Setenv("GATEWAY_HASH_AFFINITY_ESCAPE_MARGIN", "2.5")
	tests := []struct {
		policy string
		want   gateway.RoutingPolicy
	}{
		{policy: "round_robin", want: gateway.RoutingPolicyRoundRobin},
		{policy: "least_loaded", want: gateway.RoutingPolicyLeastLoaded},
		{policy: "hash_affinity", want: gateway.RoutingPolicyHashAffinity},
	}
	for _, test := range tests {
		t.Run(test.policy, func(t *testing.T) {
			router, err := routerForPolicy(test.policy)
			if err != nil {
				t.Fatal(err)
			}
			if router.PolicyName() != test.want {
				t.Fatalf("router policy = %q; want %q", router.PolicyName(), test.want)
			}
			if hashRouter, ok := router.(*gateway.HashAffinityRouter); ok && hashRouter.MaxTokenIDs() != 96 {
				t.Fatalf("hash tokenizer token bound=%d; want 96", hashRouter.MaxTokenIDs())
			}
		})
	}
	if _, err := routerForPolicy("unknown"); err == nil {
		t.Fatal("unknown policy was accepted")
	}
}

func TestEnvDurationRejectsInvalidValues(t *testing.T) {
	t.Setenv("TEST_DURATION", "250ms")
	if value, err := envDuration("TEST_DURATION", time.Second); err != nil || value != 250*time.Millisecond {
		t.Fatalf("valid duration rejected: %v %v", value, err)
	}
	t.Setenv("TEST_DURATION", "0s")
	if _, err := envDuration("TEST_DURATION", time.Second); err == nil {
		t.Fatal("non-positive duration was accepted")
	}
}

func TestEnvPositiveInt64RejectsInvalidValues(t *testing.T) {
	t.Setenv("TEST_POSITIVE_INTEGER", "17")
	if value, err := envPositiveInt64("TEST_POSITIVE_INTEGER", 1); err != nil || value != 17 {
		t.Fatalf("valid integer rejected: %d %v", value, err)
	}
	for _, invalid := range []string{"0", "-1", "not-an-integer"} {
		t.Setenv("TEST_POSITIVE_INTEGER", invalid)
		if _, err := envPositiveInt64("TEST_POSITIVE_INTEGER", 1); err == nil {
			t.Fatalf("invalid integer %q was accepted", invalid)
		}
	}
}

func TestEnvPositiveIntRejectsPlatformOverflow(t *testing.T) {
	t.Setenv("TEST_POSITIVE_INT", "17")
	if value, err := envPositiveInt("TEST_POSITIVE_INT", 1); err != nil || value != 17 {
		t.Fatalf("valid integer rejected: %d %v", value, err)
	}
	t.Setenv("TEST_POSITIVE_INT", "0")
	if _, err := envPositiveInt("TEST_POSITIVE_INT", 1); err == nil {
		t.Fatal("non-positive integer was accepted")
	}
}

func TestEnvNonNegativeFloat(t *testing.T) {
	t.Setenv("TEST_NON_NEGATIVE_FLOAT", "2.5")
	if value, err := envNonNegativeFloat("TEST_NON_NEGATIVE_FLOAT", 1); err != nil || value != 2.5 {
		t.Fatalf("valid float rejected: %v %v", value, err)
	}
	for _, invalid := range []string{"-1", "NaN", "Inf", "not-a-number"} {
		t.Setenv("TEST_NON_NEGATIVE_FLOAT", invalid)
		if _, err := envNonNegativeFloat("TEST_NON_NEGATIVE_FLOAT", 1); err == nil {
			t.Fatalf("invalid float %q was accepted", invalid)
		}
	}
}
