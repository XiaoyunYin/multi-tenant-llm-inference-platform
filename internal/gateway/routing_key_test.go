package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"
)

// deterministicTestTokenizer is intentionally a small fixture, not a model
// tokenizer. It provides stable tokens to exercise the production interface.
type deterministicTestTokenizer struct{}

func (deterministicTestTokenizer) TokenizeChat(_ context.Context, _, model string, messages []RoutingMessage, _ []BackendCandidate) (RoutingTokenizationResult, error) {
	tokens := []uint32{uint32(len(model))}
	for _, message := range messages {
		tokens = append(tokens, uint32(len(message.Role)))
		for _, value := range []byte(message.Role + "\x00" + message.Content) {
			tokens = append(tokens, uint32(value)+1)
		}
	}
	return RoutingTokenizationResult{TokenIDs: tokens}, nil
}

func newHashAffinityTestRouter(t *testing.T, blockSize, maxBlocks int, margin float64) *HashAffinityRouter {
	t.Helper()
	router, err := NewHashAffinityRouter(HashAffinityConfig{BlockSize: blockSize, MaxBlocks: maxBlocks, EscapeMargin: margin})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func routingTestContext() RoutingContext {
	return RoutingContext{
		TenantID: "tenant-test", Model: "model-test", CacheSalt: "test-cache-salt",
		TokenIDs: []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	}
}

func generationCandidate(t *testing.T, id, generation string, running, waiting float64) BackendCandidate {
	t.Helper()
	backend, err := NewBackend(id, "http://"+id+".example.test", generation)
	if err != nil {
		t.Fatal(err)
	}
	load := freshRouterLoad(id, running, waiting)
	return BackendCandidate{Backend: backend, Healthy: true, Ready: true, Load: load}
}

func TestHashAffinityUsesLongestAlignedInitialSpanAndScope(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 2, 100)
	base := routingTestContext()
	base.TokenIDs = []uint32{1, 2, 3, 4, 5, 6, 7, 8}
	baseKey, enabled, err := router.affinityKey(base)
	if err != nil || !enabled {
		t.Fatalf("affinity key enabled=%t err=%v", enabled, err)
	}

	extended := base
	extended.TokenIDs = append(append([]uint32(nil), base.TokenIDs...), 9, 10, 11, 12, 13)
	extendedKey, extendedEnabled, err := router.affinityKey(extended)
	if err != nil || !extendedEnabled || baseKey != extendedKey {
		t.Fatalf("capped prefix changed after prompt extension: enabled=%t err=%v", extendedEnabled, err)
	}

	changedPrefix := base
	changedPrefix.TokenIDs = append([]uint32(nil), base.TokenIDs...)
	changedPrefix.TokenIDs[0]++
	changedKey, _, err := router.affinityKey(changedPrefix)
	if err != nil || changedKey == baseKey {
		t.Fatalf("changed aligned token span did not change digest: err=%v", err)
	}

	for name, mutate := range map[string]func(*RoutingContext){
		"tenant": func(value *RoutingContext) { value.TenantID = "other-tenant" },
		"model":  func(value *RoutingContext) { value.Model = "other-model" },
		"salt":   func(value *RoutingContext) { value.CacheSalt = "other-cache-salt" },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			key, _, err := router.affinityKey(value)
			if err != nil || key == baseKey {
				t.Fatalf("scope change did not change digest: err=%v", err)
			}
		})
	}

	short := base
	short.TokenIDs = base.TokenIDs[:3]
	shortKey, shortEnabled, err := router.affinityKey(short)
	if err != nil || shortEnabled {
		t.Fatalf("short prompt affinity enabled=%t err=%v; want bypass", shortEnabled, err)
	}
	short.TokenIDs[0]++
	changedShortKey, _, err := router.affinityKey(short)
	if err != nil || changedShortKey == shortKey {
		t.Fatalf("short routing-key diagnostic digest ignored tokens: err=%v", err)
	}
	oneBlock := base
	oneBlock.TokenIDs = base.TokenIDs[:4]
	if _, enabled, err := router.affinityKey(oneBlock); err != nil || !enabled {
		t.Fatalf("exactly one block affinity enabled=%t err=%v; want affinity", enabled, err)
	}
}

func TestHashAffinityShortPromptUsesSeededLeastLoadedTieBreak(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 2, 10)
	context := routingTestContext()
	context.TokenIDs = []uint32{1, 2, 3}
	candidates := []BackendCandidate{
		generationCandidate(t, "backend-a", "gen-1", 2, 1),
		generationCandidate(t, "backend-b", "gen-1", 1, 2),
	}
	first := NewBackendSelectionBoundary(router, NewSeededTieBreaker(42))
	second := NewBackendSelectionBoundary(router, NewSeededTieBreaker(42))
	seen := make(map[string]bool)
	for range 32 {
		left, err := first.Select(candidates, context)
		if err != nil {
			t.Fatal(err)
		}
		right, err := second.Select(candidates, context)
		if err != nil {
			t.Fatal(err)
		}
		if left.Backend.ID != right.Backend.ID {
			t.Fatalf("same seeded tie-break chose %q and %q", left.Backend.ID, right.Backend.ID)
		}
		if left.Policy != RoutingPolicyLeastLoaded || left.FallbackReason != FallbackReasonNone {
			t.Fatalf("short-prompt decision = %+v; want least_loaded/none", left)
		}
		seen[left.Backend.ID] = true
	}
	if len(seen) != 2 {
		t.Fatalf("seeded least-loaded tie-break did not select both equal-load backends: %v", seen)
	}
}

func TestHashAffinityGatewaysAgreeAcrossCandidateOrdering(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 3, 100)
	secondRouter := newHashAffinityTestRouter(t, 4, 3, 100)
	context := routingTestContext()
	candidates := []BackendCandidate{
		generationCandidate(t, "backend-a", "gen-1", 1, 0),
		generationCandidate(t, "backend-b", "gen-2", 1, 0),
		generationCandidate(t, "backend-c", "gen-3", 1, 0),
	}
	reversed := []BackendCandidate{candidates[2], candidates[1], candidates[0]}
	first, err := NewBackendSelectionBoundary(router, NewSeededTieBreaker(1)).Select(candidates, context)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewBackendSelectionBoundary(secondRouter, NewSeededTieBreaker(99)).Select(reversed, context)
	if err != nil {
		t.Fatal(err)
	}
	if first.Backend.ID != second.Backend.ID || first.Policy != RoutingPolicyHashAffinity || second.Policy != RoutingPolicyHashAffinity {
		t.Fatalf("same membership/key did not agree: first=%+v second=%+v", first, second)
	}
}

func TestHashAffinityLoadEscapeRecordsOwnFallbackReason(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 3, 2)
	context := routingTestContext()
	balanced := []BackendCandidate{
		generationCandidate(t, "backend-a", "gen-1", 0, 0),
		generationCandidate(t, "backend-b", "gen-2", 0, 0),
	}
	key, _, err := router.affinityKey(context)
	if err != nil {
		t.Fatal(err)
	}
	preferred, _, err := router.preferredBackend(balanced, key)
	if err != nil {
		t.Fatal(err)
	}
	least := "backend-a"
	if preferred.ID == least {
		least = "backend-b"
	}
	setLoad := func(candidates []BackendCandidate, preferredLoad float64) {
		for index := range candidates {
			load := 0.0
			if candidates[index].Backend.ID == preferred.ID {
				load = preferredLoad
			}
			candidates[index].Load = freshRouterLoad(candidates[index].Backend.ID, load, 0)
		}
	}
	for _, test := range []struct {
		name          string
		preferredLoad float64
		wantEscape    bool
	}{
		{name: "below margin", preferredLoad: 1},
		{name: "at margin", preferredLoad: 2},
		{name: "above margin", preferredLoad: 3, wantEscape: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidates := append([]BackendCandidate(nil), balanced...)
			setLoad(candidates, test.preferredLoad)
			decision, err := NewBackendSelectionBoundary(router, NewSeededTieBreaker(4)).Select(candidates, context)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantEscape {
				if decision.Backend.ID != least || decision.Policy != RoutingPolicyHashAffinity || decision.FallbackReason != FallbackReasonBackendLoadEscape {
					t.Fatalf("escape decision=%+v; want backend %s with backend_load_escape", decision, least)
				}
			} else if decision.Backend.ID != preferred.ID || decision.FallbackReason != FallbackReasonNone {
				t.Fatalf("non-escape decision=%+v; want preferred backend %s", decision, preferred.ID)
			}
		})
	}
}

func TestHashAffinityStaleSamplesKeepPreferredReplicaAndSkipEscape(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 3, 0)
	context := routingTestContext()
	stale := freshRouterLoad("backend-b", 0, 0)
	stale.Fresh = false
	candidates := []BackendCandidate{
		generationCandidate(t, "backend-a", "gen-1", 1, 0),
		generationCandidate(t, "backend-b", "gen-2", 0, 0),
	}
	candidates[1].Load = stale
	key, _, err := router.affinityKey(context)
	if err != nil {
		t.Fatal(err)
	}
	preferred, _, err := router.preferredBackend(candidates, key)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := NewBackendSelectionBoundary(router, NewSeededTieBreaker(7)).Select(candidates, context)
	if err != nil || decision.Backend.ID != preferred.ID {
		t.Fatalf("stale fallback=%+v err=%v", decision, err)
	}
	if decision.Policy != RoutingPolicyHashAffinity || decision.FallbackReason != FallbackReasonEscapeUnavailable {
		t.Fatalf("stale fallback record=%+v; want hash_affinity/escape_unavailable", decision)
	}
	if decision.BackendGeneration != preferred.Generation {
		t.Fatalf("decision generation=%q; want %q", decision.BackendGeneration, preferred.Generation)
	}
}

func TestHashAffinityShortPromptUsesLeastLoadedFallbackRulesWhenStale(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 3, 0)
	context := routingTestContext()
	context.TokenIDs = context.TokenIDs[:3]
	candidates := []BackendCandidate{
		generationCandidate(t, "backend-a", "gen-1", 0, 0),
		generationCandidate(t, "backend-b", "gen-2", 0, 0),
	}
	candidates[1].Load.Fresh = false
	decision, err := NewBackendSelectionBoundary(router, NewSeededTieBreaker(7)).Select(candidates, context)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Policy != RoutingPolicyRoundRobin || decision.FallbackReason != FallbackReasonStale {
		t.Fatalf("short-prompt stale decision=%+v; want round_robin/stale", decision)
	}
}

func TestHashAffinityRendezvousIdentityIsStableBackendID(t *testing.T) {
	oldReplica := &Backend{ID: "backend-a", Generation: "gen-1"}
	newReplica := &Backend{ID: "backend-a", Generation: "gen-2"}
	key := scopedTokenDigest("tenant", "model", "salt", []uint32{1, 2, 3})
	if rendezvousScore(key, oldReplica) != rendezvousScore(key, newReplica) {
		t.Fatal("replica generation changed the stable backend ID rendezvous score")
	}
}

func TestHashAffinityMembershipChangesRecomputePreferredReplica(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 3, 100)
	context := routingTestContext()
	candidates := []BackendCandidate{
		generationCandidate(t, "backend-a", "gen-1", 0, 0),
		generationCandidate(t, "backend-b", "gen-1", 0, 0),
		generationCandidate(t, "backend-c", "gen-1", 0, 0),
	}
	added := append(append([]BackendCandidate(nil), candidates...), generationCandidate(t, "backend-d", "gen-1", 0, 0))
	var addedContext RoutingContext
	var addedKey [sha256.Size]byte
	var addedPreferred *Backend
	foundChangedKey := false
	for index := range 1024 {
		addedContext = context
		addedContext.TokenIDs = append([]uint32(nil), context.TokenIDs...)
		addedContext.TokenIDs[0] += uint32(index)
		var err error
		addedKey, _, err = router.affinityKey(addedContext)
		if err != nil {
			t.Fatal(err)
		}
		addedPreferred, _, err = router.preferredBackend(added, addedKey)
		if err != nil {
			t.Fatal(err)
		}
		initialPreferred, _, err := router.preferredBackend(candidates, addedKey)
		if err != nil {
			t.Fatal(err)
		}
		if initialPreferred.ID != selectHashBackend(t, router, candidates, addedContext) ||
			addedPreferred.ID != selectHashBackend(t, router, added, addedContext) {
			t.Fatal("selection disagreed with the rendezvous preferred replica")
		}
		if addedPreferred.ID != initialPreferred.ID {
			foundChangedKey = true
			break
		}
	}
	if !foundChangedKey {
		t.Fatal("membership addition did not change any tested preferred replica")
	}
	withoutPreferred := make([]BackendCandidate, 0, len(added)-1)
	for _, candidate := range added {
		if candidate.Backend.ID != addedPreferred.ID {
			withoutPreferred = append(withoutPreferred, candidate)
		}
	}
	removedPreferred, _, err := router.preferredBackend(withoutPreferred, addedKey)
	if err != nil || selectHashBackend(t, router, withoutPreferred, addedContext) != removedPreferred.ID {
		t.Fatalf("membership removal did not recompute placement: preferred=%v err=%v", removedPreferred, err)
	}
}

func TestHashAffinityGenerationChangeLeavesEveryPreferredKeyStable(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 3, 100)
	context := routingTestContext()
	candidates := []BackendCandidate{
		generationCandidate(t, "backend-a", "gen-1", 0, 0),
		generationCandidate(t, "backend-b", "gen-1", 0, 0),
		generationCandidate(t, "backend-c", "gen-1", 0, 0),
	}
	rotated := append([]BackendCandidate(nil), candidates...)
	for index := range rotated {
		if rotated[index].Backend.ID == "backend-b" {
			updated, err := NewBackend("backend-b", rotated[index].Backend.URL.String(), "gen-2")
			if err != nil {
				t.Fatal(err)
			}
			rotated[index].Backend = updated
		}
	}
	for index := range 512 {
		routing := context
		routing.TokenIDs = append([]uint32(nil), context.TokenIDs...)
		routing.TokenIDs[0] += uint32(index)
		key, _, err := router.affinityKey(routing)
		if err != nil {
			t.Fatal(err)
		}
		before, _, err := router.preferredBackend(candidates, key)
		if err != nil {
			t.Fatal(err)
		}
		after, _, err := router.preferredBackend(rotated, key)
		if err != nil {
			t.Fatal(err)
		}
		if before.ID != after.ID || selectHashBackend(t, router, candidates, routing) != selectHashBackend(t, router, rotated, routing) {
			t.Fatalf("generation-only change moved key %d from %q to %q", index, before.ID, after.ID)
		}
		if before.ID == "backend-b" {
			beforeDecision, beforeErr := NewBackendSelectionBoundary(router, NewSeededTieBreaker(1)).Select(candidates, routing)
			afterDecision, afterErr := NewBackendSelectionBoundary(router, NewSeededTieBreaker(1)).Select(rotated, routing)
			if beforeErr != nil || afterErr != nil || beforeDecision.BackendGeneration != "gen-1" || afterDecision.BackendGeneration != "gen-2" {
				t.Fatalf("decision omitted replica generation across replacement: before=%+v after=%+v errors=(%v,%v)", beforeDecision, afterDecision, beforeErr, afterErr)
			}
		}
	}
}

func selectHashBackend(t *testing.T, router *HashAffinityRouter, candidates []BackendCandidate, routing RoutingContext) string {
	t.Helper()
	decision, err := NewBackendSelectionBoundary(router, NewSeededTieBreaker(8)).Select(candidates, routing)
	if err != nil {
		t.Fatal(err)
	}
	return decision.Backend.ID
}

func TestContextualRouterRequiresAnInjectedTokenizer(t *testing.T) {
	backend, err := NewBackend("backend-a", "http://backend-a.example.test")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]*Backend{backend}, &http.Client{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := admission.NewMemoryCoordinator(10)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(DefaultConfig(), registry, &http.Client{}, nil,
		WithTenantRegistry(testTenantRegistry(t)),
		WithAdmissionCoordinator(coordinator),
		WithRouter(newHashAffinityTestRouter(t, 4, 2, 0)),
	)
	if err == nil || !strings.Contains(err.Error(), "routing-key tokenizer") {
		t.Fatalf("contextual router constructed without tokenizer: %v", err)
	}
}

func TestHashAffinityPlacementAuditIsBoundedDeterministicAndRedacted(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 2, 100)
	candidates := []BackendCandidate{
		generationCandidate(t, "backend-a", "gen-1", 0, 0),
		generationCandidate(t, "backend-b", "gen-2", 0, 0),
	}
	firstContext := routingTestContext()
	firstContext.TokenIDs = []uint32{11, 12, 13}
	secondContext := routingTestContext()
	secondContext.TokenIDs = []uint32{1, 2, 3, 4, 5, 6, 7, 8}
	thirdContext := routingTestContext()
	thirdContext.TokenIDs = []uint32{8, 7, 6, 5}
	popular := []PopularRoutingKey{
		{Context: firstContext, Popularity: 30},
		{Context: secondContext, Popularity: 20},
		{Context: thirdContext, Popularity: 20},
	}
	first, err := router.AuditPlacements(candidates, popular, 77, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := router.AuditPlacements(candidates, []PopularRoutingKey{popular[2], popular[0], popular[1]}, 77, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("audit was not bounded: lengths %d and %d", len(first), len(second))
	}
	for _, record := range first {
		if record.SelectedBackendGeneration == "" ||
			(record.AffinityApplied && record.PreferredBackendGeneration == "") {
			t.Fatalf("audit omitted selected or preferred backend generation: %+v", record)
		}
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("audit changed with input ordering:\n%s\n%s", firstJSON, secondJSON)
	}
	for _, forbidden := range []string{"test-cache-salt", "tenant-test", "prompt secret", "token_ids"} {
		if bytes.Contains(firstJSON, []byte(forbidden)) {
			t.Fatalf("audit leaked %q: %s", forbidden, firstJSON)
		}
	}
}

func TestConcurrentHashAffinitySelectionIsRaceSafe(t *testing.T) {
	router := newHashAffinityTestRouter(t, 4, 3, 100)
	selection := NewBackendSelectionBoundary(router, NewSeededTieBreaker(29))
	candidates := []BackendCandidate{
		generationCandidate(t, "backend-a", "gen-1", 2, 1),
		generationCandidate(t, "backend-b", "gen-2", 1, 2),
		generationCandidate(t, "backend-c", "gen-3", 5, 0),
	}
	var wait sync.WaitGroup
	var count atomic.Int64
	var invalid atomic.Bool
	for worker := range 24 {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for index := range 200 {
				context := routingTestContext()
				context.TokenIDs[0] += uint32(worker + index)
				decision, err := selection.Select(candidates, context)
				if err != nil || decision.Backend == nil {
					invalid.Store(true)
					return
				}
				count.Add(1)
			}
		}(worker)
	}
	wait.Wait()
	if invalid.Load() || count.Load() != 24*200 {
		t.Fatalf("concurrent hash selections invalid=%t count=%d", invalid.Load(), count.Load())
	}
}

func TestGatewayRecordsHashEscapeInMetricsAndTerminalLog(t *testing.T) {
	stream := roleEvent + contentEvent + finishEvent + usageEvent + doneEvent
	firstServer := httptest.NewServer(streamHandler(stream))
	secondServer := httptest.NewServer(streamHandler(stream))
	t.Cleanup(firstServer.Close)
	t.Cleanup(secondServer.Close)
	firstBackend, err := NewBackend("backend-a", firstServer.URL, "gen-1")
	if err != nil {
		t.Fatal(err)
	}
	secondBackend, err := NewBackend("backend-b", secondServer.URL, "gen-2")
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
	tenantRegistry := testTenantRegistry(t)
	tenant, err := tenantRegistry.Authenticate("Bearer " + testCredential)
	if err != nil {
		t.Fatal(err)
	}
	tokenizer := deterministicTestTokenizer{}
	tokenization, err := tokenizer.TokenizeChat(context.Background(), "request-test", "test-model", []RoutingMessage{{Role: "user", Content: "hello"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokenIDs := tokenization.TokenIDs
	router := newHashAffinityTestRouter(t, 1, 16, 0)
	routing := RoutingContext{TenantID: tenant.ID, Model: "test-model", CacheSalt: tenant.cacheSalt, TokenIDs: tokenIDs}
	initial := []BackendCandidate{
		{Backend: firstBackend, Healthy: true, Ready: true},
		{Backend: secondBackend, Healthy: true, Ready: true},
	}
	key, _, err := router.affinityKey(routing)
	if err != nil {
		t.Fatal(err)
	}
	preferred, _, err := router.preferredBackend(initial, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range backends {
		load := 0.0
		if backend == preferred {
			load = 5
		}
		collector.states[backend.ID].sample.Store(&backendLoadSample{collectedAt: time.Now(), running: load})
		collector.states[backend.ID].up.Store(true)
	}
	coordinator, err := admission.NewMemoryCoordinator(100)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	gateway, err := New(DefaultConfig(), registry, &http.Client{Timeout: time.Second}, slog.New(slog.NewJSONHandler(&logs, nil)),
		WithTenantRegistry(tenantRegistry), WithAdmissionCoordinator(coordinator),
		WithBackendMetricsCollector(collector), WithRouter(router), WithRoutingKeyTokenizer(tokenizer),
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	response := requestGateway(t, server.Client(), server.URL)
	_, readErr := io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Inference-Backend") == preferred.ID {
		t.Fatalf("response status=%d backend=%q; wanted escape away from %q", response.StatusCode, response.Header.Get("X-Inference-Backend"), preferred.ID)
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
	if terminal == nil || terminal["router_policy"] != string(RoutingPolicyHashAffinity) || terminal["router_fallback_reason"] != string(FallbackReasonBackendLoadEscape) || terminal["backend_generation"] == "" {
		t.Fatalf("terminal record=%v; want hash_affinity/backend_load_escape", terminal)
	}
	collector.states[preferred.ID].sample.Store(&backendLoadSample{collectedAt: time.Now().Add(-2 * time.Second), running: 5})
	staleResponse := requestGateway(t, server.Client(), server.URL)
	_, readErr = io.Copy(io.Discard, staleResponse.Body)
	staleResponse.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if staleResponse.StatusCode != http.StatusOK || staleResponse.Header.Get("X-Inference-Backend") != preferred.ID {
		t.Fatalf("stale telemetry selected %q with status %d; want hash-preferred %q", staleResponse.Header.Get("X-Inference-Backend"), staleResponse.StatusCode, preferred.ID)
	}
	var sawEscapeUnavailable bool
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["msg"] == "request terminal" && entry["router_fallback_reason"] == string(FallbackReasonEscapeUnavailable) {
			sawEscapeUnavailable = entry["router_policy"] == string(RoutingPolicyHashAffinity) && entry["backend_generation"] != ""
		}
	}
	if !sawEscapeUnavailable {
		t.Fatal("terminal log did not record hash_affinity/escape_unavailable with the selected generation")
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
	if !strings.Contains(string(metricsBody), `inference_gateway_routing_decisions_total{policy="hash_affinity",fallback_reason="backend_load_escape"} 1`) {
		t.Fatalf("hash escape decision missing from metrics:\n%s", metricsBody)
	}
	if !strings.Contains(string(metricsBody), `inference_gateway_routing_decisions_total{policy="hash_affinity",fallback_reason="escape_unavailable"} 1`) {
		t.Fatalf("stale telemetry decision missing from metrics:\n%s", metricsBody)
	}
}
