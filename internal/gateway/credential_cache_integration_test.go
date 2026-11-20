package gateway

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type credentialReadProbe struct {
	calls   atomic.Int64
	entered chan struct{}
	release <-chan struct{}
}

func (*credentialReadProbe) DialHook(next redis.DialHook) redis.DialHook { return next }

func (*credentialReadProbe) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (p *credentialReadProbe) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() != "hgetall" {
			return next(ctx, cmd)
		}
		call := p.calls.Add(1)
		err := next(ctx, cmd)
		if p.entered != nil && call <= credentialReadLimit {
			p.entered <- struct{}{}
			<-p.release
		}
		return err
	}
}

func probeCredentialReads(t *testing.T, store *CredentialStore, probe *credentialReadProbe) {
	t.Helper()
	opts := *store.primary.Options()
	client := redis.NewClient(&opts)
	client.AddHook(probe)
	t.Cleanup(func() { client.Close() })
	store.primary = client
}

func TestCredentialMissConcurrencyBound(t *testing.T) {
	client, storeA, registryA, first, second := managedFixture(t)
	storeB := NewCredentialStore(client, second)
	registryB := *registryA
	registryB.managed = storeB
	backend := streamHandler(contentEvent + finishEvent + doneEvent)
	_, a := newTestGatewayWithAdmission(t, DefaultConfig(), nil, registryA, first, backend)
	_, b := newTestGatewayWithAdmission(t, DefaultConfig(), nil, &registryB, second, backend)
	release := make(chan struct{})
	defer close(release)

	for i, fixture := range []struct {
		url   string
		store *CredentialStore
	}{{a.URL, storeA}, {b.URL, storeB}} {
		probe := &credentialReadProbe{
			entered: make(chan struct{}, credentialReadLimit),
			release: release,
		}
		probeCredentialReads(t, fixture.store, probe)
		done := make(chan struct{}, credentialReadLimit)
		t.Cleanup(func() {
			for range credentialReadLimit {
				<-done
			}
		})
		for j := range credentialReadLimit {
			go func() {
				defer func() { done <- struct{}{} }()
				key := fmt.Sprintf("%032x.%064x", i*credentialReadLimit+j, 1)
				status := managedRequest(t, fixture.url, key, managedBody)
				if status != http.StatusUnauthorized && status != http.StatusServiceUnavailable {
					t.Errorf("unexpected unknown-key status: %d", status)
				}
			}()
		}
		for range credentialReadLimit {
			select {
			case <-probe.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("primary read did not start")
			}
		}
		for j := range 2 * credentialReadLimit {
			key := fmt.Sprintf("%032x.%064x", 100+j, 1)
			if status := managedRequest(t, fixture.url, key, managedBody); status != http.StatusServiceUnavailable {
				t.Fatalf("at read limit: status %d", status)
			}
		}
		if got := probe.calls.Load(); got != credentialReadLimit {
			t.Fatalf("primary read calls at limit = %d", got)
		}
	}
}

func TestCachedCredentialFencedAcrossGateways(t *testing.T) {
	client, storeA, registryA, first, second := managedFixture(t)
	storeB := NewCredentialStore(client, second)
	registryB := *registryA
	registryB.managed = storeB
	probes := [2]*credentialReadProbe{{}, {}}
	probeCredentialReads(t, storeA, probes[0])
	probeCredentialReads(t, storeB, probes[1])

	var dispatches atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			dispatches.Add(1)
		}
		streamHandler(contentEvent+finishEvent+doneEvent)(w, r)
	})
	_, a := newTestGatewayWithAdmission(t, DefaultConfig(), nil, registryA, first, backend)
	_, b := newTestGatewayWithAdmission(t, DefaultConfig(), nil, &registryB, second, backend)
	endpoints := []string{a.URL, b.URL}
	warm := func(key string) {
		t.Helper()
		for _, url := range endpoints {
			if status := managedRequest(t, url, key, managedBody); status != http.StatusOK {
				t.Fatalf("warm status = %d", status)
			}
		}
	}

	ctx := context.Background()
	revoked := issueTestKey(t, storeA, "tenant-a")
	warm(revoked)
	id, _, _ := strings.Cut(revoked, ".")
	if err := client.HSet(ctx, first.CredentialKey(id), "revoked_ms", time.Now().UnixMilli()).Err(); err != nil {
		t.Fatal(err)
	}
	for i, url := range endpoints {
		if status := managedRequest(t, url, revoked, managedBody); status != http.StatusUnauthorized {
			t.Fatalf("revoked cached key: status %d", status)
		}
		store := []*CredentialStore{storeA, storeB}[i]
		if _, present := store.cached(id); probes[i].calls.Load() != 1 || present {
			t.Fatal("revocation did not deny and evict without another primary read")
		}
	}

	old := issueTestKey(t, storeA, "tenant-a")
	warm(old)
	id, _, _ = strings.Cut(old, ".")
	salt := [16]byte{1}
	secret := [32]byte{2}
	verifier := credentialDigest(salt[:], secret[:])
	if err := client.HSet(ctx, first.CredentialKey(id), "generation", 2,
		"salt", hex.EncodeToString(salt[:]), "verifier", hex.EncodeToString(verifier[:])).Err(); err != nil {
		t.Fatal(err)
	}
	newKey := id + "." + hex.EncodeToString(secret[:])
	if status := managedRequest(t, a.URL, newKey, managedBody); status != http.StatusOK || probes[0].calls.Load() != 3 {
		t.Fatalf("new secret did not refresh once at gateway A: %d", status)
	}
	if status := managedRequest(t, a.URL, old, managedBody); status != http.StatusUnauthorized || probes[0].calls.Load() != 4 {
		t.Fatalf("old secret accepted after refresh at gateway A: %d", status)
	}
	if status := managedRequest(t, b.URL, old, managedBody); status != http.StatusUnauthorized || probes[1].calls.Load() != 2 {
		t.Fatalf("old generation not fenced on cache hit at gateway B: %d", status)
	}
	if status := managedRequest(t, b.URL, newKey, managedBody); status != http.StatusOK || probes[1].calls.Load() != 3 {
		t.Fatalf("new secret did not read once at gateway B: %d", status)
	}
	if got := dispatches.Load(); got != 6 {
		t.Fatalf("dispatches = %d, want 6", got)
	}
}
