package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

var ErrNoHealthyBackend = errors.New("no healthy backend")

type Backend struct {
	ID         string
	Generation string
	URL        *url.URL

	healthy atomic.Bool
	ready   atomic.Bool
}

func NewBackend(id, rawURL string, generation ...string) (*Backend, error) {
	if len(generation) > 1 {
		return nil, errors.New("at most one backend generation may be supplied")
	}
	if !tenantIDPattern.MatchString(id) {
		return nil, errors.New("backend ID must use only letters, digits, dots, underscores, or hyphens")
	}
	replicaGeneration := "0"
	if len(generation) == 1 {
		replicaGeneration = generation[0]
		if !tenantIDPattern.MatchString(replicaGeneration) {
			return nil, errors.New("backend generation must use only letters, digits, dots, underscores, or hyphens")
		}
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("backend URL must be absolute")
	}
	backend := &Backend{ID: id, Generation: replicaGeneration, URL: parsed}
	backend.healthy.Store(true)
	backend.ready.Store(true)
	return backend, nil
}

func (b *Backend) Healthy() bool { return b.healthy.Load() }
func (b *Backend) Ready() bool   { return b.ready.Load() }

type Registry struct {
	backends   []*Backend
	backendMu  sync.RWMutex
	roundRobin *RoundRobinRouter
	client     *http.Client
	interval   time.Duration
	mu         sync.Mutex
	cancel     context.CancelFunc
	done       chan struct{}
}

func NewRegistry(backends []*Backend, client *http.Client, interval time.Duration) (*Registry, error) {
	if len(backends) == 0 {
		return nil, errors.New("at least one backend is required")
	}
	if client == nil {
		return nil, errors.New("health client is required")
	}
	if interval <= 0 {
		return nil, errors.New("health interval must be positive")
	}
	identities := make(map[string]struct{}, len(backends))
	addresses := make(map[string]struct{}, len(backends))
	for _, backend := range backends {
		if backend == nil {
			return nil, errors.New("backend must not be nil")
		}
		if _, exists := identities[backend.ID]; exists {
			return nil, errors.New("backend IDs must be unique")
		}
		identities[backend.ID] = struct{}{}
		address := backend.URL.String()
		if _, exists := addresses[address]; exists {
			return nil, errors.New("backend URLs must be unique")
		}
		addresses[address] = struct{}{}
	}
	return &Registry{backends: backends, roundRobin: NewRoundRobinRouter(), client: client, interval: interval}, nil
}

// NewDiscoveryRegistry starts unavailable until discovery and health both succeed.
func NewDiscoveryRegistry(client *http.Client, interval time.Duration) (*Registry, error) {
	if client == nil || interval <= 0 {
		return nil, errors.New("health client and positive interval are required")
	}
	return &Registry{roundRobin: NewRoundRobinRouter(), client: client, interval: interval}, nil
}

func (r *Registry) Backends() []*Backend {
	r.backendMu.RLock()
	defer r.backendMu.RUnlock()
	return append([]*Backend(nil), r.backends...)
}

// ReplaceBackends retains health only for exactly the same pod incarnation.
// Removed pointers remain valid for requests already in flight.
func (r *Registry) ReplaceBackends(backends []*Backend) {
	r.backendMu.Lock()
	defer r.backendMu.Unlock()
	for i, backend := range backends {
		backend.healthy.Store(false)
		backend.ready.Store(false)
		for _, old := range r.backends {
			if old.ID == backend.ID && old.Generation == backend.Generation && old.URL.String() == backend.URL.String() {
				backends[i] = old
				break
			}
		}
	}
	r.backends = append([]*Backend(nil), backends...)
}

func (r *Registry) AnyHealthy() bool {
	for _, backend := range r.Backends() {
		if backend.Healthy() {
			return true
		}
	}
	return false
}

func (r *Registry) AnyEligible() bool {
	for _, backend := range r.Backends() {
		if backend.Healthy() && backend.Ready() {
			return true
		}
	}
	return false
}

func (r *Registry) Candidates(loadSnapshots []BackendMetricsSnapshot) []BackendCandidate {
	loads := make(map[string]BackendMetricsSnapshot, len(loadSnapshots))
	for _, snapshot := range loadSnapshots {
		loads[snapshot.BackendID] = snapshot
	}
	backends := r.Backends()
	candidates := make([]BackendCandidate, 0, len(backends))
	for _, backend := range backends {
		candidate := BackendCandidate{Backend: backend, Healthy: backend.Healthy(), Ready: backend.Ready()}
		if snapshot, exists := loads[backend.ID]; exists && (snapshot.Generation == "" || snapshot.Generation == backend.Generation) {
			candidate.Load = snapshot
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func (r *Registry) Select() (*Backend, error) {
	selection := NewBackendSelectionBoundary(r.roundRobin, nil)
	decision, err := selection.Select(r.Candidates(nil))
	return decision.Backend, err
}

func (r *Registry) Poll(ctx context.Context) {
	for _, backend := range r.Backends() {
		r.check(ctx, backend)
	}
}

func (r *Registry) check(ctx context.Context, backend *Backend) {
	markUnavailable := func() {
		backend.healthy.Store(false)
		backend.ready.Store(false)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL.JoinPath("health").String(), nil)
	if err != nil {
		markUnavailable()
		return
	}
	response, err := r.client.Do(request)
	if err != nil {
		markUnavailable()
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	if err != nil || response.StatusCode != http.StatusOK {
		markUnavailable()
		return
	}
	var state struct {
		BackendID string `json:"backend_id"`
		Healthy   *bool  `json:"healthy"`
		Ready     *bool  `json:"ready"`
	}
	_ = json.Unmarshal(body, &state)
	if state.BackendID != "" && state.BackendID != backend.ID {
		markUnavailable()
		return
	}
	healthy, ready := true, true
	if state.Healthy != nil {
		healthy = *state.Healthy
	}
	if state.Ready != nil {
		ready = *state.Ready
	}
	backend.healthy.Store(healthy)
	backend.ready.Store(ready)
}

func (r *Registry) Start(parent context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		r.Poll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.Poll(ctx)
			}
		}
	}()
}

func (r *Registry) Close() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel = nil
	r.done = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
