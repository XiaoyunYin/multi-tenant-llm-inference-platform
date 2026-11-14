package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

var ErrNoHealthyBackend = errors.New("no healthy backend")

// Each concurrent health check has this deadline, even if the client has none.
const HealthCheckTimeout = time.Second
const HealthFreshnessMargin = 100 * time.Millisecond
const CapacityReportTimeout = 250 * time.Millisecond

type Backend struct {
	ID         string
	Generation string
	URL        *url.URL

	healthy atomic.Bool
	ready   atomic.Bool
	checked atomic.Int64
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
	backends         []*Backend
	backendMu        sync.RWMutex
	roundRobin       *RoundRobinRouter
	client           *http.Client
	interval         time.Duration
	mu               sync.Mutex
	cancel           context.CancelFunc
	done             chan struct{}
	healthLogger     atomic.Pointer[slog.Logger]
	discoveryUnknown atomic.Bool // closes routing immediately, before a pending report finishes
	discoveryMode    bool
	capacityReporter func(context.Context, int64, bool) error
	measurement      *MeasurementRecorder
}

// SetHealthLogger enables bounded poll timings and transitions, without addresses.
func (r *Registry) SetHealthLogger(logger *slog.Logger) { r.healthLogger.Store(logger) }

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
	r := &Registry{roundRobin: NewRoundRobinRouter(), client: client, interval: interval, discoveryMode: true}
	r.discoveryUnknown.Store(true)
	return r, nil
}

func (r *Registry) Backends() []*Backend {
	if r.discoveryUnknown.Load() {
		return nil
	}
	r.backendMu.RLock()
	defer r.backendMu.RUnlock()
	if r.discoveryUnknown.Load() {
		return nil
	}
	return append([]*Backend(nil), r.backends...)
}

// ReplaceBackends retains health only for exactly the same pod incarnation.
// Removed pointers remain valid for requests already in flight.
func (r *Registry) ReplaceBackends(backends []*Backend) {
	r.replaceMembership(backends, false)
}

func (r *Registry) replaceMembership(backends []*Backend, unknown bool) {
	// An in-flight publication must not delay clearing locally routable members.
	if unknown {
		r.discoveryUnknown.Store(true)
	}
	r.backendMu.Lock()
	defer r.backendMu.Unlock()
	for i, backend := range backends {
		retained := false
		for _, old := range r.backends {
			if old.ID == backend.ID && old.Generation == backend.Generation && old.URL.String() == backend.URL.String() {
				backends[i] = old
				retained = true
				break
			}
		}
		if !retained {
			backend.healthy.Store(false)
			backend.ready.Store(false)
			backend.checked.Store(0)
		}
	}
	r.backends = append([]*Backend(nil), backends...)
	r.discoveryUnknown.Store(unknown)
}

func (r *Registry) DiscoveryUnknown() bool {
	if r.discoveryUnknown.Load() {
		return true
	}
	r.backendMu.RLock()
	defer r.backendMu.RUnlock()
	return r.localDiscoveryGateLocked()
}

// Unsampled members withhold reports, but sampled eligible members can serve
// through an addition. Start/recovery stays closed until one can serve.
func (r *Registry) localDiscoveryGateLocked() bool {
	if r.discoveryUnknown.Load() {
		return true
	}
	if !r.discoveryMode {
		return false
	}
	unsampled := false
	for _, b := range r.backends {
		if b.checked.Load() == 0 {
			unsampled = true
		} else if b.Healthy() && b.Ready() {
			return false
		}
	}
	return unsampled
}

// A validated snapshot is not a count until every current pointer has completed
// a check since joining. An empty snapshot is a known count of zero.
func (r *Registry) allSampledLocked() bool {
	for _, b := range r.backends {
		if b.checked.Load() == 0 {
			return false
		}
	}
	return true
}

func (r *Registry) HealthFreshnessWindow() time.Duration {
	// Allow a report after the previous batch and a pending publication ahead
	// of a membership writer before taking the next health snapshot.
	return r.interval + HealthCheckTimeout + 2*CapacityReportTimeout + HealthFreshnessMargin
}

// Selected pointers may drain, but a new dispatch must still belong to the
// current known UID/address snapshot. In particular unknown clears immediately.
func (r *Registry) CanDispatch(selected *Backend) bool {
	if r.discoveryUnknown.Load() {
		return false
	}
	r.backendMu.RLock()
	defer r.backendMu.RUnlock()
	if r.localDiscoveryGateLocked() {
		return false
	}
	for _, b := range r.backends {
		if b == selected && b.Healthy() && b.Ready() {
			return true
		}
	}
	return false
}

func (r *Registry) SetCapacityReporter(reporter func(context.Context, int64, bool) error) {
	r.backendMu.Lock()
	defer r.backendMu.Unlock()
	r.capacityReporter = reporter
}

// Serialize the snapshot and publication with membership changes. Unknown
// sends only the interruption marker; it never refreshes the last report TTL.
func (r *Registry) ReportCapacity(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, CapacityReportTimeout)
	defer cancel()
	r.backendMu.RLock()
	defer r.backendMu.RUnlock()
	if r.capacityReporter == nil {
		return nil
	}
	// Read completeness before counting. A first check completing during this
	// loop must not turn a partially observed count into a known report.
	known := !r.discoveryUnknown.Load() && r.allSampledLocked()
	var healthy int64
	now := time.Now()
	for _, b := range r.backends {
		checked := b.checked.Load()
		if b.Healthy() && b.Ready() && checked > 0 && now.Sub(time.Unix(0, checked)) <= r.HealthFreshnessWindow() {
			healthy++
		}
	}
	r.measurement.Record("report_intent", map[string]any{"n": healthy, "report_known": known && !r.discoveryUnknown.Load()})
	return r.capacityReporter(ctx, healthy, known && !r.discoveryUnknown.Load())
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
	var checks sync.WaitGroup
	for _, backend := range r.Backends() {
		checks.Go(func() { r.check(ctx, backend) })
	}
	checks.Wait()
	r.measurementSnapshot("health", map[string]any{})
	if ctx.Err() != nil {
		return // canceled checks during shutdown are not capacity observations
	}
	_ = r.ReportCapacity(ctx)
}

func (r *Registry) check(ctx context.Context, backend *Backend) {
	ctx, cancel := context.WithTimeout(ctx, HealthCheckTimeout)
	defer cancel()
	started := time.Now()
	beforeHealthy, beforeReady := backend.Healthy(), backend.Ready()
	statusCode, errorClass := 0, "none"
	defer func() {
		backend.checked.Store(time.Now().UnixNano())
		if logger := r.healthLogger.Load(); logger != nil {
			logger.Info("backend health poll", "backend_id", backend.ID, "latency_ms", time.Since(started).Seconds()*1000, "http_status", statusCode, "error_class", errorClass, "healthy_before", beforeHealthy, "healthy_after", backend.Healthy(), "ready_before", beforeReady, "ready_after", backend.Ready())
		}
	}()
	markUnavailable := func() {
		backend.healthy.Store(false)
		backend.ready.Store(false)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL.JoinPath("health").String(), nil)
	if err != nil {
		errorClass = "invalid_request"
		markUnavailable()
		return
	}
	response, err := r.client.Do(request)
	if err != nil {
		errorClass = "transport"
		markUnavailable()
		return
	}
	defer response.Body.Close()
	statusCode = response.StatusCode
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	if err != nil || response.StatusCode != http.StatusOK {
		errorClass = "body_or_http_status"
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
		errorClass = "identity_mismatch"
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
