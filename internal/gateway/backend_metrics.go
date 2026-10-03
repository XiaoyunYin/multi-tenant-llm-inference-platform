package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxBackendMetricsBytes = 1 << 20

type backendLoadSample struct {
	collectedAt time.Time
	running     float64
	waiting     float64
	kvUsage     float64
}

type backendMetricsState struct {
	sample         atomic.Pointer[backendLoadSample]
	up             atomic.Bool
	scrapeErrors   atomic.Uint64
	lastDurationNS atomic.Int64
}

type BackendMetricsSnapshot struct {
	BackendID      string
	Generation     string
	Up             bool
	HasSample      bool
	Fresh          bool
	Running        float64
	Waiting        float64
	KVUsage        float64
	SampleAge      time.Duration
	ScrapeDuration time.Duration
	ScrapeErrors   uint64
}

type BackendMetricsCollector struct {
	backends      []*Backend
	client        *http.Client
	interval      time.Duration
	maxAge        time.Duration
	states        map[string]*backendMetricsState
	registry      *Registry
	dynamicMu     sync.Mutex
	dynamicStates map[string]*backendMetricsState

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewDiscoveryMetricsCollector never shares load samples across pod generations.
func NewDiscoveryMetricsCollector(registry *Registry, client *http.Client, interval, maxAge time.Duration) (*BackendMetricsCollector, error) {
	if registry == nil || client == nil || interval <= 0 || maxAge <= 0 {
		return nil, errors.New("registry, client, and positive metrics durations are required")
	}
	return &BackendMetricsCollector{registry: registry, client: client, interval: interval, maxAge: maxAge, dynamicStates: make(map[string]*backendMetricsState)}, nil
}

type metricsTarget struct {
	backend *Backend
	state   *backendMetricsState
}

func (c *BackendMetricsCollector) targets() []metricsTarget {
	if c.registry == nil {
		targets := make([]metricsTarget, 0, len(c.backends))
		for _, backend := range c.backends {
			targets = append(targets, metricsTarget{backend, c.states[backend.ID]})
		}
		return targets
	}
	c.dynamicMu.Lock()
	defer c.dynamicMu.Unlock()
	targets := make([]metricsTarget, 0)
	current := make(map[string]*backendMetricsState)
	for _, backend := range c.registry.Backends() {
		key := backend.ID + "@" + backend.Generation + "=" + backend.URL.String()
		state := c.dynamicStates[key]
		if state == nil {
			state = &backendMetricsState{}
		}
		current[key] = state
		targets = append(targets, metricsTarget{backend, state})
	}
	c.dynamicStates = current
	return targets
}

func NewBackendMetricsCollector(backends []*Backend, client *http.Client, interval, maxAge time.Duration) (*BackendMetricsCollector, error) {
	if len(backends) == 0 {
		return nil, errors.New("at least one backend is required")
	}
	if client == nil {
		return nil, errors.New("metrics client is required")
	}
	if interval <= 0 || maxAge <= 0 {
		return nil, errors.New("metrics interval and maximum age must be positive")
	}
	states := make(map[string]*backendMetricsState, len(backends))
	for _, backend := range backends {
		if backend == nil {
			return nil, errors.New("backend must not be nil")
		}
		if _, exists := states[backend.ID]; exists {
			return nil, errors.New("backend IDs must be unique")
		}
		states[backend.ID] = &backendMetricsState{}
	}
	return &BackendMetricsCollector{backends: backends, client: client, interval: interval, maxAge: maxAge, states: states}, nil
}

func (c *BackendMetricsCollector) Poll(ctx context.Context) {
	var wait sync.WaitGroup
	for _, target := range c.targets() {
		wait.Add(1)
		go func() {
			defer wait.Done()
			c.scrape(ctx, target.backend, target.state)
		}()
	}
	wait.Wait()
}

func (c *BackendMetricsCollector) scrape(ctx context.Context, backend *Backend, state *backendMetricsState) {
	started := time.Now()
	defer func() { state.lastDurationNS.Store(time.Since(started).Nanoseconds()) }()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL.JoinPath("metrics").String(), nil)
	if err != nil {
		state.up.Store(false)
		state.scrapeErrors.Add(1)
		return
	}
	response, err := c.client.Do(request)
	if err != nil {
		state.up.Store(false)
		state.scrapeErrors.Add(1)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		state.up.Store(false)
		state.scrapeErrors.Add(1)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxBackendMetricsBytes+1))
	if err != nil || len(payload) > maxBackendMetricsBytes {
		state.up.Store(false)
		state.scrapeErrors.Add(1)
		return
	}
	running, waiting, kvUsage, err := parseBackendLoadMetrics(payload)
	if err != nil {
		state.up.Store(false)
		state.scrapeErrors.Add(1)
		return
	}
	state.sample.Store(&backendLoadSample{
		collectedAt: time.Now(), running: running, waiting: waiting, kvUsage: kvUsage,
	})
	state.up.Store(true)
}

func (c *BackendMetricsCollector) Snapshots(now time.Time) []BackendMetricsSnapshot {
	snapshots := make([]BackendMetricsSnapshot, 0)
	for _, target := range c.targets() {
		backend, state := target.backend, target.state
		snapshot := BackendMetricsSnapshot{
			BackendID: backend.ID, Up: state.up.Load(),
			Generation:     backend.Generation,
			ScrapeDuration: time.Duration(state.lastDurationNS.Load()),
			ScrapeErrors:   state.scrapeErrors.Load(),
		}
		if sample := state.sample.Load(); sample != nil {
			snapshot.HasSample = true
			snapshot.Running = sample.running
			snapshot.Waiting = sample.waiting
			snapshot.KVUsage = sample.kvUsage
			snapshot.SampleAge = max(time.Duration(0), now.Sub(sample.collectedAt))
			snapshot.Fresh = snapshot.Up && snapshot.SampleAge <= c.maxAge
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

func (c *BackendMetricsCollector) Start(parent context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	c.cancel = cancel
	c.done = make(chan struct{})
	go func() {
		defer close(c.done)
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		c.Poll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.Poll(ctx)
			}
		}
	}()
}

func (c *BackendMetricsCollector) Close() {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.cancel = nil
	c.done = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func parseBackendLoadMetrics(payload []byte) (float64, float64, float64, error) {
	required := map[string]*float64{
		"vllm:num_requests_running": nil,
		"vllm:num_requests_waiting": nil,
		"vllm:kv_cache_usage_perc":  nil,
	}
	scanner := bufio.NewScanner(strings.NewReader(string(payload)))
	scanner.Buffer(make([]byte, 4096), maxBackendMetricsBytes)
	for scanner.Scan() {
		name, value, ok, err := parsePrometheusSample(scanner.Text())
		if err != nil {
			return 0, 0, 0, err
		}
		if !ok {
			continue
		}
		if _, wanted := required[name]; !wanted {
			continue
		}
		if required[name] != nil {
			return 0, 0, 0, fmt.Errorf("backend metric %s has multiple series", name)
		}
		copyValue := value
		required[name] = &copyValue
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, 0, fmt.Errorf("scan backend metrics: %w", err)
	}
	for name, value := range required {
		if value == nil {
			return 0, 0, 0, fmt.Errorf("backend metric %s is missing", name)
		}
	}
	running := *required["vllm:num_requests_running"]
	waiting := *required["vllm:num_requests_waiting"]
	kvUsage := *required["vllm:kv_cache_usage_perc"]
	if running < 0 || waiting < 0 || math.Trunc(running) != running || math.Trunc(waiting) != waiting {
		return 0, 0, 0, errors.New("backend request-count metrics must be non-negative integers")
	}
	if kvUsage < 0 || kvUsage > 1 {
		return 0, 0, 0, errors.New("backend KV-cache usage must be between zero and one")
	}
	return running, waiting, kvUsage, nil
}

func parsePrometheusSample(line string) (string, float64, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", 0, false, nil
	}
	separator := -1
	inLabels, quoted, escaped := false, false, false
	for index, character := range line {
		switch {
		case escaped:
			escaped = false
		case quoted && character == '\\':
			escaped = true
		case character == '"':
			quoted = !quoted
		case !quoted && character == '{':
			inLabels = true
		case !quoted && character == '}':
			inLabels = false
		case !quoted && !inLabels && (character == ' ' || character == '\t'):
			separator = index
		}
		if separator >= 0 {
			break
		}
	}
	if separator < 1 || quoted || inLabels {
		return "", 0, false, errors.New("malformed Prometheus sample")
	}
	series := line[:separator]
	name := series
	if labels := strings.IndexByte(series, '{'); labels >= 0 {
		if !strings.HasSuffix(series, "}") {
			return "", 0, false, errors.New("malformed Prometheus labels")
		}
		name = series[:labels]
	}
	fields := strings.Fields(line[separator:])
	if name == "" || len(fields) == 0 {
		return "", 0, false, errors.New("malformed Prometheus sample")
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return "", 0, false, errors.New("Prometheus sample value must be finite")
	}
	return name, value, true, nil
}
