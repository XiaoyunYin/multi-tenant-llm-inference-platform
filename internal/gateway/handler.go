package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"multi-tenant-llm-inference-platform/internal/admission"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

var errGatewayShutdown = errors.New("gateway shutdown")

const cancellationPropagationWindow = 10 * time.Millisecond

const defaultMaxEventBytes = 64 << 10

// Keep the full event bound without allocating a 64KiB+1 reader buffer for
// every short stream. Custom limits retain their existing allocation path.
var defaultEventReaders = sync.Pool{New: func() any {
	return bufio.NewReaderSize(nil, defaultMaxEventBytes+1)
}}

type terminalCause uint8

const (
	terminalCompleted terminalCause = iota
	terminalRejected
	terminalClientCancelled
	terminalUpstreamFailure
	terminalProtocolError
	terminalTimeout
	terminalStreamInterrupted
	terminalWriteFailure
	terminalShutdown
	terminalInternalError
	terminalCauseCount
)

func (cause terminalCause) String() string {
	return [...]string{
		"completed", "rejected", "client_cancelled", "upstream_failure",
		"upstream_protocol_error", "timeout", "stream_interrupted", "write_failure",
		"shutdown", "internal_error",
	}[cause]
}

type requestTerminal struct {
	cause     terminalCause
	code      string
	backendID string
	committed bool
}

type unsupportedParameterError struct{ name string }

func (e *unsupportedParameterError) Error() string { return "unsupported parameter: " + e.name }

type Config struct {
	MaxRequestBytes        int64
	MaxEventBytes          int
	MaxConcurrent          int
	FirstItemTimeout       time.Duration
	StreamIdleTimeout      time.Duration
	TotalTimeout           time.Duration
	ClientWriteTimeout     time.Duration
	AdmissionTimeout       time.Duration
	ReleaseTimeout         time.Duration
	RoutingTokenizeTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{
		MaxRequestBytes:        1 << 20,
		MaxEventBytes:          defaultMaxEventBytes,
		MaxConcurrent:          64,
		FirstItemTimeout:       5 * time.Second,
		StreamIdleTimeout:      30 * time.Second,
		TotalTimeout:           2 * time.Minute,
		ClientWriteTimeout:     5 * time.Second,
		AdmissionTimeout:       250 * time.Millisecond,
		ReleaseTimeout:         time.Second,
		RoutingTokenizeTimeout: 500 * time.Millisecond,
	}
}

func (c Config) validate() error {
	if c.MaxRequestBytes <= 0 || c.MaxEventBytes <= 0 || c.MaxConcurrent <= 0 {
		return errors.New("request, event, and concurrency limits must be positive")
	}
	if c.FirstItemTimeout <= 0 || c.StreamIdleTimeout <= 0 || c.TotalTimeout <= 0 || c.ClientWriteTimeout <= 0 || c.AdmissionTimeout <= 0 || c.ReleaseTimeout <= 0 || c.RoutingTokenizeTimeout <= 0 {
		return errors.New("gateway timeouts must be positive")
	}
	return nil
}

type Gateway struct {
	config           Config
	registry         *Registry
	backendSelection *BackendSelectionBoundary
	routingTokenizer RoutingKeyTokenizer
	client           *http.Client
	tenants          *TenantRegistry
	admission        admission.Coordinator
	logger           *slog.Logger
	metrics          Metrics
	semaphore        chan struct{}
	draining         atomic.Bool
	routingEvents    bool
	activeMu         sync.Mutex
	active           map[uint64]context.CancelCauseFunc
	changed          chan struct{}
	nextID           uint64
	tracer           trace.Tracer
}

type Option func(*Gateway) error

func WithTenantRegistry(tenants *TenantRegistry) Option {
	return func(gateway *Gateway) error {
		if tenants == nil {
			return errors.New("tenant registry is required")
		}
		gateway.tenants = tenants
		return nil
	}
}

func WithAdmissionCoordinator(coordinator admission.Coordinator) Option {
	return func(gateway *Gateway) error {
		if coordinator == nil {
			return errors.New("admission coordinator is required")
		}
		gateway.admission = coordinator
		return nil
	}
}

func WithBackendMetricsCollector(collector *BackendMetricsCollector) Option {
	return func(gateway *Gateway) error {
		if collector == nil {
			return errors.New("backend metrics collector is required")
		}
		gateway.metrics.backendMetrics = collector
		return nil
	}
}

func WithRouter(router Router) Option {
	return func(gateway *Gateway) error {
		if router == nil {
			return errors.New("router is required")
		}
		if _, known := routingPolicyIndex(router.PolicyName()); !known {
			return fmt.Errorf("unsupported router policy %q", router.PolicyName())
		}
		gateway.backendSelection.router = router
		return nil
	}
}

func WithRoutingKeyTokenizer(tokenizer RoutingKeyTokenizer) Option {
	return func(gateway *Gateway) error {
		if tokenizer == nil {
			return errors.New("routing-key tokenizer is required")
		}
		gateway.routingTokenizer = tokenizer
		return nil
	}
}

func New(config Config, registry *Registry, client *http.Client, logger *slog.Logger, options ...Option) (*Gateway, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if registry == nil || client == nil {
		return nil, errors.New("registry and upstream client are required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	gateway := &Gateway{
		config: config, registry: registry, backendSelection: NewBackendSelectionBoundary(NewRoundRobinRouter(), NewRandomTieBreaker()), client: client, logger: logger,
		semaphore: make(chan struct{}, config.MaxConcurrent), active: make(map[uint64]context.CancelCauseFunc), changed: make(chan struct{}),
		tracer: otel.Tracer("multi-tenant-llm-inference-platform/gateway"),
	}
	backendIDs := make([]string, 0)
	for _, backend := range registry.Backends() {
		backendIDs = append(backendIDs, backend.ID)
	}
	gateway.metrics.registerRoutingTokenizeBackends(backendIDs)
	for _, option := range options {
		if err := option(gateway); err != nil {
			return nil, err
		}
	}
	if gateway.tenants == nil {
		return nil, errors.New("tenant registry is required")
	}
	if gateway.admission == nil {
		return nil, errors.New("admission coordinator is required")
	}
	if gateway.backendSelection.RequiresRoutingContext() && gateway.routingTokenizer == nil {
		return nil, errors.New("contextual routing requires a routing-key tokenizer")
	}
	return gateway, nil
}

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", &g.metrics)
	mux.HandleFunc("/healthz", g.health)
	mux.HandleFunc("/readyz", g.ready)
	mux.HandleFunc("/v1/chat/completions", g.chatCompletions)
	return mux
}

func (g *Gateway) SetDraining(draining bool) {
	g.activeMu.Lock()
	g.draining.Store(draining)
	g.signalActiveChangeLocked()
	g.activeMu.Unlock()
}
func (g *Gateway) Metrics() MetricsSnapshot { return g.metrics.Snapshot() }

// WithRoutingEvents enables CPU rollout evidence without changing default logs.
func WithRoutingEvents() Option {
	return func(g *Gateway) error { g.routingEvents = true; return nil }
}

type ShutdownResult struct{ GraceExpired bool }

func (g *Gateway) Shutdown(gracePeriod, hardStop time.Duration) (ShutdownResult, error) {
	if gracePeriod <= 0 || hardStop <= 0 {
		return ShutdownResult{}, errors.New("shutdown durations must be positive")
	}
	g.SetDraining(true)
	graceContext, cancelGrace := context.WithTimeout(context.Background(), gracePeriod)
	defer cancelGrace()
	if err := g.waitForActive(graceContext); err == nil {
		return ShutdownResult{}, nil
	}
	g.cancelActive(errGatewayShutdown)
	hardStopContext, cancelHardStop := context.WithTimeout(context.Background(), hardStop)
	defer cancelHardStop()
	if err := g.waitForActive(hardStopContext); err != nil {
		return ShutdownResult{GraceExpired: true}, fmt.Errorf("active requests did not stop: %w", err)
	}
	return ShutdownResult{GraceExpired: true}, nil
}

func (g *Gateway) waitForActive(ctx context.Context) error {
	for {
		g.activeMu.Lock()
		if len(g.active) == 0 {
			g.activeMu.Unlock()
			return nil
		}
		changed := g.changed
		g.activeMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (g *Gateway) cancelActive(cause error) {
	g.activeMu.Lock()
	cancellations := make([]context.CancelCauseFunc, 0, len(g.active))
	for _, cancel := range g.active {
		cancellations = append(cancellations, cancel)
	}
	g.activeMu.Unlock()
	for _, cancel := range cancellations {
		cancel(cause)
	}
}

func (g *Gateway) signalActiveChangeLocked() {
	close(g.changed)
	g.changed = make(chan struct{})
}

func (g *Gateway) bestEffortRelease(tenantID, reservationID, requestID string) {
	ctx, cancel := context.WithTimeout(context.Background(), g.config.ReleaseTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := g.admission.Release(ctx, tenantID, reservationID); err == nil {
			return
		} else {
			lastErr = err
		}
		if attempt == 2 {
			break
		}
		delay := time.Duration(1<<attempt) * 10 * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			attempt = 2
		case <-timer.C:
		}
	}
	g.metrics.releaseFailures.Add(1)
	g.logger.Warn("reservation release failed", "request_id", requestID, "tenant_id", tenantID, "reservation_id", reservationID, "error", lastErr)
}

func (g *Gateway) health(response http.ResponseWriter, _ *http.Request) {
	response.WriteHeader(http.StatusOK)
}

func (g *Gateway) selectBackend(ctx context.Context, requestID string, tenant *TenantPolicy, request *chatRequest) (BackendDecision, error) {
	var loadSnapshots []BackendMetricsSnapshot
	if g.metrics.backendMetrics != nil {
		loadSnapshots = g.metrics.backendMetrics.Snapshots(time.Now())
	}
	candidates := g.registry.Candidates(loadSnapshots)
	if !g.backendSelection.RequiresRoutingContext() {
		return g.selectThroughBoundary(candidates)
	}
	tokenizeStarted := time.Now()
	tokenization, err := g.routingTokenizer.TokenizeChat(ctx, requestID, request.Model, request.Messages, candidates)
	g.metrics.recordRoutingTokenizeAttempts(tokenization.AttemptedBackendIDs)
	g.metrics.recordRoutingTokenizeDuration(time.Since(tokenizeStarted), err != nil)
	if err != nil {
		return g.selectLeastLoadedFallback(candidates, FallbackReasonRoutingKeyUnavailable)
	}
	return g.selectThroughBoundary(candidates, RoutingContext{
		TenantID: tenant.ID, Model: request.Model, CacheSalt: tenant.cacheSalt, TokenIDs: tokenization.TokenIDs,
	})
}

func (g *Gateway) selectThroughBoundary(candidates []BackendCandidate, routing ...RoutingContext) (BackendDecision, error) {
	started := time.Now()
	decision, err := g.backendSelection.Select(candidates, routing...)
	g.metrics.recordRoutingLookupDuration(time.Since(started))
	return decision, err
}

func (g *Gateway) selectLeastLoadedFallback(candidates []BackendCandidate, reason FallbackReason) (BackendDecision, error) {
	started := time.Now()
	decision, err := g.backendSelection.SelectLeastLoadedFallback(candidates, reason)
	g.metrics.recordRoutingLookupDuration(time.Since(started))
	return decision, err
}

func (g *Gateway) ready(response http.ResponseWriter, _ *http.Request) {
	if g.draining.Load() || !g.registry.AnyEligible() {
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusOK)
}

type message = RoutingMessage

type chatRequest struct {
	Model       string          `json:"model"`
	Messages    []message       `json:"messages"`
	Stream      *bool           `json:"stream"`
	MaxTokens   *int            `json:"max_tokens,omitempty"`
	Temperature *float64        `json:"temperature,omitempty"`
	TopP        *float64        `json:"top_p,omitempty"`
	Seed        *int64          `json:"seed,omitempty"`
	Stop        json.RawMessage `json:"stop,omitempty"`
}

type upstreamRequest struct {
	chatRequest
	CacheSalt     string `json:"cache_salt"`
	StreamOptions struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options"`
}

func (g *Gateway) chatCompletions(response http.ResponseWriter, request *http.Request) {
	// Do not trust client trace context at the public edge. Start a fresh root
	// server span so the response header, logs, and downstream traceparent are
	// owned by this gateway rather than chosen by an unauthenticated caller.
	requestContext, span := g.tracer.Start(request.Context(), "chat.completions", trace.WithSpanKind(trace.SpanKindServer), trace.WithNewRoot())
	requestContext, traceID := ensureServerTraceContext(requestContext, span)
	request = request.WithContext(requestContext)
	requestID := newID("req")
	reservationID := newID("rsv")
	started := time.Now()
	tenantID := ""
	selection := BackendDecision{Policy: RoutingPolicyNone, FallbackReason: FallbackReasonNone}
	var routerDecisionUnixNS int64
	terminal := requestTerminal{cause: terminalInternalError, code: "internal_error"}
	var upstreamHTTPStatus, upstreamErrorCode int
	var upstreamErrorType, upstreamErrorShape string
	defer func() {
		span.SetAttributes(
			attribute.String("inference.tenant.id", tenantID),
			attribute.String("inference.backend.id", terminal.backendID),
			attribute.String("inference.backend.generation", selection.BackendGeneration),
			attribute.String("inference.terminal.cause", terminal.cause.String()),
			attribute.String("inference.terminal.code", terminal.code),
			attribute.Bool("inference.stream.committed", terminal.committed),
			attribute.String("inference.router.policy", string(selection.Policy)),
			attribute.String("inference.router.fallback_reason", string(selection.FallbackReason)),
		)
		if terminal.cause != terminalCompleted {
			span.SetStatus(codes.Error, terminal.code)
		}
		span.End()
		g.logger.Info(
			"request terminal",
			"request_id", requestID,
			"trace_id", traceID,
			"tenant_id", tenantID,
			"reservation_id", reservationID,
			"backend_id", terminal.backendID,
			"backend_generation", selection.BackendGeneration,
			"router_policy", selection.Policy,
			"router_fallback_reason", selection.FallbackReason,
			"router_decision_unix_ns", routerDecisionUnixNS,
			"committed", terminal.committed,
			"cause", terminal.cause.String(),
			"code", terminal.code,
			"upstream_http_status", upstreamHTTPStatus,
			"upstream_error_code", upstreamErrorCode,
			"upstream_error_type", upstreamErrorType,
			"upstream_error_shape", upstreamErrorShape,
			"duration_ms", time.Since(started).Milliseconds(),
		)
		g.metrics.recordTerminal(terminal.cause)
	}()
	response.Header().Set("X-Request-ID", requestID)
	response.Header().Set("X-Trace-ID", traceID)
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		terminal = requestTerminal{cause: terminalRejected, code: "invalid_request"}
		g.metrics.rejected.Add(1)
		g.writeError(response, http.StatusMethodNotAllowed, "invalid_request", requestID, false)
		return
	}
	if g.draining.Load() {
		terminal = requestTerminal{cause: terminalRejected, code: "shutting_down"}
		g.metrics.rejected.Add(1)
		g.writeError(response, http.StatusServiceUnavailable, "shutting_down", requestID, true)
		return
	}
	tenant, authErr := g.tenants.Authenticate(request.Header.Get("Authorization"))
	if authErr != nil {
		terminal = requestTerminal{cause: terminalRejected, code: "unauthenticated"}
		g.metrics.rejected.Add(1)
		g.writeError(response, http.StatusUnauthorized, "unauthenticated", requestID, false)
		return
	}
	tenantID = tenant.ID
	mediaType, _, mediaErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		terminal = requestTerminal{cause: terminalRejected, code: "unsupported_media_type"}
		g.metrics.rejected.Add(1)
		g.writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type", requestID, false)
		return
	}
	maxRequestBytes := min(g.config.MaxRequestBytes, tenant.MaxRequestBytes)
	decoded, err := g.decodeRequest(response, request, maxRequestBytes)
	if err != nil {
		terminal = requestTerminal{cause: terminalRejected, code: "invalid_request"}
		g.metrics.rejected.Add(1)
		status, code := http.StatusBadRequest, "invalid_request"
		var tooLarge *http.MaxBytesError
		var unsupported *unsupportedParameterError
		if errors.As(err, &tooLarge) {
			status, code = http.StatusRequestEntityTooLarge, "request_too_large"
		} else if errors.As(err, &unsupported) {
			code = "unsupported_parameter"
		}
		terminal.code = code
		g.writeError(response, status, code, requestID, false)
		return
	}
	if !tenant.AllowsModel(decoded.Model) {
		terminal = requestTerminal{cause: terminalRejected, code: "model_not_allowed"}
		g.metrics.rejected.Add(1)
		g.writeError(response, http.StatusForbidden, "model_not_allowed", requestID, false)
		return
	}
	if decoded.MaxTokens == nil || *decoded.MaxTokens > tenant.MaxOutputTokens {
		maxTokens := tenant.MaxOutputTokens
		decoded.MaxTokens = &maxTokens
	}
	if g.draining.Load() {
		terminal = requestTerminal{cause: terminalRejected, code: "shutting_down"}
		g.metrics.rejected.Add(1)
		g.writeError(response, http.StatusServiceUnavailable, "shutting_down", requestID, true)
		return
	}
	select {
	case g.semaphore <- struct{}{}:
	default:
		terminal = requestTerminal{cause: terminalRejected, code: "gateway_capacity"}
		g.metrics.rejected.Add(1)
		g.writeError(response, http.StatusTooManyRequests, "gateway_capacity", requestID, true)
		return
	}
	admissionContext, cancelAdmission := context.WithTimeout(request.Context(), g.config.AdmissionTimeout)
	admissionResult, admissionErr := g.admission.Admit(admissionContext, admission.Request{
		TenantID: tenant.ID, ReservationID: reservationID,
		Limits: admission.Limits{
			RequestLimit: tenant.RequestRateLimit, RequestWindow: tenant.RequestRateWindow,
			MaxConcurrent: tenant.MaxConcurrent,
		},
	})
	cancelAdmission()
	if admissionErr != nil {
		g.bestEffortRelease(tenant.ID, reservationID, requestID)
		<-g.semaphore
		if request.Context().Err() != nil {
			terminal = requestTerminal{cause: terminalClientCancelled, code: "client_cancelled"}
			g.metrics.cancelled.Add(1)
			return
		}
		terminal = requestTerminal{cause: terminalRejected, code: "admission_unavailable"}
		g.metrics.rejected.Add(1)
		g.metrics.admissionUnavailable.Add(1)
		g.writeError(response, http.StatusServiceUnavailable, "admission_unavailable", requestID, true)
		return
	}
	if admissionResult.Decision != admission.Allowed {
		code := admissionResult.Decision.Code()
		if code == "" {
			g.bestEffortRelease(tenant.ID, reservationID, requestID)
			<-g.semaphore
			terminal = requestTerminal{cause: terminalRejected, code: "admission_unavailable"}
			g.metrics.rejected.Add(1)
			g.metrics.admissionUnavailable.Add(1)
			g.writeError(response, http.StatusServiceUnavailable, "admission_unavailable", requestID, true)
			return
		}
		<-g.semaphore
		terminal = requestTerminal{cause: terminalRejected, code: code}
		g.metrics.rejected.Add(1)
		g.metrics.recordAdmissionDenial(admissionResult.Decision)
		if admissionResult.RetryAfter > 0 {
			retrySeconds := max(int64(1), int64(math.Ceil(admissionResult.RetryAfter.Seconds())))
			response.Header().Set("Retry-After", strconv.FormatInt(retrySeconds, 10))
		}
		g.writeError(response, http.StatusTooManyRequests, code, requestID, true)
		return
	}
	if g.draining.Load() {
		g.bestEffortRelease(tenant.ID, reservationID, requestID)
		<-g.semaphore
		terminal = requestTerminal{cause: terminalRejected, code: "shutting_down"}
		g.metrics.rejected.Add(1)
		g.writeError(response, http.StatusServiceUnavailable, "shutting_down", requestID, true)
		return
	}
	baseContext, cancelCause := context.WithCancelCause(request.Context())
	ctx, cancelTimeout := context.WithTimeoutCause(baseContext, g.config.TotalTimeout, context.DeadlineExceeded)
	g.activeMu.Lock()
	if g.draining.Load() {
		g.activeMu.Unlock()
		cancelTimeout()
		cancelCause(nil)
		<-g.semaphore
		g.bestEffortRelease(tenant.ID, reservationID, requestID)
		terminal = requestTerminal{cause: terminalRejected, code: "shutting_down"}
		g.metrics.rejected.Add(1)
		g.writeError(response, http.StatusServiceUnavailable, "shutting_down", requestID, true)
		return
	}
	g.nextID++
	executionID := g.nextID
	g.active[executionID] = cancelCause
	g.signalActiveChangeLocked()
	g.activeMu.Unlock()
	g.metrics.requests.Add(1)
	g.metrics.active.Add(1)
	defer func() {
		cancelTimeout()
		cancelCause(nil)
		if errors.Is(context.Cause(ctx), errGatewayShutdown) {
			time.Sleep(cancellationPropagationWindow)
		}
		g.bestEffortRelease(tenant.ID, reservationID, requestID)
		g.activeMu.Lock()
		delete(g.active, executionID)
		g.signalActiveChangeLocked()
		g.activeMu.Unlock()
		g.metrics.active.Add(-1)
		<-g.semaphore
	}()

	selection, err = g.selectBackend(ctx, requestID, tenant, decoded)
	if err == nil {
		routerDecisionUnixNS = time.Now().UnixNano()
	}
	g.metrics.recordRoutingDecision(selection)
	if err != nil {
		terminal = requestTerminal{cause: terminalUpstreamFailure, code: "no_healthy_backend"}
		g.metrics.failed.Add(1)
		g.writeError(response, http.StatusServiceUnavailable, "no_healthy_backend", requestID, true)
		return
	}
	backend := selection.Backend
	terminal.backendID = backend.ID
	if g.routingEvents {
		g.logger.Info("request routed", "request_id", requestID, "backend_id", backend.ID, "backend_generation", selection.BackendGeneration, "router_decision_unix_ns", routerDecisionUnixNS)
	}
	outbound := upstreamRequest{chatRequest: *decoded, CacheSalt: tenant.cacheSalt}
	outbound.StreamOptions.IncludeUsage = true
	body, err := json.Marshal(outbound)
	if err != nil {
		terminal = requestTerminal{cause: terminalInternalError, code: "internal_error", backendID: backend.ID}
		g.metrics.failed.Add(1)
		g.writeError(response, http.StatusInternalServerError, "internal_error", requestID, false)
		return
	}
	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, backend.URL.JoinPath("v1/chat/completions").String(), bytes.NewReader(body))
	if err != nil {
		terminal = requestTerminal{cause: terminalInternalError, code: "internal_error", backendID: backend.ID}
		g.metrics.failed.Add(1)
		g.writeError(response, http.StatusInternalServerError, "internal_error", requestID, false)
		return
	}
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("X-Request-ID", requestID)
	// Propagate only the gateway-owned W3C trace context. In particular, do not
	// forward client baggage or tracestate into the backend trust boundary.
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(upstream.Header))
	firstDeadline := time.Now().Add(g.config.FirstItemTimeout)
	type upstreamResult struct {
		response *http.Response
		err      error
	}
	upstreamResults := make(chan upstreamResult, 1)
	go func() {
		result := upstreamResult{}
		result.response, result.err = g.client.Do(upstream)
		if ctx.Err() != nil && result.response != nil {
			result.response.Body.Close()
		}
		upstreamResults <- result
	}()
	firstTimer := time.NewTimer(time.Until(firstDeadline))
	var upstreamResponse *http.Response
	select {
	case result := <-upstreamResults:
		firstTimer.Stop()
		upstreamResponse, err = result.response, result.err
	case <-firstTimer.C:
		cancelCause(context.DeadlineExceeded)
		<-upstreamResults
		terminal = requestTerminal{cause: terminalTimeout, code: "upstream_timeout", backendID: backend.ID}
		g.metrics.failed.Add(1)
		g.metrics.timeouts.Add(1)
		g.writeError(response, http.StatusGatewayTimeout, "upstream_timeout", requestID, true)
		return
	case <-ctx.Done():
		firstTimer.Stop()
		<-upstreamResults
		g.handlePrecommitContext(response, request, ctx, requestID, &terminal)
		return
	}
	if err != nil {
		g.handlePrecommitReadError(response, request, ctx, requestID, backend.ID, err, &terminal)
		return
	}
	defer upstreamResponse.Body.Close()
	upstreamHTTPStatus = upstreamResponse.StatusCode
	if upstreamResponse.StatusCode != http.StatusOK {
		// The first-item deadline also bounds a trickling upstream error body.
		errorTimer := time.AfterFunc(time.Until(firstDeadline), func() { cancelCause(context.DeadlineExceeded) })
		data, readError := io.ReadAll(io.LimitReader(upstreamResponse.Body, 8193))
		errorTimer.Stop()
		if readError == nil {
			upstreamErrorCode, upstreamErrorType = nativeErrorMetadata(data)
			if upstreamErrorType != "" {
				upstreamErrorShape = "http_error"
			}
		}
		terminal = requestTerminal{cause: terminalUpstreamFailure, code: "upstream_failure", backendID: backend.ID}
		g.metrics.failed.Add(1)
		g.writeError(response, http.StatusBadGateway, "upstream_failure", requestID, true)
		return
	}
	upstreamMediaType, _, err := mime.ParseMediaType(upstreamResponse.Header.Get("Content-Type"))
	if err != nil || upstreamMediaType != "text/event-stream" {
		terminal = requestTerminal{cause: terminalProtocolError, code: "upstream_protocol_error", backendID: backend.ID}
		g.metrics.failed.Add(1)
		g.writeError(response, http.StatusBadGateway, "upstream_protocol_error", requestID, false)
		return
	}
	if identity := upstreamResponse.Header.Get("X-Inference-Backend"); identity != "" && identity != backend.ID {
		terminal = requestTerminal{cause: terminalProtocolError, code: "upstream_protocol_error", backendID: backend.ID}
		g.metrics.failed.Add(1)
		g.writeError(response, http.StatusBadGateway, "upstream_protocol_error", requestID, false)
		return
	}

	readerCtx, stopReader := context.WithCancel(ctx)
	events := streamEvents(readerCtx, upstreamResponse.Body, g.config.MaxEventBytes)
	defer func() {
		stopReader()
		upstreamResponse.Body.Close()
		for range events {
		}
	}()
	remainingFirstItemTime := time.Until(firstDeadline)
	if remainingFirstItemTime <= 0 {
		terminal = requestTerminal{cause: terminalTimeout, code: "upstream_timeout", backendID: backend.ID}
		g.metrics.failed.Add(1)
		g.metrics.timeouts.Add(1)
		g.writeError(response, http.StatusGatewayTimeout, "upstream_timeout", requestID, true)
		return
	}
	first, err := awaitEvent(readerCtx, events, remainingFirstItemTime)
	if err != nil || first.done {
		g.handlePrecommitReadError(response, request, ctx, requestID, backend.ID, err, &terminal)
		return
	}
	firstValidated, err := validateEvent(first.data, requestID, decoded.Model)
	upstreamErrorCode, upstreamErrorType = nativeErrorMetadata(first.data)
	if upstreamErrorType != "" {
		upstreamErrorShape = "sse_error"
	}
	if err != nil || firstValidated.kind == eventUsage {
		terminal = requestTerminal{cause: terminalProtocolError, code: "upstream_protocol_error", backendID: backend.ID}
		g.metrics.failed.Add(1)
		g.writeError(response, http.StatusBadGateway, "upstream_protocol_error", requestID, false)
		return
	}

	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-cache")
	response.Header().Set("X-Inference-Backend", backend.ID)
	response.WriteHeader(http.StatusOK)
	terminal.committed = true
	finished := firstValidated.kind == eventFinish
	usageSeen := false
	if err := g.writeValidated(response, firstValidated); err != nil {
		g.handleWriteError(request, backend.ID, &terminal)
		return
	}

	for {
		event, readErr := awaitEvent(readerCtx, events, g.config.StreamIdleTimeout)
		if readErr != nil {
			g.handleCommittedReadError(response, request, ctx, requestID, backend.ID, readErr, &terminal)
			return
		}
		if event.done {
			if !finished || !usageSeen {
				terminal = requestTerminal{cause: terminalProtocolError, code: "stream_interrupted", backendID: backend.ID, committed: true}
				g.metrics.failed.Add(1)
				g.metrics.partial.Add(1)
				g.interrupt(response, requestID, "generation stream interrupted")
				return
			}
			if err := g.writeRaw(response, []byte("data: [DONE]\n\n")); err != nil {
				g.handleWriteError(request, backend.ID, &terminal)
				return
			}
			g.metrics.completed.Add(1)
			terminal = requestTerminal{cause: terminalCompleted, code: "completed", backendID: backend.ID, committed: true}
			return
		}
		validated, validationErr := validateEvent(event.data, requestID, decoded.Model)
		if code, kind := nativeErrorMetadata(event.data); kind != "" {
			upstreamErrorCode, upstreamErrorType, upstreamErrorShape = code, kind, "sse_error"
		}
		if validationErr != nil || (finished && validated.kind != eventUsage) || (validated.kind == eventUsage && (!finished || usageSeen)) {
			terminal = requestTerminal{cause: terminalProtocolError, code: "stream_interrupted", backendID: backend.ID, committed: true}
			g.metrics.failed.Add(1)
			g.metrics.partial.Add(1)
			g.interrupt(response, requestID, "generation stream interrupted")
			return
		}
		if validated.kind == eventFinish {
			if finished {
				terminal = requestTerminal{cause: terminalProtocolError, code: "stream_interrupted", backendID: backend.ID, committed: true}
				g.metrics.failed.Add(1)
				g.metrics.partial.Add(1)
				g.interrupt(response, requestID, "generation stream interrupted")
				return
			}
			finished = true
		}
		if validated.kind == eventUsage {
			usageSeen = true
		}
		if err := g.writeValidated(response, validated); err != nil {
			g.handleWriteError(request, backend.ID, &terminal)
			return
		}
	}
}

func (g *Gateway) decodeRequest(response http.ResponseWriter, request *http.Request, maxRequestBytes int64) (*chatRequest, error) {
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(payload) {
		return nil, errors.New("request must be valid UTF-8")
	}
	if err := validateUniqueJSONMembers(payload); err != nil {
		return nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil || members == nil {
		return nil, errors.New("request must be a JSON object")
	}
	supported := map[string]struct{}{
		"model": {}, "messages": {}, "stream": {}, "max_tokens": {},
		"temperature": {}, "top_p": {}, "seed": {}, "stop": {},
	}
	unsupported := map[string]struct{}{
		"audio": {}, "frequency_penalty": {}, "function_call": {}, "functions": {},
		"logit_bias": {}, "logprobs": {}, "metadata": {}, "modalities": {},
		"n": {}, "parallel_tool_calls": {}, "presence_penalty": {}, "reasoning_effort": {},
		"response_format": {}, "service_tier": {}, "store": {}, "stream_options": {},
		"tenant_id": {}, "backend_id": {}, "cache_salt": {}, "tool_choice": {},
		"tools": {}, "top_logprobs": {}, "user": {},
	}
	for name := range members {
		if _, ok := supported[name]; ok {
			continue
		}
		if _, ok := unsupported[name]; ok {
			return nil, &unsupportedParameterError{name: name}
		}
		return nil, fmt.Errorf("unknown field %q", name)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded chatRequest
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("request must contain one JSON value")
	}
	if decoded.Model == "" || decoded.Stream == nil || !*decoded.Stream || len(decoded.Messages) == 0 {
		return nil, errors.New("model, messages, and stream=true are required")
	}
	for _, item := range decoded.Messages {
		if item.Content == "" || (item.Role != "system" && item.Role != "user" && item.Role != "assistant") {
			return nil, errors.New("invalid message")
		}
	}
	if decoded.MaxTokens != nil && *decoded.MaxTokens <= 0 {
		return nil, errors.New("max_tokens must be positive")
	}
	if decoded.Temperature != nil && (math.IsNaN(*decoded.Temperature) || math.IsInf(*decoded.Temperature, 0) || *decoded.Temperature < 0 || *decoded.Temperature > 2) {
		return nil, errors.New("temperature must be finite and between zero and two")
	}
	if decoded.TopP != nil && (math.IsNaN(*decoded.TopP) || math.IsInf(*decoded.TopP, 0) || *decoded.TopP <= 0 || *decoded.TopP > 1) {
		return nil, errors.New("top_p must be finite, positive, and at most one")
	}
	if len(decoded.Stop) > 0 {
		var single string
		if err := json.Unmarshal(decoded.Stop, &single); err == nil {
			if single == "" {
				return nil, errors.New("stop must not be empty")
			}
			return &decoded, nil
		}
		var multiple []string
		if err := json.Unmarshal(decoded.Stop, &multiple); err != nil || len(multiple) == 0 || len(multiple) > 4 {
			return nil, errors.New("stop must be a string or one through four strings")
		}
		for _, stop := range multiple {
			if stop == "" {
				return nil, errors.New("stop values must not be empty")
			}
		}
	}
	return &decoded, nil
}

func validateUniqueJSONMembers(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var parseValue func() error
	parseValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key must be a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON member %q", key)
				}
				seen[key] = struct{}{}
				if err := parseValue(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := parseValue(); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		closing, err := decoder.Token()
		if err != nil || closing != matchingDelimiter(delimiter) {
			return errors.New("invalid JSON structure")
		}
		return nil
	}
	if err := parseValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func matchingDelimiter(open json.Delim) json.Delim {
	if open == '{' {
		return '}'
	}
	return ']'
}

func (g *Gateway) handlePrecommitContext(response http.ResponseWriter, request *http.Request, ctx context.Context, requestID string, terminal *requestTerminal) {
	g.handlePrecommitReadError(response, request, ctx, requestID, terminal.backendID, ctx.Err(), terminal)
}

func (g *Gateway) handlePrecommitReadError(response http.ResponseWriter, request *http.Request, ctx context.Context, requestID, backendID string, err error, terminal *requestTerminal) {
	if request.Context().Err() != nil {
		*terminal = requestTerminal{cause: terminalClientCancelled, code: "client_cancelled", backendID: backendID}
		g.metrics.cancelled.Add(1)
		return
	}
	if errors.Is(context.Cause(ctx), errGatewayShutdown) {
		*terminal = requestTerminal{cause: terminalShutdown, code: "shutting_down", backendID: backendID}
		g.writeError(response, http.StatusServiceUnavailable, "shutting_down", requestID, true)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		*terminal = requestTerminal{cause: terminalTimeout, code: "upstream_timeout", backendID: backendID}
		g.metrics.failed.Add(1)
		g.metrics.timeouts.Add(1)
		g.writeError(response, http.StatusGatewayTimeout, "upstream_timeout", requestID, true)
		return
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		*terminal = requestTerminal{cause: terminalUpstreamFailure, code: "upstream_failure", backendID: backendID}
		g.metrics.failed.Add(1)
		g.writeError(response, http.StatusBadGateway, "upstream_failure", requestID, true)
		return
	}
	*terminal = requestTerminal{cause: terminalProtocolError, code: "upstream_protocol_error", backendID: backendID}
	g.metrics.failed.Add(1)
	g.writeError(response, http.StatusBadGateway, "upstream_protocol_error", requestID, false)
}

func (g *Gateway) handleCommittedReadError(response http.ResponseWriter, request *http.Request, ctx context.Context, requestID, backendID string, err error, terminal *requestTerminal) {
	if request.Context().Err() != nil {
		*terminal = requestTerminal{cause: terminalClientCancelled, code: "client_cancelled", backendID: backendID, committed: true}
		g.metrics.cancelled.Add(1)
		return
	}
	if errors.Is(context.Cause(ctx), errGatewayShutdown) {
		*terminal = requestTerminal{cause: terminalShutdown, code: "stream_interrupted", backendID: backendID, committed: true}
		g.metrics.partial.Add(1)
		g.interrupt(response, requestID, "gateway shutting down")
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		*terminal = requestTerminal{cause: terminalTimeout, code: "stream_interrupted", backendID: backendID, committed: true}
		g.metrics.failed.Add(1)
		g.metrics.partial.Add(1)
		g.metrics.timeouts.Add(1)
		g.interrupt(response, requestID, "generation stream timed out")
		return
	}
	*terminal = requestTerminal{cause: terminalStreamInterrupted, code: "stream_interrupted", backendID: backendID, committed: true}
	g.metrics.failed.Add(1)
	g.metrics.partial.Add(1)
	g.interrupt(response, requestID, "generation stream interrupted")
}

func (g *Gateway) handleWriteError(request *http.Request, backendID string, terminal *requestTerminal) {
	if request.Context().Err() != nil {
		*terminal = requestTerminal{cause: terminalClientCancelled, code: "client_cancelled", backendID: backendID, committed: terminal.committed}
		g.metrics.cancelled.Add(1)
		return
	}
	*terminal = requestTerminal{cause: terminalWriteFailure, code: "write_failure", backendID: backendID, committed: terminal.committed}
	g.metrics.failed.Add(1)
	if terminal.committed {
		g.metrics.partial.Add(1)
	}
}

func (g *Gateway) interrupt(response http.ResponseWriter, requestID, message string) {
	payload, _ := json.Marshal(map[string]any{"error": map[string]any{
		"code": "stream_interrupted", "message": message,
		"type": "upstream_error", "request_id": requestID, "retryable": false,
	}})
	_ = g.writeRaw(response, append(append([]byte("event: error\ndata: "), payload...), []byte("\n\n")...))
}

func (g *Gateway) writeError(response http.ResponseWriter, status int, code, requestID string, retryable bool) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"error": map[string]any{
		"code": code, "message": code, "type": "gateway_error", "request_id": requestID, "retryable": retryable,
	}})
}

func (g *Gateway) writeSSE(response http.ResponseWriter, payload []byte) error {
	return g.writeRaw(response, append(append([]byte("data: "), payload...), []byte("\n\n")...))
}

func (g *Gateway) writeValidated(response http.ResponseWriter, event validatedEvent) error {
	for _, payload := range event.payloads {
		if err := g.writeSSE(response, payload); err != nil {
			return err
		}
	}
	return nil
}

func (g *Gateway) writeRaw(response http.ResponseWriter, payload []byte) error {
	controller := http.NewResponseController(response)
	if err := controller.SetWriteDeadline(time.Now().Add(g.config.ClientWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	if _, err := response.Write(payload); err != nil {
		return err
	}
	return controller.Flush()
}

func newID(prefix string) string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic(fmt.Sprintf("secure random source unavailable: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(value)
}

func ensureServerTraceContext(ctx context.Context, span trace.Span) (context.Context, string) {
	spanContext := span.SpanContext()
	if !spanContext.IsValid() {
		var traceBytes [16]byte
		var spanBytes [8]byte
		if _, err := rand.Read(traceBytes[:]); err != nil {
			panic(fmt.Sprintf("secure random source unavailable: %v", err))
		}
		if _, err := rand.Read(spanBytes[:]); err != nil {
			panic(fmt.Sprintf("secure random source unavailable: %v", err))
		}
		spanContext = trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    trace.TraceID(traceBytes),
			SpanID:     trace.SpanID(spanBytes),
			TraceFlags: trace.FlagsSampled,
		})
		ctx = trace.ContextWithSpanContext(ctx, spanContext)
	}
	return ctx, spanContext.TraceID().String()
}

type eventKind uint8

const (
	eventChunk eventKind = iota
	eventFinish
	eventUsage
)

type streamEvent struct {
	data []byte
	done bool
	err  error
}

func streamEvents(ctx context.Context, body io.ReadCloser, maxBytes int) <-chan streamEvent {
	result := make(chan streamEvent)
	go func() {
		defer close(result)
		var reader *bufio.Reader
		if maxBytes == defaultMaxEventBytes {
			reader = defaultEventReaders.Get().(*bufio.Reader)
			reader.Reset(body)
			defer func() {
				reader.Reset(nil) // release the upstream body reference before reuse
				defaultEventReaders.Put(reader)
			}()
		} else {
			reader = bufio.NewReaderSize(body, maxBytes+1)
		}
		for {
			event := readEvent(reader, maxBytes)
			select {
			case result <- event:
			case <-ctx.Done():
				return
			}
			if event.err != nil || event.done {
				return
			}
		}
	}()
	return result
}

func readEvent(reader *bufio.Reader, maxBytes int) streamEvent {
	var data []byte
	dataSeen := false
	consumed := 0
	for {
		line, err := reader.ReadSlice('\n')
		consumed += len(line)
		if errors.Is(err, bufio.ErrBufferFull) || consumed > maxBytes {
			return streamEvent{err: errors.New("SSE event exceeds configured limit")}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) == 0 {
				return streamEvent{err: io.ErrUnexpectedEOF}
			}
			return streamEvent{err: err}
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			if !dataSeen {
				continue
			}
			if bytes.Equal(data, []byte("[DONE]")) {
				return streamEvent{done: true}
			}
			return streamEvent{data: data}
		}
		if bytes.HasPrefix(line, []byte(":")) {
			continue
		}
		if !bytes.HasPrefix(line, []byte("data:")) || dataSeen {
			return streamEvent{err: errors.New("unsupported SSE framing")}
		}
		dataSeen = true
		value := line[len("data:"):]
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
		data = append(data, value...)
	}
}

func awaitEvent(ctx context.Context, events <-chan streamEvent, timeout time.Duration) (streamEvent, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return streamEvent{}, ctx.Err()
	case <-timer.C:
		return streamEvent{}, context.DeadlineExceeded
	case event, ok := <-events:
		if !ok {
			return streamEvent{}, io.ErrUnexpectedEOF
		}
		return event, event.err
	}
}

type validatedEvent struct {
	kind     eventKind
	payloads [][]byte
}

func clientChunkEnvelope(upstream map[string]any, requestID, model string) map[string]any {
	// The upstream identifier and model name are not part of the public
	// identity boundary.  Every streamed chunk gets the gateway-owned request
	// identifier and the tenant-visible model requested by the caller.
	client := make(map[string]any, 5)
	client["id"] = "chatcmpl_" + requestID
	client["object"] = "chat.completion.chunk"
	if value, ok := upstream["created"]; ok {
		client["created"] = value
	}
	client["model"] = model
	return client
}

func validateEvent(data []byte, requestID, model string) (validatedEvent, error) {
	if err := validateUniqueJSONMembers(data); err != nil {
		return validatedEvent{}, errors.New("invalid chunk JSON")
	}
	var envelope struct {
		Object  string `json:"object"`
		Choices []struct {
			Index        int             `json:"index"`
			Delta        json.RawMessage `json:"delta"`
			FinishReason *string         `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int             `json:"prompt_tokens"`
			CompletionTokens int             `json:"completion_tokens"`
			TotalTokens      int             `json:"total_tokens"`
			CountSource      json.RawMessage `json:"count_source"`
		} `json:"usage,omitempty"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Object != "chat.completion.chunk" {
		return validatedEvent{}, errors.New("invalid chunk JSON")
	}
	if envelope.Usage != nil {
		if len(envelope.Choices) != 0 || len(envelope.Usage.CountSource) != 0 || envelope.Usage.PromptTokens < 0 || envelope.Usage.CompletionTokens < 0 || envelope.Usage.TotalTokens != envelope.Usage.PromptTokens+envelope.Usage.CompletionTokens {
			return validatedEvent{}, errors.New("invalid usage chunk")
		}
		var value map[string]any
		if err := json.Unmarshal(data, &value); err != nil {
			return validatedEvent{}, err
		}
		client := clientChunkEnvelope(value, requestID, model)
		client["choices"] = []any{}
		client["usage"] = map[string]any{
			"prompt_tokens":     envelope.Usage.PromptTokens,
			"completion_tokens": envelope.Usage.CompletionTokens,
			"total_tokens":      envelope.Usage.TotalTokens,
			"count_source":      "runtime_usage",
		}
		payload, err := json.Marshal(client)
		return validatedEvent{kind: eventUsage, payloads: [][]byte{payload}}, err
	}
	if len(envelope.Choices) != 1 || envelope.Choices[0].Index != 0 || len(envelope.Choices[0].Delta) == 0 {
		return validatedEvent{}, errors.New("invalid choices")
	}
	var delta map[string]any
	if err := json.Unmarshal(envelope.Choices[0].Delta, &delta); err != nil {
		return validatedEvent{}, errors.New("invalid delta")
	}
	canonicalDelta := make(map[string]any, 2)
	hasBenignField := false
	for key, value := range delta {
		switch key {
		case "role":
			text, ok := value.(string)
			if !ok || text != "assistant" {
				return validatedEvent{}, errors.New("invalid assistant role")
			}
			canonicalDelta[key] = text
			hasBenignField = true
		case "content":
			text, ok := value.(string)
			if !ok {
				return validatedEvent{}, errors.New("content must be a string")
			}
			canonicalDelta[key] = text
			hasBenignField = true
		default:
			if value != nil {
				return validatedEvent{}, errors.New("unsupported delta")
			}
			hasBenignField = true
		}
	}
	if !hasBenignField && envelope.Choices[0].FinishReason == nil {
		return validatedEvent{}, errors.New("empty non-terminal delta")
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return validatedEvent{}, err
	}
	client := clientChunkEnvelope(value, requestID, model)
	if envelope.Choices[0].FinishReason != nil {
		if *envelope.Choices[0].FinishReason != "stop" && *envelope.Choices[0].FinishReason != "length" {
			return validatedEvent{}, errors.New("invalid finish chunk")
		}
		payloads := make([][]byte, 0, 2)
		forwardDelta := make(map[string]any, 2)
		if role, exists := canonicalDelta["role"]; exists {
			forwardDelta["role"] = role
		}
		if content, exists := canonicalDelta["content"]; exists && content != "" {
			forwardDelta["content"] = content
		}
		if len(forwardDelta) > 0 {
			client["choices"] = []any{map[string]any{
				"index":         envelope.Choices[0].Index,
				"delta":         forwardDelta,
				"finish_reason": nil,
			}}
			payload, err := json.Marshal(client)
			if err != nil {
				return validatedEvent{}, err
			}
			payloads = append(payloads, payload)
		}
		client["choices"] = []any{map[string]any{
			"index":         envelope.Choices[0].Index,
			"delta":         map[string]any{},
			"finish_reason": *envelope.Choices[0].FinishReason,
		}}
		payload, err := json.Marshal(client)
		if err != nil {
			return validatedEvent{}, err
		}
		payloads = append(payloads, payload)
		return validatedEvent{kind: eventFinish, payloads: payloads}, nil
	}
	client["choices"] = []any{map[string]any{
		"index":         envelope.Choices[0].Index,
		"delta":         canonicalDelta,
		"finish_reason": nil,
	}}
	payload, err := json.Marshal(client)
	return validatedEvent{kind: eventChunk, payloads: [][]byte{payload}}, err
}
