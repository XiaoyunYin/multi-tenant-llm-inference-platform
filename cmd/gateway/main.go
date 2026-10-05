// Command gateway runs the HTTP inference gateway.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"
	"multi-tenant-llm-inference-platform/internal/diagnostics"
	"multi-tenant-llm-inference-platform/internal/gateway"
	"multi-tenant-llm-inference-platform/internal/telemetry"

	redis "github.com/redis/go-redis/v9"
)

const defaultBackends = "fake-backend-a=http://127.0.0.1:8001,fake-backend-b=http://127.0.0.1:8002"

func main() {
	check := len(os.Args) == 2 && os.Args[1] == "--check-config"
	if len(os.Args) > 1 && !check {
		fmt.Fprintln(os.Stderr, "usage: gateway [--check-config]")
		os.Exit(2)
	}
	os.Exit(runWithMode(check))
}

func run() int { return runWithMode(false) }

// Configuration checking follows the launch parser/constructors, without starting
// listeners, health pollers, metrics collectors, or contacting Redis/backends.
func runWithMode(checkConfig bool) int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	shutdownTelemetry, err := telemetry.ConfigureTracing(context.Background(), "inference-gateway")
	if err != nil {
		logger.Error("cannot configure tracing", "error", err)
		return 2
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(shutdownContext); err != nil {
			logger.Error("cannot flush tracing", "error", err)
		}
	}()
	address := envOrDefault("GATEWAY_HTTP_ADDR", ":8080")
	profileAddress := os.Getenv("GATEWAY_PPROF_ADDR")
	if err := diagnostics.ValidateAddress(profileAddress); err != nil {
		logger.Error("invalid profiling address", "error", err)
		return 2
	}
	if _, err := net.ResolveTCPAddr("tcp", address); err != nil {
		logger.Error("invalid listen address", "error", err)
		return 2
	}
	backends, discoveryConfig, err := backendConfiguration()
	if err != nil {
		logger.Error("invalid backend configuration", "error", err)
		return 2
	}
	router, err := routerForPolicy(envOrDefault("GATEWAY_ROUTING_POLICY", string(gateway.RoutingPolicyRoundRobin)))
	if err != nil {
		logger.Error("invalid routing policy", "error", err)
		return 2
	}
	tenantConfigPath := envOrDefault("TENANT_CONFIG_PATH", "deploy/local/tenants.json")
	cacheSaltSecretPath := envOrDefault("CACHE_SALT_SECRET_FILE", "deploy/local/cache-salt.secret")
	cacheSaltSecretFile, err := os.Open(cacheSaltSecretPath)
	if err != nil {
		logger.Error("cannot open cache-salt secret", "path", cacheSaltSecretPath, "error", err)
		return 2
	}
	cacheSaltSecret, secretErr := gateway.LoadCacheSaltSecret(cacheSaltSecretFile)
	secretCloseErr := cacheSaltSecretFile.Close()
	if secretErr != nil || secretCloseErr != nil {
		logger.Error("cannot load cache-salt secret", "path", cacheSaltSecretPath, "error", errors.Join(secretErr, secretCloseErr))
		return 2
	}
	tenantConfig, err := os.Open(tenantConfigPath)
	if err != nil {
		logger.Error("cannot open tenant configuration", "path", tenantConfigPath, "error", err)
		return 2
	}
	tenants, tenantErr := gateway.LoadTenantRegistry(tenantConfig, cacheSaltSecret)
	closeErr := tenantConfig.Close()
	if tenantErr != nil || closeErr != nil {
		logger.Error("cannot load tenant configuration", "path", tenantConfigPath, "error", errors.Join(tenantErr, closeErr))
		return 2
	}
	shutdownGrace, err := envDuration("GATEWAY_SHUTDOWN_GRACE", 2*time.Minute)
	if err != nil {
		logger.Error("invalid shutdown grace", "error", err)
		return 2
	}
	shutdownHardStop, err := envDuration("GATEWAY_SHUTDOWN_HARD_STOP", 10*time.Second)
	if err != nil {
		logger.Error("invalid shutdown hard stop", "error", err)
		return 2
	}
	metricsInterval, err := envDuration("BACKEND_METRICS_INTERVAL", 500*time.Millisecond)
	if err != nil {
		logger.Error("invalid backend metrics interval", "error", err)
		return 2
	}
	metricsMaxAge, err := envDuration("BACKEND_METRICS_MAX_AGE", 2*metricsInterval)
	if err != nil {
		logger.Error("invalid backend metrics maximum age", "error", err)
		return 2
	}
	if metricsMaxAge < metricsInterval {
		logger.Error("invalid backend metrics maximum age", "error", errors.New("maximum age must be at least one collection interval"))
		return 2
	}
	globalCapacity, err := envPositiveInt64("ADMISSION_GLOBAL_CAPACITY", 64)
	if err != nil {
		logger.Error("invalid global admission capacity", "error", err)
		return 2
	}
	leaseDuration, err := envDuration("ADMISSION_LEASE", 3*time.Minute)
	if err != nil {
		logger.Error("invalid admission lease", "error", err)
		return 2
	}
	tombstoneTTL, err := envDuration("ADMISSION_TOMBSTONE_TTL", 5*time.Minute)
	if err != nil {
		logger.Error("invalid admission tombstone TTL", "error", err)
		return 2
	}
	gatewayConfig := gateway.DefaultConfig()
	gatewayConfig.MaxConcurrent, err = envPositiveInt("GATEWAY_MAX_CONCURRENT", gatewayConfig.MaxConcurrent)
	if err != nil {
		logger.Error("invalid gateway concurrency", "error", err)
		return 2
	}
	gatewayConfig.TotalTimeout, err = envDuration("GATEWAY_TOTAL_TIMEOUT", gatewayConfig.TotalTimeout)
	if err != nil {
		logger.Error("invalid total request timeout", "error", err)
		return 2
	}
	gatewayConfig.FirstItemTimeout, err = envDuration("GATEWAY_FIRST_ITEM_TIMEOUT", gatewayConfig.FirstItemTimeout)
	if err != nil || gatewayConfig.FirstItemTimeout >= gatewayConfig.TotalTimeout {
		logger.Error("first item timeout must be positive and below total timeout", "error", err)
		return 2
	}
	gatewayConfig.AdmissionTimeout, err = envDuration("GATEWAY_ADMISSION_TIMEOUT", gatewayConfig.AdmissionTimeout)
	if err != nil {
		logger.Error("invalid admission timeout", "error", err)
		return 2
	}
	gatewayConfig.ReleaseTimeout, err = envDuration("GATEWAY_RELEASE_TIMEOUT", gatewayConfig.ReleaseTimeout)
	if err != nil {
		logger.Error("invalid release timeout", "error", err)
		return 2
	}
	gatewayConfig.RoutingTokenizeTimeout, err = envDuration("GATEWAY_ROUTING_TOKENIZE_TIMEOUT", gatewayConfig.RoutingTokenizeTimeout)
	if err != nil {
		logger.Error("invalid routing tokenization timeout", "error", err)
		return 2
	}
	if leaseDuration <= gatewayConfig.TotalTimeout+shutdownHardStop+gatewayConfig.ReleaseTimeout {
		logger.Error("admission lease must exceed total execution, shutdown hard stop, and release timeout")
		return 2
	}

	var coordinator admission.Coordinator
	var redisClient *redis.Client
	admissionMode := envOrDefault("ADMISSION_MODE", "redis")
	switch admissionMode {
	case "redis":
		redisClient = redis.NewClient(&redis.Options{
			Addr: envOrDefault("REDIS_ADDR", "127.0.0.1:6379"), Protocol: 2,
			MaxRetries: -1, DialTimeout: 2 * time.Second,
			ReadTimeout: gatewayConfig.AdmissionTimeout, WriteTimeout: gatewayConfig.AdmissionTimeout,
			ContextTimeoutEnabled: true,
		})
		if !checkConfig {
			pingContext, cancelPing := context.WithTimeout(context.Background(), 2*time.Second)
			pingErr := redisClient.Ping(pingContext).Err()
			cancelPing()
			if pingErr != nil {
				logger.Error("admission coordinator is unavailable", "error", pingErr)
				_ = redisClient.Close()
				return 2
			}
		}
		coordinator, err = admission.NewRedisCoordinator(redisClient, admission.RedisConfig{
			Namespace:      envOrDefault("ADMISSION_NAMESPACE", "mti:local:v1"),
			GlobalCapacity: globalCapacity, LeaseDuration: leaseDuration, TombstoneTTL: tombstoneTTL,
		})
	case "memory-test":
		if os.Getenv("ALLOW_UNSAFE_TEST_ADMISSION") != "true" {
			logger.Error("memory admission requires ALLOW_UNSAFE_TEST_ADMISSION=true")
			return 2
		}
		coordinator, err = admission.NewMemoryCoordinator(globalCapacity)
		logger.Warn("using process-local test admission; multi-gateway limits are not enforced")
	default:
		err = fmt.Errorf("ADMISSION_MODE must be redis or memory-test, got %q", admissionMode)
	}
	if err != nil {
		logger.Error("cannot create admission coordinator", "error", err)
		if redisClient != nil {
			_ = redisClient.Close()
		}
		return 2
	}
	if redisClient != nil {
		defer redisClient.Close()
	}

	transport := &http.Transport{
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       64,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	defer transport.CloseIdleConnections()
	upstreamClient := &http.Client{Transport: transport}
	healthClient := &http.Client{Timeout: time.Second, Transport: transport.Clone()}
	metricsClient := &http.Client{Timeout: metricsInterval, Transport: transport.Clone()}
	var registry *gateway.Registry
	if discoveryConfig == nil {
		registry, err = gateway.NewRegistry(backends, healthClient, 500*time.Millisecond)
	} else {
		registry, err = gateway.NewDiscoveryRegistry(healthClient, 250*time.Millisecond)
	}
	if err != nil {
		logger.Error("cannot create backend registry", "error", err)
		return 2
	}
	registry.SetHealthLogger(logger)
	if discoveryConfig != nil && !checkConfig {
		discovery, discoveryErr := gateway.NewInClusterDiscovery(*discoveryConfig, registry, logger)
		if discoveryErr != nil {
			logger.Error("cannot configure backend discovery", "error", discoveryErr)
			return 2
		}
		_ = discovery.Poll(context.Background())
		discovery.Start(context.Background())
		defer discovery.Close()
	}
	if !checkConfig {
		registry.Poll(context.Background())
		registry.Start(context.Background())
	}
	defer registry.Close()
	var backendMetrics *gateway.BackendMetricsCollector
	if discoveryConfig == nil {
		backendMetrics, err = gateway.NewBackendMetricsCollector(backends, metricsClient, metricsInterval, metricsMaxAge)
	} else {
		backendMetrics, err = gateway.NewDiscoveryMetricsCollector(registry, metricsClient, metricsInterval, metricsMaxAge)
	}
	if err != nil {
		logger.Error("cannot create backend metrics collector", "error", err)
		return 2
	}
	if !checkConfig {
		backendMetrics.Start(context.Background())
	}
	defer backendMetrics.Close()

	serviceOptions := []gateway.Option{
		gateway.WithTenantRegistry(tenants), gateway.WithAdmissionCoordinator(coordinator),
		gateway.WithBackendMetricsCollector(backendMetrics), gateway.WithRouter(router),
	}
	if discoveryConfig != nil {
		serviceOptions = append(serviceOptions, gateway.WithRoutingEvents())
	}
	if hashRouter, ok := router.(*gateway.HashAffinityRouter); ok {
		tokenizer, tokenizerErr := gateway.NewVLLMRoutingKeyTokenizer(upstreamClient, gatewayConfig.RoutingTokenizeTimeout, hashRouter.MaxTokenIDs())
		if tokenizerErr != nil {
			logger.Error("cannot create vLLM routing tokenizer", "error", tokenizerErr)
			return 2
		}
		serviceOptions = append(serviceOptions, gateway.WithRoutingKeyTokenizer(tokenizer))
	}
	service, err := gateway.New(gatewayConfig, registry, upstreamClient, logger, serviceOptions...)
	if err != nil {
		logger.Error("cannot create gateway", "error", err)
		return 2
	}
	if checkConfig {
		logger.Info("gateway configuration valid", "backends", len(backends))
		return 0
	}
	profiler, _, err := diagnostics.Start(profileAddress)
	if err != nil {
		logger.Error("cannot start loopback profiler", "error", err)
		return 1
	}
	if profiler != nil {
		defer profiler.Close()
	}
	server := &http.Server{
		Addr:              address,
		Handler:           service.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.ListenAndServe() }()
	logger.Info("gateway started", "address", address, "backends", len(backends), "pid", os.Getpid(),
		"first_item_timeout_seconds", gatewayConfig.FirstItemTimeout.Seconds(),
		"total_timeout_seconds", gatewayConfig.TotalTimeout.Seconds(),
		"admission_configuration", map[string]any{
			"mode":                        admissionMode,
			"allow_unsafe_test_admission": os.Getenv("ALLOW_UNSAFE_TEST_ADMISSION") == "true",
			"global_capacity":             globalCapacity,
			"gateway_max_concurrent":      gatewayConfig.MaxConcurrent,
			"tenants":                     tenants.AdmissionLimits(),
		})

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case received := <-signals:
		logger.Info("gateway draining", "signal", received.String())
	case serveErr := <-serverErrors:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("gateway server failed", "error", serveErr)
			return 1
		}
		return 0
	}

	service.SetDraining(true)
	serverShutdown := make(chan error, 1)
	go func() { serverShutdown <- server.Shutdown(context.Background()) }()
	result, shutdownErr := service.Shutdown(shutdownGrace, shutdownHardStop)
	if shutdownErr != nil {
		logger.Error("gateway hard-stop bound exceeded", "error", shutdownErr)
		_ = server.Close()
		<-serverShutdown
		return 1
	}
	if discoveryConfig != nil {
		logger.Info("last stream drained", "grace_expired", result.GraceExpired)
	}
	if err := <-serverShutdown; err != nil {
		logger.Error("gateway listener shutdown failed", "error", err)
		return 1
	}
	if result.GraceExpired {
		logger.Warn("gateway grace expired; active requests were cancelled")
	}
	logger.Info("gateway stopped")
	return 0
}

// Discovery variables have no effect unless explicitly opted in. In particular,
// the static parser and offline check-config path remain the Stage C defaults.
func backendConfiguration() ([]*gateway.Backend, *gateway.DiscoveryConfig, error) {
	if os.Getenv("BACKEND_DISCOVERY") == "" || os.Getenv("BACKEND_DISCOVERY") == "static" {
		backends, err := parseBackends(envOrDefault("BACKENDS", defaultBackends))
		return backends, nil, err
	}
	if os.Getenv("BACKEND_DISCOVERY") != "endpointslices" {
		return nil, nil, errors.New("BACKEND_DISCOVERY must be static or endpointslices")
	}
	interval, err := envDuration("BACKEND_DISCOVERY_INTERVAL", 250*time.Millisecond)
	if err != nil {
		return nil, nil, err
	}
	config := &gateway.DiscoveryConfig{Namespace: os.Getenv("BACKEND_DISCOVERY_NAMESPACE"), Service: os.Getenv("BACKEND_DISCOVERY_SERVICE"), Interval: interval}
	if err := config.Validate(); err != nil {
		return nil, nil, err
	}
	return nil, config, nil
}

func parseBackends(raw string) ([]*gateway.Backend, error) {
	entries := strings.Split(raw, ",")
	backends := make([]*gateway.Backend, 0, len(entries))
	for _, entry := range entries {
		parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("backend %q must use id[@generation]=url", entry)
		}
		identity := strings.SplitN(strings.TrimSpace(parts[0]), "@", 2)
		var backend *gateway.Backend
		var err error
		if len(identity) == 2 {
			backend, err = gateway.NewBackend(strings.TrimSpace(identity[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(identity[1]))
		} else {
			backend, err = gateway.NewBackend(strings.TrimSpace(identity[0]), strings.TrimSpace(parts[1]))
		}
		if err != nil {
			return nil, fmt.Errorf("backend %q: %w", entry, err)
		}
		backends = append(backends, backend)
	}
	return backends, nil
}

func routerForPolicy(policy string) (gateway.Router, error) {
	switch strings.TrimSpace(policy) {
	case string(gateway.RoutingPolicyRoundRobin):
		return gateway.NewRoundRobinRouter(), nil
	case string(gateway.RoutingPolicyLeastLoaded):
		return gateway.NewLeastLoadedRouter(), nil
	case string(gateway.RoutingPolicyHashAffinity):
		config, err := hashAffinityConfigFromEnvironment()
		if err != nil {
			return nil, err
		}
		return gateway.NewHashAffinityRouter(config)
	default:
		return nil, fmt.Errorf("GATEWAY_ROUTING_POLICY must be %q, %q, or %q, got %q", gateway.RoutingPolicyRoundRobin, gateway.RoutingPolicyLeastLoaded, gateway.RoutingPolicyHashAffinity, policy)
	}
}

func hashAffinityConfigFromEnvironment() (gateway.HashAffinityConfig, error) {
	config := gateway.HashAffinityConfig{EscapeMargin: 2}
	var err error
	config.BlockSize, err = envPositiveInt("GATEWAY_HASH_AFFINITY_BLOCK_SIZE", 16)
	if err != nil {
		return gateway.HashAffinityConfig{}, err
	}
	config.MaxBlocks, err = envPositiveInt("GATEWAY_HASH_AFFINITY_MAX_BLOCKS", 16)
	if err != nil {
		return gateway.HashAffinityConfig{}, err
	}
	config.EscapeMargin, err = envNonNegativeFloat("GATEWAY_HASH_AFFINITY_ESCAPE_MARGIN", config.EscapeMargin)
	if err != nil {
		return gateway.HashAffinityConfig{}, err
	}
	return config, nil
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", name)
	}
	return parsed, nil
}

func envPositiveInt64(name string, fallback int64) (int64, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func envPositiveInt(name string, fallback int) (int, error) {
	parsed, err := envPositiveInt64(name, int64(fallback))
	if err != nil {
		return 0, err
	}
	maxInt := int64(^uint(0) >> 1)
	if parsed > maxInt {
		return 0, fmt.Errorf("%s exceeds the platform integer limit", name)
	}
	return int(parsed), nil
}

func envNonNegativeFloat(name string, fallback float64) (float64, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed < 0 {
		return 0, fmt.Errorf("%s must be a finite, non-negative number", name)
	}
	return parsed, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
