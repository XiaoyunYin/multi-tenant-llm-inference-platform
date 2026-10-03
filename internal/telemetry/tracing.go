package telemetry

import (
	"context"
	"errors"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

type Shutdown func(context.Context) error

func ConfigureTracing(ctx context.Context, serviceName string) (Shutdown, error) {
	if serviceName == "" {
		return nil, errors.New("telemetry service name is required")
	}
	// The public gateway edge is an untrusted boundary. Keep only W3C
	// traceparent propagation available to trusted downstream calls; baggage
	// and tracestate supplied by clients must not cross into backend requests.
	otel.SetTextMapPropagator(propagation.TraceContext{})
	exporterMode := os.Getenv("OTEL_TRACES_EXPORTER")
	if exporterMode == "none" {
		return func(context.Context) error { return nil }, nil
	}
	if exporterMode != "" && exporterMode != "otlp" {
		return nil, fmt.Errorf("OTEL_TRACES_EXPORTER must be otlp or none, got %q", exporterMode)
	}
	if os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return func(context.Context) error { return nil }, nil
	}
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}
	serviceResource, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName(serviceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("create telemetry resource: %w", err)
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(serviceResource),
	)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}
