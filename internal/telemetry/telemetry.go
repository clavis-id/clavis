// Package telemetry builds the OpenTelemetry providers of the clavis binary.
//
// Tracing exports spans over OTLP/HTTP. Unless an endpoint is configured, the
// exporter reads the standard OTEL_EXPORTER_OTLP_* environment variables.
// Metrics are exposed in the Prometheus text format on a separate listener, so
// they are never reachable through the public API port. Both are disabled by
// default. Embedders do not use this package: they pass their own providers
// to clavis.Config.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// Config selects which signals to export.
type Config struct {
	// TracingEnabled exports spans over OTLP/HTTP.
	TracingEnabled bool
	// TracingEndpoint is the OTLP/HTTP traces URL, for example
	// "http://collector:4318/v1/traces". When empty, the standard
	// OTEL_EXPORTER_OTLP_* environment variables apply.
	TracingEndpoint string
	// SampleRatio is the fraction of new traces to record, between 0 and 1.
	// Traces started by a sampled parent are always recorded.
	SampleRatio float64
	// MetricsEnabled exposes metrics for Prometheus scraping.
	MetricsEnabled bool
}

// Providers are the telemetry components handed to Clavis.
type Providers struct {
	Tracer trace.TracerProvider
	Meter  metric.MeterProvider
	// MetricsHandler serves the Prometheus endpoint. It is nil when metrics
	// are disabled.
	MetricsHandler http.Handler
	shutdown       []func(context.Context) error
}

// Shutdown flushes pending telemetry and releases exporters.
func (p *Providers) Shutdown(ctx context.Context) error {
	var errs []error
	for _, fn := range p.shutdown {
		errs = append(errs, fn(ctx))
	}
	return errors.Join(errs...)
}

// Setup builds the providers described by cfg. serviceVersion is recorded as
// the service.version resource attribute.
func Setup(ctx context.Context, cfg Config, serviceVersion string) (*Providers, error) {
	p := &Providers{Tracer: tracenoop.NewTracerProvider(), Meter: metricnoop.NewMeterProvider()}
	if !cfg.TracingEnabled && !cfg.MetricsEnabled {
		return p, nil
	}

	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName("clavis"),
		semconv.ServiceVersion(serviceVersion),
	))
	if err != nil {
		return nil, fmt.Errorf("telemetry: building resource: %w", err)
	}
	env, err := resource.New(ctx, resource.WithFromEnv())
	if err != nil {
		return nil, fmt.Errorf("telemetry: reading OTEL_RESOURCE_ATTRIBUTES: %w", err)
	}
	if res, err = resource.Merge(res, env); err != nil {
		return nil, fmt.Errorf("telemetry: building resource: %w", err)
	}

	if cfg.TracingEnabled {
		var opts []otlptracehttp.Option
		if cfg.TracingEndpoint != "" {
			opts = append(opts, otlptracehttp.WithEndpointURL(cfg.TracingEndpoint))
		}
		exporter, err := otlptracehttp.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("telemetry: creating trace exporter: %w", err)
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
		)
		p.Tracer = tp
		p.shutdown = append(p.shutdown, tp.Shutdown)
	}

	if cfg.MetricsEnabled {
		registry := prometheus.NewRegistry()
		if err := registry.Register(collectors.NewGoCollector()); err != nil {
			return nil, fmt.Errorf("telemetry: registering Go runtime metrics: %w", err)
		}
		exporter, err := promexporter.New(promexporter.WithRegisterer(registry))
		if err != nil {
			return nil, fmt.Errorf("telemetry: creating metrics exporter: %w", err)
		}
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter), sdkmetric.WithResource(res))
		p.Meter = mp
		p.MetricsHandler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		p.shutdown = append(p.shutdown, mp.Shutdown)
	}
	return p, nil
}
