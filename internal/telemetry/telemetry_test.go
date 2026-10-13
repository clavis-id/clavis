package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func TestSetupDisabled(t *testing.T) {
	t.Parallel()
	p, err := Setup(t.Context(), Config{}, "v0.0.0")
	if err != nil {
		t.Fatalf("Setup() unexpected error: %v", err)
	}
	if _, ok := p.Tracer.(tracenoop.TracerProvider); !ok {
		t.Errorf("Tracer is %T, want a no-op provider", p.Tracer)
	}
	if _, ok := p.Meter.(noop.MeterProvider); !ok {
		t.Errorf("Meter is %T, want a no-op provider", p.Meter)
	}
	if p.MetricsHandler != nil {
		t.Error("MetricsHandler is set while metrics are disabled")
	}
	if err := p.Shutdown(t.Context()); err != nil {
		t.Errorf("Shutdown() unexpected error: %v", err)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	t.Parallel()
	p, err := Setup(t.Context(), Config{MetricsEnabled: true}, "v1.2.3")
	if err != nil {
		t.Fatalf("Setup() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(t.Context()) })

	counter, err := p.Meter.Meter("test").Int64Counter("clavis.test.events")
	if err != nil {
		t.Fatalf("creating counter: %v", err)
	}
	counter.Add(t.Context(), 3)

	rec := httptest.NewRecorder()
	p.MetricsHandler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	body := rec.Body.String()
	for _, want := range []string{"go_goroutines", "clavis_test_events_total", `service_name="clavis"`, `service_version="v1.2.3"`} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output does not contain %q", want)
		}
	}
}

func TestTracesAreExported(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodPost && r.URL.Path == "/v1/traces" {
			requests.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	p, err := Setup(t.Context(), Config{
		TracingEnabled:  true,
		TracingEndpoint: collector.URL + "/v1/traces",
		SampleRatio:     1,
	}, "v0.0.0")
	if err != nil {
		t.Fatalf("Setup() unexpected error: %v", err)
	}
	_, span := p.Tracer.Tracer("test").Start(t.Context(), "operation")
	span.End()
	if err := p.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() unexpected error: %v", err)
	}
	if requests.Load() == 0 {
		t.Error("no spans reached the collector after Shutdown flushed the exporter")
	}
}
