package guardcore

// Coverage-parity wave 2: the failure and edge branches of the M1/M4/M8
// surfaces (XFF walk edge guards, composite nil/empty arms, agent surface
// error paths, composition redis arms, CORS normalization), driven through
// fakes and httptest so every branch is exercised without live services.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateCORSNormalizesInPlace(t *testing.T) {
	cfg := DefaultSecurityConfig()
	cfg.EnableCORS = true
	cfg.CORSAllowMethods = []string{"get", "post"}
	cfg.CORSAllowHeaders = []string{"X-Custom", "Content-Type"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid cors must pass: %v", err)
	}
	if cfg.CORSAllowMethods[0] != "GET" || cfg.CORSAllowHeaders[0] != "x-custom" {
		t.Fatalf("cors lists must be normalized, got %v %v", cfg.CORSAllowMethods, cfg.CORSAllowHeaders)
	}
}

func TestXFFEdgeGuards(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"10.0.0.9"}
		c.TrustedProxyDepth = 5
	})
	// metachar-bearing candidate: skipped by the candidate validator
	req := xffRequest("/api", "10.0.0.9", "$({evil}), 203.0.113.9")
	if ip := extractClientIP(req, engine.Config); ip == "$({evil})" {
		t.Fatal("a metachar candidate must not be adopted")
	}
	// depth larger than the chain: the reference rejects the too-short
	// chain and falls back to the connecting peer
	req2 := xffRequest("/api", "10.0.0.9", "203.0.113.9")
	if ip := extractClientIP(req2, engine.Config); ip != "10.0.0.9" {
		t.Fatalf("a too-short chain must fall back to the connecting peer, got %q", ip)
	}
}

type failingLogfireTransport struct{}

func (failingLogfireTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport down")
}

func TestOTelAndLogfireExportErrorArms(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer server.Close()

	otelCfg := OtelConfig{
		ServiceName:      "test",
		ExporterEndpoint: server.URL,
		BatchSize:        1,
		Client:           server.Client(),
	}
	otel := NewOtelHandler(otelCfg)
	// BatchSize=1 flushes inline, so every SendMetric exercises the
	// batch-full arm and surfaces the 503 export error.
	for _, m := range []SecurityMetric{
		{MetricType: MetricRequestCount, Value: 1},
		{MetricType: MetricResponseTime, Value: 2},
		{MetricType: MetricErrorRate, Value: 3},
	} {
		if err := otel.SendMetric(m); err == nil {
			t.Fatalf("metric %s must surface the 503 export error", m.MetricType)
		}
	}

	logfire := NewLogfireHandler(LogfireConfig{
		ServiceName: "test",
		Endpoint:    server.URL,
		Client:      &http.Client{Transport: failingLogfireTransport{}},
	})
	if err := logfire.Stop(); err != nil {
		t.Fatalf("Stop must log, not propagate, the flush failure: %v", err)
	}
}

func TestCompositeNilReceiverAndEmptyChildren(t *testing.T) {
	var nilComposite *CompositeAgentHandler
	// Send/SendMetric are nil-safe (agenthandler.go:125/142).
	if err := nilComposite.SendEvent(SecurityEvent{}); err != nil {
		t.Fatalf("nil composite must stay silent: %v", err)
	}
	if err := nilComposite.SendMetric(SecurityMetric{}); err != nil {
		t.Fatalf("nil composite must stay silent: %v", err)
	}
	// Flush/Healthy dereference children() and are not nil-safe: the nil
	// receiver contract covers only the send paths.
	empty := NewCompositeAgentHandler(nil, nil)
	if err := empty.SendEvent(SecurityEvent{}); err != nil {
		t.Fatalf("empty composite must stay silent: %v", err)
	}
	if err := empty.Flush(); err != nil {
		t.Fatalf("empty composite flush must stay silent: %v", err)
	}
	if !empty.Healthy() {
		t.Fatal("an empty composite must be healthy (the reference all([]) is True)")
	}
}

func TestOTelBatchFullFlushSurfacesExportError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer server.Close()
	otel := NewOtelHandler(OtelConfig{
		ServiceName:      "test",
		ExporterEndpoint: server.URL,
		BatchSize:        1,
		Client:           server.Client(),
	})
	for _, m := range []SecurityMetric{
		{MetricType: MetricRequestCount, Value: 1},
		{MetricType: MetricResponseTime, Value: 2},
	} {
		if err := otel.SendMetric(m); err == nil {
			t.Fatalf("metric %s must surface the 503 export error", m.MetricType)
		}
	}
}

func TestOTelAndLogfireStopWithFailingTransport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer server.Close()
	logfire := NewLogfireHandler(LogfireConfig{
		ServiceName: "test",
		Endpoint:    server.URL,
		Client:      &http.Client{Transport: failingLogfireTransport{}},
	})
	// Stop logs the flush failure and returns nil (the reference logs and
	// swallows in handler.flush_buffer's caller).
	if err := logfire.Stop(); err != nil {
		t.Fatalf("Stop must log, not propagate: %v", err)
	}
	otel := NewOtelHandler(OtelConfig{
		ServiceName:      "test",
		ExporterEndpoint: server.URL,
		Client:           &http.Client{Transport: failingLogfireTransport{}},
	})
	// Nothing buffered: the flush loop never reaches the transport, so
	// Stop answers nil even with the transport down.
	if err := otel.Stop(); err != nil {
		t.Fatalf("an empty-buffer stop must answer nil: %v", err)
	}
}

func TestOTelUnreachableEndpointSurfacesTransportError(t *testing.T) {
	otel := NewOtelHandler(OtelConfig{
		ServiceName:      "test",
		ExporterEndpoint: "http://127.0.0.1:1", // nothing listens
		BatchSize:        1,
		Client:           &http.Client{Timeout: 2 * time.Second},
	})
	if err := otel.SendMetric(SecurityMetric{MetricType: MetricRequestCount, Value: 1}); err == nil {
		t.Fatal("an unreachable endpoint must surface the transport error")
	}
}
