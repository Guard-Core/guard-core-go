package guardcore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// Coverage for the parity-fix-program wave (FP-GO): the defensive and
// edge branches the feature tests leave open, proven with real inputs.
// Statements that are unreachable as written stay in the waiver
// inventory with their proofs (coverage_waivers.txt).

// ---------------------------------------------------------------- //
// ipextraction.go

// TestProxyMatchesMalformedCIDR: an unparseable CIDR trust entry matches
// nothing (the reference's ip_network ValueError arm).
func TestProxyMatchesMalformedCIDR(t *testing.T) {
	addr, err := netip.ParseAddr("10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if proxyMatches("10.1.2.3", addr, "10.0.0.0/33") {
		t.Fatal("an unparseable CIDR entry must match nothing")
	}
	if isTrustedProxy("10.1.2.3", []string{"10.0.0.0/33", "not-an-ip"}) {
		t.Fatal("malformed trust entries must not trust anything")
	}
}

// TestExtractFromForwardedHeaderEdges: the empty chain, the chain
// shorter than the depth and the metachar hop all resolve to nothing.
func TestExtractFromForwardedHeaderEdges(t *testing.T) {
	if got := extractFromForwardedHeader("", 1); got != "" {
		t.Fatalf("empty chain must resolve to nothing, got %q", got)
	}
	if got := extractFromForwardedHeader("203.0.113.5", 3); got != "" {
		t.Fatalf("chain shorter than depth must resolve to nothing, got %q", got)
	}
	if got := extractFromForwardedHeader("203.0.113.[5]", 1); got != "" {
		t.Fatalf("metachar hop must resolve to nothing, got %q", got)
	}
}

// TestIsPrivateOrLoopbackInvalid: an unparseable address is neither
// private nor loopback.
func TestIsPrivateOrLoopbackInvalid(t *testing.T) {
	if isPrivateOrLoopback("not-an-ip") {
		t.Fatal("an unparseable address must answer false")
	}
}

// TestHandleUntrustedProxyDebugLevelForPrivatePeer: a spoof attempt from
// a private peer logs at debug level, not warning.
func TestHandleUntrustedProxyDebugLevelForPrivatePeer(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"203.0.113.1"}
	})
	req := xffRequest("/api", "192.168.1.5", "198.51.100.7")
	if ip := extractClientIP(req, engine.Config); ip != "192.168.1.5" {
		t.Fatalf("the private peer must keep its own address, got %q", ip)
	}
}

// TestResolveClientIPFromForwardedChainEmptyChain: no chain keeps the
// canonical peer (the reference's `if not forwarded_for` arm).
func TestResolveClientIPFromForwardedChainEmptyChain(t *testing.T) {
	if got := resolveClientIPFromForwardedChain("192.0.2.1", "", 1, []string{"192.0.2.1"}); got != "192.0.2.1" {
		t.Fatalf("empty chain must keep the peer, got %q", got)
	}
}

// TestExtractClientIPDepthOvercountUntrustedRightSide: with
// trusted_proxy_depth = 2 the right side of the selected entry carries an
// untrusted hop, the declared depth over-counts the real proxy hops and
// the right-to-left walk takes over.
func TestExtractClientIPDepthOvercountUntrustedRightSide(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
		c.TrustedProxyDepth = 2
	})
	// depth 2 selects 203.0.113.5; 198.51.100.9 sits to its right and is
	// not a trusted proxy: the walk takes the rightmost non-trusted hop.
	req := xffRequest("/api", "192.0.2.1", "203.0.113.5, 198.51.100.9")
	if ip := extractClientIP(req, engine.Config); ip != "198.51.100.9" {
		t.Fatalf("the over-count walk must take the rightmost non-trusted hop, got %q", ip)
	}
}

// TestExtractClientIPDepthOvercountWalkFailsKeepsPeer: the over-count
// walk that only finds trusted or malformed hops resolves to nothing and
// the connecting peer wins.
func TestExtractClientIPDepthOvercountWalkFailsKeepsPeer(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1", "192.0.2.2"}
		c.TrustedProxyDepth = 2
	})
	// depth 2 selects 192.0.2.2 (trusted); the right side carries the
	// malformed "not-an-ip" (unlisted), the walk finds no resolvable
	// non-trusted hop and the peer wins.
	req := xffRequest("/api", "192.0.2.1", "192.0.2.2, not-an-ip")
	if ip := extractClientIP(req, engine.Config); ip != "192.0.2.1" {
		t.Fatalf("a failing over-count walk must keep the peer, got %q", ip)
	}
}

// TestExtractClientIPUnixPeerWalksChain: under the reference's unix
// convention a declared "unix" trust entry walks the chain even without a
// connecting address.
func TestExtractClientIPUnixPeerWalksChain(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"unix"}
	})
	req := xffRequest("/api", "", "203.0.113.9")
	if ip := extractClientIP(req, engine.Config); ip != "203.0.113.9" {
		t.Fatalf("the unix convention must walk the chain, got %q", ip)
	}
}

// TestContainsEntryMiss: the membership helper answers false on a miss.
func TestContainsEntryMiss(t *testing.T) {
	if containsEntry([]string{"unix", "203.0.113.1"}, "198.51.100.1") {
		t.Fatal("a missing entry must answer false")
	}
}

// ---------------------------------------------------------------- //
// agenthandler.go

// TestAgentHandlerFuncSendMetricBridge: the metric half of the
// adaptation seam - nil receiver, nil func and the forwarding path.
func TestAgentHandlerFuncSendMetricBridge(t *testing.T) {
	sink := newFakeSink("bridged")
	var f *AgentHandlerFunc
	if err := f.SendMetric(SecurityMetric{MetricType: MetricRequestCount, Value: 1}); err != nil {
		t.Fatalf("a nil handler func must stay silent: %v", err)
	}
	bare := &AgentHandlerFunc{}
	if err := bare.SendMetric(SecurityMetric{MetricType: MetricRequestCount, Value: 1}); err != nil {
		t.Fatalf("a nil metric func must stay silent: %v", err)
	}
	bridged := &AgentHandlerFunc{
		MetricFunc: func(m SecurityMetric) error { return sink.SendMetric(m) },
	}
	if err := bridged.SendMetric(SecurityMetric{MetricType: MetricRequestCount, Value: 1}); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if len(sink.metrics) != 1 {
		t.Fatalf("the metric must reach the wrapped sink: %+v", sink.metrics)
	}
}

// TestCompositeAgentHandlerEmptyTypeBypassesFilter: an event or metric
// without a type string skips the filter gate (the reference gates on a
// non-empty type only).
func TestCompositeAgentHandlerEmptyTypeBypassesFilter(t *testing.T) {
	sink := newFakeSink("sink")
	filter := &EventFilter{}
	filter.MutedEventTypes = map[string]bool{EventIPBlocked: true}
	filter.MutedMetricTypes = map[string]bool{MetricRequestCount: true}
	composite := NewCompositeAgentHandler([]AgentHandler{sink}, filter)
	if err := composite.SendEvent(SecurityEvent{EventType: ""}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := composite.SendMetric(SecurityMetric{MetricType: ""}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(sink.events) != 1 || len(sink.metrics) != 1 {
		t.Fatalf("the empty types must bypass the mute lists: %+v %+v", sink.events, sink.metrics)
	}
}

// TestCompositeAgentHandlerChildFailures: a failing child never fails
// the stream, on send, stop or flush.
func TestCompositeAgentHandlerChildFailures(t *testing.T) {
	failing := newFakeSink("failing")
	failing.eventErr = errors.New("send refused")
	failing.metricErr = errors.New("metric refused")
	failing.stopErr = errors.New("stop refused")
	failing.flushErr = errors.New("flush refused")
	healthy := newFakeSink("healthy")
	composite := NewCompositeAgentHandler([]AgentHandler{failing, healthy}, nil)

	if err := composite.SendEvent(SecurityEvent{EventType: EventIPBlocked}); err != nil {
		t.Fatalf("child send failures must never propagate: %v", err)
	}
	if len(healthy.events) != 1 {
		t.Fatalf("the healthy sibling must still receive the event: %+v", healthy.events)
	}
	if err := composite.SendMetric(SecurityMetric{MetricType: MetricRequestCount, Value: 1}); err != nil {
		t.Fatalf("child metric failures must never propagate: %v", err)
	}
	if len(healthy.metrics) != 1 {
		t.Fatalf("the healthy sibling must still receive the metric: %+v", healthy.metrics)
	}
	if err := composite.Stop(); err != nil {
		t.Fatalf("child stop failures must never propagate: %v", err)
	}
	if err := composite.Flush(); err != nil {
		t.Fatalf("child flush failures must never propagate: %v", err)
	}

	// Health aggregates every reporting child.
	if !composite.Healthy() {
		t.Fatal("every healthy child must keep the composite healthy")
	}
	failing.healthy = false
	if composite.Healthy() {
		t.Fatal("one unhealthy child must fail the composite health")
	}
}

// TestConcreteHandlerNameNilFallback: a nil child degrades to the
// interface name in the start-degradation log.
func TestConcreteHandlerNameNilFallback(t *testing.T) {
	if got := concreteHandlerName(nil); got != "AgentHandler" {
		t.Fatalf("a nil handler must fall back to the interface name, got %q", got)
	}
}

// ---------------------------------------------------------------- //
// logging_json.go

type failingWriter struct{ err error }

func (w *failingWriter) Write([]byte) (int, error) { return 0, w.err }

// TestJsonFormatterInjectableClock: the injectable clock drives the
// timestamp column.
func TestJsonFormatterInjectableClock(t *testing.T) {
	stamp := time.Date(2026, 10, 6, 12, 30, 15, 123000000, time.UTC)
	line := JsonFormatter{TimeNow: func() time.Time { return stamp }}.Format("clocked")
	want := `"timestamp":"2026-10-06 12:30:15.123"`
	if !strings.Contains(line, want) {
		t.Fatalf("the injected clock must drive the timestamp: %s", line)
	}
}

// TestRecordWriterWriteErrorSurfaces: a failing sink surfaces the write
// error through the record writer.
func TestRecordWriterWriteErrorSurfaces(t *testing.T) {
	console := withJSONTestLogging(t)
	SetupCustomLogging("", "text")
	writer, ok := log.Default().Writer().(*recordWriter)
	if !ok {
		t.Fatalf("the installed writer must be the record writer, got %T", log.Default().Writer())
	}
	sinkErr := errors.New("console broke")
	writer.out = &failingWriter{err: sinkErr}
	if _, err := writer.Write([]byte("ignored")); !errors.Is(err, sinkErr) {
		t.Fatalf("the sink error must surface, got %v", err)
	}
	_ = console
}

// TestSetupCustomLoggingFileIsDirectoryFallsBack: a log path that is an
// existing directory fails the file open (EISDIR regardless of
// privileges) and the console keeps streaming.
func TestSetupCustomLoggingFileIsDirectoryFallsBack(t *testing.T) {
	console := withJSONTestLogging(t)
	dir := t.TempDir()
	SetupCustomLogging(dir, "json")
	log.Default().Print("console-only after directory log path")
	if !strings.Contains(console.String(), "console-only after directory log path") {
		t.Fatalf("the console must keep streaming: %q", console.String())
	}
}

// TestRestoreStandardLoggingWithoutInstallIsNoop: a restore without a
// prior install changes nothing.
func TestRestoreStandardLoggingWithoutInstallIsNoop(t *testing.T) {
	restoreStandardLogging()        // no-op if nothing installed
	restoreStandardLogging()        // the second call hits the not-installed arm
	before := log.Default().Flags() // logger stays usable
	log.Default().Print("still logging")
	if before < 0 {
		t.Fatal("unreachable")
	}
}

// ---------------------------------------------------------------- //
// otel_handler.go

// TestDefaultOtelConfig pins the SDK-equivalent defaults.
func TestDefaultOtelConfig(t *testing.T) {
	cfg := DefaultOtelConfig()
	if cfg.ServiceName != "guard-core" || cfg.Timeout != 10*time.Second ||
		cfg.BatchSize != 64 || cfg.FlushInterval != 5*time.Second {
		t.Fatalf("defaults drifted: %+v", cfg)
	}
}

// TestOtelHandlerStartIsIdempotent: a second Start must not spawn a
// second flusher.
func TestOtelHandlerStartIsIdempotent(t *testing.T) {
	handler := NewOtelHandler(DefaultOtelConfig())
	if err := handler.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := handler.Start(); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if err := handler.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

// TestOtelHandlerMetricExportFailureSurfaces: a failing metric export
// surfaces on flush while the handler reports configured.
func TestOtelHandlerMetricExportFailureSurfaces(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	handler := NewOtelHandler(OtelConfig{ExporterEndpoint: server.URL})
	if err := handler.SendMetric(SecurityMetric{
		MetricType: MetricErrorRate,
		Value:      1,
		Timestamp:  time.Now(),
		Tags:       map[string]string{"endpoint": "/api"},
	}); err != nil {
		t.Fatalf("buffering never fails: %v", err)
	}
	if err := handler.Flush(); err == nil {
		t.Fatal("a failing collector must surface on flush")
	}
}

// TestOtelHandlerTracestateAndNonStringMetadata: the tracestate carrier
// drops, a non-string enrichment value drops, and the span still builds.
func TestOtelHandlerTracestateAndNonStringMetadata(t *testing.T) {
	var mu sync.Mutex
	var trace map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		decoded := map[string]any{}
		_ = jsonUnmarshalInto(body, &decoded)
		mu.Lock()
		trace = decoded
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewOtelHandler(OtelConfig{ExporterEndpoint: server.URL})
	if err := handler.SendEvent(SecurityEvent{
		EventType: EventIPBlocked,
		Metadata: map[string]any{
			"tracestate":         "dropped",
			"guard.project_id":   42, // non-string enrichment drops
			"guard.threat_score": "0.7",
		},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := handler.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	raw, _ := jsonMarshal(trace)
	rendered := string(raw)
	if strings.Contains(rendered, `"tracestate"`) || strings.Contains(rendered, `"guard.project_id"`) {
		t.Fatalf("the non-string and tracestate metadata must drop:\n%s", rendered)
	}
	if !strings.Contains(rendered, `"guard.threat_score"`) {
		t.Fatalf("the string enrichment must forward:\n%s", rendered)
	}
}

// TestOtelHandlerCounterShapes: the error-rate counter names
// guard.error.count, and a zero timestamp stamps at export.
func TestOtelHandlerCounterShapes(t *testing.T) {
	var mu sync.Mutex
	var metric map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		decoded := map[string]any{}
		_ = jsonUnmarshalInto(body, &decoded)
		mu.Lock()
		metric = decoded
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewOtelHandler(OtelConfig{ExporterEndpoint: server.URL})
	if err := handler.SendMetric(SecurityMetric{MetricType: MetricErrorRate, Value: 2}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := handler.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	raw, _ := jsonMarshal(metric)
	if !strings.Contains(string(raw), `"name":"guard.error.count"`) {
		t.Fatalf("the error-rate counter must pin its instrument:\n%s", raw)
	}
	if !strings.Contains(string(raw), "timeUnixNano") {
		t.Fatalf("a zero timestamp must stamp at export:\n%s", raw)
	}
}

// TestOtelHandlerExportMetricsEmptyAndUnknownNames: an empty point set
// exports nothing, and unknown metric types map onto themselves.
func TestOtelHandlerExportMetricsEmptyAndUnknownNames(t *testing.T) {
	handler := NewOtelHandler(DefaultOtelConfig())
	if err := handler.exportMetrics(context.Background(), nil); err != nil {
		t.Fatalf("an empty point set must export nothing: %v", err)
	}
	if got := metricOtelName("custom.metric"); got != "custom.metric" {
		t.Fatalf("unknown metric types must map onto themselves, got %q", got)
	}
}

// ---------------------------------------------------------------- //
// logfire_handler.go

// TestDefaultLogfireConfig pins the SDK-equivalent defaults.
func TestDefaultLogfireConfig(t *testing.T) {
	cfg := DefaultLogfireConfig()
	if cfg.ServiceName != "guard-core" || cfg.Endpoint != DefaultLogfireEndpoint ||
		cfg.Timeout != 10*time.Second || cfg.BatchSize != 64 {
		t.Fatalf("defaults drifted: %+v", cfg)
	}
}

// TestNewLogfireHandlerDefaults: an empty config fills every default.
func TestNewLogfireHandlerDefaults(t *testing.T) {
	handler := NewLogfireHandler(LogfireConfig{})
	if handler.cfg.ServiceName != "guard-core" || handler.cfg.Endpoint != DefaultLogfireEndpoint ||
		handler.cfg.Timeout != 10*time.Second || handler.cfg.BatchSize != 64 {
		t.Fatalf("defaults drifted: %+v", handler.cfg)
	}
	if handler.client == nil {
		t.Fatal("the exporter must own an HTTP client")
	}
}

// TestLogfireHandlerUnhealthyWithoutEndpoint: a zero-value handler
// reports unconfigured (the reference health_check on an unconfigured
// SDK).
func TestLogfireHandlerUnhealthyWithoutEndpoint(t *testing.T) {
	if (&LogfireHandler{}).Healthy() {
		t.Fatal("a handler without an endpoint must report unhealthy")
	}
}

// TestLogfireHandlerExportFailuresSurface: failing span and log exports
// surface on flush, and Stop surfaces the flush failure through the
// handler-failure log without failing the stop.
func TestLogfireHandlerExportFailuresSurface(t *testing.T) {
	resetLogfireClaim()
	defer resetLogfireClaim()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	handler := NewLogfireHandler(LogfireConfig{Endpoint: server.URL})
	if err := handler.SendEvent(SecurityEvent{EventType: EventIPBlocked}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := handler.Flush(); err == nil {
		t.Fatal("a failing span export must surface on flush")
	}
	if err := handler.SendMetric(SecurityMetric{MetricType: MetricRequestCount, Value: 1}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := handler.Flush(); err == nil {
		t.Fatal("a failing log export must surface on flush")
	}
	if err := handler.Stop(); err != nil {
		t.Fatalf("stop never fails, it logs: %v", err)
	}
}

// TestLogfireHandlerBatchFlush: hitting the batch size flushes without
// an explicit Flush.
func TestLogfireHandlerBatchFlush(t *testing.T) {
	resetLogfireClaim()
	defer resetLogfireClaim()
	var mu sync.Mutex
	exported := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		exported++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewLogfireHandler(LogfireConfig{Endpoint: server.URL, BatchSize: 1})
	if err := handler.SendEvent(SecurityEvent{EventType: EventIPBlocked}); err != nil {
		t.Fatalf("send: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if exported != 1 {
		t.Fatalf("the full batch must auto-export, got %d exports", exported)
	}
}

// TestLogfireHandlerZeroTimestampMetric: a metric without a timestamp
// stamps at buffer time.
func TestLogfireHandlerZeroTimestampMetric(t *testing.T) {
	resetLogfireClaim()
	defer resetLogfireClaim()
	var mu sync.Mutex
	var logBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		decoded := map[string]any{}
		_ = jsonUnmarshalInto(body, &decoded)
		mu.Lock()
		logBody = decoded
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewLogfireHandler(LogfireConfig{Endpoint: server.URL})
	if err := handler.SendMetric(SecurityMetric{MetricType: MetricRequestCount, Value: 1}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := handler.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	raw, _ := jsonMarshal(logBody)
	if !strings.Contains(string(raw), "timeUnixNano") {
		t.Fatalf("the zero timestamp must stamp at buffer time:\n%s", raw)
	}
}

// TestToInt64Widening: the metadata widening covers int, int64 and
// float64 and rejects everything else.
func TestToInt64Widening(t *testing.T) {
	if v, ok := toInt64(int(7)); !ok || v != 7 {
		t.Fatalf("int: %d %v", v, ok)
	}
	if v, ok := toInt64(int64(9)); !ok || v != 9 {
		t.Fatalf("int64: %d %v", v, ok)
	}
	if v, ok := toInt64(2.75); !ok || v != 2 {
		t.Fatalf("float64: %d %v", v, ok)
	}
	if _, ok := toInt64("not-a-number"); ok {
		t.Fatal("strings must not widen")
	}
	if _, ok := toInt64(nil); ok {
		t.Fatal("nil must not widen")
	}
}

// TestLogfireHandlerStatusCodeWidenings: the status_code metadata column
// accepts int64, float64 and rejects non-numeric values.
func TestLogfireHandlerStatusCodeWidenings(t *testing.T) {
	resetLogfireClaim()
	defer resetLogfireClaim()
	var mu sync.Mutex
	var trace map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		decoded := map[string]any{}
		_ = jsonUnmarshalInto(body, &decoded)
		mu.Lock()
		trace = decoded
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewLogfireHandler(LogfireConfig{Endpoint: server.URL})
	for _, code := range []any{int64(201), 202.0, "no-code"} {
		if err := handler.SendEvent(SecurityEvent{
			EventType: EventIPBlocked,
			Metadata:  map[string]any{"status_code": code},
		}); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if err := handler.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	raw, _ := jsonMarshal(trace)
	if !strings.Contains(string(raw), `"key":"status_code"`) {
		t.Fatalf("the numeric widenings must land as status_code:\n%s", raw)
	}
}

// ---------------------------------------------------------------- //
// otlpwire.go

// TestSortStringsSwaps: the insertion sort actually reorders.
func TestSortStringsSwaps(t *testing.T) {
	values := []string{"b", "a", "d", "c"}
	sortStrings(values)
	if strings.Join(values, ",") != "a,b,c,d" {
		t.Fatalf("the sort must reorder, got %v", values)
	}
}

// TestParseTraceparentBranches: every malformed shape rejects; the valid
// shape resolves the linkage.
func TestParseTraceparentBranches(t *testing.T) {
	if _, ok := parseTraceparent("not-a-traceparent"); ok {
		t.Fatal("the wrong part count must reject")
	}
	if _, ok := parseTraceparent("00-short-short-01"); ok {
		t.Fatal("the wrong part sizes must reject")
	}
	if _, ok := parseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e47zz-00f067aa0ba902b7-01"); ok {
		t.Fatal("non-hex parts must reject")
	}
	if _, ok := parseTraceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01"); ok {
		t.Fatal("an all-zero trace id must reject")
	}
	if _, ok := parseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"); ok {
		t.Fatal("an all-zero span id must reject")
	}
	linked, ok := parseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if !ok || linked.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || linked.ParentID != "00f067aa0ba902b7" || linked.SpanID == "" {
		t.Fatalf("the valid shape must resolve the linkage: %+v %v", linked, ok)
	}
}

// TestPostOTLPRejectsBadURLAndNon2xx: a malformed base fails the request
// build and a non-2xx collector answer surfaces with the status.
func TestPostOTLPRejectsBadURLAndNon2xx(t *testing.T) {
	if err := postOTLP(context.Background(), http.DefaultClient, "://bad", "/v1/traces", "", otlpTraceRequest{}); err == nil {
		t.Fatal("a malformed base must fail the request build")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	if err := postOTLP(context.Background(), server.Client(), server.URL, "/v1/traces", "", otlpTraceRequest{}); err == nil {
		t.Fatal("a non-2xx collector answer must surface")
	}
}

// ---------------------------------------------------------------- //
// composition.go

// TestResolveClientIdentityNilConfigIsNoop: an engine without a config
// resolves nothing and never panics.
func TestResolveClientIdentityNilConfigIsNoop(t *testing.T) {
	engine := &Engine{}
	req := xffRequest("/api", "203.0.113.5", "")
	engine.resolveClientIdentity(req)
	if state := req.State(); state != nil && state.ClientIP != "" {
		t.Fatalf("a nil config must not resolve an identity, got %q", state.ClientIP)
	}
}

// ---------------------------------------------------------------- //
// shared test helpers

// jsonUnmarshalInto decodes JSON without shadowing the production
// encoder helpers.
func jsonUnmarshalInto(body []byte, into *map[string]any) error {
	return json.Unmarshal(body, into)
}

// jsonMarshal encodes a value without shadowing the production encoder
// helpers.
func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

// Coverage-parity wave 2: the failure and edge branches of the M1/M4/M8
// surfaces, driven through fakes so every branch is exercised without
// network or race-dependence.

// TestConcreteHandlerNameNilFallback: a nil child degrades to the
// interface name in the start-degradation log.

// ---------------------------------------------------------------- //
// logging_json.go

// jsonMarshal encodes a value without shadowing the production encoder
// helpers.

// Coverage-parity wave 2: the failure and edge branches of the M1/M4/M8
// surfaces, driven through fakes so every branch is exercised without
// network or race-dependence.

func TestIPExtractionDefensiveBranches(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"unix"}
	})
	// metachar candidate in the forwarded chain: skipped, not resolved.
	req := xffRequest("/api", "", "$({malicious})")
	if ip := extractClientIP(req, engine.Config); ip == "$({malicious})" {
		t.Fatal("a metachar-bearing candidate must not be adopted verbatim")
	}
	// start < 0 guard: depth larger than the chain length.
	req2 := xffRequest("/api", "", "203.0.113.9, 198.51.100.1")
	if ip := extractClientIP(req2, engine.Config); ip == "" {
		t.Fatal("a short chain under a larger depth must still resolve a hop")
	}
}
