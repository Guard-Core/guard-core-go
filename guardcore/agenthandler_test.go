package guardcore

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSink is a recording AgentHandler with optional lifecycle surfaces.
type fakeSink struct {
	name     string
	mu       sync.Mutex
	events   []SecurityEvent
	metrics  []SecurityMetric
	startErr error
	started  bool
	stopped  bool
	flushed  int
	healthy  bool
	eventErr error
	metricErr error
	stopErr  error
	flushErr error
}

func newFakeSink(name string) *fakeSink {
	return &fakeSink{name: name, healthy: true}
}

func (s *fakeSink) SendEvent(event SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.eventErr != nil {
		return s.eventErr
	}
	s.events = append(s.events, event)
	return nil
}

func (s *fakeSink) SendMetric(metric SecurityMetric) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.metricErr != nil {
		return s.metricErr
	}
	s.metrics = append(s.metrics, metric)
	return nil
}

func (s *fakeSink) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.startErr != nil {
		return s.startErr
	}
	s.started = true
	return nil
}

func (s *fakeSink) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopErr != nil {
		return s.stopErr
	}
	s.stopped = true
	return nil
}

func (s *fakeSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushErr != nil {
		return s.flushErr
	}
	s.flushed++
	return nil
}

func (s *fakeSink) Healthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.healthy
}

func (s *fakeSink) eventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// TestCompositeAgentHandlerFanOut proves one stream reaches every sink.
func TestCompositeAgentHandlerFanOut(t *testing.T) {
	first, second := newFakeSink("first"), newFakeSink("second")
	composite := NewCompositeAgentHandler([]AgentHandler{first, second}, nil)

	event := SecurityEvent{EventType: EventIPBlocked, IPAddress: "203.0.113.5", Reason: "blacklisted"}
	metric := SecurityMetric{MetricType: MetricRequestCount, Value: 1}
	if err := composite.SendEvent(event); err != nil {
		t.Fatalf("composite send must not fail: %v", err)
	}
	if err := composite.SendMetric(metric); err != nil {
		t.Fatalf("composite send must not fail: %v", err)
	}
	if first.eventCount() != 1 || second.eventCount() != 1 {
		t.Fatalf("fan-out drifted: first=%d second=%d", first.eventCount(), second.eventCount())
	}
	if len(first.metrics) != 1 || len(second.metrics) != 1 {
		t.Fatalf("metric fan-out drifted: %+v %+v", first.metrics, second.metrics)
	}
}

// TestCompositeAgentHandlerFilter: muted types never reach the sinks.
func TestCompositeAgentHandlerFilter(t *testing.T) {
	sink := newFakeSink("sink")
	composite := NewCompositeAgentHandler([]AgentHandler{sink}, &EventFilter{
		MutedEventTypes:  map[string]bool{EventIPBlocked: true},
		MutedMetricTypes: map[string]bool{MetricErrorRate: true},
	})
	if err := composite.SendEvent(SecurityEvent{EventType: EventIPBlocked}); err != nil {
		t.Fatalf("muted sends stay silent: %v", err)
	}
	if err := composite.SendEvent(SecurityEvent{EventType: EventUserAgentBlocked}); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if err := composite.SendMetric(SecurityMetric{MetricType: MetricErrorRate}); err != nil {
		t.Fatalf("muted sends stay silent: %v", err)
	}
	if sink.eventCount() != 1 {
		t.Fatalf("only the allowed event must land, got %d", sink.eventCount())
	}
	if len(sink.metrics) != 0 {
		t.Fatalf("the muted metric must not land, got %+v", sink.metrics)
	}
}

// TestCompositeAgentHandlerChildFailureIsolation: a failing child never
// fails the stream nor blocks the other children.
func TestCompositeAgentHandlerChildFailureIsolation(t *testing.T) {
	failing := newFakeSink("failing")
	failing.eventErr = errors.New("sink down")
	healthy := newFakeSink("healthy")
	composite := NewCompositeAgentHandler([]AgentHandler{failing, healthy}, nil)
	if err := composite.SendEvent(SecurityEvent{EventType: EventIPBanned}); err != nil {
		t.Fatalf("child failure must not propagate: %v", err)
	}
	if healthy.eventCount() != 1 {
		t.Fatalf("the healthy child must still receive, got %d", healthy.eventCount())
	}
}

// TestCompositeAgentHandlerLifecycleAndDegradation: Start fans out, a
// failing child degrades without stopping the rest, Stop and Flush fan
// out, Healthy requires every reporting child up.
func TestCompositeAgentHandlerLifecycleAndDegradation(t *testing.T) {
	good, bad := newFakeSink("good"), newFakeSink("bad")
	// funcOnly has no AgentReporter surface: it counts healthy.
	funcOnly := &AgentHandlerFunc{}
	bad.startErr = errors.New("no endpoint")
	bad.healthy = false
	composite := NewCompositeAgentHandler([]AgentHandler{good, bad, funcOnly}, nil)

	if err := composite.Start(); err != nil {
		t.Fatalf("start must not fail: %v", err)
	}
	if !composite.Started() {
		t.Fatal("composite must report started")
	}
	if !composite.Degraded() {
		t.Fatal("a failed child must degrade the composite")
	}
	if failed := composite.FailedHandlers(); len(failed) != 1 || failed[0] != "fakeSink" {
		t.Fatalf("failed handlers drifted: %v", failed)
	}
	if !good.started {
		t.Fatal("the healthy child must have started")
	}
	if bad.started {
		t.Fatal("the failing child must not report started")
	}
	if err := composite.Flush(); err != nil {
		t.Fatalf("flush must not fail: %v", err)
	}
	if good.flushed != 1 {
		t.Fatal("flush must fan out")
	}
	if composite.Healthy() {
		t.Fatal("the false-reporting child must fail health")
	}
	bad.healthy = true
	if !composite.Healthy() {
		t.Fatal("all healthy children must pass health; a child without the reporting surface counts healthy")
	}
	if err := composite.Stop(); err != nil {
		t.Fatalf("stop must not fail: %v", err)
	}
	if !good.stopped {
		t.Fatal("stop must fan out")
	}
}

// TestCompositeAgentHandlerDynamicRules: the first child providing rules
// wins; provider errors fall through; no provider answers nil.
func TestCompositeAgentHandlerDynamicRules(t *testing.T) {
	rules := &DynamicRules{}
	provider := &fakeRulesProvider{fakeSink: *newFakeSink("provider"), rules: rules}
	broken := &fakeRulesProvider{fakeSink: *newFakeSink("broken"), err: errors.New("fetch failed")}
	composite := NewCompositeAgentHandler([]AgentHandler{broken, provider}, nil)

	// The composite always satisfies the provider capability, like the
	// reference composite always carries get_dynamic_rules.
	if _, ok := any(composite).(DynamicRulesProvider); !ok {
		t.Fatal("composite must satisfy DynamicRulesProvider")
	}
	got, err := composite.GetDynamicRules()
	if err != nil || got != rules {
		t.Fatalf("first valid provider must win, got %+v err=%v", got, err)
	}

	empty := NewCompositeAgentHandler([]AgentHandler{newFakeSink("plain")}, nil)
	got, err = empty.GetDynamicRules()
	if err != nil || got != nil {
		t.Fatalf("no provider must answer nil, got %+v err=%v", got, err)
	}
}

type fakeRulesProvider struct {
	fakeSink
	rules *DynamicRules
	err   error
}

func (p *fakeRulesProvider) GetDynamicRules() (*DynamicRules, error) {
	return p.rules, p.err
}

// TestAgentHandlerFuncBridge pins the adaptation seam: nil funcs answer
// nil, the funcs receive the payloads, and the adapter satisfies
// AgentHandler.
func TestAgentHandlerFuncBridge(t *testing.T) {
	var _ AgentHandler = &AgentHandlerFunc{}
	adapter := &AgentHandlerFunc{}
	if err := adapter.SendEvent(SecurityEvent{EventType: EventIPBlocked}); err != nil {
		t.Fatalf("nil event func answers nil: %v", err)
	}
	seen := make(chan SecurityEvent, 1)
	adapter.EventFunc = func(event SecurityEvent) error {
		seen <- event
		return nil
	}
	go adapter.SendEvent(SecurityEvent{EventType: EventIPBanned, IPAddress: "203.0.113.9"})
	select {
	case event := <-seen:
		if event.EventType != EventIPBanned {
			t.Fatalf("event drifted: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("the event func never ran")
	}
}

// TestEngineToAgentBridgeThroughComposite proves the engine event stream
// reaches every composite sink end to end.
func TestEngineToAgentBridgeThroughComposite(t *testing.T) {
	first, second := newFakeSink("first"), newFakeSink("second")
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.AgentHandler = NewCompositeAgentHandler([]AgentHandler{first, second}, nil)
		c.BlockedUserAgents = []string{"^badbot"}
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		Method:     "GET",
		Header:     map[string]string{"User-Agent": "badbot/1.0"},
		ClientHost: "203.0.113.5",
	})
	if resp := engine.Check(req); resp == nil {
		t.Fatal("the bad user agent must block")
	}
	for _, sink := range []*fakeSink{first, second} {
		found := false
		sink.mu.Lock()
		for _, event := range sink.events {
			if event.EventType == EventUserAgentBlocked {
				found = true
				if event.IPAddress != "203.0.113.5" {
					t.Fatalf("resolved identity drifted: %+v", event)
				}
			}
		}
		sink.mu.Unlock()
		if !found {
			t.Fatalf("sink %s missed the middleware event: %+v", sink.name, sink.events)
		}
	}
}

func resetLogfireClaim() {
	logfireConfiguredByGuard.Store(false)
	logfireConfiguredService.Store("")
}

// TestOtelHandlerExportsSpansAndMetrics drives the OTLP exporter against
// an httptest collector and pins the wire shapes.
func TestOtelHandlerExportsSpansAndMetrics(t *testing.T) {
	var mu sync.Mutex
	var traceBodies, metricBodies []map[string]any
	traces := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Errorf("bad OTLP JSON: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/traces":
			traces++
			traceBodies = append(traceBodies, decoded)
		case "/v1/metrics":
			metricBodies = append(metricBodies, decoded)
		default:
			t.Errorf("unexpected signal path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewOtelHandler(OtelConfig{
		ServiceName:        "guard-test",
		ResourceAttributes: map[string]string{"deployment.environment": "test"},
		ExporterEndpoint:   server.URL + "/v1/traces", // signal-aware join trims this
	})
	if err := handler.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	event := SecurityEvent{
		EventType:   EventSuspiciousRequest,
		IPAddress:   "203.0.113.5",
		ActionTaken: "logged_only",
		Reason:      "Potential IP spoof attempt",
		Endpoint:    "/api",
		Method:      "GET",
		Metadata: map[string]any{
			"traceparent":        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			"guard.threat_score": "0.9",
			"unrelated":          "dropped",
		},
	}
	if err := handler.SendEvent(event); err != nil {
		t.Fatalf("send event: %v", err)
	}
	if err := handler.SendMetric(SecurityMetric{
		MetricType: MetricResponseTime,
		Value:      0.42,
		Timestamp:  time.Now(),
		Tags:       map[string]string{"endpoint": "/api", "method": "GET", "status": "200"},
	}); err != nil {
		t.Fatalf("send metric: %v", err)
	}
	if err := handler.SendMetric(SecurityMetric{
		MetricType: MetricRequestCount,
		Value:      1,
		Timestamp:  time.Now(),
		Tags:       map[string]string{"endpoint": "/api", "method": "GET"},
	}); err != nil {
		t.Fatalf("send metric: %v", err)
	}
	if err := handler.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := handler.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(traceBodies) == 0 || len(metricBodies) == 0 {
		t.Fatalf("both signals must export, traces=%d metrics=%d", len(traceBodies), len(metricBodies))
	}
	traceJSON, _ := json.Marshal(traceBodies[0])
	trace := string(traceJSON)
	for _, want := range []string{
		`"name":"guard.event.suspicious_request"`,
		`"key":"service.name"`, `"stringValue":"guard-test"`,
		`"key":"guard.event_type"`, `"key":"guard.ip_address"`,
		`"key":"guard.threat_score"`,
		`"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"`,
		`"parentSpanId":"00f067aa0ba902b7"`,
		`"deployment.environment"`,
	} {
		if !strings.Contains(trace, want) {
			t.Fatalf("trace wire missing %s:\n%s", want, trace)
		}
	}
	if strings.Contains(trace, `"unrelated"`) {
		t.Fatalf("non-guard metadata must not forward:\n%s", trace)
	}
	metricJSON, _ := json.Marshal(metricBodies[0])
	metric := string(metricJSON)
	for _, want := range []string{
		`"name":"guard.request.duration"`, `"unit":"s"`,
		`"name":"guard.request.count"`, `"isMonotonic":true`,
		`"key":"endpoint"`, `"stringValue":"/api"`,
	} {
		if !strings.Contains(metric, want) {
			t.Fatalf("metric wire missing %s:\n%s", want, metric)
		}
	}

	// Unknown metric types log the reference warning and record nothing.
	if err := handler.SendMetric(SecurityMetric{MetricType: "bogus", Value: 1}); err != nil {
		t.Fatalf("unknown metric types stay silent: %v", err)
	}
}

// TestOtelHandlerBatchAutoFlush: hitting the batch size exports without
// an explicit Flush.
func TestOtelHandlerBatchAutoFlush(t *testing.T) {
	var count int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewOtelHandler(OtelConfig{ExporterEndpoint: server.URL, BatchSize: 2})
	for i := 0; i < 2; i++ {
		if err := handler.SendEvent(SecurityEvent{EventType: EventIPBlocked}); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Fatalf("the full batch must auto-export, got %d exports", count)
	}
}

// TestOtelHandlerExportFailureSurfaces: a collector 500 surfaces the
// error and the handler stays healthy-configured.
func TestOtelHandlerExportFailureSurfaces(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	handler := NewOtelHandler(OtelConfig{ExporterEndpoint: server.URL})
	if err := handler.SendEvent(SecurityEvent{EventType: EventIPBlocked}); err != nil {
		t.Fatalf("buffering never fails: %v", err)
	}
	if err := handler.Flush(); err == nil {
		t.Fatal("a failing collector must surface on flush")
	}
	if !handler.Healthy() {
		t.Fatal("health answers endpoint configuration, not transient failures")
	}
}

// TestLogfireHandlerSpansLogsAndConfigurationGuard pins the span/log
// shapes and the process-wide already-configured yield.
func TestLogfireHandlerSpansLogsAndConfigurationGuard(t *testing.T) {
	resetLogfireClaim()
	defer resetLogfireClaim()

	var mu sync.Mutex
	var traceBodies, logBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Errorf("bad OTLP JSON: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/traces":
			traceBodies = append(traceBodies, decoded)
		case "/v1/logs":
			logBodies = append(logBodies, decoded)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewLogfireHandler(LogfireConfig{
		ServiceName: "guard-logfire",
		Endpoint:    server.URL,
		Token:       "write-token",
	})
	if err := handler.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !logfireConfiguredByGuard.Load() {
		t.Fatal("the first handler must claim the configuration")
	}

	// A second handler yields to the process-wide claim with the
	// reference warning (checked while the owner still holds it).
	second := NewLogfireHandler(LogfireConfig{ServiceName: "guard-second", Endpoint: server.URL})
	if err := second.Start(); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if second.configuredByUs {
		t.Fatal("the second handler must not claim the configuration")
	}

	if err := handler.SendEvent(SecurityEvent{
		EventType:   EventIPBlocked,
		IPAddress:   "203.0.113.5",
		ActionTaken: "request_blocked",
		Reason:      "blacklisted",
		Endpoint:    "/api",
		Method:      "GET",
		Metadata: map[string]any{
			"guard.project_id": "proj-1",
			"traceparent":      "dropped",
			"status_code":      403,
		},
	}); err != nil {
		t.Fatalf("send event: %v", err)
	}
	if err := handler.SendMetric(SecurityMetric{
		MetricType: MetricErrorRate,
		Value:      1,
		Timestamp:  time.Now(),
		Tags:       map[string]string{"endpoint": "/api", "value": "again", "method": "GET"},
	}); err != nil {
		t.Fatalf("send metric: %v", err)
	}
	if err := handler.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := handler.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if logfireConfiguredByGuard.Load() {
		t.Fatal("the owning stop must release the claim")
	}

	if err := second.Stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(traceBodies) == 0 || len(logBodies) == 0 {
		t.Fatalf("both signals must export, traces=%d logs=%d", len(traceBodies), len(logBodies))
	}
	traceJSON, _ := json.Marshal(traceBodies[0])
	trace := string(traceJSON)
	for _, want := range []string{
		`"name":"guard.event.ip_blocked"`,
		`"key":"ip_address"`, `"key":"action_taken"`,
		`"key":"guard.project_id"`, `"key":"status_code"`,
	} {
		if !strings.Contains(trace, want) {
			t.Fatalf("logfire trace wire missing %s:\n%s", want, trace)
		}
	}
	if strings.Contains(trace, `"traceparent"`) {
		t.Fatalf("trace carriers must drop:\n%s", trace)
	}
	logJSON, _ := json.Marshal(logBodies[0])
	logLine := string(logJSON)
	for _, want := range []string{
		`"stringValue":"guard.metric.error_rate"`,
		`"key":"value"`, `"key":"endpoint"`, `"key":"method"`,
		`"severityText":"INFO"`,
	} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("logfire log wire missing %s:\n%s", want, logLine)
		}
	}

}

// TestEngineCompositeWithExportHandlersEndToEnd wires the full surface
// the Python handler_initializer builds: composite(otel, logfire) as the
// engine's agent handler, events fanned to both exporters.
func TestEngineCompositeWithExportHandlersEndToEnd(t *testing.T) {
	resetLogfireClaim()
	defer resetLogfireClaim()

	var mu sync.Mutex
	traceCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/traces" {
			mu.Lock()
			traceCount++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	otel := NewOtelHandler(OtelConfig{ExporterEndpoint: server.URL, ServiceName: "e2e"})
	logfire := NewLogfireHandler(LogfireConfig{Endpoint: server.URL, ServiceName: "e2e"})
	composite := NewCompositeAgentHandler([]AgentHandler{otel, logfire}, nil)
	if err := composite.Start(); err != nil {
		t.Fatalf("composite start: %v", err)
	}

	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.AgentHandler = composite
		c.BlockedUserAgents = []string{"^badbot"}
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp := engine.Check(NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		Method:     "GET",
		Header:     map[string]string{"User-Agent": "badbot/1.0"},
		ClientHost: "203.0.113.5",
	}))
	if resp == nil {
		t.Fatal("the bad user agent must block")
	}
	if err := composite.Flush(); err != nil {
		t.Fatalf("composite flush: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if traceCount == 0 {
		t.Fatal("both exporters must ship the engine event")
	}
}
