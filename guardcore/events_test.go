package guardcore

import (
	"errors"
	"strings"
	"testing"
)

// recordingAgent captures the security events and metrics an engine or
// bus emits during a test.
type recordingAgent struct {
	events    []SecurityEvent
	metrics   []SecurityMetric
	eventErr  error
	metricErr error
}

func (a *recordingAgent) SendEvent(event SecurityEvent) error {
	a.events = append(a.events, event)
	return a.eventErr
}

func (a *recordingAgent) SendMetric(metric SecurityMetric) error {
	a.metrics = append(a.metrics, metric)
	return a.metricErr
}

func (a *recordingAgent) eventTypes() []string {
	types := make([]string, 0, len(a.events))
	for _, event := range a.events {
		types = append(types, event.EventType)
	}
	return types
}

// TestEventVocabulary pins the exact observable event-name vocabulary of
// spec 12, including the constant/string asymmetries the spec calls out.
func TestEventVocabulary(t *testing.T) {
	vocabulary := EventVocabulary()
	if len(vocabulary) != 39 {
		t.Fatalf("vocabulary holds %d names, spec 12 pins 39 (the UNRESOLVED dynamic_rule_violation included)", len(vocabulary))
	}
	seen := map[string]bool{}
	for _, name := range vocabulary {
		if name == "" {
			t.Fatal("empty event name in the vocabulary")
		}
		if seen[name] {
			t.Fatalf("duplicate event name %q", name)
		}
		seen[name] = true
	}
	want := map[string]string{
		EventPenetrationAttempt:               "penetration_attempt",
		EventIPBlocked:                        "ip_blocked",
		EventIPBanned:                         "ip_banned",
		EventIPBanFailed:                      "ip_ban_failed",
		EventIPUnbanned:                       "ip_unbanned",
		EventCloudBlocked:                     "cloud_blocked",
		EventHTTPSEnforced:                    "https_enforced",
		EventDecoratorViolation:               "decorator_violation",
		EventBehaviorViolation:                "behavioral_violation",
		EventPatternDetected:                  "pattern_detected",
		EventDynamicRuleUpdated:               "dynamic_rule_updated",
		EventDynamicRuleApplied:               "dynamic_rule_applied",
		EventDynamicRuleViolation:             "dynamic_rule_violation",
		EventEmergencyMode:                    "emergency_mode_activated",
		EventAccessDenied:                     "access_denied",
		EventAuthenticationFailed:             "authentication_failed",
		EventContentFiltered:                  "content_filtered",
		EventCountryBlocked:                   "country_blocked",
		EventCSPViolation:                     "csp_violation",
		EventCustomRequestCheck:               "custom_request_check",
		EventDecodingError:                    "decoding_error",
		EventEmergencyModeBlock:               "emergency_mode_block",
		EventGeoLookupFailed:                  "geo_lookup_failed",
		EventPathExcluded:                     "path_excluded",
		EventPatternAdded:                     "pattern_added",
		EventPatternRemoved:                   "pattern_removed",
		EventRateLimited:                      "rate_limited",
		EventRateLimitScriptReloaded:          "rate_limit_script_reloaded",
		EventRedisConnection:                  "redis_connection",
		EventRedisError:                       "redis_error",
		EventRouteUnresolved:                  "route_unresolved",
		EventSecurityBypass:                   "security_bypass",
		EventSecurityHeadersApplied:           "security_headers_applied",
		EventUserAgentBlocked:                 "user_agent_blocked",
		EventSuspiciousRequest:                "suspicious_request",
		EventDetectionEngineCallbackError:     "detection_engine_callback_error",
		EventPatternAnomalyTimeout:            "pattern_anomaly_timeout",
		EventPatternAnomalySlowExecution:      "pattern_anomaly_slow_execution",
		EventPatternAnomalyStatisticalAnomaly: "pattern_anomaly_statistical_anomaly",
	}
	if len(want) != 39 {
		t.Fatalf("the assertion table itself holds %d names, want 39", len(want))
	}
	for constant, wantString := range want {
		if constant != wantString {
			t.Errorf("event constant %q drifted from the spec string %q", constant, wantString)
		}
		if !seen[constant] {
			t.Errorf("spec string %q missing from EventVocabulary()", constant)
		}
	}
	// The two documented asymmetries.
	if EventBehaviorViolation != "behavioral_violation" {
		t.Error("EVENT_BEHAVIOR_VIOLATION must be behavioral_violation, not behavior_violation")
	}
	if EventEmergencyMode != "emergency_mode_activated" {
		t.Error("EVENT_EMERGENCY_MODE must be emergency_mode_activated")
	}
	// Metric vocabulary.
	metrics := MetricVocabulary()
	if len(metrics) != 3 {
		t.Fatalf("metric vocabulary holds %d names, want 3", len(metrics))
	}
	if MetricResponseTime != "response_time" || MetricRequestCount != "request_count" || MetricErrorRate != "error_rate" {
		t.Error("metric type strings drifted")
	}
}

func TestEventFilterMutes(t *testing.T) {
	filter := EventFilter{
		MutedEventTypes:  map[string]bool{EventRateLimited: true},
		MutedMetricTypes: map[string]bool{MetricErrorRate: true},
	}
	if filter.IsEventAllowed(EventRateLimited) {
		t.Error("muted event type must not be allowed")
	}
	if !filter.IsEventAllowed(EventIPBlocked) {
		t.Error("unmuted event type must be allowed")
	}
	if filter.IsMetricAllowed(MetricErrorRate) {
		t.Error("muted metric type must not be allowed")
	}
	if !filter.IsMetricAllowed(MetricResponseTime) {
		t.Error("unmuted metric type must be allowed")
	}
}

func TestSecurityEventBusGating(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.AgentEnableEvents = false
	})
	if err != nil {
		t.Fatal(err)
	}
	agent := &recordingAgent{}
	bus := NewSecurityEventBus(agent, cfg, nil, EventFilter{})
	req := NewRequestFactory().CreateRequest(RequestOptions{Path: "/x", Method: "GET"})
	bus.SendMiddlewareEvent(EventIPBlocked, req, "request_blocked", "test", nil)
	if len(agent.events) != 0 {
		t.Fatal("agent_enable_events=false must gate the bus")
	}
	// No handler: silent no-op.
	busNoHandler := NewSecurityEventBus(nil, cfg, nil, EventFilter{})
	busNoHandler.SendMiddlewareEvent(EventIPBlocked, req, "request_blocked", "test", nil)
	// Muted type.
	cfg2, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.MutedEventTypes = []string{EventIPBlocked}
	})
	if err != nil {
		t.Fatal(err)
	}
	busMuted := NewSecurityEventBus(agent, cfg2, nil, EventFilter{MutedEventTypes: nameSet(cfg2.MutedEventTypes)})
	busMuted.SendMiddlewareEvent(EventIPBlocked, req, "request_blocked", "test", nil)
	if len(agent.events) != 0 {
		t.Fatal("muted event types must not reach the agent")
	}
}

func TestSecurityEventBusEnvelope(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.LogSensitiveParams = map[string]bool{"access_token": true}
	})
	if err != nil {
		t.Fatal(err)
	}
	agent := &recordingAgent{}
	bus := NewSecurityEventBus(agent, cfg, nil, EventFilter{})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:     "/login?access_token=PLACEHOLDER&next=/home",
		Method:   "POST",
		Scheme:   "http",
		Host:     "api.internal",
		RawQuery: "access_token=PLACEHOLDER&next=/home",
		Header: map[string]string{
			"User-Agent":  "zebra-browser/1.0",
			"Traceparent": "00-trace-span-01",
		},
	})
	bus.SendMiddlewareEvent(EventDecoratorViolation, req, "request_blocked", "nope",
		map[string]any{"decorator_type": "authentication", "violation_type": "require_https"})
	if len(agent.events) != 1 {
		t.Fatalf("expected one event, got %d", len(agent.events))
	}
	event := agent.events[0]
	if event.EventType != EventDecoratorViolation || event.HandlerName != MiddlewareHandlerName {
		t.Fatalf("identity drifted: %+v", event)
	}
	if event.ActionTaken != "request_blocked" || event.Reason != "nope" {
		t.Fatalf("action/reason drifted: %+v", event)
	}
	if event.Method != "POST" {
		t.Fatalf("method drifted: %q", event.Method)
	}
	if !strings.Contains(event.Endpoint, "access_token=[REDACTED]") {
		t.Fatalf("endpoint query secret not redacted: %q", event.Endpoint)
	}
	if strings.Contains(event.Endpoint, "PLACEHOLDER") {
		t.Fatalf("raw secret leaked into endpoint: %q", event.Endpoint)
	}
	if event.UserAgent != "zebra-browser/1.0" {
		t.Fatalf("benign user agent must ride the envelope: %q", event.UserAgent)
	}
	if event.DecoratorType != "authentication" || event.RuleType != "" {
		t.Fatalf("decorator classification drifted: %+v", event)
	}
	if event.Metadata["traceparent"] != "00-trace-span-01" {
		t.Fatalf("traceparent must forward into metadata: %+v", event.Metadata)
	}
	// The reference keeps the kwargs in metadata AND promotes them to the
	// envelope columns (_build_event: metadata verbatim).
	if event.Metadata["decorator_type"] != "authentication" {
		t.Fatal("decorator_type must stay in metadata beside the column")
	}
	if event.Timestamp.IsZero() {
		t.Fatal("envelope must carry a timestamp")
	}
}

func TestSecurityEventBusHandlerDirectBypassesGate(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.AgentEnableEvents = false
	})
	if err != nil {
		t.Fatal(err)
	}
	agent := &recordingAgent{}
	bus := NewSecurityEventBus(agent, cfg, nil, EventFilter{})
	bus.SendHandlerEvent(EventIPBanned, IPBanHandlerName, "203.0.113.9", "banned", "test", map[string]any{"duration": 60})
	if len(agent.events) != 1 {
		t.Fatal("handler-direct emitters bypass the agent_enable_events gate")
	}
	if agent.events[0].HandlerName != IPBanHandlerName {
		t.Fatalf("handler name drifted: %+v", agent.events[0])
	}
}

func TestSecurityEventBusSendFailureNeverPanics(t *testing.T) {
	cfg, _ := NewSecurityConfig(nil)
	agent := &recordingAgent{eventErr: errors.New("transport down")}
	bus := NewSecurityEventBus(agent, cfg, nil, EventFilter{})
	req := NewRequestFactory().CreateRequest(RequestOptions{Path: "/x", Method: "GET"})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("send failures must be logged, never raised: %v", r)
		}
	}()
	bus.SendMiddlewareEvent(EventIPBlocked, req, "request_blocked", "r", nil)
	bus.SendHandlerEvent(EventIPBanned, IPBanHandlerName, "1.2.3.4", "banned", "r", nil)
}

func TestSendHTTPSViolationEventRouteVsGlobal(t *testing.T) {
	cfg, _ := NewSecurityConfig(nil)
	agent := &recordingAgent{}
	bus := NewSecurityEventBus(agent, cfg, nil, EventFilter{})
	req := NewRequestFactory().CreateRequest(RequestOptions{Path: "/a", Method: "GET", Scheme: "http", Host: "api.internal"})

	bus.SendHTTPSViolationEvent(req, &RouteConfig{RequireHTTPS: true})
	if agent.events[0].EventType != EventDecoratorViolation {
		t.Fatalf("route-level https must report decorator_violation, got %q", agent.events[0].EventType)
	}
	if agent.events[0].ActionTaken != "https_redirect" {
		t.Fatalf("action drifted: %q", agent.events[0].ActionTaken)
	}
	if agent.events[0].Metadata["violation_type"] != "require_https" ||
		agent.events[0].Metadata["original_scheme"] != "http" {
		t.Fatalf("route https metadata drifted: %+v", agent.events[0].Metadata)
	}
	if !strings.Contains(agent.events[0].Metadata["redirect_url"].(string), "https://") {
		t.Fatalf("redirect_url must be the https-swapped URL: %+v", agent.events[0].Metadata)
	}

	agent.events = nil
	bus.SendHTTPSViolationEvent(req, nil)
	if agent.events[0].EventType != EventHTTPSEnforced {
		t.Fatalf("global enforcement must report https_enforced, got %q", agent.events[0].EventType)
	}
}

func TestMetricsCollectorRequestMetrics(t *testing.T) {
	cfg, _ := NewSecurityConfig(nil)
	agent := &recordingAgent{}
	collector := NewMetricsCollector(agent, cfg, EventFilter{})
	req := NewRequestFactory().CreateRequest(RequestOptions{Path: "/api", Method: "GET"})
	collector.CollectRequestMetrics(req, 0.125, 403)
	if len(agent.metrics) != 3 {
		t.Fatalf("expected response_time, request_count, error_rate, got %d metrics", len(agent.metrics))
	}
	if agent.metrics[0].MetricType != MetricResponseTime || agent.metrics[0].Value != 0.125 {
		t.Fatalf("response_time metric drifted: %+v", agent.metrics[0])
	}
	if agent.metrics[0].Tags["status"] != "403" || agent.metrics[0].Tags["endpoint"] != "/api" || agent.metrics[0].Tags["method"] != "GET" {
		t.Fatalf("response_time tags drifted: %+v", agent.metrics[0].Tags)
	}
	if agent.metrics[1].MetricType != MetricRequestCount || agent.metrics[1].Value != 1.0 {
		t.Fatalf("request_count metric drifted: %+v", agent.metrics[1])
	}
	if _, hasStatus := agent.metrics[1].Tags["status"]; hasStatus {
		t.Fatal("request_count carries no status tag in the reference")
	}
	if agent.metrics[2].MetricType != MetricErrorRate || agent.metrics[2].Value != 1.0 {
		t.Fatalf("error_rate metric drifted: %+v", agent.metrics[2])
	}

	agent.metrics = nil
	collector.CollectRequestMetrics(req, 0.01, 200)
	if len(agent.metrics) != 2 {
		t.Fatalf("a 2xx must not emit error_rate, got %d metrics", len(agent.metrics))
	}

	// Metrics gate.
	cfgOff, _ := NewSecurityConfig(func(c *SecurityConfig) { c.AgentEnableMetrics = false })
	agentOff := &recordingAgent{}
	NewMetricsCollector(agentOff, cfgOff, EventFilter{}).SendMetric(MetricResponseTime, 1, nil)
	if len(agentOff.metrics) != 0 {
		t.Fatal("agent_enable_metrics=false must gate the collector")
	}
	// Nil tags default to the empty map, not a panic.
	NewMetricsCollector(agent, cfg, EventFilter{}).SendMetric(MetricRequestCount, 1, nil)
	if len(agent.metrics) != 3 {
		t.Fatal("nil tags must not break SendMetric")
	}
}
