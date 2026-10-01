package guardcore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type errTransport struct{}

func (errTransport) Error() string { return "transport down" }

// TestSecurityEventBusCountryLookup drives the envelope's country column
// through a resolver.
func TestSecurityEventBusCountryLookup(t *testing.T) {
	cfg, _ := NewSecurityConfig(nil)
	agent := &recordingAgent{}
	bus := NewSecurityEventBus(agent, cfg, fakeCountryResolver{"203.0.113.66": "DE"}, EventFilter{})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/geo",
		Method:     "GET",
		ClientHost: "203.0.113.66",
	})
	bus.SendMiddlewareEvent(EventIPBlocked, req, "request_blocked", "r", nil)
	if len(agent.events) != 1 {
		t.Fatal("event must deliver")
	}
	if agent.events[0].Country != "DE" {
		t.Fatalf("country lookup drifted: %q", agent.events[0].Country)
	}
	// A resolver miss leaves the column empty and still delivers.
	reqMiss := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/geo",
		Method:     "GET",
		ClientHost: "203.0.113.67",
	})
	bus.SendMiddlewareEvent(EventIPBlocked, reqMiss, "request_blocked", "r", nil)
	if agent.events[1].Country != "" {
		t.Fatalf("resolver miss must leave the country empty: %q", agent.events[1].Country)
	}
	// Unknown client identity rides the envelope when no IP resolves.
	reqAnon := NewRequestFactory().CreateRequest(RequestOptions{Path: "/geo", Method: "GET"})
	bus.SendMiddlewareEvent(EventIPBlocked, reqAnon, "request_blocked", "r", nil)
	if agent.events[2].IPAddress != UnknownClientIdentity {
		t.Fatalf("anonymous client identity drifted: %q", agent.events[2].IPAddress)
	}
}

// TestSecurityEventBusHandlerEventBypassesMuteFilter pins that
// handler-direct emitters never consult the event filter: the reference
// handlers (_ipban_events.py, ratelimit_handler.py, _dynamic_rule_events.py,
// cloud_handler.py, ipinfo_handler.py) send unconditionally, so a muted
// ip_banned still reaches the agent.
func TestSecurityEventBusHandlerEventBypassesMuteFilter(t *testing.T) {
	cfg, _ := NewSecurityConfig(nil)
	agent := &recordingAgent{}
	bus := NewSecurityEventBus(agent, cfg, nil, EventFilter{MutedEventTypes: nameSet([]string{EventIPBanned})})
	bus.SendHandlerEvent(EventIPBanned, IPBanHandlerName, "1.2.3.4", "banned", "muted-but-delivered", nil)
	if len(agent.events) != 1 {
		t.Fatal("handler-direct events must bypass the mute filter (the reference handlers never consult it)")
	}
	if agent.events[0].EventType != EventIPBanned || agent.events[0].Reason != "muted-but-delivered" {
		t.Fatalf("the muted handler event must deliver whole: %+v", agent.events[0])
	}
	// A nil bus and a handler-less bus are no-ops.
	var nilBus *SecurityEventBus
	nilBus.SendHandlerEvent(EventIPBanned, IPBanHandlerName, "1.2.3.4", "banned", "r", nil)
	NewSecurityEventBus(nil, cfg, nil, EventFilter{}).SendHandlerEvent(EventIPBanned, IPBanHandlerName, "1", "banned", "r", nil)
}

// TestMetricsCollectorSendFailuresAndGates covers the collector's gate
// columns and its logged send failure.
func TestMetricsCollectorSendFailuresAndGates(t *testing.T) {
	cfg, _ := NewSecurityConfig(nil)
	failing := &recordingAgent{metricErr: errTransport{}}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("metric send failures must be logged, never raised: %v", r)
		}
	}()
	NewMetricsCollector(failing, cfg, EventFilter{}).SendMetric(MetricResponseTime, 1, nil)

	// Gate columns: no handler, disabled flag, muted type.
	NewMetricsCollector(nil, cfg, EventFilter{}).SendMetric(MetricResponseTime, 1, nil)
	cfgOff, _ := NewSecurityConfig(func(c *SecurityConfig) { c.AgentEnableMetrics = false })
	NewMetricsCollector(&recordingAgent{}, cfgOff, EventFilter{}).SendMetric(MetricResponseTime, 1, nil)
	agent := &recordingAgent{}
	NewMetricsCollector(agent, cfg, EventFilter{MutedMetricTypes: nameSet([]string{MetricResponseTime})}).SendMetric(MetricResponseTime, 1, nil)
	if len(agent.metrics) != 0 {
		t.Fatal("muted metrics must not reach the agent")
	}
	var nilCollector *MetricsCollector
	nilCollector.SendMetric(MetricResponseTime, 1, nil)
	nilCollector.CollectRequestMetrics(nil, 0, 200)
}

// TestAgentPipelineForNil pins the nil-config safety of the seam lookup.
func TestAgentPipelineForNil(t *testing.T) {
	if agentPipelineFor(nil) != nil {
		t.Fatal("a nil config has no agent pipeline")
	}
	cfg := &SecurityConfig{}
	if agentPipelineFor(cfg) != nil {
		t.Fatal("an uninstalled config has no agent pipeline")
	}
}

// TestSplitURLQueryAndUnescape covers the endpoint-redaction query
// splitter, including malformed escapes.
func TestSplitURLQueryAndUnescape(t *testing.T) {
	if _, ok := splitURLQuery("/no-query"); ok {
		t.Fatal("a path without a query must report absent")
	}
	parts, ok := splitURLQuery("/p?password=PLACEHOLDER&flag&next=%2Fhome&bad=%zz")
	if !ok {
		t.Fatal("a query-bearing path must parse")
	}
	if parts.path != "/p" {
		t.Fatalf("path drifted: %q", parts.path)
	}
	if parts.query["password"] != "PLACEHOLDER" || parts.query["flag"] != "" {
		t.Fatalf("query pairs drifted: %+v", parts.query)
	}
	// Keys decode for sensitive-name matching; values stay raw (the
	// sensitive-key redaction in redactURLForDisplay does the rest).
	if parts.query["next"] != "%2Fhome" {
		t.Fatalf("values stay raw in the query split: %q", parts.query["next"])
	}
	if parts.query["bad"] != "%zz" {
		t.Fatalf("malformed escapes must pass through: %q", parts.query["bad"])
	}
	if urlQueryUnescape("plain") != "plain" {
		t.Fatal("plain keys ride through")
	}
}

// TestPipelineResponseTimeUnstamped covers the unstamped-request branch.
func TestPipelineResponseTimeUnstamped(t *testing.T) {
	req := NewRequestFactory().CreateRequest(RequestOptions{Path: "/x", Method: "GET"})
	if got := pipelineResponseTime(req); got != 0 {
		t.Fatalf("unstamped request must report 0, got %v", got)
	}
}

// ---- dynamic rules: the remaining observable paths ----

func TestDynamicRuleCountryRulesSkipWithoutResolver(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.GeoIPHandler = nil })
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
		t.Fatal(err)
	}
	if len(cfg.BlockedCountries) != 0 {
		t.Fatalf("country rules must warn and skip without a resolver, got %v", cfg.BlockedCountries)
	}
}

func TestDynamicRuleUserAgentPatternValidation(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	rules := sampleRules()
	rules.BlockedUserAgents = []string{"goodbot[0-9]+", "[invalid"}
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	if len(cfg.BlockedUserAgents) != 1 || cfg.BlockedUserAgents[0] != "goodbot[0-9]+" {
		t.Fatalf("the failing pattern must be rejected with a warning: %v", cfg.BlockedUserAgents)
	}
}

func TestDynamicRuleSuspiciousPatternsLoggedAndSkipped(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	rules := sampleRules()
	rules.SuspiciousPatterns = []string{"union.*select"}
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	if manager.CurrentRules() == nil {
		t.Fatal("the rule still applies; suspicious patterns are a documented no-op in this port")
	}
}

func TestDynamicRuleWithoutBanManager(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	// No ban manager: IP rules log and continue, the rule applies.
	manager := NewDynamicRuleManager(cfg, nil, nil, nil)
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
		t.Fatal(err)
	}
	if manager.CurrentRules() == nil {
		t.Fatal("missing ban manager must not abort the application")
	}
}

func TestDynamicRuleUpdateRulesGuards(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	// Disabled config: the loop body is a no-op.
	cfgOff, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.EnableDynamicRules = false })
	managerOff := NewDynamicRuleManager(cfgOff, nil, NewIPBanManager(nil, nil), nil)
	if err := managerOff.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
		t.Fatal(err)
	}
	if managerOff.CurrentRules() != nil {
		t.Fatal("a disabled config must not apply rules")
	}
	// A nil delivery is a no-op.
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if manager.CurrentRules() != nil {
		t.Fatal("an empty delivery must be a no-op")
	}
	// Fetch errors propagate.
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return nil, errTransport{} }); err == nil {
		t.Fatal("fetch errors must propagate")
	}
}

func TestDynamicRuleHasExpiredNil(t *testing.T) {
	manager := NewDynamicRuleManager(&SecurityConfig{}, nil, nil, nil)
	if manager.hasExpired(nil) {
		t.Fatal("nil rules never expire")
	}
	rules := &DynamicRules{}
	if manager.hasExpired(rules) {
		t.Fatal("rules without expires_at never expire")
	}
}

func TestDynamicRuleRedisUnavailablePersistence(t *testing.T) {
	// Redis configured but down: persistence failures are loud, not fatal,
	// and the rule still applies.
	path := filepath.Join(t.TempDir(), "rules.json")
	cfg, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.DynamicRulesCachePath = path })
	downRedis := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1/0", EnableRedis: true})
	manager := NewDynamicRuleManager(cfg, downRedis, NewIPBanManager(nil, nil), nil)
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
		t.Fatalf("a down Redis must not fail the application: %v", err)
	}
	if manager.CurrentRules() == nil {
		t.Fatal("the rule must still apply")
	}
	// The file fallback still persisted.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the cache-file fallback must persist: %v", err)
	}
	// Hydration: the down Redis read logs and the file snapshot applies.
	cfg2, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.DynamicRulesCachePath = path })
	manager2 := NewDynamicRuleManager(cfg2, downRedis, NewIPBanManager(nil, nil), nil)
	manager2.HydrateLastKnownRules()
	if manager2.CurrentRules() == nil {
		t.Fatal("hydration must fall through to the file when Redis is down")
	}
}

func TestDynamicRuleExpiredFileSnapshotSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expired.json")
	expired := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	payload := `{"schema_version":1,"rules":{"rule_id":"old","version":1,"timestamp":"2026-01-01T00:00:00Z","expires_at":"` + expired + `"}}`
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.DynamicRulesCachePath = path })
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	manager.HydrateLastKnownRules()
	if manager.CurrentRules() != nil {
		t.Fatal("an expired file snapshot must be skipped")
	}
}

func TestWriteAtomicFileFailures(t *testing.T) {
	if err := writeAtomicFile(filepath.Join(t.TempDir(), "no", "such", "dir", "rules.json"), "{}"); err == nil {
		t.Fatal("a missing target directory must error")
	}
	// An unwritable directory fails the temp-file creation.
	unwritable := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(unwritable, 0o444); err != nil {
		t.Skipf("cannot create a read-only directory: %v", err)
	}
	if err := writeAtomicFile(filepath.Join(unwritable, "rules.json"), "{}"); err == nil {
		t.Fatal("an unwritable directory must error")
	}
}

func TestDynamicRuleEventTypeGates(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	rules := sampleRules()
	rules.BlockedUserAgents = nil
	rules.BlockedCloudProviders = nil
	rules.GlobalRateLimit = nil
	rules.EndpointRateLimits = nil
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []string{EventRateLimited, EventCloudBlocked, EventUserAgentBlocked} {
		if _, _, ok := manager.MatchEvent(SecurityEvent{EventType: eventType}); ok {
			t.Fatalf("%s must not match without the corresponding rules", eventType)
		}
	}
}

func TestDynamicRulesVocabularyHelper(t *testing.T) {
	if dynamicRulesContains([]string{"a"}, "b") {
		t.Fatal("membership must be exact")
	}
	if !dynamicRulesContains([]string{"a"}, "a") {
		t.Fatal("membership must be exact")
	}
}

// TestRedactedEndpointInRateLimitEvent pins that the rate_limited
// handler event redacts sensitive query params in its endpoint metadata.
func TestRedactedEndpointInRateLimitEvent(t *testing.T) {
	cfg, _ := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.AgentHandler = &recordingAgent{}
		c.LogSensitiveParams = map[string]bool{"token": true}
	})
	cfg.installAgentStream()
	rules := &RateLimitOutcome{Blocked: true, Count: 5, Window: 60, Tier: "global"}
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:     "/limits?token=PLACEHOLDER",
		Method:   "GET",
		RawQuery: "token=PLACEHOLDER",
	})
	emitRateLimitedHandlerEvent(cfg, req, "203.0.113.99", rules)
	agent := cfg.AgentHandler.(*recordingAgent)
	if len(agent.events) != 1 {
		t.Fatal("rate_limited must reach the agent")
	}
	endpoint, _ := agent.events[0].Metadata["endpoint"].(string)
	if strings.Contains(endpoint, "PLACEHOLDER") {
		t.Fatalf("the endpoint metadata must redact sensitive params: %q", endpoint)
	}
}

// TestClassifyHeaderViolation pins the reference header classification.
func TestClassifyHeaderViolation(t *testing.T) {
	tests := []struct {
		header        string
		decoratorType string
		violationType string
	}{
		{"x-api-key", "authentication", "api_key_required"},
		{"authorization", "authentication", "required_header"},
		{"x-custom", "advanced", "required_header"},
	}
	for _, tt := range tests {
		gotDecorator, gotViolation := classifyHeaderViolation(tt.header)
		if gotDecorator != tt.decoratorType || gotViolation != tt.violationType {
			t.Errorf("classifyHeaderViolation(%q) = (%q, %q), want (%q, %q)",
				tt.header, gotDecorator, gotViolation, tt.decoratorType, tt.violationType)
		}
	}
}

// TestEmitGeoEventToBusDefaults covers the metadata merge and the handler
// name fallback.
func TestEmitGeoEventToBusDefaults(t *testing.T) {
	cfg, _ := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.AgentHandler = &recordingAgent{}
	})
	cfg.installAgentStream()
	// A GeoEvent without a handler name or metadata: the ipinfo default
	// applies and the envelope stays minimal.
	emitGeoEventToBus(cfg, GeoEvent{EventType: EventGeoLookupFailed, IPAddress: "1.2.3.4"})
	agent := cfg.AgentHandler.(*recordingAgent)
	if len(agent.events) != 1 || agent.events[0].HandlerName != IPInfoHandlerName {
		t.Fatalf("the ipinfo fallback drifted: %+v", agent.events)
	}
	if _, hasCountry := agent.events[0].Metadata["country"]; hasCountry {
		t.Fatal("no country field on the event, none in the metadata")
	}
	// Metadata merges and the country/rule_type columns ride along.
	emitGeoEventToBus(cfg, GeoEvent{
		EventType:   EventCountryBlocked,
		IPAddress:   "1.2.3.4",
		Country:     "CN",
		RuleType:    "country_blacklist",
		HandlerName: CloudHandlerName,
		Metadata:    map[string]any{"providers": []string{"AWS"}},
	})
	second := agent.events[1]
	if second.HandlerName != CloudHandlerName {
		t.Fatalf("explicit handler names must ride: %+v", second)
	}
	if second.Metadata["providers"] == nil || second.Metadata["country"] != "CN" || second.Metadata["rule_type"] != "country_blacklist" {
		t.Fatalf("merged metadata drifted: %+v", second.Metadata)
	}
}

// TestForwardTraceHeadersPreexisting pins the not-already-set rule: a
// caller-provided traceparent wins over the request header.
func TestForwardTraceHeadersPreexisting(t *testing.T) {
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:   "/x",
		Method: "GET",
		Header: map[string]string{"Traceparent": "00-from-request", "Tracestate": "vendor=1"},
	})
	metadata := map[string]any{"traceparent": "00-caller-supplied"}
	got := forwardTraceHeaders(req, metadata)
	if got["traceparent"] != "00-caller-supplied" {
		t.Fatalf("a pre-existing traceparent must win: %+v", got)
	}
	if got["tracestate"] != "vendor=1" {
		t.Fatalf("tracestate must forward: %+v", got)
	}
}

// TestSplitURLQueryDecodesKeys covers the percent-decoding of query keys
// (the sensitive-name matching surface) across the hex digit classes.
func TestSplitURLQueryDecodesKeys(t *testing.T) {
	parts, ok := splitURLQuery("/p?na%6De%2Fx=%zz&&x=1")
	if !ok {
		t.Fatal("query must parse")
	}
	// %6D = 'm' (digit + uppercase hex), %2F = '/' (digit + uppercase).
	if _, present := parts.query["name/x"]; !present {
		t.Fatalf("the decoded key must match: %+v", parts.query)
	}
	// Lowercase hex digits decode too, malformed escapes ride through,
	// and empty pairs are skipped.
	if urlQueryUnescape("k%7a") != "kz" {
		t.Fatalf("lowercase hex must decode: %q", urlQueryUnescape("k%7a"))
	}
	if urlQueryUnescape("a%gg b") != "a%gg b" {
		t.Fatalf("malformed escapes must ride through: %q", urlQueryUnescape("a%gg b"))
	}
	if urlQueryUnescape("cut%") != "cut%" {
		t.Fatal("a truncated escape rides through")
	}
}
