package guardcore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Enrichment-layer tests, mirroring the reference suite:
// tests/test_enricher.py, test_enricher_identity.py,
// test_enricher_threat_score.py, test_enricher_behavior_correlation.py,
// test_enricher_rule_correlation.py and test_enricher_end_to_end.py.

func TestThreatScoreForTiers(t *testing.T) {
	cases := []struct {
		eventType string
		want      int
	}{
		{EventPenetrationAttempt, 90},
		{EventIPBanned, 70},
		{EventEmergencyMode, 60},
		{EventIPBlocked, 50},
		{EventBehaviorViolation, 50},
		{EventCloudBlocked, 50},
		{EventCountryBlocked, 50},
		{EventDecoratorViolation, 50},
		{EventAuthenticationFailed, 50},
		{EventEmergencyModeBlock, 50},
		{EventDynamicRuleViolation, 50},
		{EventPatternDetected, 50},
		{EventSuspiciousRequest, 50},
		{EventDynamicRuleApplied, 40},
		{EventCSPViolation, 40},
		{EventContentFiltered, 40},
		{EventCustomRequestCheck, 40},
		{EventDecodingError, 40},
		{EventRedisError, 40},
		{EventIPBanFailed, 40},
		{EventDetectionEngineCallbackError, 40},
		{EventPatternAnomalyTimeout, 40},
		{EventPatternAnomalySlowExecution, 40},
		{EventPatternAnomalyStatisticalAnomaly, 40},
		{EventAccessDenied, 30},
		{EventUserAgentBlocked, 30},
		{EventSecurityBypass, 30},
		{EventRateLimited, 20},
		{EventGeoLookupFailed, 20},
		{EventRedisConnection, 20},
		{EventRouteUnresolved, 20},
		{EventIPUnbanned, 10},
		{EventHTTPSEnforced, 10},
		{EventDynamicRuleUpdated, 10},
		{EventPathExcluded, 10},
		{EventPatternAdded, 10},
		{EventPatternRemoved, 10},
		{EventRateLimitScriptReloaded, 10},
		{EventSecurityHeadersApplied, 10},
	}
	for _, tc := range cases {
		if got := ThreatScoreFor(tc.eventType); got != tc.want {
			t.Errorf("ThreatScoreFor(%q) = %d, want %d", tc.eventType, got, tc.want)
		}
	}
	if got := ThreatScoreFor("completely_novel_event"); got != DefaultThreatScore {
		t.Errorf("unknown event type must score the default: got %d", got)
	}
}

func enrichTestConfig(projectID string, attrs map[string]string) *SecurityConfig {
	return &SecurityConfig{
		AgentProjectID:         projectID,
		OtelServiceName:        "svc-1",
		OtelResourceAttributes: attrs,
	}
}

func TestEnrichEventIdentityMirrorsReference(t *testing.T) {
	enricher := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("proj-123", nil)})
	event := SecurityEvent{EventType: EventIPBlocked, Metadata: map[string]any{}}
	enricher.EnrichEvent(&event)

	if event.Metadata[EnrichmentKeyProjectID] != "proj-123" {
		t.Fatalf("project id must ride: %+v", event.Metadata)
	}
	if event.Metadata[EnrichmentKeyServiceName] != "svc-1" {
		t.Fatalf("service name must always ride: %+v", event.Metadata)
	}
	if _, ok := event.Metadata[EnrichmentKeyDeploymentEnv]; ok {
		t.Fatalf("deployment env must be absent when the attribute is unset: %+v", event.Metadata)
	}
}

func TestEnrichEventIdentityAddsDeploymentEnv(t *testing.T) {
	enricher := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("proj-9", map[string]string{
		"deployment.environment": "prod",
		"service.version":        "1.2.3",
	})})
	event := SecurityEvent{EventType: EventIPBlocked, Metadata: map[string]any{}}
	enricher.EnrichEvent(&event)

	if event.Metadata[EnrichmentKeyDeploymentEnv] != "prod" {
		t.Fatalf("deployment env must ride when set: %+v", event.Metadata)
	}
}

func TestEnrichEventIdentityOmitsProjectIDWhenUnset(t *testing.T) {
	enricher := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("", nil)})
	event := SecurityEvent{EventType: EventIPBlocked, Metadata: map[string]any{}}
	enricher.EnrichEvent(&event)

	if _, ok := event.Metadata[EnrichmentKeyProjectID]; ok {
		t.Fatalf("unset project id must not ride: %+v", event.Metadata)
	}
}

func TestEnrichEventThreatScore(t *testing.T) {
	enricher := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("", nil)})

	event := SecurityEvent{EventType: EventPenetrationAttempt, Metadata: map[string]any{}}
	enricher.EnrichEvent(&event)
	if event.Metadata[EnrichmentKeyThreatScore] != 90 {
		t.Fatalf("penetration_attempt must score 90: %+v", event.Metadata)
	}

	unknown := SecurityEvent{EventType: "unknown_type_here", Metadata: map[string]any{}}
	enricher.EnrichEvent(&unknown)
	if unknown.Metadata[EnrichmentKeyThreatScore] != DefaultThreatScore {
		t.Fatalf("unknown types must score the default: %+v", unknown.Metadata)
	}

	typeless := SecurityEvent{Metadata: map[string]any{}}
	enricher.EnrichEvent(&typeless)
	if _, ok := typeless.Metadata[EnrichmentKeyThreatScore]; ok {
		t.Fatalf("typeless events must not carry a threat score: %+v", typeless.Metadata)
	}
}

// stubRuleMatcher is the DynamicRuleMatcher stand-in for enricher unit tests
// (the real manager's MatchEvent has its own suite).
type stubRuleMatcher struct {
	ruleID  string
	version int
	ok      bool
}

func (s stubRuleMatcher) MatchEvent(SecurityEvent) (string, int, bool) {
	return s.ruleID, s.version, s.ok
}

func TestEnrichEventRuleCorrelation(t *testing.T) {
	enricher := NewEventEnricher(EnrichmentContext{
		Config:             enrichTestConfig("", nil),
		DynamicRuleHandler: stubRuleMatcher{ruleID: "rule-42", version: 3, ok: true},
	})
	event := SecurityEvent{EventType: EventIPBlocked, Metadata: map[string]any{}}
	enricher.EnrichEvent(&event)
	if event.Metadata[EnrichmentKeyRuleID] != "rule-42" || event.Metadata[EnrichmentKeyRuleVersion] != 3 {
		t.Fatalf("rule correlation keys must ride: %+v", event.Metadata)
	}

	noHandler := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("", nil)})
	bare := SecurityEvent{EventType: EventIPBlocked, Metadata: map[string]any{}}
	noHandler.EnrichEvent(&bare)
	if _, ok := bare.Metadata[EnrichmentKeyRuleID]; ok {
		t.Fatalf("no handler: rule keys must not ride: %+v", bare.Metadata)
	}

	noMatch := NewEventEnricher(EnrichmentContext{
		Config:             enrichTestConfig("", nil),
		DynamicRuleHandler: stubRuleMatcher{ok: false},
	})
	unmatched := SecurityEvent{EventType: EventIPBlocked, Metadata: map[string]any{}}
	noMatch.EnrichEvent(&unmatched)
	if _, ok := unmatched.Metadata[EnrichmentKeyRuleID]; ok {
		t.Fatalf("no match: rule keys must not ride: %+v", unmatched.Metadata)
	}
}

func seedTracker(t *testing.T, ip string, count int, offsets []float64) *BehaviorTracker {
	t.Helper()
	tracker := NewBehaviorTracker(nil, nil, nil, nil)
	now := float64(time.Now().UnixNano()) / float64(time.Second)
	for i := 0; i < count; i++ {
		endpoint := fmt.Sprintf("endpoint-%d", i%2)
		row := tracker.usageCounts[endpoint]
		if row == nil {
			row = map[string][]float64{}
			tracker.usageCounts[endpoint] = row
		}
		row[ip] = append(row[ip], now+offsets[i])
	}
	return tracker
}

func TestGetRecentEventCountMirrorsReference(t *testing.T) {
	empty := NewBehaviorTracker(nil, nil, nil, nil)
	if got := empty.GetRecentEventCount("1.2.3.4", 300); got != 0 {
		t.Fatalf("empty tracker must count 0: %d", got)
	}
	if got := empty.GetRecentEventCount("", 300); got != 0 {
		t.Fatalf("empty ip must count 0: %d", got)
	}

	summing := seedTracker(t, "1.2.3.4", 3, []float64{-10, -20, -30})
	if got := summing.GetRecentEventCount("1.2.3.4", 300); got != 3 {
		t.Fatalf("counts must sum across endpoints: %d", got)
	}

	windowed := seedTracker(t, "1.2.3.4", 3, []float64{-10, -600, -700})
	if got := windowed.GetRecentEventCount("1.2.3.4", 300); got != 1 {
		t.Fatalf("timestamps outside the window must be excluded: %d", got)
	}
}

func TestEnrichEventBehaviorCorrelation(t *testing.T) {
	tracker := seedTracker(t, "1.2.3.4", 2, []float64{-10, -20})
	enricher := NewEventEnricher(EnrichmentContext{
		Config:          enrichTestConfig("", nil),
		BehaviorTracker: tracker,
	})
	// The key is sha256(f"{ip}|{service}|{bucket}")[:16] with the bucket
	// derived from the injectable clock; pin the clock before enriching.
	pinned := time.Unix(1700000000, 0)
	enricher.now = func() time.Time { return pinned }
	event := SecurityEvent{EventType: EventPenetrationAttempt, IPAddress: "1.2.3.4", Metadata: map[string]any{}}
	enricher.EnrichEvent(&event)

	if event.Metadata[EnrichmentKeyRecentEventCount] != 2 {
		t.Fatalf("recent event count must ride: %+v", event.Metadata)
	}
	key, ok := event.Metadata[EnrichmentKeyBehaviorKey].(string)
	if !ok || len(key) != 16 {
		t.Fatalf("correlation key must be a 16-char string: %+v", event.Metadata)
	}
	bucket := pinned.Unix() / behaviorCorrelationWindowSeconds
	sum := sha256.Sum256([]byte(fmt.Sprintf("1.2.3.4|svc-1|%d", bucket)))
	want := hex.EncodeToString(sum[:])[:16]
	if key != want {
		t.Fatalf("correlation key drifted: got %q want %q", key, want)
	}
}

func TestEnrichEventBehaviorCorrelationDeterminism(t *testing.T) {
	tracker := seedTracker(t, "1.2.3.4", 1, []float64{-5})
	enricher := NewEventEnricher(EnrichmentContext{
		Config:          enrichTestConfig("", nil),
		BehaviorTracker: tracker,
	})
	enricher.now = func() time.Time { return time.Unix(1700000000, 0) }

	first := SecurityEvent{EventType: EventIPBlocked, IPAddress: "1.2.3.4", Metadata: map[string]any{}}
	second := SecurityEvent{EventType: EventRateLimited, IPAddress: "1.2.3.4", Metadata: map[string]any{}}
	enricher.EnrichEvent(&first)
	enricher.EnrichEvent(&second)
	if first.Metadata[EnrichmentKeyBehaviorKey] != second.Metadata[EnrichmentKeyBehaviorKey] {
		t.Fatalf("same ip in the same window must share the key: %+v vs %+v",
			first.Metadata, second.Metadata)
	}

	otherIP := NewEventEnricher(EnrichmentContext{
		Config:          enrichTestConfig("", nil),
		BehaviorTracker: NewBehaviorTracker(nil, nil, nil, nil),
	})
	otherIP.now = enricher.now
	a := SecurityEvent{EventType: EventIPBlocked, IPAddress: "1.1.1.1", Metadata: map[string]any{}}
	b := SecurityEvent{EventType: EventIPBlocked, IPAddress: "2.2.2.2", Metadata: map[string]any{}}
	otherIP.EnrichEvent(&a)
	otherIP.EnrichEvent(&b)
	if a.Metadata[EnrichmentKeyBehaviorKey] == b.Metadata[EnrichmentKeyBehaviorKey] {
		t.Fatalf("different ips must not share the key")
	}
}

func TestEnrichEventSkipsBehaviorFields(t *testing.T) {
	// No tracker: neither behavior key rides.
	noTracker := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("", nil)})
	event := SecurityEvent{EventType: EventIPBlocked, IPAddress: "1.2.3.4", Metadata: map[string]any{}}
	noTracker.EnrichEvent(&event)
	if _, ok := event.Metadata[EnrichmentKeyBehaviorKey]; ok {
		t.Fatalf("no tracker: correlation key must not ride")
	}
	if _, ok := event.Metadata[EnrichmentKeyRecentEventCount]; ok {
		t.Fatalf("no tracker: count must not ride")
	}

	// Tracker present but empty ip: skipped too.
	tracker := NewBehaviorTracker(nil, nil, nil, nil)
	noIP := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("", nil), BehaviorTracker: tracker})
	ipless := SecurityEvent{EventType: EventIPBlocked, Metadata: map[string]any{}}
	noIP.EnrichEvent(&ipless)
	if _, ok := ipless.Metadata[EnrichmentKeyBehaviorKey]; ok {
		t.Fatalf("empty ip: correlation key must not ride")
	}
}

// TestEnrichEventNilSafety mirrors test_enricher.py: a nil event, a nil
// metadata map and a nil config all ship untouched without panicking.
func TestEnrichEventNilSafety(t *testing.T) {
	enricher := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("", nil)})

	var nilEvent *SecurityEvent
	enricher.EnrichEvent(nilEvent)

	metadataless := SecurityEvent{EventType: EventIPBlocked}
	enricher.EnrichEvent(&metadataless)
	if metadataless.Metadata != nil {
		t.Fatalf("events without a metadata map must ship unenriched")
	}

	var nilEnricher *EventEnricher
	nilEnricher.EnrichEvent(&SecurityEvent{Metadata: map[string]any{}})
	nilEnricher.EnrichMetric(&SecurityMetric{Tags: map[string]string{}})
}

// TestEnrichEventNilConfigContext: an enricher built without a config (the
// zero EnrichmentContext) still enriches defensively with an empty identity.
func TestEnrichEventNilConfigContext(t *testing.T) {
	enricher := NewEventEnricher(EnrichmentContext{BehaviorTracker: NewBehaviorTracker(nil, nil, nil, nil)})
	enricher.now = func() time.Time { return time.Unix(1700000000, 0) }
	event := SecurityEvent{EventType: EventIPBlocked, IPAddress: "1.2.3.4", Metadata: map[string]any{}}
	enricher.EnrichEvent(&event)
	if event.Metadata[EnrichmentKeyServiceName] != "" {
		t.Fatalf("nil config degrades to an empty service name: %+v", event.Metadata)
	}
	if _, ok := event.Metadata[EnrichmentKeyBehaviorKey]; !ok {
		t.Fatalf("behavior correlation still rides without a config: %+v", event.Metadata)
	}
}

func TestEnrichMetricIdentity(t *testing.T) {
	enricher := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("proj-metric", map[string]string{
		"deployment.environment": "staging",
	})})
	metric := SecurityMetric{MetricType: MetricResponseTime, Tags: map[string]string{"endpoint": "/x"}}
	enricher.EnrichMetric(&metric)

	if metric.Tags["endpoint"] != "/x" {
		t.Fatalf("existing tags must survive: %+v", metric.Tags)
	}
	if metric.Tags[EnrichmentKeyProjectID] != "proj-metric" ||
		metric.Tags[EnrichmentKeyServiceName] != "svc-1" ||
		metric.Tags[EnrichmentKeyDeploymentEnv] != "staging" {
		t.Fatalf("identity keys must ride metric tags: %+v", metric.Tags)
	}

	// Nil tags and nil metric ship untouched.
	tagless := SecurityMetric{MetricType: MetricResponseTime}
	enricher.EnrichMetric(&tagless)
	if tagless.Tags != nil {
		t.Fatalf("metrics without tags must ship unenriched")
	}
	var nilMetric *SecurityMetric
	enricher.EnrichMetric(nilMetric)
}

// TestCompositeEnrichedEventsReachSinks mirrors test_enricher_end_to_end.py:
// the enriched fields land on every emitted event and metric.
func TestCompositeEnrichedEventsReachSinks(t *testing.T) {
	sink := newFakeSink("recorder")
	enricher := NewEventEnricher(EnrichmentContext{
		Config:             enrichTestConfig("proj-e2e", map[string]string{"deployment.environment": "prod"}),
		DynamicRuleHandler: stubRuleMatcher{ruleID: "rule-abc", version: 7, ok: true},
		BehaviorTracker:    seedTracker(t, "1.2.3.4", 1, []float64{-5}),
	})
	composite := NewCompositeAgentHandlerWithEnricher([]AgentHandler{sink}, &EventFilter{}, enricher)

	composite.SendEvent(SecurityEvent{
		EventType: EventIPBlocked,
		IPAddress: "1.2.3.4",
		Metadata:  map[string]any{},
	})
	if len(sink.events) != 1 {
		t.Fatalf("event must reach the sink: %d", len(sink.events))
	}
	meta := sink.events[0].Metadata
	for key, want := range map[string]any{
		EnrichmentKeyProjectID:        "proj-e2e",
		EnrichmentKeyServiceName:      "svc-1",
		EnrichmentKeyDeploymentEnv:    "prod",
		EnrichmentKeyThreatScore:      50,
		EnrichmentKeyRuleID:           "rule-abc",
		EnrichmentKeyRuleVersion:      7,
		EnrichmentKeyRecentEventCount: 1,
	} {
		if meta[key] != want {
			t.Fatalf("%s = %+v, want %+v", key, meta[key], want)
		}
	}
	if key, _ := meta[EnrichmentKeyBehaviorKey].(string); len(key) != 16 {
		t.Fatalf("behavior key must ride the emitted event: %+v", meta)
	}

	composite.SendMetric(SecurityMetric{MetricType: MetricResponseTime, Tags: map[string]string{"endpoint": "/api"}})
	if len(sink.metrics) != 1 {
		t.Fatalf("metric must reach the sink: %d", len(sink.metrics))
	}
	tags := sink.metrics[0].Tags
	if tags["endpoint"] != "/api" || tags[EnrichmentKeyProjectID] != "proj-e2e" ||
		tags[EnrichmentKeyServiceName] != "svc-1" || tags[EnrichmentKeyDeploymentEnv] != "prod" {
		t.Fatalf("metric identity keys must ride: %+v", tags)
	}
}

// TestCompositeMutedEventSkipsEnricher mirrors test_enricher_end_to_end's
// muted-event case: the filter gates before the enricher, so a muted event
// is neither enriched nor dispatched.
func TestCompositeMutedEventSkipsEnricher(t *testing.T) {
	sink := newFakeSink("recorder")
	enricher := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("proj", nil)})
	filter := &EventFilter{MutedEventTypes: map[string]bool{EventIPBlocked: true}}
	composite := NewCompositeAgentHandlerWithEnricher([]AgentHandler{sink}, filter, enricher)

	event := SecurityEvent{EventType: EventIPBlocked, IPAddress: "1.2.3.4"}
	composite.SendEvent(event)

	if len(sink.events) != 0 {
		t.Fatalf("muted event must not reach the sink")
	}
	if event.Metadata != nil {
		t.Fatalf("muted event must not be enriched in place: %+v", event.Metadata)
	}
}

// TestEnrichmentEngineWiring proves the installed stream enriches every
// emission path: bus events, handler-direct events and metrics all land on
// the agent handler with the guard.* keys.
func TestEnrichmentEngineWiring(t *testing.T) {
	agent := &recordingAgent{}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.EnableEnrichment = true
		c.AgentHandler = agent
		c.AgentProjectID = "proj-wiring"
		c.OtelResourceAttributes = map[string]string{"deployment.environment": "prod"}
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if engine.Config.agent == nil || engine.Config.agent.enricher == nil {
		t.Fatal("enrichment must install the enricher on the agent pipeline")
	}

	bus := busFor(cfg)
	bus.SendHandlerEvent(EventIPBlocked, IPBanHandlerName, "203.0.113.9", "banned", "threshold", nil)
	if len(agent.events) != 1 {
		t.Fatalf("handler-direct event must reach the agent: %d", len(agent.events))
	}
	meta := agent.events[0].Metadata
	if meta[EnrichmentKeyProjectID] != "proj-wiring" || meta[EnrichmentKeyServiceName] != DefaultOtelServiceName ||
		meta[EnrichmentKeyDeploymentEnv] != "prod" || meta[EnrichmentKeyThreatScore] != 50 {
		t.Fatalf("bus emission must be enriched: %+v", meta)
	}

	cfg.agent.metrics.SendMetric(MetricRequestCount, 1, map[string]string{"endpoint": "/x"})
	if len(agent.metrics) != 1 {
		t.Fatalf("metric must reach the agent")
	}
	if agent.metrics[0].Tags[EnrichmentKeyProjectID] != "proj-wiring" {
		t.Fatalf("metrics must be enriched through the stream: %+v", agent.metrics[0].Tags)
	}
}

// TestEnrichmentEngineWiringDynamicRules proves the live manager's rules
// feed the enricher's rule correlation (the reference singleton semantics).
func TestEnrichmentEngineWiringDynamicRules(t *testing.T) {
	agent := &recordingAgent{}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.EnableEnrichment = true
		c.EnableDynamicRules = true
		c.AgentHandler = agent
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if engine.DynamicRules == nil {
		t.Fatal("dynamic rules manager must exist")
	}
	if err := engine.DynamicRules.UpdateRules(func() (*DynamicRules, error) {
		return &DynamicRules{
			RuleID:        "rule-1",
			Version:       3,
			Timestamp:     time.Now().UTC(),
			TTL:           300,
			IPBlacklist:   []string{"203.0.113.50"},
			IPBanDuration: 900,
		}, nil
	}); err != nil {
		t.Fatal(err)
	}

	busFor(cfg).SendHandlerEvent(EventIPBlocked, IPBanHandlerName, "203.0.113.50", "banned", "blacklisted", nil)
	// The rule update itself emitted dynamic_rule_updated / applied events;
	// find the ip_blocked emission among them.
	var blocked *SecurityEvent
	for i := range agent.events {
		if agent.events[i].EventType == EventIPBlocked {
			blocked = &agent.events[i]
			break
		}
	}
	if blocked == nil {
		t.Fatalf("ip_blocked event must reach the agent: %+v", agent.events)
	}
	if blocked.Metadata[EnrichmentKeyRuleID] != "rule-1" || blocked.Metadata[EnrichmentKeyRuleVersion] != 3 {
		t.Fatalf("matched dynamic rule must ride the emitted event: %+v", blocked.Metadata)
	}
}

// TestEnrichmentDisabledKeepsStreamPlain: without EnableEnrichment the
// stream forwards events untouched (the reference build_enricher's None).
func TestEnrichmentDisabledKeepsStreamPlain(t *testing.T) {
	agent := &recordingAgent{}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.AgentHandler = agent
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if engine.Config.agent.enricher != nil {
		t.Fatal("no enrichment config: the stream must not carry an enricher")
	}
	busFor(cfg).SendHandlerEvent(EventIPBlocked, IPBanHandlerName, "203.0.113.9", "banned", "threshold", map[string]any{"k": "v"})
	if len(agent.events) != 1 {
		t.Fatalf("event must reach the agent: %d", len(agent.events))
	}
	if _, enriched := agent.events[0].Metadata[EnrichmentKeyProjectID]; enriched {
		t.Fatalf("disabled enrichment must leave events plain: %+v", agent.events[0].Metadata)
	}
}

func TestEnrichmentConfigValidation(t *testing.T) {
	_, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableEnrichment = true
	})
	if err == nil {
		t.Fatal("enable_enrichment without enable_agent must be rejected")
	}
	if want := "enable_enrichment requires enable_agent=true"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error must mirror the reference message: %v", err)
	}

	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.OtelServiceName = ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OtelServiceName != DefaultOtelServiceName {
		t.Fatalf("empty service name must default to %q: %q", DefaultOtelServiceName, cfg.OtelServiceName)
	}
}

// TestAttachDynamicRuleMatcherGuards covers the defensive arms of the
// pipeline seam: nil pipeline, enricher-less pipeline, nil matcher.
func TestAttachDynamicRuleMatcherGuards(t *testing.T) {
	var nilPipeline *agentPipeline
	nilPipeline.attachDynamicRuleMatcher(stubRuleMatcher{ok: true})

	cfg := &SecurityConfig{}
	cfg.installAgentStream(nil)
	cfg.agent.attachDynamicRuleMatcher(stubRuleMatcher{ok: true})

	enricher := NewEventEnricher(EnrichmentContext{Config: enrichTestConfig("", nil)})
	enriched := NewCompositeAgentHandlerWithEnricher([]AgentHandler{newFakeSink("s")}, &EventFilter{}, enricher)
	plainPipeline := &agentPipeline{handler: enriched, enricher: enricher}
	plainPipeline.attachDynamicRuleMatcher(nil)
	if enricher.ctx.DynamicRuleHandler != nil {
		t.Fatal("nil matcher must not install")
	}
	plainPipeline.attachDynamicRuleMatcher(stubRuleMatcher{ruleID: "r", version: 1, ok: true})
	if enricher.ctx.DynamicRuleHandler == nil {
		t.Fatal("matcher must install on the enricher")
	}
}
