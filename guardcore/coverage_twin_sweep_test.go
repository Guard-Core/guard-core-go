package guardcore

// Twin sweep for the statements the feature-port waves left uncovered and
// that are reachable with real inputs (the provably unreachable defensive
// guards live in .github/scripts/coverage_waivers.txt with their proofs).

import (
	"strings"
	"testing"
)

// TestBehaviorViolationReachesAgentBus pins that the behavioral_violation
// handler event rides the installed agent bus (behavior.go emitBehaviorEvent).
func TestBehaviorViolationReachesAgentBus(t *testing.T) {
	agent := &recordingAgent{}
	cfg := behaviorTestConfig(t, func(c *SecurityConfig) {
		c.AgentHandler = agent
	})
	cfg.installAgentStream(nil)
	ban := NewIPBanManager(nil, nil)
	tracker := NewBehaviorTracker(cfg, nil, ban, nil)
	tracker.ApplyAction(BehaviorRuleConfig{RuleType: "usage", Action: "ban"}, "203.0.113.77", "ep", "details")
	if len(agent.events) != 1 {
		t.Fatalf("the behavioral violation must reach the agent bus, got %+v", agent.events)
	}
	event := agent.events[0]
	if event.EventType != EventBehaviorViolation || event.HandlerName != BehaviorHandlerName {
		t.Fatalf("event envelope drifted: %+v", event)
	}
	if event.ActionTaken != "ban" || event.IPAddress != "203.0.113.77" {
		t.Fatalf("action and client must ride the envelope: %+v", event)
	}
	if event.Metadata["endpoint"] != "ep" || event.Metadata["rule_type"] != "usage" {
		t.Fatalf("metadata drifted: %+v", event.Metadata)
	}
}

// TestValidateAgentSurfaceNormalizations covers the agent-surface validator:
// the both-channels-off branch and the dynamic-rule interval default.
func TestValidateAgentSurfaceNormalizations(t *testing.T) {
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.AgentHandler = &recordingAgent{}
		c.AgentEnableEvents = false
		c.AgentEnableMetrics = false
	}); err != nil {
		t.Fatalf("both channels off with a handler is allowed, got %v", err)
	}
	// EnableDynamicRules with an unset interval fills the pydantic default.
	cfgDyn, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableDynamicRules = true
		c.DynamicRuleInterval = 0
	})
	if err != nil {
		t.Fatalf("dynamic rules config: %v", err)
	}
	if cfgDyn.DynamicRuleInterval != DefaultDynamicRuleInterval {
		t.Fatalf("the interval must default to %d, got %d", DefaultDynamicRuleInterval, cfgDyn.DynamicRuleInterval)
	}
	// An explicit interval below the ge=60 bound fails validation.
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableDynamicRules = true
		c.DynamicRuleInterval = 30
	}); err == nil {
		t.Fatal("a sub-bound interval must fail validation")
	}
}

// rulesProviderAgent is an agent handler that also carries the
// DynamicRulesProvider capability, like the reference agent handler.
type rulesProviderAgent struct {
	recordingAgent
	rules *DynamicRules
}

func (a *rulesProviderAgent) GetDynamicRules() (*DynamicRules, error) { return a.rules, nil }

// TestEngineDynamicRuleLoopStartup drives startDynamicRuleLoop through
// Engine.Initialize for both agent shapes: a provider handler starts the
// update loop (hydrate + Start) and a capability-less handler stays idle.
func TestEngineDynamicRuleLoopStartup(t *testing.T) {
	provider := &rulesProviderAgent{rules: sampleRules()}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableDynamicRules = true
		c.AgentHandler = provider
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if engine.DynamicRules == nil {
		t.Fatal("enable_dynamic_rules must install the manager")
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	engine.Close()

	// A handler without GetDynamicRules logs and leaves the loop idle.
	idleCfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableDynamicRules = true
		c.AgentHandler = &recordingAgent{}
	})
	if err != nil {
		t.Fatal(err)
	}
	idleEngine, err := NewEngine(idleCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := idleEngine.Initialize(); err != nil {
		t.Fatalf("a capability-less handler must not fail startup: %v", err)
	}
	idleEngine.Close()
}

// TestFileUploadScanMatchesSkipsOverlappingCandidate pins the overlap guard:
// a second filename token whose candidate start falls inside the first
// candidate's span is skipped (fileupload.go fileUploadScanMatches). The
// first candidate's quoted body swallows a newline plus the second token, so
// the second token's newline separator start lands behind lastEnd.
func TestFileUploadScanMatchesSkipsOverlappingCandidate(t *testing.T) {
	body := "filename=\"x.php%00\nfilename=\"b\""
	matches := fileUploadScanMatches(newScanText(body), fileUploadTruncationSource)
	if len(matches) != 1 {
		t.Fatalf("the outer candidate must match once and the swallowed token must skip: %d", len(matches))
	}
	if got := matches[0].full(); got != body {
		t.Fatalf("the match must span the whole candidate: %q", got)
	}
}

// TestRedactPairsDepthCap pins the bounded value rescan: a value-nesting
// chain deeper than pairRedactionMaxDepth stops redacting (the cap), while a
// shallow chain still redacts the innermost sensitive pair. The bare-token
// form (no spaces) nests exactly one label per recursion level.
func TestRedactPairsDepthCap(t *testing.T) {
	sensitive := map[string]bool{"token": true}
	shallow := "a:b:c:token=x"
	if got := redactPairsInText(shallow, sensitive); got != "a:b:c:token="+RedactedPlaceholder {
		t.Fatalf("a shallow chain must redact the inner pair, got %q", got)
	}
	deep := "a:b:c:d:e:f:g:token=x"
	if got := redactPairsInText(deep, sensitive); got != deep {
		t.Fatalf("past the depth cap the scan must leave the text alone, got %q", got)
	}
}

// TestRedactURLFragmentPairs pins the fragment redaction branch of
// RedactURLForDisplay: the fragment redacts like the query.
func TestRedactURLFragmentPairs(t *testing.T) {
	sensitive := map[string]bool{"token": true}
	got := RedactURLForDisplay("https://host/p?x=1#token=secret", sensitive, nil, nil)
	// The redacted fragment re-encodes through parsed.String().
	if !strings.Contains(got, "#token=%5BREDACTED%5D") {
		t.Fatalf("the fragment pair must redact: %q", got)
	}
	if !strings.Contains(got, "x=1") {
		t.Fatalf("a clean query must survive: %q", got)
	}
}

// TestMultipartPartEndingMidHeaders covers a part whose header block runs to
// the end of the body without a blank line: the payload defaults to the body
// tail (readPart's no-closing-boundary branch).
func TestMultipartPartEndingMidHeaders(t *testing.T) {
	parts := parseMultipartParts("--B\nX-Header: value", "B")
	if len(parts) != 1 {
		t.Fatalf("one unclosed part must parse: %d", len(parts))
	}
	if len(parts[0].payload) != 0 {
		t.Fatalf("the payload must default to the empty body tail: %q", parts[0].payload)
	}
	if len(parts[0].headers) != 1 || parts[0].headers[0].name != "X-Header" {
		t.Fatalf("the header must survive: %+v", parts[0].headers)
	}
}

// TestMultipartPayloadKeepsBareNewlineOverCR pins the payload slicing
// guards: a lone-newline payload between a CR and the boundary collapses to
// the empty slice (both terminator bytes belong to the delimiter).
func TestMultipartPayloadKeepsBareNewlineOverCR(t *testing.T) {
	parts := parseMultipartParts("--B\nH: v\n\r\n\n--B", "B")
	if len(parts) != 1 {
		t.Fatalf("one part must parse: %d", len(parts))
	}
	if len(parts[0].payload) != 0 {
		t.Fatalf("the lone newline payload must collapse to the clamp: %q", parts[0].payload)
	}
	if len(parts[0].headers) != 1 || parts[0].headers[0].value != "v" {
		t.Fatalf("headers must survive: %+v", parts[0].headers)
	}
}

// TestEmitRateLimitedHandlerEventWithoutBus pins the agentless early return:
// no installed bus, no event, no panic.
func TestEmitRateLimitedHandlerEventWithoutBus(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.EnableRedis = false })
	if err != nil {
		t.Fatal(err)
	}
	rules := &RateLimitOutcome{Blocked: true, Count: 5, Window: 60, Tier: "global", Limit: 100}
	req := newTestRequest(t, nil)
	emitRateLimitedHandlerEvent(cfg, req, "203.0.113.99", rules)
}

// TestEmitScriptReloadedEvent pins the NOSCRIPT recovery event: a manager
// with an installed bus emits rate_limit_script_reloaded.
func TestEmitScriptReloadedEvent(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.EnableRedis = false })
	if err != nil {
		t.Fatal(err)
	}
	agent := &recordingAgent{}
	manager := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, nil)
	manager.SetEventBus(NewSecurityEventBus(agent, cfg, nil, EventFilter{}), false)
	manager.emitScriptReloaded()
	if len(agent.events) != 1 {
		t.Fatalf("the script-reloaded event must reach the bus, got %+v", agent.events)
	}
	event := agent.events[0]
	if event.EventType != EventRateLimitScriptReloaded || event.HandlerName != RateLimitHandlerName {
		t.Fatalf("event envelope drifted: %+v", event)
	}
	if event.IPAddress != "system" || event.ActionTaken != "script_reloaded" {
		t.Fatalf("the system envelope drifted: %+v", event)
	}
}

// TestTemplateExpressionOverlapRegions pins the overlap guard in
// templateExpressionMatches: a second region starting inside the first
// matched region's span is skipped.
func TestTemplateExpressionOverlapRegions(t *testing.T) {
	// "<%1+2<%>%>": the first matched region spans [0, 8); the second starts
	// at 5, inside it, and must skip instead of double-reporting.
	matches := templateExpressionMatches(newScanText("<%1+2<%>%>"), "asp")
	if len(matches) != 1 {
		t.Fatalf("the overlapping region must skip, got %d matches", len(matches))
	}
}

// TestExtractAttackRegionsCapAtBudget pins the region-budget clamp: more
// distinct attack regions than the budget truncates the merge to the budget.
func TestExtractAttackRegionsCapAtBudget(t *testing.T) {
	// 12 indicator hits (backticks and semicolons) 250 runes apart: 12
	// non-merging regions against a budget of maxContentLength/100 = 10.
	// Two patterns keep each FindAllStringIndex call under the per-pattern
	// match cap, so the merge truly overflows the budget.
	var b strings.Builder
	for i := 0; i < 12; i++ {
		if i > 0 {
			b.WriteString(strings.Repeat("a", 249))
		}
		if i%2 == 0 {
			b.WriteString("`")
		} else {
			b.WriteString(";")
		}
	}
	regions := extractAttackRegions(newScanText(b.String()), 1000)
	if len(regions) != 10 {
		t.Fatalf("the merged regions must clamp to the budget, got %d", len(regions))
	}
}

// TestHeadersCacheConfigurationWithoutRedis pins the redis-less cache write:
// a manager without a handler returns quietly.
func TestHeadersCacheConfigurationWithoutRedis(t *testing.T) {
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager.CacheConfiguration()
}
