package guardcore

import (
	"log"
	"strings"
	"testing"
	"time"
)

func behaviorRule(ruleType, pattern string, threshold int) BehaviorRuleConfig {
	// Action defaults to ban so the tests can observe the dispatch through
	// the ban manager; individual tests override it when they care.
	return BehaviorRuleConfig{RuleType: ruleType, Pattern: pattern, Threshold: threshold, Window: 60, Action: "ban"}
}

func TestBehaviorConfigDefaults(t *testing.T) {
	cfg := testConfig(t)
	if cfg.BehaviorMaxResponseBodyInspectBytes != DefaultBehaviorMaxResponseBodyInspectBytes {
		t.Fatalf("inspect-bytes default must be %d, got %d", DefaultBehaviorMaxResponseBodyInspectBytes, cfg.BehaviorMaxResponseBodyInspectBytes)
	}
	if cfg.BehaviorScanResponseBody {
		t.Fatalf("behavior_scan_response_body must default to false")
	}
	if len(cfg.GlobalBehaviorRules) != 0 {
		t.Fatalf("global_behavior_rules must default to empty")
	}
}

func TestBehaviorRuleConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		rule    BehaviorRuleConfig
		wantErr string
	}{
		{"bad rule_type", BehaviorRuleConfig{RuleType: "nope", Threshold: 1}, "rule_type"},
		{"zero threshold", BehaviorRuleConfig{RuleType: "usage", Threshold: 0}, "threshold"},
		{"bad action", BehaviorRuleConfig{RuleType: "usage", Threshold: 1, Action: "ignore"}, "action"},
		{"negative ban_duration", BehaviorRuleConfig{RuleType: "usage", Threshold: 1, BanDuration: -1}, "ban_duration"},
	}
	for _, tc := range cases {
		err := ValidateBehaviorRuleConfig(&tc.rule)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: want error mentioning %q, got %v", tc.name, tc.wantErr, err)
		}
	}
	rule := BehaviorRuleConfig{RuleType: "usage", Threshold: 3}
	if err := ValidateBehaviorRuleConfig(&rule); err != nil {
		t.Fatalf("minimal rule must validate: %v", err)
	}
	if rule.Window != DefaultBehaviorWindow || rule.Action != DefaultBehaviorAction {
		t.Fatalf("defaults must apply: window=%d action=%q", rule.Window, rule.Action)
	}
}

func TestBehaviorScanFlagFailClosed(t *testing.T) {
	// Mirrors _validate_return_pattern_requires_scan: a body-reading
	// return_pattern rule is rejected while the scan flag is off...
	_, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.GlobalBehaviorRules = []BehaviorRuleConfig{behaviorRule("return_pattern", "token", 3)}
	})
	if err == nil || !strings.Contains(err.Error(), "behavior_scan_response_body") {
		t.Fatalf("body-reading rule with scan off must fail closed, got %v", err)
	}
	// ...a status: pattern is unaffected...
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.GlobalBehaviorRules = []BehaviorRuleConfig{behaviorRule("return_pattern", "status:404", 3)}
	}); err != nil {
		t.Fatalf("status: pattern must not require the scan flag: %v", err)
	}
	// ...and the same rule passes once the flag is on.
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BehaviorScanResponseBody = true
		c.GlobalBehaviorRules = []BehaviorRuleConfig{behaviorRule("return_pattern", "token", 3)}
	}); err != nil {
		t.Fatalf("body-reading rule with scan on must validate: %v", err)
	}
}

func TestBehaviorInspectBytesBounds(t *testing.T) {
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.BehaviorMaxResponseBodyInspectBytes = 512 }); err == nil {
		t.Fatalf("inspect bytes below 1024 must be rejected")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.BehaviorMaxResponseBodyInspectBytes = 10485761 }); err == nil {
		t.Fatalf("inspect bytes above 10485760 must be rejected")
	}
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if cfg.BehaviorMaxResponseBodyInspectBytes != 262144 {
		t.Fatalf("zero must normalize to the 262144 default, got %d", cfg.BehaviorMaxResponseBodyInspectBytes)
	}
}

func TestBehaviorTrackerUsageThresholdLocal(t *testing.T) {
	cfg := testConfig(t)
	tracker := NewBehaviorTracker(cfg, nil, nil, testLogger())
	rule := behaviorRule("usage", "", 2)
	now := 1000.0
	if tracker.TrackEndpointUsage("GET:/api", "1.2.3.4", rule, now) {
		t.Fatalf("first hit must not trip threshold 2")
	}
	if tracker.TrackEndpointUsage("GET:/api", "1.2.3.4", rule, now+1) {
		t.Fatalf("second hit must not trip threshold 2")
	}
	if !tracker.TrackEndpointUsage("GET:/api", "1.2.3.4", rule, now+2) {
		t.Fatalf("third hit must trip threshold 2")
	}
	// A different client tracks independently.
	if tracker.TrackEndpointUsage("GET:/api", "5.6.7.8", rule, now+3) {
		t.Fatalf("independent client must start from zero")
	}
	// Entries outside the window are pruned.
	if tracker.TrackEndpointUsage("GET:/api", "1.2.3.4", rule, now+float64(rule.Window)+3) {
		t.Fatalf("hits must expire out of the window")
	}
}

func TestBehaviorCheckResponseStatusPattern(t *testing.T) {
	cfg := testConfig(t)
	tracker := NewBehaviorTracker(cfg, nil, nil, testLogger())
	matched, evaluated := tracker.CheckResponsePattern(&Response{StatusCode: 404}, "status:404")
	if !evaluated || !matched {
		t.Fatalf("status:404 must match a 404 response")
	}
	matched, _ = tracker.CheckResponsePattern(&Response{StatusCode: 200}, "status:404")
	if matched {
		t.Fatalf("status:404 must not match a 200 response")
	}
	if matched, evaluated := tracker.CheckResponsePattern(&Response{StatusCode: 404}, "status:abc"); matched || !evaluated {
		t.Fatalf("a malformed status pattern counts as evaluated no-match, got %v/%v", matched, evaluated)
	}
}

func TestBehaviorCheckResponseBodyPatterns(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.BehaviorScanResponseBody = true })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	tracker := NewBehaviorTracker(cfg, nil, nil, testLogger())
	resp := &Response{StatusCode: 200, Body: []byte(`{"items":["secret"],"detail":"Access denied"}`)}
	if matched, _ := tracker.CheckResponsePattern(resp, "Access denied"); !matched {
		t.Fatalf("bare substring must match (case-insensitively)")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "ACCESS DENIED"); !matched {
		t.Fatalf("bare substring must match case-insensitively")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, `json:items[].==secret`); !matched {
		t.Fatalf("json array pattern must match")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, `json:detail=="Access denied"`); !matched {
		t.Fatalf("json scalar pattern must match")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, `json:detail=="nope"`); matched {
		t.Fatalf("json mismatch must not match")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "regex:access\\s+denied"); !matched {
		t.Fatalf("regex pattern must match")
	}
	// With the scan flag off, body patterns are not evaluated at all.
	off := testConfig(t)
	offTracker := NewBehaviorTracker(off, nil, nil, testLogger())
	if _, evaluated := offTracker.CheckResponsePattern(resp, "Access denied"); evaluated {
		t.Fatalf("body patterns must be unevaluated while behavior_scan_response_body is off")
	}
}

func TestBehaviorProcessorUsageRulesBan(t *testing.T) {
	cfg := testConfig(t)
	ban := NewIPBanManager(nil, nil)
	tracker := NewBehaviorTracker(cfg, nil, ban, testLogger())
	proc := NewBehavioralProcessor(cfg, tracker, nil, testLogger())
	rules := []BehaviorRuleConfig{behaviorRule("usage", "", 2)}
	registry := NewRouteRegistry()
	registry.Register("/api", func(rc *RouteConfig) { rc.BehaviorRules = rules })
	route := registry.Get("/api")

	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
	})
	now := float64(time.Now().Unix())
	proc.ProcessUsageRules(req, "9.9.9.9", route, now)
	proc.ProcessUsageRules(req, "9.9.9.9", route, now)
	if ban.IsIPBanned("9.9.9.9") {
		t.Fatalf("ban must fire only on threshold excess")
	}
	proc.ProcessUsageRules(req, "9.9.9.9", route, now)
	if !ban.IsIPBanned("9.9.9.9") {
		t.Fatalf("third usage hit must trip threshold 2 and ban the IP")
	}
	// Exclusion-scoped requests never track.
	other := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		state.ExclusionScoped = true
	})
	proc.ProcessUsageRules(other, "8.8.8.8", route, now)
	if ban.IsIPBanned("8.8.8.8") {
		t.Fatalf("exclusion-scoped requests must not run behavior rules")
	}
	// Endpoint id mirrors get_endpoint_id's METHOD:path fallback.
	if got := proc.GetEndpointID(req); got != "GET:/api" {
		t.Fatalf("endpoint id must be METHOD:path, got %q", got)
	}
	// A routed request keys its counters on the owned route id (the
	// guard-core #141/#142 per-route behavioral counter contract).
	routed := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		state.GuardRouteID = "/api"
	})
	if got := proc.GetEndpointID(routed); got != "/api" {
		t.Fatalf("routed requests must key counters on the route id, got %q", got)
	}
}

func TestBehaviorProcessorGlobalReturnRulesCorrelation(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.GlobalBehaviorRules = []BehaviorRuleConfig{{
			RuleType: "return_pattern", Pattern: "status:404", Threshold: 4,
			Window: 60, Action: "ban", CorrelateWithDetection: true,
		}}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	tracker := NewBehaviorTracker(cfg, nil, ban, testLogger())
	counts := &suspiciousCountStore{m: map[string]map[string]int{}}
	proc := NewBehavioralProcessor(cfg, tracker, counts, testLogger())

	counts.m["6.6.6.1"] = map[string]int{"sqli": 2}
	counts.m["6.6.6.2"] = map[string]int{"sqli": 0}
	resp := &Response{StatusCode: 404}
	now := float64(time.Now().Unix())

	// Correlated IP: threshold halves to max(1, 4/2)=2.
	correlated := newTestRequest(t, nil)
	proc.ProcessGlobalReturnRules(correlated, resp, "6.6.6.1", now)
	proc.ProcessGlobalReturnRules(correlated, resp, "6.6.6.1", now)
	if ban.IsIPBanned("6.6.6.1") {
		t.Fatalf("two correlated hits must not trip the halved threshold (strictly greater)")
	}
	proc.ProcessGlobalReturnRules(correlated, resp, "6.6.6.1", now)
	if !ban.IsIPBanned("6.6.6.1") {
		t.Fatalf("three correlated hits must trip the halved threshold (2)")
	}

	// Non-correlated IPs: zero counts and no counts both keep threshold 4.
	for _, ip := range []string{"6.6.6.2", "6.6.6.3"} {
		req := newTestRequest(t, nil)
		for i := 0; i < 4; i++ {
			proc.ProcessGlobalReturnRules(req, resp, ip, now)
		}
		if ban.IsIPBanned(ip) {
			t.Fatalf("%s: four uncorrelated hits must not trip threshold 4 (strictly greater)", ip)
		}
		proc.ProcessGlobalReturnRules(req, resp, ip, now)
		if !ban.IsIPBanned(ip) {
			t.Fatalf("%s: five uncorrelated hits must trip threshold 4", ip)
		}
	}
}

func TestEngineCheckRunsUsageRules(t *testing.T) {
	var fired int
	engine, err := NewEngine(mustBehaviorConfig(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableRateLimiting = false
		c.OnBlock = func(req Request, payload map[string]any) { fired++ }
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer engine.Close()
	engine.Routes.Register("/api", func(rc *RouteConfig) {
		rc.BehaviorRules = []BehaviorRuleConfig{behaviorRule("usage", "", 1)}
	})
	for i := 0; i < 2; i++ {
		req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
			opts.Path = "/api"
			state.GuardRouteID = "/api"
		})
		if resp := engine.Check(req); resp != nil {
			t.Fatalf("behavior rules never block the request, got %+v", resp)
		}
	}
	// Two usage hits trip threshold 1 engine-side (strictly greater).
	// The ban applies engine-side: the next request is blocked by ip_security.
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Path = "/api"
		state.GuardRouteID = "/api"
	})
	if resp := engine.Check(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("the usage-rule ban must block the next request with 403, got %+v", resp)
	}
}

func TestEngineProcessResponseRunsReturnRules(t *testing.T) {
	engine, err := NewEngine(mustBehaviorConfig(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.GlobalBehaviorRules = []BehaviorRuleConfig{behaviorRule("return_pattern", "status:404", 2)}
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer engine.Close()
	for i := 0; i < 2; i++ {
		req := newTestRequest(t, nil)
		engine.ProcessResponse(req, &Response{StatusCode: 404})
	}
	if engine.Ban.IsIPBanned(resolveClientIP(newTestRequest(t, nil))) {
		t.Fatalf("two 404s must not trip threshold 2 (strictly greater)")
	}
	engine.ProcessResponse(newTestRequest(t, nil), &Response{StatusCode: 404})
	if !engine.Ban.IsIPBanned(resolveClientIP(newTestRequest(t, nil))) {
		t.Fatalf("third 404 must trip the global return_pattern threshold and ban")
	}
}

func mustBehaviorConfig(t *testing.T, mutate func(*SecurityConfig)) *SecurityConfig {
	t.Helper()
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	return cfg
}

func TestBehaviorUsageRuleBanDurationOverride(t *testing.T) {
	cfg := testConfig(t)
	ban := NewIPBanManager(nil, nil)
	tracker := NewBehaviorTracker(cfg, nil, ban, testLogger())
	rule := behaviorRule("usage", "", 1)
	rule.Action = "ban"
	rule.BanDuration = 12345
	req := newTestRequest(t, nil)
	tracker.ApplyAction(rule, "7.7.7.7", procEndpointIDForTest(req, cfg), "test details")
	if !ban.IsIPBanned("7.7.7.7") {
		t.Fatalf("ban action must ban the IP")
	}
}

func procEndpointIDForTest(req Request, cfg *SecurityConfig) string {
	proc := NewBehavioralProcessor(cfg, nil, nil, testLogger())
	return proc.GetEndpointID(req)
}

func testLogger() *log.Logger { return log.Default() }
