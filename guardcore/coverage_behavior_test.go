package guardcore

// Coverage tests for the behavior-rules surface (behavior.go): validation,
// the sliding-window tracker, response-pattern matching, action dispatch
// and the behavioral processor stages.

import (
	"strings"
	"testing"
)

func behaviorTestConfig(t *testing.T, mutate func(*SecurityConfig)) *SecurityConfig {
	t.Helper()
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BehaviorScanResponseBody = true
		if mutate != nil {
			mutate(c)
		}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func TestValidateBehaviorRuleConfigBounds(t *testing.T) {
	rule := &BehaviorRuleConfig{RuleType: "weird", Threshold: 1}
	if err := ValidateBehaviorRuleConfig(rule); err == nil || !strings.Contains(err.Error(), "rule_type") {
		t.Fatalf("unknown rule types fail, got %v", err)
	}
	rule = &BehaviorRuleConfig{RuleType: "usage", Threshold: 0}
	if err := ValidateBehaviorRuleConfig(rule); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("zero thresholds fail, got %v", err)
	}
	rule = &BehaviorRuleConfig{RuleType: "usage", Threshold: 1, Window: -3, Action: "ban"}
	if err := ValidateBehaviorRuleConfig(rule); err == nil || !strings.Contains(err.Error(), "window") {
		t.Fatalf("negative windows fail, got %v", err)
	}
	rule = &BehaviorRuleConfig{RuleType: "usage", Threshold: 1, Action: "ban", BanDuration: -1}
	if err := ValidateBehaviorRuleConfig(rule); err == nil || !strings.Contains(err.Error(), "ban_duration") {
		t.Fatalf("negative ban durations fail, got %v", err)
	}
	rule = &BehaviorRuleConfig{RuleType: "usage", Threshold: 1, Action: "weird"}
	if err := ValidateBehaviorRuleConfig(rule); err == nil || !strings.Contains(err.Error(), "action") {
		t.Fatalf("unknown actions fail, got %v", err)
	}
	rule = &BehaviorRuleConfig{RuleType: "usage", Threshold: 1}
	if err := ValidateBehaviorRuleConfig(rule); err != nil || rule.Window != DefaultBehaviorWindow || rule.Action != DefaultBehaviorAction {
		t.Fatalf("defaults fill in, got %+v %v", rule, err)
	}
}

func TestValidateBehaviorRulesAgainstScanFlag(t *testing.T) {
	rules := []BehaviorRuleConfig{
		{RuleType: "return_pattern", Pattern: "status:500"},
		{RuleType: "usage"},
	}
	if err := validateBehaviorRulesAgainstScanFlag(rules, false, "behavior_rules"); err != nil {
		t.Fatalf("status patterns scan-free, got %v", err)
	}
	if err := validateBehaviorRulesAgainstScanFlag(rules, true, "behavior_rules"); err != nil {
		t.Fatalf("no body rules never fail, got %v", err)
	}
	rules = append(rules, BehaviorRuleConfig{RuleType: "return_pattern", Pattern: "regex:secret"})
	if err := validateBehaviorRulesAgainstScanFlag(rules, false, "behavior_rules"); err == nil {
		t.Fatal("body rules require the scan flag")
	}
	if err := validateBehaviorRulesAgainstScanFlag(rules, true, "behavior_rules"); err != nil {
		t.Fatalf("body rules pass with the scan flag on, got %v", err)
	}
	if err := validateBehaviorRulesAgainstScanFlag([]BehaviorRuleConfig{{RuleType: "return_pattern"}}, false, "behavior_rules"); err != nil {
		t.Fatalf("pattern-less rules pass, got %v", err)
	}
}

func TestNewBehaviorTrackerDefaultsLogger(t *testing.T) {
	cfg := behaviorTestConfig(t, nil)
	tracker := NewBehaviorTracker(cfg, nil, nil, nil)
	if tracker.log == nil || tracker.usageCounts == nil || tracker.returnPatterns == nil {
		t.Fatal("trackers initialize their stores")
	}
}

func TestTrackEndpointUsageLocalWindow(t *testing.T) {
	cfg := behaviorTestConfig(t, func(c *SecurityConfig) { c.RedisFailOpen = true })
	tracker := NewBehaviorTracker(cfg, nil, nil, nil)
	rule := BehaviorRuleConfig{RuleType: "usage", Threshold: 2, Window: 60}
	if tracker.TrackEndpointUsage("ep", "1.2.3.4", rule, 100) {
		t.Fatal("first hits stay under the threshold")
	}
	tracker.TrackEndpointUsage("ep", "1.2.3.4", rule, 101)
	if !tracker.TrackEndpointUsage("ep", "1.2.3.4", rule, 102) {
		t.Fatal("third hits cross the threshold")
	}
	// Sliding-window pruning drops expired hits.
	if tracker.TrackEndpointUsage("ep", "1.2.3.4", BehaviorRuleConfig{RuleType: "usage", Threshold: 2, Window: 5}, 500) {
		t.Fatal("expired windows reset the count")
	}
}

func TestTrackEndpointUsageFailsClosedWithoutRedis(t *testing.T) {
	cfg := behaviorTestConfig(t, func(c *SecurityConfig) { c.RedisFailOpen = false })
	mgr := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1", Prefix: "t:", EnableRedis: true})
	tracker := NewBehaviorTracker(cfg, mgr, nil, nil)
	rule := BehaviorRuleConfig{RuleType: "usage", Threshold: 1, Window: 60}
	if tracker.TrackEndpointUsage("ep", "1.2.3.4", rule, 100) {
		t.Fatal("fail-closed trackers report false when redis is down")
	}
}

func TestTrackReturnPatternStages(t *testing.T) {
	cfg := behaviorTestConfig(t, nil)
	tracker := NewBehaviorTracker(cfg, nil, nil, nil)
	resp := &Response{StatusCode: 500, Body: []byte(`{"items": ["secret"], "note": "Secret Stuff"}`)}
	rule := BehaviorRuleConfig{RuleType: "return_pattern", Threshold: 1, Window: 60, Pattern: "status:500"}

	// Empty patterns never track.
	if tracker.TrackReturnPattern("ep", "1.2.3.4", resp, BehaviorRuleConfig{RuleType: "return_pattern"}, 100, 0) {
		t.Fatal("pattern-less rules never track")
	}
	// Thresholds compare strictly greater.
	if tracker.TrackReturnPattern("ep", "1.2.3.4", resp, rule, 100, 0) {
		t.Fatal("first matches stay at the threshold")
	}
	if !tracker.TrackReturnPattern("ep", "1.2.3.4", resp, rule, 101, 0) {
		t.Fatal("second matches cross the threshold")
	}
	// Non-matching responses never advance the window.
	other := &Response{StatusCode: 200, Body: []byte("fine")}
	if tracker.TrackReturnPattern("ep", "1.2.3.4", other, rule, 102, 0) {
		t.Fatal("non-matching responses never track")
	}
}

func TestCheckResponsePatternKinds(t *testing.T) {
	cfg := behaviorTestConfig(t, nil)
	tracker := NewBehaviorTracker(cfg, nil, nil, nil)
	resp := &Response{StatusCode: 503, Body: []byte(`{"detail": ["Down"], "note": "Secret Stuff", "n": 3, "ok": true, "nothing": null}`)}

	if matched, evaluated := tracker.CheckResponsePattern(resp, "status:503"); !matched || !evaluated {
		t.Fatalf("status patterns match, got %v %v", matched, evaluated)
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "status:abc"); matched {
		t.Fatal("invalid status patterns never match")
	}
	if matched, evaluated := tracker.CheckResponsePattern(resp, "missing-marker"); matched || !evaluated {
		t.Fatalf("substring patterns evaluate, got %v %v", matched, evaluated)
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "json:detail[]==down"); !matched {
		t.Fatal("json array patterns match case-insensitively")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "json:detail[]==up"); matched {
		t.Fatal("json misses stay misses")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "json:note==secret stuff"); !matched {
		t.Fatal("json scalar paths match case-insensitively")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "json:n==3"); !matched {
		t.Fatal("json numbers render as scalars")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "json:nothing==None"); !matched {
		t.Fatal("json nulls render as None")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "json:ok==true"); !matched {
		t.Fatal("json booleans render lowercase")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "json:noparse"); matched {
		t.Fatal("patterns without == never match")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "json:missing==x"); matched {
		t.Fatal("missing paths never match")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "json:detail.nope==x"); matched {
		t.Fatal("scalar traversals never match")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "regex:D[o]wn"); !matched {
		t.Fatal("regex patterns match")
	}
	if matched, _ := tracker.CheckResponsePattern(resp, "regex:["); matched {
		t.Fatal("invalid regexes never match")
	}
	// Regex bodies that blow the pattern budget log and miss.
	big := strings.Repeat("a", 4000) + "!"
	if matched, evaluated := tracker.CheckResponsePattern(&Response{StatusCode: 200, Body: []byte(big)}, "regex:(a+)+$"); matched || !evaluated {
		t.Fatalf("timed-out patterns miss cleanly, got %v %v", matched, evaluated)
	}
	// Bodies that fail to parse never match json patterns.
	if matched, evaluated := tracker.CheckResponsePattern(&Response{StatusCode: 200, Body: []byte("not json")}, "json:x==1"); matched || !evaluated {
		t.Fatalf("unparseable bodies evaluate clean, got %v %v", matched, evaluated)
	}
	// Nil responses under status patterns recover to a clean miss.
	if matched, evaluated := tracker.CheckResponsePattern(nil, "status:500"); matched || !evaluated {
		t.Fatalf("nil responses recover clean, got %v %v", matched, evaluated)
	}
	// Array segments on scalar subjects never match.
	if matchJSONPattern("scalar", "a[]==x") {
		t.Fatal("scalar array segments never match")
	}
	// The scan flag gates body patterns entirely.
	cfgOff := behaviorTestConfig(t, func(c *SecurityConfig) { c.BehaviorScanResponseBody = false })
	offTracker := NewBehaviorTracker(cfgOff, nil, nil, nil)
	if matched, evaluated := offTracker.CheckResponsePattern(resp, "secret"); matched || evaluated {
		t.Fatalf("scan-flag-off skips body patterns, got %v %v", matched, evaluated)
	}
	// Empty bodies evaluate to a clean miss.
	if matched, evaluated := tracker.CheckResponsePattern(&Response{StatusCode: 200}, "x"); matched || !evaluated {
		t.Fatalf("empty bodies evaluate clean, got %v %v", matched, evaluated)
	}
	// Body budgets truncate before matching.
	cfgSmall := behaviorTestConfig(t, func(c *SecurityConfig) { c.BehaviorMaxResponseBodyInspectBytes = 1024 })
	smallTracker := NewBehaviorTracker(cfgSmall, nil, nil, nil)
	long := []byte(strings.Repeat("0123456789", 200) + "needle")
	if matched, _ := smallTracker.CheckResponsePattern(&Response{StatusCode: 200, Body: long}, "needle"); matched {
		t.Fatal("budgeted bodies truncate")
	}
}

func TestMatchJSONPatternShapes(t *testing.T) {
	if matchJSONPattern(map[string]any{"a": "x"}, "a") {
		t.Fatal("patterns without == never match")
	}
	if matchJSONPattern("scalar", "a==x") {
		t.Fatal("scalar traversals never match")
	}
	if matchJSONPattern(map[string]any{"a": "x"}, "a.b==x") {
		t.Fatal("scalar midpaths never match")
	}
	if matchJSONPattern(map[string]any{"list": "x"}, "list[]==x") {
		t.Fatal("non-array list segments never match")
	}
	if matchJSONPattern(map[string]any{"list": []any{map[string]any{}}}, "list[].k==x") {
		t.Fatal("array element maps resolve")
	}
}

func TestJSONScalarToString(t *testing.T) {
	if got := jsonScalarToString("s"); got != "s" {
		t.Fatalf("strings stay, got %q", got)
	}
	if got := jsonScalarToString(true); got != "true" {
		t.Fatalf("true renders lowercase, got %q", got)
	}
	if got := jsonScalarToString(false); got != "false" {
		t.Fatalf("false renders lowercase, got %q", got)
	}
	if got := jsonScalarToString(2.5); got != "2.5" {
		t.Fatalf("floats render shortest, got %q", got)
	}
	if got := jsonScalarToString(nil); got != "None" {
		t.Fatalf("nulls render as None, got %q", got)
	}
	if got := jsonScalarToString([]any{1}); got != "[1]" {
		t.Fatalf("other values render via %v, got %q", "%v", got)
	}
}

func TestBehaviorTrackerLocalEviction(t *testing.T) {
	cfg := behaviorTestConfig(t, nil)
	tracker := NewBehaviorTracker(cfg, nil, nil, nil)
	// Fill a row map to the cap and force one more insertion.
	rows := map[string][]float64{}
	for i := 0; i < maxTrackedClientsPerEndpoint; i++ {
		rows[strings.Repeat("k", i+1)] = []float64{}
	}
	tracker.trackLocal(map[string]map[string][]float64{"bucket": rows}, "bucket", "fresh", 1, 0)
	if len(rows) > maxTrackedClientsPerEndpoint {
		t.Fatalf("client rows stay bounded, got %d", len(rows))
	}
	// The endpoint store evicts too.
	endpoints := map[string]map[string][]float64{}
	for i := 0; i < maxTrackedEndpoints; i++ {
		endpoints[strings.Repeat("e", i+1)] = map[string][]float64{}
	}
	tracker.trackLocal(endpoints, "fresh", "c", 1, 0)
	if len(endpoints) > maxTrackedEndpoints {
		t.Fatalf("endpoint rows stay bounded, got %d", len(endpoints))
	}
}

func TestApplyActionDispatch(t *testing.T) {
	cfg := behaviorTestConfig(t, nil)
	ban := NewIPBanManager(nil, nil)
	tracker := NewBehaviorTracker(cfg, nil, ban, nil)

	// Ban actions enforce through the ban manager.
	tracker.ApplyAction(BehaviorRuleConfig{RuleType: "frequency", Action: "ban"}, "203.0.113.90", "ep", "details")
	if !ban.IsIPBanned("203.0.113.90") {
		t.Fatal("ban actions enforce")
	}
	// Refused bans stay quiet.
	tracker.ApplyAction(BehaviorRuleConfig{RuleType: "frequency", Action: "ban"}, "127.0.0.1", "ep", "details")
	// Alert and throttle actions log.
	tracker.ApplyAction(BehaviorRuleConfig{RuleType: "usage", Action: "alert"}, "203.0.113.90", "ep", "details")
	tracker.ApplyAction(BehaviorRuleConfig{RuleType: "usage", Action: "throttle"}, "203.0.113.90", "ep", "details")
	tracker.ApplyAction(BehaviorRuleConfig{RuleType: "usage", Action: "log"}, "203.0.113.90", "ep", "details")

	// Passive mode logs instead of enforcing.
	passive := behaviorTestConfig(t, func(c *SecurityConfig) { c.PassiveMode = true })
	passiveTracker := NewBehaviorTracker(passive, nil, ban, nil)
	for _, action := range []string{"ban", "alert", "log", "throttle", ""} {
		passiveTracker.ApplyAction(BehaviorRuleConfig{RuleType: "usage", Action: action}, "203.0.113.91", "ep", "details")
	}
	if ban.IsIPBanned("203.0.113.91") {
		t.Fatal("passive mode never bans")
	}
	// The suspicious level annotates log lines; the empty level defaults.
	tracker.cfg.LogSuspiciousLevel = ""
	tracker.logAtSuspiciousLevel("plain message")
}

func TestBehavioralProcessorEndpoints(t *testing.T) {
	cfg := behaviorTestConfig(t, nil)
	processor := NewBehavioralProcessor(cfg, NewBehaviorTracker(cfg, nil, nil, nil), nil, nil)
	if got := processor.GetEndpointID(nil); got != "" {
		t.Fatalf("nil requests carry no endpoint, got %q", got)
	}
	runtime := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.Extras = map[string]any{"guard_endpoint_id": "runtime-id"}
	})
	if got := processor.GetEndpointID(runtime); got != "runtime-id" {
		t.Fatalf("runtime ids win, got %q", got)
	}
	// The per-endpoint route id outranks the runtime extra (the reference
	// get_endpoint_id reads guard_route_id first, guard-core #141/#142).
	routed := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "route-7"
		state.Extras = map[string]any{"guard_endpoint_id": "runtime-id"}
	})
	if got := processor.GetEndpointID(routed); got != "route-7" {
		t.Fatalf("route ids outrank runtime extras, got %q", got)
	}
	// An empty route id falls through to the runtime extra.
	emptyRoute := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = ""
		state.Extras = map[string]any{"guard_endpoint_id": "runtime-id"}
	})
	if got := processor.GetEndpointID(emptyRoute); got != "runtime-id" {
		t.Fatalf("empty route ids fall through, got %q", got)
	}
	derived := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Path = "/users/42"
		opts.Method = "get"
	})
	if got := processor.GetEndpointID(derived); !strings.HasPrefix(got, "GET:") {
		t.Fatalf("derived ids redact paths, got %q", got)
	}
	// Nil loggers default.
	p2 := NewBehavioralProcessor(cfg, nil, nil, nil)
	if p2.log == nil {
		t.Fatal("processors default their logger")
	}
}

func TestProcessUsageRulesStages(t *testing.T) {
	cfg := behaviorTestConfig(t, nil)
	tracker := NewBehaviorTracker(cfg, nil, nil, nil)
	processor := NewBehavioralProcessor(cfg, tracker, nil, nil)

	// Guard clauses: nil tracker, nil request, scoped state, route-less.
	emptyProcessor := NewBehavioralProcessor(cfg, nil, nil, nil)
	emptyProcessor.ProcessUsageRules(nil, "1.2.3.4", nil, 0)
	processor.ProcessUsageRules(nil, "1.2.3.4", nil, 0)
	scoped := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.ExclusionScoped = true })
	processor.ProcessUsageRules(scoped, "1.2.3.4", &RouteConfig{}, 0)
	processor.ProcessUsageRules(newTestRequest(t, nil), "1.2.3.4", nil, 0)
	processor.ProcessUsageRules(newTestRequest(t, nil), "1.2.3.4", &RouteConfig{}, 0)

	// Threshold excess dispatches the action.
	route := &RouteConfig{BehaviorRules: []BehaviorRuleConfig{
		{RuleType: "usage", Threshold: 1, Window: 60, Action: "log"},
		{RuleType: "return_pattern", Threshold: 1, Window: 60, Pattern: "status:500"},
	}}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ClientIP = "203.0.113.61"
	})
	processor.ProcessUsageRules(req, "203.0.113.61", route, 100)
	// The second call crosses the strict threshold and dispatches.
	processor.ProcessUsageRules(req, "203.0.113.61", route, 101)
}

func TestProcessReturnRulesStages(t *testing.T) {
	cfg := behaviorTestConfig(t, nil)
	tracker := NewBehaviorTracker(cfg, nil, nil, nil)
	processor := NewBehavioralProcessor(cfg, tracker, nil, nil)

	emptyProcessor := NewBehavioralProcessor(cfg, nil, nil, nil)
	emptyProcessor.ProcessReturnRules(nil, nil, "1.2.3.4", nil, 0)
	processor.ProcessReturnRules(nil, nil, "1.2.3.4", nil, 0)
	scoped := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.ExclusionScoped = true })
	processor.ProcessReturnRules(scoped, nil, "1.2.3.4", &RouteConfig{}, 0)
	processor.ProcessReturnRules(newTestRequest(t, nil), nil, "1.2.3.4", nil, 0)

	route := &RouteConfig{BehaviorRules: []BehaviorRuleConfig{
		{RuleType: "return_pattern", Threshold: 1, Window: 60, Pattern: "status:500", Action: "log"},
		{RuleType: "usage", Threshold: 1, Window: 60, Action: "log"},
	}}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ClientIP = "203.0.113.62"
	})
	processor.ProcessReturnRules(req, &Response{StatusCode: 500}, "203.0.113.62", route, 100)
	// The same request again crosses the strict threshold.
	processor.ProcessReturnRules(req, &Response{StatusCode: 500}, "203.0.113.62", route, 101)
}

func TestProcessGlobalReturnRulesCorrelation(t *testing.T) {
	cfg := behaviorTestConfig(t, func(c *SecurityConfig) {
		c.GlobalBehaviorRules = []BehaviorRuleConfig{
			{RuleType: "return_pattern", Threshold: 2, Window: 60, Pattern: "status:500", Action: "log", CorrelateWithDetection: true},
			{RuleType: "return_pattern", Threshold: 1, Window: 60, Pattern: "status:404", Action: "log", CorrelateWithDetection: true},
		}
	})
	counts := &suspiciousCountStore{m: map[string]map[string]int{
		"203.0.113.63": {"sqli": 2, "xss": 0},
	}}
	tracker := NewBehaviorTracker(cfg, nil, nil, nil)
	processor := NewBehavioralProcessor(cfg, tracker, counts, nil)

	emptyProcessor := NewBehavioralProcessor(cfg, nil, nil, nil)
	emptyProcessor.ProcessGlobalReturnRules(nil, nil, "1.2.3.4", 0)
	processor.ProcessGlobalReturnRules(nil, nil, "1.2.3.4", 0)
	scoped := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.ExclusionScoped = true })
	processor.ProcessGlobalReturnRules(scoped, nil, "1.2.3.4", 0)
	noRules := behaviorTestConfig(t, nil)
	NewBehavioralProcessor(noRules, tracker, counts, nil).ProcessGlobalReturnRules(newTestRequest(t, nil), nil, "1.2.3.4", 0)

	// Correlation halves the threshold: two hits trip a threshold of two.
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ClientIP = "203.0.113.63"
	})
	resp := &Response{StatusCode: 500}
	processor.ProcessGlobalReturnRules(req, resp, "203.0.113.63", 100)
	processor.ProcessGlobalReturnRules(req, resp, "203.0.113.63", 101)
	// A clean category store keeps the full threshold: one hit stays under.
	cleanCounts := &suspiciousCountStore{m: map[string]map[string]int{}}
	cleanProcessor := NewBehavioralProcessor(cfg, tracker, cleanCounts, nil)
	cleanProcessor.ProcessGlobalReturnRules(req, resp, "203.0.113.64", 100)
	if got := cleanProcessor.collectCorrelatedCategories("203.0.113.64"); len(got) != 0 {
		t.Fatalf("unknown ips correlate to nothing, got %v", got)
	}
}

func TestCollectCorrelatedCategories(t *testing.T) {
	p := &BehavioralProcessor{}
	if got := p.collectCorrelatedCategories("1.2.3.4"); got != nil {
		t.Fatalf("nil counts correlate to nothing, got %v", got)
	}
	counts := &suspiciousCountStore{m: map[string]map[string]int{
		"1.2.3.4": {"zeta": 1, "alpha": 3, "empty": 0},
	}}
	p.counts = counts
	got := p.collectCorrelatedCategories("1.2.3.4")
	if len(got) != 2 || got[0] != "alpha" || got[1] != "zeta" {
		t.Fatalf("positive categories sort, got %v", got)
	}
}
