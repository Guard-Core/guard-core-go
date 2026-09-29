package guardcore

// Coverage tests for the pipeline internals: hook dispatch, verdict
// helpers, rate-limit plumbing, staleness rebuilds and error handling.

import (
	"errors"
	"strings"
	"testing"
)

func TestUnsupportedCheckAccessors(t *testing.T) {
	c := &unsupportedCheck{name: "emergency_mode", excluded: true, applies: func(*SecurityConfig) bool { return true }}
	if !c.EnforcedOnExcludedPaths() {
		t.Fatal("excluded sentinels report themselves")
	}
	if !c.AppliesTo(&SecurityConfig{}) {
		t.Fatal("sentinel applies follow their predicate")
	}
	if c.CheckName() != "emergency_mode" {
		t.Fatal("sentinels carry their name")
	}
}

func TestIPSecurityCheckApplies(t *testing.T) {
	c := &ipSecurityCheck{cfg: &SecurityConfig{}, name: "ip_security"}
	if !c.AppliesTo(c.cfg) {
		t.Fatal("ip security always applies")
	}
}

func TestFireGeoEventRecovers(t *testing.T) {
	// Nil configs and hooks are no-ops.
	fireGeoEvent(nil, GeoEvent{})
	fireGeoEvent(&SecurityConfig{}, GeoEvent{})
	// Panicking hooks do not take the request down.
	cfg := &SecurityConfig{OnGeoEvent: func(GeoEvent) { panic("boom") }}
	fireGeoEvent(cfg, GeoEvent{})
}

func TestGlobalCountryVerdictNilResolver(t *testing.T) {
	cfg := &SecurityConfig{BlockedCountries: []string{"CN"}}
	if reason, blocked := globalCountryVerdict(cfg, "203.0.113.9"); blocked {
		t.Fatalf("nil resolvers never block, got %q %v", reason, blocked)
	}
}

func TestRateLimitCheckEarlyExits(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.RateLimit = 1
		c.RateLimitWindow = 60
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, nil)
	rl.now = func() float64 { return 1000.0 }
	check := &rateLimitCheck{cfg: cfg, manager: rl}

	// Whitelisted and exempt requests skip the tier run.
	for _, mutate := range []func(*RequestState){
		func(s *RequestState) { s.IsWhitelisted = true },
		func(s *RequestState) { s.IsExempt = true },
	} {
		req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
			state.ClientIP = "203.0.113.9"
			mutate(state)
		})
		if resp := check.Check(req); resp != nil {
			t.Fatal("whitelisted and exempt requests skip the check")
		}
	}
	// Identity-less requests skip the tier run.
	req := newTestRequest(t, nil)
	if resp := check.Check(req); resp != nil {
		t.Fatal("identity-less requests skip the check")
	}
}

func TestRateLimitCheckPassiveMode(t *testing.T) {
	var hooks []map[string]any
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.RateLimit = 1
		c.RateLimitWindow = 60
		c.PassiveMode = true
		c.OnBlock = func(req Request, payload map[string]any) { hooks = append(hooks, payload) }
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, nil)
	rl.now = func() float64 { return 1000.0 }
	check := &rateLimitCheck{cfg: cfg, manager: rl}
	mk := func() Request {
		return newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
			state.ClientIP = "203.0.113.50"
		})
	}
	if resp := check.Check(mk()); resp != nil {
		t.Fatal("first request passes")
	}
	resp := check.Check(mk())
	if resp != nil {
		t.Fatalf("passive mode never blocks, got %+v", resp)
	}
	if len(hooks) != 1 {
		t.Fatalf("passive blocks fire one hook, got %d", len(hooks))
	}
}

func TestRouteRateConfigFrom(t *testing.T) {
	if got := routeRateConfigFrom(nil); got != nil {
		t.Fatal("nil routes carry no tier")
	}
	if got := routeRateConfigFrom(&RouteConfig{}); got != nil {
		t.Fatal("tier-less routes carry no tier")
	}
	limit, window := 5, 30
	got := routeRateConfigFrom(&RouteConfig{
		RateLimit:       limit,
		RateLimitWindow: window,
		GeoRateLimits:   map[string]RateLimitEntry{"CN": {Requests: 1, Window: 10}},
	})
	if got == nil || got.RateLimit == nil || *got.RateLimit != limit {
		t.Fatalf("route tiers carry their limit, got %+v", got)
	}
	if got.RateLimitWindow == nil || *got.RateLimitWindow != window {
		t.Fatalf("route tiers carry their window, got %+v", got)
	}
	if len(got.GeoRateLimits) != 1 {
		t.Fatalf("route tiers carry geo limits, got %v", got.GeoRateLimits)
	}
}

func TestSuspiciousActivityCheckApplies(t *testing.T) {
	c := &suspiciousActivityCheck{}
	if c.AppliesTo(&SecurityConfig{}) {
		t.Fatal("detection-disabled configs never apply")
	}
	if !c.AppliesTo(&SecurityConfig{EnablePenetrationDetection: true}) {
		t.Fatal("detection-enabled configs apply")
	}
}

func TestRegisterViolationsWithoutBanning(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableIPBanning = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	c := &suspiciousActivityCheck{
		cfg:    cfg,
		counts: &suspiciousCountStore{m: map[string]map[string]int{}},
	}
	if c.registerViolations(cfg, "203.0.113.77", []string{"sqli"}) {
		t.Fatal("banning-disabled configs never escalate")
	}
}

func TestRegisterViolationsRefusalsContinue(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableIPBanning = true
		c.AutoBanThreshold = 1
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	c := &suspiciousActivityCheck{
		cfg:    cfg,
		ban:    ban,
		counts: &suspiciousCountStore{m: map[string]map[string]int{}},
	}
	// Loopback refusals fall through without escalating.
	if c.registerViolations(cfg, "127.0.0.1", []string{"sqli"}) {
		t.Fatal("refused bans never escalate")
	}
}

func TestFirstThreatOfAndMessages(t *testing.T) {
	if firstThreatOf(DetectResult{}) != nil {
		t.Fatal("empty results have no first threat")
	}
	cases := []struct {
		name   string
		threat map[string]any
		want   string
	}{
		{"nil", nil, "Threat detected"},
		{"semantic_probability", map[string]any{"type": "semantic", "attack_type": "xss", "probability": 0.9}, "Semantic attack: xss (score: 0.90)"},
		{"semantic_score", map[string]any{"type": "semantic", "threat_score": 0.55}, "Semantic attack: suspicious (score: 0.55)"},
		{"timeout", map[string]any{"type": "pattern_timeout", "pattern": "boom"}, "Pattern exceeded scan time budget: 'boom'"},
		{"regex", map[string]any{"type": "regex", "pattern": "pwn"}, "Value matched pattern 'pwn'"},
		{"unknown", map[string]any{"type": "weird"}, "Threat detected"},
	}
	for _, tc := range cases {
		if got := threatMessage(tc.threat); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestExtractRequestBodyValues(t *testing.T) {
	if got := extractRequestBodyValues(nil, nil, nil); got != nil {
		t.Fatal("nil configs scan nothing")
	}
	// A failing body read leaves the body unscanned.
	failing := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.BodyFunc = func() ([]byte, error) { return nil, errors.New("read boom") }
	})
	if got := extractRequestBodyValues(failing, &SecurityConfig{}, nil); got != nil {
		t.Fatalf("failed reads scan nothing, got %v", got)
	}
	// Inspection budgets truncate the scanned body.
	scfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.Detection.MaxBodyInspectBytes = 4
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	req := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Body = []byte("a=1b=2c=3d=4")
	})
	values := extractRequestBodyValues(req, scfg, nil)
	if len(values) == 0 || !strings.Contains(values[0].content, "a=1") {
		t.Fatalf("budgeted bodies still scan, got %v", values)
	}
	for _, v := range values {
		if strings.Contains(v.content, "d=4") {
			t.Fatalf("budgets cap the scanned body, got %q", v.content)
		}
	}
}

func TestFireBlockHookRecovers(t *testing.T) {
	// Nil configs and hooks are no-ops.
	fireBlockHook(nil, newTestRequest(t, nil), "ip_security", "reason", "", false, 403)
	fireBlockHook(&SecurityConfig{}, newTestRequest(t, nil), "ip_security", "reason", "", false, 403)
	// Panicking hooks recover.
	cfg := &SecurityConfig{OnBlock: func(req Request, payload map[string]any) { panic("hook boom") }}
	fireBlockHook(cfg, newTestRequest(t, nil), "ip_security", "reason", "", false, 403)
	// Excluded check names skip the hook.
	fired := 0
	cfg = &SecurityConfig{OnBlock: func(req Request, payload map[string]any) { fired++ }}
	fireBlockHook(cfg, newTestRequest(t, nil), "https_enforcement", "reason", "", false, 0)
	if fired != 0 {
		t.Fatalf("excluded checks skip the hook, got %d", fired)
	}
}

func TestFireBlockHookForced(t *testing.T) {
	fireBlockHookForced(nil, newTestRequest(t, nil), "x", "reason", "", false, 0)
	fireBlockHookForced(&SecurityConfig{}, newTestRequest(t, nil), "x", "reason", "", false, 0)

	var got []map[string]any
	cfg := &SecurityConfig{OnBlock: func(req Request, payload map[string]any) { got = append(got, payload) }}
	fireBlockHookForced(cfg, newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ClientIP = "203.0.113.9"
	}), "x", "reason", "info", false, 429)
	if len(got) != 1 {
		t.Fatalf("forced hooks fire once, got %d", len(got))
	}
	if got[0]["status_code"] != 429 || got[0]["client_ip"] != "203.0.113.9" {
		t.Fatalf("forced hooks carry the payload, got %v", got[0])
	}
	// Unknown identities and null statuses flow through the payload.
	fireBlockHookForced(cfg, newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ""
		state.ClientIP = ""
	}), "x", "reason", "", false, 0)
	if len(got) != 2 {
		t.Fatalf("forced hooks fire per call, got %d", len(got))
	}
	if got[1]["status_code"] != nil || got[1]["client_ip"] != UnknownClientIdentity {
		t.Fatalf("status-less payloads null out, got %v", got[1])
	}
	// Panicking hooks recover.
	cfg = &SecurityConfig{OnBlock: func(req Request, payload map[string]any) { panic("boom") }}
	fireBlockHookForced(cfg, newTestRequest(t, nil), "x", "reason", "", false, 0)
}

func TestNewSecurityCheckPipelineMutedLogs(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.MutedCheckLogs = map[string]bool{"rate_limit": true}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	p := NewSecurityCheckPipeline(nil, cfg, nil)
	if !p.mutedCheckLogs["rate_limit"] {
		t.Fatal("muted check logs seed the pipeline")
	}
	// Nil configs still produce a working pipeline.
	p = NewSecurityCheckPipeline(nil, nil, nil)
	if p.isStale() {
		t.Fatal("config-less pipelines never go stale")
	}
}

func TestPipelineStalenessViaRouteRevision(t *testing.T) {
	cfg := testConfig(t)
	routes := NewRouteRegistry()
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	p, _ := BuildDefaultPipeline(cfg, ban, rl, routes)
	if p.IsStale() {
		t.Fatal("fresh pipelines are not stale")
	}
	routes.Register("/login", func(rc *RouteConfig) { rc.RateLimit = 5 })
	if !p.IsStale() {
		t.Fatal("route revisions staleness")
	}
	// Executing rebuilds and clears the staleness.
	_ = p.Execute(newTestRequest(t, nil))
	if p.IsStale() {
		t.Fatal("executions rebuild stale pipelines")
	}
}

func TestPipelineExecuteSkipsExcludedWhenScoped(t *testing.T) {
	cfg := testConfig(t)
	calls := 0
	check := &fakeCheck{name: "soft", excluded: false, applies: true, resp: nil}
	_ = check
	counting := &countingCheck{check: check, onCheck: func() { calls++ }}
	p := NewSecurityCheckPipeline([]SecurityCheck{counting}, cfg, nil)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ExclusionScoped = true
	})
	if resp := p.Execute(req); resp != nil {
		t.Fatalf("scoped exclusions never block, got %+v", resp)
	}
	if calls != 0 {
		t.Fatalf("excluded checks stay skipped, got %d calls", calls)
	}
}

type countingCheck struct {
	check   SecurityCheck
	onCheck func()
}

func (c *countingCheck) CheckName() string                  { return c.check.CheckName() }
func (c *countingCheck) EnforcedOnExcludedPaths() bool      { return c.check.EnforcedOnExcludedPaths() }
func (c *countingCheck) AppliesTo(cfg *SecurityConfig) bool { return c.check.AppliesTo(cfg) }
func (c *countingCheck) Check(req Request) *Response {
	c.onCheck()
	return c.check.Check(req)
}

func TestRunCheckRecoversPanics(t *testing.T) {
	panicking := &unsupportedCheck{name: "boom", excluded: true, applies: func(*SecurityConfig) bool { return true }}
	resp, err := runCheck(panicking, newTestRequest(t, nil))
	if resp != nil || err == nil {
		t.Fatalf("panicking checks surface errors, got %+v %v", resp, err)
	}
}

func TestHandleCheckErrorBranches(t *testing.T) {
	check := &fakeCheck{name: "flaky", excluded: true, applies: true}

	// Redis failures fail open when configured.
	cfg := testConfig(t)
	cfg.RedisFailOpen = true
	p := NewSecurityCheckPipeline(nil, cfg, nil)
	if resp := p.handleCheckError(check, newTestRequest(t, nil), &GuardRedisError{StatusCode: 500, Message: "down"}, map[string]bool{}); resp != nil {
		t.Fatalf("redis failures fail open, got %+v", resp)
	}

	// Fail-secure blocks with the custom message.
	cfg = testConfig(t)
	cfg.FailSecure = true
	cfg.CustomErrorResponses[500] = "custom down"
	p = NewSecurityCheckPipeline(nil, cfg, nil)
	resp := p.handleCheckError(check, newTestRequest(t, nil), errors.New("boom"), map[string]bool{})
	if resp == nil || resp.StatusCode != 500 || string(resp.Body) != "custom down" {
		t.Fatalf("fail-secure blocks with 500, got %+v", resp)
	}

	// Non-fail-secure configs skip the block.
	cfg = testConfig(t)
	cfg.FailSecure = false
	p = NewSecurityCheckPipeline(nil, cfg, nil)
	if resp := p.handleCheckError(check, newTestRequest(t, nil), errors.New("boom"), map[string]bool{}); resp != nil {
		t.Fatalf("non-fail-secure configs skip blocks, got %+v", resp)
	}

	// Muted checks stay silent but keep the same decisions.
	p = NewSecurityCheckPipeline(nil, testConfig(t), nil)
	if resp := p.handleCheckError(check, newTestRequest(t, nil), errors.New("boom"), map[string]bool{"flaky": true}); resp == nil {
		t.Fatal("muted checks still fail secure by default")
	}
}

func TestBuildDefaultPipelineNilConfig(t *testing.T) {
	p, counts := BuildDefaultPipeline(nil, nil, nil, nil)
	if p != nil || counts != nil {
		t.Fatal("nil configs build nothing")
	}
}

func TestBuildChecksRouteDrivenSlots(t *testing.T) {
	cfg := testConfig(t)
	routes := NewRouteRegistry()
	routes.Register("/admin", func(rc *RouteConfig) {
		rc.AuthRequired = "apikey"
		rc.TimeRestrictions = map[string]string{"mon": "09:00-17:00"}
	})
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	p, _ := BuildDefaultPipeline(cfg, ban, rl, routes)
	names := p.CheckNames()
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "authentication") || !strings.Contains(joined, "time_window") {
		t.Fatalf("route-driven slots join the pipeline, got %v", names)
	}
}
