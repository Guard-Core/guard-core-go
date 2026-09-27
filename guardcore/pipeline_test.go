package guardcore

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
)

func newTestRequest(t *testing.T, mutate func(opts *RequestOptions, state *RequestState)) Request {
	t.Helper()
	opts := RequestOptions{Path: "/api", Scheme: "http", Host: "example.com", Method: "GET", ClientHost: "203.0.113.9"}
	state := &RequestState{}
	if mutate != nil {
		mutate(&opts, state)
	}
	opts.State = state
	return &guardRequest{opts: opts}
}

type fakeCheck struct {
	name     string
	excluded bool
	applies  bool
	resp     *Response
	err      error
	calls    int
}

func (c *fakeCheck) CheckName() string                  { return c.name }
func (c *fakeCheck) EnforcedOnExcludedPaths() bool      { return c.excluded }
func (c *fakeCheck) AppliesTo(cfg *SecurityConfig) bool { return c.applies }
func (c *fakeCheck) Check(req Request) *Response {
	c.calls++
	if c.err != nil {
		panic(c.err)
	}
	return c.resp
}

func testConfig(t *testing.T) *SecurityConfig {
	t.Helper()
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	return cfg
}

func TestPipelineFirstNonNilResponseWins(t *testing.T) {
	cfg := testConfig(t)
	first := &fakeCheck{name: "a", resp: errorResponse(nil, 403, "first")}
	second := &fakeCheck{name: "b", resp: errorResponse(nil, 403, "second")}
	p := NewSecurityCheckPipeline([]SecurityCheck{first, second}, cfg, nil)
	resp := p.Execute(newTestRequest(t, nil))
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != "first" {
		t.Fatalf("expected first response to win, got %+v", resp)
	}
	if second.calls != 0 {
		t.Fatalf("short-circuit violated: second check ran %d times", second.calls)
	}
}

func TestPipelineOrderPreserved(t *testing.T) {
	cfg := testConfig(t)
	var order []string
	var mu sync.Mutex
	mk := func(name string) SecurityCheck {
		return &orderRecorder{name: name, record: func(n string) {
			mu.Lock()
			order = append(order, n)
			mu.Unlock()
		}}
	}
	p := NewSecurityCheckPipeline([]SecurityCheck{mk("one"), mk("two"), mk("three")}, cfg, nil)
	p.Execute(newTestRequest(t, nil))
	if strings.Join(order, ",") != "one,two,three" {
		t.Fatalf("unexpected order: %v", order)
	}
}

type orderRecorder struct {
	name   string
	record func(string)
}

func (o *orderRecorder) CheckName() string              { return o.name }
func (o *orderRecorder) EnforcedOnExcludedPaths() bool  { return false }
func (o *orderRecorder) AppliesTo(*SecurityConfig) bool { return true }
func (o *orderRecorder) Check(req Request) *Response {
	o.record(o.name)
	return nil
}

func TestPipelineExclusionScoping(t *testing.T) {
	cfg := testConfig(t)
	normal := &fakeCheck{name: "normal", excluded: false}
	scoped := &fakeCheck{name: "scoped", excluded: true}
	p := NewSecurityCheckPipeline([]SecurityCheck{normal, scoped}, cfg, nil)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ExclusionScoped = true
	})
	p.Execute(req)
	if normal.calls != 0 {
		t.Fatalf("non-excluded check ran on exclusion-scoped request")
	}
	if scoped.calls != 1 {
		t.Fatalf("excluded-path-enforced check did not run")
	}
}

func TestPipelineFailSecureBlocksOnCheckError(t *testing.T) {
	cfg := testConfig(t)
	boom := &fakeCheck{name: "boom", err: errors.New("kaboom")}
	after := &fakeCheck{name: "after"}
	p := NewSecurityCheckPipeline([]SecurityCheck{boom, after}, cfg, nil)
	resp := p.Execute(newTestRequest(t, nil))
	if resp == nil || resp.StatusCode != 500 || string(resp.Body) != "Security check failed" {
		t.Fatalf("fail_secure should return 500 'Security check failed', got %+v", resp)
	}
	if after.calls != 0 {
		t.Fatalf("fail-secure response must short-circuit")
	}
}

func TestPipelineFailOpenContinuesOnCheckError(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.FailSecure = false })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	boom := &fakeCheck{name: "boom", err: errors.New("kaboom")}
	after := &fakeCheck{name: "after", resp: errorResponse(nil, 403, "blocked")}
	p := NewSecurityCheckPipeline([]SecurityCheck{boom, after}, cfg, nil)
	resp := p.Execute(newTestRequest(t, nil))
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("fail-open should continue to next check, got %+v", resp)
	}
	if boom.calls != 1 || after.calls != 1 {
		t.Fatalf("unexpected call counts: %d %d", boom.calls, after.calls)
	}
}

func TestPipelineRedisErrorFailOpenSkips(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.RedisFailOpen = true })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	redisCheck := &fakeCheck{name: "rl", err: newGuardRedisError("redis down")}
	after := &fakeCheck{name: "after", resp: nil}
	p := NewSecurityCheckPipeline([]SecurityCheck{redisCheck, after}, cfg, nil)
	resp := p.Execute(newTestRequest(t, nil))
	if resp != nil {
		t.Fatalf("redis_fail_open should skip the failing check, got %+v", resp)
	}
	if after.calls != 1 {
		t.Fatalf("pipeline should continue after skipped check")
	}
}

func TestPipelineRedisErrorFailSecureBlocks(t *testing.T) {
	cfg := testConfig(t)
	redisCheck := &fakeCheck{name: "rl", err: newGuardRedisError("redis down")}
	p := NewSecurityCheckPipeline([]SecurityCheck{redisCheck}, cfg, nil)
	resp := p.Execute(newTestRequest(t, nil))
	if resp == nil || resp.StatusCode != 500 || string(resp.Body) != "Security check failed" {
		t.Fatalf("fail_secure must 500 on redis error, got %+v", resp)
	}
}

func TestPipelineOnBlockPayload(t *testing.T) {
	cfg := testConfig(t)
	var mu sync.Mutex
	var payloads []map[string]any
	cfg.OnBlock = func(req Request, payload map[string]any) {
		mu.Lock()
		payloads = append(payloads, payload)
		mu.Unlock()
	}
	blocking := &fakeCheck{name: "ip_security", resp: errorResponse(nil, 403, "no")}
	p := NewSecurityCheckPipeline([]SecurityCheck{blocking}, cfg, nil)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ClientIP = "203.0.113.9"
		state.BlockStash = &BlockStash{Reason: "Banned IP attempted access: 203.0.113.9", TriggerInfo: "banned_ip"}
	})
	p.Execute(req)
	if len(payloads) != 1 {
		t.Fatalf("on_block must fire exactly once, got %d", len(payloads))
	}
	payload := payloads[0]
	for _, key := range []string{"check_name", "reason", "trigger_info", "passive_mode", "client_ip", "path", "method", "status_code"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("payload missing key %q: %v", key, payload)
		}
	}
	if payload["check_name"] != "ip_security" {
		t.Fatalf("wrong check_name: %v", payload["check_name"])
	}
	if payload["reason"] != "Banned IP attempted access: 203.0.113.9" {
		t.Fatalf("stash reason not used: %v", payload["reason"])
	}
	if payload["trigger_info"] != "banned_ip" {
		t.Fatalf("stash trigger_info not used: %v", payload["trigger_info"])
	}
	if payload["passive_mode"] != false {
		t.Fatalf("passive_mode must be false on short-circuit path")
	}
	if payload["status_code"] != 403 {
		t.Fatalf("status_code must come from the blocking response: %v", payload["status_code"])
	}
	if payload["method"] != "GET" || payload["path"] != "/api" {
		t.Fatalf("bad method/path: %v", payload)
	}
}

func TestPipelineOnBlockSuppressedChecks(t *testing.T) {
	for _, name := range []string{"custom_request", "custom_validators", "https_enforcement"} {
		cfg := testConfig(t)
		fired := false
		cfg.OnBlock = func(req Request, payload map[string]any) { fired = true }
		blocking := &fakeCheck{name: name, resp: errorResponse(nil, 400, "no")}
		p := NewSecurityCheckPipeline([]SecurityCheck{blocking}, cfg, nil)
		p.Execute(newTestRequest(t, nil))
		if fired {
			t.Fatalf("on_block must be suppressed for %s", name)
		}
	}
}

func TestPipelineOnBlockHookPanicSwallowed(t *testing.T) {
	cfg := testConfig(t)
	cfg.OnBlock = func(req Request, payload map[string]any) { panic("hook exploded") }
	blocking := &fakeCheck{name: "ip_security", resp: errorResponse(nil, 403, "no")}
	p := NewSecurityCheckPipeline([]SecurityCheck{blocking}, cfg, nil)
	resp := p.Execute(newTestRequest(t, nil))
	if resp == nil {
		t.Fatalf("hook panic must not affect the blocking verdict")
	}
}

func TestPipelineStalenessRebuildOnRevision(t *testing.T) {
	cfg := testConfig(t)
	rebuilds := 0
	p := NewSecurityCheckPipeline([]SecurityCheck{&fakeCheck{name: "a"}}, cfg, func() []SecurityCheck {
		rebuilds++
		return []SecurityCheck{&fakeCheck{name: "a"}}
	})
	p.Execute(newTestRequest(t, nil))
	if rebuilds != 0 {
		t.Fatalf("no rebuild expected without mutation, got %d", rebuilds)
	}
	cfg.BumpRevision()
	p.Execute(newTestRequest(t, nil))
	if rebuilds != 1 {
		t.Fatalf("revision bump must trigger exactly one rebuild, got %d", rebuilds)
	}
	p.Execute(newTestRequest(t, nil))
	if rebuilds != 1 {
		t.Fatalf("rebuild must not re-run while fresh, got %d", rebuilds)
	}
}

func TestPipelineStalenessRebuildOnContainerSignature(t *testing.T) {
	cfg := testConfig(t)
	rebuilds := 0
	p := NewSecurityCheckPipeline([]SecurityCheck{&fakeCheck{name: "a"}}, cfg, func() []SecurityCheck {
		rebuilds++
		return []SecurityCheck{&fakeCheck{name: "a"}}
	})
	p.Execute(newTestRequest(t, nil))
	cfg.EndpointRateLimits["/login"] = RateLimitEntry{Requests: 5, Window: 60}
	cfg.BumpRevision()
	p.Execute(newTestRequest(t, nil))
	if rebuilds != 1 {
		t.Fatalf("container signature change must trigger rebuild, got %d", rebuilds)
	}
}

func TestBuildDefaultPipelineImplementedSlots(t *testing.T) {
	cfg := testConfig(t)
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	p, _ := BuildDefaultPipeline(cfg, ban, rl, nil)
	names := p.CheckNames()
	want := []string{"route_config", "ip_security", "rate_limit", "suspicious_activity"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("expected pipeline %v with default config, got %v", want, names)
	}
}

func TestSentinelCheckFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	sentinel := &unsupportedCheck{name: "emergency_mode", excluded: false, applies: func(*SecurityConfig) bool { return true }}
	p := NewSecurityCheckPipeline([]SecurityCheck{sentinel}, cfg, nil)
	resp := p.Execute(newTestRequest(t, nil))
	if resp == nil || resp.StatusCode != 500 {
		t.Fatalf("fail-closed sentinel must yield 500 in fail-secure mode, got %+v", resp)
	}
}

func TestUnsupportedConfigFeaturesFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*SecurityConfig)
	}{
		{"enable_dynamic_rules", func(c *SecurityConfig) { c.EnableDynamicRules = true }},
		{"enable_agent", func(c *SecurityConfig) { c.EnableAgent = true }},
	}
	for _, tc := range cases {
		_, err := NewSecurityConfig(tc.mutate)
		var unsupported *UnsupportedFeatureError
		if !errors.As(err, &unsupported) {
			t.Fatalf("enabling %s must fail with UnsupportedFeatureError, got %v", tc.name, err)
		}
		if !strings.Contains(err.Error(), tc.name) {
			t.Fatalf("error should name the feature %s: %v", tc.name, err)
		}
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := testConfig(t)
	if !cfg.EnableRedis || cfg.RedisPrefix != "guard_core:" || cfg.RedisURL != "redis://localhost:6379" {
		t.Fatalf("bad redis defaults: %+v", cfg)
	}
	if !cfg.EnableIPBanning || cfg.AutoBanThreshold != 10 || cfg.AutoBanDuration != 3600 {
		t.Fatalf("bad ban defaults: %+v", cfg)
	}
	if !cfg.EnableRateLimiting || cfg.RateLimit != 10 || cfg.RateLimitWindow != 60 {
		t.Fatalf("bad rate limit defaults: %+v", cfg)
	}
	if !cfg.EnablePenetrationDetection || len(cfg.EnabledDetectionCategories) != len(AllDetectionCategories) {
		t.Fatalf("bad detection defaults")
	}
	if !cfg.FailSecure || cfg.PassiveMode {
		t.Fatalf("bad failure-policy defaults")
	}
	if cfg.TrustedProxyDepth != 1 {
		t.Fatalf("bad trusted_proxy_depth default")
	}
	sort.Strings(cfg.ExcludePaths)
	want := append([]string(nil), DefaultExcludePaths...)
	sort.Strings(want)
	if strings.Join(cfg.ExcludePaths, ",") != strings.Join(want, ",") {
		t.Fatalf("bad exclude_paths default: %v", cfg.ExcludePaths)
	}
}

func TestConfigValidationRejections(t *testing.T) {
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.TrustedProxyDepth = 0 }); err == nil {
		t.Fatalf("trusted_proxy_depth=0 must be rejected")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.RateLimit = 0 }); err == nil {
		t.Fatalf("rate_limit=0 must be rejected")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.Blacklist = []string{"not-an-ip"} }); err == nil {
		t.Fatalf("invalid blacklist entry must be rejected")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.ThreatBanConfig = map[string]ThreatBanEntry{"made_up": {Threshold: 3, Duration: 60}}
	}); err == nil {
		t.Fatalf("unknown threat_ban_config category must be rejected")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnabledDetectionCategories = []string{"xss", "nope"}
	}); err == nil {
		t.Fatalf("unknown detection category must be rejected")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.MutedCheckLogs = map[string]bool{"not_a_check": true}
	}); err == nil {
		t.Fatalf("unknown muted check name must be rejected")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnabledDetectionCategories = nil
	}); err == nil {
		t.Fatalf("detection enabled with empty category set must be rejected")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.ExcludePaths = []string{"relative"} }); err == nil {
		t.Fatalf("relative exclude path must be rejected")
	}
}

func TestRequestContract(t *testing.T) {
	factory := NewRequestFactory()
	req := factory.CreateRequest(RequestOptions{
		Path: "/api/users", Scheme: "https", Host: "example.com", RawQuery: "a=1&b=2",
		Method: "post", ClientHost: "203.0.113.5",
		Header: map[string]string{"X-Custom": "yes"},
		Body:   []byte("payload"),
	})
	if req.Method() != "POST" {
		t.Fatalf("method must be upper-cased, got %q", req.Method())
	}
	if req.URLPath() != "/api/users" || req.URLScheme() != "https" {
		t.Fatalf("bad path/scheme: %q %q", req.URLPath(), req.URLScheme())
	}
	if req.URLFull() != "https://example.com/api/users?a=1&b=2" {
		t.Fatalf("bad full url: %q", req.URLFull())
	}
	if req.URLReplaceScheme("http") != "http://example.com/api/users?a=1&b=2" {
		t.Fatalf("bad replaced scheme: %q", req.URLReplaceScheme("http"))
	}
	if req.ClientHost() != "203.0.113.5" {
		t.Fatalf("bad client host")
	}
	if v, ok := req.Headers().Get("x-custom"); !ok || v != "yes" {
		t.Fatalf("headers must be case-insensitive")
	}
	if req.QueryParams()["b"] != "2" {
		t.Fatalf("bad query params: %v", req.QueryParams())
	}
	first, err := req.Body()
	if err != nil || string(first) != "payload" {
		t.Fatalf("bad body: %q %v", first, err)
	}
	second, _ := req.Body()
	if &first[0] != &second[0] {
		t.Fatalf("body must be cached and repeatable")
	}
	if req.State() == nil {
		t.Fatalf("state must never be nil")
	}
}

func TestResponseFactory(t *testing.T) {
	f := NewResponseFactory()
	resp := f.CreateResponse("no", 403)
	if resp.StatusCode != 403 || string(resp.Body) != "no" || resp.Headers == nil {
		t.Fatalf("bad create_response: %+v", resp)
	}
	resp.SetHeader("X-Test", "1")
	if resp.Headers["X-Test"] != "1" {
		t.Fatalf("response headers must be mutable")
	}
	redirect := f.CreateRedirectResponse("https://example.com/login", 302)
	if redirect.StatusCode != 302 || redirect.Headers["Location"] != "https://example.com/login" {
		t.Fatalf("bad redirect response: %+v", redirect)
	}
}

func TestIPSecurityCheckBypassMatrix(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.Blacklist = []string{"203.0.113.9"} })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	check := &ipSecurityCheck{cfg: cfg, ban: ban, name: "ip_security"}

	req := newTestRequest(t, nil)
	if resp := check.Check(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("blacklisted IP must be blocked with 403, got %+v", resp)
	}

	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.BypassChecks = []string{"ip"}
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("ip bypass must skip restrictions, got %+v", resp)
	}

	bannedIP := "198.51.100.7"
	if _, err := ban.Ban(bannedIP, 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.BypassChecks = []string{"ip"}
		state.ClientIP = bannedIP
	})
	if resp := check.Check(req); resp == nil || resp.StatusCode != 403 || string(resp.Body) != IPBanBlockedMessage {
		t.Fatalf("ip bypass must keep banned-IP sub-check enforced, got %+v", resp)
	}

	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.BypassChecks = []string{"ip_ban"}
		state.ClientIP = bannedIP
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("ip_ban bypass must skip the banned-IP sub-check, got %+v", resp)
	}
}

func TestIPSecurityCheckSkipsWithoutClientIP(t *testing.T) {
	cfg := testConfig(t)
	check := &ipSecurityCheck{cfg: cfg, ban: NewIPBanManager(nil, nil), name: "ip_security"}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ""
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("check must skip without any client identity, got %+v", resp)
	}
}

func TestIPSecurityCheckExclusionScopedGlobalOnly(t *testing.T) {
	cfg := testConfig(t)
	check := &ipSecurityCheck{cfg: cfg, ban: NewIPBanManager(nil, nil), name: "ip_security"}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ExclusionScoped = true
		state.ClientIP = "203.0.113.9"
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("non-restricted IP must pass global-only scope, got %+v", resp)
	}
}

func TestIPSecurityCheckWhitelistRestrictive(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.Whitelist = []string{"203.0.113.0/24"} })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	check := &ipSecurityCheck{cfg: cfg, ban: NewIPBanManager(nil, nil), name: "ip_security"}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ClientIP = "198.51.100.1"
	})
	if resp := check.Check(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("non-whitelisted IP must be blocked, got %+v", resp)
	}
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ClientIP = "203.0.113.77"
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("whitelisted IP must pass, got %+v", resp)
	}
	if !req.State().IsWhitelisted {
		t.Fatalf("whitelist match must set state.IsWhitelisted")
	}
}

func TestRateLimitCheckBlocksAndBypasses(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.RateLimit = 1
		c.RateLimitWindow = 60
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	rl.now = func() float64 { return 1000.0 }
	check := &rateLimitCheck{cfg: cfg, manager: rl}

	mk := func(bypass []string) Request {
		return newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
			state.ClientIP = "203.0.113.9"
			state.BypassChecks = bypass
		})
	}
	if resp := check.Check(mk(nil)); resp != nil {
		t.Fatalf("first request must pass, got %+v", resp)
	}
	resp := check.Check(mk(nil))
	if resp == nil || resp.StatusCode != 429 {
		t.Fatalf("second request must be rate limited with 429, got %+v", resp)
	}
	if resp := check.Check(mk([]string{"rate_limit"})); resp != nil {
		t.Fatalf("rate_limit bypass must skip the check, got %+v", resp)
	}
}

func TestRateLimitCheckDisabledWhenGated(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.EnableRateLimiting = false })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	check := &rateLimitCheck{cfg: cfg, manager: NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, nil)}
	if check.AppliesTo(cfg) {
		t.Fatalf("rate_limit must not apply when disabled and no endpoint limits")
	}
}

func TestSuspiciousActivityDetectsAndBlocks(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.AutoBanThreshold = 100
		c.AutoBanDuration = 600
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	check := &suspiciousActivityCheck{cfg: cfg, ban: ban, counts: &suspiciousCountStore{m: map[string]map[string]int{}}}

	clean := newTestRequest(t, nil)
	if resp := check.Check(clean); resp != nil {
		t.Fatalf("benign request must pass, got %+v", resp)
	}

	evilly := func(mutate func(*RequestState)) Request {
		return newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
			opts.Path = "/search"
			opts.RawQuery = "q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
			opts.QueryParams = map[string]string{"q": "1' UNION SELECT username,password FROM users--"}
			mutate(state)
		})
	}
	resp := check.Check(evilly(func(state *RequestState) {}))
	if resp == nil || resp.StatusCode != 400 || string(resp.Body) != SuspiciousBlockedMsg {
		t.Fatalf("threat must be blocked with 400 'Suspicious activity detected', got %+v", resp)
	}

	resp = check.Check(evilly(func(state *RequestState) { state.BypassChecks = []string{"penetration"} }))
	if resp != nil {
		t.Fatalf("penetration bypass must suppress detection, got %+v", resp)
	}

	for i := 0; i < cfg.AutoBanThreshold; i++ {
		resp = check.Check(evilly(func(state *RequestState) {}))
	}
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != SuspiciousBannedMsg {
		t.Fatalf("threshold must escalate to ban with 403, got %+v", resp)
	}
	if !ban.IsIPBanned("203.0.113.9") {
		t.Fatalf("ban manager must hold the escalated ban")
	}
}

func TestSuspiciousActivityPassiveModeLogsOnly(t *testing.T) {
	var fired []map[string]any
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.PassiveMode = true
		c.OnBlock = func(req Request, payload map[string]any) { fired = append(fired, payload) }
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	check := &suspiciousActivityCheck{cfg: cfg, ban: NewIPBanManager(nil, nil), counts: &suspiciousCountStore{m: map[string]map[string]int{}}}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Path = "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"
		opts.QueryParams = map[string]string{"q": "1' UNION SELECT password FROM users--"}
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("passive mode must never block, got %+v", resp)
	}
	if len(fired) != 1 {
		t.Fatalf("passive mode must fire on_block inline once, got %d", len(fired))
	}
	if fired[0]["passive_mode"] != true {
		t.Fatalf("passive payload must set passive_mode=true: %v", fired[0])
	}
	if fired[0]["status_code"] != nil {
		t.Fatalf("passive payload status_code must be null, got %v", fired[0]["status_code"])
	}
}

func TestSuspiciousCategoryThresholdUsesThreatBanConfig(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.AutoBanThreshold = 100
		c.ThreatBanConfig = map[string]ThreatBanEntry{"sqli": {Threshold: 2, Duration: 55}}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	check := &suspiciousActivityCheck{cfg: cfg, ban: ban, counts: &suspiciousCountStore{m: map[string]map[string]int{}}}
	mk := func() Request {
		return newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
			opts.Path = "/search"
			opts.RawQuery = "q=1%27%20UNION%20SELECT%20password%20FROM%20users--"
			opts.QueryParams = map[string]string{"q": "1' UNION SELECT password FROM users--"}
		})
	}
	if resp := check.Check(mk()); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("first violation tracks only, got %+v", resp)
	}
	resp := check.Check(mk())
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("second sqli violation must hit category threshold ban, got %+v", resp)
	}
	if !ban.IsIPBanned("203.0.113.9") {
		t.Fatalf("category ban must be recorded in the ban manager")
	}
}
