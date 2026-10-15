package guardcore

import "testing"

func noAddrRequest(t *testing.T, path string) Request {
	return newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ""
		opts.Path = path
	})
}

func TestCheckRejectsUnresolvableClientAddressUnderFailSecure(t *testing.T) {
	var hook map[string]any
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.FailSecure = true
		c.OnBlock = func(_ Request, payload map[string]any) { hook = payload }
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	resp := engine.Check(noAddrRequest(t, "/api"))
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != "Client address could not be determined" {
		t.Fatalf("want 403 Client address could not be determined, got %+v", resp)
	}
	if hook == nil || hook["check_name"] != "client_address_unresolved" || hook["passive_mode"] != false || hook["status_code"] != 403 {
		t.Fatalf("on_block hook payload mismatch: %+v", hook)
	}
}

func TestCheckUnresolvableClientAddressContinuesWithoutFailSecure(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) { c.FailSecure = false }))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if resp := engine.Check(noAddrRequest(t, "/api")); resp != nil {
		t.Fatalf("fail_secure=false must continue, got %+v", resp)
	}
}

func TestCheckUnresolvableClientAddressExcludedPathContinues(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.FailSecure = true
		c.ExcludePaths = []string{"/public"}
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if resp := engine.Check(noAddrRequest(t, "/public")); resp != nil {
		t.Fatalf("excluded path must continue (reference returns before the address check), got %+v", resp)
	}
}

func TestCheckUnresolvableClientAddressUnixTrustedProxyResolves(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.FailSecure = true
		c.TrustedProxies = []string{"unix"}
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ""
		opts.Header = map[string]string{"X-Forwarded-For": "198.51.100.7"}
	})
	if resp := engine.Check(req); resp != nil {
		t.Fatalf("a chain resolvable through the unix proxy must pass, got %+v", resp)
	}
}

func bypassReturnRuleEngine(t *testing.T, passive bool) *Engine {
	engine, err := NewEngine(mustBehaviorConfig(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.PassiveMode = passive
		c.GlobalBehaviorRules = []BehaviorRuleConfig{behaviorRule("return_pattern", "status:404", 1)}
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	engine.Routes.Register("open", func(rc *RouteConfig) { rc.BypassedChecks = []string{"all"} })
	return engine
}

func runReturn(t *testing.T, engine *Engine, route, path string) {
	for i := 0; i < 3; i++ {
		req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
			opts.Path = path
			state.GuardRouteID = route
		})
		engine.Check(req)
		engine.ProcessResponse(req, &Response{StatusCode: 404})
	}
}

func TestProcessResponseSkipsAllChecksBypassRoute(t *testing.T) {
	engine := bypassReturnRuleEngine(t, false)
	defer engine.Close()
	runReturn(t, engine, "open", "/api")
	if engine.Ban.IsIPBanned("203.0.113.9") {
		t.Fatalf("an all-checks bypass response must not run return rules")
	}
}

func TestProcessResponseMetricsFollowReferencePass(t *testing.T) {
	for name, tc := range map[string]struct {
		passive     bool
		route, path string
		wantMetrics bool
	}{
		"all-checks bypass":      {false, "open", "/api", false},
		"plain route":            {false, "guarded", "/api", true},
		"excluded path (scoped)": {false, "guarded", "/public", true},
		"passive bypass route":   {true, "open", "/api", true},
	} {
		t.Run(name, func(t *testing.T) {
			engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
				c.PassiveMode = tc.passive
				c.ExcludePaths = []string{"/public"}
			})
			engine.Routes.Register("open", func(rc *RouteConfig) { rc.BypassedChecks = []string{"all"} })
			req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
				opts.Path = tc.path
				state.GuardRouteID = tc.route
			})
			engine.Check(req)
			engine.ProcessResponse(req, &Response{StatusCode: 200})
			if got := len(agent.metrics) > 0; got != tc.wantMetrics {
				t.Fatalf("metrics collected = %v, want %v (%d metrics)", got, tc.wantMetrics, len(agent.metrics))
			}
		})
	}
}

func autobanEngine(t *testing.T, mutate func(*SecurityConfig)) *Engine {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.EnableRateLimiting = true
		c.RateLimit = 1
		c.RateLimitWindow = 60
		c.EnableIPBanning = true
		c.EnableRateLimitAutoBan = true
		c.AutoBanThreshold = 2
		c.AutoBanDuration = 60
		if mutate != nil {
			mutate(c)
		}
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return engine
}

func TestRateLimitCheckFeedsAutobanThroughEngineCheck(t *testing.T) {
	engine := autobanEngine(t, nil)
	var statuses []int
	for i := 0; i < 5; i++ {
		if resp := engine.Check(newTestRequest(t, nil)); resp != nil {
			statuses = append(statuses, resp.StatusCode)
		}
	}
	if !engine.Ban.IsIPBanned("203.0.113.9") {
		t.Fatalf("enable_rate_limit_auto_ban must ban after the threshold of rate-limit violations (statuses %v)", statuses)
	}
}

func TestRateLimitAutobanOffPassiveAndThreatEntry(t *testing.T) {
	run := func(engine *Engine) {
		for i := 0; i < 5; i++ {
			engine.Check(newTestRequest(t, nil))
		}
	}
	off := autobanEngine(t, func(c *SecurityConfig) { c.EnableRateLimitAutoBan = false })
	run(off)
	if off.Ban.IsIPBanned("203.0.113.9") {
		t.Fatal("autoban off must not ban")
	}
	passive := autobanEngine(t, func(c *SecurityConfig) { c.PassiveMode = true })
	run(passive)
	if passive.Ban.IsIPBanned("203.0.113.9") {
		t.Fatal("passive mode must not ban")
	}
	entry := autobanEngine(t, func(c *SecurityConfig) {
		c.AutoBanThreshold = 100
		c.ThreatBanConfig = map[string]ThreatBanEntry{"rate_limit": {Threshold: 1, Duration: 30}}
	})
	run(entry)
	if !entry.Ban.IsIPBanned("203.0.113.9") {
		t.Fatal("threat_ban_config[rate_limit] must override the flat threshold")
	}
}

func TestUnresolvableClientAddressResponseCarriesCORSHeaders(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, corsTestConfig(func(c *SecurityConfig) { c.FailSecure = true })))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ""
		opts.Header = map[string]string{"Origin": "https://app.example.com"}
	})
	resp := engine.Check(req)
	if resp == nil || resp.StatusCode != 403 || resp.Headers["Access-Control-Allow-Origin"] != "https://app.example.com" {
		t.Fatalf("the 403 must carry the reference passthrough CORS headers, got %+v", resp)
	}
}

func TestRecordAutobanTiersAndGuards(t *testing.T) {
	newCheck := func(mutate func(*SecurityConfig)) (*rateLimitCheck, *Engine) {
		engine := autobanEngine(t, func(c *SecurityConfig) {
			c.AutoBanThreshold = 1
			if mutate != nil {
				mutate(c)
			}
		})
		return &rateLimitCheck{cfg: engine.Config, manager: engine.RateLimit, ban: engine.Ban,
			counts: &suspiciousCountStore{m: map[string]map[string]int{}}}, engine
	}
	req := newTestRequest(t, nil)
	for _, outcome := range []*RateLimitOutcome{
		{Tier: "endpoint", Limit: 5, Window: 60},
		{Tier: "route", Limit: 5, Window: 60},
		{Tier: "geo", Limit: 5, Window: 60},
		{Tier: "geo", Limit: 5, Window: 60, Country: "US"},
		{Tier: "global"},
	} {
		check, engine := newCheck(nil)
		check.recordAutoban(req, "203.0.113.1", outcome)
		if !engine.Ban.IsIPBanned("203.0.113.1") {
			t.Fatalf("tier %q must ban at the flat threshold", outcome.Tier)
		}
	}

	check, engine := newCheck(func(c *SecurityConfig) { c.EnableIPBanning = false })
	check.recordAutoban(req, "198.51.100.1", &RateLimitOutcome{})
	if engine.Ban.IsIPBanned("198.51.100.1") || countFor(check.counts, "198.51.100.1", "rate_limit") != 1 {
		t.Fatal("banning disabled must only count")
	}

	check, _ = newCheck(nil)
	check.ban = nil
	check.recordAutoban(req, "198.51.100.2", &RateLimitOutcome{})

	check, engine = newCheck(func(c *SecurityConfig) { c.AutoBanThreshold = 5 })
	check.recordAutoban(req, "198.51.100.3", &RateLimitOutcome{})
	if engine.Ban.IsIPBanned("198.51.100.3") {
		t.Fatal("below the threshold must not ban")
	}

	check, engine = newCheck(nil)
	// Set after validation: the config rejects a zero duration, the ban call
	// is what refuses it.
	check.cfg.ThreatBanConfig = map[string]ThreatBanEntry{"rate_limit": {Threshold: 1, Duration: 0}}
	check.recordAutoban(req, "198.51.100.4", &RateLimitOutcome{})
	if engine.Ban.IsIPBanned("198.51.100.4") {
		t.Fatal("a failed ban call must not ban")
	}

	check, engine = newCheck(nil)
	check.recordAutoban(req, "127.0.0.1", &RateLimitOutcome{})
	if engine.Ban.IsIPBanned("127.0.0.1") {
		t.Fatal("the self-DoS guard must refuse a loopback ban")
	}
}
