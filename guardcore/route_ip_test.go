package guardcore

// Engine-level tests for the per-route RouteConfig.IPWhitelist/IPBlacklist
// enforcement in the ip_security check. Semantics mirror the reference
// check_route_ip_access (guard_core/core/checks/helpers.py) and its
// TypeScript port checkRouteIpAccess
// (packages/core/src/core/checks/helpers.ts): the route blacklist denies
// first, a configured route whitelist takes over the route verdict, the
// global lists still apply afterwards, and a route IPWhitelist clears the
// IsWhitelisted/IsExempt identity flags exactly like the reference
// skip_ip_lists gate (_resolve_is_whitelisted/_resolve_is_exempt in
// guard_core/core/checks/implementations/ip_security.py).

import (
	"fmt"
	"testing"
)

const (
	routeIPTestIP     = "192.0.2.50"
	routeIPOtherIP    = "192.0.2.60"
	routeIPTestRoute  = "/api/private"
	routeIPOtherRoute = "/api/open"
)

// newRouteIPTestPipeline builds the default pipeline without Redis plus a
// route registry pre-registering one route configured by mutate.
func newRouteIPTestPipeline(t *testing.T, routeID string, route func(*RouteConfig), mutate func(*SecurityConfig)) (*SecurityCheckPipeline, *RouteRegistry) {
	t.Helper()
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	rl.now = func() float64 { return 1000.0 }
	routes := NewRouteRegistry()
	routes.Register(routeID, route)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, routes)
	return pipeline, routes
}

func routeIPRequest(t *testing.T, clientIP, routeID string) Request {
	t.Helper()
	return newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Path = routeID
		opts.ClientHost = clientIP
		state.GuardRouteID = routeID
	})
}

// A route whitelist miss denies the route even when no global list would,
// and a route whitelist match passes the route stage where the same IP would
// be denied by the route verdict alone; the global lists keep the final say
// either way (the TS checkRouteIpAccess contract).
func TestRouteIPWhitelistTakesOverTheRouteVerdict(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPWhitelist = []string{routeIPTestIP}
	}, nil)
	req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("route whitelist match must pass, got %+v", resp)
	}
	req = routeIPRequest(t, routeIPOtherIP, routeIPTestRoute)
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("route whitelist miss must be denied although the global lists pass everyone, got %+v", resp)
	}
}

// A route whitelist miss denies even when no global list would.
func TestRouteIPWhitelistMissDenies(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPWhitelist = []string{routeIPOtherIP}
	}, nil)
	req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("route whitelist miss must be denied with 403 Forbidden, got %+v", resp)
	}
	if req.State().BlockStash == nil || req.State().BlockStash.Reason != fmt.Sprintf("IP not allowed by route config: %s", routeIPTestIP) {
		t.Fatalf("route denial must stash the route-config reason, got %+v", req.State().BlockStash)
	}
}

// A route blacklist blocks its match even though the global lists would pass
// everyone, and leaves other IPs and other routes untouched.
func TestRouteIPBlacklistBlocksWhereGlobalPasses(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPBlacklist = []string{routeIPTestIP}
	}, nil)
	req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("route blacklist match must be denied with 403 Forbidden, got %+v", resp)
	}
	for _, tc := range []struct{ ip, route string }{
		{routeIPOtherIP, routeIPTestRoute},
		{routeIPTestIP, routeIPOtherRoute},
	} {
		req := routeIPRequest(t, tc.ip, tc.route)
		if resp := pipeline.Execute(req); resp != nil {
			t.Fatalf("ip %s on %s must pass, got %+v", tc.ip, tc.route, resp)
		}
	}
}

// The route blacklist wins over the route whitelist when an IP appears in
// both (the TS port checks ipBlacklist before ipWhitelist).
func TestRouteIPBlacklistBeatsRouteWhitelist(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPWhitelist = []string{routeIPTestIP}
		rc.IPBlacklist = []string{routeIPTestIP}
	}, nil)
	req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("IP in both route lists must be denied, got %+v", resp)
	}
}

// A route whitelist match never relaxes the global lists (the ruled NO):
// a globally blacklisted IP that the route whitelist allows is still denied
// by the global stage, and so is an IP the global whitelist would reject.
func TestRouteIPWhitelistDoesNotRelaxGlobalLists(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPWhitelist = []string{routeIPTestIP}
	}, func(c *SecurityConfig) {
		c.Blacklist = []string{routeIPTestIP}
	})
	req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("globally blacklisted IP must stay denied despite the route whitelist match, got %+v", resp)
	}
	pipeline, _ = newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPWhitelist = []string{routeIPTestIP}
	}, func(c *SecurityConfig) {
		c.Whitelist = []string{routeIPOtherIP}
	})
	req = routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	resp = pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("IP outside the global whitelist must stay denied despite the route whitelist match, got %+v", resp)
	}
}

// A route IPWhitelist clears both identity flags for the request even when
// the IP passes the global whitelist and the exempt list (the reference
// _resolve_is_whitelisted/_resolve_is_exempt receive skip_ip_lists=True and
// return False for both). With no route override the flags keep their
// meaning.
func TestRouteIPWhitelistClearsIdentityFlags(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPWhitelist = []string{routeIPTestIP}
	}, func(c *SecurityConfig) {
		c.Whitelist = []string{routeIPTestIP}
		c.ExemptIPs = []string{routeIPTestIP}
	})
	req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("route whitelist match must pass, got %+v", resp)
	}
	if req.State().IsWhitelisted || req.State().IsExempt {
		t.Fatalf("route ipWhitelist override must clear both flags (whitelisted=%v exempt=%v)",
			req.State().IsWhitelisted, req.State().IsExempt)
	}
	req = routeIPRequest(t, routeIPTestIP, routeIPOtherRoute)
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("global whitelist match must pass off the decorated route, got %+v", resp)
	}
	if !req.State().IsWhitelisted || !req.State().IsExempt {
		t.Fatalf("without the route override both flags must set (whitelisted=%v exempt=%v)",
			req.State().IsWhitelisted, req.State().IsExempt)
	}
}

// A route IPBlacklist alone leaves the identity flags alone: an exempt IP
// that is not route-blacklisted keeps IsExempt (and its rate-limit skip),
// while the same route still clears nothing for other IPs.
func TestRouteIPBlacklistKeepsIdentityFlags(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPBlacklist = []string{routeIPOtherIP}
	}, func(c *SecurityConfig) {
		c.RateLimit = 2
		c.RateLimitWindow = 60
		c.ExemptIPs = []string{routeIPTestIP}
	})
	for i := 0; i < 5; i++ {
		req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
		if resp := pipeline.Execute(req); resp != nil {
			t.Fatalf("exempt IP request %d must pass and keep its skip, got %+v", i+1, resp)
		}
		if !req.State().IsExempt {
			t.Fatalf("route ipBlacklist alone must not clear the exempt flag")
		}
	}
	req := routeIPRequest(t, routeIPOtherIP, routeIPTestRoute)
	if resp := pipeline.Execute(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("route-blacklisted IP must be denied, got %+v", resp)
	}
}

// Without route IP lists the global behavior is byte-for-byte unchanged:
// global blacklist denies on a registered route too, and the global exempt
// flag survives.
func TestNoRouteIPListsKeepsGlobalBehavior(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.RateLimit = 10
	}, func(c *SecurityConfig) {
		c.Blacklist = []string{routeIPTestIP}
		c.ExemptIPs = []string{routeIPOtherIP}
		c.Whitelist = []string{routeIPOtherIP}
	})
	req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("global blacklist must deny on a route without IP lists, got %+v", resp)
	}
	if req.State().IsExempt || req.State().IsWhitelisted {
		t.Fatalf("a denied request must carry neither flag")
	}
	ok := routeIPRequest(t, routeIPOtherIP, routeIPTestRoute)
	if resp := pipeline.Execute(ok); resp != nil {
		t.Fatalf("whitelisted IP must pass, got %+v", resp)
	}
	if !ok.State().IsWhitelisted || !ok.State().IsExempt {
		t.Fatalf("whitelist+exempt flags must survive a route without IP lists (whitelisted=%v exempt=%v)",
			ok.State().IsWhitelisted, ok.State().IsExempt)
	}
}

// The exemption the route override clears is the real skip: with a route
// IPWhitelist in play the exempt flag never sets, so rate limiting counts the
// exempt IP again and trips 429 at the crossing.
func TestRouteIPWhitelistOverrideRestoresRateLimiting(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPWhitelist = []string{routeIPTestIP}
	}, func(c *SecurityConfig) {
		c.RateLimit = 2
		c.RateLimitWindow = 60
		c.ExemptIPs = []string{routeIPTestIP}
	})
	for i := 0; i < 2; i++ {
		req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
		if resp := pipeline.Execute(req); resp != nil {
			t.Fatalf("request %d must pass, got %+v", i+1, resp)
		}
	}
	req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 429 {
		t.Fatalf("exempt flag cleared by the route override: rate limit must trip with 429, got %+v", resp)
	}
}

// Passive mode stashes the route denial but lets the request through.
func TestRouteIPDenialPassiveModeOnlyStashes(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPBlacklist = []string{routeIPTestIP}
	}, func(c *SecurityConfig) {
		c.PassiveMode = true
	})
	req := routeIPRequest(t, routeIPTestIP, routeIPTestRoute)
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("passive mode must not block, got %+v", resp)
	}
	if req.State().BlockStash == nil || req.State().BlockStash.TriggerInfo != "ip_restriction" {
		t.Fatalf("passive mode must stash the route denial, got %+v", req.State().BlockStash)
	}
}

// The exclusion-scoped path ignores route IP rules entirely, like the
// reference which passes route_config=None there.
func TestExclusionScopedPathIgnoresRouteIPRules(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPBlacklist = []string{routeIPTestIP}
		rc.IPWhitelist = []string{routeIPOtherIP}
	}, func(c *SecurityConfig) {
		c.ExcludePaths = []string{routeIPTestRoute}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Path = routeIPTestRoute
		opts.ClientHost = routeIPTestIP
		state.GuardRouteID = routeIPTestRoute
		state.ExclusionScoped = true
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("exclusion-scoped request must not run route IP rules, got %+v", resp)
	}
	if req.State().BlockStash != nil {
		t.Fatalf("exclusion-scoped request must not stash a route denial, got %+v", req.State().BlockStash)
	}
}

// The ip bypass clears the whole check, route rules included.
func TestIPBypassSkipsRouteIPRules(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPBlacklist = []string{routeIPTestIP}
	}, nil)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Path = routeIPTestRoute
		opts.ClientHost = routeIPTestIP
		state.GuardRouteID = routeIPTestRoute
		state.BypassChecks = []string{"ip"}
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("ip bypass must skip the route IP rules, got %+v", resp)
	}
}

// Route CIDR entries match like the global lists (ipMatchesList semantics).
func TestRouteIPListsMatchCIDREntries(t *testing.T) {
	pipeline, _ := newRouteIPTestPipeline(t, routeIPTestRoute, func(rc *RouteConfig) {
		rc.IPWhitelist = []string{"192.0.2.48/28"}
		rc.IPBlacklist = []string{"192.0.2.32/28"}
	}, nil)
	req := routeIPRequest(t, "192.0.2.51", routeIPTestRoute)
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("CIDR whitelist match must pass, got %+v", resp)
	}
	req = routeIPRequest(t, "192.0.2.33", routeIPTestRoute)
	if resp := pipeline.Execute(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("CIDR blacklist match must be denied, got %+v", resp)
	}
}
