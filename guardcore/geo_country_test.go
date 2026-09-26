package guardcore

// Engine-level tests for the geo country rules in the ip_security check.
// Semantics mirror the reference _resolve_country_verdict,
// _check_blocked_countries_detail and check_country_access
// (guard_core/_utils/access_control.py plus guard_core/core/checks/helpers.py):
// the global lists decide first, the country stage runs after them (skipped
// for a global whitelist or a route allow_countries match), loopback IPs are
// exempt from the global stage only, an unresolved country fails closed in
// allowlist mode and open in blocklist mode, and the exempt flag still only
// sets once every deny check passed.

import (
	"fmt"
	"testing"
)

// fakeCountryResolver answers from a fixed ip -> country code table; misses
// mirror the reference get_country returning None.
type fakeCountryResolver map[string]string

func (f fakeCountryResolver) GetCountry(ip string) (string, bool) {
	code, ok := f[ip]
	return code, ok
}

func newGeoTestPipeline(t *testing.T, mutate func(*SecurityConfig)) (*SecurityCheckPipeline, *SecurityConfig) {
	t.Helper()
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	rl.now = func() float64 { return 1000.0 }
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, NewRouteRegistry())
	return pipeline, cfg
}

func newGeoTestPipelineWithRoute(t *testing.T, routeID string, route func(*RouteConfig), mutate func(*SecurityConfig)) (*SecurityCheckPipeline, *RouteRegistry) {
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

const (
	geoUSIP    = "192.0.2.7"
	geoBRIP    = "198.51.100.5"
	geoRouteID = "/api/geo"
)

// A blocked-country IP is denied 403 with the reference block reason and the
// country_restriction trigger, while other countries pass untouched.
func TestBlockedCountryIPDenies(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		blocked bool
		reason  string
	}{
		{"blocked country", geoUSIP, true, "IP from blocked country: US"},
		{"other country", geoBRIP, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline, _ := newGeoTestPipeline(t, func(c *SecurityConfig) {
				c.BlockedCountries = []string{"US"}
				c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US", geoBRIP: "BR"}
			})
			req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
				opts.ClientHost = tc.ip
			})
			resp := pipeline.Execute(req)
			if !tc.blocked {
				if resp != nil {
					t.Fatalf("non-blocked country must pass, got %+v", resp)
				}
				return
			}
			if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
				t.Fatalf("blocked country must deny 403 Forbidden, got %+v", resp)
			}
			if req.State().BlockStash == nil || req.State().BlockStash.Reason != tc.reason {
				t.Fatalf("block stash must carry the reference reason %q, got %+v", tc.reason, req.State().BlockStash)
			}
			if req.State().BlockStash.TriggerInfo != "country_restriction" {
				t.Fatalf("block stash must carry country_restriction, got %+v", req.State().BlockStash)
			}
		})
	}
}

// A non-empty whitelist_countries is restrictive: listed countries pass,
// unlisted ones are denied, and an unresolved country fails closed.
func TestAllowedCountryListIsRestrictive(t *testing.T) {
	pipeline, _ := newGeoTestPipeline(t, func(c *SecurityConfig) {
		c.WhitelistCountries = []string{"DE"}
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US", geoBRIP: "DE"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoBRIP
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("allowed country must pass, got %+v", resp)
	}
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("unlisted country must deny 403 Forbidden, got %+v", resp)
	}
	if req.State().BlockStash == nil || req.State().BlockStash.Reason != "IP from blocked country: US" {
		t.Fatalf("resolved non-allowed country must stash the country reason, got %+v", req.State().BlockStash)
	}
}

func TestUnresolvedCountryVerdictDependsOnMode(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*SecurityConfig)
		shouldBlock  bool
		expectReason string
	}{
		{"allowlist fails closed", func(c *SecurityConfig) {
			c.WhitelistCountries = []string{"US"}
			c.GeoIPHandler = fakeCountryResolver{}
		}, true, fmt.Sprintf("IP %s not in global allowlist/blocklist", geoUSIP)},
		{"blocklist fails open", func(c *SecurityConfig) {
			c.BlockedCountries = []string{"US"}
			c.GeoIPHandler = fakeCountryResolver{}
		}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline, _ := newGeoTestPipeline(t, tc.mutate)
			req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
				opts.ClientHost = geoUSIP
			})
			resp := pipeline.Execute(req)
			if tc.shouldBlock {
				if resp == nil || resp.StatusCode != 403 {
					t.Fatalf("unresolved country in allowlist mode must deny, got %+v", resp)
				}
				if req.State().BlockStash == nil || req.State().BlockStash.Reason != tc.expectReason {
					t.Fatalf("unresolved allowlist denial must stash the generic reason, got %+v", req.State().BlockStash)
				}
				return
			}
			if resp != nil {
				t.Fatalf("unresolved country in blocklist mode must pass, got %+v", resp)
			}
		})
	}
}

// Loopback IPs are exempt from the global country stage: they pass even in
// allowlist mode where any resolution would fail.
func TestLoopbackExemptFromGlobalCountryCheck(t *testing.T) {
	pipeline, _ := newGeoTestPipeline(t, func(c *SecurityConfig) {
		c.WhitelistCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "127.0.0.1"
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("loopback must be exempt from the country allowlist, got %+v", resp)
	}
}

// A global whitelist match skips the country stage: a whitelisted IP from a
// blocked country passes and keeps its identity flag.
func TestGlobalWhitelistMatchSkipsCountries(t *testing.T) {
	pipeline, _ := newGeoTestPipeline(t, func(c *SecurityConfig) {
		c.Whitelist = []string{geoUSIP}
		c.BlockedCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("whitelisted IP must bypass the country block, got %+v", resp)
	}
	if !req.State().IsWhitelisted {
		t.Fatalf("whitelist match must set the identity flag")
	}
}

// exempt_ips never opens the country gate: an exempt IP from a blocked
// country is denied, and the exempt flag only sets once the country stage
// passed.
func TestExemptIPStillSubjectToCountryRules(t *testing.T) {
	pipeline, _ := newGeoTestPipeline(t, func(c *SecurityConfig) {
		c.ExemptIPs = []string{geoUSIP, geoBRIP}
		c.BlockedCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US", geoBRIP: "BR"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
	})
	if resp := pipeline.Execute(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("exempt IP from a blocked country must stay denied, got %+v", resp)
	}
	if req.State().IsExempt {
		t.Fatalf("a country-denied request must not carry the exempt flag")
	}
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoBRIP
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("exempt IP from an allowed country must pass, got %+v", resp)
	}
	if !req.State().IsExempt {
		t.Fatalf("exempt flag must survive the country stage")
	}
}

// Route-level country rules: blocked_countries denies on the decorated
// route only, and an allow_countries match clears the global country stage
// for the request.
func TestRouteCountryListsCombineWithGlobalStage(t *testing.T) {
	pipeline, _ := newGeoTestPipelineWithRoute(t, geoRouteID, func(rc *RouteConfig) {
		rc.BlockedCountries = []string{"US"}
	}, func(c *SecurityConfig) {
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
		state.GuardRouteID = geoRouteID
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("route blocked country must deny 403 Forbidden, got %+v", resp)
	}
	if req.State().BlockStash == nil || req.State().BlockStash.Reason != fmt.Sprintf("IP not allowed by route config: %s", geoUSIP) {
		t.Fatalf("route denial must stash the route-config reason, got %+v", req.State().BlockStash)
	}
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("route country rules must not leak off the route, got %+v", resp)
	}
}

func TestRouteAllowedCountriesIsRestrictive(t *testing.T) {
	pipeline, _ := newGeoTestPipelineWithRoute(t, geoRouteID, func(rc *RouteConfig) {
		rc.WhitelistCountries = []string{"DE"}
	}, func(c *SecurityConfig) {
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US", geoBRIP: "DE"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoBRIP
		state.GuardRouteID = geoRouteID
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("route allowed country must pass, got %+v", resp)
	}
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
		state.GuardRouteID = geoRouteID
	})
	if resp := pipeline.Execute(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("route country allowlist miss must deny, got %+v", resp)
	}
}

// Unlike the global stage, the route country check has no loopback
// exemption: an unresolvable loopback IP denies under a route allowlist
// (the reference check_country_access answers False for an unresolved
// country).
func TestRouteAllowedCountriesHasNoLoopbackExemption(t *testing.T) {
	pipeline, _ := newGeoTestPipelineWithRoute(t, geoRouteID, func(rc *RouteConfig) {
		rc.WhitelistCountries = []string{"US"}
	}, func(c *SecurityConfig) {
		c.GeoIPHandler = fakeCountryResolver{}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "127.0.0.1"
		state.GuardRouteID = geoRouteID
	})
	if resp := pipeline.Execute(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("unresolved loopback must deny under the route allowlist, got %+v", resp)
	}
}

// A route blocked_countries match beats a route IPWhitelist match (the
// reference combines the verdicts: any deny denies), and the global stage
// still applies afterwards.
func TestRouteCountryDenialBeatsRouteIPWhitelist(t *testing.T) {
	pipeline, _ := newGeoTestPipelineWithRoute(t, geoRouteID, func(rc *RouteConfig) {
		rc.IPWhitelist = []string{geoUSIP}
		rc.BlockedCountries = []string{"US"}
	}, func(c *SecurityConfig) {
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
		state.GuardRouteID = geoRouteID
	})
	if resp := pipeline.Execute(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("country denial must beat the route IP whitelist match, got %+v", resp)
	}
}

// A route allow_countries match skips the global country stage: an IP whose
// country the route allows passes even when the same country is globally
// blocked.
func TestRouteAllowedCountrySkipsGlobalCountries(t *testing.T) {
	pipeline, _ := newGeoTestPipelineWithRoute(t, geoRouteID, func(rc *RouteConfig) {
		rc.WhitelistCountries = []string{"US"}
	}, func(c *SecurityConfig) {
		c.BlockedCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
		state.GuardRouteID = geoRouteID
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("route allow_countries must clear the global country stage, got %+v", resp)
	}
	// Off the route the global block applies again.
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
	})
	if resp := pipeline.Execute(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("the global country block must apply off the decorated route, got %+v", resp)
	}
}

// Passive mode stashes the country denial but lets the request through.
func TestCountryDenialPassiveModeOnlyStashes(t *testing.T) {
	pipeline, _ := newGeoTestPipeline(t, func(c *SecurityConfig) {
		c.BlockedCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US"}
		c.PassiveMode = true
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("passive mode must not block, got %+v", resp)
	}
	if req.State().BlockStash == nil || req.State().BlockStash.TriggerInfo != "country_restriction" {
		t.Fatalf("passive mode must stash the country denial, got %+v", req.State().BlockStash)
	}
}

// The exclusion-scoped path ignores route country rules but keeps the
// global ones (the reference passes route_config=None there, and
// ip_security is enforced on excluded paths).
func TestExclusionScopedEnforcesGlobalCountries(t *testing.T) {
	pipeline, _ := newGeoTestPipelineWithRoute(t, geoRouteID, func(rc *RouteConfig) {
		rc.WhitelistCountries = []string{"US"}
	}, func(c *SecurityConfig) {
		c.BlockedCountries = []string{"US"}
		c.ExcludePaths = []string{geoRouteID}
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
		state.GuardRouteID = geoRouteID
		state.ExclusionScoped = true
	})
	if resp := pipeline.Execute(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("exclusion-scoped requests keep the global country block, got %+v", resp)
	}
}

// The ip bypass clears the whole stage, country rules included.
func TestIPBypassSkipsCountryChecks(t *testing.T) {
	pipeline, _ := newGeoTestPipeline(t, func(c *SecurityConfig) {
		c.BlockedCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{geoUSIP: "US"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
		state.BypassChecks = []string{"ip"}
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("ip bypass must skip the country rules, got %+v", resp)
	}
}

// Without country rules the check is byte-for-byte the pre-geo behavior:
// the resolver is never consulted.
func TestNoCountryRulesKeepsGlobalBehavior(t *testing.T) {
	resolver := fakeCountryResolver{geoUSIP: "US"}
	pipeline, cfg := newGeoTestPipeline(t, func(c *SecurityConfig) {
		c.Blacklist = []string{geoUSIP}
		c.GeoIPHandler = resolver
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoUSIP
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || req.State().BlockStash.Reason != "IP is blacklisted" {
		t.Fatalf("blacklist behavior must be unchanged without country rules, got %+v", resp)
	}
	// No country rules configured: the resolver must never be hit.
	counter := &countingCountryResolver{inner: resolver}
	cfg.GeoIPHandler = counter
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = geoBRIP
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("unlisted IP must pass, got %+v", resp)
	}
	if counter.calls != 0 {
		t.Fatalf("country rules off must never consult the resolver, got %d calls", counter.calls)
	}
}

type countingCountryResolver struct {
	inner CountryResolver
	calls int
}

func (c *countingCountryResolver) GetCountry(ip string) (string, bool) {
	c.calls++
	return c.inner.GetCountry(ip)
}
