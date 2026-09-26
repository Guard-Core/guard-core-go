package guardcore

// Engine-level port of the guard-core exempt_ips reference tests
// (tests/test_core/test_exempt_ips.py) against the acceptance checklist of
// specs/exempt-ips.md. The per-route decorator cases (route block_ip /
// require_ip taking over) are covered separately against the enforced
// RouteConfig.IPWhitelist/IPBlacklist semantics in route_ip_test.go.

import (
	"testing"
)

const (
	exemptTestIP  = "198.51.100.7"
	otherTestIP   = "203.0.113.9"
	exemptTestNet = "198.51.100.16/28"
)

// newExemptTestPipeline builds the default pipeline without Redis (in-memory
// ban and rate-limit stores) and freezes the rate-limit clock so limit trips
// are deterministic.
func newExemptTestPipeline(t *testing.T, mutate func(*SecurityConfig)) (*SecurityCheckPipeline, *IPBanManager) {
	t.Helper()
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	rl.now = func() float64 { return 1000.0 }
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, nil)
	return pipeline, ban
}

func exemptRequest(t *testing.T, clientIP string, mutate func(opts *RequestOptions, state *RequestState)) Request {
	t.Helper()
	return newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = clientIP
		if mutate != nil {
			mutate(opts, state)
		}
	})
}

// Checklist 1: an exempt IP (exact entry) exceeds rate_limit with only
// normal responses.
func TestExemptIPRateLimitIsSkipped(t *testing.T) {
	pipeline, _ := newExemptTestPipeline(t, func(c *SecurityConfig) {
		c.RateLimit = 2
		c.RateLimitWindow = 60
		c.ExemptIPs = []string{exemptTestIP}
	})
	for i := 0; i < 10; i++ {
		req := exemptRequest(t, exemptTestIP, nil)
		if resp := pipeline.Execute(req); resp != nil {
			t.Fatalf("exempt IP request %d must pass, got %+v", i+1, resp)
		}
	}
}

// Checklist 2: same, matched through a CIDR entry.
func TestExemptCIDRRateLimitIsSkipped(t *testing.T) {
	pipeline, _ := newExemptTestPipeline(t, func(c *SecurityConfig) {
		c.RateLimit = 2
		c.RateLimitWindow = 60
		c.ExemptIPs = []string{exemptTestNet}
	})
	for i := 0; i < 10; i++ {
		req := exemptRequest(t, "198.51.100.20", nil)
		if resp := pipeline.Execute(req); resp != nil {
			t.Fatalf("CIDR-exempt IP request %d must pass, got %+v", i+1, resp)
		}
	}
}

// Checklist 3: a non-exempt client on the same deployment still hits 429.
func TestNonExemptClientStillRateLimited(t *testing.T) {
	pipeline, _ := newExemptTestPipeline(t, func(c *SecurityConfig) {
		c.RateLimit = 2
		c.RateLimitWindow = 60
		c.ExemptIPs = []string{exemptTestIP}
	})
	for i := 0; i < 2; i++ {
		req := exemptRequest(t, otherTestIP, nil)
		if resp := pipeline.Execute(req); resp != nil {
			t.Fatalf("non-exempt request %d must pass, got %+v", i+1, resp)
		}
	}
	req := exemptRequest(t, otherTestIP, nil)
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 429 {
		t.Fatalf("non-exempt client must be rate limited with 429, got %+v", resp)
	}
}

// Checklist 4: with an empty whitelist, exempt_ips denies nobody, and only
// matching clients carry the flag (the Python reference pins is_whitelisted
// False alongside is_exempt True).
func TestExemptIPsWithoutWhitelistDenyNothing(t *testing.T) {
	pipeline, _ := newExemptTestPipeline(t, func(c *SecurityConfig) {
		c.ExemptIPs = []string{exemptTestIP, exemptTestNet}
	})
	for _, ip := range []string{exemptTestIP, "198.51.100.20", otherTestIP, "192.0.2.1"} {
		req := exemptRequest(t, ip, nil)
		if resp := pipeline.Execute(req); resp != nil {
			t.Fatalf("whitelist stays empty: %s must pass as before, got %+v", ip, resp)
		}
		want := ip == exemptTestIP || ip == "198.51.100.20"
		if req.State().IsExempt != want {
			t.Fatalf("ip %s: IsExempt = %v, want %v", ip, req.State().IsExempt, want)
		}
		if req.State().IsWhitelisted {
			t.Fatalf("ip %s: exemption must never set IsWhitelisted", ip)
		}
	}
}

// Reference: test_exempt_match_sets_the_flag_without_blocking_anyone, at the
// ip check level, including the no-client-identity case.
func TestExemptMatchSetsTheFlagWithoutBlockingAnyone(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.ExemptIPs = []string{exemptTestIP, exemptTestNet}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	check := &ipSecurityCheck{cfg: cfg, ban: NewIPBanManager(nil, nil), name: "ip_security"}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{exemptTestIP, true},
		{"198.51.100.20", true},
		{otherTestIP, false},
	} {
		req := exemptRequest(t, tc.ip, nil)
		if resp := check.Check(req); resp != nil {
			t.Fatalf("ip %s must pass, got %+v", tc.ip, resp)
		}
		if req.State().IsExempt != tc.want {
			t.Fatalf("ip %s: IsExempt = %v, want %v", tc.ip, req.State().IsExempt, tc.want)
		}
		if req.State().IsWhitelisted {
			t.Fatalf("ip %s: exemption must never set IsWhitelisted", tc.ip)
		}
	}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ""
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("unknown client must pass, got %+v", resp)
	}
	if req.State().IsExempt {
		t.Fatalf("unknown client must not get the exempt flag")
	}
}

// Checklist 5 / reference test_blacklisted_exempt_ip_is_still_blocked.
func TestBlacklistedExemptIPIsStillBlocked(t *testing.T) {
	pipeline, _ := newExemptTestPipeline(t, func(c *SecurityConfig) {
		c.Blacklist = []string{exemptTestIP}
		c.ExemptIPs = []string{exemptTestIP}
	})
	req := exemptRequest(t, exemptTestIP, nil)
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("blacklisted exempt IP must be blocked with 403, got %+v", resp)
	}
	if req.State().IsExempt {
		t.Fatalf("a denied request must not carry the exempt flag")
	}
}

// Checklist 6 / reference test_banned_exempt_ip_is_still_blocked.
func TestBannedExemptIPIsStillBlocked(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.ExemptIPs = []string{exemptTestIP}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(nil, nil)
	if applied, err := ban.Ban(exemptTestIP, 60, "test"); err != nil || !applied {
		t.Fatalf("ban: applied=%v err=%v", applied, err)
	}
	check := &ipSecurityCheck{cfg: cfg, ban: ban, name: "ip_security"}
	req := exemptRequest(t, exemptTestIP, nil)
	resp := check.Check(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != IPBanBlockedMessage {
		t.Fatalf("banned exempt IP must be blocked with 403 'IP address banned', got %+v", resp)
	}
	if req.State().IsExempt {
		t.Fatalf("a banned request must not carry the exempt flag")
	}
}

// Reference test_exempt_ip_does_not_pass_a_restrictive_whitelist: exemption
// never opens the whitelist gate, and listed IPs keep the whitelist behavior.
func TestExemptIPDoesNotPassARestrictiveWhitelist(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.Whitelist = []string{otherTestIP}
		c.ExemptIPs = []string{exemptTestIP}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	check := &ipSecurityCheck{cfg: cfg, ban: NewIPBanManager(nil, nil), name: "ip_security"}
	req := exemptRequest(t, exemptTestIP, nil)
	resp := check.Check(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("exempt IP must not pass a restrictive whitelist, got %+v", resp)
	}
	if req.State().IsExempt || req.State().IsWhitelisted {
		t.Fatalf("a denied request must carry neither flag (exempt=%v whitelisted=%v)",
			req.State().IsExempt, req.State().IsWhitelisted)
	}
	ok := exemptRequest(t, otherTestIP, nil)
	if resp := check.Check(ok); resp != nil {
		t.Fatalf("whitelist match must still pass, got %+v", resp)
	}
	if !ok.State().IsWhitelisted || ok.State().IsExempt {
		t.Fatalf("whitelist match must set only IsWhitelisted (exempt=%v whitelisted=%v)",
			ok.State().IsExempt, ok.State().IsWhitelisted)
	}
}

// Checklist 8 / reference test_penetration_detection_still_scans_an_exempt_request:
// the exempt flag must not reach the suspicious-activity check.
func TestPenetrationDetectionStillScansAnExemptRequest(t *testing.T) {
	pipeline, _ := newExemptTestPipeline(t, func(c *SecurityConfig) {
		c.AutoBanThreshold = 1000
		c.ExemptIPs = []string{exemptTestIP}
	})
	req := exemptRequest(t, exemptTestIP, func(opts *RequestOptions, state *RequestState) {
		opts.Path = "/search"
		opts.RawQuery = "q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
		opts.QueryParams = map[string]string{"q": "1' UNION SELECT username,password FROM users--"}
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 400 || string(resp.Body) != SuspiciousBlockedMsg {
		t.Fatalf("attack payload from an exempt IP must still be a 400 suspicious block, got %+v", resp)
	}
}

// The violation counting inside suspicious_activity is part of the same check
// the reference leaves untouched for exempt requests, so it keeps counting.
func TestExemptIPViolationsStillEscalateToBan(t *testing.T) {
	pipeline, ban := newExemptTestPipeline(t, func(c *SecurityConfig) {
		c.AutoBanThreshold = 3
		c.AutoBanDuration = 600
		c.ExemptIPs = []string{exemptTestIP}
	})
	malicious := func() Request {
		return exemptRequest(t, exemptTestIP, func(opts *RequestOptions, state *RequestState) {
			opts.Path = "/search"
			opts.RawQuery = "q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
			opts.QueryParams = map[string]string{"q": "1' UNION SELECT username,password FROM users--"}
		})
	}
	for i := 0; i < 2; i++ {
		resp := pipeline.Execute(malicious())
		if resp == nil || resp.StatusCode != 400 {
			t.Fatalf("violation %d must stay a 400, got %+v", i+1, resp)
		}
	}
	resp := pipeline.Execute(malicious())
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != SuspiciousBannedMsg {
		t.Fatalf("third violation must escalate to a 403 ban, got %+v", resp)
	}
	if !ban.IsIPBanned(exemptTestIP) {
		t.Fatalf("ban manager must hold the escalated ban for the exempt IP")
	}
}

// Reference test_user_agent_check_is_skipped_for_an_exempt_request.
func TestUserAgentCheckIsSkippedForAnExemptRequest(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BlockedUserAgents = []string{"badbot"}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	check := &userAgentCheck{cfg: cfg}
	exempt := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Header = map[string]string{"User-Agent": "badbot/1.0"}
		state.IsExempt = true
	})
	if resp := check.Check(exempt); resp != nil {
		t.Fatalf("exempt request must skip the user-agent check, got %+v", resp)
	}
	notExempt := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Header = map[string]string{"User-Agent": "badbot/1.0"}
	})
	if resp := check.Check(notExempt); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("non-exempt bad user agent must be blocked with 403, got %+v", resp)
	}
}

// Full-pipeline wiring: a blocked user agent passes for an exempt IP and is
// still blocked for everyone else.
func TestExemptIPUserAgentBlocksAreSkipped(t *testing.T) {
	pipeline, _ := newExemptTestPipeline(t, func(c *SecurityConfig) {
		c.BlockedUserAgents = []string{"badbot"}
		c.ExemptIPs = []string{exemptTestIP}
	})
	req := exemptRequest(t, exemptTestIP, func(opts *RequestOptions, state *RequestState) {
		opts.Header = map[string]string{"User-Agent": "badbot/1.0"}
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("exempt IP with blocked user agent must pass, got %+v", resp)
	}
	req = exemptRequest(t, otherTestIP, func(opts *RequestOptions, state *RequestState) {
		opts.Header = map[string]string{"User-Agent": "badbot/1.0"}
	})
	if resp := pipeline.Execute(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("non-exempt blocked user agent must 403, got %+v", resp)
	}
}

// Reference test_cloud_provider_check_is_skipped_for_an_exempt_request: the
// exempt flag skips cloud blocks whose selector list comes from the route.
func TestCloudProviderCheckIsSkippedForAnExemptRequestOnRouteBlocks(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS"}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	manager := NewCloudManager()
	manager.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8"), false)
	check := &cloudProviderCheck{cfg: cfg, manager: manager}
	exempt := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.0.0.1"
		state.IsExempt = true
		state.RouteConfig = &RouteConfig{BlockCloudProviders: []string{"AWS"}}
	})
	if resp := check.Check(exempt); resp != nil {
		t.Fatalf("exempt request must skip the route cloud block, got %+v", resp)
	}
	notExempt := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.0.0.1"
		state.RouteConfig = &RouteConfig{BlockCloudProviders: []string{"AWS"}}
	})
	if resp := check.Check(notExempt); resp == nil || resp.StatusCode != 403 || string(resp.Body) != CloudBlockedMsg {
		t.Fatalf("non-exempt cloud IP must be blocked with 403, got %+v", resp)
	}
}

// Reference test_global_cloud_block_still_applies_as_it_does_for_the_whitelist
// (exempt variant): the global block_cloud_providers list still blocks an
// exempt IP; only per-route cloud blocks are skipped.
func TestGlobalCloudBlockStillAppliesToAnExemptIP(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS"}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	manager := NewCloudManager()
	manager.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8"), false)
	check := &cloudProviderCheck{cfg: cfg, manager: manager}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.0.0.1"
		state.IsExempt = true
	})
	if resp := check.Check(req); resp == nil || resp.StatusCode != 403 || string(resp.Body) != CloudBlockedMsg {
		t.Fatalf("global cloud block must still apply to an exempt IP, got %+v", resp)
	}
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = otherTestIP
		state.IsExempt = true
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("exempt non-cloud IP must pass, got %+v", resp)
	}
}

// Checklist 9: an invalid exempt_ips entry is a config error at construction,
// and the field defaults to empty.
func TestExemptIPsInvalidEntryFailsClosed(t *testing.T) {
	for _, entry := range []string{"not-an-ip", "999.1.2.3", "198.51.100.0/99"} {
		if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.ExemptIPs = []string{entry} }); err == nil {
			t.Fatalf("invalid exempt_ips entry %q must fail config validation", entry)
		}
	}
	if got := DefaultSecurityConfig().ExemptIPs; len(got) != 0 {
		t.Fatalf("exempt_ips must default to empty, got %v", got)
	}
}

// Checklist 10: matching semantics are exactly the whitelist matcher's
// (ipMatchesList), including its exact-form canonicalization.
func TestExemptIPMatchingMirrorsTheWhitelistMatcher(t *testing.T) {
	cases := []struct {
		name    string
		client  string
		entries []string
		want    bool
	}{
		{"exact ipv4 entry", exemptTestIP, []string{exemptTestIP}, true},
		{"exact ipv6 entry", "2001:db8::1", []string{"2001:db8::1"}, true},
		{"ipv4-mapped entry with same-form client", "::ffff:198.51.100.8", []string{"::ffff:198.51.100.8"}, true},
		{"ipv4 cidr matches v4-mapped client", "::ffff:198.51.100.9", []string{"198.51.100.0/24"}, true},
		{"ipv4-mapped cidr matches mapped client", "::ffff:198.51.100.9", []string{"::ffff:198.51.100.0/120"}, true},
		{"ipv6 cidr entry", "2001:db8::1", []string{"2001:db8::/32"}, true},
		{"unlisted client", otherTestIP, []string{exemptTestIP}, false},
		{"mapped entry vs plain client follows the matcher", exemptTestIP, []string{"::ffff:" + exemptTestIP}, false},
	}
	for _, tc := range cases {
		cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.ExemptIPs = tc.entries })
		if err != nil {
			t.Fatalf("%s: config: %v", tc.name, err)
		}
		check := &ipSecurityCheck{cfg: cfg, ban: NewIPBanManager(nil, nil), name: "ip_security"}
		req := exemptRequest(t, tc.client, nil)
		if resp := check.Check(req); resp != nil {
			t.Fatalf("%s: request must pass the ip check, got %+v", tc.name, resp)
		}
		if req.State().IsExempt != tc.want {
			t.Fatalf("%s: IsExempt = %v, want %v", tc.name, req.State().IsExempt, tc.want)
		}
	}
}
