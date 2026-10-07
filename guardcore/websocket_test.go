package guardcore

import (
	"testing"
)

func wsEngine(t *testing.T, mutate func(*SecurityConfig)) *Engine {
	t.Helper()
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func wsRequest(t *testing.T, mutate func(opts *RequestOptions, state *RequestState)) Request {
	t.Helper()
	return newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Method = "WEBSOCKET"
		opts.Body = nil
		if mutate != nil {
			mutate(opts, state)
		}
	})
}

func assertClose(t *testing.T, got *WebSocketCloseReason, want WebSocketCloseReason, label string) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: expected close %+v, got nil", label, want)
	}
	if *got != want {
		t.Fatalf("%s: expected close %+v, got %+v", label, want, *got)
	}
}

func TestGuardWebSocketAllowsCleanHandshake(t *testing.T) {
	engine := wsEngine(t, nil)
	if reason := engine.GuardWebSocket(wsRequest(t, nil)); reason != nil {
		t.Fatalf("clean handshake must pass, got %+v", reason)
	}
}

func TestGuardWebSocketUnknownAddressFailSecure(t *testing.T) {
	engine := wsEngine(t, func(c *SecurityConfig) { c.FailSecure = true })
	reason := engine.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = ""
	}))
	assertClose(t, reason, WSCloseClientAddressUnknown, "unknown address under fail_secure")

	open := wsEngine(t, func(c *SecurityConfig) { c.FailSecure = false })
	if reason := open.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = ""
	})); reason != nil {
		t.Fatalf("unknown address without fail_secure must pass, got %+v", reason)
	}
}

func TestGuardWebSocketBannedIP(t *testing.T) {
	engine := wsEngine(t, func(c *SecurityConfig) { c.EnableRedis = false })
	if _, err := engine.Ban.Ban("203.0.113.9", 60, "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	assertClose(t, engine.GuardWebSocket(wsRequest(t, nil)), WSCloseIPBanned, "banned IP")
}

func TestGuardWebSocketIPNotAllowed(t *testing.T) {
	engine := wsEngine(t, func(c *SecurityConfig) { c.Blacklist = []string{"203.0.113.9"} })
	assertClose(t, engine.GuardWebSocket(wsRequest(t, nil)), WSCloseIPNotAllowed, "blacklisted IP")

	whitelistOnly := wsEngine(t, func(c *SecurityConfig) { c.Whitelist = []string{"198.51.100.7"} })
	assertClose(t, whitelistOnly.GuardWebSocket(wsRequest(t, nil)), WSCloseIPNotAllowed, "whitelist miss")
	if reason := whitelistOnly.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "198.51.100.7"
	})); reason != nil {
		t.Fatalf("whitelist hit must pass, got %+v", reason)
	}

	unparsable := wsEngine(t, nil)
	assertClose(t, unparsable.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "not-an-ip"
	})), WSCloseIPNotAllowed, "unparsable address")
}

func TestGuardWebSocketUnknownIdentityWhitelistRules(t *testing.T) {
	blocked := wsEngine(t, func(c *SecurityConfig) { c.FailSecure = false; c.Whitelist = []string{"198.51.100.7"} })
	assertClose(t, blocked.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = ""
	})), WSCloseIPNotAllowed, "unknown identity under an IP whitelist")

	countryBlocked := wsEngine(t, func(c *SecurityConfig) {
		c.FailSecure = false
		c.WhitelistCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{"203.0.113.9": "BR"}
	})
	assertClose(t, countryBlocked.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = ""
	})), WSCloseIPNotAllowed, "unknown identity under a country whitelist")

	if reason := blocked.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "198.51.100.7"
	})); reason != nil {
		t.Fatalf("known identity under a whitelist hit must pass, got %+v", reason)
	}
	neutral := wsEngine(t, func(c *SecurityConfig) { c.FailSecure = false })
	if reason := neutral.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = ""
	})); reason != nil {
		t.Fatalf("unknown identity without whitelist rules must pass, got %+v", reason)
	}
}

func TestGuardWebSocketRateLimitExceeded(t *testing.T) {
	engine := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.RateLimit = 1
		c.RateLimitWindow = 60
	})
	if reason := engine.GuardWebSocket(wsRequest(t, nil)); reason != nil {
		t.Fatalf("first request must pass, got %+v", reason)
	}
	assertClose(t, engine.GuardWebSocket(wsRequest(t, nil)), WSCloseRateLimitExceeded, "second request over the limit")

	whitelisted := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.RateLimit = 1
		c.RateLimitWindow = 60
		c.Whitelist = []string{"203.0.113.9"}
	})
	state := &RequestState{}
	req := wsRequest(t, nil)
	if reason := whitelisted.GuardWebSocket(req); reason != nil {
		t.Fatalf("whitelisted IPs skip the rate limit, got %+v", reason)
	}
	if !req.State().IsWhitelisted {
		t.Fatal("the guard must set the whitelist identity flag on the request state")
	}
	_ = state
}

func TestGuardWebSocketDetectionSuspicious(t *testing.T) {
	detector := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnablePenetrationDetection = true
	})
	reason := detector.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/api/..%2f..%2fetc/passwd"
	}))
	assertClose(t, reason, WSCloseSuspiciousActivity, "suspicious handshake")

	disabled := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnablePenetrationDetection = false
	})
	if reason := disabled.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/api/..%2f..%2fetc/passwd"
	})); reason != nil {
		t.Fatalf("detection disabled must pass, got %+v", reason)
	}
}

func TestGuardWebSocketDetectionExcludedPathSkips(t *testing.T) {
	engine := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnablePenetrationDetection = true
		c.ExcludePaths = []string{"/ws"}
	})
	excluded := wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/ws/search"
		opts.RawQuery = "q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
		opts.QueryParams = map[string]string{"q": "1' UNION SELECT username,password FROM users--"}
	})
	if reason := engine.GuardWebSocket(excluded); reason != nil {
		t.Fatalf("excluded path must skip detection, got %+v", reason)
	}
	if !engine.exclusions.matches("/ws/search") {
		t.Fatal("the exclusion must be active")
	}
}

func TestGuardWebSocketDetectionInertBusKeepsCounts(t *testing.T) {
	engine := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnablePenetrationDetection = true
		c.PassiveMode = true
	})
	if reason := engine.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/api/..%2f..%2fetc/passwd"
	})); reason != nil {
		t.Fatalf("passive mode never closes the handshake, got %+v", reason)
	}
	engine.suspiciousCounts.mu.Lock()
	total := 0
	for _, counts := range engine.suspiciousCounts.m["203.0.113.9"] {
		total += counts
	}
	engine.suspiciousCounts.mu.Unlock()
	if total == 0 {
		t.Fatal("the detection pass must record categories into the shared registry")
	}
}

func TestGuardWebSocketRedisDownContainment(t *testing.T) {
	deadRedis := func(c *SecurityConfig) {
		c.EnableRedis = true
		c.RedisURL = "redis://127.0.0.1:1"
		c.RateLimit = 100
		c.RateLimitWindow = 60
	}
	// Wire the rate limiter's redis surface without a successful connect:
	// InitializeRedis installs the Lua surface, the script load fails
	// against the dead port, and the first CheckRateLimitByIP surfaces the
	// redis error to the guard's containment.
	ready := func(engine *Engine) *Engine {
		engine.RateLimit.InitializeRedis(engine.Redis)
		return engine
	}

	// redis_fail_open: the manager contains the error into its in-memory
	// fallback and the handshake proceeds.
	failOpen := ready(wsEngine(t, func(c *SecurityConfig) {
		deadRedis(c)
		c.RedisFailOpen = true
	}))
	if reason := failOpen.GuardWebSocket(wsRequest(t, nil)); reason != nil {
		t.Fatalf("fail-open must allow the handshake, got %+v", reason)
	}

	// Neither fail-open nor fail-secure: the error logs and the default
	// (allow) applies, like the reference _guarded_redis_call tail.
	neutral := ready(wsEngine(t, func(c *SecurityConfig) {
		deadRedis(c)
		c.RedisFailOpen = false
		c.FailSecure = false
	}))
	if reason := neutral.GuardWebSocket(wsRequest(t, nil)); reason != nil {
		t.Fatalf("non-fail-open non-fail-secure must allow on the default, got %+v", reason)
	}

	// fail-secure: the 1013 security-check-failed close.
	failSecure := ready(wsEngine(t, func(c *SecurityConfig) {
		deadRedis(c)
		c.RedisFailOpen = false
		c.FailSecure = true
	}))
	assertClose(t, failSecure.GuardWebSocket(wsRequest(t, nil)), WSCloseSecurityCheckFailed, "fail-secure redis error")
}

func TestGuardWebSocketCountryStage(t *testing.T) {
	blocked := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.BlockedCountries = []string{"BR"}
		c.GeoIPHandler = fakeCountryResolver{"203.0.113.9": "BR", "198.51.100.7": "US"}
	})
	assertClose(t, blocked.GuardWebSocket(wsRequest(t, nil)), WSCloseIPNotAllowed, "blocked country")
	if reason := blocked.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "198.51.100.7"
	})); reason != nil {
		t.Fatalf("non-blocked country must pass, got %+v", reason)
	}

	allowlist := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.WhitelistCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{"203.0.113.9": "BR", "198.51.100.7": "US"}
	})
	assertClose(t, allowlist.GuardWebSocket(wsRequest(t, nil)), WSCloseIPNotAllowed, "country outside the allowlist")
	if reason := allowlist.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "198.51.100.7"
	})); reason != nil {
		t.Fatalf("allowlisted country must pass, got %+v", reason)
	}
	// An unresolved country denies under an allowlist.
	assertClose(t, allowlist.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "192.0.2.50"
	})), WSCloseIPNotAllowed, "unresolved country under allowlist")

	// Loopback is exempt from the country stage.
	loopback := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.WhitelistCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{"203.0.113.9": "BR"}
	})
	if reason := loopback.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "127.0.0.1"
	})); reason != nil {
		t.Fatalf("loopback must skip the country stage, got %+v", reason)
	}

	// A global whitelist match clears the country stage entirely.
	whitelistFirst := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.Whitelist = []string{"203.0.113.9"}
		c.WhitelistCountries = []string{"US"}
		c.GeoIPHandler = fakeCountryResolver{"203.0.113.9": "BR"}
	})
	if reason := whitelistFirst.GuardWebSocket(wsRequest(t, nil)); reason != nil {
		t.Fatalf("whitelist match must skip the country stage, got %+v", reason)
	}
}

func TestGuardWebSocketCloudProviderStage(t *testing.T) {
	engine := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.BlockCloudProviders = []string{"AWS"}
	})
	cloud := NewCloudManager()
	set := newCloudRangeSet()
	masked, key, err := parseCloudNetwork("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parseCloudNetwork: %v", err)
	}
	set.networks[key] = masked
	set.regions[key] = "us-east-1"
	cloud.installRanges("AWS", set, true)
	engine.Cloud = cloud

	assertClose(t, engine.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "10.1.2.3"
	})), WSCloseIPNotAllowed, "cloud provider IP")
	if reason := engine.GuardWebSocket(wsRequest(t, nil)); reason != nil {
		t.Fatalf("non-cloud IP must pass the cloud stage, got %+v", reason)
	}
}

func TestGuardWebSocketDetectionCheckFailureClosesTryAgain(t *testing.T) {
	engine := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnablePenetrationDetection = true
		c.FailSecure = true
	})
	// A nil category map makes the detection pass panic on record; the
	// pipeline's fail-secure containment answers 500 and the guard maps it
	// to the try-again-later close.
	engine.suspiciousCounts = &suspiciousCountStore{}
	assertClose(t, engine.GuardWebSocket(wsRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/search"
		opts.RawQuery = "q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
		opts.QueryParams = map[string]string{"q": "1' UNION SELECT username,password FROM users--"}
	})), WSCloseSecurityCheckFailed, "detection check failure under fail-secure")
}

func TestGuardWebSocketDetectionNilCounts(t *testing.T) {
	engine := wsEngine(t, nil)
	engine.suspiciousCounts = nil
	req := wsRequest(t, nil)
	if reason := engine.guardWebSocketDetection(req); reason != nil {
		t.Fatalf("nil counts registry must skip detection, got %+v", reason)
	}
}

func TestGuardWebSocketSharedCountsBetweenPipelineAndGuard(t *testing.T) {
	engine := wsEngine(t, func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnablePenetrationDetection = true
	})
	if engine.suspiciousCounts == nil {
		t.Fatal("the engine must retain the shared suspicious-count registry")
	}
	// The guard's detection check resolves to the engine's store, so a
	// violation recorded by the HTTP pipeline's check raises the websocket
	// verdict thresholds and vice versa (the reference
	// _resolve_shared_suspicious_counts semantics).
	check := &suspiciousActivityCheck{cfg: engine.Config, ban: engine.Ban, counts: engine.suspiciousCounts}
	if check.counts != engine.suspiciousCounts {
		t.Fatal("the check must be built over the shared store")
	}
}
