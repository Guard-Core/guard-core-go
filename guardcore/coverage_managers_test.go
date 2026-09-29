package guardcore

// Coverage tests for the remaining manager and config surfaces: geoip
// lifecycle internals, ipban local stores, config validation, logging
// redaction, composition plumbing and the route config check.

import (
	"errors"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGeoIPManagerClockHelpers(t *testing.T) {
	m := &GeoIPManager{}
	// The default clock is the wall clock.
	if m.nowUTC().IsZero() {
		t.Fatal("default clocks tick")
	}
	stamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return stamp }
	if got := m.nowUTC(); !got.Equal(stamp) {
		t.Fatalf("injected clocks win, got %v", got)
	}
	// Injected sleeps skip real backoff.
	slept := false
	m.sleep = func(time.Duration) { slept = true }
	m.sleepBackoff(time.Second)
	if !slept {
		t.Fatal("injected sleeps run")
	}
	// The default sleep path handles zero durations instantly.
	m.sleep = nil
	m.sleepBackoff(0)
}

func TestGeoIPManagerInitializeFailures(t *testing.T) {
	// Unwritable directories log and continue; a missing token stops the
	// download attempt without retries.
	m := &GeoIPManager{DBPath: "/proc/guardcore-nonexistent/db.mmdb", now: func() time.Time { return time.Unix(0, 0) }}
	m.Initialize()
	if !m.initialized {
		t.Fatal("initializations complete even on failures")
	}
	// A dead redis cache logs its failure and continues.
	dead := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1", EnableRedis: true})
	m2 := &GeoIPManager{DBPath: "/proc/guardcore-nonexistent/db.mmdb", Redis: dead, now: func() time.Time { return time.Unix(0, 0) }}
	m2.Initialize()
}

func TestGeoIPManagerDownloadDatabaseFailures(t *testing.T) {
	// Missing tokens fail immediately.
	m := &GeoIPManager{DBPath: "/tmp/guardcore-test.mmdb"}
	if err := m.downloadDatabase(); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("missing tokens fail, got %v", err)
	}
	// Malformed URLs fail fast.
	m = &GeoIPManager{DBPath: "/tmp/guardcore-test.mmdb", Token: "tok", dataURL: "://bad", sleep: func(time.Duration) {}}
	if err := m.downloadDatabase(); err == nil {
		t.Fatal("malformed urls fail")
	}
	// Unreachable endpoints retry with backoff and fail.
	m = &GeoIPManager{DBPath: "/tmp/guardcore-test.mmdb", Token: "tok", dataURL: "http://127.0.0.1:1/db", sleep: func(time.Duration) {}}
	m.customHTTPClient = &http.Client{Timeout: time.Second}
	if err := m.downloadDatabase(); err == nil {
		t.Fatal("unreachable endpoints fail")
	}
	// HTTP errors carry their status.
	status := &downloadStatusError{status: 403}
	if got := describeDownloadError(status); got != "HTTPError (HTTP 403)" {
		t.Fatalf("status errors describe themselves, got %q", got)
	}
	if got := describeDownloadError(errors.New("plain")); !strings.Contains(got, "errors.errorString") {
		t.Fatalf("plain errors name their type, got %q", got)
	}
	// HTTP clients default when none is injected.
	if (&GeoIPManager{}).httpClient() != http.DefaultClient {
		t.Fatal("default clients are stdlib")
	}
}

func TestGeoIPManagerWriteDatabaseAtomically(t *testing.T) {
	// Unwritable parents fail the write.
	m := &GeoIPManager{DBPath: "/proc/guardcore-nonexistent/db.mmdb"}
	if err := m.writeDatabaseAtomically([]byte("x")); err == nil {
		t.Fatal("unwritable parents fail")
	}
	// Directories cannot be replaced by renames.
	dir := t.TempDir() + "/as-dir.mmdb"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	m2 := &GeoIPManager{DBPath: dir}
	if err := m2.writeDatabaseAtomically([]byte("x")); err == nil {
		t.Fatal("directory targets fail renames")
	}
}

func TestGeoIPManagerCloseAndStatus(t *testing.T) {
	m := &GeoIPManager{}
	if err := m.Close(); err != nil {
		t.Fatalf("closing empty managers is a no-op, got %v", err)
	}
	status := m.GetStatus()
	if status["ready"] != false {
		t.Fatal("empty managers report unreadiness")
	}
}

func TestIPBanManagerTrustedProxyParsing(t *testing.T) {
	m := NewIPBanManager(nil, []string{"10.0.0.0/8", "not-a-network"})
	m.mu.Lock()
	proxies := len(m.trustedProxies)
	m.mu.Unlock()
	if proxies != 1 {
		t.Fatalf("valid proxies load and junk skips, got %d", proxies)
	}
}

func TestIPBanManagerLocalEviction(t *testing.T) {
	m := NewIPBanManager(nil, nil)
	// Fill the local cache to force one eviction.
	for i := 0; i < localCacheMaxSize; i++ {
		m.localSet(string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune(i)), 1e18)
	}
	m.localSet("overflow", 1e18)
	m.mu.Lock()
	size := len(m.bannedIPs)
	m.mu.Unlock()
	if size > localCacheMaxSize {
		t.Fatalf("local caches stay bounded, got %d", size)
	}
}

func TestIPBanManagerUnparseableAndExpiredNetworks(t *testing.T) {
	m := NewIPBanManager(nil, nil)
	if m.IsIPBanned("not-an-ip") {
		t.Fatal("unparseable addresses never register")
	}
	// Expired network bans fall out of the scan.
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	m.mu.Lock()
	m.bannedNetworks = append(m.bannedNetworks, networkBanEntry{network: prefix, expiry: 1})
	m.mu.Unlock()
	if m.IsIPBanned("10.1.2.3") {
		t.Fatal("expired network bans never register")
	}
}

func TestConfigValidateBehaviorRuleFailures(t *testing.T) {
	_, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.GlobalBehaviorRules = []BehaviorRuleConfig{{RuleType: "weird", Threshold: 1}}
	})
	if err == nil || !strings.Contains(err.Error(), "global_behavior_rules[0]") {
		t.Fatalf("bad global rules name their slot, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) {
		c.GlobalBehaviorRules = []BehaviorRuleConfig{{RuleType: "return_pattern", Threshold: 1, Pattern: "regex:x"}}
	})
	if err == nil || !strings.Contains(err.Error(), "behavior_scan_response_body") {
		t.Fatalf("body rules require the scan flag, got %v", err)
	}
	// The default inspect budget fills in when unset.
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if cfg.BehaviorMaxResponseBodyInspectBytes != DefaultBehaviorMaxResponseBodyInspectBytes {
		t.Fatalf("inspect budgets default, got %d", cfg.BehaviorMaxResponseBodyInspectBytes)
	}
}

func TestConfigValidateLogLevelAndProxies(t *testing.T) {
	// Log levels normalize and validate.
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.LogRequestLevel = "debug" })
	if err != nil || cfg.LogRequestLevel != "DEBUG" {
		t.Fatalf("log levels normalize, got %q %v", cfg.LogRequestLevel, err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.LogRequestLevel = "bogus" })
	if err == nil || !strings.Contains(err.Error(), "log_request_level") {
		t.Fatalf("bogus levels fail, got %v", err)
	}
	// Invalid user agent patterns fail.
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.BlockedUserAgents = []string{"["} })
	if err == nil || !strings.Contains(err.Error(), "blocked_user_agents") {
		t.Fatalf("bad agent patterns fail, got %v", err)
	}
	// IP lists validate their entries.
	for _, field := range []func(*SecurityConfig){
		func(c *SecurityConfig) { c.TrustedProxies = []string{"junk"} },
		func(c *SecurityConfig) { c.Whitelist = []string{"junk"} },
		func(c *SecurityConfig) { c.ExemptIPs = []string{"junk"} },
		func(c *SecurityConfig) { c.Blacklist = []string{"junk"} },
	} {
		if _, err := NewSecurityConfig(field); err == nil {
			t.Fatal("junk ip list entries fail")
		}
	}
	// The /0 shorthand validates as a prefix.
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.Whitelist = []string{"::/0"} }); err != nil {
		t.Fatalf("zero routes parse, got %v", err)
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.Whitelist = []string{"junk/0"} }); err == nil {
		t.Fatal("junk zero routes fail")
	}
}

func TestConfigIPMatching(t *testing.T) {
	// Canonicalization passes junk through untouched.
	if got := canonicalizeIPString("junk"); got != "junk" {
		t.Fatalf("junk passes through, got %q", got)
	}
	if got := canonicalizeIPString("::ffff:10.1.2.3"); got != "::ffff:10.1.2.3" {
		t.Fatalf("mapped addresses keep their form, got %q", got)
	}
	// List matching covers prefixes, zero routes and exact hits.
	if !ipMatchesList("10.1.2.3", []string{"10.0.0.0/8"}) {
		t.Fatal("prefixes match")
	}
	if !ipMatchesList("10.1.2.3", []string{"0.0.0.0/0"}) {
		t.Fatal("zero routes match everything")
	}
	if ipMatchesList("10.1.2.3", []string{"junk/8"}) {
		t.Fatal("junk prefixes never match")
	}
	if ipMatchesList("junk", []string{"10.0.0.0/8"}) {
		t.Fatal("junk ips never match")
	}
	if ipMatchesList("::ffff:10.1.2.3", []string{"10.1.2.3"}) {
		t.Fatal("exact entries compare canonical text")
	}
	if !ipMatchesList("::ffff:c0a8:101", []string{"::ffff:c0a8:101"}) {
		t.Fatal("entries canonicalize before matching")
	}
}

func TestRedactURLForDisplaySensitivity(t *testing.T) {
	// Query-less and sensitivity-less inputs pass through.
	if got := RedactURLForDisplay("/path", nil, nil, nil); got != "/path" {
		t.Fatalf("plain paths pass, got %q", got)
	}
	sensitive := map[string]bool{"token": true}
	got := RedactURLForDisplay("/path?token=abc&q=a+b", sensitive, nil, nil)
	if !strings.Contains(got, "%5BREDACTED%5D") {
		t.Fatalf("sensitive params redact, got %q", got)
	}
	if !strings.Contains(got, "q=a+b") {
		t.Fatalf("plain params stay, got %q", got)
	}
	// Case-insensitive matching.
	got = RedactURLForDisplay("/p?Token=x", sensitive, nil, nil)
	if !strings.Contains(got, "%5BREDACTED%5D") {
		t.Fatalf("sensitivity is case-insensitive, got %q", got)
	}
	// Empty raw urls pass through.
	if got := RedactURLForDisplay("", nil, nil, nil); got != "" {
		t.Fatalf("empty urls pass, got %q", got)
	}
	if got := urlQueryEscape("a b/c"); got != "a%20b%2Fc" {
		t.Fatalf("escapes encode, got %q", got)
	}
	if got := urlQueryEscape("a-b_c.d~e"); got != "a-b_c.d~e" {
		t.Fatalf("unreserved characters stay, got %q", got)
	}
}

func TestExtractRequestContextIdentity(t *testing.T) {
	opts := LogOptions{}
	// Identity-less requests fall back to the unknown identity.
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ""
		state.ClientIP = ""
	})
	ctx := extractRequestContext(req, opts)
	if ctx["client_ip"] != UnknownClientIdentity {
		t.Fatalf("unknown identities fill in, got %v", ctx["client_ip"])
	}
	known := newTestRequest(t, nil)
	ctx = extractRequestContext(known, opts)
	if ctx["client_ip"] != "203.0.113.9" {
		t.Fatalf("known identities carry, got %v", ctx["client_ip"])
	}
}

func TestRouteConfigCheckVerdicts(t *testing.T) {
	registry := NewRouteRegistry()
	cfg := &SecurityConfig{}
	c := &routeConfigCheck{cfg: cfg, registry: registry}
	if c.EnforcedOnExcludedPaths() != true {
		t.Fatal("route config checks enforce everywhere")
	}
	if !c.AppliesTo(cfg) {
		t.Fatal("route config checks always apply")
	}
	if c.CheckName() != "route_config" {
		t.Fatal("checks carry their name")
	}
	// Registered routes resolve into the request state.
	registry.Register("/resolves", nil)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/resolves"
	})
	if resp := c.Check(req); resp != nil {
		t.Fatalf("resolved routes pass, got %+v", resp)
	}
	state := req.State()
	if state.RouteConfig == nil || state.ClientIP != "203.0.113.9" {
		t.Fatalf("route resolution fills the state, got %+v", state.RouteConfig)
	}
	// Strict modes block unresolved routes.
	strictCfg := &SecurityConfig{RouteResolutionStrict: true}
	sc := &routeConfigCheck{cfg: strictCfg, registry: registry}
	unresolved := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/nope"
		state.RouteUnresolved = true
	})
	if resp := sc.Check(unresolved); resp == nil || resp.StatusCode != 500 {
		t.Fatalf("strict unresolved routes block with 500, got %+v", resp)
	}
	passiveStrict := &SecurityConfig{RouteResolutionStrict: true, PassiveMode: true}
	pc := &routeConfigCheck{cfg: passiveStrict, registry: registry}
	if resp := pc.Check(unresolved); resp != nil {
		t.Fatalf("passive modes never block, got %+v", resp)
	}
}

func TestEmergencyModeCheckVerdicts(t *testing.T) {
	c := &emergencyModeCheck{cfg: &SecurityConfig{}}
	if c.AppliesTo(&SecurityConfig{EnableDynamicRules: true}) != true {
		t.Fatal("dynamic rules apply the sentinel")
	}
	// Inactive emergency modes skip.
	if resp := c.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("inactive modes pass, got %+v", resp)
	}
	// Whitelisted IPs pass.
	cfg := &SecurityConfig{EmergencyMode: true, EmergencyWhitelist: []string{"203.0.113.9"}}
	w := &emergencyModeCheck{cfg: cfg}
	if resp := w.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("whitelisted ips pass, got %+v", resp)
	}
	// Everyone else gets 503.
	other := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.ClientIP = "198.51.100.7"
	})
	if resp := w.Check(other); resp == nil || resp.StatusCode != 503 {
		t.Fatalf("emergency modes block with 503, got %+v", resp)
	}
	passive := &emergencyModeCheck{cfg: &SecurityConfig{EmergencyMode: true, PassiveMode: true}}
	if resp := passive.Check(other); resp != nil {
		t.Fatalf("passive modes never block, got %+v", resp)
	}
}

func TestExclusionMatcherMatches(t *testing.T) {
	cfg := &SecurityConfig{ExcludePaths: []string{"/healthz"}}
	m := &exclusionMatcher{cfg: cfg}
	// Exclusions are subtree matches.
	if !m.matches("/healthz") || !m.matches("/healthz/deep") {
		t.Fatal("configured exclusions match their subtree")
	}
	if m.matches("/other") {
		t.Fatal("other paths never match")
	}
	// Mutating the config refreshes the entry set.
	cfg.ExcludePaths = []string{"/fresh"}
	if !m.matches("/fresh/deep") {
		t.Fatal("mutated exclusions refresh")
	}
	if m.matches("/healthz") {
		t.Fatal("stale exclusions drop out")
	}
	// Unparseable paths never match.
	if m.matches("http://[::1") {
		t.Fatal("unparseable paths never match")
	}
}
