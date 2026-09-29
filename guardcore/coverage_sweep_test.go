package guardcore

// Final coverage sweep: config validation bounds, CORS header branches,
// security header errors, logging redaction branches, composition plumbing,
// the route accessors and remaining rate-limit unit paths.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSecurityConfigNumericBounds(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*SecurityConfig)
		want   string
	}{
		{"auto_ban_threshold", func(c *SecurityConfig) { c.AutoBanThreshold = 0 }, "auto_ban_threshold"},
		{"auto_ban_duration", func(c *SecurityConfig) { c.AutoBanDuration = 0 }, "auto_ban_duration"},
		{"threat_category", func(c *SecurityConfig) {
			c.ThreatBanConfig = map[string]ThreatBanEntry{"nope": {Threshold: 1, Duration: 1}}
		}, "threat_ban_config"},
		{"threat_threshold", func(c *SecurityConfig) {
			c.ThreatBanConfig = map[string]ThreatBanEntry{"sqli": {Threshold: 0, Duration: 1}}
		}, "threshold"},
		{"threat_duration", func(c *SecurityConfig) {
			c.ThreatBanConfig = map[string]ThreatBanEntry{"sqli": {Threshold: 1, Duration: 0}}
		}, "duration"},
		{"rate_limit", func(c *SecurityConfig) { c.RateLimit = 0 }, "rate_limit"},
		{"rate_limit_window", func(c *SecurityConfig) { c.RateLimitWindow = 0 }, "rate_limit_window"},
		{"endpoint_requests", func(c *SecurityConfig) {
			c.EndpointRateLimits = map[string]RateLimitEntry{"/x": {Requests: 0, Window: 1}}
		}, "requests"},
		{"endpoint_window", func(c *SecurityConfig) {
			c.EndpointRateLimits = map[string]RateLimitEntry{"/x": {Requests: 1, Window: 0}}
		}, "window"},
		{"exclude_paths", func(c *SecurityConfig) { c.ExcludePaths = []string{"relative"} }, "exclude_paths"},
		{"ipinfo_max_age", func(c *SecurityConfig) { c.IPInfoToken = "t"; c.IPInfoMaxAge = -1 }, "ipinfo_max_age"},
	}
	for _, tc := range cases {
		_, err := NewSecurityConfig(tc.mutate)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: got %v, want a %q failure", tc.name, err, tc.want)
		}
	}
}

func TestSecurityConfigDefaultsFill(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.CloudIPRefreshInterval = -5
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if cfg.CloudIPRefreshInterval != DefaultCloudIPRefreshInterval {
		t.Fatalf("refresh intervals default, got %v", cfg.CloudIPRefreshInterval)
	}
	// Out-of-range refresh intervals clamp to the bounds.
	cfg, err = NewSecurityConfig(func(c *SecurityConfig) { c.CloudIPRefreshInterval = 1 })
	if err != nil || cfg.CloudIPRefreshInterval != MinCloudIPRefreshInterval {
		t.Fatalf("small intervals clamp, got %v %v", cfg.CloudIPRefreshInterval, err)
	}
	cfg, err = NewSecurityConfig(func(c *SecurityConfig) { c.CloudIPRefreshInterval = 1 << 30 })
	if err != nil || cfg.CloudIPRefreshInterval != MaxCloudIPRefreshInterval {
		t.Fatalf("large intervals clamp, got %v %v", cfg.CloudIPRefreshInterval, err)
	}
}

func TestSecurityConfigGeoHandlerRequirement(t *testing.T) {
	_, err := NewSecurityConfig(func(c *SecurityConfig) { c.BlockedCountries = []string{"CN"} })
	if err == nil || !strings.Contains(err.Error(), "geo_ip_handler") {
		t.Fatalf("country rules need a geo handler, got %v", err)
	}
	// A token builds the download-backed handler instead.
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BlockedCountries = []string{"CN"}
		c.IPInfoToken = "tok"
	})
	if err != nil {
		t.Fatalf("token-backed handlers build: %v", err)
	}
	if cfg.GeoIPHandler == nil {
		t.Fatal("token configs wire the ipinfo manager")
	}
	if cfg.IPInfoMaxAge != DefaultIPInfoMaxAge {
		t.Fatalf("max ages default, got %v", cfg.IPInfoMaxAge)
	}
}

func TestLowercaseRedactURLForDisplay(t *testing.T) {
	// Query-less and sensitivity-less inputs pass through.
	if got := redactURLForDisplay("/path", nil, nil); got != "/path" {
		t.Fatalf("plain paths pass, got %q", got)
	}
	sensitive := map[string]bool{"token": true}
	got := redactURLForDisplay("/path", map[string]string{"token": "abc", "q": "a b"}, sensitive)
	if !strings.Contains(got, "[REDACTED]") || !strings.Contains(got, "q=a%20b") {
		t.Fatalf("query strings rebuild with redactions, got %q", got)
	}
}

func TestCORSPolicyBuildResponseHeadersPaths(t *testing.T) {
	// The wildcard-origins path composes without credentials.
	policy := &CORSPolicy{
		allowAllOrigins: true,
		allowMethods:    []string{"GET"},
		allowHeaders:    []string{"*"},
		allowAllHeaders: true,
	}
	headers := NewHeaders()
	headers.Set("Origin", "https://any.example")
	got := policy.buildResponseHeaders(headers)
	if got["Access-Control-Allow-Origin"] != "*" {
		t.Fatalf("wildcard origins echo stars, got %v", got)
	}
	if got["Access-Control-Allow-Headers"] != "*" {
		t.Fatalf("allow-all headers echo stars, got %v", got)
	}
	if _, ok := got["Access-Control-Allow-Credentials"]; ok {
		t.Fatalf("credential-less policies stay silent, got %v", got)
	}
	// Restricted policies reject foreign origins even with credentials.
	restricted := &CORSPolicy{
		allowOrigins:     map[string]bool{"https://good.example": true},
		allowMethods:     []string{"GET"},
		allowHeaders:     []string{"content-type"},
		allowCredentials: true,
	}
	headers = NewHeaders()
	headers.Set("Origin", "https://evil.example")
	if got := restricted.buildResponseHeaders(headers); got != nil {
		t.Fatalf("foreign origins get nothing, got %v", got)
	}
	// Allowed origins with credentials echo the origin.
	headers = NewHeaders()
	headers.Set("Origin", "https://good.example")
	got = restricted.buildResponseHeaders(headers)
	if got["Access-Control-Allow-Origin"] != "https://good.example" || got["Access-Control-Allow-Credentials"] != "true" {
		t.Fatalf("allowed origins compose, got %v", got)
	}
}

func TestValidateSecurityHeadersPermissionsPolicyError(t *testing.T) {
	bad := "\r\ninject"
	sh := &SecurityHeadersConfig{PermissionsPolicy: &bad}
	err := validateSecurityHeaders(sh)
	if err == nil || !strings.Contains(err.Error(), "Permissions-Policy") {
		t.Fatalf("permissions policy errors name themselves, got %v", err)
	}
}

func TestLoggingRedactionBranches(t *testing.T) {
	sensitive := map[string]bool{"password": true}
	// Empty blobs pass through.
	if got := RedactBlobForDisplay("", sensitive, nil, nil); got != "" {
		t.Fatalf("empty blobs pass, got %q", got)
	}
	// URL-encoded json blobs retry after decoding.
	encoded := "%7B%22password%22%3A%20%22x%22%7D"
	if got := RedactBlobForDisplay(encoded, sensitive, nil, nil); !strings.Contains(got, RedactedPlaceholder) {
		t.Fatalf("encoded blobs decode and redact, got %q", got)
	}
	// Non-json blobs fall through to the pair redactor.
	if got := RedactBlobForDisplay("password=abc", sensitive, nil, nil); !strings.Contains(got, RedactedPlaceholder) {
		t.Fatalf("pair blobs redact, got %q", got)
	}
	// Marshal failures yield empty strings.
	if got := marshalCompactJSON(make(chan int)); got != "" {
		t.Fatalf("unmarshalable values stay empty, got %q", got)
	}
	// Non-json payloads never text-redact.
	if got := jsonRedactText("plain text", sensitive); got != "" {
		t.Fatalf("plain text never json-redacts, got %q", got)
	}
	// Depth-capped arrays collapse onto the placeholder.
	deep := strings.Repeat("[", jsonRedactionMaxDepth+3) + strings.Repeat("]", jsonRedactionMaxDepth+3)
	var parsed any
	if err := json.Unmarshal([]byte(deep), &parsed); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	redacted, _, capHit := redactSensitiveJSON(parsed, sensitive, 1)
	if !capHit || !strings.Contains(fmt.Sprintf("%v", redacted), RedactedPlaceholder) {
		t.Fatalf("depth caps collapse, got %v %v", redacted, capHit)
	}
	// Empty raw urls pass through.
	if got := RedactURLForDisplay("", nil, nil, nil); got != "" {
		t.Fatalf("empty urls pass, got %q", got)
	}
	// Paths carrying sensitive xml-style segments redact in place.
	got := RedactURLForDisplay("/reset/<password>x</password>/y", nil, sensitive, nil)
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("sensitive path segments redact, got %q", got)
	}
}

func TestCompositionEnginePlumbing(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	// CORS-less engines return nil cors headers.
	if got := engine.CORSResponseHeaders(newTestRequest(t, nil)); got != nil {
		t.Fatalf("cors-less engines return nil, got %v", got)
	}
	// Response headers compose from the security headers config.
	engine.Config.SecurityHeaders.FrameOptions = "DENY"
	headers := engine.ResponseHeaders()
	if headers["X-Frame-Options"] != "DENY" {
		t.Fatalf("response headers compose, got %v", headers)
	}
	// Error responses flow through the engine factory.
	resp := engine.CreateErrorResponse(418, "teapot")
	if resp.StatusCode != 418 {
		t.Fatalf("error responses carry codes, got %+v", resp)
	}
	// Response processing runs the behavioral return stages.
	engine.ProcessResponse(newTestRequest(t, nil), &Response{StatusCode: 200})
	// Closes shut the engine down cleanly.
	if err := engine.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestEmergencyAndHTTPSCheckAccessors(t *testing.T) {
	if (&emergencyModeCheck{}).EnforcedOnExcludedPaths() {
		t.Fatal("emergency checks never enforce on excluded paths")
	}
	httpsCheck := &httpsEnforcementCheck{cfg: &SecurityConfig{EnforceHTTPS: true, TrustedProxies: []string{"10.0.0.8"}}}
	if httpsCheck.EnforcedOnExcludedPaths() {
		t.Fatal("https checks never enforce on excluded paths")
	}
	if !httpsCheck.AppliesTo(httpsCheck.cfg) {
		t.Fatal("https checks apply when enabled")
	}
	if !httpsCheck.isTrustedProxy("10.0.0.8") || httpsCheck.isTrustedProxy("203.0.113.9") {
		t.Fatal("trusted proxies resolve")
	}
}

func TestRateLimitManagerUnitPaths(t *testing.T) {
	// Zero-valued configs fall back to the defaults.
	rl := NewRateLimitManager(RateLimitConfig{}, nil, nil)
	if rl.cfg.RateLimit != DefaultRateLimit || rl.cfg.RateLimitWindow != DefaultRateLimitWindow {
		t.Fatalf("limits default, got %+v", rl.cfg)
	}
	if rl.cfg.AutoBanThreshold != DefaultAutoBanThreshold || rl.cfg.AutoBanDuration != DefaultAutoBanDuration {
		t.Fatalf("ban settings default, got %+v", rl.cfg)
	}
	// Repeated fail-open warnings warn once.
	resetRateLimitFailOpenWarned()
	counter := &writeCounter{}
	logger := log.New(counter, "", 0)
	warnRedisFailOpenInMemoryFallback(logger)
	warnRedisFailOpenInMemoryFallback(logger)
	if counter.writes != 1 {
		t.Fatalf("fail-open warnings deduplicate, got %d", counter.writes)
	}
	resetRateLimitFailOpenWarned()
	// Handlers that are not rate-limit redis implementations stay unwired.
	off := NewRedisManager(RedisConfig{EnableRedis: false})
	rl.InitializeRedis(off)
	if rl.rlRedis != nil {
		t.Fatal("non-rate-limit handlers stay unwired")
	}
	// The ByIP primitive validates its inputs.
	if _, err := rl.CheckRateLimitByIP("junk", "path"); err == nil {
		t.Fatal("junk ips fail")
	}
	if _, err := rl.CheckRateLimitByIP("10.0.0.1", "pa:th"); err == nil {
		t.Fatal("colons in paths fail")
	}
	// Disabled rate limiting always allows.
	if allowed, err := rl.CheckRateLimitByIP("10.0.0.2", "path"); err != nil || !allowed {
		t.Fatalf("disabled rate limiting allows, got %v %v", allowed, err)
	}
	// Autoban feeding stays quiet in passive mode and without a manager.
	passive := NewRateLimitManager(RateLimitConfig{EnableRateLimiting: true, EnableRateLimitAutoBan: true, EnableIPBanning: true, PassiveMode: true}, nil, nil)
	passive.feedRateLimitAutoban("10.0.0.3")
	noBan := NewRateLimitManager(RateLimitConfig{EnableRateLimiting: true, EnableRateLimitAutoBan: true, EnableIPBanning: true}, nil, nil)
	noBan.feedRateLimitAutoban("10.0.0.3")
	// Threshold ban resolution below the threshold stays quiet.
	if noBan.resolveAndApplyThresholdBan("10.0.0.3", map[string]int{"rate_limit": 1}) {
		t.Fatal("sub-threshold counts never ban")
	}
	// Threat-ban categories ban through their own thresholds.
	ban := NewIPBanManager(nil, nil)
	withBan := NewRateLimitManager(RateLimitConfig{
		EnableRateLimiting:     true,
		EnableIPBanning:        true,
		EnableRateLimitAutoBan: true,
		ThreatBanConfig:        map[string]ThreatBanEntry{"rate_limit": {Threshold: 1, Duration: 60}},
	}, nil, ban)
	if !withBan.resolveAndApplyThresholdBan("203.0.113.150", map[string]int{"rate_limit": 1}) {
		t.Fatal("threat thresholds ban")
	}
	if !ban.IsIPBanned("203.0.113.150") {
		t.Fatal("threat bans enforce")
	}
}

type writeCounter struct {
	writes int
}

func (w *writeCounter) Write(p []byte) (int, error) {
	w.writes++
	return len(p), nil
}

// fakeAdminRedis extends the shared fake handler with the admin surface the
// ban-key migration needs.
type fakeAdminRedis struct {
	*fakeRedisHandler
	scanResults []string
	scanErr     error
	getErr      error
	pttlResults map[string]time.Duration
	pttlErr     error
	failPTTLKey string
	setPXErr    error
	deleteErr   error
}

func (f *fakeAdminRedis) ScanMatch(string) ([]string, error) { return f.scanResults, f.scanErr }
func (f *fakeAdminRedis) GetKey(namespace, key string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.fakeRedisHandler.GetKey(namespace, key)
}
func (f *fakeAdminRedis) PTTL(key string) (time.Duration, error) {
	if f.pttlErr != nil || (f.failPTTLKey != "" && key == f.failPTTLKey) {
		return 0, errors.New("pttl boom")
	}
	return f.pttlResults[key], nil
}
func (f *fakeAdminRedis) SetPX(key, value string, ttl time.Duration) error {
	return f.setPXErr
}
func (f *fakeAdminRedis) DeleteKeys(keys ...string) (int64, error) {
	if f.deleteErr != nil {
		return 0, f.deleteErr
	}
	return int64(len(keys)), nil
}

func TestFileUploadWhitespaceAndOverlaps(t *testing.T) {
	tx := newScanText("a   b")
	if got := fileUploadSkipWhitespace(tx, 1); got != 4 {
		t.Fatalf("whitespace skips, got %d", got)
	}
	// Candidates whose starts fall inside earlier matches fold away.
	tx = newScanText(`filename="a.php"filename="b.php"`)
	got := fileUploadScanMatches(tx, fileUploadDangerousSource)
	if len(got) != 1 {
		t.Fatalf("overlapping candidates fold, got %d", len(got))
	}
}

func TestDetectDecodedViewAppendsThreat(t *testing.T) {
	// Encoded traversals decode into more sightings than the raw view has.
	result := Detect("%252e%252e%252fetc%2fpasswd", "", "request_body")
	found := false
	for _, threat := range result.Threats {
		if threat["category"] == "path_traversal" {
			found = true
		}
	}
	if !found {
		t.Fatalf("decoded traversal deltas report, got %v", result.Threats)
	}
}

func TestParseHeaderParamsEmptyPieces(t *testing.T) {
	main, params := parseHeaderParams("")
	if main != "" || len(params) != 0 {
		t.Fatalf("empty headers parse to defaults, got %q %v", main, params)
	}
}

func TestGeoIPManagerRefreshFailureKeepsState(t *testing.T) {
	m := &GeoIPManager{DBPath: "/tmp/guardcore-refresh.mmdb", Token: "tok", dataURL: "http://127.0.0.1:1/db", sleep: func(time.Duration) {}}
	m.customHTTPClient = &http.Client{Timeout: time.Second}
	m.Refresh()
	if !m.initialized {
		t.Fatal("refreshes complete even on failures")
	}
	m.mu.RLock()
	ready := m.reader != nil
	m.mu.RUnlock()
	if ready {
		t.Fatal("failed refreshes keep no reader")
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestIPBanManagerResetWithBrokenRedis(t *testing.T) {
	dead := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1", EnableRedis: true})
	ban := NewIPBanManager(dead, nil)
	if err := ban.Reset(); err == nil {
		t.Fatal("broken redis resets fail")
	}
}

func TestIPBanManagerMigrationBranches(t *testing.T) {
	// Disabled handlers skip migration.
	ban := NewIPBanManager(newFakeRedisHandler(), nil)
	ban.InitializeRedis(newFakeRedisHandler())
	// Scan failures log and skip.
	scanErr := &fakeAdminRedis{fakeRedisHandler: newFakeRedisHandler(), scanErr: errors.New("scan boom")}
	ban.redis = scanErr
	ban.admin = scanErr
	ban.migrateLegacyBanKeys()

	// Legacy keys migrate onto canonical addresses.
	fake := &fakeAdminRedis{
		fakeRedisHandler: newFakeRedisHandler(),
		scanResults:      []string{"guard_core:banned_ips:0:0:0:0:0:ffff:c0a8:101"},
		pttlResults:      map[string]time.Duration{},
	}
	fake.data["banned_ips:0:0:0:0:0:ffff:c0a8:101"] = "4000000000"
	fake.pttlResults["guard_core:banned_ips:0:0:0:0:0:ffff:c0a8:101"] = time.Hour
	ban.redis = fake
	ban.admin = fake
	ban.migrateLegacyBanKeys()

	// Missing values fail the migration.
	fake.scanResults = []string{"guard_core:banned_ips:10.1.2.3"}
	delete(fake.data, "banned_ips:10.1.2.3")
	fake.pttlResults["guard_core:banned_ips:10.1.2.3"] = time.Hour
	ban.migrateLegacyBanKeys()

	// PTTL failures log and skip.
	fake.scanResults = []string{"guard_core:banned_ips:0:0:0:0:0:ffff:c0a8:101"}
	fake.data["banned_ips:0:0:0:0:0:ffff:c0a8:101"] = "4000000000"
	fake.pttlErr = errors.New("pttl boom")
	ban.migrateLegacyBanKeys()
	fake.pttlErr = nil

	// Get failures log and skip.
	fake.getErr = errors.New("get boom")
	ban.migrateLegacyBanKeys()
	fake.getErr = nil

	// Expired legacy keys delete outright; delete failures log and skip.
	fake.scanResults = []string{"guard_core:banned_ips:0:0:0:0:0:ffff:c0a8:101"}
	fake.pttlResults["guard_core:banned_ips:0:0:0:0:0:ffff:c0a8:101"] = -time.Second
	fake.deleteErr = errors.New("delete boom")
	ban.migrateLegacyBanKeys()
	fake.deleteErr = nil

	// Expired keys with healthy deletes succeed quietly.
	ban.migrateLegacyBanKeys()

	// Second PTTL failures (the canonical comparison) log and skip.
	fake.pttlResults["guard_core:banned_ips:0:0:0:0:0:ffff:c0a8:101"] = time.Hour
	fake.failPTTLKey = "guard_core:banned_ips:192.168.1.1"
	ban.migrateLegacyBanKeys()
	fake.failPTTLKey = ""

	// SetPX failures log and skip.
	fake.setPXErr = errors.New("setpx boom")
	ban.migrateLegacyBanKeys()
	fake.setPXErr = nil

	// Canonical keys with newer TTLs just delete the legacy copy.
	fake.setPXErr = nil
	fake.pttlResults["fake:banned_ips:0:0:0:0:0:ffff:c0a8:101"] = time.Minute
	ban.migrateLegacyBanKeys()
}

func TestJSONRedactTextScalars(t *testing.T) {
	// Scalar json payloads never text-redact.
	if got := jsonRedactText("42", map[string]bool{"a": true}); got != "" {
		t.Fatalf("scalar payloads never redact, got %q", got)
	}
}

func TestRedactURLForDisplayUnparseable(t *testing.T) {
	// Unparseable urls pass through untouched.
	raw := "http://[::1"
	if got := RedactURLForDisplay(raw, nil, nil, nil); got != raw {
		t.Fatalf("unparseable urls pass through, got %q", got)
	}
}

func TestEngineMatcherRejectsBadPercents(t *testing.T) {
	cfg := &SecurityConfig{ExcludePaths: []string{"/ok"}}
	m := &exclusionMatcher{cfg: cfg}
	// Paths whose percent runs decode into invalid utf8 never match.
	if m.matches("/%ff%fe") {
		t.Fatal("undecodable percent runs never match")
	}
}

func TestAnchoredAnywherePastEnd(t *testing.T) {
	tx := newScanText("x.php")
	if anchoredAnywhere(fileUploadTruncationMarkerRE, tx, tx.n+1) {
		t.Fatal("offsets past the end never anchor")
	}
}

func TestRateLimitInitializeRedisNonRateLimitHandler(t *testing.T) {
	fake := newFakeRedisHandler()
	rl := NewRateLimitManager(RateLimitConfig{EnableRateLimiting: true}, fake, nil)
	rl.InitializeRedis(fake)
	if rl.rlRedis != nil {
		t.Fatal("handlers without the rate limit surface stay unwired")
	}
}

func TestRateLimitAutobanTotalPathBanError(t *testing.T) {
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfig{
		EnableRateLimiting:     true,
		EnableIPBanning:        true,
		EnableRateLimitAutoBan: true,
		AutoBanThreshold:       1,
	}, nil, ban)
	// Non-IP overflows fail the network ban and log.
	if rl.resolveAndApplyThresholdBan("junk/24", map[string]int{"rate_limit": 3}) {
		t.Fatal("failed total bans stay quiet")
	}
}

func TestGeoIPManagerDownloadWriteFailures(t *testing.T) {
	// Successful downloads onto unwritable targets fail the write.
	m := &GeoIPManager{DBPath: "/proc/guardcore-nonexistent/db.mmdb", Token: "tok", sleep: func(time.Duration) {}}
	m.customHTTPClient = &http.Client{Transport: statusRoundTripper{status: 200, body: []byte("bytes")}}
	m.dataURL = "http://geo.test/db"
	if err := m.downloadDatabase(); err == nil {
		t.Fatal("unwritable targets fail the write")
	}
	// Successful downloads warn when the redis cache write fails.
	dead := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1", EnableRedis: true})
	m2 := &GeoIPManager{DBPath: t.TempDir() + "/db.mmdb", Token: "tok", Redis: dead, sleep: func(time.Duration) {}}
	m2.customHTTPClient = &http.Client{Transport: statusRoundTripper{status: 200, body: []byte("bytes")}}
	m2.dataURL = "http://geo.test/db"
	if err := m2.downloadDatabase(); err != nil {
		t.Fatalf("redis cache failures warn only, got %v", err)
	}
}
