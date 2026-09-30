package guardcore

// Final coverage sweep part two: zero-config validation, closed-client redis
// errors, geoip download lifecycle, multipart sibling parts and matcher
// remainders. Integration cases live in coverage_redis_live_test.go.

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestZeroConfigValidateFillsDefaults(t *testing.T) {
	c := &SecurityConfig{
		TrustedProxyDepth:           1,
		AutoBanThreshold:            1,
		AutoBanDuration:             60,
		RateLimit:                   1,
		RateLimitWindow:             60,
		DetectionBinaryMinRunLength: 4,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("minimal configs validate, got %v", err)
	}
	if c.Detection.CompilerTimeout != 2*time.Second || c.Detection.MaxContentLength != 10000 || c.Detection.MaxBodyInspectBytes != 262144 {
		t.Fatalf("detection budgets default, got %+v", c.Detection)
	}
	if c.RedisURL != DefaultRedisURL || c.RedisPrefix != DefaultRedisPrefix {
		t.Fatalf("redis settings default, got %q %q", c.RedisURL, c.RedisPrefix)
	}
	if c.EndpointRateLimits == nil || c.ThreatBanConfig == nil || c.CustomErrorResponses == nil || c.MutedCheckLogs == nil ||
		c.LogSensitiveHeaders == nil || c.LogSensitiveParams == nil || c.LogSensitiveBodyFields == nil {
		t.Fatal("maps default to empty sets")
	}
	// CORS validation failures surface.
	bad := &SecurityConfig{
		TrustedProxyDepth: 1, AutoBanThreshold: 1, AutoBanDuration: 60, RateLimit: 1, RateLimitWindow: 60,
		EnableCORS:           true,
		CORSAllowOrigins:     []string{"*"},
		CORSAllowCredentials: true,
	}
	if err := bad.Validate(); err == nil {
		t.Fatal("wildcard origins with credentials fail")
	}
}

func TestLRUStoreEviction(t *testing.T) {
	store := newLRUStore[int]()
	for i := 0; i < maxTrackedRateLimitKeys; i++ {
		store.set(string(rune('a'+i%26))+string(rune(i)), i)
	}
	store.set("overflow", 1)
	if store.len() > maxTrackedRateLimitKeys {
		t.Fatalf("stores stay bounded, got %d", store.len())
	}
	store.clear()
	if store.len() != 0 {
		t.Fatal("clears empty the store")
	}
}

func TestRateLimitTiersUseEndpointKeys(t *testing.T) {
	cfg := RateLimitConfig{EnableRateLimiting: true, RateLimit: 5, RateLimitWindow: 60}
	rl := NewRateLimitManager(cfg, nil, nil)
	rl.now = func() float64 { return 100.0 }
	rl.cfg.EndpointRateLimits = map[string]RateLimitEntry{"/only": {Requests: 1, Window: 60}}
	// The endpoint tier runs on its own key.
	if out, err := rl.CheckRateLimit("203.0.113.160", "/only", nil, nil); err != nil || out.Blocked {
		t.Fatalf("first endpoint requests pass, got %+v %v", out, err)
	}
	out, err := rl.CheckRateLimit("203.0.113.160", "/only", nil, nil)
	if err != nil || !out.Blocked || out.Tier != "endpoint" {
		t.Fatalf("second endpoint requests block on the endpoint tier, got %+v %v", out, err)
	}
	// Disabled rate limiting always allows.
	off := NewRateLimitManager(RateLimitConfig{EnableRateLimiting: false}, nil, nil)
	if out, err := off.CheckRateLimit("203.0.113.160", "/only", nil, nil); err != nil || out == nil || out.Blocked {
		t.Fatalf("disabled rate limiting allows, got %+v %v", out, err)
	}
}

func TestRateLimitAutobanBanErrors(t *testing.T) {
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfig{
		EnableRateLimiting:     true,
		EnableIPBanning:        true,
		EnableRateLimitAutoBan: true,
		ThreatBanConfig:        map[string]ThreatBanEntry{"rate_limit": {Threshold: 1, Duration: 0}},
	}, nil, ban)
	// Ban attempts that fail log and stay quiet.
	if rl.resolveAndApplyThresholdBan("junk/24", map[string]int{"rate_limit": 5}) {
		t.Fatal("failed bans stay quiet")
	}
	// Non-IPBanning configs never ban.
	noBanCfg := NewRateLimitManager(RateLimitConfig{EnableRateLimiting: true}, nil, ban)
	if noBanCfg.resolveAndApplyThresholdBan("10.0.0.1", map[string]int{"rate_limit": 100}) {
		t.Fatal("banning-disabled configs never ban")
	}
}

func TestTimeWindowDefaultClock(t *testing.T) {
	c := &timeWindowCheck{cfg: &SecurityConfig{}}
	if c.now().IsZero() {
		t.Fatal("default clocks tick")
	}
}

func TestRequestSizeContentCheckPassiveMode(t *testing.T) {
	c := &requestSizeContentCheck{cfg: &SecurityConfig{PassiveMode: true}}
	route := &RouteConfig{MaxRequestSize: 10, AllowedContentTypes: []string{"application/json"}}
	big := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Content-Length"] = "5"
		opts.Header["Content-Type"] = "text/plain"
	})
	if resp := c.Check(big); resp != nil {
		t.Fatalf("passive modes never block, got %+v", resp)
	}
	// Oversized bodies with compliant types still fire the size hook.
	oversized := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Content-Length"] = "100"
		opts.Header["Content-Type"] = "application/json"
	})
	if resp := c.Check(oversized); resp != nil {
		t.Fatalf("passive modes never block, got %+v", resp)
	}
}

func TestBehaviorTrackerRedisUnavailableError(t *testing.T) {
	cfg := behaviorTestConfig(t, nil)
	disabled := NewRedisManager(RedisConfig{EnableRedis: false})
	tracker := NewBehaviorTracker(cfg, disabled, nil, nil)
	if _, err := tracker.recordSlidingWindowHit("ns", "k", 1, 0, 60); err != errBehaviorRedisUnavailable {
		t.Fatalf("disabled redis reports unavailable, got %v", err)
	}
}

func TestCheckResponsePatternDefaultBodyBudget(t *testing.T) {
	// Trackers built from raw configs fall back to the default budget.
	cfg := &SecurityConfig{BehaviorScanResponseBody: true}
	tracker := NewBehaviorTracker(cfg, nil, nil, nil)
	long := []byte(strings.Repeat("x", 300000) + "needle")
	if matched, _ := tracker.CheckResponsePattern(&Response{StatusCode: 200, Body: long}, "needle"); matched {
		t.Fatal("default budgets truncate")
	}
}

func TestEngineMatcherRejectsPercentRuns(t *testing.T) {
	cfg := &SecurityConfig{ExcludePaths: []string{"/ok"}}
	m := &exclusionMatcher{cfg: cfg}
	// Paths whose percent runs never settle never match.
	if m.matches("/%2525") {
		t.Fatal("indeterminate percent runs never match")
	}
}

func TestCompositionCloseWithGeoCloserError(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	engine.Config.GeoIPHandler = failingGeoCloser{}
	if err := engine.Close(); err == nil {
		t.Fatal("geo closer errors surface")
	}
}

type failingGeoCloser struct{}

func (failingGeoCloser) GetCountry(string) (string, bool) { return "", false }
func (failingGeoCloser) Close() error                     { return errors.New("close boom") }

func TestCompositionProcessResponseNilResponse(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	// Nil responses skip the behavioral return stages entirely.
	engine.ProcessResponse(newTestRequest(t, nil), nil)
}

func TestEngineGroupCaptureInMatchers(t *testing.T) {
	// Capture groups flow into match metadata on both scan paths.
	grouped := mustCompile(`(b)`, 0, windowTimeout)
	tx := newScanText("abc")
	found := findAllMatches(grouped, tx)
	if len(found) != 1 || found[0].group1() != "b" {
		t.Fatalf("captures flow through sweeps, got %v", found)
	}
	m, ok := findFirstAt(grouped, tx, 1, 3)
	if !ok || m.group1() != "b" {
		t.Fatalf("captures flow through anchored finds, got %v %v", m, ok)
	}
	if m, ok := searchFrom(grouped, tx, 0); !ok || m.group1() != "b" {
		t.Fatalf("captures flow through searches, got %v %v", m, ok)
	}
}

func TestScanDollarBodyEscapeAtEnd(t *testing.T) {
	// Trailing escapes fail the body scan.
	if _, ok := scanDollarSubstitutionBody([]rune("(a\\"), 1, ')', '('); ok {
		t.Fatal("trailing escapes fail bodies")
	}
	// Unclosed bodies fail.
	if _, ok := scanDollarSubstitutionBody([]rune("(abc"), 1, ')', '('); ok {
		t.Fatal("unclosed bodies fail")
	}
	// Dollar-substitution openers walk past the paren pair.
	end, ok := scanBacktickCandidateBody([]rune("`$(id)x`"), 0)
	if !ok || end != 8 {
		t.Fatalf("dollar openers skip the pair, got %d %v", end, ok)
	}
}

func TestParseMultipartSiblingParts(t *testing.T) {
	body := "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nfirst\r\n" +
		"--b\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nsecond\r\n" +
		"--b--\r\n"
	parts := parseMultipartParts(body, "b")
	if len(parts) != 2 {
		t.Fatalf("sibling parts both parse, got %d", len(parts))
	}
	if string(parts[0].payload) != "first" || string(parts[1].payload) != "second" {
		t.Fatalf("siblings keep their payloads, got %q %q", parts[0].payload, parts[1].payload)
	}
}

func TestParseMultipartDanglingOpen(t *testing.T) {
	// A body that is only the opening boundary yields no parts.
	if parts := parseMultipartParts("--b", "b"); len(parts) != 0 {
		t.Fatalf("dangling opens yield nothing, got %v", parts)
	}
}

func TestGeoIPDownloadHTTPFailures(t *testing.T) {
	// Response bodies that fail mid-read surface the read error.
	m := &GeoIPManager{DBPath: t.TempDir() + "/db.mmdb", Token: "tok", sleep: func(time.Duration) {}}
	m.customHTTPClient = &http.Client{Transport: failingBodyRoundTripper{}}
	m.dataURL = "http://geo.test/db"
	if err := m.downloadDatabase(); err == nil {
		t.Fatal("failing bodies surface errors")
	}
	// Non-2xx statuses surface their status error.
	m2 := &GeoIPManager{DBPath: t.TempDir() + "/db.mmdb", Token: "tok", sleep: func(time.Duration) {}}
	m2.customHTTPClient = &http.Client{Transport: statusRoundTripper{status: 403}}
	m2.dataURL = "http://geo.test/db"
	if err := m2.downloadDatabase(); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("statuses surface, got %v", err)
	}
	// Successful downloads land on disk.
	m3 := &GeoIPManager{DBPath: t.TempDir() + "/db.mmdb", Token: "tok", sleep: func(time.Duration) {}}
	m3.customHTTPClient = &http.Client{Transport: statusRoundTripper{status: 200, body: []byte("database bytes")}}
	m3.dataURL = "http://geo.test/db"
	if err := m3.downloadDatabase(); err != nil {
		t.Fatalf("healthy downloads write, got %v", err)
	}
}

type failingBodyRoundTripper struct{}

func (failingBodyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: errReadCloser{}}, nil
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("read boom") }
func (errReadCloser) Close() error             { return nil }

type statusRoundTripper struct {
	status int
	body   []byte
}

func (s statusRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	body := s.body
	if body == nil {
		body = []byte("nope")
	}
	return &http.Response{StatusCode: s.status, Body: &sliceReadCloser{data: body}}, nil
}

type sliceReadCloser struct {
	data   []byte
	offset int
}

func (s *sliceReadCloser) Read(p []byte) (int, error) {
	if s.offset >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.offset:])
	s.offset += n
	return n, nil
}

func (s *sliceReadCloser) Close() error { return nil }
