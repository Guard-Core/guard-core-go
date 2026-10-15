package guardcore

import (
	"encoding/base64"
	"testing"
)

// sessionCookieHeader is the Guard-Core/guard-core#161 repro: a JWT session
// cookie with the issue's claims plus theme=system and _ga.
func sessionCookieHeader() string {
	enc := base64.RawURLEncoding.EncodeToString
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	jwt := enc([]byte(`{"alg": "ES256", "typ": "JWT"}`)) + "." +
		enc([]byte(`{"sub": "3f2c1b9e-8a47-4d2e-9c1f-5b6a7d8e9f01", "name": "Jane Doe (Acme)", "email": "jane.doe@example.com", "roles": ["admin"], "iat": 1792000000, "exp": 1792000900}`)) + "." +
		enc(sig)
	return "session=" + jwt + "; theme=system; _ga=GA1.1.123456789.1792000000"
}

// scanThreatCounts runs the request header scan and returns the regex and
// semantic threat counts the pattern_detected telemetry event carries:
// detectThreat itself reports regex categories only, so the event is where
// a semantic hit is observable.
func scanThreatCounts(t *testing.T, cfg *SecurityConfig, route *RouteConfig, headers map[string]string) (regex, semantic int) {
	t.Helper()
	resetSusPatternsForTest(t)
	agent := &susCaptureAgent{}
	DefaultSusPatternsManager.SetAgentHandler(agent)
	defer DefaultSusPatternsManager.SetAgentHandler(nil)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { opts.Header = headers })
	detectThreat(req, cfg, resolveDetectionExclusions(cfg, route))
	for _, event := range agent.events {
		r, _ := event.Metadata["regex_threats"].(int)
		s, _ := event.Metadata["semantic_threats"].(int)
		regex, semantic = regex+r, semantic+s
	}
	return regex, semantic
}

// semanticScanFired reports whether the semantic analyzer flagged a header.
func semanticScanFired(t *testing.T, cfg *SecurityConfig, route *RouteConfig, headers map[string]string) bool {
	t.Helper()
	_, semantic := scanThreatCounts(t, cfg, route, headers)
	return semantic > 0
}

func TestSemanticHeaderExclusionDefaultScansSemantics(t *testing.T) {
	cfg := newDetectConfig(t, nil)
	if !semanticScanFired(t, cfg, nil, map[string]string{"x-session": sessionCookieHeader()}) {
		t.Fatal("with no opt-in the semantic analyzer must still flag the session value (0.711)")
	}
}

func TestSemanticHeaderExclusionGlobalSkipsSemanticOnly(t *testing.T) {
	cfg := newDetectConfig(t, func(c *SecurityConfig) {
		c.ExcludedSemanticDetectionHeaders = map[string]bool{" X-Session ": true}
	})
	if semanticScanFired(t, cfg, nil, map[string]string{"x-session": sessionCookieHeader()}) {
		t.Fatal("a semantic-excluded header (any case, trimmed) must skip the semantic analyzer")
	}
	if !semanticScanFired(t, cfg, nil, map[string]string{"x-other": sessionCookieHeader()}) {
		t.Fatal("headers outside the set must keep the semantic analyzer")
	}
	categories := runDetectThreatHeaders(t, cfg, map[string]string{"x-session": "<script>alert(1)</script>"})
	if !containsString(categories, "xss") {
		t.Fatalf("regex scanning of a semantic-excluded header must be unchanged, got %v", categories)
	}
}

func TestSemanticHeaderExclusionRouteMergesWithGlobal(t *testing.T) {
	cfg := newDetectConfig(t, func(c *SecurityConfig) {
		c.ExcludedSemanticDetectionHeaders = map[string]bool{"x-global": true}
	})
	route := &RouteConfig{ExcludedSemanticDetectionHeaders: map[string]bool{"X-Route": true}}
	r := resolveDetectionExclusions(cfg, route)
	if !r.semanticHeaders["x-global"] || !r.semanticHeaders["x-route"] || len(r.semanticHeaders) != 2 {
		t.Fatalf("route set must merge with the global set, got %v", r.semanticHeaders)
	}
	for _, name := range []string{"x-global", "x-route"} {
		if semanticScanFired(t, cfg, route, map[string]string{name: sessionCookieHeader()}) {
			t.Fatalf("%s must skip the semantic analyzer", name)
		}
	}
	if r := resolveDetectionExclusions(cfg, &RouteConfig{}); !r.semanticHeaders["x-global"] || len(r.semanticHeaders) != 1 {
		t.Fatalf("a route without the set keeps the global set, got %v", r.semanticHeaders)
	}
}
