package guardcore

// Engine-level tests for the CORS handling. Semantics mirror the reference
// CorsHandler (guard_core/handlers/cors_handler.py) plus the adapter
// dispatch contract (fastapi-guard guard/middleware.py): a preflight
// (OPTIONS + access-control-request-method) runs the security pipeline and
// is then short-circuited with 200 "OK" or 400 "Disallowed CORS: ...",
// blocked responses compose the CORS headers on top of the security-header
// set, and a disallowed origin on a normal response gets no CORS headers at
// all (the browser enforces).

import (
	"strings"
	"testing"
)

func newCORSTestEngine(t *testing.T, mutate func(*SecurityConfig)) *Engine {
	t.Helper()
	engine, err := NewEngine(newCompositionConfig(t, mutate))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return engine
}

func corsTestConfig(mutate func(*SecurityConfig)) func(*SecurityConfig) {
	return func(c *SecurityConfig) {
		c.EnableCORS = true
		c.CORSAllowOrigins = []string{"https://app.example.com"}
		c.CORSAllowMethods = []string{"GET", "POST"}
		c.CORSAllowHeaders = []string{"content-type", "x-request-id"}
		if mutate != nil {
			mutate(c)
		}
	}
}

func preflightRequest(t *testing.T, mutate func(opts *RequestOptions, state *RequestState)) Request {
	t.Helper()
	return newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Method = "OPTIONS"
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Access-Control-Request-Method"] = "GET"
		opts.Header["Origin"] = "https://app.example.com"
		if mutate != nil {
			mutate(opts, state)
		}
	})
}

func headerValue(resp *Response, name string) (string, bool) {
	for key, value := range resp.Headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

// A valid preflight is short-circuited with 200 "OK", the echoed origin, the
// joined allow-methods, the max-age and the Vary hint.
func TestPreflightAllowedReturnsOK(t *testing.T) {
	engine := newCORSTestEngine(t, corsTestConfig(nil))
	resp := engine.Check(preflightRequest(t, nil))
	if resp == nil || resp.StatusCode != 200 || string(resp.Body) != "OK" {
		t.Fatalf("allowed preflight must answer 200 OK, got %+v", resp)
	}
	for name, want := range map[string]string{
		"Access-Control-Allow-Origin":  "https://app.example.com",
		"Access-Control-Allow-Methods": "GET, POST",
		"Access-Control-Max-Age":       "600",
		"Vary":                         "Origin",
	} {
		if got, ok := headerValue(resp, name); !ok || got != want {
			t.Fatalf("preflight %s = %q (%v), want %q", name, got, ok, want)
		}
	}
	if _, ok := headerValue(resp, "Access-Control-Allow-Credentials"); ok {
		t.Fatalf("credentials header must be absent while cors_allow_credentials is false")
	}
}

// A wildcard policy without credentials answers preflights with "*".
func TestPreflightWildcardOriginAnswersStar(t *testing.T) {
	engine := newCORSTestEngine(t, corsTestConfig(nil))
	engine.CORS.allowAllOrigins = true
	resp := engine.Check(preflightRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Header["Origin"] = "https://other.example.org"
	}))
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("wildcard preflight must answer 200, got %+v", resp)
	}
	if got, _ := headerValue(resp, "Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("wildcard origin must answer *, got %q", got)
	}
}

// Disallowed origin, method, or requested headers fail the preflight with
// 400 and the reference "Disallowed CORS: <failures>" body; the verdict
// headers are still attached, exactly like the reference builds them before
// deciding.
func TestPreflightDisallowedRequests(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(opts *RequestOptions, state *RequestState)
		body    string
		acaoSet bool
	}{
		{"disallowed origin", func(opts *RequestOptions, state *RequestState) {
			opts.Header["Origin"] = "https://evil.example.net"
		}, "Disallowed CORS: origin", false},
		{"disallowed method", func(opts *RequestOptions, state *RequestState) {
			opts.Header["Access-Control-Request-Method"] = "DELETE"
		}, "Disallowed CORS: method", true},
		{"disallowed requested header", func(opts *RequestOptions, state *RequestState) {
			opts.Header["Access-Control-Request-Headers"] = "content-type, x-private-token"
		}, "Disallowed CORS: headers", true},
		{"origin and method together", func(opts *RequestOptions, state *RequestState) {
			opts.Header["Origin"] = "https://evil.example.net"
			opts.Header["Access-Control-Request-Method"] = "DELETE"
		}, "Disallowed CORS: origin, method", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newCORSTestEngine(t, corsTestConfig(nil))
			resp := engine.Check(preflightRequest(t, tc.mutate))
			if resp == nil || resp.StatusCode != 400 {
				t.Fatalf("disallowed preflight must answer 400, got %+v", resp)
			}
			if string(resp.Body) != tc.body {
				t.Fatalf("disallowed preflight body = %q, want %q", resp.Body, tc.body)
			}
			_, acao := headerValue(resp, "Access-Control-Allow-Origin")
			if acao != tc.acaoSet {
				t.Fatalf("preflight ACAO presence = %v, want %v", acao, tc.acaoSet)
			}
			if got, ok := headerValue(resp, "Access-Control-Allow-Methods"); !ok || got != "GET, POST" {
				t.Fatalf("the 400 must still carry allow-methods, got %q (%v)", got, ok)
			}
		})
	}
}

// With allow-headers wildcard the preflight echoes the requested headers
// verbatim instead of checking membership.
func TestPreflightAllowAllHeadersEchoesRequest(t *testing.T) {
	engine := newCORSTestEngine(t, corsTestConfig(nil))
	engine.CORS.allowAllHeaders = true
	resp := engine.Check(preflightRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Header["Access-Control-Request-Headers"] = "X-Custom, Content-Type"
	}))
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("allow-all-headers preflight must answer 200, got %+v", resp)
	}
	if got, _ := headerValue(resp, "Access-Control-Allow-Headers"); got != "X-Custom, Content-Type" {
		t.Fatalf("allow-all-headers must echo the raw requested value, got %q", got)
	}
}

// Credentials add the allow-credentials header on a passing preflight; the
// wildcard + credentials combination is accepted at construction and
// downgraded at policy resolution (credentials dropped, wildcard answers
// without the allow-credentials header), like the reference
// _compute_cors_config.
func TestPreflightCredentials(t *testing.T) {
	engine := newCORSTestEngine(t, corsTestConfig(nil))
	engine.CORS.allowCredentials = true
	resp := engine.Check(preflightRequest(t, nil))
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("credentialed preflight must answer 200, got %+v", resp)
	}
	if got, _ := headerValue(resp, "Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("credentials preflight must carry allow-credentials true, got %q", got)
	}
	if got, _ := headerValue(resp, "Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("credentialed preflight must echo the origin, not *, got %q", got)
	}

	wildcardCreds, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableCORS = true
		c.CORSAllowOrigins = []string{"*"}
		c.CORSAllowCredentials = true
	})
	if err != nil {
		t.Fatalf("wildcard + credentials must be accepted at construction, got %v", err)
	}
	policy := newCORSPolicy(wildcardCreds)
	if policy == nil || !policy.allowAllOrigins {
		t.Fatalf("wildcard + credentials must resolve to an allow-all policy: %+v", policy)
	}
	if policy.allowCredentials {
		t.Fatalf("wildcard + credentials must drop the credentials flag at resolution (the reference _compute_cors_config downgrade)")
	}
}

// A preflight still runs the security pipeline first: a blacklisted origin
// IP gets the blocked 403 with the CORS headers composed on top of the
// engine security headers (the reference _handle_preflight blocked path).
func TestPreflightBlockedResponseComposesCORSAndSecurityHeaders(t *testing.T) {
	engine := newCORSTestEngine(t, corsTestConfig(nil))
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "unit-test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	resp := engine.Check(preflightRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.113.7"
	}))
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != IPBanBlockedMessage {
		t.Fatalf("blocked preflight must return the pipeline 403, got %+v", resp)
	}
	if got, ok := headerValue(resp, "Access-Control-Allow-Origin"); !ok || got != "https://app.example.com" {
		t.Fatalf("blocked preflight must compose the CORS origin, got %q (%v)", got, ok)
	}
	if got, _ := headerValue(resp, "X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("blocked response must keep the security headers, got %q", got)
	}
}

// Blocked ordinary responses compose the CORS headers too; a disallowed
// origin gets the security headers without any CORS header.
func TestBlockedResponseCORSComposition(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		acao   string
	}{
		{"allowed origin", "https://app.example.com", "https://app.example.com"},
		{"disallowed origin", "https://evil.example.net", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newCORSTestEngine(t, corsTestConfig(nil))
			if _, err := engine.Ban.Ban("203.0.113.7", 60, "unit-test"); err != nil {
				t.Fatalf("ban: %v", err)
			}
			resp := engine.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
				opts.ClientHost = "203.0.113.7"
				opts.Header = map[string]string{"Origin": tc.origin}
			}))
			if resp == nil || resp.StatusCode != 403 {
				t.Fatalf("blacklisted IP must be blocked, got %+v", resp)
			}
			if got, _ := headerValue(resp, "X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("blocked response must keep the security headers, got %q", got)
			}
			got, _ := headerValue(resp, "Access-Control-Allow-Origin")
			if got != tc.acao {
				t.Fatalf("blocked response ACAO = %q, want %q", got, tc.acao)
			}
		})
	}
}

// Pass-through responses get their CORS headers from the CORSResponseHeaders
// API, mirroring _inject_cors_headers: no origin, no headers; a disallowed
// origin gets nothing; expose headers ride along.
func TestCORSResponseHeadersAPI(t *testing.T) {
	engine := newCORSTestEngine(t, corsTestConfig(func(c *SecurityConfig) {
		c.CORSExposeHeaders = []string{"X-Request-Id"}
	}))
	req := newTestRequest(t, nil)
	if headers := engine.CORSResponseHeaders(req); headers != nil {
		t.Fatalf("no Origin header must yield no CORS headers, got %v", headers)
	}
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Header = map[string]string{"Origin": "https://app.example.com"}
	})
	headers := engine.CORSResponseHeaders(req)
	for name, want := range map[string]string{
		"Vary":                          "Origin",
		"Access-Control-Allow-Origin":   "https://app.example.com",
		"Access-Control-Expose-Headers": "X-Request-Id",
	} {
		if headers[name] != want {
			t.Fatalf("CORSResponseHeaders[%s] = %q, want %q", name, headers[name], want)
		}
	}
	req = newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Header = map[string]string{"Origin": "https://evil.example.net"}
	})
	if headers := engine.CORSResponseHeaders(req); headers != nil {
		t.Fatalf("disallowed origin must yield no CORS headers, got %v", headers)
	}
}

// With CORS disabled the engine behaves exactly as before: no CORS headers
// anywhere, preflights are ordinary requests.
func TestCORSDisabledKeepsPriorBehavior(t *testing.T) {
	engine := newCORSTestEngine(t, nil)
	if engine.CORS != nil {
		t.Fatalf("CORS policy must be nil while disabled")
	}
	req := preflightRequest(t, nil)
	if resp := engine.Check(req); resp != nil {
		t.Fatalf("preflight without CORS must run the plain pipeline, got %+v", resp)
	}
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "unit-test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	resp := engine.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.113.7"
		opts.Header = map[string]string{"Origin": "https://app.example.com"}
	}))
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("blocked response expected, got %+v", resp)
	}
	if _, ok := headerValue(resp, "Access-Control-Allow-Origin"); ok {
		t.Fatalf("no CORS header may appear while CORS is disabled")
	}
}

// An OPTIONS request without the access-control-request-method header is
// not a preflight and flows through the pipeline like any other request.
func TestOptionWithoutPreflightHeaderIsOrdinary(t *testing.T) {
	engine := newCORSTestEngine(t, corsTestConfig(nil))
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Method = "OPTIONS"
		opts.Header = map[string]string{"Origin": "https://app.example.com"}
	})
	if IsPreflight(req) {
		t.Fatalf("OPTIONS without the preflight header must not detect as preflight")
	}
	if resp := engine.Check(req); resp != nil {
		t.Fatalf("ordinary OPTIONS must flow through the pipeline, got %+v", resp)
	}
}

// Config normalization mirrors CorsHandler._init_enabled: methods
// uppercased, header names lowercased, and the defaults from the field
// definitions.
func TestCORSConfigNormalization(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableCORS = true
		c.CORSAllowOrigins = []string{"https://App.example.com"}
		c.CORSAllowMethods = []string{"get", "Post"}
		c.CORSAllowHeaders = []string{"Content-Type", "X-Request-Id"}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if got := strings.Join(cfg.CORSAllowMethods, ","); got != "GET,POST" {
		t.Fatalf("methods must be uppercased, got %q", got)
	}
	if got := strings.Join(cfg.CORSAllowHeaders, ","); got != "content-type,x-request-id" {
		t.Fatalf("headers must be lowercased, got %q", got)
	}
	if cfg.CORSMaxAge != 600 {
		t.Fatalf("default max-age must be 600, got %d", cfg.CORSMaxAge)
	}
}

// The runtime fallbacks mirror the reference `or` defaults: an empty method
// list answers ["GET"] and a zero max-age answers 600.
func TestCORSPolicyRuntimeFallbacks(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableCORS = true
		c.CORSAllowMethods = nil
		c.CORSMaxAge = 0
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	resp := engine.Check(preflightRequest(t, nil))
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("GET preflight must pass the GET fallback policy, got %+v", resp)
	}
	if got, _ := headerValue(resp, "Access-Control-Allow-Methods"); got != "GET" {
		t.Fatalf("empty method list must fall back to GET, got %q", got)
	}
	if got, _ := headerValue(resp, "Access-Control-Max-Age"); got != "600" {
		t.Fatalf("zero max-age must fall back to 600, got %q", got)
	}
}
