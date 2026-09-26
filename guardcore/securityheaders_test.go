package guardcore

// Engine-level tests for the security headers management ported from
// guard_core/handlers/security_headers_handler.py and its config mixin.
// Blocked responses must carry the headers (the reference error factory
// applies them in create_error_response), the engine ResponseHeaders API
// feeds the adapters' pass-through application (factory.py process_response),
// and disabled or absent configuration yields no headers at all.

import (
	"reflect"
	"testing"
)

const headerTestIP = "192.0.2.50"

func newHeaderTestConfig(t *testing.T, mutate func(*SecurityConfig)) *SecurityConfig {
	t.Helper()
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func blockedHeaderResponse(t *testing.T, cfg *SecurityConfig) *Response {
	t.Helper()
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, nil)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = headerTestIP
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("expected the request to be blocked with 403, got %+v", resp)
	}
	return resp
}

func securityHeaderTestConfig(mutate func(sh *SecurityHeadersConfig)) func(*SecurityConfig) {
	return func(c *SecurityConfig) {
		c.Blacklist = []string{headerTestIP}
		if mutate != nil {
			mutate(c.SecurityHeaders)
		}
	}
}

// A blocked response carries the reference's default header set: the ten
// class defaults plus the default HSTS line.
func TestBlockedResponseCarriesDefaultSecurityHeaders(t *testing.T) {
	cfg := newHeaderTestConfig(t, securityHeaderTestConfig(nil))
	resp := blockedHeaderResponse(t, cfg)
	want := map[string]string{
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "SAMEORIGIN",
		"X-XSS-Protection":                  "1; mode=block",
		"Referrer-Policy":                   "strict-origin-when-cross-origin",
		"Permissions-Policy":                "geolocation=(), microphone=(), camera=()",
		"X-Permitted-Cross-Domain-Policies": "none",
		"X-Download-Options":                "noopen",
		"Cross-Origin-Embedder-Policy":      "require-corp",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":      "same-origin",
		"Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
	}
	if !reflect.DeepEqual(resp.Headers, want) {
		t.Fatalf("blocked response headers mismatch:\n got %v\nwant %v", resp.Headers, want)
	}
}

// The engine API that the adapters apply to pass-through responses returns
// the same default set, and honors configuration overrides and custom
// headers, with custom landing last.
func TestResponseHeadersAPIHonorsConfig(t *testing.T) {
	cfg := newHeaderTestConfig(t, func(c *SecurityConfig) {
		c.SecurityHeaders.FrameOptions = "DENY"
		c.SecurityHeaders.ReferrerPolicy = "no-referrer"
		c.SecurityHeaders.Custom = map[string]string{"X-Request-Realm": "edge"}
	})
	headers := (&Engine{Config: cfg}).ResponseHeaders()
	if headers["X-Frame-Options"] != "DENY" || headers["Referrer-Policy"] != "no-referrer" {
		t.Fatalf("overrides not honored: %v", headers)
	}
	if headers["X-Request-Realm"] != "edge" {
		t.Fatalf("custom header missing: %v", headers)
	}
	if _, ok := headers["Strict-Transport-Security"]; !ok {
		t.Fatalf("default HSTS missing: %v", headers)
	}

	cfg = newHeaderTestConfig(t, func(c *SecurityConfig) {
		c.SecurityHeaders.Custom = map[string]string{"X-Frame-Options": "SAMEORIGIN"}
		c.SecurityHeaders.FrameOptions = "DENY"
	})
	headers = (&Engine{Config: cfg}).ResponseHeaders()
	if headers["X-Frame-Options"] != "SAMEORIGIN" {
		t.Fatalf("custom headers must override the computed set last: %v", headers)
	}
}

// CSP and HSTS blocks build their header values like the reference.
func TestResponseHeadersCSPAndHSTS(t *testing.T) {
	cfg := newHeaderTestConfig(t, func(c *SecurityConfig) {
		c.SecurityHeaders.CSP = []CSPDirective{
			{Name: "default-src", Sources: []string{"'self'", "https://cdn.example.com"}},
			{Name: "upgrade-insecure-requests"},
		}
		c.SecurityHeaders.HSTS = &HSTSConfig{MaxAge: 63072000, IncludeSubdomains: true, Preload: true}
	})
	headers := (&Engine{Config: cfg}).ResponseHeaders()
	if got, want := headers["Content-Security-Policy"], "default-src 'self' https://cdn.example.com; upgrade-insecure-requests"; got != want {
		t.Fatalf("CSP = %q, want %q", got, want)
	}
	if got, want := headers["Strict-Transport-Security"], "max-age=63072000; includeSubDomains; preload"; got != want {
		t.Fatalf("HSTS = %q, want %q", got, want)
	}

	// Preload corrections: max_age below one year drops preload, and preload
	// forces includeSubDomains on.
	cfg = newHeaderTestConfig(t, func(c *SecurityConfig) {
		c.SecurityHeaders.HSTS = &HSTSConfig{MaxAge: 3600, IncludeSubdomains: false, Preload: true}
	})
	headers = (&Engine{Config: cfg}).ResponseHeaders()
	if got, want := headers["Strict-Transport-Security"], "max-age=3600; includeSubDomains"; got != want {
		t.Fatalf("corrected HSTS = %q, want %q", got, want)
	}
}

// The three-way Permissions-Policy value: nil keeps the class default, a
// pointer to "" removes the header, another value overrides it.
func TestResponseHeadersPermissionsPolicySemantics(t *testing.T) {
	cfg := newHeaderTestConfig(t, func(c *SecurityConfig) {
		c.SecurityHeaders.PermissionsPolicy = nil
	})
	headers := (&Engine{Config: cfg}).ResponseHeaders()
	if headers["Permissions-Policy"] != "geolocation=(), microphone=(), camera=()" {
		t.Fatalf("nil Permissions-Policy must keep the class default: %v", headers)
	}
	empty := ""
	cfg = newHeaderTestConfig(t, func(c *SecurityConfig) {
		c.SecurityHeaders.PermissionsPolicy = &empty
	})
	headers = (&Engine{Config: cfg}).ResponseHeaders()
	if _, ok := headers["Permissions-Policy"]; ok {
		t.Fatalf("empty Permissions-Policy must remove the header: %v", headers)
	}
	value := "geolocation=(self)"
	cfg = newHeaderTestConfig(t, func(c *SecurityConfig) {
		c.SecurityHeaders.PermissionsPolicy = &value
	})
	headers = (&Engine{Config: cfg}).ResponseHeaders()
	if headers["Permissions-Policy"] != value {
		t.Fatalf("Permissions-Policy override not honored: %v", headers)
	}
}

// Disabled security headers strip every header from blocked responses and
// from the adapter API; a nil configuration behaves like disabled.
func TestDisabledSecurityHeadersYieldNone(t *testing.T) {
	cfg := newHeaderTestConfig(t, securityHeaderTestConfig(func(sh *SecurityHeadersConfig) {
		sh.Enabled = false
	}))
	resp := blockedHeaderResponse(t, cfg)
	if len(resp.Headers) != 0 {
		t.Fatalf("disabled config must not emit headers on blocks, got %v", resp.Headers)
	}
	if headers := (&Engine{Config: cfg}).ResponseHeaders(); len(headers) != 0 {
		t.Fatalf("disabled config must produce no adapter headers, got %v", headers)
	}
	cfg = newHeaderTestConfig(t, func(c *SecurityConfig) {
		c.Blacklist = []string{headerTestIP}
		c.SecurityHeaders = nil
	})
	resp = blockedHeaderResponse(t, cfg)
	if len(resp.Headers) != 0 {
		t.Fatalf("nil security_headers must not emit headers on blocks, got %v", resp.Headers)
	}
}

// Fail-closed validation: invalid custom names, CRLF values, oversized
// values and broken overrides all fail config construction; control
// characters are sanitized away like the reference.
func TestSecurityHeadersValidation(t *testing.T) {
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.SecurityHeaders.Custom = map[string]string{"bad name\n": "x"}
	}); err == nil {
		t.Fatalf("invalid custom header name must fail config construction")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.SecurityHeaders.Custom = map[string]string{"X-Ok": "line1\r\nline2"}
	}); err == nil {
		t.Fatalf("CRLF header value must fail config construction")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.SecurityHeaders.Custom = map[string]string{"X-Big": string(make([]byte, 8193))}
	}); err == nil {
		t.Fatalf("oversized header value must fail config construction")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.SecurityHeaders.FrameOptions = "SAME\rORIGIN"
	}); err == nil {
		t.Fatalf("CRLF in an override must fail config construction")
	}
	cfg := newHeaderTestConfig(t, func(c *SecurityConfig) {
		c.SecurityHeaders.Custom = map[string]string{"X-Ok": "a\x01\x02b\tc"}
	})
	if got := cfg.SecurityHeaders.Custom["X-Ok"]; got != "ab\tc" {
		t.Fatalf("control characters must be sanitized away, got %q", got)
	}
}
