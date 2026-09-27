package guardcore

import (
	"strings"
	"testing"
	"time"
)

func routeTestRequest(t *testing.T, mutate func(opts *RequestOptions, state *RequestState)) Request {
	t.Helper()
	return newTestRequest(t, mutate)
}

func TestRouteRegistryRegisterGetRevision(t *testing.T) {
	registry := NewRouteRegistry()
	if registry.Revision() != 0 {
		t.Fatalf("initial revision must be 0")
	}
	registry.Register("/api/data", func(rc *RouteConfig) { rc.RequireHTTPS = true })
	if registry.Revision() != 1 {
		t.Fatalf("register must bump revision, got %d", registry.Revision())
	}
	rc := registry.Get("/api/data")
	if rc == nil || !rc.RequireHTTPS {
		t.Fatalf("route config not stored: %+v", rc)
	}
	if registry.Get("/missing") != nil {
		t.Fatalf("unknown route must resolve to nil")
	}
	if rc.EnableSuspiciousDetection != true {
		t.Fatalf("default enable_suspicious_detection must be true")
	}
}

func TestRouteConfigHasBypass(t *testing.T) {
	rc := &RouteConfig{BypassedChecks: []string{"rate_limit"}}
	if !rc.HasBypass("rate_limit") || rc.HasBypass("ip") {
		t.Fatalf("HasBypass mismatch")
	}
	if !(&RouteConfig{BypassedChecks: []string{"all"}}).HasBypass("anything") {
		t.Fatalf("'all' must bypass every check")
	}
	if ShouldBypassCheck("ip", nil) {
		t.Fatalf("nil route config must not bypass")
	}
}

func TestRouteResolverMatchesReference(t *testing.T) {
	registry := NewRouteRegistry()
	registry.Register("/exact", func(rc *RouteConfig) { rc.AuthRequired = "bearer" })
	resolver := NewRouteConfigResolver(registry)
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/exact"
	})
	if got := resolver.GetRouteConfig(req.State()); got == nil || got.AuthRequired != "bearer" {
		t.Fatalf("resolver must return registered config, got %+v", got)
	}
	req2 := routeTestRequest(t, nil)
	if got := resolver.GetRouteConfig(req2.State()); got != nil {
		t.Fatalf("unresolved route id must yield nil, got %+v", got)
	}
	if resolver.GetRouteConfig(nil) != nil {
		t.Fatalf("nil state must yield nil")
	}
}

func TestRouteConfigCheckStashesAndResolves(t *testing.T) {
	registry := NewRouteRegistry()
	registry.Register("/api", nil)
	cfg := testConfig(t)
	check := &routeConfigCheck{cfg: cfg, registry: registry}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/api"
		state.RouteUnresolved = false
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("resolved route must pass, got %+v", resp)
	}
	if req.State().RouteConfig == nil {
		t.Fatalf("route config must be stashed on state")
	}
	if req.State().ClientIP != "203.0.113.9" {
		t.Fatalf("client ip must be resolved into state, got %q", req.State().ClientIP)
	}
}

func TestRouteConfigCheckStrictUnresolved(t *testing.T) {
	registry := NewRouteRegistry()
	cfg := testConfig(t)
	cfg.RouteResolutionStrict = true
	check := &routeConfigCheck{cfg: cfg, registry: registry}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteUnresolved = true
	})
	resp := check.Check(req)
	if resp == nil || resp.StatusCode != 500 || string(resp.Body) != "Route resolution failed" {
		t.Fatalf("strict unresolved route must 500, got %+v", resp)
	}
	if req.State().BlockStash == nil || req.State().BlockStash == nil || req.State().BlockStash.TriggerInfo != "" {
		t.Fatalf("block stash missing: %+v", req.State().BlockStash)
	}
	passive := testConfig(t)
	passive.RouteResolutionStrict = true
	passive.PassiveMode = true
	fired := false
	passive.OnBlock = func(req Request, payload map[string]any) {
		fired = true
		if payload["check_name"] != "route_config" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
	}
	req2 := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteUnresolved = true
	})
	if resp := (&routeConfigCheck{cfg: passive, registry: registry}).Check(req2); resp != nil {
		t.Fatalf("passive mode must not block, got %+v", resp)
	}
	if !fired {
		t.Fatalf("passive block hook must fire")
	}
}

func TestEmergencyModeBlocks503(t *testing.T) {
	cfg := testConfig(t)
	cfg.EmergencyMode = true
	check := &emergencyModeCheck{cfg: cfg}
	resp := check.Check(routeTestRequest(t, nil))
	if resp == nil || resp.StatusCode != 503 || string(resp.Body) != "Service temporarily unavailable" {
		t.Fatalf("emergency mode must 503, got %+v", resp)
	}
	if cfg.EmergencyWhitelist != nil {
		t.Fatalf("whitelist must default empty")
	}
}

func TestEmergencyModeWhitelistAllowed(t *testing.T) {
	cfg := testConfig(t)
	cfg.EmergencyMode = true
	cfg.EmergencyWhitelist = []string{"203.0.113.9"}
	check := &emergencyModeCheck{cfg: cfg}
	if resp := check.Check(routeTestRequest(t, nil)); resp != nil {
		t.Fatalf("whitelisted IP must pass, got %+v", resp)
	}
	cfg.EmergencyWhitelist = []string{"203.0.113.0/24"}
	if resp := check.Check(routeTestRequest(t, nil)); resp != nil {
		t.Fatalf("whitelisted CIDR must pass, got %+v", resp)
	}
}

func TestEmergencyModePassiveSuppression(t *testing.T) {
	cfg := testConfig(t)
	cfg.EmergencyMode = true
	cfg.PassiveMode = true
	fired := false
	cfg.OnBlock = func(req Request, payload map[string]any) {
		fired = true
		if payload["check_name"] != "emergency_mode" || payload["passive_mode"] != true {
			t.Fatalf("unexpected payload: %+v", payload)
		}
	}
	check := &emergencyModeCheck{cfg: cfg}
	if resp := check.Check(routeTestRequest(t, nil)); resp != nil {
		t.Fatalf("passive emergency mode must not block, got %+v", resp)
	}
	if !fired {
		t.Fatalf("passive hook must fire")
	}
}

func TestEmergencyModeAppliesTo(t *testing.T) {
	cfg := testConfig(t)
	check := &emergencyModeCheck{cfg: cfg}
	if check.AppliesTo(cfg) {
		t.Fatalf("must not apply with emergency off")
	}
	cfg.EmergencyMode = true
	if !check.AppliesTo(cfg) {
		t.Fatalf("must apply when emergency mode on")
	}
	off := testConfig(t)
	off.EnableDynamicRules = true
	if !check.AppliesTo(off) {
		t.Fatalf("must apply with dynamic rules")
	}
}

func TestHTTPSEnforcementRedirects301(t *testing.T) {
	cfg := testConfig(t)
	cfg.EnforceHTTPS = true
	check := &httpsEnforcementCheck{cfg: cfg}
	resp := check.Check(routeTestRequest(t, nil))
	if resp == nil || resp.StatusCode != 301 {
		t.Fatalf("http request must 301, got %+v", resp)
	}
	if resp.Headers["Location"] != "https://example.com/api" {
		t.Fatalf("bad redirect target: %v", resp.Headers)
	}
}

func TestHTTPSEnforcementAllowsHTTPS(t *testing.T) {
	cfg := testConfig(t)
	cfg.EnforceHTTPS = true
	check := &httpsEnforcementCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, _ *RequestState) { opts.Scheme = "https" })
	if resp := check.Check(req); resp != nil {
		t.Fatalf("https request must pass, got %+v", resp)
	}
}

func TestHTTPSEnforcementTrustedProxyXFP(t *testing.T) {
	cfg := testConfig(t)
	cfg.EnforceHTTPS = true
	cfg.TrustXForwardedProto = true
	cfg.TrustedProxies = []string{"10.0.0.1"}
	check := &httpsEnforcementCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "10.0.0.1"
		opts.Header = map[string]string{"X-Forwarded-Proto": "https"}
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("trusted proxy https XFP must pass, got %+v", resp)
	}
	reqUntrusted := routeTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "198.51.100.7"
		opts.Header = map[string]string{"X-Forwarded-Proto": "https"}
	})
	if resp := check.Check(reqUntrusted); resp == nil || resp.StatusCode != 301 {
		t.Fatalf("untrusted proxy XFP must redirect, got %+v", resp)
	}
	reqHTTP := routeTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.ClientHost = "10.0.0.1"
		opts.Header = map[string]string{"X-Forwarded-Proto": "http"}
	})
	if resp := check.Check(reqHTTP); resp == nil || resp.StatusCode != 301 {
		t.Fatalf("http XFP must redirect, got %+v", resp)
	}
}

func TestHTTPSEnforcementRouteOverride(t *testing.T) {
	cfg := testConfig(t)
	cfg.EnforceHTTPS = false
	check := &httpsEnforcementCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequireHTTPS: true}
	})
	if resp := check.Check(req); resp == nil || resp.StatusCode != 301 {
		t.Fatalf("route require_https must redirect even when global off, got %+v", resp)
	}
	reqOff := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequireHTTPS: false}
	})
	cfg.EnforceHTTPS = true
	if resp := check.Check(reqOff); resp != nil {
		t.Fatalf("route opt-out must disable redirect, got %+v", resp)
	}
}

func TestHTTPSEnforcementPassiveAndOnBlockSuppressed(t *testing.T) {
	cfg := testConfig(t)
	cfg.EnforceHTTPS = true
	cfg.PassiveMode = true
	fired := false
	cfg.OnBlock = func(req Request, payload map[string]any) { fired = true }
	check := &httpsEnforcementCheck{cfg: cfg}
	if resp := check.Check(routeTestRequest(t, nil)); resp != nil {
		t.Fatalf("passive must not redirect, got %+v", resp)
	}
	if fired {
		t.Fatalf("https_enforcement must be suppressed from on_block")
	}
}

func TestRequestSizeContent413(t *testing.T) {
	cfg := testConfig(t)
	check := &requestSizeContentCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{MaxRequestSize: 100}
		opts.Header = map[string]string{"Content-Length": "101"}
	})
	resp := check.Check(req)
	if resp == nil || resp.StatusCode != 413 || string(resp.Body) != "Request too large" {
		t.Fatalf("oversize must 413, got %+v", resp)
	}
	if req.State().BlockStash == nil || req.State().BlockStash.TriggerInfo != "" {
		t.Fatalf("stash missing: %+v", req.State().BlockStash)
	}
	if !strings.Contains(req.State().BlockStash.Reason, "Request size 101 exceeds limit: 100") {
		t.Fatalf("bad reason: %q", req.State().BlockStash.Reason)
	}
}

func TestRequestSizeContentAllowed(t *testing.T) {
	cfg := testConfig(t)
	check := &requestSizeContentCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{MaxRequestSize: 100}
		opts.Header = map[string]string{"Content-Length": "100"}
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("at-limit must pass, got %+v", resp)
	}
	noLength := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{MaxRequestSize: 100}
	})
	if resp := check.Check(noLength); resp != nil {
		t.Fatalf("missing content-length must pass, got %+v", resp)
	}
}

func TestRequestSizeContent415(t *testing.T) {
	cfg := testConfig(t)
	check := &requestSizeContentCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AllowedContentTypes: []string{"application/json"}}
		opts.Header = map[string]string{"Content-Type": "text/plain; charset=utf-8"}
	})
	resp := check.Check(req)
	if resp == nil || resp.StatusCode != 415 || string(resp.Body) != "Unsupported content type" {
		t.Fatalf("bad content type must 415, got %+v", resp)
	}
	reqOK := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AllowedContentTypes: []string{"application/json"}}
		opts.Header = map[string]string{"Content-Type": "application/json; charset=utf-8"}
	})
	if resp := check.Check(reqOK); resp != nil {
		t.Fatalf("params stripped before comparison, got %+v", resp)
	}
	reqNoHeader := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AllowedContentTypes: []string{"application/json"}}
	})
	if resp := check.Check(reqNoHeader); resp == nil || resp.StatusCode != 415 {
		t.Fatalf("missing content type must 415, got %+v", resp)
	}
}

func TestRequestSizeContentNoRoutePasses(t *testing.T) {
	cfg := testConfig(t)
	check := &requestSizeContentCheck{cfg: cfg}
	if resp := check.Check(routeTestRequest(t, nil)); resp != nil {
		t.Fatalf("no route config must pass, got %+v", resp)
	}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{}
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("route without limits must pass, got %+v", resp)
	}
}

func TestRequiredHeaders(t *testing.T) {
	cfg := testConfig(t)
	check := &requiredHeadersCheck{cfg: cfg}
	missing := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequiredHeaders: RequiredHeaders{{Name: "X-Client", Value: "required"}}}
	})
	resp := check.Check(missing)
	if resp == nil || resp.StatusCode != 400 || string(resp.Body) != "Missing required header: X-Client" {
		t.Fatalf("missing header must 400, got %+v", resp)
	}
	mismatch := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequiredHeaders: RequiredHeaders{{Name: "X-Client", Value: "ios"}}}
		opts.Header = map[string]string{"X-Client": "android"}
	})
	resp = check.Check(mismatch)
	if resp == nil || resp.StatusCode != 400 || string(resp.Body) != "Header 'X-Client' does not match the required value" {
		t.Fatalf("mismatched header must 400, got %+v", resp)
	}
	ok := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequiredHeaders: RequiredHeaders{
			{Name: "X-Client", Value: "ios"},
			{Name: "X-Token", Value: "required"},
		}}
		opts.Header = map[string]string{"X-Client": "ios", "X-Token": "whatever"}
	})
	if resp := check.Check(ok); resp != nil {
		t.Fatalf("satisfied headers must pass, got %+v", resp)
	}
}

func TestRequiredHeadersPassive(t *testing.T) {
	cfg := testConfig(t)
	cfg.PassiveMode = true
	fired := false
	cfg.OnBlock = func(req Request, payload map[string]any) {
		fired = true
		if payload["check_name"] != "required_headers" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
	}
	check := &requiredHeadersCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequiredHeaders: RequiredHeaders{{Name: "X-Client", Value: "required"}}}
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("passive must not block, got %+v", resp)
	}
	if !fired {
		t.Fatalf("passive hook must fire")
	}
}

func TestAuthenticationPresenceOnly(t *testing.T) {
	cfg := testConfig(t)
	check := &authenticationCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AuthorizationHeaderRequired: "basic"}
	})
	resp := check.Check(req)
	if resp == nil || resp.StatusCode != 401 || string(resp.Body) != "Authentication required" {
		t.Fatalf("missing authorization must 401, got %+v", resp)
	}
	if req.State().BlockStash == nil || req.State().BlockStash.TriggerInfo != "" {
		t.Fatalf("violation type must be authorization_header, got %+v", req.State().BlockStash)
	}
	okReq := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AuthorizationHeaderRequired: "bearer"}
		opts.Header = map[string]string{"Authorization": "Bearer anything"}
	})
	if resp := check.Check(okReq); resp != nil {
		t.Fatalf("presence-only scheme satisfied must pass without verifier, got %+v", resp)
	}
}

func TestAuthenticationBearerWithVerifier(t *testing.T) {
	cfg := testConfig(t)
	check := &authenticationCheck{cfg: cfg}
	verifier := func(req Request, credential string) (any, error) {
		if credential == "good" {
			return "user-1", nil
		}
		return nil, nil
	}
	okReq := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AuthRequired: "bearer", AuthVerifier: verifier}
		opts.Header = map[string]string{"Authorization": "Bearer good"}
	})
	if resp := check.Check(okReq); resp != nil {
		t.Fatalf("valid credential must pass, got %+v", resp)
	}
	if okReq.State().AuthPrincipal != "user-1" {
		t.Fatalf("principal must be stashed, got %v", okReq.State().AuthPrincipal)
	}
	badReq := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AuthRequired: "bearer", AuthVerifier: verifier}
		opts.Header = map[string]string{"Authorization": "Bearer bad"}
	})
	resp := check.Check(badReq)
	if resp == nil || resp.StatusCode != 401 || string(resp.Body) != "Authentication required" {
		t.Fatalf("invalid credential must 401, got %+v", resp)
	}
	schemeReq := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AuthRequired: "bearer", AuthVerifier: verifier}
		opts.Header = map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}
	})
	if resp := check.Check(schemeReq); resp == nil || resp.StatusCode != 401 {
		t.Fatalf("wrong scheme must 401, got %+v", resp)
	}
}

func TestAuthenticationVerifierFailurePaths(t *testing.T) {
	cfg := testConfig(t)
	check := &authenticationCheck{cfg: cfg}
	errVerifier := func(req Request, credential string) (any, error) {
		return "user", errAuthBoom
	}
	errReq := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AuthRequired: "basic", AuthVerifier: errVerifier}
		opts.Header = map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}
	})
	if resp := check.Check(errReq); resp == nil || resp.StatusCode != 401 {
		t.Fatalf("verifier error must 401, got %+v", resp)
	}
	emptyVerifier := func(req Request, credential string) (any, error) { return "", nil }
	emptyReq := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AuthRequired: "basic", AuthVerifier: emptyVerifier}
		opts.Header = map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}
	})
	if resp := check.Check(emptyReq); resp == nil || resp.StatusCode != 401 {
		t.Fatalf("empty principal must 401, got %+v", resp)
	}
	noVerifier := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{AuthRequired: "basic"}
		opts.Header = map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}
	})
	if resp := check.Check(noVerifier); resp == nil || resp.StatusCode != 401 {
		t.Fatalf("missing verifier must 401, got %+v", resp)
	}
}

func TestAuthenticationAPIKey(t *testing.T) {
	cfg := testConfig(t)
	check := &authenticationCheck{cfg: cfg}
	missing := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{APIKeyRequired: true, APIKeyHeader: "X-API-Key"}
	})
	if resp := check.Check(missing); resp == nil || resp.StatusCode != 401 {
		t.Fatalf("missing api key must 401, got %+v", resp)
	}
	verifier := func(req Request, credential string) (any, error) {
		if credential == "key-1" {
			return map[string]string{"id": "client-1"}, nil
		}
		return nil, nil
	}
	ok := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{APIKeyRequired: true, APIKeyHeader: "X-API-Key", APIKeyVerifier: verifier}
		opts.Header = map[string]string{"X-API-Key": "key-1"}
	})
	if resp := check.Check(ok); resp != nil {
		t.Fatalf("valid api key must pass, got %+v", resp)
	}
	fallback := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{APIKeyRequired: true, APIKeyHeader: "X-API-Key"}
		opts.Header = map[string]string{"X-API-Key": "key-1"}
	})
	cfg.AuthVerifier = verifier
	if resp := check.Check(fallback); resp != nil {
		t.Fatalf("config-level verifier fallback must apply, got %+v", resp)
	}
}

func TestReferrer(t *testing.T) {
	cfg := testConfig(t)
	check := &referrerCheck{cfg: cfg}
	missing := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequireReferrer: []string{"example.com"}}
	})
	resp := check.Check(missing)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != "Referrer required" {
		t.Fatalf("missing referrer must 403, got %+v", resp)
	}
	invalid := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequireReferrer: []string{"example.com"}}
		opts.Header = map[string]string{"Referer": "https://evil.com/page"}
	})
	resp = check.Check(invalid)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != "Invalid referrer" {
		t.Fatalf("disallowed referrer must 403, got %+v", resp)
	}
	if invalid.State().BlockStash == nil || invalid.State().BlockStash.TriggerInfo != "" {
		t.Fatalf("stash missing: %+v", invalid.State().BlockStash)
	}
	direct := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequireReferrer: []string{"example.com"}}
		opts.Header = map[string]string{"Referer": "https://example.com/page"}
	})
	if resp := check.Check(direct); resp != nil {
		t.Fatalf("allowed domain must pass, got %+v", resp)
	}
	sub := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequireReferrer: []string{"example.com"}}
		opts.Header = map[string]string{"Referer": "https://api.example.com/page"}
	})
	if resp := check.Check(sub); resp != nil {
		t.Fatalf("subdomain must pass, got %+v", resp)
	}
	urlEntry := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{RequireReferrer: []string{"https://example.com/x"}}
		opts.Header = map[string]string{"Referer": "https://example.com/page"}
	})
	if resp := check.Check(urlEntry); resp != nil {
		t.Fatalf("URL entry must be normalized to host, got %+v", resp)
	}
}

func TestTimeWindow(t *testing.T) {
	cfg := testConfig(t)
	at := func(hhmm string) func() time.Time {
		return func() time.Time {
			ts, err := time.ParseInLocation("15:04", hhmm, time.UTC)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			return ts
		}
	}
	check := &timeWindowCheck{cfg: cfg, nowFn: at("12:00")}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{TimeRestrictions: map[string]string{"start": "09:00", "end": "17:00", "timezone": "UTC"}}
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("inside window must pass, got %+v", resp)
	}
	outside := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{TimeRestrictions: map[string]string{"start": "09:00", "end": "17:00", "timezone": "UTC"}}
	})
	resp := check.Check(outside)
	_ = resp
	night := &timeWindowCheck{cfg: cfg, nowFn: at("20:00")}
	resp = night.Check(outside)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != "Access not allowed at this time" {
		t.Fatalf("outside window must 403, got %+v", resp)
	}
	overnight := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{TimeRestrictions: map[string]string{"start": "22:00", "end": "06:00", "timezone": "UTC"}}
	})
	late := &timeWindowCheck{cfg: cfg, nowFn: at("23:30")}
	if resp := late.Check(overnight); resp != nil {
		t.Fatalf("overnight window must admit 23:30, got %+v", resp)
	}
	morning := &timeWindowCheck{cfg: cfg, nowFn: at("05:00")}
	if resp := morning.Check(overnight); resp != nil {
		t.Fatalf("overnight window must admit 05:00, got %+v", resp)
	}
	noon := &timeWindowCheck{cfg: cfg, nowFn: at("12:00")}
	if resp := noon.Check(overnight); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("overnight window must block noon, got %+v", resp)
	}
	shifted := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{TimeRestrictions: map[string]string{"start": "09:00", "end": "17:00", "timezone": "America/New_York"}}
	})
	inTz := &timeWindowCheck{cfg: cfg, nowFn: func() time.Time {
		return time.Date(2024, 1, 15, 14, 0, 0, 0, time.UTC)
	}}
	if resp := inTz.Check(shifted); resp != nil {
		t.Fatalf("14:00 UTC is 09:00 EST, must pass, got %+v", resp)
	}
	outTz := &timeWindowCheck{cfg: cfg, nowFn: func() time.Time {
		return time.Date(2024, 1, 15, 22, 30, 0, 0, time.UTC)
	}}
	if resp := outTz.Check(shifted); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("22:30 UTC is 17:30 EST, must block, got %+v", resp)
	}
	badTz := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{TimeRestrictions: map[string]string{"start": "00:00", "end": "23:59", "timezone": "Not/AZone"}}
	})
	if resp := inTz.Check(badTz); resp != nil {
		t.Fatalf("invalid timezone must fall back to UTC and pass, got %+v", resp)
	}
}

func TestUserAgent(t *testing.T) {
	cfg := testConfig(t)
	cfg.BlockedUserAgents = []string{"curl"}
	check := &userAgentCheck{cfg: cfg}
	blocked := routeTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Header = map[string]string{"User-Agent": "curl/8.0"}
	})
	resp := check.Check(blocked)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != "User-Agent not allowed" {
		t.Fatalf("blocked UA must 403, got %+v", resp)
	}
	if !strings.Contains(blocked.State().BlockStash.Reason, "Blocked user agent: curl/8.0") {
		t.Fatalf("bad reason: %q", blocked.State().BlockStash.Reason)
	}
	allowed := routeTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Header = map[string]string{"User-Agent": "Mozilla/5.0"}
	})
	if resp := check.Check(allowed); resp != nil {
		t.Fatalf("allowed UA must pass, got %+v", resp)
	}
	missing := routeTestRequest(t, nil)
	if resp := check.Check(missing); resp != nil {
		t.Fatalf("missing UA must pass global check, got %+v", resp)
	}
}

func TestUserAgentRoutePatterns(t *testing.T) {
	cfg := testConfig(t)
	check := &userAgentCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{BlockedUserAgents: []string{"python-requests"}}
		opts.Header = map[string]string{"User-Agent": "python-requests/2.31"}
	})
	if resp := check.Check(req); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("route pattern must block, got %+v", resp)
	}
}

func TestUserAgentWhitelistedIP(t *testing.T) {
	cfg := testConfig(t)
	cfg.BlockedUserAgents = []string{"curl"}
	check := &userAgentCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.IsWhitelisted = true
		opts.Header = map[string]string{"User-Agent": "curl/8.0"}
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("whitelisted IP must skip UA check, got %+v", resp)
	}
}

func TestUserAgentAppliesTo(t *testing.T) {
	cfg := testConfig(t)
	if userAgentApplies(cfg, nil) {
		t.Fatalf("nothing configured must not apply")
	}
	cfg.BlockedUserAgents = []string{"curl"}
	if !userAgentApplies(cfg, nil) {
		t.Fatalf("global patterns must apply")
	}
	cfg2 := testConfig(t)
	cfg2.EnableDynamicRules = true
	if !userAgentApplies(cfg2, nil) {
		t.Fatalf("dynamic rules must apply")
	}
	cfg3 := testConfig(t)
	if !userAgentApplies(cfg3, []*RouteConfig{{BlockedUserAgents: []string{"x"}}}) {
		t.Fatalf("route patterns must apply")
	}
	if !requestSizeContentApplies([]*RouteConfig{{MaxRequestSize: 1}}) ||
		!requestSizeContentApplies([]*RouteConfig{{AllowedContentTypes: []string{"a"}}}) {
		t.Fatalf("request_size_content gating broken")
	}
	if requestSizeContentApplies([]*RouteConfig{{}}) {
		t.Fatalf("empty route must not apply")
	}
	if !requiredHeadersApplies([]*RouteConfig{{RequiredHeaders: RequiredHeaders{{Name: "a"}}}}) {
		t.Fatalf("required_headers gating broken")
	}
	if !authenticationApplies([]*RouteConfig{{AuthRequired: "bearer"}, {APIKeyRequired: true}, {AuthorizationHeaderRequired: "basic"}}) {
		t.Fatalf("authentication gating broken")
	}
	if !referrerApplies([]*RouteConfig{{RequireReferrer: []string{"x"}}}) {
		t.Fatalf("referrer gating broken")
	}
	if !timeWindowApplies([]*RouteConfig{{TimeRestrictions: map[string]string{"start": "1", "end": "2"}}}) {
		t.Fatalf("time_window gating broken")
	}
	if !anyRoute([]*RouteConfig{{RequireHTTPS: true}}, func(rc *RouteConfig) bool { return rc.RequireHTTPS }) {
		t.Fatalf("https gating broken")
	}
}

func TestRoutePipelineEndToEnd(t *testing.T) {
	registry := NewRouteRegistry()
	registry.Register("/api/data", func(rc *RouteConfig) {
		rc.RequiredHeaders = RequiredHeaders{{Name: "X-Client", Value: "required"}}
		rc.RequireReferrer = []string{"example.com"}
		rc.BlockedUserAgents = []string{"curl"}
	})
	cfg := testConfig(t)
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, registry)
	names := pipeline.CheckNames()
	if names[0] != "route_config" {
		t.Fatalf("route_config must be slot 1, got %v", names)
	}
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	for _, want := range []string{"required_headers", "referrer", "user_agent", "ip_security"} {
		if !found[want] {
			t.Fatalf("expected %s in pipeline, got %v", want, names)
		}
	}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/api/data"
		opts.Header = map[string]string{"Referer": "https://example.com/"}
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 400 || string(resp.Body) != "Missing required header: X-Client" {
		t.Fatalf("pipeline must enforce route headers, got %+v", resp)
	}
	good := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/api/data"
		opts.Header = map[string]string{"X-Client": "web", "Referer": "https://example.com/"}
	})
	if resp := pipeline.Execute(good); resp != nil {
		t.Fatalf("satisfied route config must pass, got %+v", resp)
	}
	badRef := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/api/data"
		opts.Header = map[string]string{"X-Client": "web", "Referer": "https://evil.com/"}
	})
	if resp := pipeline.Execute(badRef); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("pipeline must enforce referrer, got %+v", resp)
	}
}

func TestRoutePipelineNoRouteConfigPasses(t *testing.T) {
	registry := NewRouteRegistry()
	registry.Register("/api/data", func(rc *RouteConfig) {
		rc.RequiredHeaders = RequiredHeaders{{Name: "X-Client", Value: "required"}}
	})
	cfg := testConfig(t)
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, registry)
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/other"
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("request on non-configured route must pass, got %+v", resp)
	}
}

func TestRouteRevisionTriggersRebuild(t *testing.T) {
	registry := NewRouteRegistry()
	cfg := testConfig(t)
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, registry)
	before := pipeline.CheckNames()
	registry.Register("/api", func(rc *RouteConfig) { rc.RequireHTTPS = true })
	if !pipeline.IsStale() {
		t.Fatalf("route revision change must mark pipeline stale")
	}
	if err := pipeline.rebuildIfStale(); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	after := pipeline.CheckNames()
	if strings.Join(before, ",") == strings.Join(after, ",") {
		t.Fatalf("https_enforcement slot must appear after route registration: before=%v after=%v", before, after)
	}
}

func TestExclusionScopedSkipsRouteGuardChecks(t *testing.T) {
	registry := NewRouteRegistry()
	registry.Register("/api", func(rc *RouteConfig) {
		rc.RequiredHeaders = RequiredHeaders{{Name: "X-Client", Value: "required"}}
	})
	cfg := testConfig(t)
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, registry)
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/api"
		state.ExclusionScoped = true
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("exclusion-scoped request must skip route guard checks, got %+v", resp)
	}
}

func TestCustomErrorResponseOverrides(t *testing.T) {
	cfg := testConfig(t)
	cfg.CustomErrorResponses[413] = "Custom too big"
	cfg.CustomErrorResponses[503] = "Custom down"
	check := &requestSizeContentCheck{cfg: cfg}
	req := routeTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{MaxRequestSize: 10}
		opts.Header = map[string]string{"Content-Length": "20"}
	})
	resp := check.Check(req)
	if string(resp.Body) != "Custom too big" {
		t.Fatalf("custom error response must override body, got %q", resp.Body)
	}
	emergency := &emergencyModeCheck{cfg: cfg}
	cfg.EmergencyMode = true
	resp = emergency.Check(routeTestRequest(t, nil))
	if string(resp.Body) != "Custom down" {
		t.Fatalf("custom error response must override emergency body, got %q", resp.Body)
	}
}

var errAuthBoom = &authTestError{}

type authTestError struct{}

func (*authTestError) Error() string { return "auth backend down" }
