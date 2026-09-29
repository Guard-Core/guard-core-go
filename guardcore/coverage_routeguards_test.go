package guardcore

// Coverage tests for the per-route guard checks (checks_routeguards.go).

import (
	"strings"
	"testing"
	"time"
)

func TestRequestSizeContentCheckPlumbing(t *testing.T) {
	c := &requestSizeContentCheck{cfg: &SecurityConfig{}}
	if c.EnforcedOnExcludedPaths() {
		t.Fatal("request size checks never enforce on excluded paths")
	}
	if c.AppliesTo(&SecurityConfig{}) {
		t.Fatal("request size checks are route-driven only")
	}
	if !requestSizeContentApplies([]*RouteConfig{{MaxRequestSize: 10}}) ||
		!requestSizeContentApplies([]*RouteConfig{{AllowedContentTypes: []string{"application/json"}}}) ||
		requestSizeContentApplies([]*RouteConfig{{}}) {
		t.Fatal("request size applies follow the route fields")
	}
	if c.CheckName() != "request_size_content" {
		t.Fatal("checks carry their name")
	}
}

func TestRequestSizeContentCheckVerdicts(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	c := &requestSizeContentCheck{cfg: cfg}
	route := &RouteConfig{MaxRequestSize: 10, AllowedContentTypes: []string{"application/json"}}

	// Route-less requests skip everything.
	if resp := c.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("route-less requests skip, got %+v", resp)
	}
	// Oversized content lengths block with 413.
	big := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Content-Length"] = "100"
		opts.Header["Content-Type"] = "application/json"
	})
	if resp := c.Check(big); resp == nil || resp.StatusCode != 413 {
		t.Fatalf("oversized bodies block with 413, got %+v", resp)
	}
	// Disallowed content types block with 415.
	wrongType := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Content-Length"] = "5"
		opts.Header["Content-Type"] = "text/plain"
	})
	if resp := c.Check(wrongType); resp == nil || resp.StatusCode != 415 {
		t.Fatalf("disallowed types block with 415, got %+v", resp)
	}
	// Compliant requests pass.
	good := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Content-Length"] = "5"
		opts.Header["Content-Type"] = "application/json; charset=utf-8"
	})
	if resp := c.Check(good); resp != nil {
		t.Fatalf("compliant requests pass, got %+v", resp)
	}
	// Malformed content lengths fail closed through a panic.
	broken := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{MaxRequestSize: 10}
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Content-Length"] = "NaN"
	})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("malformed lengths must panic")
			}
		}()
		c.Check(broken)
	}()
}

func TestRequiredHeadersCheck(t *testing.T) {
	c := &requiredHeadersCheck{cfg: &SecurityConfig{}}
	if c.EnforcedOnExcludedPaths() {
		t.Fatal("required headers never enforce on excluded paths")
	}
	if c.AppliesTo(&SecurityConfig{}) {
		t.Fatal("required headers are route-driven only")
	}
	if !requiredHeadersApplies([]*RouteConfig{{RequiredHeaders: RequiredHeaders{{Name: "X-A"}}}}) {
		t.Fatal("header requirements apply")
	}
	if c.CheckName() != "required_headers" {
		t.Fatal("checks carry their name")
	}
	route := &RouteConfig{RequiredHeaders: RequiredHeaders{
		{Name: "X-Mode", Value: "required"},
		{Name: "X-Tenant", Value: "acme"},
	}}
	mismatchRoute := &RouteConfig{RequiredHeaders: RequiredHeaders{{Name: "X-Tenant", Value: "acme"}}}

	if resp := c.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("route-less requests skip, got %+v", resp)
	}
	missing := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.RouteConfig = route })
	if resp := c.Check(missing); resp == nil || resp.StatusCode != 400 || !strings.Contains(string(resp.Body), "X-Mode") {
		t.Fatalf("missing headers block with 400, got %+v", resp)
	}
	mismatched := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = mismatchRoute
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["X-Tenant"] = "other"
	})
	if resp := c.Check(mismatched); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("mismatched values block, got %+v", resp)
	}
	compliant := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["X-Mode"] = "anything"
		opts.Header["X-Tenant"] = "acme"
	})
	if resp := c.Check(compliant); resp != nil {
		t.Fatalf("compliant requests pass, got %+v", resp)
	}
	// Passive mode fires the hook and lets the request through.
	passive := &requiredHeadersCheck{cfg: &SecurityConfig{PassiveMode: true}}
	if resp := passive.Check(missing); resp != nil {
		t.Fatalf("passive mode never blocks, got %+v", resp)
	}
}

func TestExtractCredential(t *testing.T) {
	cases := []struct {
		header, authType string
		credential       string
		reason           string
	}{
		{"Bearer abc", "bearer", "abc", ""},
		{"basic x", "bearer", "", "Missing or invalid Bearer token"},
		{"Basic abc", "basic", "abc", ""},
		{"Bearer abc", "basic", "", "Missing or invalid Basic authentication"},
		{"", "apikey", "", "Missing apikey authentication"},
		{"raw-credential", "apikey", "raw-credential", ""},
	}
	for _, tc := range cases {
		credential, reason := extractCredential(tc.header, tc.authType)
		if credential != tc.credential || reason != tc.reason {
			t.Fatalf("extractCredential(%q, %q) = %q, %q; want %q, %q", tc.header, tc.authType, credential, reason, tc.credential, tc.reason)
		}
	}
}

func TestAuthenticationCheck(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	c := &authenticationCheck{cfg: cfg}
	if c.EnforcedOnExcludedPaths() {
		t.Fatal("authentication never enforces on excluded paths")
	}
	if c.AppliesTo(&SecurityConfig{}) {
		t.Fatal("authentication is route-driven only")
	}
	if !authenticationApplies([]*RouteConfig{{AuthRequired: "bearer"}}) ||
		!authenticationApplies([]*RouteConfig{{APIKeyRequired: true}}) ||
		!authenticationApplies([]*RouteConfig{{AuthorizationHeaderRequired: "basic"}}) {
		t.Fatal("authentication applies follow the route fields")
	}
	if c.CheckName() != "authentication" {
		t.Fatal("checks carry their name")
	}

	if resp := c.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("route-less requests skip, got %+v", resp)
	}
	plain := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.RouteConfig = &RouteConfig{} })
	if resp := c.Check(plain); resp != nil {
		t.Fatalf("auth-less routes skip, got %+v", resp)
	}

	// Authorization-header-required schemes validate the shape only.
	schemeRoute := &RouteConfig{AuthorizationHeaderRequired: "bearer"}
	noScheme := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.RouteConfig = schemeRoute })
	if resp := c.Check(noScheme); resp == nil || resp.StatusCode != 401 {
		t.Fatalf("missing schemes block with 401, got %+v", resp)
	}
	withScheme := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = schemeRoute
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Authorization"] = "Bearer tok"
	})
	if resp := c.Check(withScheme); resp != nil {
		t.Fatalf("shaped credentials pass, got %+v", resp)
	}

	// Verifier-driven auth validates the principal.
	authRoute := &RouteConfig{AuthRequired: "bearer", AuthVerifier: func(req Request, credential string) (any, error) {
		if credential == "good" {
			return "principal", nil
		}
		return nil, nil
	}}
	good := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = authRoute
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Authorization"] = "Bearer good"
	})
	if resp := c.Check(good); resp != nil {
		t.Fatalf("good credentials pass, got %+v", resp)
	}
	bad := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = authRoute
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Authorization"] = "Bearer bad"
	})
	if resp := c.Check(bad); resp == nil || resp.StatusCode != 401 {
		t.Fatalf("empty principals block, got %+v", resp)
	}
	// Empty-string principals count as empty.
	emptyPrincipalRoute := &RouteConfig{AuthRequired: "bearer", AuthVerifier: func(req Request, credential string) (any, error) {
		return "", nil
	}}
	empty := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = emptyPrincipalRoute
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Authorization"] = "Bearer good"
	})
	if resp := c.Check(empty); resp == nil || resp.StatusCode != 401 {
		t.Fatalf("empty string principals block, got %+v", resp)
	}
	// API-key routes read their own header.
	keyRoute := &RouteConfig{APIKeyRequired: true, APIKeyHeader: "X-Key", APIKeyVerifier: func(req Request, credential string) (any, error) {
		return map[string]string{"k": credential}, nil
	}}
	withKey := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = keyRoute
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["X-Key"] = "secret"
	})
	if resp := c.Check(withKey); resp != nil {
		t.Fatalf("api keys pass, got %+v", resp)
	}
	// Passive mode never blocks.
	passive := &authenticationCheck{cfg: &SecurityConfig{PassiveMode: true}}
	if resp := passive.Check(noScheme); resp != nil {
		t.Fatalf("passive mode never blocks, got %+v", resp)
	}
}

func TestReferrerDomainHelpers(t *testing.T) {
	if got := normalizeAllowedReferrerDomain("https://App.Example.com/path"); got != "app.example.com" {
		t.Fatalf("urls normalize to hosts, got %q", got)
	}
	if got := normalizeAllowedReferrerDomain("App.Example.com/path"); got != "app.example.com" {
		t.Fatalf("paths strip, got %q", got)
	}
	if !isReferrerDomainAllowed("https://app.example.com/x", []string{"example.com"}) {
		t.Fatal("subdomains of allowed domains pass")
	}
	if isReferrerDomainAllowed("http://[::1", []string{"example.com"}) {
		t.Fatal("unparseable referrers never pass")
	}
}

func TestReferrerCheck(t *testing.T) {
	cfg := &SecurityConfig{}
	c := &referrerCheck{cfg: cfg}
	if c.EnforcedOnExcludedPaths() {
		t.Fatal("referrer checks never enforce on excluded paths")
	}
	if c.AppliesTo(&SecurityConfig{}) {
		t.Fatal("referrer checks are route-driven only")
	}
	if !referrerApplies([]*RouteConfig{{RequireReferrer: []string{"example.com"}}}) {
		t.Fatal("referrer requirements apply")
	}
	if c.CheckName() != "referrer" {
		t.Fatal("checks carry their name")
	}
	route := &RouteConfig{RequireReferrer: []string{"good.example.com"}}

	if resp := c.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("route-less requests skip, got %+v", resp)
	}
	noReferrer := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.RouteConfig = route })
	if resp := c.Check(noReferrer); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("missing referrers block with 403, got %+v", resp)
	}
	badReferrer := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Referer"] = "https://evil.example.com/"
	})
	if resp := c.Check(badReferrer); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("foreign referrers block, got %+v", resp)
	}
	goodReferrer := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = route
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["Referer"] = "https://good.example.com/page"
	})
	if resp := c.Check(goodReferrer); resp != nil {
		t.Fatalf("allowed referrers pass, got %+v", resp)
	}
	passive := &referrerCheck{cfg: &SecurityConfig{PassiveMode: true}}
	if resp := passive.Check(noReferrer); resp != nil {
		t.Fatalf("passive mode never blocks, got %+v", resp)
	}
	if resp := passive.Check(badReferrer); resp != nil {
		t.Fatalf("passive mode never blocks, got %+v", resp)
	}
}

func TestTimeWindowCheck(t *testing.T) {
	c := &timeWindowCheck{cfg: &SecurityConfig{}}
	if c.EnforcedOnExcludedPaths() {
		t.Fatal("time windows never enforce on excluded paths")
	}
	if c.AppliesTo(&SecurityConfig{}) {
		t.Fatal("time windows are route-driven only")
	}
	if !timeWindowApplies([]*RouteConfig{{TimeRestrictions: map[string]string{"start": "09:00"}}}) {
		t.Fatal("time restrictions apply")
	}
	if c.CheckName() != "time_window" {
		t.Fatal("checks carry their name")
	}
	// The injected clock wins over the wall clock.
	c.nowFn = func() time.Time { return time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC) }
	if got := c.now(); got.Hour() != 10 {
		t.Fatalf("injected clocks win, got %v", got)
	}
	// Missing bounds are always open.
	if !c.checkTimeWindow(map[string]string{}) {
		t.Fatal("boundless windows stay open")
	}
	if !c.checkTimeWindow(map[string]string{"start": "09:00"}) {
		t.Fatal("startless windows stay open")
	}
	// Unknown timezones fall back to UTC.
	if !c.checkTimeWindow(map[string]string{"start": "09:00", "end": "17:00", "timezone": "Not/AZone"}) {
		t.Fatal("unknown timezones fall back")
	}
	// Overnight windows wrap.
	c.nowFn = func() time.Time { return time.Date(2024, 1, 1, 23, 0, 0, 0, time.UTC) }
	if !c.checkTimeWindow(map[string]string{"start": "22:00", "end": "02:00"}) {
		t.Fatal("overnight windows wrap")
	}
	c.nowFn = func() time.Time { return time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC) }
	if c.checkTimeWindow(map[string]string{"start": "22:00", "end": "02:00"}) {
		t.Fatal("outside overnight windows close")
	}

	route := &RouteConfig{TimeRestrictions: map[string]string{"start": "09:00", "end": "17:00"}}
	if resp := c.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("route-less requests skip, got %+v", resp)
	}
	c.nowFn = func() time.Time { return time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC) }
	if resp := c.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.RouteConfig = route })); resp != nil {
		t.Fatalf("in-window requests pass, got %+v", resp)
	}
	c.nowFn = func() time.Time { return time.Date(2024, 1, 1, 20, 0, 0, 0, time.UTC) }
	late := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.RouteConfig = route })
	if resp := c.Check(late); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("out-of-window requests block, got %+v", resp)
	}
	passive := &timeWindowCheck{cfg: &SecurityConfig{PassiveMode: true}}
	passive.nowFn = c.nowFn
	if resp := passive.Check(late); resp != nil {
		t.Fatalf("passive mode never blocks, got %+v", resp)
	}
}

func TestUserAgentCheck(t *testing.T) {
	// Built directly (not via NewSecurityConfig) so the intentionally
	// invalid pattern survives config validation for the matcher test.
	cfg := &SecurityConfig{BlockedUserAgents: []string{"badbot", "["}}
	c := &userAgentCheck{cfg: cfg}
	if c.EnforcedOnExcludedPaths() {
		t.Fatal("user agent checks never enforce on excluded paths")
	}
	if c.AppliesTo(&SecurityConfig{}) {
		t.Fatal("agent-less configs never apply")
	}
	if !userAgentApplies(cfg, nil) {
		t.Fatal("blocked agents apply")
	}
	if !userAgentApplies(&SecurityConfig{}, []*RouteConfig{{BlockedUserAgents: []string{"x"}}}) {
		t.Fatal("route agents apply")
	}
	if c.CheckName() != "user_agent" {
		t.Fatal("checks carry their name")
	}
	// Oversized subjects truncate; bad patterns skip.
	long := strings.Repeat("x", 505) + "badbot" + strings.Repeat("y", 100)
	if !userAgentMatchesBlockedPattern(long, cfg.BlockedUserAgents) {
		t.Fatal("truncated subjects still match")
	}
	if userAgentMatchesBlockedPattern("bot", cfg.BlockedUserAgents) {
		t.Fatal("invalid patterns skip")
	}

	// Whitelisted and exempt requests skip.
	for _, mutate := range []func(*RequestState){
		func(s *RequestState) { s.IsWhitelisted = true },
		func(s *RequestState) { s.IsExempt = true },
	} {
		req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
			if opts.Header == nil {
				opts.Header = map[string]string{}
			}
			opts.Header["User-Agent"] = "badbot"
			mutate(state)
		})
		if resp := c.Check(req); resp != nil {
			t.Fatal("whitelisted and exempt requests skip")
		}
	}
	// Blocked agents get 403.
	blocked := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["User-Agent"] = "badbot/1.0"
	})
	if resp := c.Check(blocked); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("blocked agents get 403, got %+v", resp)
	}
	// Route-level blocks fire too.
	routeCfg := &SecurityConfig{}
	rc := &userAgentCheck{cfg: routeCfg}
	routeBlocked := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{BlockedUserAgents: []string{"evilbot"}}
		if opts.Header == nil {
			opts.Header = map[string]string{}
		}
		opts.Header["User-Agent"] = "evilbot"
	})
	if resp := rc.Check(routeBlocked); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("route blocks fire, got %+v", resp)
	}
	// Passive mode never blocks.
	passive := &userAgentCheck{cfg: &SecurityConfig{BlockedUserAgents: []string{"badbot"}, PassiveMode: true}}
	if resp := passive.Check(blocked); resp != nil {
		t.Fatalf("passive mode never blocks, got %+v", resp)
	}
}
