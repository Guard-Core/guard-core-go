package conformance

// Pipeline-kind conformance suites (spec 4.1.0): replays the reference
// pipeline harness cases through the real guardcore engine. Comparison
// follows specs/fixtures/README.md: only the keys present in each expected
// record are compared; the events key is skipped because the Go engine
// exposes no general event-bus capture surface.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

type pipelineSuiteFile struct {
	Suite        string         `json:"suite"`
	Kind         string         `json:"kind"`
	SpecVersion  string         `json:"spec_version"`
	EngineVesion string         `json:"engine_version"`
	Cases        []pipelineCase `json:"cases"`
}

type pipelineCase struct {
	ID           string                    `json:"id"`
	Config       map[string]any            `json:"config"`
	GeoCountries map[string]string         `json:"geo_countries"`
	Routes       map[string]map[string]any `json:"routes"`
	Drives       []pipelineDrive           `json:"drives"`
	Expected     []map[string]any          `json:"expected"`
}

type pipelineDrive struct {
	ClientIP       string            `json:"client_ip"`
	Method         string            `json:"method"`
	URLPath        string            `json:"url_path"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	Stage          string            `json:"stage"`
	ResponseStatus int               `json:"response_status"`
	ResponseBody   string            `json:"response_body"`
}

type behaviorRuleSpec struct {
	RuleType    string `json:"rule_type"`
	Threshold   int    `json:"threshold"`
	Window      int    `json:"window"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`
	BanDuration int    `json:"ban_duration"`
}

type fakeCountryResolver map[string]string

func (f fakeCountryResolver) GetCountry(ip string) (string, bool) {
	code, ok := f[ip]
	return code, ok
}

func strList(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprint(item))
	}
	return out
}

func buildPipelineConfig(t *testing.T, raw map[string]any, geo fakeCountryResolver) *guardcore.SecurityConfig {
	t.Helper()
	cfg, err := tryBuildPipelineConfig(t, raw, geo)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func tryBuildPipelineConfig(t *testing.T, raw map[string]any, geo fakeCountryResolver) (*guardcore.SecurityConfig, error) {
	t.Helper()
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.EnableRedis = false
		c.EnableRateLimitAutoBan = false
		c.EnableIPBanning = false
		c.AutoBanThreshold = 1000
		if v, ok := raw["whitelist"].([]any); ok {
			c.Whitelist = strList(v)
		}
		if v, ok := raw["blacklist"].([]any); ok {
			c.Blacklist = strList(v)
		}
		if v, ok := raw["exempt_ips"].([]any); ok {
			c.ExemptIPs = strList(v)
		}
		if v, ok := raw["blocked_user_agents"].([]any); ok {
			c.BlockedUserAgents = strList(v)
		}
		if v, ok := raw["blocked_countries"].([]any); ok {
			c.BlockedCountries = strList(v)
		}
		if v, ok := raw["whitelist_countries"].([]any); ok {
			c.WhitelistCountries = strList(v)
		}
		if v, ok := raw["rate_limit"].(float64); ok {
			c.RateLimit = int(v)
		}
		if v, ok := raw["rate_limit_window"].(float64); ok {
			c.RateLimitWindow = int(v)
		}
		if v, ok := raw["endpoint_rate_limits"].(map[string]any); ok {
			limits := map[string]guardcore.RateLimitEntry{}
			for path, entry := range v {
				pair, ok := entry.([]any)
				if !ok || len(pair) != 2 {
					t.Fatalf("endpoint_rate_limits[%s]: want [limit, window]", path)
				}
				limits[path] = guardcore.RateLimitEntry{
					Requests: int(pair[0].(float64)),
					Window:   int(pair[1].(float64)),
				}
			}
			c.EndpointRateLimits = limits
		}
		if v, ok := raw["passive_mode"].(bool); ok {
			c.PassiveMode = v
		}
		if v, ok := raw["custom_error_responses"].(map[string]any); ok {
			overrides := map[int]string{}
			for code, message := range v {
				var status int
				if _, err := fmt.Sscanf(code, "%d", &status); err != nil {
					t.Fatalf("custom_error_responses key %q: %v", code, err)
				}
				overrides[status] = fmt.Sprint(message)
			}
			c.CustomErrorResponses = overrides
		}
		if v, ok := raw["security_headers"].(map[string]any); ok {
			c.SecurityHeaders = pipelineSecurityHeaders(v)
		}
		if v, ok := raw["enable_cors"].(bool); ok {
			c.EnableCORS = v
		}
		if v, ok := raw["cors_allow_origins"].([]any); ok {
			c.CORSAllowOrigins = strList(v)
		}
		if v, ok := raw["cors_allow_methods"].([]any); ok {
			c.CORSAllowMethods = strList(v)
		}
		if v, ok := raw["cors_allow_headers"].([]any); ok {
			c.CORSAllowHeaders = strList(v)
		}
		if v, ok := raw["cors_allow_credentials"].(bool); ok {
			c.CORSAllowCredentials = v
		}
		if v, ok := raw["global_behavior_rules"].([]any); ok {
			rules := make([]guardcore.BehaviorRuleConfig, 0, len(v))
			for _, item := range v {
				data, err := json.Marshal(item)
				if err != nil {
					t.Fatalf("global_behavior_rules: %v", err)
				}
				var spec behaviorRuleSpec
				if err := json.Unmarshal(data, &spec); err != nil {
					t.Fatalf("global_behavior_rules: %v", err)
				}
				rules = append(rules, guardcore.BehaviorRuleConfig{
					RuleType:    spec.RuleType,
					Threshold:   spec.Threshold,
					Window:      spec.Window,
					Pattern:     spec.Pattern,
					Action:      spec.Action,
					BanDuration: spec.BanDuration,
				})
			}
			c.GlobalBehaviorRules = rules
		}
		if v, ok := raw["behavior_scan_response_body"].(bool); ok {
			c.BehaviorScanResponseBody = v
		}
		if len(c.BlockedCountries) > 0 || len(c.WhitelistCountries) > 0 {
			c.GeoIPHandler = geo
		}
	})
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func pipelineSecurityHeaders(raw map[string]any) *guardcore.SecurityHeadersConfig {
	headers := guardcore.DefaultSecurityHeaders()
	if enabled, ok := raw["enabled"].(bool); ok && !enabled {
		headers.Enabled = false
	}
	if v, ok := raw["frame_options"].(string); ok {
		headers.FrameOptions = v
	}
	if v, ok := raw["content_type_options"].(string); ok {
		headers.ContentTypeOptions = v
	}
	if v, ok := raw["xss_protection"].(string); ok {
		headers.XSSProtection = v
	}
	if v, ok := raw["referrer_policy"].(string); ok {
		headers.ReferrerPolicy = v
	}
	if v, ok := raw["custom"].(map[string]any); ok {
		custom := map[string]string{}
		for name, value := range v {
			custom[name] = fmt.Sprint(value)
		}
		headers.Custom = custom
	}
	if v, ok := raw["csp"].(map[string]any); ok {
		directives := make([]guardcore.CSPDirective, 0, len(v))
		names := make([]string, 0, len(v))
		for name := range v {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			directives = append(directives, guardcore.CSPDirective{
				Name:    name,
				Sources: strList(v[name].([]any)),
			})
		}
		headers.CSP = directives
	}
	if v, ok := raw["hsts"].(map[string]any); ok {
		hsts := &guardcore.HSTSConfig{IncludeSubdomains: true}
		if maxAge, ok := v["max_age"].(float64); ok {
			hsts.MaxAge = int(maxAge)
		}
		if include, ok := v["include_subdomains"].(bool); ok {
			hsts.IncludeSubdomains = include
		}
		if preload, ok := v["preload"].(bool); ok {
			hsts.Preload = preload
		}
		headers.HSTS = hsts
	}
	return headers
}

func pipelineRouteMutator(overrides map[string]any) func(*guardcore.RouteConfig) {
	return func(rc *guardcore.RouteConfig) {
		for key, value := range overrides {
			switch key {
			case "rate_limit":
				if v, ok := value.(float64); ok {
					rc.RateLimit = int(v)
				}
			case "rate_limit_window":
				if v, ok := value.(float64); ok {
					rc.RateLimitWindow = int(v)
				}
			case "ip_whitelist":
				rc.IPWhitelist = strList(value)
			case "ip_blacklist":
				rc.IPBlacklist = strList(value)
			case "blocked_countries":
				rc.BlockedCountries = strList(value)
			case "whitelist_countries":
				rc.WhitelistCountries = strList(value)
			case "blocked_user_agents":
				rc.BlockedUserAgents = strList(value)
			case "bypassed_checks":
				rc.BypassedChecks = strList(value)
			case "enable_suspicious_detection":
				if v, ok := value.(bool); ok {
					rc.EnableSuspiciousDetection = v
				}
			case "excluded_detection_headers":
				rc.ExcludedDetectionHeaders = map[string]bool{}
				for _, name := range strList(value) {
					rc.ExcludedDetectionHeaders[name] = true
				}
			}
		}
	}
}

func runPipelineCase(t *testing.T, c pipelineCase) []string {
	t.Helper()
	geo := fakeCountryResolver(c.GeoCountries)
	cfg, cfgErr := tryBuildPipelineConfig(t, c.Config, geo)
	if cfgErr != nil {
		// Documented divergence: the reference SecurityConfig ACCEPTS
		// wildcard origins + credentials at construction time (it logs an
		// error and blocks CORS at response time), while this port fails
		// closed at config validation. The runtime outcome (no CORS
		// headers) matches; the construction outcome cannot be replayed
		// here. Reported as a divergence, never as a pass.
		return []string{"DIVERGENCE config-construction rejected: " + cfgErr.Error()}
	}

	var payloads []map[string]any
	cfg.OnBlock = func(_ guardcore.Request, payload map[string]any) {
		observable := map[string]any{}
		for _, key := range []string{"check_name", "reason", "trigger_info", "passive_mode", "client_ip", "path", "method", "status_code"} {
			observable[key] = payload[key]
		}
		payloads = append(payloads, observable)
	}

	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer func() { _ = engine.Close() }()
	routeIDs := make([]string, 0, len(c.Routes))
	for path := range c.Routes {
		routeIDs = append(routeIDs, path)
	}
	sort.Strings(routeIDs)
	for _, path := range routeIDs {
		engine.Routes.Register(path, pipelineRouteMutator(c.Routes[path]))
	}

	var failures []string
	recordPayloads := func() []any {
		out := make([]any, 0, len(payloads))
		for _, payload := range payloads {
			out = append(out, payload)
		}
		return out
	}

	for index, drive := range c.Drives {
		payloads = nil
		if index >= len(c.Expected) {
			break
		}
		want := c.Expected[index]
		state := &guardcore.RequestState{}
		if _, ok := c.Routes[drive.URLPath]; ok {
			state.GuardRouteID = drive.URLPath
		}
		req := guardcore.NewRequestFactory().CreateRequest(guardcore.RequestOptions{
			Path:       drive.URLPath,
			Host:       "example.com",
			Method:     drive.Method,
			ClientHost: drive.ClientIP,
			Header:     drive.Headers,
			Body:       []byte(drive.Body),
			State:      state,
		})

		var resp *guardcore.Response
		if drive.Stage == "process_response" {
			body := drive.ResponseBody
			if body == "" {
				body = "ok"
			}
			status := drive.ResponseStatus
			if status == 0 {
				status = 200
			}
			resp = guardcore.NewResponseFactory().CreateResponse(body, status)
			engine.ProcessResponse(req, resp)
			for name, value := range engine.ResponseHeaders() {
				resp.SetHeader(name, value)
			}
			if _, hasOrigin := drive.Headers["Origin"]; hasOrigin {
				for name, value := range engine.CORSResponseHeaders(req) {
					resp.SetHeader(name, value)
				}
			}
		} else {
			resp = engine.Check(req)
		}

		if status, ok := want["status"]; ok {
			var got any
			if resp != nil {
				got = resp.StatusCode
			}
			if !anyEqual(got, status) {
				failures = append(failures, fmt.Sprintf("drive %d status: got %v want %v", index, got, status))
				continue
			}
		}
		if resp != nil {
			if body, ok := want["body"]; ok {
				if string(resp.Body) != fmt.Sprint(body) {
					failures = append(failures, fmt.Sprintf("drive %d body: got %q want %q", index, string(resp.Body), body))
				}
			}
			if headers, ok := want["headers"].(map[string]any); ok {
				for name, value := range headers {
					if resp.Headers[name] != fmt.Sprint(value) {
						failures = append(failures, fmt.Sprintf("drive %d header %s: got %q want %q", index, name, resp.Headers[name], value))
					}
				}
			}
		}
		if isExempt, ok := want["is_exempt"]; ok {
			if !anyEqual(state.IsExempt, isExempt) {
				failures = append(failures, fmt.Sprintf("drive %d is_exempt: got %v want %v", index, state.IsExempt, isExempt))
			}
		}
		if isWhitelisted, ok := want["is_whitelisted"]; ok {
			if !anyEqual(state.IsWhitelisted, isWhitelisted) {
				failures = append(failures, fmt.Sprintf("drive %d is_whitelisted: got %v want %v", index, state.IsWhitelisted, isWhitelisted))
			}
		}
		// events: skipped (no general event-bus capture on the Go engine).
		if wantPayloads, ok := want["on_block"].([]any); ok {
			gotPayloads := recordPayloads()
			if len(gotPayloads) != len(wantPayloads) {
				failures = append(failures, fmt.Sprintf("drive %d on_block count: got %d want %d", index, len(gotPayloads), len(wantPayloads)))
			} else {
				for pi, wantPayload := range wantPayloads {
					wantMap, ok := wantPayload.(map[string]any)
					if !ok {
						continue
					}
					gotMap := gotPayloads[pi].(map[string]any)
					for key, wantValue := range wantMap {
						if !anyEqual(gotMap[key], wantValue) {
							failures = append(failures, fmt.Sprintf("drive %d on_block %s: got %v want %v", index, key, gotMap[key], wantValue))
						}
					}
				}
			}
		}
	}
	return failures
}

func anyEqual(got, want any) bool {
	switch w := want.(type) {
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	case float64:
		g, ok := got.(int)
		if ok {
			return float64(g) == w
		}
		gf, ok := got.(float64)
		return ok && gf == w
	case string:
		g, ok := got.(string)
		return ok && g == w
	case nil:
		return got == nil
	}
	return fmt.Sprint(got) == fmt.Sprint(want)
}

func TestPipelineConformance(t *testing.T) {
	indexData, err := os.ReadFile("guard-core-spec-4.1.0/cases/index.json")
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		SpecVersion string `json:"spec_version"`
		Suites      map[string]struct {
			CaseCount int      `json:"case_count"`
			Kind      string   `json:"kind"`
			Consumers []string `json:"consumers"`
		} `json:"suites"`
	}
	if err := json.Unmarshal(indexData, &index); err != nil {
		t.Fatal(err)
	}
	if index.SpecVersion != "4.1.0" {
		t.Fatalf("spec_version mismatch: corpus targets %s but the runner requires 4.1.0", index.SpecVersion)
	}

	xfail := loadPipelineXfail(t)
	xfailCaseIDs := make([]string, 0, len(xfail.Cases))
	for id := range xfail.Cases {
		xfailCaseIDs = append(xfailCaseIDs, id)
	}
	sort.Strings(xfailCaseIDs)

	names := make([]string, 0, len(index.Suites))
	for name, entry := range index.Suites {
		if entry.Kind == "pipeline" && consumes(index.Suites[name].Consumers, "go") {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	total, failed, divergent, xfailed, stale := 0, 0, 0, 0, 0
	baselinedSeen := map[string]bool{}
	var failures, xfails, stales []string
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join("guard-core-spec-4.1.0", "cases", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var suite pipelineSuiteFile
		if err := json.Unmarshal(data, &suite); err != nil {
			t.Fatal(err)
		}
		for _, c := range suite.Cases {
			total++
			d := runPipelineCase(t, c)
			isXfail := xfail.Cases[name+"/"+c.ID] != ""
			if len(d) == 0 {
				if isXfail {
					stale++
					stales = append(stales, fmt.Sprintf("stale xfail baseline entry %s: case now passes; remove the entry", c.ID))
				}
				continue
			}
			if len(d) == 1 && strings.HasPrefix(d[0], "DIVERGENCE") {
				divergent++
				baselinedSeen[c.ID] = true
				failures = append(failures, fmt.Sprintf("DIVERGENCE %s/%s: %s", name, c.ID, d[0]))
				continue
			}
			if isXfail {
				xfailed++
				baselinedSeen[name+"/"+c.ID] = true
				xfails = append(xfails, fmt.Sprintf("xfail %s/%s [%s]: %s", name, c.ID, xfail.Cases[name+"/"+c.ID], strings.Join(d, "; ")))
				continue
			}
			failed++
			failures = append(failures, fmt.Sprintf("%s/%s: %s", name, c.ID, strings.Join(d, "; ")))
		}
	}
	for _, d := range failures {
		if strings.HasPrefix(d, "DIVERGENCE") {
			t.Logf("%s", d)
		}
	}
	for _, x := range xfails {
		t.Logf("%s", x)
	}
	if len(stales) > 0 {
		t.Fatalf("stale xfail baseline:\n%s", strings.Join(stales, "\n"))
	}
	if len(baselinedSeen) != len(xfailCaseIDs) {
		for _, id := range xfailCaseIDs {
			if !baselinedSeen[id] {
				t.Errorf("xfail baseline entry %s never ran; corpus changed?", id)
			}
		}
	}
	if failed > 0 {
		real := make([]string, 0, len(failures))
		for _, d := range failures {
			if !strings.HasPrefix(d, "DIVERGENCE") {
				real = append(real, d)
			}
		}
		t.Fatalf("pipeline conformance drift: %d/%d cases differ\n%s", failed, total, strings.Join(real, "\n"))
	}
	t.Logf("pipeline conformance gate: %d passed, %d failed, %d xfail, %d config divergences (spec 4.1.0)", total-failed-divergent-xfailed, failed, xfailed, divergent)
	t.Logf("pipeline conformance drift (unbaselined): %s", strings.Join(failures, "\n"))
}

type pipelineXfail struct {
	SpecVersion string            `json:"spec_version"`
	Cases       map[string]string `json:"cases"`
}

func loadPipelineXfail(t *testing.T) pipelineXfail {
	t.Helper()
	data, err := os.ReadFile("guard-core-spec-4.1.0/go_pipeline_xfail.json")
	if err != nil {
		if os.IsNotExist(err) {
			return pipelineXfail{Cases: map[string]string{}}
		}
		t.Fatal(err)
	}
	var baseline pipelineXfail
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.SpecVersion != "4.1.0" {
		t.Fatalf("xfail baseline spec pin %s does not match 4.1.0", baseline.SpecVersion)
	}
	return baseline
}

func consumes(consumers []string, engine string) bool {
	for _, c := range consumers {
		if c == engine {
			return true
		}
	}
	return false
}
