package conformance

// events-kind conformance suite (spec 4.1.0, event_stream.json): one case
// per reference event type, each pinning the ordered list of full
// SecurityEvent envelopes the real engine emits for the scenario. The Go
// engine's event bus (guardcore/events.go, the PR #42 milestone) is the
// capture surface: the runner installs a recording agent handler as the
// config's AgentHandler and converts every SecurityEvent (and the
// performance monitor's AnomalyEvent family) into the reference envelope
// shape.
//
// Comparison follows index.json > comparison > events_envelopes:
//   - only the keys present in each expected envelope are compared;
//   - the volatile fields (events_volatile_fields: execution_time,
//     execution_time_ms, idempotency_key, response_time, timestamp) are
//     dropped recursively;
//   - an expected null accepts an absent field, JSON null, or an empty
//     string: the reference envelope distinguishes None from "", the Go
//     envelope's omitempty encoding collapses all three, and the None
//     columns mean "no value";
//   - an expected empty metadata object accepts an absent/nil metadata.
//
// Cases whose scenario seam has no Go counterpart yet are recorded in
// guard-core-spec-4.1.0/go_events_xfail.json with a per-case reason tied
// to the Go source (fail-closed: unbaselined failures are red, baselined
// cases that pass are red, baselined cases that never ran are red).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const eventsXfailFile = "guard-core-spec-4.1.0/go_events_xfail.json"

type eventsSuiteFile struct {
	Suite string       `json:"suite"`
	Kind  string       `json:"kind"`
	Doc   string       `json:"doc"`
	Cases []eventsCase `json:"cases"`
}

type eventsCase struct {
	ID           string                    `json:"id"`
	Config       map[string]any            `json:"config"`
	GeoCountries map[string]string         `json:"geo_countries"`
	Routes       map[string]map[string]any `json:"routes"`
	Drives       []map[string]any          `json:"drives"`
	Expected     []map[string]any          `json:"expected"`
	Xfail        bool                      `json:"xfail"`
	XfailReason  string                    `json:"xfail_reason"`
}

// eventsVolatileKeys mirrors index.json > comparison > events_volatile_fields.
var eventsVolatileKeys = map[string]bool{
	"execution_time":    true,
	"execution_time_ms": true,
	"idempotency_key":   true,
	"response_time":     true,
	"timestamp":         true,
}

func normalizeEnvelope(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, item := range x {
			if eventsVolatileKeys[k] {
				continue
			}
			out[k] = normalizeEnvelope(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, normalizeEnvelope(item))
		}
		return out
	case float64:
		return round6(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return v
	}
}

func decodeToMap(v any) map[string]any {
	raw, err := json.Marshal(v)
	if err != nil {
		return map[string]any{"marshal_error": err.Error()}
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return map[string]any{"marshal_error": err.Error()}
	}
	return normalizeEnvelope(decoded).(map[string]any)
}

// envelopeDiffs compares only the keys present in the expected envelope,
// recursively. The null/empty-string tolerance and the empty-object
// tolerance are documented in the file comment; everything else is exact
// (floats at 6-decimal precision).
func envelopeDiffs(path string, got, want any) []string {
	switch w := want.(type) {
	case map[string]any:
		if got == nil && len(w) == 0 {
			// An expected empty object accepts an absent value: the Go
			// encoding omits empty metadata maps.
			return nil
		}
		g, ok := got.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: got %v (%T) want object %v", path, got, got, w)}
		}
		var diffs []string
		keys := make([]string, 0, len(w))
		for k := range w {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			diffs = append(diffs, envelopeDiffs(path+"."+k, g[k], w[k])...)
		}
		return diffs
	case []any:
		g, ok := got.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s: got %v want list %v", path, got, w)}
		}
		if len(g) != len(w) {
			return []string{fmt.Sprintf("%s: got %v want %v", path, got, w)}
		}
		var diffs []string
		for i := range w {
			diffs = append(diffs, envelopeDiffs(fmt.Sprintf("%s[%d]", path, i), g[i], w[i])...)
		}
		return diffs
	case nil:
		switch got {
		case nil, "":
			return nil
		}
		return []string{fmt.Sprintf("%s: got %v want null", path, got)}
	case string:
		g, ok := got.(string)
		if !ok || g != w {
			return []string{fmt.Sprintf("%s: got %v want %q", path, got, w)}
		}
		return nil
	case bool:
		g, ok := got.(bool)
		if !ok || g != w {
			return []string{fmt.Sprintf("%s: got %v want %v", path, got, w)}
		}
		return nil
	case float64:
		g, ok := got.(float64)
		if !ok || round6(g) != round6(w) {
			return []string{fmt.Sprintf("%s: got %v want %v", path, got, w)}
		}
		return nil
	default:
		if !reflect.DeepEqual(got, want) {
			return []string{fmt.Sprintf("%s: got %v want %v", path, got, want)}
		}
		return nil
	}
}

// recordingAgent is the conformance capture sink: every bus event and
// monitor anomaly the engine emits lands here in emission order.
type recordingAgent struct {
	events []map[string]any
}

func (a *recordingAgent) SendEvent(event guardcore.SecurityEvent) error {
	a.events = append(a.events, decodeToMap(event))
	return nil
}

func (a *recordingAgent) SendMetric(metric guardcore.SecurityMetric) error {
	_ = metric
	return nil
}

// SendAnomalyEvent makes the agent an AnomalyEventSender so the
// performance monitor's anomaly family reaches the same sink. The
// AnomalyEvent struct carries no JSON tags, so the reference envelope
// shape (snake_case payload keys) is mapped explicitly.
func (a *recordingAgent) SendAnomalyEvent(event guardcore.AnomalyEvent) error {
	envelope := map[string]any{
		"event_type":   event.EventType,
		"ip_address":   event.IPAddress,
		"action_taken": event.ActionTaken,
		"reason":       event.Reason,
	}
	if event.Metadata != nil {
		envelope["metadata"] = normalizeEnvelope(event.Metadata)
	}
	a.events = append(a.events, normalizeEnvelope(envelope).(map[string]any))
	return nil
}

// corpusRejectAll is the custom_request_check marker implementation; the
// check_function metadata carries the marker through the config's
// CustomRequestCheckName.
var corpusRejectAll = func(_ guardcore.Request) *guardcore.Response {
	return guardcore.NewResponseFactory().CreateResponse("corpus rejected", 418)
}

// makeDecoratorRequest builds the harness-shaped request the decorator
// senders answer.
func makeDecoratorRequest(t *testing.T, step map[string]any) guardcore.Request {
	t.Helper()
	return guardcore.NewRequestFactory().CreateRequest(guardcore.RequestOptions{
		Path:       stepString(step, "url_path"),
		Scheme:     "http",
		Host:       "example.com",
		Method:     "GET",
		ClientHost: stepString(step, "client_ip"),
		State:      &guardcore.RequestState{},
	})
}

// eventsRouteMutator extends the pipeline mutator with the decorator knobs
// the events scenarios need (events_harness EVENTS_ROUTE_KEYS).
func eventsRouteMutator(overrides map[string]any) func(*guardcore.RouteConfig) {
	base := pipelineRouteMutator(overrides)
	return func(rc *guardcore.RouteConfig) {
		base(rc)
		for key, value := range overrides {
			switch key {
			case "auth_required":
				if v, ok := value.(string); ok {
					rc.AuthRequired = v
				}
			case "require_https":
				if v, ok := value.(bool); ok {
					rc.RequireHTTPS = v
				}
			case "max_request_size":
				if v, ok := value.(float64); ok {
					rc.MaxRequestSize = int64(v)
				}
			case "block_cloud_providers":
				rc.BlockCloudProviders = strList(value)
			}
		}
	}
}

// buildEventsEngine constructs the engine for one case: no Redis, the
// recording agent wired, the case's config overrides and route table.
// When the case cannot be driven the returned reason explains which seam
// is missing.
func buildEventsEngine(t *testing.T, c eventsCase, agent *recordingAgent) (*guardcore.Engine, error) {
	t.Helper()
	if marker, ok := c.Config["custom_request_check"]; ok {
		if _, isMarker := marker.(string); isMarker && marker != "corpus_reject_all" {
			return nil, fmt.Errorf("unknown custom_request_check marker %v", marker)
		}
	}
	cfg, err := guardcore.NewSecurityConfig(func(sc *guardcore.SecurityConfig) {
		sc.EnableRedis = false
		sc.EnableRateLimitAutoBan = false
		sc.AutoBanThreshold = 1000
		sc.EnableAgent = true
		sc.AgentHandler = agent
		sc.AgentEnableEvents = true
		if v, ok := numArg(c.Config["auto_ban_threshold"]); ok {
			sc.AutoBanThreshold = v
		}
		if v, ok := c.Config["enable_ip_banning"].(bool); ok {
			sc.EnableIPBanning = v
		}
		if v, ok := c.Config["passive_mode"].(bool); ok {
			sc.PassiveMode = v
		}
		if v, ok := c.Config["blacklist"].([]any); ok {
			sc.Blacklist = strList(v)
		}
		if v, ok := c.Config["blocked_user_agents"].([]any); ok {
			sc.BlockedUserAgents = strList(v)
		}
		if v, ok := c.Config["rate_limit"].(float64); ok {
			sc.RateLimit = int(v)
		}
		if v, ok := c.Config["rate_limit_window"].(float64); ok {
			sc.RateLimitWindow = int(v)
		}
		if v, ok := c.Config["endpoint_rate_limits"].(map[string]any); ok {
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
			sc.EndpointRateLimits = limits
		}
		if v, ok := c.Config["emergency_mode"].(bool); ok {
			sc.EmergencyMode = v
		}
		if v, ok := c.Config["emergency_whitelist"].([]any); ok {
			sc.EmergencyWhitelist = strList(v)
		}
		if v, ok := c.Config["enforce_https"].(bool); ok {
			sc.EnforceHTTPS = v
		}
		if v, ok := c.Config["exclude_paths"].([]any); ok {
			sc.ExcludePaths = strList(v)
		}
		if v, ok := c.Config["route_resolution_strict"].(bool); ok {
			sc.RouteResolutionStrict = v
		}
		if v, ok := c.Config["trusted_proxies"].([]any); ok {
			sc.TrustedProxies = strList(v)
		}
		if v, ok := c.Config["block_cloud_providers"].([]any); ok {
			sc.BlockCloudProviders = strList(v)
		}
		if v, ok := c.Config["enable_dynamic_rules"].(bool); ok {
			sc.EnableDynamicRules = v
		}
		if marker, ok := c.Config["custom_request_check"].(string); ok && marker == "corpus_reject_all" {
			sc.CustomRequestCheck = corpusRejectAll
			sc.CustomRequestCheckName = marker
		}
		if len(c.GeoCountries) > 0 {
			sc.GeoIPHandler = fakeCountryResolver(c.GeoCountries)
		}
	})
	if err != nil {
		return nil, err
	}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		return nil, err
	}
	routeIDs := make([]string, 0, len(c.Routes))
	for path := range c.Routes {
		routeIDs = append(routeIDs, path)
	}
	sort.Strings(routeIDs)
	for _, path := range routeIDs {
		engine.Routes.Register(path, eventsRouteMutator(c.Routes[path]))
	}
	return engine, nil
}

func numArg(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int(f), true
}

func stepString(step map[string]any, key string) string {
	if v, ok := step[key].(string); ok {
		return v
	}
	return ""
}

func stepFloat(step map[string]any, key string) (float64, bool) {
	if v, ok := step[key].(float64); ok {
		return v, true
	}
	return 0, false
}

// runEventsCase drives one case through the real engine and returns the
// captured envelopes in emission order, or an error when a scenario seam
// has no Go driver yet.
func runEventsCase(t *testing.T, c eventsCase) ([]map[string]any, error) {
	t.Helper()
	agent := &recordingAgent{}
	c = prepareEventsScenario(c)
	engine, err := buildEventsEngine(t, c, agent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = engine.Close() }()
	// The cloud check binds the package default manager; the pinned-range
	// seam must not leak into later cases.
	defer guardcore.DefaultCloudManager.SetRangeFetcher(nil)

	for _, raw := range c.Drives {
		if err := driveEventsStep(t, engine, agent, raw, c); err != nil {
			return nil, err
		}
	}
	return agent.events, nil
}

// prepareEventsScenario adapts the reference injection seams that map onto
// engine construction inputs: geo_country_stub pins the GeoIP handler's
// country answers and the blocked list, so it becomes a route-level
// blocked_countries decorator (the reference check_country_access hop is
// the route decorator stage) plus a stub resolver entry and a real
// pipeline drive (the Go country verdict lives in the ip_security check).
func prepareEventsScenario(c eventsCase) eventsCase {
	drives := make([]map[string]any, 0, len(c.Drives))
	rewrote := false
	for _, raw := range c.Drives {
		if stepString(raw, "call") == "geo_country_stub" {
			blocked := strList(raw["blocked_countries"])
			ip := stepString(raw, "ip")
			country := stepString(raw, "country")
			if c.GeoCountries == nil {
				c.GeoCountries = map[string]string{}
			}
			c.GeoCountries[ip] = country
			if c.Routes == nil {
				c.Routes = map[string]map[string]any{}
			}
			route := c.Routes["/api"]
			if route == nil {
				route = map[string]any{}
			}
			route["blocked_countries"] = func() []any {
				out := make([]any, 0, len(blocked))
				for _, b := range blocked {
					out = append(out, b)
				}
				return out
			}()
			c.Routes["/api"] = route
			drives = append(drives, map[string]any{"client_ip": ip, "url_path": "/api"})
			rewrote = true
			continue
		}
		drives = append(drives, raw)
	}
	if rewrote {
		c.Drives = drives
	}
	return c
}

func driveEventsStep(t *testing.T, engine *guardcore.Engine, agent *recordingAgent, raw map[string]any, c eventsCase) error {
	t.Helper()
	if call := stepString(raw, "call"); call != "" {
		return driveEventsCall(t, engine, agent, call, raw, c)
	}
	// Pipeline drive: one request through the real check pipeline.
	state := &guardcore.RequestState{}
	if path, ok := raw["url_path"].(string); ok {
		if _, has := c.Routes[path]; has {
			state.GuardRouteID = path
		}
	}
	if _, ok := raw["guard_route_unresolved"].(bool); ok {
		state.RouteUnresolved = true
	}
	headers := map[string]string{}
	if rawHeaders, ok := raw["headers"].(map[string]any); ok {
		for name, value := range rawHeaders {
			headers[name] = fmt.Sprint(value)
		}
	}
	method := stepString(raw, "method")
	if method == "" {
		method = "GET"
	}
	body, _ := raw["body"].(string)
	if body != "" {
		if _, has := headers["Content-Length"]; !has {
			// The harness request pins content-length for every non-empty
			// body (_PipelineRequest.__init__).
			headers["Content-Length"] = fmt.Sprint(len(body))
		}
	}
	req := guardcore.NewRequestFactory().CreateRequest(guardcore.RequestOptions{
		Path:       stepString(raw, "url_path"),
		Scheme:     "http",
		Host:       "example.com",
		Method:     method,
		ClientHost: stepString(raw, "client_ip"),
		Header:     headers,
		Body:       []byte(body),
		State:      state,
	})
	engine.Check(req)
	return nil
}

// driveEventsCall maps the harness's handler-call steps onto the Go
// engine's exported manager surfaces. Missing seams return an error that
// names the seam; those cases are recorded in the fail-closed baseline.
func driveEventsCall(t *testing.T, engine *guardcore.Engine, agent *recordingAgent, call string, step map[string]any, c eventsCase) error {
	t.Helper()
	switch call {
	case "ban_ip":
		ip := stepString(step, "ip")
		duration := 3600
		if v, ok := stepFloat(step, "duration"); ok {
			duration = int(v)
		}
		reason := stepString(step, "reason")
		if reason == "" {
			reason = "corpus_ban"
		}
		_, err := engine.Ban.Ban(ip, duration, reason)
		return err
	case "unban_ip":
		return engine.Ban.Unban(stepString(step, "ip"))
	case "behavior_action":
		ruleRaw, ok := step["rule"].(map[string]any)
		if !ok {
			return fmt.Errorf("behavior_action: missing rule")
		}
		// _rule_from_payload defaults: window 3600, action "log".
		rule := guardcore.BehaviorRuleConfig{RuleType: stepString(ruleRaw, "rule_type"), Action: "log", Window: 3600}
		if v, ok := stepFloat(ruleRaw, "threshold"); ok {
			rule.Threshold = int(v)
		}
		if v, ok := stepFloat(ruleRaw, "window"); ok && int(v) != 0 {
			rule.Window = int(v)
		}
		if v, ok := ruleRaw["action"].(string); ok && v != "" {
			rule.Action = v
		}
		endpointID := stepString(step, "endpoint_id")
		if endpointID == "" {
			endpointID = "corpus.endpoint"
		}
		details := stepString(step, "details")
		engine.Behavior.ApplyAction(rule, stepString(step, "ip"), endpointID, details)
		return nil
	case "dynamic_rules":
		if engine.DynamicRules == nil {
			return fmt.Errorf("dynamic rules manager not built (enable_dynamic_rules missing)")
		}
		payload, ok := step["rules"].(map[string]any)
		if !ok {
			return fmt.Errorf("dynamic_rules: missing rules payload")
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		rules := &guardcore.DynamicRules{}
		if err := json.Unmarshal(raw, rules); err != nil {
			return err
		}
		return engine.DynamicRules.UpdateRules(func() (*guardcore.DynamicRules, error) {
			return rules, nil
		})
	case "monitor_anomaly":
		anomalyThreshold := 3.0
		if v, ok := stepFloat(step, "anomaly_threshold"); ok {
			anomalyThreshold = v
		}
		slowThreshold := 0.1
		if v, ok := stepFloat(step, "slow_pattern_threshold"); ok {
			slowThreshold = v
		}
		minSamples := 10
		if v, ok := stepFloat(step, "min_samples_for_anomaly"); ok {
			minSamples = int(v)
		}
		monitor := guardcore.NewPerformanceMonitor(guardcore.PerformanceMonitorOptions{
			AnomalyThreshold:     anomalyThreshold,
			SlowPatternThreshold: slowThreshold,
			MinSamplesForAnomaly: minSamples,
		})
		samples, ok := step["samples"].([]any)
		if !ok {
			return fmt.Errorf("monitor_anomaly: missing samples")
		}
		for _, item := range samples {
			sample, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("monitor_anomaly: bad sample")
			}
			executionTime, _ := stepFloat(sample, "execution_time")
			contentLength := 128
			if v, ok := stepFloat(sample, "content_length"); ok {
				contentLength = int(v)
			}
			monitor.RecordMetric(guardcore.MetricObservation{
				Pattern:       stepString(sample, "pattern"),
				ExecutionTime: executionTime,
				ContentLength: contentLength,
				Matched:       sample["matched"] == true,
				Timeout:       sample["timeout"] == true,
				Agent:         agent,
			})
		}
		return nil
	case "monitor_callback_fault":
		monitor := guardcore.NewPerformanceMonitor(guardcore.PerformanceMonitorOptions{
			MinSamplesForAnomaly: 10,
		})
		monitor.RegisterAnomalyCallback(func(map[string]any) {
			panic("corpus injected callback failure")
		})
		executionTime, _ := stepFloat(step, "execution_time")
		monitor.RecordMetric(guardcore.MetricObservation{
			Pattern:       stepString(step, "pattern"),
			ExecutionTime: executionTime,
			ContentLength: 128,
			Agent:         agent,
		})
		return nil
	case "cloud_stub":
		// The reference pins cloud_handler lookup answers; the Go engine's
		// cloud check reads the default manager's installed ranges, so the
		// stub pins a range fetcher AND refreshes once so the ranges are
		// installed (cleared after the case).
		provider := stepString(step, "provider")
		if provider == "" {
			provider = "AWS"
		}
		network := stepString(step, "network")
		if network == "" {
			network = "203.0.113.0/24"
		}
		guardcore.DefaultCloudManager.SetRangeFetcher(func(string) ([]string, map[string]string, error) {
			return []string{network}, nil, nil
		})
		if err := guardcore.DefaultCloudManager.RefreshAsync([]string{provider}, 0); err != nil {
			return err
		}
		return nil
	case "geo_download_failure":
		// The reference drives IPInfoManager.initialize with a failing
		// _download_database; the Go lifecycle equivalent is the built-in
		// manager pointed at a closed port (the exported SetDownloadEndpoint
		// seam), with the engine's config so the geo event reaches the bus.
		// The manager's emission gate also consults the OnGeoEvent hook, so
		// a no-op subscriber is installed (the bus hop is unconditional).
		scratch := t.TempDir()
		engine.Config.OnGeoEvent = func(guardcore.GeoEvent) {}
		manager := guardcore.NewIPInfoManager("corpus-token", filepath.Join(scratch, "corpus.mmdb"), guardcore.DefaultIPInfoMaxAge, engine.Config)
		manager.SetDownloadEndpoint("http://127.0.0.1:1/db", nil)
		manager.Initialize()
		return nil
	case "rate_limit_script_reload":
		// The reference re-caches the rate-limit Lua script after a
		// SCRIPT FLUSH; the Go manager's NOSCRIPT recovery is the same
		// seam: load the script, flush the server's script cache, then
		// record one hit.
		return driveRateLimitScriptReload(t, engine, step)
	case "redis_connect":
		// The reference drives RedisManager.initialize against the live
		// Redis with the handler attached.
		return driveRedisConnect(t, engine, eventsRedisURL(), false)
	case "redis_connect_error":
		return driveRedisConnect(t, engine, "redis://localhost:59999/0", true)
	case "bypass":
		// The reference drives BypassHandler.handle_security_bypass; the
		// Go engine's route bypass short-circuits in Engine.Check, so the
		// driver runs the real bypass path (no event emitted yet).
		state := &guardcore.RequestState{GuardRouteID: stepString(step, "url_path")}
		req := guardcore.NewRequestFactory().CreateRequest(guardcore.RequestOptions{
			Path:       stepString(step, "url_path"),
			Host:       "example.com",
			Method:     "GET",
			ClientHost: stepString(step, "client_ip"),
			State:      state,
		})
		engine.Check(req)
		return nil
	case "path_excluded":
		// The reference drives RequestValidator.is_path_excluded; the Go
		// engine's exclusion matcher runs in Engine.Check, so the driver
		// runs the real exclusion path (no event emitted yet).
		req := guardcore.NewRequestFactory().CreateRequest(guardcore.RequestOptions{
			Path:       stepString(step, "url_path"),
			Host:       "example.com",
			Method:     "GET",
			ClientHost: stepString(step, "client_ip"),
			State:      &guardcore.RequestState{},
		})
		engine.Check(req)
		return nil
	// Scenario seams the Go engine does not expose yet. Each error names
	// the seam; those cases carry per-case reasons in the fail-closed
	// baseline.
	case "decorator_event":
		// The reference decorator senders route through the middleware bus
		// (BaseSecurityDecorator.send_decorator_event); the Go bus is the
		// same seam, so the driver calls it with the mapped event surface.
		cfg := engine.Config
		bus := guardcore.NewSecurityEventBus(cfg.AgentHandler, cfg, nil, guardcore.EventFilter{})
		kwargs, _ := step["kwargs"].(map[string]any)
		switch stepString(step, "send") {
		case "send_access_denied_event":
			kwargs["decorator_type"], _ = kwargs["decorator_type"].(string)
			reason, _ := kwargs["reason"].(string)
			bus.SendMiddlewareEvent(guardcore.EventAccessDenied, makeDecoratorRequest(t, step), "blocked", reason, kwargs)
			return nil
		case "send_authentication_failed_event":
			authType, _ := kwargs["auth_type"].(string)
			reason, _ := kwargs["reason"].(string)
			bus.SendMiddlewareEvent(guardcore.EventAuthenticationFailed, makeDecoratorRequest(t, step), "blocked", reason,
				map[string]any{"decorator_type": "authentication", "auth_type": authType})
			return nil
		default:
			return fmt.Errorf("unknown decorator sender %q", stepString(step, "send"))
		}
	case "csp_report":
		// The reference drives security_headers_manager.validate_csp_report
		// with the handler attached; the Go manager's ValidateCSPReport is
		// the same surface.
		report, _ := step["report"].(map[string]any)
		manager := guardcore.NewSecurityHeadersManager(guardcore.DefaultSecurityHeaders())
		manager.SetAgentHandler(agent)
		if !manager.ValidateCSPReport(report) {
			return fmt.Errorf("corpus CSP report was rejected as invalid")
		}
		return nil
	case "headers_applied":
		// The reference drives security_headers_manager.get_headers with
		// the handler attached on a cleared cache.
		path := stepString(step, "path")
		engine.Config.OnGeoEvent = func(guardcore.GeoEvent) {}
		state := guardcore.DefaultSecurityHeaders()
		manager := guardcore.NewSecurityHeadersManager(state)
		manager.SetAgentHandler(agent)
		manager.GetHeaders(path)
		return nil
	case "ipban_fault":
		// The reference monkeypatches ban_ip to raise; the Go seam is the
		// exported SetBanFault hook on the ban manager.
		engine.Ban.SetBanFault(func(string) error {
			return fmt.Errorf("corpus injected ban failure")
		})
		return nil
	case "detect", "add_pattern", "remove_pattern":
		return fmt.Errorf("sus-patterns handler telemetry seam not mapped in this runner revision")
	default:
		return fmt.Errorf("unknown events harness call %q", call)
	}
}

// eventsRedisURL answers the harness's EVENTS_REDIS_URL: the URL is a
// pinned envelope field, so the corpus host spelling is kept verbatim.
func eventsRedisURL() string {
	return "redis://localhost:6379/0"
}

func redisHostAddr() string {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	return host + ":6379"
}

// driveRateLimitScriptReload runs the reference NOSCRIPT-recovery scenario:
// a real manager over the live Redis with the script loaded, a SCRIPT FLUSH
// wiping the server cache, then one tiered check (the tiered path is the
// Lua-script path; CheckRateLimitByIP forces the pipeline fallback).
func driveRateLimitScriptReload(t *testing.T, engine *guardcore.Engine, step map[string]any) error {
	t.Helper()
	url := eventsRedisURL()
	prefix := "guard_core:corpus_evts:"
	flusher := redis.NewClient(&redis.Options{Addr: redisHostAddr()})
	defer func() { _ = flusher.Close() }()
	redisMgr := guardcore.NewRedisManager(guardcore.RedisConfig{URL: url, Prefix: prefix, EnableRedis: true})
	defer func() { _ = redisMgr.Close() }()
	cfg := engine.Config
	bus := guardcore.NewSecurityEventBus(cfg.AgentHandler, cfg, nil, guardcore.EventFilter{})
	manager := guardcore.NewRateLimitManager(guardcore.RateLimitConfigFromSecurityConfig(cfg), redisMgr, engine.Ban)
	manager.SetEventBus(bus, cfg.PassiveMode)
	manager.InitializeRedis(redisMgr)
	// Flush AFTER the load: the manager's cached SHA now points at a script
	// the server no longer has, so the next eval takes the NOSCRIPT branch.
	if err := flusher.ScriptFlush(t.Context()).Err(); err != nil {
		return fmt.Errorf("script flush: %w", err)
	}
	if _, err := manager.CheckRateLimit(stepString(step, "client_ip"), stepString(step, "url_path"), nil, nil); err != nil {
		return err
	}
	return nil
}

// driveRedisConnect performs a real RedisManager.Initialize against url.
func driveRedisConnect(t *testing.T, engine *guardcore.Engine, url string, expectFailure bool) error {
	t.Helper()
	prefix := "guard_core:corpus_evts:"
	manager := guardcore.NewRedisManager(guardcore.RedisConfig{URL: url, Prefix: prefix, EnableRedis: true})
	manager.SetAgentHandler(engine.Config.AgentHandler)
	err := manager.Initialize()
	if expectFailure {
		if err == nil {
			_ = manager.Close()
			return fmt.Errorf("expected connection failure for %s", url)
		}
		return nil
	}
	if err != nil {
		return err
	}
	return manager.Close()
}

func loadEventsXfail(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(eventsXfailFile)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}
		}
		t.Fatal(err)
	}
	var baseline struct {
		SpecVersion string            `json:"spec_version"`
		Cases       map[string]string `json:"cases"`
	}
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.SpecVersion != corpusSpecVersion {
		t.Fatalf("xfail baseline spec pin %s does not match %s", baseline.SpecVersion, corpusSpecVersion)
	}
	return baseline.Cases
}

func TestEventsConformance(t *testing.T) {
	path := filepath.Join(corpusCasesDir, "event_stream.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var suite eventsSuiteFile
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	if suite.Kind != "events" {
		t.Fatalf("suite kind drifted: %q", suite.Kind)
	}
	if len(suite.Cases) == 0 {
		t.Fatal("event_stream corpus matched zero cases: a vacuous pass is a failure")
	}

	xfail := loadEventsXfail(t)
	baselinedSeen := map[string]bool{}
	total, passed, xfailed, skipped, stale := 0, 0, 0, 0, 0
	var failures, xfailNotes []string
	for _, c := range suite.Cases {
		key := suite.Suite + "/" + c.ID
		if c.Xfail {
			// Corpus-advisory xfail: no deterministic driver exists in the
			// reference either; carry no expectations.
			skipped++
			continue
		}
		total++
		got, runErr := runEventsCase(t, c)
		var diffs []string
		if runErr != nil {
			diffs = []string{"driver: " + runErr.Error()}
		} else {
			if len(got) != len(c.Expected) {
				diffs = append(diffs, fmt.Sprintf("event count: got %d want %d", len(got), len(c.Expected)))
			}
			for i, want := range c.Expected {
				if i >= len(got) {
					break
				}
				diffs = append(diffs, envelopeDiffs(fmt.Sprintf("event[%d]", i), got[i], normalizeEnvelope(want))...)
			}
		}
		if len(diffs) == 0 {
			passed++
			if reason, ok := xfail[key]; ok {
				stale++
				baselinedSeen[key] = true
				failures = append(failures, fmt.Sprintf("stale xfail baseline entry %s [%s]: case now reproduces the reference envelopes; remove the entry", key, reason))
			}
			continue
		}
		reason, ok := xfail[key]
		if !ok {
			failures = append(failures, fmt.Sprintf("%s:\n  %s\n  record the divergence in %s", key, strings.Join(prefixAll(diffs, "  "), "\n  "), eventsXfailFile))
			continue
		}
		baselinedSeen[key] = true
		xfailed++
		xfailNotes = append(xfailNotes, fmt.Sprintf("xfail %s [%s]: %s", key, reason, strings.Join(diffs, "; ")))
	}
	for id := range xfail {
		if !baselinedSeen[id] {
			failures = append(failures, fmt.Sprintf("xfail baseline entry %s never ran; corpus changed?", id))
		}
	}
	sort.Strings(xfailNotes)
	for _, x := range xfailNotes {
		t.Logf("%s", x)
	}
	if len(failures) > 0 {
		t.Fatalf("events conformance drift: %d failures over %d cases\n%s", len(failures), total, strings.Join(failures, "\n"))
	}
	t.Logf("events conformance gate: %d passed, %d xfail, %d corpus-advisory skipped, %d stale, %d cases (spec %s)", passed, xfailed, skipped, stale, total, corpusSpecVersion)
}
