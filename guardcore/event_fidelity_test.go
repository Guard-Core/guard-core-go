package guardcore

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The event-fidelity wave's new surfaces, pinned the way the corpus pins
// them: the reference envelope shape, the emission conditions and the
// fail-soft error paths.

func TestSecurityHeadersManagerEmitsHeadersAppliedOnMiss(t *testing.T) {
	agent := &recordingAgent{}
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager.SetAgentHandler(agent)
	headers := manager.GetHeaders("/api")
	if len(headers) == 0 {
		t.Fatal("the default header set must resolve")
	}
	if len(agent.events) != 1 {
		t.Fatalf("the miss must announce headers_applied once, got %+v", agent.events)
	}
	event := agent.events[0]
	if event.EventType != EventSecurityHeadersApplied || event.HandlerName != "security_headers" {
		t.Fatalf("identity drifted: %+v", event)
	}
	if event.ActionTaken != "headers_added" {
		t.Fatalf("action drifted: %+v", event)
	}
	if event.Metadata["path"] != "/api" {
		t.Fatalf("path metadata drifted: %+v", event.Metadata)
	}
	if event.Metadata["headers_count"] != len(headers) {
		t.Fatalf("headers_count drifted: %+v", event.Metadata)
	}
	if event.Metadata["has_hsts"] != true || event.Metadata["has_csp"] != false {
		t.Fatalf("csp/hsts flags drifted: %+v", event.Metadata)
	}
	// The cache hit must not re-announce.
	_ = manager.GetHeaders("/api")
	if len(agent.events) != 1 {
		t.Fatalf("cache hits must not re-emit, got %+v", agent.events)
	}
	// Empty paths never announce (the reference gate).
	manager.GetHeaders("")
	if len(agent.events) != 1 {
		t.Fatalf("empty paths must not announce, got %+v", agent.events)
	}
}

func TestValidateCSPReportVerdictAndEvent(t *testing.T) {
	agent := &recordingAgent{}
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	if manager.ValidateCSPReport(map[string]any{"csp-report": map[string]any{"document-uri": "https://x"}}) {
		t.Fatal("a report missing required fields must be rejected")
	}
	manager.SetAgentHandler(agent)
	valid := map[string]any{
		"csp-report": map[string]any{
			"document-uri":       "https://example.com/page",
			"violated-directive": "script-src",
			"blocked-uri":        "https://evil.example/x.js",
		},
	}
	if !manager.ValidateCSPReport(valid) {
		t.Fatal("a complete report must validate")
	}
	if len(agent.events) != 1 {
		t.Fatalf("the violation must reach the handler, got %+v", agent.events)
	}
	event := agent.events[0]
	if event.EventType != EventCSPViolation || event.ActionTaken != "logged" || event.HandlerName != "security_headers" {
		t.Fatalf("identity drifted: %+v", event)
	}
	metadata := event.Metadata
	if metadata["document_uri"] != "https://example.com/page" || metadata["violated_directive"] != "script-src" {
		t.Fatalf("report fields drifted: %+v", metadata)
	}
	if metadata["source_file"] != "None" {
		t.Fatalf("the absent source_file must str()-render as None: %+v", metadata)
	}
	if metadata["line_number"] != nil {
		t.Fatalf("the absent line_number must stay nil: %+v", metadata)
	}
}

func TestValidateCSPReportLineNumberParsing(t *testing.T) {
	agent := &recordingAgent{}
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager.SetAgentHandler(agent)
	if !manager.ValidateCSPReport(map[string]any{"csp-report": map[string]any{
		"document-uri": "https://x", "violated-directive": "d", "blocked-uri": "https://b", "line-number": float64(42),
	}}) {
		t.Fatal("report must validate")
	}
	if got := agent.events[0].Metadata["line_number"]; got != 42 {
		t.Fatalf("line_number drifted: %+v", got)
	}
	if !manager.ValidateCSPReport(map[string]any{"csp-report": map[string]any{
		"document-uri": "https://x", "violated-directive": "d", "blocked-uri": "https://b", "line-number": "not-a-number",
	}}) {
		t.Fatal("an unparseable line number must not reject the report")
	}
	if got := agent.events[1].Metadata["line_number"]; got != nil {
		t.Fatalf("an unparseable line number must render nil, got %+v", got)
	}
}

func TestDetectIPSpoofingEmitsSuspiciousRequest(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		Scheme:     "http",
		Host:       "example.com",
		Method:     "GET",
		ClientHost: "203.0.113.17",
		Header:     map[string]string{"X-Forwarded-For": "198.51.100.77"},
	})
	engine.Check(req)
	event := findEvent(agent, EventSuspiciousRequest)
	if event == nil {
		t.Fatalf("suspicious_request must reach the agent, got %v", agent.eventTypes())
	}
	if event.HandlerName != "ip_extraction" || event.ActionTaken != "spoofing_detected" {
		t.Fatalf("identity drifted: %+v", event)
	}
	if want := "Potential IP spoof attempt: X-Forwarded-For header 198.51.100.77"; event.Reason != want {
		t.Fatalf("reason drifted: %q, want %q", event.Reason, want)
	}

	// A trusted-proxy peer runs the legitimate chain, no event.
	engine2, agent2 := newEventTestEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req2 := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "192.0.2.1",
		Header:     map[string]string{"X-Forwarded-For": "198.51.100.77"},
	})
	engine2.Check(req2)
	if findEvent(agent2, EventSuspiciousRequest) != nil {
		t.Fatalf("trusted proxy peers must not trip the spoof gate, got %v", agent2.eventTypes())
	}
}

func TestPathExcludedAndBypassEvents(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.ExcludePaths = []string{"/health"}
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/health",
		ClientHost: "203.0.113.10",
	})
	engine.Check(req)
	event := findEvent(agent, EventPathExcluded)
	if event == nil {
		t.Fatalf("path_excluded must reach the agent, got %v", agent.eventTypes())
	}
	if event.ActionTaken != "security_checks_bypassed" {
		t.Fatalf("action drifted: %+v", event)
	}
	if want := "Path /health excluded from security checks"; event.Reason != want {
		t.Fatalf("reason drifted: %q, want %q", event.Reason, want)
	}
	if event.Metadata["excluded_path"] != "/health" {
		t.Fatalf("excluded_path drifted: %+v", event.Metadata)
	}
	exclusions, ok := event.Metadata["configured_exclusions"].([]string)
	if !ok || len(exclusions) != 1 || exclusions[0] != "/health" {
		t.Fatalf("configured_exclusions drifted: %+v", event.Metadata)
	}
	// The TTL cache dedups repeat emissions.
	engine.Check(req)
	if len(agent.events) != 1 {
		t.Fatalf("repeat exclusions must not re-emit, got %v", agent.eventTypes())
	}

	// The all-checks bypass announces itself.
	engine2, agent2 := newEventTestEngine(t, nil)
	engine2.Routes.Register("/open", func(rc *RouteConfig) {
		rc.BypassedChecks = []string{"all"}
	})
	req2 := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/open",
		ClientHost: "203.0.113.10",
		State:      &RequestState{GuardRouteID: "/open"},
	})
	engine2.Check(req2)
	bypass := findEvent(agent2, EventSecurityBypass)
	if bypass == nil {
		t.Fatalf("security_bypass must reach the agent, got %v", agent2.eventTypes())
	}
	if bypass.ActionTaken != "all_checks_bypassed" {
		t.Fatalf("action drifted: %+v", bypass)
	}
	if bypass.Metadata["endpoint"] != "/open" {
		t.Fatalf("endpoint metadata drifted: %+v", bypass.Metadata)
	}
}

func TestSetBanFaultDrivesTheEscalationFailure(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.Blacklist = []string{"203.0.113.13"}
		c.EnableIPBanning = true
		c.AutoBanThreshold = 1
	})
	engine.Ban.SetBanFault(func(string) error {
		return errCorpusBanFault
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "203.0.113.13",
		Body:       []byte("<script>alert(1)</script>"),
	})
	engine.Check(req)
	event := findEvent(agent, EventIPBanFailed)
	if event == nil {
		t.Fatalf("ip_ban_failed must reach the agent, got %v", agent.eventTypes())
	}
	if event.ActionTaken != "ban_not_applied" {
		t.Fatalf("action drifted: %+v", event)
	}
	if want := "Escalation ban failed for 203.0.113.13: corpus injected ban failure"; event.Reason != want {
		t.Fatalf("reason drifted: %q, want %q", event.Reason, want)
	}
	if event.Metadata["ip_address"] != "203.0.113.13" {
		t.Fatalf("ip_address kwarg drifted: %+v", event.Metadata)
	}
	// Clearing the seam restores the real ban path.
	engine.Ban.SetBanFault(nil)
}

var errCorpusBanFault = &staticError{"corpus injected ban failure"}

type staticError struct{ message string }

func (e *staticError) Error() string { return e.message }

func TestCustomRequestCheckConfiguredName(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.CustomRequestCheck = corpusStyleBlocker
		c.CustomRequestCheckName = "corpus_reject_all"
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{Path: "/api", ClientHost: "203.0.113.10"})
	engine.Check(req)
	event := findEvent(agent, EventCustomRequestCheck)
	if event == nil {
		t.Fatalf("custom_request_check must reach the agent, got %v", agent.eventTypes())
	}
	if event.Metadata["check_function"] != "corpus_reject_all" {
		t.Fatalf("the configured name must ride check_function: %+v", event.Metadata)
	}
}

func corpusStyleBlocker(Request) *Response {
	return NewResponseFactory().CreateResponse("blocked", http.StatusTeapot)
}

func TestRedactRedisURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"redis://localhost:6379/0", "redis://localhost:6379/0"},
		{"redis://user:secret@redis.internal:6380/2", "redis://redis.internal:6380/2"},
		{"redis://[::1]:6379/0", "redis://[::1]:6379/0"},
		{"redis://", "redis://"},
	}
	for _, tc := range cases {
		if got := redactRedisURL(tc.in); got != tc.want {
			t.Fatalf("redactRedisURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := redactRedisURL("redis://[::1:bad"); !strings.HasSuffix(got, "<unparseable>") {
		t.Fatalf("an unparseable URL must render the placeholder, got %q", got)
	}
}

func TestSendHandlerEventRequestEnvelope(t *testing.T) {
	agent := &recordingAgent{}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.LogSensitiveParams = map[string]bool{"access_token": true}
	})
	if err != nil {
		t.Fatal(err)
	}
	bus := NewSecurityEventBus(agent, cfg, nil, EventFilter{})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:     "/api?access_token=PLACEHOLDER",
		RawQuery: "access_token=PLACEHOLDER",
		Scheme:   "http",
		Host:     "example.com",
		Method:   "GET",
		Header: map[string]string{
			"User-Agent":  "ua-bot/2.0",
			"Traceparent": "00-trace-span-01",
		},
	})
	bus.SendHandlerEventRequest(EventRateLimited, RateLimitHandlerName, req, "request_blocked", "reason", "",
		map[string]any{"request_count": 2})
	if len(agent.events) != 1 {
		t.Fatalf("the envelope must reach the handler, got %+v", agent.events)
	}
	event := agent.events[0]
	if event.HandlerName != RateLimitHandlerName {
		t.Fatalf("handler name drifted: %+v", event)
	}
	if !strings.Contains(event.Endpoint, "access_token=[REDACTED]") {
		t.Fatalf("endpoint must redact, got %q", event.Endpoint)
	}
	if event.UserAgent != "ua-bot/2.0" {
		t.Fatalf("user agent drifted: %q", event.UserAgent)
	}
	if event.Metadata["traceparent"] != "00-trace-span-01" {
		t.Fatalf("traceparent must forward: %+v", event.Metadata)
	}
	if event.Metadata["request_count"] != 2 {
		t.Fatalf("kwargs must ride metadata: %+v", event.Metadata)
	}
}

func TestSendHandlerEventRequestNilTolerance(t *testing.T) {
	// A nil bus and a handler-less bus are both inert.
	var nilBus *SecurityEventBus
	nilBus.SendHandlerEventRequest(EventRateLimited, RateLimitHandlerName, nil, "a", "r", "", nil)
	bus := &SecurityEventBus{}
	bus.SendHandlerEventRequest(EventRateLimited, RateLimitHandlerName, nil, "a", "r", "", nil)

	// The log-sensitive accessors tolerate a nil config.
	agent := &recordingAgent{}
	nilCfgBus := NewSecurityEventBus(agent, nil, nil, EventFilter{})
	if nilCfgBus.logSensitiveParams() != nil || nilCfgBus.logSensitiveBodyFields() != nil || nilCfgBus.logSensitiveHeaders() != nil {
		t.Fatal("a nil config must render nil sensitive sets")
	}
	if len(agent.events) != 0 {
		t.Fatalf("the accessors must not emit, got %+v", agent.events)
	}
}

func TestEscalationAnnouncesTrackedAndBanned(t *testing.T) {
	// Threshold 5 with one category hit: the escalation announces tracked.
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.Blacklist = []string{"203.0.113.40"}
		c.EnableIPBanning = true
		c.AutoBanThreshold = 5
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "203.0.113.40",
		Body:       []byte("<script>alert(1)</script>"),
	})
	engine.Check(req)
	announcements := 0
	for _, event := range agent.events {
		if event.EventType == EventPenetrationAttempt && strings.HasPrefix(event.Reason, "Identity violation escalated:") {
			announcements++
			if event.ActionTaken != "tracked" {
				t.Fatalf("a refused ban must announce tracked, got %+v", event)
			}
			if event.Metadata["violation_category"] != "ip_blocked" {
				t.Fatalf("violation_category drifted: %+v", event.Metadata)
			}
		}
	}
	if announcements != 1 {
		t.Fatalf("the escalation must announce once, got %d (%v)", announcements, agent.eventTypes())
	}

	// Threshold 1: the local ban applies, the announcement reports banned.
	engine2, agent2 := newEventTestEngine(t, func(c *SecurityConfig) {
		c.Blacklist = []string{"203.0.113.41"}
		c.EnableIPBanning = true
		c.AutoBanThreshold = 1
	})
	req2 := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "203.0.113.41",
		Body:       []byte("<script>alert(1)</script>"),
	})
	engine2.Check(req2)
	banned := false
	for _, event := range agent2.events {
		if event.EventType == EventPenetrationAttempt && strings.HasPrefix(event.Reason, "Identity violation escalated:") {
			banned = event.ActionTaken == "banned"
		}
	}
	if !banned {
		t.Fatalf("the applied ban must announce banned, got %v", agent2.eventTypes())
	}

	// Banning disabled: the escalation still announces tracked.
	engine3, agent3 := newEventTestEngine(t, func(c *SecurityConfig) {
		c.Blacklist = []string{"203.0.113.42"}
		c.EnableIPBanning = false
	})
	req3 := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "203.0.113.42",
		Body:       []byte("<script>alert(1)</script>"),
	})
	engine3.Check(req3)
	sawTracked := false
	for _, event := range agent3.events {
		if event.EventType == EventPenetrationAttempt && strings.HasPrefix(event.Reason, "Identity violation escalated:") {
			sawTracked = event.ActionTaken == "tracked"
		}
	}
	if !sawTracked {
		t.Fatalf("banning-disabled escalations still announce tracked, got %v", agent3.eventTypes())
	}
}

func TestEscalationEarlyReturns(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.EnableRedis = false })
	if err != nil {
		t.Fatal(err)
	}
	cfg.installAgentStream()
	check := &ipSecurityCheck{cfg: cfg, counts: &suspiciousCountStore{m: map[string]map[string]int{}}}
	// An empty IP never escalates.
	check.escalateIdentityViolation(newTestRequest(t, nil), "", "ip_blocked", "reason")
	// A whitelisted identity never escalates.
	req := newTestRequest(t, func(_ *RequestOptions, state *RequestState) { state.IsWhitelisted = true })
	check.escalateIdentityViolation(req, "203.0.113.44", "ip_blocked", "reason")
	// A clean request finds no detection and stops.
	check.escalateIdentityViolation(newTestRequest(t, nil), "203.0.113.45", "ip_blocked", "reason")
}

func TestEmitPathExcludedEventResetsAtCapacity(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.ExcludePaths = []string{"/health"}
	})
	engine.exclusions.mu.Lock()
	engine.exclusions.emittedPaths = map[string]time.Time{}
	for i := 0; i < 1000; i++ {
		engine.exclusions.emittedPaths[fmt.Sprintf("/p%d", i)] = time.Now().Add(-time.Hour)
	}
	engine.exclusions.mu.Unlock()
	req := NewRequestFactory().CreateRequest(RequestOptions{Path: "/health", ClientHost: "203.0.113.10"})
	engine.Check(req)
	found := false
	for _, event := range agent.events {
		if event.EventType == EventPathExcluded {
			found = true
		}
	}
	if !found {
		t.Fatalf("the capacity reset must still announce the exclusion, got %v", agent.eventTypes())
	}
}

func TestDetectIPSpoofingQuietArms(t *testing.T) {
	// No forwarded header: nothing to inspect.
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{Path: "/api", ClientHost: "203.0.113.17"})
	engine.Check(req)
	if len(agent.events) != 0 {
		t.Fatalf("a headerless request must stay quiet, got %v", agent.eventTypes())
	}
	// No installed bus: the detection is inert.
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	if err != nil {
		t.Fatal(err)
	}
	busless, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busless.Close() }()
	req2 := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "203.0.113.17",
		Header:     map[string]string{"X-Forwarded-For": "198.51.100.77"},
	})
	busless.Check(req2)
}

func TestPythonHelpers(t *testing.T) {
	if got := pythonListRepr([]string{"a", "b"}); got != "['a', 'b']" {
		t.Fatalf("pythonListRepr drifted: %q", got)
	}
	if got := pythonListRepr(nil); got != "[]" {
		t.Fatalf("pythonListRepr empty drifted: %q", got)
	}
	if got := safeCSPLineNumber(7); got != 7 {
		t.Fatalf("safeCSPLineNumber int drifted: %+v", got)
	}
	if got := pythonStr(true); got != "true" {
		t.Fatalf("pythonStr true drifted: %q", got)
	}
	if got := pythonStr(false); got != "false" {
		t.Fatalf("pythonStr false drifted: %q", got)
	}
	if got := pythonStr(42); got != "42" {
		t.Fatalf("pythonStr default drifted: %q", got)
	}
}

func TestRedisAndHeadersEventSendFailuresStaySoft(t *testing.T) {
	failing := &recordingAgent{eventErr: errAgentDown}
	manager := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1", Prefix: "guard_core:", EnableRedis: true})
	manager.SetAgentHandler(failing)
	// The failure is logged, never raised: the initialize error is the
	// connection failure, not the send failure.
	if err := manager.Initialize(); err == nil {
		t.Fatal("the dial failure must still fail the initialize")
	}

	headers := NewSecurityHeadersManager(DefaultSecurityHeaders())
	headers.SetAgentHandler(failing)
	_ = headers.GetHeaders("/api")
	if !headers.ValidateCSPReport(map[string]any{"csp-report": map[string]any{
		"document-uri": "https://x", "violated-directive": "d", "blocked-uri": "https://b",
	}}) {
		t.Fatal("a send failure must not flip the verdict")
	}
}

var errAgentDown = &staticError{"agent down"}

func TestSendHandlerEventRequestSendFailureStaysSoft(t *testing.T) {
	agent := &recordingAgent{eventErr: errAgentDown}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {})
	if err != nil {
		t.Fatal(err)
	}
	bus := NewSecurityEventBus(agent, cfg, nil, EventFilter{})
	req := NewRequestFactory().CreateRequest(RequestOptions{Path: "/api", ClientHost: "203.0.113.10"})
	bus.SendHandlerEventRequest(EventRateLimited, RateLimitHandlerName, req, "request_blocked", "reason", "", nil)
}

func TestEscalationThresholdArms(t *testing.T) {
	// The per-category threat entry drives duration and reason.
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.Blacklist = []string{"203.0.113.50"}
		c.EnableIPBanning = true
		c.AutoBanThreshold = 100
		c.ThreatBanConfig = map[string]ThreatBanEntry{"xss": {Threshold: 1, Duration: 60}}
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "203.0.113.50",
		Body:       []byte("<script>alert(1)</script>"),
	})
	engine.Check(req)
	banned := false
	for _, event := range agent.events {
		if event.EventType == EventPenetrationAttempt && strings.HasPrefix(event.Reason, "Identity violation escalated:") {
			banned = event.ActionTaken == "banned"
		}
	}
	if !banned {
		t.Fatalf("the threat-entry ban must announce banned, got %v", agent.eventTypes())
	}

	// The flat threshold over the category total applies when no per-
	// category entry crossed: two distinct categories, threshold 2.
	engine2, agent2 := newEventTestEngine(t, func(c *SecurityConfig) {
		c.Blacklist = []string{"203.0.113.51"}
		c.EnableIPBanning = true
		c.AutoBanThreshold = 2
	})
	body := "<script>alert(1)</script> AND 1=1 UNION SELECT * FROM users--"
	req2 := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "203.0.113.51",
		Body:       []byte(body),
	})
	engine2.Check(req2)
	sawAnnouncement := false
	for _, event := range agent2.events {
		if event.EventType == EventPenetrationAttempt && strings.HasPrefix(event.Reason, "Identity violation escalated:") {
			sawAnnouncement = true
		}
	}
	if !sawAnnouncement {
		t.Fatalf("the flat-threshold escalation must announce, got %v", agent2.eventTypes())
	}

	// The flat-threshold ban failure aborts the announcement.
	engine3, agent3 := newEventTestEngine(t, func(c *SecurityConfig) {
		c.Blacklist = []string{"203.0.113.52"}
		c.EnableIPBanning = true
		c.AutoBanThreshold = 2
	})
	engine3.Ban.SetBanFault(func(string) error { return errCorpusBanFault })
	req3 := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "203.0.113.52",
		Body:       []byte(body),
	})
	engine3.Check(req3)
	failed := false
	for _, event := range agent3.events {
		if event.EventType == EventIPBanFailed {
			failed = true
		}
		if event.EventType == EventPenetrationAttempt && strings.HasPrefix(event.Reason, "Identity violation escalated:") {
			t.Fatalf("a failed flat ban must abort the announcement, got %+v", event)
		}
	}
	if !failed {
		t.Fatalf("the flat-ban failure must report ip_ban_failed, got %v", agent3.eventTypes())
	}
}

func TestEscalationRefusedBanAnnouncesTracked(t *testing.T) {
	// A loopback deny with an attack payload: the ban manager refuses the
	// self-DoS ban, the escalation announces tracked.
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.Blacklist = []string{"127.0.0.1"}
		c.EnableIPBanning = true
		c.AutoBanThreshold = 1
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "127.0.0.1",
		Body:       []byte("<script>alert(1)</script>"),
	})
	engine.Check(req)
	found := false
	for _, event := range agent.events {
		if event.EventType == EventPenetrationAttempt && strings.HasPrefix(event.Reason, "Identity violation escalated:") {
			found = event.ActionTaken == "tracked"
		}
	}
	if !found {
		t.Fatalf("a refused ban must announce tracked, got %v", agent.eventTypes())
	}
}

func TestHeadersNilAgentAndStringLineNumbers(t *testing.T) {
	// The private senders stay inert without a handler.
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager.sendHeadersAppliedEvent("/api", map[string]string{"X": "y"})
	manager.sendCSPViolationEvent(map[string]any{"document-uri": "https://x"})

	// A numeric string line number parses.
	agent := &recordingAgent{}
	manager2 := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager2.SetAgentHandler(agent)
	if !manager2.ValidateCSPReport(map[string]any{"csp-report": map[string]any{
		"document-uri": "https://x", "violated-directive": "d", "blocked-uri": "https://b", "line-number": "17",
	}}) {
		t.Fatal("the report must validate")
	}
	if got := agent.events[0].Metadata["line_number"]; got != 17 {
		t.Fatalf("string line numbers parse, got %+v", got)
	}
}

func TestEscalationFlatRefusalAnnouncesTracked(t *testing.T) {
	// No per-category entry matches the payload's categories, so the flat
	// total threshold drives the ban; the loopback refusal lands in the
	// flat refusal arm and the escalation announces tracked.
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.Blacklist = []string{"127.0.0.1"}
		c.EnableIPBanning = true
		c.AutoBanThreshold = 1
		// The xss entry's threshold sits above the single hit, so the
		// per-category loop misses and the flat total threshold drives.
		c.ThreatBanConfig = map[string]ThreatBanEntry{"xss": {Threshold: 5, Duration: 60}}
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		ClientHost: "127.0.0.1",
		Body:       []byte("<script>alert(1)</script>"),
	})
	engine.Check(req)
	found := false
	for _, event := range agent.events {
		if event.EventType == EventPenetrationAttempt && strings.HasPrefix(event.Reason, "Identity violation escalated:") {
			found = event.ActionTaken == "tracked"
		}
	}
	if !found {
		t.Fatalf("the flat refusal must announce tracked, got %v", agent.eventTypes())
	}
}
