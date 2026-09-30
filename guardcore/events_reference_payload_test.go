package guardcore

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Reference-payload pins for the event emissions the fidelity review
// called out: every assertion quotes the exact event type, reason string,
// and metadata the Python reference emits at the matching site
// (ip_security.py, cloud_provider.py, user_agent.py, rate_limit.py,
// emergency_mode.py, custom_request.py, checks/helpers.py,
// _dynamic_rules.py).

// referenceBlocker is a named custom request check so the event payload's
// check_function pin is deterministic.
func referenceBlocker(Request) *Response {
	return NewResponseFactory().CreateResponse("blocked by the custom check", http.StatusForbidden)
}

func agentConfig(t *testing.T, mutate func(*SecurityConfig)) (*SecurityConfig, *recordingAgent) {
	t.Helper()
	agent := &recordingAgent{}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.AgentHandler = agent
		if mutate != nil {
			mutate(c)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.installAgentStream()
	return cfg, agent
}

// TestReferenceBannedIPBlockedEvent pins ip_security.py's
// _check_banned_ip emission: ip_blocked with the banned filter tier, the
// client IP kwarg, and the banned-access reason, in passive and active
// mode alike.
func TestReferenceBannedIPBlockedEvent(t *testing.T) {
	tests := []struct {
		name        string
		passive     bool
		actionTaken string
	}{
		{"active", false, "request_blocked"},
		{"passive", true, "logged_only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
				c.PassiveMode = tt.passive
			})
			if _, err := engine.Ban.Ban("203.0.113.77", 120, "test-ban"); err != nil {
				t.Fatal(err)
			}
			req := newTestRequest(t, func(_ *RequestOptions, state *RequestState) {
				state.ClientIP = "203.0.113.77"
			})
			resp := engine.Check(req)
			if tt.passive {
				if resp != nil {
					t.Fatalf("passive mode must not block, got %+v", resp)
				}
			} else if resp == nil || resp.StatusCode != http.StatusForbidden {
				t.Fatalf("active mode must block with 403, got %+v", resp)
			}
			var blocked *SecurityEvent
			for i := range agent.events {
				if agent.events[i].EventType == EventIPBlocked {
					blocked = &agent.events[i]
				}
			}
			if blocked == nil {
				t.Fatalf("ip_blocked must reach the agent on the banned path, got %v", agent.eventTypes())
			}
			if blocked.ActionTaken != tt.actionTaken {
				t.Fatalf("action_taken drifted: %+v", blocked)
			}
			if want := "Banned IP attempted access: 203.0.113.77"; blocked.Reason != want {
				t.Fatalf("reason drifted: %q, want %q", blocked.Reason, want)
			}
			if blocked.Metadata["filter_type"] != "banned" {
				t.Fatalf("the banned tier must ride filter_type, got %+v", blocked.Metadata)
			}
			if blocked.Metadata["ip_address"] != "203.0.113.77" {
				t.Fatalf("the client IP kwarg must ride metadata, got %+v", blocked.Metadata)
			}
			if blocked.HandlerName != MiddlewareHandlerName {
				t.Fatalf("bus events carry the middleware handler name: %+v", blocked)
			}
		})
	}
}

// TestReferenceCloudBlockEvents pins cloud_provider.py's
// _emit_cloud_block_events: the cloud handler's cloud_blocked event
// (handler cloud, provider and network metadata) always rides, and a
// route-tier block adds the block_clouds decorator_violation with the
// checked provider list.
func TestReferenceCloudBlockEvents(t *testing.T) {
	tests := []struct {
		name    string
		route   func(rc *RouteConfig)
		wantSch []string
	}{
		{
			name:    "global tier",
			route:   nil,
			wantSch: []string{EventCloudBlocked},
		},
		{
			name:    "route tier",
			route:   func(rc *RouteConfig) { rc.BlockCloudProviders = []string{"AWS"} },
			wantSch: []string{EventCloudBlocked, EventDecoratorViolation},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, agent := agentConfig(t, func(c *SecurityConfig) {
				c.BlockCloudProviders = []string{"AWS"}
			})
			manager := NewCloudManager()
			manager.installRanges("AWS", cloudTestRangeSet(t, nil, "203.0.113.0/24"), false)
			check := &cloudProviderCheck{cfg: cfg, manager: manager}
			req := newTestRequest(t, func(_ *RequestOptions, state *RequestState) {
				if tt.route != nil {
					state.RouteConfig = &RouteConfig{}
					tt.route(state.RouteConfig)
				}
			})
			if resp := check.Check(req); resp == nil || resp.StatusCode != http.StatusForbidden {
				t.Fatalf("the cloud IP must block with 403, got %+v", resp)
			}
			if len(agent.events) != len(tt.wantSch) {
				t.Fatalf("event schedule drifted: %v", agent.eventTypes())
			}
			cloud := agent.events[0]
			if cloud.EventType != EventCloudBlocked {
				t.Fatalf("first event must be cloud_blocked, got %v", agent.eventTypes())
			}
			if cloud.HandlerName != CloudHandlerName {
				t.Fatalf("cloud_blocked carries the cloud handler name: %+v", cloud)
			}
			if cloud.IPAddress != "203.0.113.9" || cloud.ActionTaken != "request_blocked" {
				t.Fatalf("cloud_blocked envelope drifted: %+v", cloud)
			}
			if want := "IP belongs to blocked cloud provider: AWS"; cloud.Reason != want {
				t.Fatalf("cloud_blocked reason drifted: %q, want %q", cloud.Reason, want)
			}
			if cloud.Metadata["cloud_provider"] != "AWS" || cloud.Metadata["network"] == "" {
				t.Fatalf("cloud_blocked metadata drifted: %+v", cloud.Metadata)
			}
			if len(tt.wantSch) == 2 {
				decorated := agent.events[1]
				if decorated.EventType != EventDecoratorViolation {
					t.Fatalf("route tier must add decorator_violation, got %v", agent.eventTypes())
				}
				if decorated.DecoratorType != "block_clouds" {
					t.Fatalf("decorator_type drifted: %+v", decorated)
				}
				if want := "Cloud provider IP 203.0.113.9 blocked"; decorated.Reason != want {
					t.Fatalf("decorator reason drifted: %q, want %q", decorated.Reason, want)
				}
				providers, _ := decorated.Metadata["blocked_providers"].([]string)
				if len(providers) != 1 || providers[0] != "AWS" {
					t.Fatalf("blocked_providers must carry the checked list: %+v", decorated.Metadata)
				}
				if decorated.Metadata["violation_type"] != "cloud_provider" {
					t.Fatalf("violation_type drifted: %+v", decorated.Metadata)
				}
			}
		})
	}
}

// TestReferenceUserAgentTierEvents pins user_agent.py's tier split: a
// route blocklist reports decorator_violation
// (access_control/user_agent, blocked_user_agent), the global list
// reports user_agent_blocked with the global filter tier; both quote the
// redacted user agent in the reference reason format.
func TestReferenceUserAgentTierEvents(t *testing.T) {
	tests := []struct {
		name          string
		globalList    []string
		routeList     []string
		userAgent     string
		wantType      string
		wantDecorator string
		wantReason    string
		wantMetadata  map[string]any
	}{
		{
			name:         "global tier",
			globalList:   []string{"^curl"},
			userAgent:    "curl/8.0",
			wantType:     EventUserAgentBlocked,
			wantReason:   "User agent 'curl/8.0' in global blocklist",
			wantMetadata: map[string]any{"user_agent": "curl/8.0", "filter_type": "global"},
		},
		{
			name:          "route tier",
			globalList:    []string{"^curl"},
			routeList:     []string{"^badbot"},
			userAgent:     "curl/8.0",
			wantType:      EventDecoratorViolation,
			wantDecorator: "access_control",
			wantReason:    "User agent 'curl/8.0' blocked",
			wantMetadata:  map[string]any{"violation_type": "user_agent", "blocked_user_agent": "curl/8.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, agent := agentConfig(t, func(c *SecurityConfig) {
				c.BlockedUserAgents = tt.globalList
			})
			check := &userAgentCheck{cfg: cfg}
			req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
				opts.Header = map[string]string{"User-Agent": tt.userAgent}
				state.RouteConfig = &RouteConfig{BlockedUserAgents: tt.routeList}
			})
			if resp := check.Check(req); resp == nil || resp.StatusCode != http.StatusForbidden {
				t.Fatalf("the blocked user agent must 403, got %+v", resp)
			}
			if len(agent.events) != 1 {
				t.Fatalf("exactly one event must emit, got %v", agent.eventTypes())
			}
			event := agent.events[0]
			if event.EventType != tt.wantType {
				t.Fatalf("event type drifted: %q, want %q", event.EventType, tt.wantType)
			}
			if tt.wantDecorator != "" && event.DecoratorType != tt.wantDecorator {
				t.Fatalf("decorator_type drifted: %+v", event)
			}
			if event.Reason != tt.wantReason {
				t.Fatalf("reason drifted: %q, want %q", event.Reason, tt.wantReason)
			}
			for key, want := range tt.wantMetadata {
				if event.Metadata[key] != want {
					t.Fatalf("metadata[%q] = %v, want %v (full: %+v)", key, event.Metadata[key], want, event.Metadata)
				}
			}
		})
	}
}

// TestReferenceRateLimitTierEventPayloads pins rate_limit.py's tier
// payloads: the endpoint/route/geo tiers quote the tier's CONFIGURED
// limit (never the tripping count) and the reference reason strings.
func TestReferenceRateLimitTierEventPayloads(t *testing.T) {
	tests := []struct {
		name          string
		outcome       *RateLimitOutcome
		wantType      string
		wantDecorator string
		wantRuleType  string
		wantReason    string
		wantMetadata  map[string]any
	}{
		{
			name:         "endpoint tier quotes the configured limit",
			outcome:      &RateLimitOutcome{Blocked: true, Count: 9, Window: 60, Tier: "endpoint", Limit: 5},
			wantType:     EventDynamicRuleViolation,
			wantRuleType: "endpoint_rate_limit",
			wantReason:   "Endpoint-specific rate limit exceeded: 5 requests per 60s for /api",
			wantMetadata: map[string]any{
				"endpoint":   "/api",
				"rate_limit": 5,
				"window":     60,
			},
		},
		{
			name:          "route tier quotes the configured limit",
			outcome:       &RateLimitOutcome{Blocked: true, Count: 9, Window: 60, Tier: "route", Limit: 4},
			wantType:      EventDecoratorViolation,
			wantDecorator: "rate_limiting",
			wantReason:    "Route-specific rate limit exceeded: 4 requests per 60s",
			wantMetadata: map[string]any{
				"violation_type": "rate_limit",
				"rate_limit":     4,
				"window":         60,
			},
		},
		{
			name:          "geo tier quotes country and configured limit",
			outcome:       &RateLimitOutcome{Blocked: true, Count: 9, Window: 30, Tier: "geo", Limit: 7, Country: "CN"},
			wantType:      EventDecoratorViolation,
			wantDecorator: "geo_rate_limiting",
			wantReason:    "Geo rate limit exceeded for CN: 7 requests per 30s",
			wantMetadata: map[string]any{
				"violation_type": "geo_rate_limit",
				"rate_limit":     7,
				"window":         30,
			},
		},
		{
			name:          "geo tier unknown country",
			outcome:       &RateLimitOutcome{Blocked: true, Count: 9, Window: 30, Tier: "geo", Limit: 7},
			wantType:      EventDecoratorViolation,
			wantDecorator: "geo_rate_limiting",
			wantReason:    "Geo rate limit exceeded for unknown: 7 requests per 30s",
			wantMetadata: map[string]any{
				"violation_type": "geo_rate_limit",
				"rate_limit":     7,
				"window":         30,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, agent := agentConfig(t, nil)
			check := &rateLimitCheck{cfg: cfg}
			req := newTestRequest(t, nil)
			check.emitRateLimitEvent(req, "203.0.113.9", "hook reason stays with the hook", tt.outcome)
			if len(agent.events) != 1 {
				t.Fatalf("exactly one event must emit, got %v", agent.eventTypes())
			}
			event := agent.events[0]
			if event.EventType != tt.wantType {
				t.Fatalf("event type drifted: %q, want %q", event.EventType, tt.wantType)
			}
			if tt.wantDecorator != "" && event.DecoratorType != tt.wantDecorator {
				t.Fatalf("decorator_type drifted: %+v", event)
			}
			if tt.wantRuleType != "" && event.RuleType != tt.wantRuleType {
				t.Fatalf("rule_type drifted: %+v", event)
			}
			if event.Reason != tt.wantReason {
				t.Fatalf("reason drifted: %q, want %q", event.Reason, tt.wantReason)
			}
			for key, want := range tt.wantMetadata {
				if event.Metadata[key] != want {
					t.Fatalf("metadata[%q] = %v, want %v (full: %+v)", key, event.Metadata[key], want, event.Metadata)
				}
			}
		})
	}
}

// TestReferenceRateLimitTierTripsViaEngine drives the endpoint and route
// tiers through the engine so the configured-limit plumbing
// (RateLimitOutcome.Limit) is exercised end to end.
func TestReferenceRateLimitTierTripsViaEngine(t *testing.T) {
	t.Run("endpoint tier", func(t *testing.T) {
		engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
			c.EndpointRateLimits = map[string]RateLimitEntry{"/limited": {Requests: 2, Window: 60}}
		})
		var resp *Response
		for i := 0; i < 3; i++ {
			req := NewRequestFactory().CreateRequest(RequestOptions{
				Path:       "/limited",
				Method:     "GET",
				ClientHost: "203.0.113.90",
			})
			resp = engine.Check(req)
		}
		if resp == nil || resp.StatusCode != RateLimitBlockedStatus {
			t.Fatalf("the endpoint tier must block with 429, got %+v", resp)
		}
		event := findEvent(agent, EventDynamicRuleViolation)
		if event == nil {
			t.Fatalf("dynamic_rule_violation must reach the agent, got %v", agent.eventTypes())
		}
		if want := "Endpoint-specific rate limit exceeded: 2 requests per 60s for /limited"; event.Reason != want {
			t.Fatalf("reason drifted: %q, want %q", event.Reason, want)
		}
		if event.Metadata["rate_limit"] != 2 {
			t.Fatalf("the configured limit must ride, not the tripping count: %+v", event.Metadata)
		}
		if event.Metadata["request_count"] != nil {
			t.Fatalf("the tier events carry no count: %+v", event.Metadata)
		}
	})

	t.Run("route tier", func(t *testing.T) {
		engine, agent := newEventTestEngine(t, nil)
		engine.Routes.Register("/routed", func(rc *RouteConfig) {
			rc.RateLimit = 1
			rc.RateLimitWindow = 60
		})
		var resp *Response
		for i := 0; i < 2; i++ {
			req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
				opts.Path = "/routed"
				state.GuardRouteID = "/routed"
			})
			resp = engine.Check(req)
		}
		if resp == nil || resp.StatusCode != RateLimitBlockedStatus {
			t.Fatalf("the route tier must block with 429, got %+v", resp)
		}
		event := findEvent(agent, EventDecoratorViolation)
		if event == nil {
			t.Fatalf("decorator_violation must reach the agent, got %v", agent.eventTypes())
		}
		if event.DecoratorType != "rate_limiting" {
			t.Fatalf("decorator_type drifted: %+v", event)
		}
		if want := "Route-specific rate limit exceeded: 1 requests per 60s"; event.Reason != want {
			t.Fatalf("reason drifted: %q, want %q", event.Reason, want)
		}
		if event.Metadata["rate_limit"] != 1 || event.Metadata["violation_type"] != "rate_limit" || event.Metadata["window"] != 60 {
			t.Fatalf("route tier metadata drifted: %+v", event.Metadata)
		}
	})
}

func findEvent(agent *recordingAgent, eventType string) *SecurityEvent {
	for i := range agent.events {
		if agent.events[i].EventType == eventType {
			return &agent.events[i]
		}
	}
	return nil
}

// TestDynamicRulesRejectInvalidAutoBanFields pins the reference ge=1
// constraints (_dynamic_rules.py): a delivery whose auto_ban_threshold or
// auto_ban_duration is zero or negative is rejected WHOLE, and the
// previously active rules stay in force.
func TestDynamicRulesRejectInvalidAutoBanFields(t *testing.T) {
	tests := []struct {
		name      string
		threshold *int
		duration  *int
		wantErr   string
	}{
		{name: "zero threshold", threshold: intPtr(0), wantErr: "auto_ban_threshold"},
		{name: "negative threshold", threshold: intPtr(-3), wantErr: "auto_ban_threshold"},
		{name: "zero duration", duration: intPtr(0), wantErr: "auto_ban_duration"},
		{name: "negative duration", duration: intPtr(-1), wantErr: "auto_ban_duration"},
		{name: "boundary ones apply", threshold: intPtr(1), duration: intPtr(1)},
		{name: "absent overrides apply"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _ := dynamicTestConfig(t, nil)
			manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
			if err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
				t.Fatal(err)
			}
			baselineUserAgents := append([]string(nil), cfg.BlockedUserAgents...)

			delivery := sampleRules()
			delivery.RuleID = "rule-2"
			delivery.Version = 4
			delivery.BlockedUserAgents = []string{"newbot[0-9]*"}
			delivery.AutoBanThreshold = tt.threshold
			delivery.AutoBanDuration = tt.duration
			err := manager.UpdateRules(func() (*DynamicRules, error) { return delivery, nil })
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("the delivery must apply: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("the delivery must be rejected with %q, got %v", tt.wantErr, err)
			}
			// The whole delivery is rejected: nothing applied.
			if current := manager.CurrentRules(); current == nil || current.RuleID != "rule-1" {
				t.Fatalf("the previous rules must stay active, got %+v", current)
			}
			if strings.Join(cfg.BlockedUserAgents, ",") != strings.Join(baselineUserAgents, ",") {
				t.Fatalf("a rejected delivery must not touch the config: %v", cfg.BlockedUserAgents)
			}
		})
	}
}

// TestLastKnownSnapshotRejectsInvalidAutoBanFields pins the ge=1 gate on
// the persistence path: an unusable snapshot is skipped like any other
// unparseable payload (the reference revalidates through the model).
func TestLastKnownSnapshotRejectsInvalidAutoBanFields(t *testing.T) {
	zero := 0
	invalid := DumpLastKnownRulesSnapshot(DynamicRules{
		RuleID:           "rule-1",
		Version:          1,
		Timestamp:        time.Now().UTC(),
		AutoBanThreshold: &zero,
	})
	if _, err := LoadLastKnownRulesSnapshot(invalid); err == nil || !strings.Contains(err.Error(), "auto_ban_threshold") {
		t.Fatalf("an out-of-range snapshot must be rejected, got %v", err)
	}
	one := 1
	valid := DumpLastKnownRulesSnapshot(DynamicRules{
		RuleID:           "rule-1",
		Version:          1,
		Timestamp:        time.Now().UTC(),
		AutoBanThreshold: &one,
		AutoBanDuration:  &one,
	})
	if _, err := LoadLastKnownRulesSnapshot(valid); err != nil {
		t.Fatalf("a boundary-valid snapshot must load: %v", err)
	}
}

// TestReferenceEmergencyModeBlockEventReason pins emergency_mode.py's
// event reason, distinct from the log_activity string the hook carries.
func TestReferenceEmergencyModeBlockEventReason(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.EmergencyMode = true
		c.EmergencyWhitelist = []string{"203.0.113.5"}
	})
	req := newTestRequest(t, func(_ *RequestOptions, state *RequestState) {
		state.ClientIP = "203.0.113.9"
	})
	if resp := engine.Check(req); resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("emergency mode must block with 503, got %+v", resp)
	}
	event := findEvent(agent, EventEmergencyModeBlock)
	if event == nil {
		t.Fatalf("emergency_mode_block must reach the agent, got %v", agent.eventTypes())
	}
	if want := "[EMERGENCY MODE] IP 203.0.113.9 not in whitelist"; event.Reason != want {
		t.Fatalf("event reason drifted: %q, want %q", event.Reason, want)
	}
	if event.Metadata["emergency_whitelist_count"] != 1 || event.Metadata["emergency_active"] != true {
		t.Fatalf("emergency metadata drifted: %+v", event.Metadata)
	}
}

// TestReferenceCustomRequestCheckEventPinsFunctionName pins
// custom_request.py's check_function kwarg alongside the response status.
func TestReferenceCustomRequestCheckEventPinsFunctionName(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.CustomRequestCheck = referenceBlocker
	})
	req := newTestRequest(t, nil)
	resp := engine.Check(req)
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the custom check must block, got %+v", resp)
	}
	event := findEvent(agent, EventCustomRequestCheck)
	if event == nil {
		t.Fatalf("custom_request_check must reach the agent, got %v", agent.eventTypes())
	}
	if want := "Custom request check returned blocking response"; event.Reason != want {
		t.Fatalf("reason drifted: %q, want %q", event.Reason, want)
	}
	if event.Metadata["response_status"] != http.StatusForbidden {
		t.Fatalf("response_status drifted: %+v", event.Metadata)
	}
	if event.Metadata["check_function"] != "referenceBlocker" {
		t.Fatalf("check_function must carry the function name: %+v", event.Metadata)
	}
}

// TestReferenceIPBanFailedEventCarriesIP pins helpers.py's
// _emit_ban_escalation_failed payload: action ban_not_applied plus the
// ip_address kwarg.
func TestReferenceIPBanFailedEventCarriesIP(t *testing.T) {
	cfg, agent := agentConfig(t, func(c *SecurityConfig) {
		c.EnableIPBanning = true
		c.AutoBanThreshold = 100
		c.ThreatBanConfig = map[string]ThreatBanEntry{"sqli": {Threshold: 1, Duration: 60}}
	})
	check := &suspiciousActivityCheck{cfg: cfg, ban: NewIPBanManager(nil, nil), counts: &suspiciousCountStore{m: map[string]map[string]int{}}}
	req := newTestRequest(t, nil)
	// An unparseable target fails the ban manager's own validation, the
	// same Ban-error column the reference's escalation failure covers.
	if applied := check.registerViolations(cfg, req, "not-an-ip", []string{"sqli"}); applied {
		t.Fatal("the failed ban must not report applied")
	}
	event := findEvent(agent, EventIPBanFailed)
	if event == nil {
		t.Fatalf("ip_ban_failed must reach the agent, got %v", agent.eventTypes())
	}
	if event.ActionTaken != "ban_not_applied" {
		t.Fatalf("action drifted: %+v", event)
	}
	if !strings.HasPrefix(event.Reason, "Escalation ban failed for not-an-ip:") {
		t.Fatalf("reason drifted: %q", event.Reason)
	}
	if event.Metadata["ip_address"] != "not-an-ip" {
		t.Fatalf("the ip_address kwarg must ride metadata: %+v", event.Metadata)
	}
}
