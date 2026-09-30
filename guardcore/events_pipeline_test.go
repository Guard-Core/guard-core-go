package guardcore

import (
	"net/http"
	"testing"
)

// newEventTestEngine builds a real Engine over a recording agent so the
// wiring (bus seams, stage emits, metrics) is observable end to end.
func newEventTestEngine(t *testing.T, mutate func(*SecurityConfig)) (*Engine, *recordingAgent) {
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
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return engine, agent
}

func TestEngineBlockedRequestEmitsMiddlewareEvent(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.BlockedUserAgents = []string{"^badbot"}
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:   "/api",
		Method: "GET",
		Header: map[string]string{"User-Agent": "badbot/1.0"},
	})
	resp := engine.Check(req)
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the bad user agent must block with 403, got %+v", resp)
	}
	found := false
	for _, event := range agent.events {
		if event.EventType == EventUserAgentBlocked {
			found = true
			if event.ActionTaken != "request_blocked" {
				t.Fatalf("action drifted: %+v", event)
			}
			if event.HandlerName != MiddlewareHandlerName {
				t.Fatalf("middleware events carry the middleware handler name: %+v", event)
			}
			if event.Metadata["filter_type"] != "global" {
				t.Fatalf("filter_type drifted: %+v", event.Metadata)
			}
		}
	}
	if !found {
		t.Fatalf("user_agent_blocked must reach the agent, got %v", agent.eventTypes())
	}
}

func TestEngineBanEmitsIPBanned(t *testing.T) {
	engine, agent := newEventTestEngine(t, nil)
	applied, err := engine.Ban.Ban("203.0.113.77", 120, "test-ban")
	if err != nil || !applied {
		t.Fatalf("ban failed: %v %v", applied, err)
	}
	found := false
	for _, event := range agent.events {
		if event.EventType == EventIPBanned {
			found = true
			if event.IPAddress != "203.0.113.77" || event.ActionTaken != "banned" {
				t.Fatalf("ban event envelope drifted: %+v", event)
			}
			if event.HandlerName != IPBanHandlerName {
				t.Fatalf("handler name drifted: %+v", event)
			}
			if event.Metadata["duration"] != 120 {
				t.Fatalf("duration metadata drifted: %+v", event.Metadata)
			}
		}
	}
	if !found {
		t.Fatalf("ip_banned must reach the agent, got %v", agent.eventTypes())
	}
	if err := engine.Ban.Unban("203.0.113.77"); err != nil {
		t.Fatal(err)
	}
	found = false
	for _, event := range agent.events {
		if event.EventType == EventIPUnbanned {
			found = true
			if event.Reason != "dynamic_rule_whitelist" {
				t.Fatalf("unban reason drifted: %+v", event)
			}
		}
	}
	if !found {
		t.Fatalf("ip_unbanned must reach the agent, got %v", agent.eventTypes())
	}
}

func TestEngineRateLimitBlockEmitsRateLimited(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.RateLimit = 1
		c.RateLimitWindow = 60
	})
	for i := 0; i < 2; i++ {
		req := NewRequestFactory().CreateRequest(RequestOptions{
			Path:       "/limited",
			Method:     "GET",
			ClientHost: "203.0.113.90",
		})
		engine.Check(req)
	}
	found := false
	for _, event := range agent.events {
		if event.EventType == EventRateLimited {
			found = true
			if event.HandlerName != RateLimitHandlerName {
				t.Fatalf("rate_limited carries the rate_limit handler name: %+v", event)
			}
			if event.Metadata["request_count"] == nil || event.Metadata["rate_limit"] != 1 {
				t.Fatalf("rate_limited metadata drifted: %+v", event.Metadata)
			}
		}
	}
	if !found {
		t.Fatalf("rate_limited must reach the agent, got %v", agent.eventTypes())
	}
}

func TestEngineHTTPSRedirectEmitsEnforced(t *testing.T) {
	engine, agent := newEventTestEngine(t, func(c *SecurityConfig) {
		c.EnforceHTTPS = true
	})
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:   "/secure",
		Method: "GET",
		Scheme: "http",
	})
	resp := engine.Check(req)
	if resp == nil || resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("http must redirect, got %+v", resp)
	}
	found := false
	for _, event := range agent.events {
		if event.EventType == EventHTTPSEnforced {
			found = true
			if event.ActionTaken != "https_redirect" {
				t.Fatalf("action drifted: %+v", event)
			}
		}
	}
	if !found {
		t.Fatalf("https_enforced must reach the agent, got %v", agent.eventTypes())
	}
}

func TestEngineSuspiciousBlockEmitsPenetrationAttempt(t *testing.T) {
	engine, agent := newEventTestEngine(t, nil)
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/probe",
		Method:     "GET",
		ClientHost: "203.0.113.101",
		Header:     map[string]string{"X-Evil": "; cat /etc/passwd"},
	})
	resp := engine.Check(req)
	if resp == nil {
		t.Fatal("the traversal payload must block")
	}
	found := false
	for _, event := range agent.events {
		if event.EventType == EventPenetrationAttempt {
			found = true
			if event.ActionTaken != "request_blocked" {
				t.Fatalf("action drifted: %+v", event)
			}
			if _, ok := event.Metadata["request_count"]; !ok {
				t.Fatalf("penetration_attempt carries the request count: %+v", event.Metadata)
			}
		}
	}
	if !found {
		t.Fatalf("penetration_attempt must reach the agent, got %v", agent.eventTypes())
	}
}

func TestEngineProcessResponseCollectsMetrics(t *testing.T) {
	engine, agent := newEventTestEngine(t, nil)
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:   "/metrics",
		Method: "GET",
	})
	if resp := engine.Check(req); resp != nil {
		t.Fatal("a benign request passes")
	}
	engine.ProcessResponse(req, &Response{StatusCode: 200})
	if len(agent.metrics) < 2 {
		t.Fatalf("response_time and request_count must collect, got %d", len(agent.metrics))
	}
	if agent.metrics[0].MetricType != MetricResponseTime || agent.metrics[1].MetricType != MetricRequestCount {
		t.Fatalf("metric order drifted: %+v", agent.metrics)
	}
	foundErrorRate := false
	for _, metric := range agent.metrics {
		if metric.MetricType == MetricErrorRate {
			foundErrorRate = true
		}
	}
	if foundErrorRate {
		t.Fatal("a 200 response must not emit error_rate")
	}
}

func TestFireGeoEventForwardsThroughBusAndHook(t *testing.T) {
	agent := &recordingAgent{}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.AgentHandler = agent
	})
	if err != nil {
		t.Fatal(err)
	}
	hooked := 0
	cfg.OnGeoEvent = func(GeoEvent) { hooked++ }
	cfg.installAgentStream()
	fireGeoEvent(cfg, GeoEvent{
		EventType:   EventCountryBlocked,
		IPAddress:   "203.0.113.55",
		ActionTaken: "request_blocked",
		Reason:      "Country CN is blocked",
		Country:     "CN",
		RuleType:    "country_blacklist",
		HandlerName: IPInfoHandlerName,
	})
	if hooked != 1 {
		t.Fatalf("the OnGeoEvent hook must still fire: %d", hooked)
	}
	if len(agent.events) != 1 {
		t.Fatalf("the geo family must forward through the bus, got %v", agent.eventTypes())
	}
	event := agent.events[0]
	if event.EventType != EventCountryBlocked || event.HandlerName != IPInfoHandlerName {
		t.Fatalf("forwarded envelope drifted: %+v", event)
	}
	if event.Metadata["country"] != "CN" || event.Metadata["rule_type"] != "country_blacklist" {
		t.Fatalf("forwarded metadata drifted: %+v", event.Metadata)
	}
}

func TestEngineCloseStopsDynamicLoop(t *testing.T) {
	engine, _ := newEventTestEngine(t, func(c *SecurityConfig) {
		c.EnableDynamicRules = true
	})
	if engine.DynamicRules == nil {
		t.Fatal("the dynamic rule manager must exist when enable_dynamic_rules is set")
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	// Double close: the manager's stop is once-only and the engine must
	// tolerate it.
	if err := engine.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
}
