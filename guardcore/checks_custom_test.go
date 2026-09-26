package guardcore

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
)

func TestRequestLoggingCheckAppliesTo(t *testing.T) {
	cfg := testConfig(t)
	check := &requestLoggingCheck{cfg: cfg}
	if check.AppliesTo(cfg) {
		t.Fatalf("request_logging must not apply without log_request_level")
	}
	cfg.LogRequestLevel = "INFO"
	if !check.AppliesTo(cfg) {
		t.Fatalf("request_logging must apply when log_request_level is set")
	}
	if check.CheckName() != "request_logging" || check.EnforcedOnExcludedPaths() {
		t.Fatalf("unexpected check metadata")
	}
}

func TestRequestLoggingCheckLogsAndAllows(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	cfg := testConfig(t)
	cfg.LogRequestLevel = "DEBUG"
	cfg.LogSensitiveParams = map[string]bool{"token": true}
	cfg.MutedCheckLogs = map[string]bool{}
	check := &requestLoggingCheck{cfg: cfg, logger: logger}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.RawQuery = "token=t&x=1"
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("request_logging must never block, got %+v", resp)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "Request from 203.0.113.9") {
		t.Fatalf("unexpected log line %q", out)
	}
	if !strings.Contains(out, "token=%5BREDACTED%5D") || !strings.Contains(out, "x=1") {
		t.Fatalf("sensitive param must be redacted: %q", out)
	}
}

func TestRequestLoggingCheckMuted(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	cfg := testConfig(t)
	cfg.LogRequestLevel = "INFO"
	cfg.MutedCheckLogs = map[string]bool{"request_logging": true}
	check := &requestLoggingCheck{cfg: cfg, logger: logger}
	check.Check(newTestRequest(t, nil))
	if buf.Len() != 0 {
		t.Fatalf("muted request_logging must not log: %q", buf.String())
	}
}

func TestCustomValidatorsAppliesTo(t *testing.T) {
	cfg := testConfig(t)
	if (&customValidatorsCheck{cfg: cfg}).AppliesTo(cfg) {
		t.Fatalf("custom_validators must not apply without route validators")
	}
	routes := []*RouteConfig{{}, {CustomValidators: []func(req Request) *Response{func(req Request) *Response { return nil }}}}
	if !customValidatorsApplies(routes) {
		t.Fatalf("custom_validators must apply when any route carries validators")
	}
}

func TestCustomValidatorsCheckPassAndNoRoute(t *testing.T) {
	cfg := testConfig(t)
	check := &customValidatorsCheck{cfg: cfg}
	calls := 0
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{CustomValidators: []func(req Request) *Response{
			func(req Request) *Response { calls++; return nil },
		}}
	})
	if resp := check.Check(req); resp != nil || calls != 1 {
		t.Fatalf("passing validator must allow (calls=%d resp=%+v)", calls, resp)
	}
	if resp := check.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("no route config must allow, got %+v", resp)
	}
}

func TestCustomValidatorsCheckFailBlocks(t *testing.T) {
	var buf bytes.Buffer
	cfg := testConfig(t)
	cfg.OnBlock = nil
	validatorResp := &Response{StatusCode: 418, Body: []byte("nope")}
	hookPayloads := []map[string]any{}
	cfg.OnBlock = func(req Request, payload map[string]any) { hookPayloads = append(hookPayloads, payload) }
	check := &customValidatorsCheck{cfg: cfg, logger: log.New(&buf, "", 0)}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{CustomValidators: []func(req Request) *Response{
			func(req Request) *Response { return nil },
			func(req Request) *Response { return validatorResp },
		}}
	})
	resp := check.Check(req)
	if resp != validatorResp {
		t.Fatalf("validator response must pass through raw, got %+v", resp)
	}
	if !strings.Contains(buf.String(), "Suspicious activity detected from") || !strings.Contains(buf.String(), "Reason: Custom validation failed") {
		t.Fatalf("failure must log suspicious: %q", buf.String())
	}
	if len(hookPayloads) != 0 {
		t.Fatalf("on_block must NOT fire for custom_validators (ON_BLOCK_EXCLUDED_CHECK_NAMES): %v", hookPayloads)
	}
	stash := req.State().BlockStash
	if stash == nil || stash.Reason != "Custom validation failed" || stash.TriggerInfo != "" {
		t.Fatalf("block stash must be set: %+v", stash)
	}
}

func TestCustomValidatorsCheckPassiveMode(t *testing.T) {
	var buf bytes.Buffer
	cfg := testConfig(t)
	cfg.PassiveMode = true
	hookFired := false
	cfg.OnBlock = func(req Request, payload map[string]any) {
		hookFired = true
	}
	check := &customValidatorsCheck{cfg: cfg, logger: log.New(&buf, "", 0)}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{CustomValidators: []func(req Request) *Response{
			func(req Request) *Response { return &Response{StatusCode: 403} },
		}}
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("passive mode must not block, got %+v", resp)
	}
	if hookFired {
		t.Fatalf("passive hook must stay suppressed for custom_validators (ON_BLOCK_EXCLUDED_CHECK_NAMES)")
	}
	if !strings.Contains(buf.String(), "[PASSIVE MODE] Penetration attempt detected from") {
		t.Fatalf("passive suspicious log shape: %q", buf.String())
	}
	if req.State().BlockStash != nil {
		t.Fatalf("passive mode must not stash")
	}
}

func TestCustomRequestCheckVerdicts(t *testing.T) {
	cfg := testConfig(t)
	check := &customRequestCheck{cfg: cfg}
	if resp := check.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("nil verdict must allow, got %+v", resp)
	}
	blocking := &Response{StatusCode: 403, Body: []byte("custom denial")}
	cfg.CustomRequestCheck = func(req Request) *Response { return blocking }
	if resp := check.Check(newTestRequest(t, nil)); resp != blocking {
		t.Fatalf("blocking verdict must pass through, got %+v", resp)
	}
	cfg.PassiveMode = true
	if resp := check.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("passive mode must allow despite blocking verdict, got %+v", resp)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("custom_request_check must be accepted: %v", err)
	}
}

func TestCustomRequestCheckAppliesTo(t *testing.T) {
	cfg := testConfig(t)
	check := &customRequestCheck{cfg: cfg}
	if check.AppliesTo(cfg) {
		t.Fatalf("custom_request must not apply without a callback")
	}
	cfg.CustomRequestCheck = func(req Request) *Response { return nil }
	if !check.AppliesTo(cfg) {
		t.Fatalf("custom_request must apply with a callback")
	}
}

func pipelineWithManagers(t *testing.T, cfg *SecurityConfig, registry *RouteRegistry) *SecurityCheckPipeline {
	t.Helper()
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, registry)
	return pipeline
}

func TestCustomRequestPipelineLevel(t *testing.T) {
	cfg := testConfig(t)
	blocking := &Response{StatusCode: 403, Body: []byte("custom denial")}
	cfg.CustomRequestCheck = func(req Request) *Response { return blocking }
	pipeline := pipelineWithManagers(t, cfg, nil)
	names := pipeline.CheckNames()
	if names[len(names)-1] != "custom_request" {
		t.Fatalf("custom_request must be the last slot, got %v", names)
	}
	resp := pipeline.Execute(newTestRequest(t, nil))
	if resp != blocking {
		t.Fatalf("pipeline must return the custom response, got %+v", resp)
	}
}

func TestCustomRequestPipelinePassive(t *testing.T) {
	cfg := testConfig(t)
	cfg.PassiveMode = true
	cfg.CustomRequestCheck = func(req Request) *Response { return &Response{StatusCode: 403} }
	pipeline := pipelineWithManagers(t, cfg, nil)
	if resp := pipeline.Execute(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("passive custom_request must allow, got %+v", resp)
	}
}

func TestRequestLoggingPipelineSlot(t *testing.T) {
	cfg := testConfig(t)
	cfg.LogRequestLevel = "INFO"
	pipeline := pipelineWithManagers(t, cfg, nil)
	names := pipeline.CheckNames()
	want := []string{"route_config", "request_logging", "ip_security", "rate_limit", "suspicious_activity"}
	if len(names) != len(want) {
		t.Fatalf("unexpected pipeline composition, got %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("request_logging must occupy slot 4, got %v", names)
		}
	}
	if resp := pipeline.Execute(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("request_logging must never block, got %+v", resp)
	}
}

func TestCustomValidatorsPipelineLevel(t *testing.T) {
	cfg := testConfig(t)
	cfg.OnBlock = nil
	registry := NewRouteRegistry()
	registry.Register("/api", func(rc *RouteConfig) {
		rc.CustomValidators = []func(req Request) *Response{
			func(req Request) *Response { return &Response{StatusCode: 403, Body: []byte("validator denied")} },
		}
	})
	pipeline := pipelineWithManagers(t, cfg, registry)
	found := false
	for _, name := range pipeline.CheckNames() {
		if name == "custom_validators" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom_validators must be in the pipeline, got %v", pipeline.CheckNames())
	}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.GuardRouteID = "/api" })
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != "validator denied" {
		t.Fatalf("pipeline must short-circuit with the raw validator response, got %+v", resp)
	}
}

func TestCustomValidatorsPipelineStashNotFiredToHook(t *testing.T) {
	cfg := testConfig(t)
	var reasons []string
	cfg.OnBlock = func(req Request, payload map[string]any) {
		if reason, ok := payload["reason"].(string); ok {
			reasons = append(reasons, reason)
		}
	}
	registry := NewRouteRegistry()
	registry.Register("/api", func(rc *RouteConfig) {
		rc.CustomValidators = []func(req Request) *Response{
			func(req Request) *Response { return &Response{StatusCode: 403} },
		}
	})
	pipeline := pipelineWithManagers(t, cfg, registry)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.GuardRouteID = "/api" })
	if resp := pipeline.Execute(req); resp == nil {
		t.Fatalf("expected block")
	}
	if len(reasons) != 0 {
		t.Fatalf("on_block must not fire for custom_validators (ON_BLOCK_EXCLUDED_CHECK_NAMES): %v", reasons)
	}
	stash := req.State().BlockStash
	if stash == nil || stash.Reason != "Custom validation failed" {
		t.Fatalf("block stash must still be set: %+v", stash)
	}
}

func TestCustomValidatorsValidatorPanicFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	registry := NewRouteRegistry()
	registry.Register("/api", func(rc *RouteConfig) {
		rc.CustomValidators = []func(req Request) *Response{
			func(req Request) *Response { panic(errors.New("boom")) },
		}
	})
	pipeline := pipelineWithManagers(t, cfg, registry)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) { state.GuardRouteID = "/api" })
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 500 {
		t.Fatalf("fail-secure must turn validator panics into a 500, got %+v", resp)
	}
}

func TestLogSuspiciousLevelDefaultAndValidation(t *testing.T) {
	cfg := testConfig(t)
	if cfg.LogSuspiciousLevel != "WARNING" {
		t.Fatalf("log_suspicious_level default must be WARNING, got %q", cfg.LogSuspiciousLevel)
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.LogSuspiciousLevel = "NOPE" }); err == nil {
		t.Fatalf("invalid log_suspicious_level must be rejected")
	}
	cfg2, err := NewSecurityConfig(func(c *SecurityConfig) { c.LogSuspiciousLevel = "error" })
	if err != nil {
		t.Fatalf("lowercase level must be normalized: %v", err)
	}
	if cfg2.LogSuspiciousLevel != "ERROR" {
		t.Fatalf("level must be normalized, got %q", cfg2.LogSuspiciousLevel)
	}
}
