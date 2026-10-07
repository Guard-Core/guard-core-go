package guardcore

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// capturePackageLog redirects the package default logger for the duration
// of the test (applyModifier reports modifier panics through log.Printf,
// mirroring the reference logger.exception on the factory logger).
func capturePackageLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr); _ = previous })
	return &buf
}

func TestApplyModifierWithoutConfigReturnsIncoming(t *testing.T) {
	resp := &Response{StatusCode: 403, Body: []byte("blocked")}
	if got := applyModifier(nil, resp); got != resp {
		t.Fatal("nil config must return the incoming response")
	}
	if got := applyModifier(&SecurityConfig{}, resp); got != resp {
		t.Fatal("nil modifier must return the incoming response")
	}
}

func TestApplyModifierReplacesResponse(t *testing.T) {
	cfg := testConfig(t)
	cfg.CustomResponseModifier = func(resp *Response) *Response {
		modified := &Response{StatusCode: resp.StatusCode, Body: resp.Body}
		modified.SetHeader("X-Modified", "1")
		return modified
	}
	incoming := &Response{StatusCode: 403, Body: []byte("blocked")}
	got := applyModifier(cfg, incoming)
	if got == incoming {
		t.Fatal("the modifier's result must replace the incoming response")
	}
	if v, ok := got.Headers["X-Modified"]; !ok || v != "1" {
		t.Fatalf("modified headers missing, got %v", got.Headers)
	}
}

func TestApplyModifierNilResultKeepsIncoming(t *testing.T) {
	cfg := testConfig(t)
	cfg.CustomResponseModifier = func(resp *Response) *Response { return nil }
	incoming := &Response{StatusCode: 403, Body: []byte("blocked")}
	if got := applyModifier(cfg, incoming); got != incoming {
		t.Fatal("a nil modifier result must keep the incoming response (never drop a block)")
	}
}

func TestApplyModifierPanicReturnsUnmodified(t *testing.T) {
	buf := capturePackageLog(t)
	cfg := testConfig(t)
	cfg.CustomResponseModifier = func(resp *Response) *Response { panic("boom") }
	incoming := &Response{StatusCode: 403, Body: []byte("blocked")}
	got := applyModifier(cfg, incoming)
	if got != incoming {
		t.Fatal("a panicking modifier must return the unmodified response")
	}
	logged := buf.String()
	if !strings.Contains(logged, "custom_response_modifier raised") ||
		!strings.Contains(logged, "returning unmodified response") ||
		!strings.Contains(logged, "boom") {
		t.Fatalf("panic must be logged with the reference message, got %q", logged)
	}
}

func TestCreateErrorResponseRunsModifier(t *testing.T) {
	cfg := testConfig(t)
	cfg.CustomResponseModifier = func(resp *Response) *Response {
		resp.SetHeader("X-Modifier", "applied")
		return resp
	}
	resp := createErrorResponse(cfg, 403, "Blocked")
	if v := resp.Headers["X-Modifier"]; v != "applied" {
		t.Fatalf("error response must pass through the modifier, got %v", resp.Headers)
	}
	failed := errorResponse(cfg, 500, "Security check failed")
	if v := failed.Headers["X-Modifier"]; v != "applied" {
		t.Fatalf("fail-secure response must pass through the modifier, got %v", failed.Headers)
	}
}

func TestHTTPSRedirectRunsModifier(t *testing.T) {
	cfg := testConfig(t)
	cfg.EnforceHTTPS = true
	cfg.CustomResponseModifier = func(resp *Response) *Response {
		resp.SetHeader("X-Modifier", "redirect")
		return resp
	}
	check := &httpsEnforcementCheck{cfg: cfg}
	resp := check.Check(newTestRequest(t, nil))
	if resp == nil || resp.StatusCode != 301 {
		t.Fatalf("http request must 301, got %+v", resp)
	}
	if resp.Headers["X-Modifier"] != "redirect" {
		t.Fatalf("redirect must pass through the modifier, got %v", resp.Headers)
	}
}

func TestCustomRequestCheckRunsModifier(t *testing.T) {
	cfg := testConfig(t)
	modifierCalls := 0
	cfg.CustomRequestCheck = func(req Request) *Response {
		blocked := &Response{StatusCode: 403, Body: []byte("nope")}
		blocked.SetHeader("X-Custom", "1")
		return blocked
	}
	cfg.CustomResponseModifier = func(resp *Response) *Response {
		modifierCalls++
		resp.SetHeader("X-Modifier", "custom")
		return resp
	}
	check := &customRequestCheck{cfg: cfg}
	resp := check.Check(newTestRequest(t, nil))
	if resp == nil || resp.Headers["X-Modifier"] != "custom" {
		t.Fatalf("custom_request blocking response must pass through the modifier, got %+v", resp)
	}
	if modifierCalls != 1 {
		t.Fatalf("modifier must run exactly once, got %d", modifierCalls)
	}

	passive := testConfig(t)
	passive.PassiveMode = true
	passive.CustomRequestCheck = cfg.CustomRequestCheck
	passive.CustomResponseModifier = cfg.CustomResponseModifier
	passiveCalls := 0
	passive.CustomResponseModifier = func(resp *Response) *Response {
		passiveCalls++
		return resp
	}
	if resp := (&customRequestCheck{cfg: passive}).Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("passive mode must not block, got %+v", resp)
	}
	if passiveCalls != 0 {
		t.Fatalf("passive mode must not run the modifier, got %d calls", passiveCalls)
	}
}

func TestCustomValidatorsResponseSkipsModifier(t *testing.T) {
	cfg := testConfig(t)
	modifierCalls := 0
	cfg.CustomResponseModifier = func(resp *Response) *Response {
		modifierCalls++
		return resp
	}
	registry := NewRouteRegistry()
	registry.Register("/api", func(rc *RouteConfig) {
		rc.CustomValidators = []func(req Request) *Response{
			func(req Request) *Response { return &Response{StatusCode: 403, Body: []byte("validator")} },
		}
	})
	state := &RequestState{GuardRouteID: "/api", RouteConfig: registry.Get("/api")}
	req := newTestRequest(t, nil)
	req.State().GuardRouteID = state.GuardRouteID
	req.State().RouteConfig = state.RouteConfig
	check := &customValidatorsCheck{cfg: cfg, routes: []*RouteConfig{state.RouteConfig}, logger: log.Default()}
	resp := check.Check(req)
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("validator response must block, got %+v", resp)
	}
	if modifierCalls != 0 {
		t.Fatalf("validator responses return as-is without the modifier pass, got %d calls", modifierCalls)
	}
}

func TestEngineModifyResponsePassthroughSeam(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.CustomResponseModifier = func(resp *Response) *Response {
			resp.SetHeader("X-Modifier", "passthrough")
			return resp
		}
	})
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	resp := &Response{StatusCode: 200, Body: []byte("ok")}
	got := engine.ModifyResponse(resp)
	if got.Headers["X-Modifier"] != "passthrough" {
		t.Fatalf("passthrough seam must run the modifier, got %v", got.Headers)
	}
	if v, ok := engine.ResponseHeaders()["X-Modifier"]; ok && v != "passthrough" {
		t.Fatalf("engine header computation must be untouched, got %q", v)
	}
}
