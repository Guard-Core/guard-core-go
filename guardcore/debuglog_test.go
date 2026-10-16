package guardcore

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
)

type blockingStubCheck struct{}

func (blockingStubCheck) CheckName() string              { return "stub_check" }
func (blockingStubCheck) AppliesTo(*SecurityConfig) bool { return true }
func (blockingStubCheck) EnforcedOnExcludedPaths() bool  { return false }
func (blockingStubCheck) Check(Request) *Response {
	return NewResponseFactory().CreateResponse("no", 403)
}

// emitDebugLines drives every spec-DEBUG emit site once.
func emitDebugLines(t *testing.T, muted map[string]bool) {
	t.Helper()
	cfg := testConfig(t)
	for _, resultType := range []string{"no_rules", "no_geolocation", "loopback_exempt"} {
		logCountryCheckResult(cfg, resultType, "203.0.113.9", "")
	}
	cfg.MutedCheckLogs = muted
	p := NewSecurityCheckPipeline([]SecurityCheck{blockingStubCheck{}}, cfg, nil)
	if resp := p.Execute(newTestRequest(t, nil)); resp == nil {
		t.Fatal("the stub check must block")
	}
	handleUntrustedProxy(cfg, newTestRequest(t, nil), "10.0.0.1", "10.0.0.1", "203.0.113.99")
}

// Spec 02-config (country verdicts) and 03-pipeline (blocked-by) mandate DEBUG:
// hidden at the default slog level, shown after slog.SetLogLoggerLevel(Debug).
func TestSpecDebugLogsFollowSlogLevel(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	prev := slog.SetLogLoggerLevel(slog.LevelInfo)
	t.Cleanup(func() { log.SetOutput(os.Stderr); slog.SetLogLoggerLevel(prev) })

	emitDebugLines(t, map[string]bool{})
	if out := buf.String(); strings.Contains(out, "No countries blocked") || strings.Contains(out, "Request blocked by") ||
		strings.Contains(out, "Potential IP spoof") || strings.Contains(out, "geolocat") || strings.Contains(out, "Loopback") {
		t.Fatalf("debug lines must be hidden at the default level, got %q", out)
	}

	slog.SetLogLoggerLevel(slog.LevelDebug)
	buf.Reset()
	emitDebugLines(t, map[string]bool{})
	out := buf.String()
	for _, want := range []string{
		"DEBUG No countries blocked or whitelisted 203.0.113.9",
		"DEBUG IP not geolocated 203.0.113.9 - IP geolocation failed",
		"DEBUG Loopback IP exempt from country allowlist check 203.0.113.9",
		"DEBUG Request blocked by stub_check check=stub_check path=",
		"method=",
		"DEBUG Potential IP spoof attempt: X-Forwarded-For header 203.0.113.99",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}

	buf.Reset()
	emitDebugLines(t, map[string]bool{"stub_check": true})
	if strings.Contains(buf.String(), "Request blocked by") {
		t.Fatalf("muted_check_logs must still silence the blocked-by line, got %q", buf.String())
	}
}
