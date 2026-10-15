package guardcore

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestMergeSensitiveLogHeaders(t *testing.T) {
	merged := mergeSensitiveLogHeaders(map[string]bool{"X-Custom-Secret": true})
	for _, name := range []string{"authorization", "proxy-authorization", "cookie", "x-api-key", "x-custom-secret"} {
		if !merged[name] {
			t.Fatalf("expected %q in merged sensitive headers, got %v", name, merged)
		}
	}
	if merged["host"] {
		t.Fatalf("host must not be sensitive")
	}
}

func TestRedactSensitiveHeaders(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer abc123",
		"Cookie":        "session=xyz",
		"X-Custom":      "password=hunter2",
		"Host":          "example.com",
	}
	got := RedactSensitiveHeaders(headers, nil, nil, nil)
	if got["Authorization"] != "[REDACTED]" {
		t.Fatalf("Authorization must be fully masked, got %q", got["Authorization"])
	}
	if got["Cookie"] != "[REDACTED]" {
		t.Fatalf("Cookie must be fully masked, got %q", got["Cookie"])
	}
	if got["X-Custom"] != "password=[REDACTED]" {
		t.Fatalf("sensitive pair inside non-sensitive header value must be masked, got %q", got["X-Custom"])
	}
	if got["Host"] != "example.com" {
		t.Fatalf("non-sensitive header must pass through, got %q", got["Host"])
	}
}

func TestRedactHeaderValueForDisplay(t *testing.T) {
	if got := RedactHeaderValueForDisplay("", nil, nil, nil); got != "" {
		t.Fatalf("empty header value must stay empty, got %q", got)
	}
	got := RedactHeaderValueForDisplay(`{"api_key": "sk-123", "user": "bob"}`, nil, nil, nil)
	want := `{"api_key":"[REDACTED]","user":"bob"}`
	if got != want {
		t.Fatalf("json header redaction: got %q, want %q", got, want)
	}
	got = RedactHeaderValueForDisplay("token=abc123; other=ok", nil, nil, nil)
	if got != "token=[REDACTED]; other=ok" {
		t.Fatalf("pair header redaction: got %q", got)
	}
}

func TestRedactBlobForDisplayJSON(t *testing.T) {
	got := RedactBlobForDisplay(`{"password":"p","nested":{"token":"t","keep":1}}`, nil, nil, nil)
	want := `{"nested":{"keep":1,"token":"[REDACTED]"},"password":"[REDACTED]"}`
	if got != want {
		t.Fatalf("nested json redaction: got %q, want %q", got, want)
	}
	got = RedactBlobForDisplay(`[{"apikey":"k"},{"clean":true}]`, nil, nil, nil)
	want = `[{"apikey":"[REDACTED]"},{"clean":true}]`
	if got != want {
		t.Fatalf("json array redaction: got %q, want %q", got, want)
	}
	if got := RedactBlobForDisplay(`{"clean": 1}`, nil, nil, nil); got != `{"clean": 1}` {
		t.Fatalf("unchanged json must pass through verbatim, got %q", got)
	}
}

func TestRedactBlobForDisplayXMLEnabledAndParams(t *testing.T) {
	got := RedactBlobForDisplay("<password>hunter2</password><user>bob</user>", nil, nil, nil)
	want := "<password>[REDACTED]</password><user>bob</user>"
	if got != want {
		t.Fatalf("xml redaction: got %q, want %q", got, want)
	}
	got = RedactBlobForDisplay("q=secret&safe=1", map[string]bool{"q": true}, nil, nil)
	if got != "q=[REDACTED]&safe=1" {
		t.Fatalf("param pair redaction: got %q", got)
	}
}

func TestRedactURLForDisplay(t *testing.T) {
	cfg := map[string]bool{"api_key": true}
	got := RedactURLForDisplay("https://user:secretpw@example.com/api?api_key=k123&page=2", cfg, nil, nil)
	want := "https://user:[REDACTED]@example.com/api?api_key=%5BREDACTED%5D&page=2"
	if got != want {
		t.Fatalf("url redaction: got %q, want %q", got, want)
	}
	if got := RedactURLForDisplay("https://example.com/clean/path", cfg, nil, nil); got != "https://example.com/clean/path" {
		t.Fatalf("clean url must be returned verbatim, got %q", got)
	}
}

func captureLogger(buf *bytes.Buffer) *log.Logger {
	return log.New(buf, "", 0)
}

func TestLogActivityRequestLine(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Header = map[string]string{"Authorization": "Bearer z", "Accept": "text/html"}
		opts.RawQuery = "api_key=k"
	})
	LogActivity(req, LogOptions{
		Logger:         captureLogger(&buf),
		LogType:        "request",
		Level:          "INFO",
		CheckName:      "request_logging",
		MutedCheckLogs: map[string]bool{},
	})
	out := buf.String()
	if !strings.HasPrefix(out, "Request from 203.0.113.9: GET http://example.com/api?api_key=") {
		t.Fatalf("unexpected request line: %q", out)
	}
	if !strings.Contains(out, "api_key=%5BREDACTED%5D") {
		t.Fatalf("sensitive param must be redacted in url: %q", out)
	}
	if !strings.Contains(out, "authorization=[REDACTED]") || !strings.Contains(out, "accept=text/html") {
		t.Fatalf("headers must be redacted selectively: %q", out)
	}
}

func TestLogActivityMutedCheckSuppressed(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, nil)
	LogActivity(req, LogOptions{
		Logger:         captureLogger(&buf),
		LogType:        "request",
		Level:          "WARNING",
		CheckName:      "request_logging",
		MutedCheckLogs: map[string]bool{"request_logging": true},
	})
	if buf.Len() != 0 {
		t.Fatalf("muted check log must be suppressed, got %q", buf.String())
	}
}

func TestLogActivityEmptyLevelNoOutput(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, nil)
	LogActivity(req, LogOptions{Logger: captureLogger(&buf), LogType: "request", Level: ""})
	if buf.Len() != 0 {
		t.Fatalf("empty level must skip logging, got %q", buf.String())
	}
}

func TestLogActivitySuspiciousNonPassiveStashes(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, nil)
	fired := false
	LogActivity(req, LogOptions{
		Logger:      captureLogger(&buf),
		LogType:     "suspicious",
		Reason:      "Custom validation failed",
		TriggerInfo: "custom_validation",
		Level:       "WARNING",
		PassiveMode: false,
		CheckName:   "custom_validators",
		OnBlock:     func(req Request, payload map[string]any) { fired = true },
	})
	if fired {
		t.Fatalf("non-passive suspicious log must stash, not fire the hook")
	}
	stash := req.State().BlockStash
	if stash == nil || stash.Reason != "Custom validation failed" || stash.TriggerInfo != "custom_validation" {
		t.Fatalf("block stash not written: %+v", stash)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "Suspicious activity detected from 203.0.113.9: GET http://example.com/api") {
		t.Fatalf("unexpected suspicious line: %q", out)
	}
	if !strings.Contains(out, "Reason: Custom validation failed") {
		t.Fatalf("suspicious line must carry the reason: %q", out)
	}
}

func TestLogActivitySuspiciousPassiveFiresHookAndLogsPassiveShape(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, nil)
	var payload map[string]any
	LogActivity(req, LogOptions{
		Logger:      captureLogger(&buf),
		LogType:     "suspicious",
		Reason:      "Custom validation failed",
		TriggerInfo: "custom_validation",
		Level:       "WARNING",
		PassiveMode: true,
		CheckName:   "suspicious_activity",
		OnBlock: func(req Request, p map[string]any) {
			payload = p
			payload["ignored"] = nil
		},
	})
	if payload == nil || payload["check_name"] != "suspicious_activity" || payload["passive_mode"] != true {
		t.Fatalf("passive mode must fire the hook with payload, got %v", payload)
	}
	if req.State().BlockStash != nil {
		t.Fatalf("passive mode must not stash")
	}
	out := buf.String()
	if !strings.HasPrefix(out, "[PASSIVE MODE] Penetration attempt detected from") {
		t.Fatalf("passive suspicious line shape: %q", out)
	}
	if !strings.Contains(out, "Trigger: custom_validation") {
		t.Fatalf("passive suspicious line must carry trigger: %q", out)
	}
}

func TestLogActivityPassiveSuspiciousWithoutTriggerKeepsReason(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, nil)
	LogActivity(req, LogOptions{
		Logger:      captureLogger(&buf),
		LogType:     "suspicious",
		Reason:      "Rate limit exceeded for IP: 203.0.113.9",
		Level:       "WARNING",
		PassiveMode: true,
	})
	out := buf.String()
	if !strings.HasPrefix(out, "[PASSIVE MODE] Suspicious activity detected from") || strings.Contains(out, "Penetration attempt") {
		t.Fatalf("passive line without trigger must not claim a penetration attempt: %q", out)
	}
	if !strings.Contains(out, "Reason: Rate limit exceeded for IP: 203.0.113.9 - Headers:") || strings.Contains(out, "Trigger:") {
		t.Fatalf("passive line without trigger must carry the reason: %q", out)
	}
}

func TestLogActivityGenericShape(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, nil)
	LogActivity(req, LogOptions{Logger: captureLogger(&buf), LogType: "debug", Reason: "why", Level: "DEBUG"})
	if got := buf.String(); !strings.HasPrefix(got, "Debug from 203.0.113.9: GET http://example.com/api - Details: why") {
		t.Fatalf("generic line shape: %q", got)
	}
}
