package guardcore

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withJSONTestLogging swaps the console sink for a buffer and restores
// the standard logging state afterwards.
func withJSONTestLogging(t *testing.T) *strings.Builder {
	t.Helper()
	var console strings.Builder
	oldConsole := customLogConsole
	customLogConsole = &console
	t.Cleanup(func() {
		restoreStandardLogging()
		customLogConsole = oldConsole
	})
	return &console
}

// TestJsonFormatterShape pins the reference JsonFormatter record: the
// four columns, JSON encoded.
func TestJsonFormatterShape(t *testing.T) {
	line := JsonFormatter{}.Format("Suspicious activity detected")
	var decoded map[string]string
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("the record must be a JSON object: %v", err)
	}
	if len(decoded) != 4 {
		t.Fatalf("record must carry exactly timestamp/level/logger/message: %v", decoded)
	}
	if decoded["level"] != "INFO" || decoded["logger"] != guardLoggerName {
		t.Fatalf("level/logger drifted: %v", decoded)
	}
	if decoded["message"] != "Suspicious activity detected" {
		t.Fatalf("message drifted: %v", decoded)
	}
	if !strings.Contains(decoded["timestamp"], ":") {
		t.Fatalf("timestamp must keep the asctime shape: %v", decoded)
	}
}

// TestTextFormatRecord pins the reference text line.
func TestTextFormatRecord(t *testing.T) {
	got := textFormatRecord("2026-10-06 12:00:00.123", "INFO", guardLoggerName, "hello")
	want := "[guardcore] 2026-10-06 12:00:00.123 - INFO - hello"
	if got != want {
		t.Fatalf("text line drifted: %q, want %q", got, want)
	}
}

// TestSetupCustomLoggingJSON drives the whole stream in json format: the
// console and the file each see one JSON record per log call, and a
// second call replaces the handlers instead of stacking them.
func TestSetupCustomLoggingJSON(t *testing.T) {
	console := withJSONTestLogging(t)
	logFile := filepath.Join(t.TempDir(), "nested", "dir", "guard.log")

	logger := SetupCustomLogging(logFile, "json")
	if logger == nil {
		t.Fatal("the logger must come back")
	}
	logger.Print("first structured record")

	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("the file sink must exist (directories created): %v", err)
	}
	fileLines := nonEmptyLines(string(raw))
	if len(fileLines) != 1 {
		t.Fatalf("the file must hold one record, got %d: %q", len(fileLines), string(raw))
	}
	consoleLines := nonEmptyLines(console.String())
	if len(consoleLines) != 1 {
		t.Fatalf("the console must hold one record, got %d: %q", len(consoleLines), console.String())
	}
	for _, line := range append(append([]string{}, fileLines...), consoleLines...) {
		var record map[string]string
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("each record must be JSON: %v (%q)", err, line)
		}
		if record["message"] != "first structured record" {
			t.Fatalf("message drifted: %v", record)
		}
	}

	// A second setup replaces the handlers: still one record per call.
	SetupCustomLogging(logFile, "json")
	logger.Print("second structured record")
	raw, err = os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("reread: %v", err)
	}
	if got := len(nonEmptyLines(string(raw))); got != 2 {
		t.Fatalf("handler replacement must not stack sinks, got %d records: %q", got, string(raw))
	}
}

// TestSetupCustomLoggingText pins the default text stream.
func TestSetupCustomLoggingText(t *testing.T) {
	console := withJSONTestLogging(t)
	SetupCustomLogging("", "text")
	log.Default().Print("plain record")
	lines := nonEmptyLines(console.String())
	if len(lines) != 1 {
		t.Fatalf("one console record expected, got %q", console.String())
	}
	if !strings.HasPrefix(lines[0], "[guardcore] ") || !strings.Contains(lines[0], " - INFO - plain record") {
		t.Fatalf("text record drifted: %q", lines[0])
	}
}

// TestSetupCustomLoggingUnwritableFileFallsBackToConsole: a failing file
// path warns and keeps the console stream (the reference logs the
// failure and continues).
func TestSetupCustomLoggingUnwritableFileFallsBackToConsole(t *testing.T) {
	console := withJSONTestLogging(t)
	// A file path under a regular file (not a directory) cannot be
	// created.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	SetupCustomLogging(filepath.Join(blocker, "child", "guard.log"), "json")
	log.Default().Print("console-only record")
	if !strings.Contains(console.String(), "console-only record") {
		t.Fatalf("the console must keep streaming: %q", console.String())
	}
}

// TestLogFormatConfigValidation pins the config switch.
func TestLogFormatConfigValidation(t *testing.T) {
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.LogFormat = "xml" }); err == nil {
		t.Fatal("an unknown log_format must fail validation")
	}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.LogFormat = "JSON" })
	if err != nil {
		t.Fatalf("case-insensitive json must validate: %v", err)
	}
	if cfg.LogFormat != "json" {
		t.Fatalf("log_format must normalize, got %q", cfg.LogFormat)
	}
	def := DefaultSecurityConfig()
	if def.LogFormat != "text" {
		t.Fatalf("the default log_format is text, got %q", def.LogFormat)
	}
}

// TestNewEngineInstallsStructuredLogging proves the config switch shapes
// the engine's own log output: an engine-side warning lands in the file
// as a JSON record.
func TestNewEngineInstallsStructuredLogging(t *testing.T) {
	withJSONTestLogging(t)
	logFile := filepath.Join(t.TempDir(), "logs", "engine.log")

	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.LogFormat = "json"
		c.LogFile = logFile
		// An agentless dynamic-rule engine logs the idle-loop warning
		// through the package default logger during Initialize.
		c.EnableDynamicRules = true
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	engine.Close()

	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("the engine log file must exist: %v", err)
	}
	for _, line := range nonEmptyLines(string(raw)) {
		var record map[string]string
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("engine records must be JSON: %v (%q)", err, line)
		}
		if strings.Contains(record["message"], "enable_dynamic_rules is set but the agent handler cannot fetch") {
			return
		}
	}
	t.Fatalf("the engine idle-rule-loop warning must reach the JSON stream: %q", string(raw))
}

func nonEmptyLines(text string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
