package guardcore

import (
	"strings"
	"testing"
)

// TestDecodePatternSourceEscape pins the escape-decoding table used to
// unmask sensitive names hidden inside pattern sources.
func TestDecodePatternSourceEscape(t *testing.T) {
	tests := []struct {
		seq  string
		want string
	}{
		{`\x41`, "A"},
		{`\u0041`, "A"},
		{`\U00000041`, "A"},
		{`\101`, "A"},
		{`\x7a`, "z"},
		{`\X4A`, "J"},
		{`\u004A`, "J"},
		// Out-of-range and malformed sequences come back verbatim.
		{`\U00110000`, `\U00110000`},
		{`\x`, `\x`},
		{`noescape`, `noescape`},
	}
	for _, tt := range tests {
		if got := decodePatternSourceEscape(tt.seq); got != tt.want {
			t.Errorf("decodePatternSourceEscape(%q) = %q, want %q", tt.seq, got, tt.want)
		}
	}
}

// TestPatternSourceNamesASensitiveField pins the sensitive-name probe:
// escapes and stripped separators cannot smuggle a name past it.
func TestPatternSourceNamesASensitiveField(t *testing.T) {
	sensitive := map[string]bool{"password": true, "api_key": true}
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{"plain", `secret\s*=\s*password`, true},
		// Reference behavior: the escape decoder only rewrites \x/\u/\U
		// and octal spellings, so the literal class letters of \s survive
		// normalization and a dash-separated spelling keeps its dashes;
		// neither names the field.
		{"escaped class letters do not name", `p\s*a\s*s\s*s\s*w\s*o\s*r\s*d`, false},
		{"hex escapes", `\x70\x61\x73\x73\x77\x6f\x72\x64`, true},
		{"dashes are token characters", `p-a-s-s-w-o-r-d`, false},
		{"benign", `SELECT\s+.+\s+FROM`, false},
		{"prefix collision kept honest", `wordlist`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := patternSourceNamesASensitiveField(tt.source, sensitive); got != tt.want {
				t.Fatalf("patternSourceNamesASensitiveField(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

// TestRedactPatternSource pins the two branches: sensitive-naming sources
// collapse to the placeholder, everything else flows through the blob
// redactor unchanged.
func TestRedactPatternSource(t *testing.T) {
	if got := RedactPatternSource(`secret\s*=\s*password`); got != RedactedPlaceholder {
		t.Fatalf("sensitive pattern source = %q, want %q", got, RedactedPlaceholder)
	}
	benign := `SELECT\s+.+\s+FROM\s+users`
	if got := RedactPatternSource(benign); got != benign {
		t.Fatalf("benign pattern source mutated: %q", got)
	}
	// A value-shaped blob gets its pairs redacted by the blob redactor.
	if got := RedactPatternSource(`token=abc123`); strings.Contains(got, "abc123") {
		t.Fatalf("embedded secret survived: %q", got)
	}
}

// TestAnomalyEventTypeFallback covers the unknown-kind fallback of the
// event-type mapping.
func TestAnomalyEventTypeFallback(t *testing.T) {
	if anomalyEventType("mystery") != EventPatternAnomalyTimeout {
		t.Fatal("unknown anomaly kinds must fall back to the timeout event type")
	}
}

// TestMeanOfEmpty covers the empty-window mean guard.
func TestMeanOfEmpty(t *testing.T) {
	if meanOf(nil) != 0 {
		t.Fatal("mean of an empty window must be 0")
	}
}

// TestStatisticalAnomalyDefensiveSampleFloor drives the reference's
// second sample-count guard (sample_count < 2), reachable only when the
// configured min floor is 1; the constructor clamps to >= 10, so this is
// a white-box parity check of the ported guard.
func TestStatisticalAnomalyDefensiveSampleFloor(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	m.minSamplesForAnomaly = 1
	m.patternStats["p"] = &PatternStats{Pattern: "p", RecentTimes: []float64{0.01}}
	anomaly := m.detectStatisticalAnomalyLocked(PerformanceMetric{Pattern: "p", ExecutionTime: 5.0})
	if anomaly != nil {
		t.Fatalf("a one-sample window must never statistical-anomaly: %+v", anomaly)
	}
}

// TestReserveAnomalyEmissionMissingStats pins the evicted-pattern path:
// without stats the emission is allowed and nothing is stamped.
func TestReserveAnomalyEmissionMissingStats(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	if !m.reserveAnomalyEmission("ghost") {
		t.Fatal("a pattern without stats must always reserve emission")
	}
	m.mu.Lock()
	_, stamped := m.patternStats["ghost"]
	m.mu.Unlock()
	if stamped {
		t.Fatal("reserve must not create stats for the missing pattern")
	}
}

// TestBuildPatternReportZeroExecutions covers the defensive division
// floor in the report builder.
func TestBuildPatternReportZeroExecutions(t *testing.T) {
	report := buildPatternReport("p", &PatternStats{Pattern: "p", MinExecutionTime: infFloat()})
	if report.MatchRate != 0 || report.TimeoutRate != 0 {
		t.Fatalf("zero-execution report rates must be 0: %+v", report)
	}
	if report.MinExecutionTime != 0 {
		t.Fatalf("the +Inf sentinel must report as 0: %+v", report)
	}
}

// TestRunAnomalyCallbackPanicWithoutSink covers the panicking-callback
// path when no agent sink is attached: the panic is contained, no event
// is attempted.
func TestRunAnomalyCallbackPanicWithoutSink(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a panicking callback must be contained: %v", r)
		}
	}()
	runAnomalyCallback(func(map[string]any) { panic("boom") }, map[string]any{"type": "timeout"}, nil, "")
}

// TestPerformanceMonitorTimeoutAnomalySanitization runs a timeout anomaly
// through the sanitized-callback path (timeout anomalies carry
// content_length, not execution_time).
func TestPerformanceMonitorTimeoutAnomalySanitization(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	var got map[string]any
	m.RegisterAnomalyCallback(func(sanitized map[string]any) { got = sanitized })
	m.RecordMetric(MetricObservation{Pattern: `token=[\s\S]*`, ExecutionTime: 0.001, Timeout: true})
	if got == nil {
		t.Fatal("timeout anomaly must reach the sanitized callbacks")
	}
	if got["type"] != AnomalyTimeout {
		t.Fatalf("sanitized type = %v, want timeout", got["type"])
	}
	if _, hasExec := got["execution_time"]; hasExec {
		t.Fatalf("timeout anomaly must not carry execution_time: %+v", got)
	}
	if got["content_length"] != 0 {
		t.Fatalf("timeout anomaly content_length drifted: %+v", got)
	}
}

// TestDisplayTruncate pins the 50-rune display cap boundary.
func TestDisplayTruncate(t *testing.T) {
	short := strings.Repeat("a", 50)
	if displayTruncate(short) != short {
		t.Fatal("a 50-rune pattern stays whole")
	}
	long := strings.Repeat("a", 51)
	if got := displayTruncate(long); got != short+"..." {
		t.Fatalf("displayTruncate(51 runes) = %d runes, want 50 plus '...'", len([]rune(got)))
	}
}

// TestStatisticalAnomalyZeroStd pins the zero-variance guard: identical
// window samples give std 0, so even an above-mean metric never
// statistical-anomalies (white-box: the constructor clamps
// min_samples_for_anomaly to >= 10, a two-sample window needs the floor
// lowered).
func TestStatisticalAnomalyZeroStd(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	m.minSamplesForAnomaly = 2
	m.patternStats["p"] = &PatternStats{Pattern: "p", RecentTimes: []float64{0.5, 0.5}}
	if anomaly := m.detectStatisticalAnomalyLocked(PerformanceMetric{Pattern: "p", ExecutionTime: 1.0}); anomaly != nil {
		t.Fatalf("zero-variance window must not statistical-anomaly: %+v", anomaly)
	}
}

// TestRunAnomalyCallbackErrorEventSendFailure covers the callback-error
// path when even the error event cannot be delivered: the failure is
// logged, never raised.
func TestRunAnomalyCallbackErrorEventSendFailure(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("send failures must stay contained: %v", r)
		}
	}()
	runAnomalyCallback(func(map[string]any) { panic("boom") }, map[string]any{"type": "timeout"}, &recordingSink{err: errSentinel{}}, "")
}

// TestProblematicPatternsSkipsEmptyExecutions covers the zero-execution
// skip in the problematic-patterns collector (white-box: stats entries
// only gain executions through RecordMetric, so the entry is seeded
// directly).
func TestProblematicPatternsSkipsEmptyExecutions(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	m.mu.Lock()
	m.patternStats["seeded"] = &PatternStats{Pattern: "seeded", MinExecutionTime: infFloat()}
	m.insertionOrder = append(m.insertionOrder, "seeded")
	m.mu.Unlock()
	if got := m.GetProblematicPatterns(); len(got) != 0 {
		t.Fatalf("zero-execution stats must be skipped, got %+v", got)
	}
}
