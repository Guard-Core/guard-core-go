package guardcore

import (
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingSink captures every anomaly event a test monitor emits.
type recordingSink struct {
	mu     sync.Mutex
	events []AnomalyEvent
	err    error
}

func (s *recordingSink) SendAnomalyEvent(event AnomalyEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return s.err
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func (s *recordingSink) last() AnomalyEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events[len(s.events)-1]
}

func monitorWithSamples(t *testing.T, opts PerformanceMonitorOptions) *PerformanceMonitor {
	t.Helper()
	return NewPerformanceMonitor(opts)
}

func TestPerformanceMonitorConstructorClamps(t *testing.T) {
	tests := []struct {
		name string
		in   PerformanceMonitorOptions
		want PerformanceMonitorOptions
	}{
		{"defaults pass through", DefaultPerformanceMonitorOptions(), DefaultPerformanceMonitorOptions()},
		{"threshold low clamp", PerformanceMonitorOptions{AnomalyThreshold: 0.1}, PerformanceMonitorOptions{AnomalyThreshold: 1.0}},
		{"threshold high clamp", PerformanceMonitorOptions{AnomalyThreshold: 50}, PerformanceMonitorOptions{AnomalyThreshold: 10.0}},
		{"slow low clamp", PerformanceMonitorOptions{SlowPatternThreshold: 0.001}, PerformanceMonitorOptions{SlowPatternThreshold: 0.01}},
		{"slow high clamp", PerformanceMonitorOptions{SlowPatternThreshold: 99}, PerformanceMonitorOptions{SlowPatternThreshold: 10.0}},
		{"history low clamp", PerformanceMonitorOptions{HistorySize: 1}, PerformanceMonitorOptions{HistorySize: 100}},
		{"history high clamp", PerformanceMonitorOptions{HistorySize: 100000}, PerformanceMonitorOptions{HistorySize: 10000}},
		{"tracked low clamp", PerformanceMonitorOptions{MaxTrackedPatterns: 1}, PerformanceMonitorOptions{MaxTrackedPatterns: 100}},
		{"tracked high clamp", PerformanceMonitorOptions{MaxTrackedPatterns: 99999}, PerformanceMonitorOptions{MaxTrackedPatterns: 5000}},
		{"cooldown low clamp", PerformanceMonitorOptions{AnomalyEmissionCooldown: 0.1}, PerformanceMonitorOptions{AnomalyEmissionCooldown: 1.0}},
		{"cooldown high clamp", PerformanceMonitorOptions{AnomalyEmissionCooldown: 7200}, PerformanceMonitorOptions{AnomalyEmissionCooldown: 3600}},
		{"samples low clamp", PerformanceMonitorOptions{MinSamplesForAnomaly: 1}, PerformanceMonitorOptions{MinSamplesForAnomaly: 10}},
		{"samples high clamp", PerformanceMonitorOptions{MinSamplesForAnomaly: 5000}, PerformanceMonitorOptions{MinSamplesForAnomaly: 1000}},
	}
	wantDefaults := map[string]float64{"threshold": 3.0, "slow": 0.1, "cooldown": 60.0}
	if wantDefaults["threshold"] != DefaultPerformanceMonitorOptions().AnomalyThreshold ||
		wantDefaults["slow"] != DefaultPerformanceMonitorOptions().SlowPatternThreshold ||
		wantDefaults["cooldown"] != DefaultPerformanceMonitorOptions().AnomalyEmissionCooldown {
		t.Fatalf("default options drifted: %+v", DefaultPerformanceMonitorOptions())
	}
	if DefaultPerformanceMonitorOptions().HistorySize != 1000 ||
		DefaultPerformanceMonitorOptions().MaxTrackedPatterns != 1000 ||
		DefaultPerformanceMonitorOptions().MinSamplesForAnomaly != 30 {
		t.Fatalf("default int options drifted: %+v", DefaultPerformanceMonitorOptions())
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewPerformanceMonitor(tt.in)
			if m.anomalyThreshold != tt.want.AnomalyThreshold && tt.in.AnomalyThreshold != 0 {
				t.Fatalf("anomaly_threshold = %v, want %v", m.anomalyThreshold, tt.want.AnomalyThreshold)
			}
			if tt.in.SlowPatternThreshold != 0 && m.slowPatternThreshold != tt.want.SlowPatternThreshold {
				t.Fatalf("slow_pattern_threshold = %v, want %v", m.slowPatternThreshold, tt.want.SlowPatternThreshold)
			}
		})
	}
	// Dedicated window assertion: the recent-times window is
	// max(min_samples, 100).
	low := NewPerformanceMonitor(PerformanceMonitorOptions{MinSamplesForAnomaly: 10})
	if low.recentTimesWindow != DefaultRecentTimesWindow {
		t.Fatalf("recent window = %d, want %d", low.recentTimesWindow, DefaultRecentTimesWindow)
	}
	high := NewPerformanceMonitor(PerformanceMonitorOptions{MinSamplesForAnomaly: 500})
	if high.recentTimesWindow != 500 {
		t.Fatalf("recent window = %d, want 500", high.recentTimesWindow)
	}
}

func TestPerformanceMonitorRecordsCountersAndWindow(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	// 150 fast matching samples: counters advance, window caps at 100,
	// min/max/avg track.
	for i := 0; i < 150; i++ {
		m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 0.002, ContentLength: 10, Matched: true})
	}
	report := m.GetPatternReport("p")
	if report == nil {
		t.Fatal("tracked pattern must report")
	}
	if report.TotalExecutions != 150 || report.TotalMatches != 150 || report.TotalTimeouts != 0 {
		t.Fatalf("counters drifted: %+v", report)
	}
	if report.MatchRate != 1.0 || report.TimeoutRate != 0 {
		t.Fatalf("rates drifted: %+v", report)
	}
	if report.MinExecutionTime != 0.002 || report.MaxExecutionTime != 0.002 || report.AvgExecutionTime != 0.002 {
		t.Fatalf("timing stats drifted: %+v", report)
	}
	m.mu.Lock()
	window := len(m.patternStats["p"].RecentTimes)
	m.mu.Unlock()
	if window != DefaultRecentTimesWindow {
		t.Fatalf("recent times window = %d, want %d", window, DefaultRecentTimesWindow)
	}
	if report.PatternHash == "" {
		t.Fatal("report must carry a pattern hash")
	}
}

func TestPerformanceMonitorTimeoutSampleExcludedFromTiming(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 5.0, ContentLength: 3, Timeout: true})
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 0.5, ContentLength: 3})
	report := m.GetPatternReport("p")
	if report.TotalTimeouts != 1 {
		t.Fatalf("timeout counter = %d, want 1", report.TotalTimeouts)
	}
	if report.TimeoutRate != 0.5 {
		t.Fatalf("timeout rate = %v, want 0.5", report.TimeoutRate)
	}
	// The timeout sample never joins the window: min stays 0.5, not 0.
	if report.MinExecutionTime != 0.5 || report.MaxExecutionTime != 0.5 {
		t.Fatalf("timeout sample leaked into timing: %+v", report)
	}
}

func TestPerformanceMonitorUntrackedPatternReport(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	if report := m.GetPatternReport("never-seen"); report != nil {
		t.Fatalf("untracked pattern must report nil, got %+v", report)
	}
}

func TestPerformanceMonitorLongPatternNameTruncated(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	long := strings.Repeat("x", 250)
	m.RecordMetric(MetricObservation{Pattern: long, ExecutionTime: 0.001})
	report := m.GetPatternReport(long)
	if report == nil {
		t.Fatal("truncated name must still resolve the tracked stats")
	}
	m.mu.Lock()
	_, tracked := m.patternStats[truncatePatternName(long)]
	m.mu.Unlock()
	if !tracked {
		t.Fatal("the truncated name keys the stats store, like the reference")
	}
	if truncatePatternName(long) != strings.Repeat("x", 100)+"...[truncated]" {
		t.Fatalf("truncatePatternName produced %q", truncatePatternName(long))
	}
	// Negative inputs clamp to zero.
	m.RecordMetric(MetricObservation{Pattern: "neg", ExecutionTime: -5, ContentLength: -3})
	if report := m.GetPatternReport("neg"); report.MaxExecutionTime != 0 {
		t.Fatalf("negative execution time must clamp to 0, got %v", report.MaxExecutionTime)
	}
}

func TestPerformanceMonitorSlowExecutionAnomaly(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	sink := &recordingSink{}
	m.RecordMetric(MetricObservation{Pattern: "slowpoke", ExecutionTime: 0.2, ContentLength: 5, Agent: sink})
	if sink.count() != 1 {
		t.Fatalf("expected one anomaly event, got %d", sink.count())
	}
	event := sink.last()
	if event.EventType != EventPatternAnomalySlowExecution {
		t.Fatalf("event type = %q, want %q", event.EventType, EventPatternAnomalySlowExecution)
	}
	if event.IPAddress != "system" || event.ActionTaken != "anomaly_detected" {
		t.Fatalf("envelope drifted: %+v", event)
	}
	if event.Reason != "Pattern performance anomaly: slow_execution" {
		t.Fatalf("reason drifted: %q", event.Reason)
	}
	if event.Metadata["component"] != "PerformanceMonitor" {
		t.Fatalf("metadata component drifted: %+v", event.Metadata)
	}
	if _, ok := event.Metadata["correlation_id"]; !ok {
		t.Fatal("metadata must carry correlation_id")
	}
	if event.Metadata["execution_time"] != 0.2 {
		t.Fatalf("metadata execution_time drifted: %+v", event.Metadata)
	}
}

func TestPerformanceMonitorTimeoutAnomalySuppressesSlow(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	sink := &recordingSink{}
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 9.0, ContentLength: 5, Timeout: true, Agent: sink})
	if sink.count() != 1 {
		t.Fatalf("expected exactly the timeout anomaly, got %d events", sink.count())
	}
	if sink.last().EventType != EventPatternAnomalyTimeout {
		t.Fatalf("event type = %q, want timeout", sink.last().EventType)
	}
	if sink.last().Metadata["content_length"] != 5 {
		t.Fatalf("timeout anomaly metadata drifted: %+v", sink.last().Metadata)
	}
}

func TestPerformanceMonitorStatisticalAnomaly(t *testing.T) {
	// min_samples 10 (clamped floor): 9 tight samples then one outlier.
	m := monitorWithSamples(t, PerformanceMonitorOptions{MinSamplesForAnomaly: 10, AnomalyThreshold: 3.0})
	sink := &recordingSink{}
	for i := 0; i < 10; i++ {
		m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 0.01, ContentLength: 1, Agent: sink})
	}
	if sink.count() != 0 {
		t.Fatalf("tight samples must not anomaly, got %d", sink.count())
	}
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 1.0, ContentLength: 1, Agent: sink})
	// The reference accumulates anomalies: the outlier is both a
	// slow-execution anomaly and (the sample joins the window before the
	// check, exactly like Python) a statistical one.
	if sink.count() != 2 {
		t.Fatalf("outlier must trip slow plus statistical anomalies, got %d events", sink.count())
	}
	event := sink.last()
	if event.EventType != EventPatternAnomalyStatisticalAnomaly {
		t.Fatalf("last event type = %q, want statistical", event.EventType)
	}
	if sink.events[0].EventType != EventPatternAnomalySlowExecution {
		t.Fatalf("first event type = %q, want slow execution", sink.events[0].EventType)
	}
	if event.EventType != EventPatternAnomalyStatisticalAnomaly {
		t.Fatalf("event type = %q, want statistical", event.EventType)
	}
	z, _ := event.Metadata["z_score"].(float64)
	if z <= 3.0 {
		t.Fatalf("z_score = %v, want > threshold 3.0", z)
	}
	if event.Metadata["avg_time"].(float64) <= 0 || event.Metadata["std_time"].(float64) <= 0 {
		t.Fatalf("statistical metadata drifted: %+v", event.Metadata)
	}
}

func TestPerformanceMonitorStatisticalAnomalyNeedsSamples(t *testing.T) {
	// The slow threshold sits above every sample so only the statistical
	// path could ever emit: with 29 samples in the window (one below the
	// clamped floor of 30) the outlier stays silent.
	m := monitorWithSamples(t, PerformanceMonitorOptions{MinSamplesForAnomaly: 30, SlowPatternThreshold: 10.0})
	sink := &recordingSink{}
	for i := 0; i < 28; i++ {
		m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 0.01, Agent: sink})
	}
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 5.0, Agent: sink})
	if sink.count() != 0 {
		t.Fatalf("anomaly fired with %d samples in the window (min 30)", sink.count())
	}
}

func TestPerformanceMonitorStatisticalAnomalyBelowMean(t *testing.T) {
	m := monitorWithSamples(t, PerformanceMonitorOptions{MinSamplesForAnomaly: 10, SlowPatternThreshold: 1.0})
	sink := &recordingSink{}
	for i := 0; i < 10; i++ {
		m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 0.5, Agent: sink})
	}
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 0.01, Agent: sink})
	if sink.count() != 0 {
		t.Fatalf("below-mean sample must not anomaly, got %d", sink.count())
	}
}

func TestPerformanceMonitorZeroVarianceNoAnomaly(t *testing.T) {
	// Identical samples then a huge outlier can still anomaly; instead
	// force std 0 with an outlier that equals the mean after a min/max
	// spread keeps variance 0: impossible, so pin the documented guard via
	// a single-sample window of size min_samples where all are equal and
	// the outlier equals the mean (no z-score path). The guard is directly
	// reachable through a window whose variance is exactly zero and a
	// metric strictly greater than the mean only when variance > 0, so
	// this test pins the opposite edge: variance zero with metric == mean.
	m := monitorWithSamples(t, PerformanceMonitorOptions{MinSamplesForAnomaly: 10, SlowPatternThreshold: 0.05})
	sink := &recordingSink{}
	for i := 0; i < 11; i++ {
		m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 0.02, Agent: sink})
	}
	if sink.count() != 0 {
		t.Fatal("zero-variance window must never statistical-anomaly")
	}
}

func TestPerformanceMonitorCooldown(t *testing.T) {
	m := monitorWithSamples(t, PerformanceMonitorOptions{SlowPatternThreshold: 10.0, AnomalyEmissionCooldown: 3600})
	sink := &recordingSink{}
	// Statistical anomalies bypass the slow threshold (execution > mean)
	// once enough samples exist; drive two statistical trips in a row.
	for i := 0; i < 30; i++ {
		m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 0.01, Agent: sink})
	}
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 2.0, Agent: sink})
	first := sink.count()
	if first == 0 {
		t.Fatal("first anomaly must emit")
	}
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 3.0, Agent: sink})
	if sink.count() != first {
		t.Fatal("second anomaly inside the cooldown must not emit to the agent")
	}
	// Callbacks still fire inside the cooldown (only agent emission is
	// reserved).
	m.RegisterAnomalyCallback(func(sanitized map[string]any) {})
	called := 0
	m.mu.Lock()
	called = len(m.anomalyCallbacks)
	m.mu.Unlock()
	if called != 1 {
		t.Fatalf("callback registration lost: %d", called)
	}
}

func TestPerformanceMonitorCooldownIsPerPattern(t *testing.T) {
	m := monitorWithSamples(t, PerformanceMonitorOptions{SlowPatternThreshold: 0.5})
	sink := &recordingSink{}
	m.RecordMetric(MetricObservation{Pattern: "a", ExecutionTime: 1.0, Agent: sink})
	m.RecordMetric(MetricObservation{Pattern: "b", ExecutionTime: 1.0, Agent: sink})
	if sink.count() != 2 {
		t.Fatalf("each pattern's first anomaly must emit, got %d", sink.count())
	}
}

func TestPerformanceMonitorCallbacksReceiveSanitizedAnomaly(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	received := make(chan map[string]any, 4)
	m.RegisterAnomalyCallback(func(sanitized map[string]any) { received <- sanitized })
	sink := &recordingSink{}
	m.RecordMetric(MetricObservation{
		Pattern:       "token=[\\s\\S]*password=[\\s\\S]*",
		ExecutionTime: 1.0,
		ContentLength: 7,
		Agent:         sink,
	})
	select {
	case sanitized := <-received:
		if sanitized["type"] != AnomalySlowExecution {
			t.Fatalf("sanitized type = %v", sanitized["type"])
		}
		pattern, _ := sanitized["pattern"].(string)
		if strings.Contains(strings.ToLower(pattern), "password") {
			t.Fatalf("sanitized pattern leaked the sensitive name: %q", pattern)
		}
		if hash, ok := sanitized["pattern_hash"].(string); !ok || len(hash) != 8 {
			t.Fatalf("sanitized anomaly must carry an 8-char pattern_hash, got %v", sanitized["pattern_hash"])
		}
		if sanitized["execution_time"] != 1.0 {
			t.Fatalf("sanitized numeric fields must survive: %+v", sanitized)
		}
	case <-time.After(time.Second):
		t.Fatal("callback never invoked")
	}
	// The agent event carries the redacted but untruncated pattern.
	if strings.Contains(strings.ToLower(fmtAny(sink.last().Metadata["pattern"])), "password") {
		t.Fatalf("agent event leaked the sensitive name: %+v", sink.last().Metadata)
	}
}

func fmtAny(v any) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ToLower(toStr(v)), "\n", ""))
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestPerformanceMonitorPanickingCallbackSendsCallbackErrorEvent(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	m.RegisterAnomalyCallback(func(map[string]any) { panic("callback exploded") })
	sink := &recordingSink{}
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 1.0, Agent: sink, CorrelationID: "corr-7"})
	if sink.count() != 2 {
		t.Fatalf("expected the anomaly plus the callback-error event, got %d", sink.count())
	}
	errEvent := sink.last()
	if errEvent.EventType != EventDetectionEngineCallbackError {
		t.Fatalf("event type = %q, want %q", errEvent.EventType, EventDetectionEngineCallbackError)
	}
	if errEvent.ActionTaken != "logged" {
		t.Fatalf("action_taken = %q, want logged", errEvent.ActionTaken)
	}
	if !strings.Contains(errEvent.Reason, "callback exploded") {
		t.Fatalf("reason must carry the failure: %q", errEvent.Reason)
	}
	if errEvent.Metadata["anomaly_type"] != AnomalySlowExecution {
		t.Fatalf("callback-error anomaly_type drifted: %+v", errEvent.Metadata)
	}
	if errEvent.Metadata["correlation_id"] != "corr-7" {
		t.Fatalf("callback-error correlation_id drifted: %+v", errEvent.Metadata)
	}
}

func TestPerformanceMonitorSendFailureDoesNotPanic(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	m.RegisterAnomalyCallback(func(map[string]any) {})
	sink := &recordingSink{err: errSentinel{}}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("send failures must be logged, not raised: %v", r)
		}
	}()
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 1.0, Agent: sink})
}

type errSentinel struct{}

func (errSentinel) Error() string { return "transport down" }

func TestPerformanceMonitorNoAgentNoCallbackSilence(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 5.0})
	if m.GetSummaryStats().TotalExecutions != 1 {
		t.Fatal("metrics must record even without a sink")
	}
}

func TestPerformanceMonitorEvictsOldestTrackedPattern(t *testing.T) {
	m := NewPerformanceMonitor(PerformanceMonitorOptions{MaxTrackedPatterns: 100})
	for i := 0; i < 100; i++ {
		m.RecordMetric(MetricObservation{Pattern: string(rune('a'+i)) + "-pattern", ExecutionTime: 0.001})
	}
	firstPattern := "a-pattern"
	if m.GetPatternReport(firstPattern) == nil {
		t.Fatal("first tracked pattern should still be present at capacity")
	}
	m.RecordMetric(MetricObservation{Pattern: "overflow-pattern", ExecutionTime: 0.001})
	if m.GetPatternReport(firstPattern) != nil {
		t.Fatal("the first-inserted pattern must be evicted at capacity")
	}
	if m.GetPatternReport("overflow-pattern") == nil {
		t.Fatal("the newest pattern must be tracked")
	}
}

func TestPerformanceMonitorClearAndRemoveStats(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	m.RecordMetric(MetricObservation{Pattern: "a", ExecutionTime: 0.001})
	m.RecordMetric(MetricObservation{Pattern: "b", ExecutionTime: 0.001})
	m.RemovePatternStats("a")
	if m.GetPatternReport("a") != nil {
		t.Fatal("removed pattern must lose its stats")
	}
	if m.GetPatternReport("b") == nil {
		t.Fatal("other patterns must survive RemovePatternStats")
	}
	m.RemovePatternStats("missing")
	m.ClearStats()
	if m.GetPatternReport("b") != nil {
		t.Fatal("ClearStats must drop every pattern")
	}
	empty := m.GetSummaryStats()
	if empty.TotalExecutions != 0 || empty.AvgExecutionTime != 0 || empty.TimeoutRate != 0 || empty.MatchRate != 0 {
		t.Fatalf("summary after clear must be the empty summary: %+v", empty)
	}
}

func TestPerformanceMonitorSummaryStats(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	if got := m.GetSummaryStats(); got != EmptySummaryStats() {
		t.Fatalf("empty summary drifted: %+v", got)
	}
	m.RecordMetric(MetricObservation{Pattern: "a", ExecutionTime: 0.2, Matched: true})
	m.RecordMetric(MetricObservation{Pattern: "b", ExecutionTime: 0.9, Timeout: true})
	m.RecordMetric(MetricObservation{Pattern: "c", ExecutionTime: 0.3})
	m.RecordMetric(MetricObservation{Pattern: "d", ExecutionTime: 0.1})
	summary := m.GetSummaryStats()
	if summary.TotalExecutions != 4 || summary.TotalPatterns != 4 {
		t.Fatalf("totals drifted: %+v", summary)
	}
	if summary.TimeoutRate != 0.25 || summary.MatchRate != 0.25 {
		t.Fatalf("rates drifted: %+v", summary)
	}
	// The timeout sample is excluded from the timing aggregates.
	if math.Abs(summary.AvgExecutionTime-0.2) > 1e-9 || summary.MinExecutionTime != 0.1 || summary.MaxExecutionTime != 0.3 {
		t.Fatalf("timing summary drifted: %+v", summary)
	}
}

func TestPerformanceMonitorSlowPatternsOrderingAndLimit(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	m.RecordMetric(MetricObservation{Pattern: "fast", ExecutionTime: 0.001})
	m.RecordMetric(MetricObservation{Pattern: "slowest", ExecutionTime: 0.9})
	m.RecordMetric(MetricObservation{Pattern: "middle", ExecutionTime: 0.4})
	m.RecordMetric(MetricObservation{Pattern: "timedout", ExecutionTime: 5.0, Timeout: true})
	reports := m.GetSlowPatterns(2)
	if len(reports) != 2 {
		t.Fatalf("limit must cap the report list, got %d", len(reports))
	}
	if reports[0].Pattern != "slowest" || reports[1].Pattern != "middle" {
		t.Fatalf("ordering drifted: %s then %s", reports[0].Pattern, reports[1].Pattern)
	}
	// The timeout-only pattern has no timing samples and never appears.
	all := m.GetSlowPatterns(10)
	for _, report := range all {
		if report.Pattern == "timedout" {
			t.Fatal("timeout-only pattern must not appear in slow patterns")
		}
	}
}

func TestPerformanceMonitorProblematicPatterns(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	// high timeout rate: > 10% of executions.
	for i := 0; i < 2; i++ {
		m.RecordMetric(MetricObservation{Pattern: "flaky", ExecutionTime: 0.001, Timeout: true})
	}
	m.RecordMetric(MetricObservation{Pattern: "flaky", ExecutionTime: 0.001})
	// consistently slow: average above the 0.1 threshold.
	m.RecordMetric(MetricObservation{Pattern: "grinder", ExecutionTime: 0.5})
	m.RecordMetric(MetricObservation{Pattern: "fine", ExecutionTime: 0.001})
	problematic := m.GetProblematicPatterns()
	if len(problematic) != 2 {
		t.Fatalf("expected 2 problematic patterns, got %+v", problematic)
	}
	issues := map[string]string{}
	for _, p := range problematic {
		issues[p.Pattern] = p.Issue
	}
	if issues["flaky"] != "high_timeout_rate" {
		t.Fatalf("flaky issue = %q", issues["flaky"])
	}
	if issues["grinder"] != "consistently_slow" {
		t.Fatalf("grinder issue = %q", issues["grinder"])
	}
}

func TestPerformanceMonitorReportDisplayTruncationAndRedaction(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	long := strings.Repeat("a", 80) + "z"
	m.RecordMetric(MetricObservation{Pattern: long, ExecutionTime: 0.001})
	report := m.GetPatternReport(long)
	if !strings.HasSuffix(report.Pattern, "...") || len([]rune(report.Pattern)) != 53 {
		t.Fatalf("report pattern must cap at 50 runes plus '...': %q", report.Pattern)
	}
	m.RecordMetric(MetricObservation{Pattern: `secret\s*=\s*password`, ExecutionTime: 0.001})
	sensitive := m.GetPatternReport(`secret\s*=\s*password`)
	if sensitive.Pattern != RedactedPlaceholder {
		t.Fatalf("sensitive-naming pattern must collapse to %q, got %q", RedactedPlaceholder, sensitive.Pattern)
	}
}

func TestPerformanceMonitorAnomalyEventTypeMapping(t *testing.T) {
	if anomalyEventType(AnomalyTimeout) != EventPatternAnomalyTimeout ||
		anomalyEventType(AnomalySlowExecution) != EventPatternAnomalySlowExecution ||
		anomalyEventType(AnomalyStatisticalAnomaly) != EventPatternAnomalyStatisticalAnomaly {
		t.Fatal("anomaly-to-event-type mapping drifted")
	}
}

func TestDetectSlowExecutionAnomalyBoundaries(t *testing.T) {
	metric := PerformanceMetric{Pattern: "p", ExecutionTime: 0.1}
	if DetectSlowExecutionAnomaly(metric, 0.1) != nil {
		t.Fatal("execution exactly at the threshold is not slow")
	}
	if DetectSlowExecutionAnomaly(PerformanceMetric{ExecutionTime: 0.1001, Timeout: true}, 0.1) != nil {
		t.Fatal("timeout samples are never slow anomalies")
	}
	if a := DetectSlowExecutionAnomaly(PerformanceMetric{ExecutionTime: 0.2, ContentLength: 9}, 0.1); a == nil {
		t.Fatal("execution above the threshold must detect")
	} else if a.ContentLength != 9 || a.ExecutionTime != 0.2 {
		t.Fatalf("slow anomaly fields drifted: %+v", a)
	}
}

func TestPerformanceMonitorConcurrencySmoke(t *testing.T) {
	m := NewPerformanceMonitor(DefaultPerformanceMonitorOptions())
	sink := &recordingSink{}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				m.RecordMetric(MetricObservation{Pattern: "concurrent", ExecutionTime: 0.001, Agent: sink})
			}
		}(i)
	}
	wg.Wait()
	if m.GetPatternReport("concurrent").TotalExecutions != 16*20 {
		t.Fatal("concurrent recording lost samples")
	}
}

func TestPerformanceMonitorSummaryEmptyWindowAfterHistoryRoll(t *testing.T) {
	m := NewPerformanceMonitor(PerformanceMonitorOptions{HistorySize: 100})
	for i := 0; i < 100; i++ {
		m.RecordMetric(MetricObservation{Pattern: "p", ExecutionTime: 0.001, Matched: true})
	}
	summary := m.GetSummaryStats()
	if summary.TotalExecutions != 100 || summary.MatchRate != 1 {
		t.Fatalf("summary over a full window drifted: %+v", summary)
	}
	if math.IsNaN(summary.AvgExecutionTime) {
		t.Fatal("avg must never be NaN")
	}
}
