package guardcore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PerformanceMonitor, ported from the reference detection-engine monitor
// (guard_core/detection_engine/monitor.py plus monitor_types.py,
// monitor_anomalies.py and monitor_reporting.py): per-pattern execution
// stats, the anomaly-detection trio (timeout, slow execution, statistical
// anomaly), sanitized anomaly callbacks, and the agent anomaly-event
// envelope. Config knobs mirror the reference SecurityConfig fields the
// corpus pins (detection_anomaly_threshold 3.0, detection_slow_pattern_
// threshold 0.1, detection_monitor_history_size 1000,
// detection_anomaly_emission_cooldown 60.0, detection_min_samples_for_
// anomaly 30).

const (
	// DefaultRecentTimesWindow mirrors DEFAULT_RECENT_TIMES_WINDOW
	// (monitor_types.py): the rolling sample window feeding the averages
	// and the statistical anomaly.
	DefaultRecentTimesWindow = 100

	// maxPatternNameLength mirrors record_metric's MAX_PATTERN_LENGTH:
	// longer pattern names are truncated with a "...[truncated]" suffix
	// before they key any state.
	maxPatternNameLength = 100

	// displayPatternPrefixLength mirrors the 50-character prefix cap the
	// reports and sanitized anomalies apply.
	displayPatternPrefixLength = 50
)

// PerformanceMetric is one pattern execution observation
// (monitor_types.PerformanceMetric).
type PerformanceMetric struct {
	Pattern       string
	ExecutionTime float64
	ContentLength int
	Timestamp     time.Time
	Matched       bool
	Timeout       bool
}

// PatternStats is one pattern's running statistics
// (monitor_types.PatternStats). MinExecutionTime starts at +Inf like the
// reference's float("inf") sentinel and is reported as 0 until a
// non-timeout sample arrives.
type PatternStats struct {
	Pattern              string
	TotalExecutions      int64
	TotalMatches         int64
	TotalTimeouts        int64
	AvgExecutionTime     float64
	MaxExecutionTime     float64
	MinExecutionTime     float64
	RecentTimes          []float64
	LastAnomalyEmittedAt time.Time
	// HasEmittedAnomaly distinguishes the reference's
	// last_anomaly_emitted_at=None from a real stamp.
	HasEmittedAnomaly bool
}

// PerformanceMonitorOptions carries the constructor knobs, mirroring
// PerformanceMonitor.__init__'s parameters and defaults.
type PerformanceMonitorOptions struct {
	AnomalyThreshold        float64 // default 3.0
	SlowPatternThreshold    float64 // default 0.1
	HistorySize             int     // default 1000
	MaxTrackedPatterns      int     // default 1000
	AnomalyEmissionCooldown float64 // seconds, default 60.0
	MinSamplesForAnomaly    int     // default 30
}

// DefaultPerformanceMonitorOptions returns the reference defaults.
func DefaultPerformanceMonitorOptions() PerformanceMonitorOptions {
	return PerformanceMonitorOptions{
		AnomalyThreshold:        3.0,
		SlowPatternThreshold:    0.1,
		HistorySize:             1000,
		MaxTrackedPatterns:      1000,
		AnomalyEmissionCooldown: 60.0,
		MinSamplesForAnomaly:    30,
	}
}

// AnomalyEventSender receives the monitor's anomaly and callback-error
// events. The reference passes the agent handler into record_metric; the
// event-bus milestone's agent stream provides the production sink. Send
// failures are logged by the monitor, never raised, exactly like the
// reference.
type AnomalyEventSender interface {
	SendAnomalyEvent(event AnomalyEvent) error
}

// AnomalyEvent is the monitor-scoped SecurityEvent envelope
// (monitor_anomalies.build_anomaly_event_data /
// build_callback_error_event_data): the same field names the reference
// SecurityEvent carries, narrowed to what the monitor emits.
type AnomalyEvent struct {
	Timestamp   time.Time
	EventType   string
	IPAddress   string
	ActionTaken string
	Reason      string
	Metadata    map[string]any
}

// Anomaly kinds, mirroring the reference's anomaly dicts and the
// pattern_anomaly_* event-type mapping.
const (
	AnomalyTimeout            = "timeout"
	AnomalySlowExecution      = "slow_execution"
	AnomalyStatisticalAnomaly = "statistical_anomaly"
)

// Event-type strings the monitor emits (guard_core/core/events/
// event_types.py). Defined here so the monitor has no import cycle with
// the events milestone; the events vocabulary test asserts the equality
// with the bus constants.
const (
	EventPatternAnomalyTimeout            = "pattern_anomaly_timeout"
	EventPatternAnomalySlowExecution      = "pattern_anomaly_slow_execution"
	EventPatternAnomalyStatisticalAnomaly = "pattern_anomaly_statistical_anomaly"
	EventDetectionEngineCallbackError     = "detection_engine_callback_error"
)

// Anomaly is one detected performance anomaly (the reference's anomaly
// dict, typed). Only the fields meaningful for the anomaly's Type are set.
type Anomaly struct {
	Type          string
	Pattern       string
	ContentLength int
	ExecutionTime float64
	ZScore        float64
	AvgTime       float64
	StdTime       float64
}

// fields renders the anomaly as the reference dict shape.
func (a Anomaly) fields() map[string]any {
	fields := map[string]any{
		"type":    a.Type,
		"pattern": a.Pattern,
	}
	switch a.Type {
	case AnomalyTimeout:
		fields["content_length"] = a.ContentLength
	case AnomalySlowExecution:
		fields["execution_time"] = a.ExecutionTime
		fields["content_length"] = a.ContentLength
	case AnomalyStatisticalAnomaly:
		fields["execution_time"] = a.ExecutionTime
		fields["z_score"] = a.ZScore
		fields["avg_time"] = a.AvgTime
		fields["std_time"] = a.StdTime
	}
	return fields
}

func anomalyEventType(anomalyType string) string {
	switch anomalyType {
	case AnomalyTimeout:
		return EventPatternAnomalyTimeout
	case AnomalySlowExecution:
		return EventPatternAnomalySlowExecution
	case AnomalyStatisticalAnomaly:
		return EventPatternAnomalyStatisticalAnomaly
	}
	return EventPatternAnomalyTimeout
}

// PerformanceMonitor tracks per-pattern execution statistics and detects
// performance anomalies. Safe for concurrent use (the reference guards
// its state with an asyncio.Lock).
type PerformanceMonitor struct {
	anomalyThreshold        float64
	slowPatternThreshold    float64
	historySize             int
	maxTrackedPatterns      int
	anomalyEmissionCooldown float64
	minSamplesForAnomaly    int
	recentTimesWindow       int

	mu               sync.Mutex
	patternStats     map[string]*PatternStats
	insertionOrder   []string
	recentMetrics    []PerformanceMetric
	anomalyCallbacks []func(sanitized map[string]any)
}

// NewPerformanceMonitor applies the reference constructor clamps:
// anomaly_threshold [1, 10], slow_pattern_threshold [0.01, 10],
// history_size [100, 10000], max_tracked_patterns [100, 5000],
// anomaly_emission_cooldown [1, 3600], min_samples_for_anomaly
// [10, 1000] (PerformanceMonitor.__init__).
func NewPerformanceMonitor(opts PerformanceMonitorOptions) *PerformanceMonitor {
	clampFloat := func(v, lo, hi float64) float64 {
		if v < lo {
			return lo
		}
		if v > hi {
			return hi
		}
		return v
	}
	clampInt := func(v, lo, hi int) int {
		if v < lo {
			return lo
		}
		if v > hi {
			return hi
		}
		return v
	}
	minSamples := clampInt(opts.MinSamplesForAnomaly, 10, 1000)
	window := minSamples
	if window < DefaultRecentTimesWindow {
		window = DefaultRecentTimesWindow
	}
	return &PerformanceMonitor{
		anomalyThreshold:        clampFloat(opts.AnomalyThreshold, 1.0, 10.0),
		slowPatternThreshold:    clampFloat(opts.SlowPatternThreshold, 0.01, 10.0),
		historySize:             clampInt(opts.HistorySize, 100, 10000),
		maxTrackedPatterns:      clampInt(opts.MaxTrackedPatterns, 100, 5000),
		anomalyEmissionCooldown: clampFloat(opts.AnomalyEmissionCooldown, 1.0, 3600.0),
		minSamplesForAnomaly:    minSamples,
		recentTimesWindow:       window,
		patternStats:            map[string]*PatternStats{},
	}
}

// truncatePatternName applies record_metric's MAX_PATTERN_LENGTH cap with
// the "...[truncated]" suffix.
func truncatePatternName(pattern string) string {
	runes := []rune(pattern)
	if len(runes) <= maxPatternNameLength {
		return pattern
	}
	return string(runes[:maxPatternNameLength]) + "...[truncated]"
}

// DisplayTruncate caps a redacted pattern at 50 runes with a "..."
// suffix, the reports' safe_pattern form.
func displayTruncate(pattern string) string {
	runes := []rune(pattern)
	if len(runes) <= displayPatternPrefixLength {
		return pattern
	}
	return string(runes[:displayPatternPrefixLength]) + "..."
}

// RecordMetric observes one pattern execution and dispatches anomaly
// checks, mirroring record_metric: the metric lands in the recent
// history, per-pattern counters advance (timeout samples never join the
// timing window), the statistical anomaly is computed under the lock, and
// anomaly dispatch (agent events plus sanitized callbacks) runs after.
func (m *PerformanceMonitor) RecordMetric(obs MetricObservation) {
	pattern := truncatePatternName(obs.Pattern)
	if obs.ExecutionTime < 0 {
		obs.ExecutionTime = 0
	}
	if obs.ContentLength < 0 {
		obs.ContentLength = 0
	}
	metric := PerformanceMetric{
		Pattern:       pattern,
		ExecutionTime: obs.ExecutionTime,
		ContentLength: obs.ContentLength,
		Timestamp:     time.Now().UTC(),
		Matched:       obs.Matched,
		Timeout:       obs.Timeout,
	}

	m.mu.Lock()
	m.recentMetrics = append(m.recentMetrics, metric)
	if overflow := len(m.recentMetrics) - m.historySize; overflow > 0 {
		m.recentMetrics = m.recentMetrics[overflow:]
	}
	stats := m.patternStats[pattern]
	if stats == nil {
		if len(m.patternStats) >= m.maxTrackedPatterns {
			// Python evicts next(iter(self.pattern_stats)): the
			// first-inserted key.
			oldest := m.insertionOrder[0]
			m.insertionOrder = m.insertionOrder[1:]
			delete(m.patternStats, oldest)
		}
		stats = &PatternStats{
			Pattern:          pattern,
			MinExecutionTime: infFloat(),
			RecentTimes:      make([]float64, 0, m.recentTimesWindow),
		}
		m.patternStats[pattern] = stats
		m.insertionOrder = append(m.insertionOrder, pattern)
	}
	stats.TotalExecutions++
	if metric.Matched {
		stats.TotalMatches++
	}
	if metric.Timeout {
		stats.TotalTimeouts++
	} else {
		stats.RecentTimes = append(stats.RecentTimes, metric.ExecutionTime)
		if overflow := len(stats.RecentTimes) - m.recentTimesWindow; overflow > 0 {
			stats.RecentTimes = stats.RecentTimes[overflow:]
		}
		if metric.ExecutionTime > stats.MaxExecutionTime {
			stats.MaxExecutionTime = metric.ExecutionTime
		}
		if metric.ExecutionTime < stats.MinExecutionTime {
			stats.MinExecutionTime = metric.ExecutionTime
		}
		stats.AvgExecutionTime = meanOf(stats.RecentTimes)
	}
	statisticalAnomaly := m.detectStatisticalAnomalyLocked(metric)
	m.mu.Unlock()

	m.checkAnomalies(metric, statisticalAnomaly, obs.Agent, obs.CorrelationID)
}

// MetricObservation is one RecordMetric request.
type MetricObservation struct {
	Pattern       string
	ExecutionTime float64
	ContentLength int
	Matched       bool
	Timeout       bool
	// Agent is the optional anomaly event sink (the reference's
	// per-call agent_handler argument).
	Agent AnomalyEventSender
	// CorrelationID rides the anomaly event metadata.
	CorrelationID string
}

func infFloat() float64 { return math.Inf(1) }

// meanOf mirrors math.fsum(values)/len(values).
func meanOf(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// DetectTimeoutAnomaly mirrors detect_timeout_anomaly.
func DetectTimeoutAnomaly(metric PerformanceMetric) *Anomaly {
	if metric.Timeout {
		return &Anomaly{Type: AnomalyTimeout, Pattern: metric.Pattern, ContentLength: metric.ContentLength}
	}
	return nil
}

// DetectSlowExecutionAnomaly mirrors detect_slow_execution_anomaly: a
// timeout sample suppresses the slow-execution check.
func DetectSlowExecutionAnomaly(metric PerformanceMetric, slowPatternThreshold float64) *Anomaly {
	if !metric.Timeout && metric.ExecutionTime > slowPatternThreshold {
		return &Anomaly{
			Type:          AnomalySlowExecution,
			Pattern:       metric.Pattern,
			ExecutionTime: metric.ExecutionTime,
			ContentLength: metric.ContentLength,
		}
	}
	return nil
}

// detectStatisticalAnomalyLocked mirrors detect_statistical_anomaly; it
// must run under m.mu because it reads the pattern's timing window.
func (m *PerformanceMonitor) detectStatisticalAnomalyLocked(metric PerformanceMetric) *Anomaly {
	stats := m.patternStats[metric.Pattern]
	if stats == nil || len(stats.RecentTimes) < m.minSamplesForAnomaly {
		return nil
	}
	recentTimes := stats.RecentTimes
	sampleCount := len(recentTimes)
	if sampleCount < 2 {
		return nil
	}
	avgTime := meanOf(recentTimes)
	// The reference guards `anomaly_threshold >= 0` before the mean
	// comparison; the constructor clamps the threshold to >= 1, so the
	// guard always holds and the sample must exceed the mean.
	if metric.ExecutionTime <= avgTime {
		return nil
	}
	variance := 0.0
	for _, t := range recentTimes {
		d := t - avgTime
		variance += d * d
	}
	variance /= float64(sampleCount - 1)
	stdTime := sqrtFloat(variance)
	if stdTime <= 0 {
		return nil
	}
	zScore := (metric.ExecutionTime - avgTime) / stdTime
	if zScore > m.anomalyThreshold {
		return &Anomaly{
			Type:          AnomalyStatisticalAnomaly,
			Pattern:       metric.Pattern,
			ExecutionTime: metric.ExecutionTime,
			ZScore:        zScore,
			AvgTime:       avgTime,
			StdTime:       stdTime,
		}
	}
	return nil
}

func sqrtFloat(x float64) float64 { return math.Sqrt(x) }

// SanitizeAnomalyData mirrors sanitize_anomaly_data: the pattern is
// redacted, capped at 50 runes with a "..." suffix, and a short stable
// pattern_hash is attached (the reference hashes with Python's salted
// str(hash()); the port uses the first 8 hex chars of SHA-256, equally
// opaque and stable within a process).
func SanitizeAnomalyData(anomaly Anomaly) map[string]any {
	safe := anomaly.fields()
	if _, ok := safe["pattern"]; ok {
		redacted := RedactPatternSource(anomaly.Pattern)
		safe["pattern"] = displayTruncate(redacted)
		safe["pattern_hash"] = shortPatternHash(redacted)
	}
	return safe
}

func shortPatternHash(pattern string) string {
	sum := sha256.Sum256([]byte(pattern))
	return hex.EncodeToString(sum[:])[:8]
}

// BuildAnomalyEventData mirrors build_anomaly_event_data: the event
// envelope carries the redacted (but not display-truncated) pattern plus
// the anomaly fields in metadata.
func BuildAnomalyEventData(anomaly Anomaly, correlationID string) AnomalyEvent {
	safe := anomaly.fields()
	if _, ok := safe["pattern"]; ok {
		safe["pattern"] = RedactPatternSource(anomaly.Pattern)
	}
	metadata := map[string]any{
		"component":      "PerformanceMonitor",
		"correlation_id": correlationID,
	}
	for k, v := range safe {
		metadata[k] = v
	}
	return AnomalyEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   anomalyEventType(anomaly.Type),
		IPAddress:   "system",
		ActionTaken: "anomaly_detected",
		Reason:      fmt.Sprintf("Pattern performance anomaly: %s", anomaly.Type),
		Metadata:    metadata,
	}
}

// BuildCallbackErrorEventData mirrors build_callback_error_event_data.
func BuildCallbackErrorEventData(err error, safeAnomaly map[string]any, correlationID string) AnomalyEvent {
	anomalyType := "unknown"
	if t, ok := safeAnomaly["type"].(string); ok && t != "" {
		anomalyType = t
	}
	return AnomalyEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   EventDetectionEngineCallbackError,
		IPAddress:   "system",
		ActionTaken: "logged",
		Reason:      fmt.Sprintf("Anomaly callback failed: %v", err),
		Metadata: map[string]any{
			"component":      "PerformanceMonitor",
			"correlation_id": correlationID,
			"callback_error": fmt.Sprint(err),
			"anomaly_type":   anomalyType,
		},
	}
}

// checkAnomalies mirrors _check_anomalies: timeout suppresses the
// slow-execution check, the statistical anomaly accumulates alongside,
// agent emission is gated by the per-pattern cooldown reserve, and every
// anomaly reaches the sanitized callbacks.
func (m *PerformanceMonitor) checkAnomalies(metric PerformanceMetric, statisticalAnomaly *Anomaly, agent AnomalyEventSender, correlationID string) {
	var anomalies []*Anomaly
	if timeoutAnomaly := DetectTimeoutAnomaly(metric); timeoutAnomaly != nil {
		anomalies = append(anomalies, timeoutAnomaly)
	} else if slowAnomaly := DetectSlowExecutionAnomaly(metric, m.slowPatternThreshold); slowAnomaly != nil {
		anomalies = append(anomalies, slowAnomaly)
	}
	if statisticalAnomaly != nil {
		anomalies = append(anomalies, statisticalAnomaly)
	}

	if agent != nil && len(anomalies) > 0 && m.reserveAnomalyEmission(metric.Pattern) {
		for _, anomaly := range anomalies {
			m.sendAnomalyEvent(anomaly, agent, correlationID)
		}
	}

	for _, anomaly := range anomalies {
		m.notifyCallbacks(*anomaly, agent, correlationID)
	}
}

func (m *PerformanceMonitor) sendAnomalyEvent(anomaly *Anomaly, agent AnomalyEventSender, correlationID string) {
	if err := agent.SendAnomalyEvent(BuildAnomalyEventData(*anomaly, correlationID)); err != nil {
		log.Printf("Failed to send anomaly event to agent: %v", err)
	}
}

// notifyCallbacks mirrors _notify_callbacks: each registered callback
// receives the sanitized anomaly; a panicking-or-erroring callback is out
// of the monitor's control in Go, so the callback wrapper is responsible
// for returning; the callback-error event path is exercised by the
// exported BuildCallbackErrorEventData via sinks that observe callback
// failures.
func (m *PerformanceMonitor) notifyCallbacks(anomaly Anomaly, agent AnomalyEventSender, correlationID string) {
	safe := SanitizeAnomalyData(anomaly)
	m.mu.Lock()
	callbacks := append([]func(map[string]any){}, m.anomalyCallbacks...)
	m.mu.Unlock()
	for _, callback := range callbacks {
		runAnomalyCallback(callback, safe, agent, correlationID)
	}
}

// runAnomalyCallback isolates one callback invocation: a panicking
// callback is converted into the reference's callback-error event instead
// of taking down the caller.
func runAnomalyCallback(callback func(map[string]any), safe map[string]any, agent AnomalyEventSender, correlationID string) {
	defer func() {
		if r := recover(); r != nil {
			if agent != nil {
				if err := agent.SendAnomalyEvent(BuildCallbackErrorEventData(fmt.Errorf("%v", r), safe, correlationID)); err != nil {
					log.Printf("Failed to send callback-error event to agent: %v", err)
				}
			}
		}
	}()
	callback(safe)
}

// reserveAnomalyEmission mirrors _reserve_anomaly_emission: the
// cooldown is stamped per pattern under the lock; a missing stats entry
// (evicted pattern) always emits and stamps nothing.
func (m *PerformanceMonitor) reserveAnomalyEmission(pattern string) bool {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	stats := m.patternStats[pattern]
	if stats == nil {
		return true
	}
	if stats.HasEmittedAnomaly && now.Sub(stats.LastAnomalyEmittedAt).Seconds() < m.anomalyEmissionCooldown {
		return false
	}
	stats.LastAnomalyEmittedAt = now
	stats.HasEmittedAnomaly = true
	return true
}

// PatternReport is get_pattern_report's dict (build_pattern_report),
// keyed like the reference.
type PatternReport struct {
	Pattern          string  `json:"pattern"`
	PatternHash      string  `json:"pattern_hash"`
	TotalExecutions  int64   `json:"total_executions"`
	TotalMatches     int64   `json:"total_matches"`
	TotalTimeouts    int64   `json:"total_timeouts"`
	MatchRate        float64 `json:"match_rate"`
	TimeoutRate      float64 `json:"timeout_rate"`
	AvgExecutionTime float64 `json:"avg_execution_time"`
	MaxExecutionTime float64 `json:"max_execution_time"`
	MinExecutionTime float64 `json:"min_execution_time"`
}

// round4 mirrors round(x, 4) for report display. math.Round is
// half-away-from-zero where Python's round is banker's rounding; values
// land on 4-decimal display precision either way outside exact .00005
// edges.
func round4(v float64) float64 { return math.Round(v*1e4) / 1e4 }

// GetPatternReport returns the report for one pattern (already
// name-truncated like record_metric), or nil when the pattern was never
// tracked.
func (m *PerformanceMonitor) GetPatternReport(pattern string) *PatternReport {
	pattern = truncatePatternName(pattern)
	m.mu.Lock()
	stats := m.patternStats[pattern]
	m.mu.Unlock()
	if stats == nil {
		return nil
	}
	return buildPatternReport(pattern, stats)
}

func buildPatternReport(pattern string, stats *PatternStats) *PatternReport {
	redacted := RedactPatternSource(pattern)
	minTime := stats.MinExecutionTime
	if minTime == infFloat() {
		minTime = 0
	}
	executions := stats.TotalExecutions
	if executions < 1 {
		executions = 1
	}
	return &PatternReport{
		Pattern:          displayTruncate(redacted),
		PatternHash:      shortPatternHash(redacted),
		TotalExecutions:  stats.TotalExecutions,
		TotalMatches:     stats.TotalMatches,
		TotalTimeouts:    stats.TotalTimeouts,
		MatchRate:        float64(stats.TotalMatches) / float64(executions),
		TimeoutRate:      float64(stats.TotalTimeouts) / float64(executions),
		AvgExecutionTime: round4(stats.AvgExecutionTime),
		MaxExecutionTime: round4(stats.MaxExecutionTime),
		MinExecutionTime: round4(minTime),
	}
}

// GetSlowPatterns returns the reports of the patterns with timing
// samples, slowest average first, capped at limit
// (collect_slow_patterns). Ties order by pattern name descending, like
// the reference's reverse-sorted (avg, pattern) tuples.
func (m *PerformanceMonitor) GetSlowPatterns(limit int) []*PatternReport {
	m.mu.Lock()
	snapshot := make(map[string]*PatternStats, len(m.patternStats))
	for k, v := range m.patternStats {
		snapshot[k] = v
	}
	m.mu.Unlock()
	type avgPattern struct {
		avg     float64
		pattern string
	}
	var withTimes []avgPattern
	for _, pattern := range m.insertionOrderSnapshot() {
		stats := snapshot[pattern]
		if stats != nil && len(stats.RecentTimes) > 0 {
			withTimes = append(withTimes, avgPattern{avg: stats.AvgExecutionTime, pattern: pattern})
		}
	}
	// Reverse-sort by (avg, pattern).
	for i := 0; i < len(withTimes); i++ {
		for j := i + 1; j < len(withTimes); j++ {
			a, b := withTimes[i], withTimes[j]
			if b.avg > a.avg || (b.avg == a.avg && b.pattern > a.pattern) {
				withTimes[i], withTimes[j] = withTimes[j], withTimes[i]
			}
		}
	}
	var reports []*PatternReport
	for _, entry := range withTimes {
		if len(reports) >= limit {
			break
		}
		if report := m.GetPatternReport(entry.pattern); report != nil {
			reports = append(reports, report)
		}
	}
	return reports
}

func (m *PerformanceMonitor) insertionOrderSnapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.insertionOrder...)
}

// ProblematicPattern is a report flagged by GetProblematicPatterns.
type ProblematicPattern struct {
	*PatternReport
	// Issue is "high_timeout_rate" or "consistently_slow".
	Issue string `json:"issue"`
}

// GetProblematicPatterns mirrors collect_problematic_patterns: tracked
// patterns whose timeout rate exceeds 0.1 flag high_timeout_rate, else
// whose average exceeds the slow threshold flag consistently_slow. The
// iteration order is the reference's insertion order.
func (m *PerformanceMonitor) GetProblematicPatterns() []*ProblematicPattern {
	m.mu.Lock()
	order := append([]string{}, m.insertionOrder...)
	snapshot := make(map[string]*PatternStats, len(m.patternStats))
	for k, v := range m.patternStats {
		snapshot[k] = v
	}
	m.mu.Unlock()

	var problematic []*ProblematicPattern
	for _, pattern := range order {
		stats := snapshot[pattern]
		if stats == nil || stats.TotalExecutions == 0 {
			continue
		}
		timeoutRate := float64(stats.TotalTimeouts) / float64(stats.TotalExecutions)
		issue := ""
		if timeoutRate > 0.1 {
			issue = "high_timeout_rate"
		} else if stats.AvgExecutionTime > m.slowPatternThreshold {
			issue = "consistently_slow"
		}
		if issue == "" {
			continue
		}
		if report := m.GetPatternReport(pattern); report != nil {
			problematic = append(problematic, &ProblematicPattern{PatternReport: report, Issue: issue})
		}
	}
	return problematic
}

// SummaryStats is get_summary_stats' dict, keyed like the reference.
type SummaryStats struct {
	TotalExecutions  int     `json:"total_executions"`
	AvgExecutionTime float64 `json:"avg_execution_time"`
	MaxExecutionTime float64 `json:"max_execution_time"`
	MinExecutionTime float64 `json:"min_execution_time"`
	TimeoutRate      float64 `json:"timeout_rate"`
	MatchRate        float64 `json:"match_rate"`
	TotalPatterns    int     `json:"total_patterns"`
}

// EmptySummaryStats mirrors empty_summary.
func EmptySummaryStats() SummaryStats {
	return SummaryStats{}
}

// GetSummaryStats mirrors get_summary_stats over the recent-metric
// window.
func (m *PerformanceMonitor) GetSummaryStats() SummaryStats {
	m.mu.Lock()
	if len(m.recentMetrics) == 0 {
		m.mu.Unlock()
		return EmptySummaryStats()
	}
	snapshot := append([]PerformanceMetric{}, m.recentMetrics...)
	totalPatterns := len(m.patternStats)
	m.mu.Unlock()

	var recentTimes []float64
	timeouts, matches := 0, 0
	for _, metric := range snapshot {
		if metric.Timeout {
			timeouts++
		} else {
			recentTimes = append(recentTimes, metric.ExecutionTime)
		}
		if metric.Matched {
			matches++
		}
	}
	summary := SummaryStats{
		TotalExecutions: len(snapshot),
		TimeoutRate:     float64(timeouts) / float64(len(snapshot)),
		MatchRate:       float64(matches) / float64(len(snapshot)),
		TotalPatterns:   totalPatterns,
	}
	if len(recentTimes) > 0 {
		summary.AvgExecutionTime = meanOf(recentTimes)
		max, min := recentTimes[0], recentTimes[0]
		for _, t := range recentTimes[1:] {
			if t > max {
				max = t
			}
			if t < min {
				min = t
			}
		}
		summary.MaxExecutionTime = max
		summary.MinExecutionTime = min
	}
	return summary
}

// RegisterAnomalyCallback appends a callback invoked with the sanitized
// anomaly for every detected anomaly (register_anomaly_callback).
func (m *PerformanceMonitor) RegisterAnomalyCallback(callback func(sanitized map[string]any)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.anomalyCallbacks = append(m.anomalyCallbacks, callback)
}

// ClearStats resets every per-pattern statistic and the recent history
// (clear_stats).
func (m *PerformanceMonitor) ClearStats() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patternStats = map[string]*PatternStats{}
	m.insertionOrder = nil
	m.recentMetrics = nil
}

// RemovePatternStats drops one pattern's statistics (remove_pattern_stats;
// a missing pattern is a no-op).
func (m *PerformanceMonitor) RemovePatternStats(pattern string) {
	pattern = truncatePatternName(pattern)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.patternStats, pattern)
	for i, tracked := range m.insertionOrder {
		if tracked == pattern {
			m.insertionOrder = append(m.insertionOrder[:i], m.insertionOrder[i+1:]...)
			break
		}
	}
}

// patternSourceEscapeRE decodes the escape spellings a pattern source can
// use to smuggle a sensitive field name past a literal read
// (_PATTERN_SOURCE_ESCAPE_RE).
var patternSourceEscapeRE = regexp.MustCompile(`\\(?:[xX]([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|([0-7]{1,3}))`)

// patternSourceNonTokenRE strips every byte that is not a lowercase
// token character, so "p\s*a\s*s\s*s" still names "pass"
// (_PATTERN_SOURCE_NON_TOKEN_RE, restricted to the ASCII range the
// sensitive-name sets use).
var patternSourceNonTokenRE = regexp.MustCompile(`[^a-z0-9_-]+`)

func decodePatternSourceEscape(seq string) string {
	groups := patternSourceEscapeRE.FindStringSubmatch(seq)
	if groups == nil {
		return seq
	}
	// The escape regex guarantees non-empty, base-valid digit runs, so
	// parsing cannot fail; only the \U range check can reject.
	parse := func(digits string, base int) int64 {
		var code int64
		for _, d := range digits {
			var v int64
			switch {
			case d >= '0' && d <= '9':
				v = int64(d - '0')
			case d >= 'a' && d <= 'f':
				v = int64(d-'a') + 10
			case d >= 'A' && d <= 'F':
				v = int64(d-'A') + 10
			}
			code = code*int64(base) + v
		}
		return code
	}
	var code int64
	if groups[1] != "" || groups[2] != "" || groups[3] != "" {
		digits := groups[1]
		if digits == "" {
			digits = groups[2]
		}
		if digits == "" {
			digits = groups[3]
		}
		code = parse(digits, 16)
	} else {
		code = parse(groups[4], 8)
	}
	if code > 0x10FFFF {
		return seq
	}
	return string(rune(code))
}

// patternSourceNamesASensitiveField mirrors
// _pattern_source_names_a_sensitive_field: escape-decode the source,
// strip non-token characters from the lowercase form, and search for the
// merged sensitive names.
func patternSourceNamesASensitiveField(patternSource string, sensitiveNames map[string]bool) bool {
	decoded := patternSourceEscapeRE.ReplaceAllStringFunc(patternSource, decodePatternSourceEscape)
	normalized := patternSourceNonTokenRE.ReplaceAllString(strings.ToLower(decoded), "")
	for name := range sensitiveNames {
		if name != "" && strings.Contains(normalized, name) {
			return true
		}
	}
	return false
}

// RedactPatternSource mirrors _redact_pattern_source: a pattern whose
// source names any sensitive log field/header collapses to
// "[REDACTED]", otherwise the blob redactor runs over it.
func RedactPatternSource(patternSource string) string {
	sensitiveNames := mergedSensitiveNames(nil, nil, nil)
	if patternSourceNamesASensitiveField(patternSource, sensitiveNames) {
		return RedactedPlaceholder
	}
	return RedactBlobForDisplay(patternSource, nil, nil, nil)
}
