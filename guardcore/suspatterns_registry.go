package guardcore

// Port of guard_core/handlers/_suspatterns_registry.py (the
// SusPatternsManager registry mixin) plus the manager's telemetry surface:
// the runtime sus-pattern registry with add/remove, the pattern_added /
// pattern_removed / pattern_detected handler-direct events, the
// detect_pattern_match probe and the Redis-persisted custom patterns.
//
// The reference manager is a module singleton (sus_patterns_handler =
// SusPatternsManager()); the port binds one package default
// (DefaultSusPatternsManager) at composition time, the same
// singleton-to-package-default idiom the cloud manager uses.

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
)

const susPatternsHandlerName = "sus_patterns"

// susPatternEntry is one runtime-registered pattern with its compiled
// engine (the reference's (re.Pattern, contexts, category) tuple folded to
// the parts the scan consumes; runtime entries scan every context, the
// reference's _CTX_ALL, with the "custom" category).
type susPatternEntry struct {
	source string
	re     *regexp2.Regexp
}

// SusPatternsManager is the runtime sus-pattern registry.
type SusPatternsManager struct {
	mu sync.RWMutex
	// patterns/compiled hold runtime additions registered with custom=false
	// (the shipped corpus is the compile-time table these ride beside).
	patterns []string
	compiled []susPatternEntry
	// customPatterns is the deduplicated custom set plus its insertion
	// order (the reference keeps a set for membership and renders it
	// comma-joined into Redis).
	customPatterns map[string]bool
	customOrder    []string
	compiledCustom []susPatternEntry
	redisHandler   RedisHandler
	agentHandler   AgentHandler
	log            *log.Logger
	// perfMonitor is the detection performance monitor wired from the
	// six detection knobs at composition (the reference detection state
	// carries the monitor _build_enhanced_detection_state builds); Detect
	// records the overall_detection metric into it.
	perfMonitor   *PerformanceMonitor
	anomalySender AnomalyEventSender
}

// DefaultSusPatternsManager mirrors the reference module singleton.
var DefaultSusPatternsManager = NewSusPatternsManager(nil)

// NewSusPatternsManager builds a manager; a nil logger defaults to the
// standard logger.
func NewSusPatternsManager(logger *log.Logger) *SusPatternsManager {
	if logger == nil {
		logger = log.Default()
	}
	return &SusPatternsManager{
		customPatterns: map[string]bool{},
		log:            logger,
	}
}

// SetAgentHandler attaches the telemetry sink (the reference
// initialize_agent); a nil handler makes the pattern events inert.
func (m *SusPatternsManager) SetAgentHandler(handler AgentHandler) {
	m.mu.Lock()
	m.agentHandler = handler
	m.mu.Unlock()
}

// SetPerformanceMonitor attaches the detection performance monitor and
// its anomaly event sink (the reference detection state carrying the
// monitor and record_metric's agent_handler argument); a nil monitor
// silences the metrics.
func (m *SusPatternsManager) SetPerformanceMonitor(monitor *PerformanceMonitor, sender AnomalyEventSender) {
	m.mu.Lock()
	m.perfMonitor = monitor
	m.anomalySender = sender
	m.mu.Unlock()
}

// InitializeRedis attaches the Redis handler and restores the persisted
// custom patterns (the reference initialize_redis: a comma-joined
// "patterns/custom" key; unrestorable entries log and skip).
func (m *SusPatternsManager) InitializeRedis(handler RedisHandler) {
	m.mu.Lock()
	m.redisHandler = handler
	m.mu.Unlock()
	if handler == nil {
		return
	}
	cached, err := handler.GetKey("patterns", "custom")
	if err != nil || cached == "" {
		return
	}
	for _, pattern := range strings.Split(cached, ",") {
		if pattern == "" {
			continue
		}
		m.mu.RLock()
		known := m.customPatterns[pattern]
		m.mu.RUnlock()
		if known {
			continue
		}
		if !m.AddPattern(pattern, true) {
			m.log.Printf("Skipped restoring persisted pattern: %s...", truncateRunes(RedactPatternSource(pattern), 50))
		}
	}
}

// AddPattern validates the pattern through the ReDoS safety chain, then
// registers it (custom entries dedupe and persist through Redis; default
// entries append). Rejections log the redacted source and return false.
func (m *SusPatternsManager) AddPattern(pattern string, custom bool) bool {
	// The empirical cost probe routes through the configured disk cache
	// when detection_pattern_validation_cache_path is set (the reference
	// PatternValidationCache): the deterministic gates always re-run.
	if safe, reason := validatePatternSafetyCostCached(pattern, DefaultConfig().MaxBodyInspectBytes); !safe {
		m.log.Printf("Rejected unsafe pattern (%s): %s...", reason, truncateRunes(RedactPatternSource(pattern), 50))
		return false
	}
	compiled, err := compileRE(pattern, regexp2.IgnoreCase, windowTimeout)
	if err != nil {
		m.log.Printf("Rejected uncompilable pattern: %s...: %v", truncateRunes(RedactPatternSource(pattern), 50), err)
		return false
	}

	m.mu.Lock()
	entry := susPatternEntry{source: pattern, re: compiled}
	var total int
	if custom {
		if !m.customPatterns[pattern] {
			m.customPatterns[pattern] = true
			m.customOrder = append(m.customOrder, pattern)
			m.compiledCustom = append(m.compiledCustom, entry)
		}
		total = len(m.customOrder)
		if m.redisHandler != nil {
			if err := m.redisHandler.SetKey("patterns", "custom", strings.Join(m.customOrder, ","), nil); err != nil {
				m.log.Printf("Failed to persist custom pattern: %v", err)
			}
		}
	} else {
		m.patterns = append(m.patterns, pattern)
		m.compiled = append(m.compiled, entry)
		total = len(m.patterns)
	}
	m.mu.Unlock()

	m.sendPatternEvent(EventPatternAdded, "system", "pattern_added",
		fmt.Sprintf("%s pattern added to detection system", patternKindCapitalized(custom)),
		RedactPatternSource(pattern), patternKind(custom), total)
	return true
}

// RemovePattern drops a runtime pattern; custom removals persist through
// Redis. Unknown patterns return false.
func (m *SusPatternsManager) RemovePattern(pattern string, custom bool) bool {
	removed := false
	var total int
	m.mu.Lock()
	if custom {
		if m.customPatterns[pattern] {
			delete(m.customPatterns, pattern)
			for i, p := range m.customOrder {
				if p == pattern {
					m.customOrder = append(m.customOrder[:i], m.customOrder[i+1:]...)
					break
				}
			}
			kept := m.compiledCustom[:0]
			for _, entry := range m.compiledCustom {
				if entry.source != pattern {
					kept = append(kept, entry)
				}
			}
			m.compiledCustom = kept
			removed = true
		}
		total = len(m.customOrder)
		if removed && m.redisHandler != nil {
			if err := m.redisHandler.SetKey("patterns", "custom", strings.Join(m.customOrder, ","), nil); err != nil {
				m.log.Printf("Failed to persist custom pattern removal: %v", err)
			}
		}
	} else {
		for i, p := range m.patterns {
			if p == pattern {
				m.patterns = append(m.patterns[:i], m.patterns[i+1:]...)
				if i < len(m.compiled) {
					m.compiled = append(m.compiled[:i], m.compiled[i+1:]...)
					removed = true
				}
				break
			}
		}
		total = len(m.patterns)
	}
	m.mu.Unlock()

	if !removed {
		return false
	}
	m.sendPatternEvent(EventPatternRemoved, "system", "pattern_removed",
		fmt.Sprintf("%s pattern removed from detection system", patternKindCapitalized(custom)),
		RedactPatternSource(pattern), patternKind(custom), total)
	return true
}

// GetDefaultPatterns returns the runtime-registered default patterns.
func (m *SusPatternsManager) GetDefaultPatterns() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.patterns...)
}

// GetCustomPatterns returns the custom pattern set in insertion order.
func (m *SusPatternsManager) GetCustomPatterns() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.customOrder...)
}

// GetAllPatterns returns the runtime additions (defaults then customs).
func (m *SusPatternsManager) GetAllPatterns() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append(append([]string{}, m.patterns...), m.customOrder...)
}

// ClearCustomPatterns empties the custom set and its compiled entries
// (the reference harness seeding shape).
func (m *SusPatternsManager) ClearCustomPatterns() {
	m.mu.Lock()
	m.customPatterns = map[string]bool{}
	m.customOrder = nil
	m.compiledCustom = nil
	m.mu.Unlock()
}

// SeedCustomPattern registers a pattern directly, bypassing validation and
// telemetry (the reference harness seeding the registry before a removal
// case; not a user-facing path).
func (m *SusPatternsManager) SeedCustomPattern(pattern string) {
	compiled, err := compileRE(pattern, regexp2.IgnoreCase, windowTimeout)
	if err != nil {
		return
	}
	m.mu.Lock()
	if m.customPatterns == nil {
		m.customPatterns = map[string]bool{}
	}
	m.customPatterns[pattern] = true
	m.customOrder = append(m.customOrder, pattern)
	m.compiledCustom = append(m.compiledCustom, susPatternEntry{source: pattern, re: compiled})
	m.mu.Unlock()
}

// Reset clears the custom patterns and detaches the handlers (the
// reference reset; the shipped corpus is compile-time and unaffected).
func (m *SusPatternsManager) Reset() {
	m.mu.Lock()
	m.customPatterns = map[string]bool{}
	m.customOrder = nil
	m.compiledCustom = nil
	m.redisHandler = nil
	m.agentHandler = nil
	m.mu.Unlock()
}

// DetectPatternMatch mirrors detect_pattern_match: one detection pass and
// the first threat's identity (a redacted pattern source for regex hits,
// "semantic:<attack_type>" for semantic hits, "unknown" otherwise).
func (m *SusPatternsManager) DetectPatternMatch(content, ip, context, correlationID string) (bool, string) {
	result := m.Detect(content, ip, context, correlationID)
	if !result.IsThreat {
		return false, ""
	}
	if len(result.Threats) > 0 {
		threat := result.Threats[0]
		if threat["type"] == "regex" {
			if pattern, ok := threat["pattern"].(string); ok {
				return true, RedactPatternSource(pattern)
			}
		} else if threat["type"] == "semantic" {
			if attackType, ok := threat["attack_type"].(string); ok {
				return true, "semantic:" + attackType
			}
		}
	}
	return true, "unknown"
}

// Detect runs the shipped corpus scan plus the runtime registry and emits
// the reference's pattern_detected telemetry when the agent handler is
// attached (the manager detect() flow).
func (m *SusPatternsManager) Detect(content, ip, context, correlationID string) DetectResult {
	start := time.Now()
	result := Detect(content, ip, context)

	customThreats := m.scanCustomPatterns(content)
	regexCount, semanticCount := 0, 0
	for _, threat := range append(append([]map[string]any{}, result.Threats...), customThreats...) {
		if threat["type"] == "semantic" {
			semanticCount++
		} else {
			regexCount++
		}
	}

	threats := result.Threats
	if len(customThreats) > 0 {
		threats = append(append([]map[string]any{}, result.Threats...), customThreats...)
		result.Threats = threats
		result.IsThreat = true
		result.ThreatScore += float64(len(customThreats))
	}

	// The reference detect() records the overall_detection metric once
	// per pass into the configured performance monitor (total elapsed
	// time, content length, matched, no timeout).
	m.mu.RLock()
	monitor := m.perfMonitor
	m.mu.RUnlock()
	if monitor != nil {
		monitor.RecordMetric(MetricObservation{
			Pattern:       "overall_detection",
			ExecutionTime: time.Since(start).Seconds(),
			ContentLength: len(content),
			Matched:       result.IsThreat,
			Timeout:       false,
			Agent:         agentHandlerAnomalySender{handler: m.currentAgentHandler()},
			CorrelationID: correlationID,
		})
	}

	if m.currentAgentHandler() == nil || !result.IsThreat {
		return result
	}

	matchedPattern := "unknown"
	for _, threat := range threats {
		if threat["type"] == "regex" {
			if p, ok := threat["pattern"].(string); ok {
				matchedPattern = p
			}
			break
		}
	}
	patternMatched := RedactPatternSource(matchedPattern)

	preview := content
	if len([]rune(preview)) > 100 {
		preview = truncateRunes(preview, 100)
	}
	categories := collectThreatCategories(threats)
	metadata := map[string]any{
		"pattern":           patternMatched,
		"context":           context,
		"content_preview":   preview,
		"threat_score":      result.ThreatScore,
		"threats":           len(threats),
		"regex_threats":     regexCount,
		"semantic_threats":  semanticCount,
		"timeouts":          0,
		"detection_method":  result.DetectionMethod,
		"execution_time_ms": int(time.Since(start).Milliseconds()),
		"threat_categories": categories,
	}
	if correlationID != "" {
		metadata["correlation_id"] = correlationID
	}
	if len(categories) > 0 {
		metadata["category"] = categories[0]
	}
	m.sendEvent(EventPatternDetected, ip, "threat_detected",
		"Threat detected in "+context, patternMatched, metadata)
	return result
}

// scanCustomPatterns runs the runtime registry over the content (the
// reference _scan_for_threats consulting compiled_patterns plus
// compiled_custom_patterns; runtime entries match every context).
func (m *SusPatternsManager) scanCustomPatterns(content string) []map[string]any {
	m.mu.RLock()
	entries := make([]susPatternEntry, 0, len(m.compiled)+len(m.compiledCustom))
	entries = append(entries, m.compiled...)
	entries = append(entries, m.compiledCustom...)
	m.mu.RUnlock()

	var threats []map[string]any
	rs := []rune(content)
	for _, entry := range entries {
		match, err := entry.re.FindRunesMatchStartingAt(rs, 0)
		if err != nil || match == nil {
			continue
		}
		threats = append(threats, map[string]any{
			"type":     "regex",
			"pattern":  entry.source,
			"match":    match.String(),
			"position": match.Index,
			"category": "custom",
			"weight":   1.0,
		})
	}
	return threats
}

func (m *SusPatternsManager) currentAgentHandler() AgentHandler {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.agentHandler
}

// sendPatternEvent emits the pattern_added / pattern_removed envelopes
// (the reference _send_pattern_event).
func (m *SusPatternsManager) sendPatternEvent(eventType, ip, actionTaken, reason, pattern, patternType string, total int) {
	m.sendEvent(eventType, ip, actionTaken, reason, "", map[string]any{
		"pattern":        pattern,
		"pattern_type":   patternType,
		"total_patterns": total,
	})
}

// sendEvent is the reference _send_pattern_event: a handler-direct
// SecurityEvent with the sus_patterns handler name.
func (m *SusPatternsManager) sendEvent(eventType, ip, actionTaken, reason, patternMatched string, metadata map[string]any) {
	handler := m.currentAgentHandler()
	if handler == nil {
		return
	}
	event := SecurityEvent{
		EventType:      eventType,
		IPAddress:      ip,
		ActionTaken:    actionTaken,
		Reason:         reason,
		PatternMatched: patternMatched,
		HandlerName:    susPatternsHandlerName,
		Metadata:       metadata,
	}
	if err := handler.SendEvent(event); err != nil {
		m.log.Printf("Failed to send pattern event to agent: %v", err)
	}
}

func patternKind(custom bool) string {
	if custom {
		return "custom"
	}
	return "default"
}

func patternKindCapitalized(custom bool) string {
	if custom {
		return "Custom"
	}
	return "Default"
}

// collectThreatCategories mirrors _collect_threat_categories: the threats'
// categories in first-seen order (regex threats carry category, semantic
// threats their attack type).
func collectThreatCategories(threats []map[string]any) []string {
	var categories []string
	seen := map[string]bool{}
	for _, threat := range threats {
		var category string
		switch threat["type"] {
		case "regex":
			category, _ = threat["category"].(string)
		case "semantic":
			category, _ = threat["attack_type"].(string)
		}
		if category == "" || seen[category] {
			continue
		}
		seen[category] = true
		categories = append(categories, category)
	}
	return categories
}

func truncateRunes(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit])
}

// ResetSusPatterns resets the package-default manager (the test and
// composition reset seam for the singleton).
func ResetSusPatterns() {
	DefaultSusPatternsManager.Reset()
}
