package guardcore

// Tests mirroring tests/test_sus_patterns/test_add_pattern_contract.py,
// test_add_pattern_safety.py and the pattern event corpus cases.

import (
	"testing"
)

func resetSusPatternsForTest(t *testing.T) {
	t.Helper()
	ResetSusPatterns()
	// the reference reset keeps runtime default additions; the tests need
	// the full singleton state cleared between cases
	DefaultSusPatternsManager.mu.Lock()
	DefaultSusPatternsManager.patterns = nil
	DefaultSusPatternsManager.compiled = nil
	// The performance monitor and its anomaly sender are composition-time
	// wiring on the singleton (NewEngine installs them); tests detached
	// from engine construction must not inherit an accumulated monitor or
	// a stale sender.
	DefaultSusPatternsManager.perfMonitor = nil
	DefaultSusPatternsManager.anomalySender = nil
	DefaultSusPatternsManager.mu.Unlock()
	t.Cleanup(func() { ResetSusPatterns() })
}

type susCaptureAgent struct {
	events []SecurityEvent
}

func (a *susCaptureAgent) SendEvent(event SecurityEvent) error {
	a.events = append(a.events, event)
	return nil
}

func (a *susCaptureAgent) SendMetric(metric SecurityMetric) error {
	return nil
}

func TestAddPatternContract(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager

	if !m.AddPattern("corpuspattern-[a-z]+", true) {
		t.Fatal("safe custom pattern rejected")
	}
	customs := m.GetCustomPatterns()
	if len(customs) != 1 || customs[0] != "corpuspattern-[a-z]+" {
		t.Fatalf("custom set wrong: %v", customs)
	}
	// the custom set dedupes
	if !m.AddPattern("corpuspattern-[a-z]+", true) {
		t.Fatal("re-add should succeed")
	}
	if len(m.GetCustomPatterns()) != 1 {
		t.Fatalf("custom set should dedupe: %v", m.GetCustomPatterns())
	}
	// default additions append and are distinct from customs
	if !m.AddPattern("corpuspattern2-[a-z]+", false) {
		t.Fatal("safe default pattern rejected")
	}
	if got := m.GetDefaultPatterns(); len(got) != 1 {
		t.Fatalf("default list wrong: %v", got)
	}
	all := m.GetAllPatterns()
	if len(all) != 2 {
		t.Fatalf("all patterns wrong: %v", all)
	}
}

func TestAddPatternSafetyRejection(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager

	for _, pattern := range []string{`(.*)+`, `(a+)+$`, `*leading`, `(unclosed`} {
		if m.AddPattern(pattern, true) {
			t.Fatalf("unsafe pattern accepted: %q", pattern)
		}
	}
	if len(m.GetCustomPatterns()) != 0 {
		t.Fatalf("rejected patterns leaked into the registry: %v", m.GetCustomPatterns())
	}
}

func TestRemovePattern(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager

	m.AddPattern("corpuspattern-[a-z]+", true)
	if !m.RemovePattern("corpuspattern-[a-z]+", true) {
		t.Fatal("custom removal failed")
	}
	if len(m.GetCustomPatterns()) != 0 {
		t.Fatalf("custom removal left patterns: %v", m.GetCustomPatterns())
	}
	// removing an unknown pattern reports false
	if m.RemovePattern("corpuspattern-[a-z]+", true) {
		t.Fatal("removing an absent pattern reported success")
	}
	// default removal
	m.AddPattern("defpattern-[a-z]+", false)
	if !m.RemovePattern("defpattern-[a-z]+", false) {
		t.Fatal("default removal failed")
	}
	if len(m.GetDefaultPatterns()) != 0 {
		t.Fatalf("default removal left patterns: %v", m.GetDefaultPatterns())
	}
}

func TestPatternEvents(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	agent := &susCaptureAgent{}
	m.SetAgentHandler(agent)
	defer m.SetAgentHandler(nil)

	m.AddPattern("corpuspattern-[a-z]+", true)
	if len(agent.events) != 1 {
		t.Fatalf("pattern_added event missing: %d", len(agent.events))
	}
	added := agent.events[0]
	if added.EventType != EventPatternAdded || added.IPAddress != "system" ||
		added.ActionTaken != "pattern_added" ||
		added.Reason != "Custom pattern added to detection system" ||
		added.HandlerName != susPatternsHandlerName {
		t.Fatalf("pattern_added envelope wrong: %+v", added)
	}
	if added.PatternMatched != "" {
		t.Fatalf("pattern_matched should be absent on add events: %q", added.PatternMatched)
	}
	if added.Metadata["pattern"] != "corpuspattern-[a-z]+" ||
		added.Metadata["pattern_type"] != "custom" {
		t.Fatalf("pattern_added metadata wrong: %v", added.Metadata)
	}
	if added.Metadata["total_patterns"] != 1 {
		t.Fatalf("total_patterns wrong: %v", added.Metadata["total_patterns"])
	}

	agent.events = nil
	if !m.RemovePattern("corpuspattern-[a-z]+", true) {
		t.Fatal("removal failed")
	}
	if len(agent.events) != 1 {
		t.Fatalf("pattern_removed event missing: %d", len(agent.events))
	}
	removed := agent.events[0]
	if removed.EventType != EventPatternRemoved ||
		removed.Reason != "Custom pattern removed from detection system" {
		t.Fatalf("pattern_removed envelope wrong: %+v", removed)
	}
	if removed.Metadata["total_patterns"] != 0 {
		t.Fatalf("removed total_patterns wrong: %v", removed.Metadata["total_patterns"])
	}

	// a failed removal emits nothing
	agent.events = nil
	m.RemovePattern("absent-pattern", true)
	if len(agent.events) != 0 {
		t.Fatalf("failed removal emitted events: %d", len(agent.events))
	}
}

func TestDetectPatternMatch(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager

	safe, _ := m.DetectPatternMatch("hello world", "203.0.113.7", "request_body", "")
	if safe {
		t.Fatal("benign content matched")
	}
	matched, pattern := m.DetectPatternMatch("<script>alert(1)</script>", "203.0.113.7", "request_body", "")
	if !matched {
		t.Fatal("xss payload not matched")
	}
	if pattern == "" || pattern == "unknown" {
		t.Fatalf("matched pattern identity wrong: %q", pattern)
	}
	// runtime custom patterns participate in detection
	m.AddPattern("corpuspattern-[a-z]+", true)
	matched, pattern = m.DetectPatternMatch("attack corpuspattern-abc here", "203.0.113.7", "request_body", "")
	if !matched || pattern != "corpuspattern-[a-z]+" {
		t.Fatalf("custom pattern detection wrong: %v %q", matched, pattern)
	}
}

func TestDetectEmitsPatternDetected(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	agent := &susCaptureAgent{}
	m.SetAgentHandler(agent)
	defer m.SetAgentHandler(nil)

	m.Detect("<script>alert(1)</script>", "203.0.113.7", "request_body", "corr-1")
	if len(agent.events) != 1 {
		t.Fatalf("pattern_detected event missing: %d", len(agent.events))
	}
	event := agent.events[0]
	if event.EventType != EventPatternDetected ||
		event.IPAddress != "203.0.113.7" ||
		event.ActionTaken != "threat_detected" ||
		event.Reason != "Threat detected in request_body" ||
		event.HandlerName != susPatternsHandlerName {
		t.Fatalf("pattern_detected envelope wrong: %+v", event)
	}
	if event.PatternMatched == "" {
		t.Fatal("pattern_matched missing")
	}
	for _, key := range []string{"pattern", "context", "content_preview", "threat_score",
		"threats", "regex_threats", "semantic_threats", "timeouts", "detection_method",
		"threat_categories", "category"} {
		if _, ok := event.Metadata[key]; !ok {
			t.Fatalf("metadata key %s missing: %v", key, event.Metadata)
		}
	}
	if event.Metadata["context"] != "request_body" {
		t.Fatalf("context metadata wrong: %v", event.Metadata["context"])
	}
	if event.Metadata["content_preview"] != "<script>alert(1)</script>" {
		t.Fatalf("content preview wrong: %v", event.Metadata["content_preview"])
	}
	if event.Metadata["correlation_id"] != "corr-1" {
		t.Fatalf("correlation id wrong: %v", event.Metadata["correlation_id"])
	}

	// benign content emits nothing
	agent.events = nil
	m.Detect("hello world", "203.0.113.7", "request_body", "")
	if len(agent.events) != 0 {
		t.Fatalf("benign detection emitted events: %d", len(agent.events))
	}
}

func TestSusPatternsManagerReset(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	m.AddPattern("corpuspattern-[a-z]+", true)
	m.Reset()
	if len(m.GetCustomPatterns()) != 0 {
		t.Fatalf("reset left customs: %v", m.GetCustomPatterns())
	}
	if m.currentAgentHandler() != nil {
		t.Fatal("reset left the agent handler attached")
	}
}

func TestCollectThreatCategories(t *testing.T) {
	threats := []map[string]any{
		{"type": "regex", "category": "xss"},
		{"type": "regex", "category": "xss"},
		{"type": "semantic", "attack_type": "sqli"},
		{"type": "regex"},
	}
	got := collectThreatCategories(threats)
	if len(got) != 2 || got[0] != "xss" || got[1] != "sqli" {
		t.Fatalf("categories wrong: %v", got)
	}
}
