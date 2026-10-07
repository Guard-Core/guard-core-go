package conformance

// pattern_safety-kind conformance suite (spec 4.1.0, safety_gates.json):
// the reference oracle is guard_core.detection_engine.compiler.
// PatternCompiler.validate_pattern_safety, whose verdict classes are the
// reference's full safety chain: the dangerous-construct gate, the compile
// gate, the structural ReDoS prefilters, the subprocess probe on the given
// test strings and the reach-probe cost arbiter.
//
// The Go engine ships the ported chain (guardcore.ValidatePatternSafety):
// the dangerous-construct gate and the ordered structural prefilters are
// direct ports of _redos_structural_prefilters, the compile gate is a
// Python-re-compatible parser (the reference oracle's grammar, which
// rejects constructs regexp2 alone accepts, e.g. atomic groups), and the
// reach-probe cost arbiter ports _redos_cost_arbiter with regexp2 as the
// timing engine under a MatchTimeout kill switch. Every corpus case must
// reproduce the reference verdict: the same safe/reject decision and the
// same reason class. There is no xfail registry for this suite by design:
// a divergence is red, and re-introducing a baseline file is red too.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const safetyXfailFile = "guard-core-spec-4.1.0/go_safety_xfail.json"

type safetySuiteFile struct {
	Suite string       `json:"suite"`
	Kind  string       `json:"kind"`
	Cases []safetyCase `json:"cases"`
}

type safetyCase struct {
	ID    string `json:"id"`
	Input struct {
		Pattern          string   `json:"pattern"`
		Mode             string   `json:"mode"`
		TestStrings      []string `json:"test_strings"`
		MaxContentLength int      `json:"max_content_length"`
	} `json:"input"`
	Expected struct {
		Safe        bool   `json:"safe"`
		ReasonClass string `json:"reason_class"`
	} `json:"expected"`
}

// classifySafetyReason mirrors the corpus generator's CLASS_RULES: the
// reason string prefix decides the reason_class.
func classifySafetyReason(reason string) string {
	rules := []struct {
		prefix string
		class  string
	}{
		{"Pattern contains dangerous construct", "dangerous_construct"},
		{"Pattern validation failed:", "compile_failed"},
		{"Pattern contains nested unbounded quantifier", "structural_nested_unbounded"},
		{"Pattern contains adjacent broad unbounded quantifiers", "structural_adjacent_broad"},
		{"terminator cannot be reached by", "structural_unreachable_terminator"},
		{"absorb the mandatory literal", "structural_literal_absorb"},
		{"ambiguous optional tail", "structural_ambiguous_tail"},
		{"Pattern timed out on test string", "probe_string_timeout"},
		{"probe exceeded the", "probe_subprocess_timeout"},
		{"could not construct a test string that", "unreachable_probe"},
		{"Pattern extrapolated CPU cost", "over_budget"},
		{"probe construction exceeded its deadline", "builder_deadline"},
		{"Pattern appears safe", "safe"},
	}
	for _, rule := range rules {
		if strings.Contains(reason, rule.prefix) {
			return rule.class
		}
	}
	return "other"
}

// runSafetyCase maps one corpus case onto the ported validator and
// reproduces the reference verdict. The returned string is empty when the
// case reproduced the reference verdict, otherwise a diff.
func runSafetyCase(c safetyCase) string {
	var (
		safe     bool
		reason   string
		modifier = "cost"
	)
	switch c.Input.Mode {
	case "test_strings":
		modifier = "test_strings"
		safe, reason = guardcore.ValidatePatternSafetyStrings(c.Input.Pattern, c.Input.TestStrings)
	default:
		safe, reason = guardcore.ValidatePatternSafetyCost(c.Input.Pattern, c.Input.MaxContentLength)
	}
	gotClass := classifySafetyReason(reason)
	if safe == c.Expected.Safe && gotClass == c.Expected.ReasonClass {
		return ""
	}
	return fmt.Sprintf("FAIL %s mode: got safe=%v class=%s (reason %q), want safe=%v class=%s",
		modifier, safe, gotClass, reason, c.Expected.Safe, c.Expected.ReasonClass)
}

// TestPatternSafetyConformance runs the full safety_gates corpus against
// the ported safety chain. Fail-closed: any verdict divergence fails, and
// the deleted xfail registry must stay deleted.
func TestPatternSafetyConformance(t *testing.T) {
	if _, err := os.Stat(safetyXfailFile); err == nil {
		t.Fatalf("xfail registry %s must not exist: the ported safety chain must reproduce every reference verdict; a re-added baseline is an xfail regression", safetyXfailFile)
	}
	path := filepath.Join(corpusCasesDir, "safety_gates.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var suite safetySuiteFile
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	if suite.Kind != "pattern_safety" {
		t.Fatalf("suite kind drifted: %q", suite.Kind)
	}
	if len(suite.Cases) == 0 {
		t.Fatal("safety_gates corpus matched zero cases: a vacuous pass is a failure")
	}

	total, passed := 0, 0
	var failures []string
	for _, c := range suite.Cases {
		total++
		if outcome := runSafetyCase(c); outcome != "" {
			failures = append(failures, fmt.Sprintf("%s: %s", suite.Suite+"/"+c.ID, outcome))
			continue
		}
		passed++
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		t.Fatalf("pattern_safety conformance drift: %d failures over %d cases\n%s", len(failures), total, strings.Join(failures, "\n"))
	}
	t.Logf("pattern_safety conformance gate: %d passed, 0 divergences, 0 stale baselines, %d cases (spec %s)", passed, total, corpusSpecVersion)
}
