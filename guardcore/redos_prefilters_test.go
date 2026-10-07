package guardcore

// Tests for the ordered structural prefilters, the dangerous-construct
// gate and the verdict-class mapping (the reference
// _redos_structural_prefilters surface).

import (
	"strings"
	"testing"
)

func TestDangerousConstructViolation(t *testing.T) {
	dangerous := []string{
		`(.*)+`,
		`(.+)+`,
		`([a-z]*)+`,
		`([a-z]+)+`,
		`(\d+)+s`,
		`(a+)+$`,
		`(a*){2,}`,
		`(x+x+)+y`,
		`([a-z]+.*)+`,
		`(.*.*)+`,
	}
	for _, pattern := range dangerous {
		reason, found := dangerousConstructViolation(pattern)
		if !found {
			t.Fatalf("dangerous construct missed: %q", pattern)
		}
		if !hasPrefixCheck(reason, "Pattern contains dangerous construct: ") {
			t.Fatalf("dangerous reason wrong: %q", reason)
		}
	}
	safe := []string{
		`(\d|\w)*;`,
		`(?:\w+\s?)+$`,
		`'[^\']*'`,
	}
	for _, pattern := range safe {
		if _, found := dangerousConstructViolation(pattern); found {
			t.Fatalf("dangerous construct false positive: %q", pattern)
		}
	}
}

func hasPrefixCheck(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestFirstStructuralSafetyViolationOrder(t *testing.T) {
	// nested unbounded outranks the other structural rules
	reason, found := firstStructuralSafetyViolation(`(?:a|aa)+$`)
	if !found || !hasPrefixCheck(reason, "Pattern contains nested unbounded quantifier: ") {
		t.Fatalf("nested unbounded reason wrong: %q", reason)
	}
	reason, found = firstStructuralSafetyViolation(`.*x.*`)
	if !found || !hasPrefixCheck(reason, "Pattern contains adjacent broad unbounded quantifiers: ") {
		t.Fatalf("adjacent broad reason wrong: %q", reason)
	}
	reason, found = firstStructuralSafetyViolation(`foo.*bar`)
	if !found || !hasPrefixCheck(reason, "Pattern contains a broad scan whose terminator cannot be reached by") {
		t.Fatalf("unreachable terminator reason wrong: %q", reason)
	}
	reason, found = firstStructuralSafetyViolation(`[\w-]*--`)
	if !found || !hasPrefixCheck(reason, "Pattern contains a quantified class that can absorb the mandatory literal") {
		t.Fatalf("literal absorb reason wrong: %q", reason)
	}
	reason, found = firstStructuralSafetyViolation(`(?:\w+\s?)+$`)
	if !found || !hasPrefixCheck(reason, "Pattern contains an ambiguous optional tail inside an unbounded quantified group: ") {
		t.Fatalf("ambiguous tail reason wrong: %q", reason)
	}
	if _, found := firstStructuralSafetyViolation(`'[^']*'`); found {
		t.Fatal("safe pattern flagged")
	}
}

func TestStructuralViolationClass(t *testing.T) {
	cases := map[string]string{
		"Pattern contains dangerous construct: x":                                                               "dangerous_construct",
		"Pattern validation failed: oops":                                                                       "compile_failed",
		"Pattern contains nested unbounded quantifier: x":                                                       "structural_nested_unbounded",
		"Pattern contains adjacent broad unbounded quantifiers: a and b":                                        "structural_adjacent_broad",
		"Pattern contains a broad scan whose terminator cannot be reached by repeating its own prefix: x":       "structural_unreachable_terminator",
		"Pattern contains a quantified class that can absorb the mandatory literal immediately following it: x": "structural_literal_absorb",
		"Pattern contains an ambiguous optional tail inside an unbounded quantified group: x":                   "structural_ambiguous_tail",
		"Pattern timed out on test string of length 10":                                                         "probe_string_timeout",
		"Pattern validation probe exceeded the killable-subprocess timeout":                                     "probe_subprocess_timeout",
		"Pattern validation probe could not construct a test string that reaches every quantified region":       "unreachable_probe",
		"Pattern extrapolated CPU cost at cap (10 chars) is 1.000s":                                             "over_budget",
		"Pattern validation probe construction exceeded its deadline":                                           "builder_deadline",
		"Pattern appears safe": "safe",
		"something else":       "safe",
	}
	for reason, want := range cases {
		if got := structuralViolationClass(reason); got != want {
			t.Fatalf("class(%q) = %q, want %q", reason, got, want)
		}
	}
}

func TestFirstStructuralSafetyViolationDepthRejection(t *testing.T) {
	// a deeply nested pattern triggers the reference's depth rejection
	deep := ""
	for i := 0; i < maxGroupNestingDepth+2; i++ {
		deep += "("
	}
	deep += "a"
	for i := 0; i < maxGroupNestingDepth+2; i++ {
		deep += ")"
	}
	reason, found := firstStructuralSafetyViolation(deep)
	// the reference wraps the rejection reason in the first rule's message
	if !found || !strings.Contains(reason, nestingDepthRejectionReason) {
		t.Fatalf("depth rejection wrong: %q", reason)
	}
}

func TestPrefilterChecksAreOrdered(t *testing.T) {
	// the rule table matches the reference order and messages
	wantMessages := []string{
		"Pattern contains nested unbounded quantifier: ",
		"Pattern contains adjacent broad unbounded quantifiers: ",
		"Pattern contains a broad scan whose terminator cannot be reached by repeating its own prefix: ",
		"Pattern contains a quantified class that can absorb the mandatory literal immediately following it: ",
		"Pattern contains an ambiguous optional tail inside an unbounded quantified group: ",
	}
	if len(structuralSafetyChecks) != len(wantMessages) {
		t.Fatalf("check count wrong: %d", len(structuralSafetyChecks))
	}
	for i, check := range structuralSafetyChecks {
		if check.message != wantMessages[i] {
			t.Fatalf("check %d message drifted: %q", i, check.message)
		}
	}
}
