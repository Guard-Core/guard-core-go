package guardcore

// Tests mirroring tests/test_sus_patterns/test_compiler.py's safety chain
// surface: ValidatePatternSafety verdicts for the fast classes (gates that
// decide without timing) plus the regexp2 translation helper. The timed
// cost-verdict corpus itself lives in the conformance suite.

import (
	"strings"
	"testing"
)

func TestValidatePatternSafetyDangerous(t *testing.T) {
	for _, pattern := range []string{`(.*)+`, `(.+)+`, `([a-z]+.*)+`, `(\d+)+s`, `(x+x+)+y`, `(a*){2,}`} {
		safe, reason := ValidatePatternSafetyCost(pattern, 10000)
		if safe || !strings.HasPrefix(reason, "Pattern contains dangerous construct: ") {
			t.Fatalf("dangerous verdict wrong for %q: %v %q", pattern, safe, reason)
		}
		safe, reason = ValidatePatternSafetyStrings(pattern, []string{"x"})
		if safe || !strings.HasPrefix(reason, "Pattern contains dangerous construct: ") {
			t.Fatalf("dangerous verdict (strings) wrong for %q: %v %q", pattern, safe, reason)
		}
	}
}

func TestValidatePatternSafetyCompileGate(t *testing.T) {
	for _, pattern := range []string{`[invalid`, `(unclosed`, `*leading`, `(?P<1bad>x)`, `(?>a)+`, `a**`} {
		safe, reason := ValidatePatternSafetyCost(pattern, 10000)
		if safe || !strings.HasPrefix(reason, "Pattern validation failed: ") {
			t.Fatalf("compile verdict wrong for %q: %v %q", pattern, safe, reason)
		}
	}
}

func TestValidatePatternSafetyStructuralStringsMode(t *testing.T) {
	cases := []struct {
		pattern string
		class   string
	}{
		{`'\s*(?:\s+|,)+\s*--`, "structural_nested_unbounded"},
		{`((\d{1,3}\d{1,3}))+$`, "structural_ambiguous_tail"},
		{`.*x.*`, "structural_adjacent_broad"},
		{`<!\[CDATA\[.*?\]\]>`, "structural_unreachable_terminator"},
		{`[\w-]*--`, "structural_literal_absorb"},
	}
	for _, tc := range cases {
		safe, reason := ValidatePatternSafetyStrings(tc.pattern, []string{"abcdefghij", "attack-test-string-123", "x"})
		class := structuralViolationClass(reason)
		if safe || class != tc.class {
			t.Fatalf("structural verdict wrong for %q: safe=%v class=%s (%q)", tc.pattern, safe, class, reason)
		}
	}
}

func TestValidatePatternSafetyStringsProbe(t *testing.T) {
	safe, reason := ValidatePatternSafetyStrings(`'[^']*'`, []string{"abcdefghij", "attack-test-string-123", "x"})
	if !safe || reason != "Pattern appears safe" {
		t.Fatalf("safe probe wrong: %v %q", safe, reason)
	}
}

func TestValidatePatternSafetyFlagsDefault(t *testing.T) {
	// zero flags selects the reference defaults (IgnoreCase|Multiline)
	safe, _ := ValidatePatternSafety(`UNION\s+SELECT`, nil, 10000, 0)
	if !safe {
		t.Fatal("default flags must accept a plain pattern")
	}
}

func TestTranslateForRegexp2(t *testing.T) {
	if got := translateForRegexp2(`a\Zb`); got != `a\zb` {
		t.Fatalf("Z rewrite wrong: %q", got)
	}
	if got := translateForRegexp2(`(?P<name>x)(?P=name)`); got != `(?<name>x)\k<name>` {
		t.Fatalf("named group rewrite wrong: %q", got)
	}
	if got := translateForRegexp2(`plain`); got != "plain" {
		t.Fatalf("plain rewrite wrong: %q", got)
	}
	if got := translateForRegexp2(`(?P=x`); got != `(?P=x` {
		t.Fatalf("unterminated name rewrite wrong: %q", got)
	}
	if _, err := compileForProbe(`(?P<name>x)\Z`, defaultPatternFlags, 0); err != nil {
		t.Fatalf("compileForProbe wrong: %v", err)
	}
}

func TestRunPatternSafetyProbe(t *testing.T) {
	safe, reason := runPatternSafetyProbe(`'[^']*'`, []string{"abcdefghij"}, defaultPatternFlags)
	if !safe || reason != "Pattern appears safe" {
		t.Fatalf("probe wrong: %v %q", safe, reason)
	}
	safe, reason = runPatternSafetyProbe("(unclosed", []string{"x"}, defaultPatternFlags)
	if safe || !strings.HasPrefix(reason, "Pattern validation failed: ") {
		t.Fatalf("probe compile failure wrong: %v %q", safe, reason)
	}
}

func TestRegexp2OptionsForFlags(t *testing.T) {
	opts := regexp2OptionsForFlags(flagIgnoreCase | flagMultiline | flagDotAll)
	if int(opts) == 0 {
		t.Fatal("options wrong")
	}
	if regexp2OptionsForFlags(0) != 0 {
		t.Fatal("empty options wrong")
	}
}

func TestCostVerdictSafeAndHostile(t *testing.T) {
	// fast acceptance: the corpus's linear patterns validate quickly
	safe, reason := ValidatePatternSafetyCost(`hello world`, 10000)
	if !safe || reason != "Pattern appears safe" {
		t.Fatalf("linear cost verdict wrong: %v %q", safe, reason)
	}
	safe, _ = ValidatePatternSafetyCost(`\d{3}-\d{4}`, 10000)
	if !safe {
		t.Fatal("bounded cost verdict wrong")
	}
	safe, _ = ValidatePatternSafetyCost(`^\s*$`, 10000)
	if !safe {
		t.Fatal("anchor cost verdict wrong")
	}
	safe, _ = ValidatePatternSafetyCost(`(?i)union\s+select`, 10000)
	if !safe {
		t.Fatal("inline-flag cost verdict wrong")
	}
	safe, _ = ValidatePatternSafetyCost(`\b(?:foo|bar|baz)\b`, 10000)
	if !safe {
		t.Fatal("alternation cost verdict wrong")
	}
	safe, _ = ValidatePatternSafetyCost(`[a-z]+[0-9]*_?`, 10000)
	if !safe {
		t.Fatal("mixed cost verdict wrong")
	}
}

func TestCostVerdictHostile(t *testing.T) {
	// `\d+/` is outside the corpus contract: on this engine the zeros probe
	// trips the MatchTimeout at both verdict sizes, so the arbiter rejects
	// it with the reference's over-budget reason.
	safe, reason := ValidatePatternSafetyCost(`\d+/`, 10000)
	class := structuralViolationClass(reason)
	if safe || class != "over_budget" {
		t.Fatalf("hostile slash verdict wrong: safe=%v class=%s (%q)", safe, class, reason)
	}
}

func TestCostVerdictDefaultCap(t *testing.T) {
	// maxContentLength 0 selects the reference default cap
	safe, _ := ValidatePatternSafetyCost(`hello world`, 0)
	if !safe {
		t.Fatal("default cap verdict wrong")
	}
}
