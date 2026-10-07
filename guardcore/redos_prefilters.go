package guardcore

// Port of guard_core.detection_engine._redos_structural_prefilters: the
// dangerous-construct gate and the ordered structural safety checks whose
// messages pin the reference verdict classes.

import (
	"regexp"
	"strings"
)

const (
	innerUnboundedQuantifier = `(?:\*|\+|\{[0-9]+,\})`
	outerUnboundedQuantifier = `(?:\+|\{[0-9]+,\})`
)

// The three dangerous-construct regexes mirror _DANGEROUS_CONSTRUCT_PATTERNS
// verbatim (the f-string substitutions inlined).
var dangerousConstructPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\(\.` + innerUnboundedQuantifier + `\)` + outerUnboundedQuantifier),
	regexp.MustCompile(`\([^)]*` + innerUnboundedQuantifier + `\)` + outerUnboundedQuantifier),
	regexp.MustCompile(`(?:\.` + innerUnboundedQuantifier + `){2,}`),
}

// dangerousConstructViolation mirrors _dangerous_construct_violation.
func dangerousConstructViolation(pattern string) (string, bool) {
	for _, dangerous := range dangerousConstructPatterns {
		if dangerous.MatchString(pattern) {
			return "Pattern contains dangerous construct: " + dangerous.String(), true
		}
	}
	return "", false
}

// structuralSafetyCheck is one entry of _STRUCTURAL_SAFETY_CHECKS.
type structuralSafetyCheck struct {
	name    string
	message string
	check   func(pattern string) (string, bool, error)
}

var structuralSafetyChecks = []structuralSafetyCheck{
	{
		name:    "nested_unbounded",
		message: "Pattern contains nested unbounded quantifier: ",
		check:   detectNestedUnboundedQuantifier,
	},
	{
		name:    "adjacent_broad",
		message: "Pattern contains adjacent broad unbounded quantifiers: ",
		check:   detectAdjacentBroadUnboundedQuantifiers,
	},
	{
		name:    "unreachable_terminator",
		message: "Pattern contains a broad scan whose terminator cannot be reached by repeating its own prefix: ",
		check: func(pattern string) (string, bool, error) {
			if finding, found := detectUnreachableTerminatorScan(pattern); found {
				return finding, true, nil
			}
			return "", false, nil
		},
	},
	{
		name:    "literal_absorb",
		message: "Pattern contains a quantified class that can absorb the mandatory literal immediately following it: ",
		check: func(pattern string) (string, bool, error) {
			if finding, found := detectAmbiguousLiteralBoundary(pattern); found {
				return finding, true, nil
			}
			return "", false, nil
		},
	},
	{
		name:    "ambiguous_tail",
		message: "Pattern contains an ambiguous optional tail inside an unbounded quantified group: ",
		check:   detectAmbiguousOptionalTail,
	},
}

// firstStructuralSafetyViolation mirrors
// _first_structural_safety_violation, including the nesting-depth rejection
// reason substitution.
func firstStructuralSafetyViolation(pattern string) (string, bool) {
	for _, check := range structuralSafetyChecks {
		finding, found, err := check.check(pattern)
		if err != nil {
			// GroupNestingTooDeep becomes the reference's rejection reason.
			return nestingDepthRejectionReason, true
		}
		if found {
			return check.message + finding, true
		}
	}
	return "", false
}

// structuralViolationClass maps a violation reason to the reference
// reason_class (the generator's CLASS_RULES order).
func structuralViolationClass(reason string) string {
	switch {
	case strings.Contains(reason, "Pattern contains dangerous construct"):
		return "dangerous_construct"
	case strings.Contains(reason, "Pattern validation failed:"):
		return "compile_failed"
	case strings.Contains(reason, "Pattern contains nested unbounded quantifier"):
		return "structural_nested_unbounded"
	case strings.Contains(reason, "Pattern contains adjacent broad unbounded quantifiers"):
		return "structural_adjacent_broad"
	case strings.Contains(reason, "terminator cannot be reached by"):
		return "structural_unreachable_terminator"
	case strings.Contains(reason, "absorb the mandatory literal"):
		return "structural_literal_absorb"
	case strings.Contains(reason, "ambiguous optional tail"):
		return "structural_ambiguous_tail"
	case strings.Contains(reason, "Pattern timed out on test string"):
		return "probe_string_timeout"
	case strings.Contains(reason, "probe exceeded the"):
		return "probe_subprocess_timeout"
	case strings.Contains(reason, "could not construct a test string that"):
		return "unreachable_probe"
	case strings.Contains(reason, "Pattern extrapolated CPU cost"):
		return "over_budget"
	case strings.Contains(reason, "probe construction exceeded its deadline"):
		return "builder_deadline"
	}
	return "safe"
}
