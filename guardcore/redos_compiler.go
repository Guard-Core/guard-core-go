package guardcore

// Port of guard_core.detection_engine.compiler.PatternCompiler's safety
// surface: ValidatePatternSafety reproduces validate_pattern_safety's full
// chain - the dangerous-construct gate, the Python-re compile gate, the
// structural prefilters plus the per-string probe (test_strings mode), and
// the reach-probe cost arbiter (cost_verdict mode).

import (
	"fmt"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

// defaultPatternFlags mirrors the reference validator's
// re.IGNORECASE | re.MULTILINE default.
const defaultPatternFlags = flagIgnoreCase | flagMultiline

// translateForRegexp2 rewrites Python-re syntax the timing engine cannot
// parse into its .NET-flavoured equivalents: \Z -> \z (the mechanical
// rewrite compileRE applies) and (?P<name> / (?P=name) -> (?<name> /
// \k<name>.
func translateForRegexp2(src string) string {
	translated := translatePattern(src)
	var b strings.Builder
	for i := 0; i < len(translated); i++ {
		if translated[i] == '(' && i+2 < len(translated) && translated[i+1] == '?' && translated[i+2] == 'P' {
			if i+3 < len(translated) && translated[i+3] == '<' {
				b.WriteString("(?<")
				i += 3
				continue
			}
			if i+3 < len(translated) && translated[i+3] == '=' {
				// find the closing ')'
				end := strings.IndexByte(translated[i:], ')')
				if end != -1 {
					name := translated[i+4 : i+end]
					b.WriteString("\\k<" + name + ">")
					i += end
					continue
				}
			}
		}
		b.WriteByte(translated[i])
	}
	return b.String()
}

// compileForProbe compiles a validated pattern for the empirical probe
// stages.
func compileForProbe(pattern string, flags reFlags, timeout time.Duration) (*regexp2.Regexp, error) {
	return compileRE(translateForRegexp2(pattern), regexp2OptionsForFlags(flags), timeout)
}

// runPatternSafetyProbe mirrors _run_pattern_safety_probe_subprocess's
// inline verdict: every test string must be searched within the
// per-string threshold.
func runPatternSafetyProbe(pattern string, testStrings []string, flags reFlags) (bool, string) {
	compiled, err := compileForProbe(pattern, flags, patternSafetyProbeTimeout)
	if err != nil {
		return false, "Pattern validation failed: " + err.Error()
	}
	for _, testStr := range testStrings {
		start := time.Now()
		_, err := compiled.FindStringMatch(testStr)
		elapsed := time.Since(start).Seconds()
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "timeout") {
			return false, fmt.Sprintf("Pattern timed out on test string of length %d", len(testStr))
		}
		if elapsed > patternSafetyPerStringThreshold {
			return false, fmt.Sprintf("Pattern timed out on test string of length %d", len(testStr))
		}
	}
	return true, "Pattern appears safe"
}

// ValidatePatternSafety mirrors
// PatternCompiler.validate_pattern_safety: the reference's full safety
// chain for one pattern. testStrings selects the reference's
// test_strings mode (structural prefilters plus the per-string probe);
// otherwise the reach-probe cost arbiter decides. maxContentLength is the
// extrapolation cap (0 selects the reference default); flags select the
// compile-time flags (0 selects the reference defaults).
func ValidatePatternSafety(pattern string, testStrings []string, maxContentLength int, flags reFlags) (bool, string) {
	if flags == 0 {
		flags = defaultPatternFlags
	}
	// Gate 1: dangerous constructs.
	if violation, found := dangerousConstructViolation(pattern); found {
		return false, violation
	}
	// Gate 2: the Python-re compile gate.
	if _, err := parseRedosPattern(pattern, flags); err != nil {
		return false, "Pattern validation failed: " + err.Error()
	}
	if testStrings != nil {
		// Gate 3: structural prefilters decide before the probe.
		if violation, found := firstStructuralSafetyViolation(pattern); found {
			return false, violation
		}
		return runPatternSafetyProbe(pattern, testStrings, flags)
	}
	return reachProbeCostVerdict(pattern, maxContentLength, flags)
}

// ValidatePatternSafetyCost runs the cost-verdict mode with the reference
// default flags.
func ValidatePatternSafetyCost(pattern string, maxContentLength int) (bool, string) {
	return ValidatePatternSafety(pattern, nil, maxContentLength, 0)
}

// ValidatePatternSafetyStrings runs the test-strings mode with the
// reference default flags.
func ValidatePatternSafetyStrings(pattern string, testStrings []string) (bool, string) {
	return ValidatePatternSafety(pattern, testStrings, 0, 0)
}
