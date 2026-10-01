package conformance

// pattern_safety-kind conformance suite (spec 4.1.0, safety_gates.json):
// the reference oracle is guard_core.detection_engine.compiler.
// PatternCompiler.validate_pattern_safety, whose verdict classes are the
// reference's full safety chain: the dangerous-construct gate, the compile
// gate, the structural ReDoS prefilters, the subprocess probe on the given
// test strings and the reach-probe cost arbiter.
//
// The Go engine's pattern validation is the shipped compile path (regexp2
// behind guardcore.compileRE: translatePattern's \\Z rewrite, IgnoreCase,
// a 2s MatchTimeout) plus the timeout verdict at match time; it has no
// structural or cost-arbiter chain. The runner therefore maps honestly per
// the corpus comparison contract (index.json > comparison >
// pattern_safety_records):
//
//   - safe verdicts: the engine-acceptance mapping. The shipped engine
//     must compile the pattern and execute it over every corpus test
//     string without a MatchTimeout trip. A reference-safe pattern the
//     shipped engine rejects or times out is a real (red) divergence.
//   - compile_failed verdicts: the shipped compile path must reject the
//     pattern too. Grammar differences between Python re and regexp2 land
//     in the fail-closed baseline with a per-case reason.
//   - every other reason_class (dangerous_construct, structural_*,
//     over_budget): the Go engine cannot produce the class. Each case is
//     recorded in go_safety_xfail.json with the class's documented
//     divergence reason tied to the Go source; the baseline is
//     fail-closed: an unbaselined failure is red, a baselined case that
//     starts producing the reference verdict is red (stale), and a
//     baselined case that never ran is red.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
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

// compileShippedEngine mirrors the shipped engine's pattern compile path
// for validation verdicts: translatePattern's \\Z rewrite (the same
// mechanical rewrite guardcore.compileRE applies, shared with the pattern
// ledger), the reference validate flags (re.IGNORECASE | re.MULTILINE),
// and the corpus detection_compiler_timeout knob (2s) as the MatchTimeout.
func compileShippedEngine(pattern string) (*regexp2.Regexp, error) {
	translated, _ := translatePatternZ(pattern)
	re, err := regexp2.Compile(translated, regexp2.IgnoreCase|regexp2.Multiline)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = 2 * time.Second
	return re, nil
}

func isMatchTimeoutErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Timeout")
}

// runSafetyCase maps one corpus case onto the shipped engine's validation
// surface. The returned string is empty when the case reproduced the
// reference verdict, the recorded divergence reason when the case maps to
// a documented class divergence, and a "FAIL " prefixed diff when the
// engine must reproduce the verdict but did not.
func runSafetyCase(c safetyCase) string {
	re, compileErr := compileShippedEngine(c.Input.Pattern)
	switch {
	case c.Expected.ReasonClass == "compile_failed":
		if compileErr != nil {
			// The shipped engine rejects the pattern at compile time,
			// reproducing the reference verdict.
			return ""
		}
		return "DIVERGENCE the shipped regexp2 engine compiles what Python re rejects (grammar difference); the compile_failed verdict is not reproducible"
	case c.Expected.Safe:
		// reason_class "safe": the engine-acceptance mapping. A
		// reference-safe pattern must compile and run within budget.
		if compileErr != nil {
			return fmt.Sprintf("FAIL reference-safe pattern rejected by the shipped engine: %v", compileErr)
		}
		if c.Input.Mode == "test_strings" {
			for _, probe := range c.Input.TestStrings {
				if _, err := re.FindStringMatch(probe); isMatchTimeoutErr(err) {
					return fmt.Sprintf("FAIL reference-safe pattern tripped the MatchTimeout on test string %q: %v", probe, err)
				}
			}
		}
		return ""
	default:
		// unsafe verdicts whose class the shipped chain cannot produce:
		// recorded per case in the fail-closed baseline.
		return "DIVERGENCE " + safetyClassDivergence(c.Expected.ReasonClass)
	}
}

// safetyClassDivergence ties every non-reproducible reason_class to the Go
// source fact that explains it.
func safetyClassDivergence(class string) string {
	switch class {
	case "dangerous_construct":
		return "the shipped engine is a backtracking regexp2 build behind guardcore.compileRE (guardcore/engine.go) with a 2s MatchTimeout; the reference dangerous-construct gate (_redos_structural_prefilters._dangerous_construct_violation) has no Go counterpart because regexp2 executes those constructs under the timeout"
	case "structural_nested_unbounded", "structural_adjacent_broad", "structural_unreachable_terminator", "structural_literal_absorb", "structural_ambiguous_tail":
		return "the Go engine ships no structural ReDoS prefilters (no counterpart of _redos_structural_prefilters._first_structural_safety_violation); acceptance is decided by regexp2 compilation plus the MatchTimeout at match time (guardcore/engine.go compileRE)"
	case "over_budget":
		return "the Go engine has no reach-probe cost arbiter (no counterpart of _redos_cost_arbiter.py); CPU-cost extrapolation is not reproducible"
	case "probe_string_timeout", "probe_subprocess_timeout", "unreachable_probe", "builder_deadline":
		return "the Go engine has no subprocess probe or builder-deadline machinery (no counterpart of the reference probe harness in _redos_cost_arbiter.py)"
	default:
		return fmt.Sprintf("unmapped reason_class %q: extend runSafetyCase mapping", class)
	}
}

type safetyXfail struct {
	SpecVersion string            `json:"spec_version"`
	Cases       map[string]string `json:"cases"`
}

func loadSafetyXfail(t *testing.T) safetyXfail {
	t.Helper()
	data, err := os.ReadFile(safetyXfailFile)
	if err != nil {
		if os.IsNotExist(err) {
			return safetyXfail{Cases: map[string]string{}}
		}
		t.Fatal(err)
	}
	var baseline safetyXfail
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.SpecVersion != corpusSpecVersion {
		t.Fatalf("xfail baseline spec pin %s does not match %s", baseline.SpecVersion, corpusSpecVersion)
	}
	return baseline
}

func TestPatternSafetyConformance(t *testing.T) {
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

	xfail := loadSafetyXfail(t)
	baselinedSeen := map[string]bool{}
	total, passed, divergent, stale := 0, 0, 0, 0
	var failures, divergences []string
	for _, c := range suite.Cases {
		total++
		key := suite.Suite + "/" + c.ID
		outcome := runSafetyCase(c)
		if outcome == "" {
			passed++
			if reason, ok := xfail.Cases[key]; ok {
				stale++
				baselinedSeen[key] = true
				failures = append(failures, fmt.Sprintf("stale xfail baseline entry %s [%s]: case now reproduces the reference verdict; remove the entry", key, reason))
			}
			continue
		}
		if strings.HasPrefix(outcome, "DIVERGENCE") {
			reason, ok := xfail.Cases[key]
			if !ok {
				failures = append(failures, fmt.Sprintf("%s: %s\n  record it in %s with this reason", key, outcome, safetyXfailFile))
				continue
			}
			baselinedSeen[key] = true
			divergent++
			divergences = append(divergences, fmt.Sprintf("xfail %s [%s]", key, reason))
			continue
		}
		if reason, ok := xfail.Cases[key]; ok {
			baselinedSeen[key] = true
			failures = append(failures, fmt.Sprintf("%s is baselined [%s] but now fails hard: %s", key, reason, outcome))
			continue
		}
		failures = append(failures, fmt.Sprintf("%s: %s", key, outcome))
	}

	for id := range xfail.Cases {
		if !baselinedSeen[id] {
			failures = append(failures, fmt.Sprintf("xfail baseline entry %s never ran; corpus changed?", id))
		}
	}
	sort.Strings(divergences)
	for _, d := range divergences {
		t.Logf("%s", d)
	}
	if len(failures) > 0 {
		t.Fatalf("pattern_safety conformance drift: %d failures over %d cases\n%s", len(failures), total, strings.Join(failures, "\n"))
	}
	t.Logf("pattern_safety conformance gate: %d passed, %d documented divergences, %d stale baselines, %d cases (spec %s)", passed, divergent, stale, total, corpusSpecVersion)
}
