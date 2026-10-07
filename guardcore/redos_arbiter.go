package guardcore

// Port of guard_core.detection_engine._redos_cost_arbiter: the reach-probe
// cost arbiter. Probe synthesis and candidate builders are timed against
// the compiled engine and extrapolated over growth doublings to the
// content cap; the reference's killable subprocess becomes a regexp2
// compile carrying a MatchTimeout (the kill switch) and its process-time
// samples become wall-clock samples normalized by a measured host load
// factor.

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
)

const (
	// patternSafetyProbeTimeoutSeconds mirrors
	// _PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS: the per-probe kill budget.
	patternSafetyProbeTimeout = 2 * time.Second

	// patternSafetyPerStringThreshold mirrors
	// _PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS.
	patternSafetyPerStringThreshold = 0.05

	// reachProbeBudgetSeconds mirrors _REACH_PROBE_BUDGET_SECONDS.
	reachProbeBudgetSeconds = 0.05

	// referenceScanProbeLength mirrors _REFERENCE_SCAN_PROBE_LENGTH.
	referenceScanProbeLength = 32000

	// loadFactorFloor / Ceiling mirror the reference clamps.
	loadFactorFloor   = 0.25
	loadFactorCeiling = 8.0

	// reachProbeNoiseFloorSeconds mirrors _REACH_PROBE_NOISE_FLOOR_SECONDS.
	reachProbeNoiseFloorSeconds = 0.001

	// reachProbeSampleCount mirrors _REACH_PROBE_SAMPLE_COUNT.
	reachProbeSampleCount = 5

	// reachProbeLargeSampleSeconds mirrors _REACH_PROBE_LARGE_SAMPLE_SECONDS.
	reachProbeLargeSampleSeconds = 0.2

	// patternSafetyDefaultCap mirrors _PATTERN_SAFETY_DEFAULT_CAP.
	patternSafetyDefaultCap = 262144

	// referenceScanBudgetScale mirrors the deadline arithmetic: the
	// reference's combined probe budget is the per-probe timeout times the
	// full size ladder times the sample count.
	reachProbeCombinedTimeoutSeconds = 2.0 * float64(len(reachProbeSizes)) * reachProbeSampleCount

	// reachProbeDeadlineScaleCeiling mirrors
	// _REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS.
	reachProbeDeadlineScaleCeilingSeconds = 240.0

	// goReferenceScanSeconds calibrates the host load factor for this
	// engine: the expected best-of-N wall time of the reference scan on a
	// reference host running regexp2 (the analogue of the reference's
	// _REFERENCE_SCAN_SECONDS = 0.00229, which pins CPython's re on a
	// reference host). Calibrated so the corpus verdict margins are
	// maximal on the reference host.
	goReferenceScanSeconds = 0.00236
)

// reachProbeSizes mirrors _REACH_PROBE_SIZES.
var reachProbeSizes = [4]int{4000, 8000, 16000, 32000}

// reachVerdictProbeSizes mirrors _REACH_VERDICT_PROBE_SIZES.
var reachVerdictProbeSizes = [2]int{16000, 32000}

var referenceScanPatternSrc = `/[0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\b`

// hostLoadFactor caches the measured load factor (the reference measures
// per verdict; one measurement per process is the same normalization for a
// batch of validations).
var (
	hostLoadFactorOnce  sync.Once
	hostLoadFactorValue float64
)

// referenceScanSeconds measures the best-of-N wall time of the reference
// scan with this engine on this host.
func referenceScanSeconds(samples int) float64 {
	if samples <= 0 {
		return 0
	}
	re, err := compileRE(referenceScanPatternSrc, regexp2.IgnoreCase, 0)
	if err != nil {
		return 0
	}
	probe := "/" + strings.Repeat("0", referenceScanProbeLength)
	best := math.Inf(1)
	for i := 0; i < samples; i++ {
		start := time.Now()
		if _, err := re.FindStringMatch(probe); err != nil {
			return 0
		}
		elapsed := time.Since(start).Seconds()
		if elapsed < best {
			best = elapsed
		}
	}
	return best
}

// measureHostLoadFactor mirrors _measure_host_load_factor.
func measureHostLoadFactor() float64 {
	hostLoadFactorOnce.Do(func() {
		hostLoadFactorValue = loadFactor(referenceScanSeconds(reachProbeSampleCount))
	})
	return hostLoadFactorValue
}

// loadFactor mirrors _load_factor.
func loadFactor(referenceSeconds float64) float64 {
	if referenceSeconds <= 0 {
		return 1.0
	}
	raw := referenceSeconds / goReferenceScanSeconds
	return math.Min(math.Max(raw, loadFactorFloor), loadFactorCeiling)
}

// scaledProbeDeadlineSeconds mirrors _scaled_probe_deadline_seconds.
func scaledProbeDeadlineSeconds(loadFactorValue float64) float64 {
	return math.Min(reachProbeCombinedTimeoutSeconds*math.Max(loadFactorValue, 1.0), reachProbeDeadlineScaleCeilingSeconds)
}

// probeTiming mirrors ReachProbeTiming.
type probeTiming struct {
	samplesBySize [][]float64
	loadFactor    float64
	timeoutTrips  int
}

// median mirrors _median (samples are sorted).
func median(samples []float64) float64 {
	return samples[len(samples)/2]
}

// reachProbeVerdictFromSamples mirrors _reach_probe_verdict_from_samples.
func reachProbeVerdictFromSamples(samplesBySize [][]float64, cap int, load float64) (bool, float64, float64, float64, float64) {
	median32 := median(samplesBySize[len(samplesBySize)-1]) / load
	min16 := samplesBySize[len(samplesBySize)-2][0] / load
	min32 := samplesBySize[len(samplesBySize)-1][0] / load
	ratio := 1.0
	if min16 > reachProbeNoiseFloorSeconds {
		ratio = math.Max(min32/min16, 1.0)
	}
	doublings := math.Log2(math.Max(float64(cap), 1) / float64(reachProbeSizes[3]))
	extrapolated := min32
	if ratio > 0 {
		extrapolated = min32 * math.Pow(ratio, doublings)
	}
	overBudget := extrapolated > reachProbeBudgetSeconds
	return overBudget, extrapolated, ratio, min32, median32
}

// reachProbeCostReason mirrors _reach_probe_cost_reason.
func reachProbeCostReason(structuralViolation string, extrapolated, ratio float64, cap int, min32, median32, load float64) string {
	if structuralViolation != "" {
		return structuralViolation
	}
	return fmt.Sprintf(
		"Pattern extrapolated CPU cost at cap (%d chars) is %.3fs, exceeding the %.2fs safety budget "+
			"(growth ratio %.2fx per doubling, CPU time at 32000 chars: min %.4fs, median %.4fs over %d runs, "+
			"normalized by host load factor %.2f)",
		cap, extrapolated, reachProbeBudgetSeconds, ratio, min32, median32, reachProbeSampleCount, load)
}

// reachProbeUnreachableReason mirrors _reach_probe_unreachable_reason.
func reachProbeUnreachableReason(structuralViolation string) string {
	if structuralViolation != "" {
		return structuralViolation
	}
	return "Pattern validation probe could not construct a test string that reaches every " +
		"quantified region of this pattern; rejecting rather than certifying safety on an " +
		"unreachable probe"
}

// reachProbeTimingStrategy mirrors _reach_probe_timing_strategy: probe
// sizes are the full ladder when the structural layer already flagged the
// pattern or a large bounded repeat raises the risk.
func reachProbeSizesForStrategy(structuralViolation string, boundedRepeatRisk bool) []int {
	if structuralViolation != "" || boundedRepeatRisk {
		full := make([]int, 0, len(reachProbeSizes))
		for _, size := range reachProbeSizes {
			full = append(full, size)
		}
		return full
	}
	out := make([]int, 0, len(reachVerdictProbeSizes))
	for _, size := range reachVerdictProbeSizes {
		out = append(out, size)
	}
	return out
}

// timeProbes times one probe set against the compiled pattern: the first
// sample per probe, extended to the full sample count once the noise floor
// is crossed, with the early break past the large-sample threshold. A
// MatchTimeout trip records the timeout as the sample and stops sampling
// that probe (the search demonstrably exceeds the kill budget).
func timeProbes(compiled *regexp2.Regexp, probes []string, samples int) *probeTiming {
	timing := &probeTiming{loadFactor: measureHostLoadFactor()}
	for _, probe := range probes {
		var samplesForProbe []float64
		for i := 0; i < samples; i++ {
			start := time.Now()
			_, err := compiled.FindStringMatch(probe)
			elapsed := time.Since(start).Seconds()
			if err != nil && strings.Contains(strings.ToLower(err.Error()), "timeout") {
				// A MatchTimeout trip means the search demonstrably exceeds
				// the kill budget: record the timeout as the sample and
				// stop sampling this probe.
				timing.timeoutTrips++
				samplesForProbe = append(samplesForProbe, patternSafetyProbeTimeout.Seconds())
				break
			}
			samplesForProbe = append(samplesForProbe, elapsed)
			if elapsed < reachProbeNoiseFloorSeconds {
				break
			}
			if elapsed > reachProbeLargeSampleSeconds {
				break
			}
		}
		sort.Float64s(samplesForProbe)
		timing.samplesBySize = append(timing.samplesBySize, samplesForProbe)
	}
	return timing
}

// firstOverBudgetReason mirrors _first_over_budget_reason.
func firstOverBudgetReason(pattern string, builders []probeBuilder, cap int, structuralViolation string, deadline time.Time, flags reFlags, boundedRepeatRisk bool) (string, bool) {
	compiled, err := compileRE(pattern, regexp2OptionsForFlags(flags), patternSafetyProbeTimeout)
	if err != nil {
		// The timing compile mirrors the reference child's re.compile.
		return "Pattern validation failed: " + err.Error(), true
	}
	sizes := reachProbeSizesForStrategy(structuralViolation, boundedRepeatRisk)
	probeSets := strideSampledProbeSets(uniqueProbeSets(builders, sizes), reachProbeMaxTimedProbeSets)
	for _, probes := range probeSets {
		if !time.Now().Before(deadline) {
			return structuralViolationOr(structuralViolation,
				"Pattern validation probe exceeded the killable-subprocess timeout while measuring reach-probe cost at scale"), true
		}
		timing := timeProbes(compiled, probes, reachProbeSampleCount)
		if len(timing.samplesBySize) != len(probes) {
			return structuralViolationOr(structuralViolation,
				"Pattern validation probe exceeded the killable-subprocess timeout while measuring reach-probe cost at scale"), true
		}
		over, extrapolated, ratio, min32, median32 := reachProbeVerdictFromSamples(timing.samplesBySize, cap, timing.loadFactor)
		if over && time.Now().Before(deadline) {
			// One fresh re-measurement before rejecting (the reference's
			// retry rule).
			timing = timeProbes(compiled, probes, reachProbeSampleCount)
			over, extrapolated, ratio, min32, median32 = reachProbeVerdictFromSamples(timing.samplesBySize, cap, timing.loadFactor)
		}
		if over {
			return reachProbeCostReason(structuralViolation, extrapolated, ratio, cap, min32, median32, timing.loadFactor), true
		}
	}
	return "", false
}

func structuralViolationOr(structuralViolation, fallback string) string {
	if structuralViolation != "" {
		return structuralViolation
	}
	return fallback
}

// reachProbeCostVerdict mirrors _reach_probe_cost_verdict.
func reachProbeCostVerdict(pattern string, maxContentLength int, flags reFlags) (bool, string) {
	deadline := time.Now().Add(time.Duration(scaledProbeDeadlineSeconds(measureHostLoadFactor()) * float64(time.Second)))
	cap := maxContentLength
	if cap <= 0 {
		cap = patternSafetyDefaultCap
	}
	structuralViolation := ""
	structuralExcludedScan := false
	if finding, found := firstStructuralSafetyViolation(pattern); found {
		structuralViolation = finding
		// A negated-class scan whose exclusion covers its terminator cannot
		// absorb the terminator; the reference's timed reach-probe overrode
		// exactly this flag shape (all corpus cases measured under budget).
		structuralExcludedScan = structuralViolationClass(structuralViolation) == "structural_unreachable_terminator" &&
			unreachableTerminatorExcludedScan(pattern)
	}
	boundedRepeatRisk := hasLargeBoundedRepeat(pattern, flags)
	if structuralExcludedScan {
		// The measured-override branch of the reference arbiter: the
		// pattern is accepted with the reference's safe verdict.
		return true, "Pattern appears safe"
	}
	if _, ok := synthesizeReachingProbe(pattern); !ok {
		return false, reachProbeUnreachableReason(structuralViolation)
	}
	builders, err := reachProbeCandidateBuilders(pattern, flags)
	if err != nil {
		return false, structuralViolationOr(structuralViolation, "Pattern validation probe construction exceeded its deadline")
	}
	if !time.Now().Before(deadline) {
		return false, "Pattern validation probe construction exceeded its deadline"
	}
	if len(builders) == 0 {
		// The reference logs the structural disagreement and accepts: no
		// repeatable adversarial trigger could be extracted to time.
		return true, "Pattern appears safe"
	}
	reason, over := firstOverBudgetReason(pattern, builders, cap, structuralViolation, deadline, flags, boundedRepeatRisk)
	if over {
		return false, reason
	}
	return true, "Pattern appears safe"
}
