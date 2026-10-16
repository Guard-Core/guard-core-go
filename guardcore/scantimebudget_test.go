package guardcore

import (
	"math"
	"strings"
	"testing"
	"time"
)

// jumpClock is a fake scan clock that advances by step on every read, so a
// small cap is spent without burning real CPU. The wall clock the slice
// boundary reads advances by step too, so every pattern check crosses a
// slice and charges the CPU clock (the per-pattern check itself reads only
// the wall clock; see TestCPUClockIsReadPerPassNotPerPattern).
func jumpClock(t *testing.T, step float64) {
	t.Helper()
	prevCPU, prevWall := scanCPUNow, scanWallNow
	cpu, wall := 0.0, 0.0
	scanCPUNow = func() float64 {
		cpu += step
		return cpu
	}
	scanWallNow = func() float64 {
		wall += step
		return wall
	}
	t.Cleanup(func() { scanCPUNow, scanWallNow = prevCPU, prevWall })
}

func TestScanSecondsDefaultAndRange(t *testing.T) {
	if got := DefaultConfig().MaxScanSeconds; got != 10.0 {
		t.Fatalf("DefaultConfig().MaxScanSeconds = %v, want 10", got)
	}
	cfg, err := NewSecurityConfig(nil)
	if err != nil || cfg.Detection.MaxScanSeconds != 10.0 {
		t.Fatalf("default must be 10.0 and valid, got %v, %v", cfg.Detection.MaxScanSeconds, err)
	}
	cfg, err = NewSecurityConfig(func(c *SecurityConfig) { c.Detection.MaxScanSeconds = 0 })
	if err != nil || cfg.Detection.MaxScanSeconds != 10.0 {
		t.Fatalf("zero means the default, got %v, %v", cfg.Detection.MaxScanSeconds, err)
	}
	for _, ok := range []float64{0.1, 5, 60} {
		if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.Detection.MaxScanSeconds = ok }); err != nil {
			t.Fatalf("%v must validate, got %v", ok, err)
		}
	}
	for _, bad := range []float64{0.05, -1, 60.5, math.NaN(), math.Inf(1)} {
		_, err := NewSecurityConfig(func(c *SecurityConfig) { c.Detection.MaxScanSeconds = bad })
		if err == nil || !strings.Contains(err.Error(), "detection_max_scan_seconds") {
			t.Fatalf("%v must be rejected naming the knob, got %v", bad, err)
		}
	}
}

func TestExhaustedBudgetRecordsTheReferenceThreat(t *testing.T) {
	jumpClock(t, 1000)
	buf := captureLogForKnobs(t)
	cfg := testConfig(t)
	cfg.Detection.MaxScanSeconds = 0.1
	budget := newDetectionScanBudget(cfg, "203.0.113.7")
	result := DefaultSusPatternsManager.detect("a benign value", "203.0.113.7", "query_param", "", false, budget)
	if !result.IsThreat {
		t.Fatal("an exhausted budget must fail closed")
	}
	var budgetThreat map[string]any
	for _, threat := range result.Threats {
		if threat["pattern"] == "scan_time_budget_exhausted" {
			budgetThreat = threat
			break
		}
	}
	if budgetThreat == nil {
		t.Fatalf("no budget threat in %v", result.Threats)
	}
	want := map[string]any{
		"type": "pattern_timeout", "pattern": "scan_time_budget_exhausted", "match": "",
		"position": 0, "execution_time": 0.0, "category": "custom", "weight": 1.0,
	}
	if len(budgetThreat) != len(want) {
		t.Fatalf("threat shape = %v, want %v", budgetThreat, want)
	}
	for k, v := range want {
		if budgetThreat[k] != v {
			t.Fatalf("threat[%q] = %v, want %v", k, budgetThreat[k], v)
		}
	}
	if n := strings.Count(buf.String(), "detection_max_scan_seconds (0.1) reached for client 203.0.113.7"); n != 1 {
		t.Fatalf("the warning must log exactly once per request, got %d in %q", n, buf.String())
	}
}

func TestExhaustedBudgetBlocksAndNamesTheBudget(t *testing.T) {
	jumpClock(t, 1000)
	cfg := testConfig(t)
	cfg.Detection.MaxScanSeconds = 0.1
	req := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/clean"
		opts.RawQuery = "a=hello"
		opts.QueryParams = map[string]string{"a": "hello"}
	})
	categories, trigger := detectThreat(req, cfg, resolveDetectionExclusions(cfg, nil))
	if len(categories) == 0 {
		t.Fatal("an exhausted budget must block, not pass the request")
	}
	if !strings.Contains(trigger, "Pattern exceeded scan time budget: 'scan_time_budget_exhausted'") {
		t.Fatalf("the trigger must name the budget, got %q", trigger)
	}
}

func TestThreatsMessageAppendsTheTimeout(t *testing.T) {
	regex := map[string]any{"type": "regex", "pattern": "p1"}
	timeout := map[string]any{"type": "pattern_timeout", "pattern": "scan_time_budget_exhausted"}
	if got := threatsMessage([]map[string]any{regex, timeout}); got != "Value matched pattern 'p1'; Pattern exceeded scan time budget: 'scan_time_budget_exhausted'" {
		t.Fatalf("got %q", got)
	}
	if got := threatsMessage([]map[string]any{timeout, regex}); got != "Pattern exceeded scan time budget: 'scan_time_budget_exhausted'" {
		t.Fatalf("got %q", got)
	}
	if got := threatsMessage([]map[string]any{regex}); got != "Value matched pattern 'p1'" {
		t.Fatalf("got %q", got)
	}
	if got := threatsMessage(nil); got != "Threat detected" {
		t.Fatalf("got %q", got)
	}
}

func TestRequestWithinBudgetIsUnaffected(t *testing.T) {
	cfg := testConfig(t)
	clean := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/clean"
		opts.RawQuery = "a=hello"
		opts.QueryParams = map[string]string{"a": "hello"}
	})
	if categories, trigger := detectThreat(clean, cfg, resolveDetectionExclusions(cfg, nil)); categories != nil {
		t.Fatalf("a clean request within budget must pass, got %v %q", categories, trigger)
	}
	attack := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/x"
		opts.RawQuery = "a=<script>alert(1)</script>"
		opts.QueryParams = map[string]string{"a": "<script>alert(1)</script>"}
	})
	categories, trigger := detectThreat(attack, cfg, resolveDetectionExclusions(cfg, nil))
	if len(categories) != 1 || categories[0] != "xss" || strings.Contains(trigger, "scan time budget") {
		t.Fatalf("an attack within budget keeps its own category, got %v %q", categories, trigger)
	}
}

func TestBareDetectHasNoBudget(t *testing.T) {
	jumpClock(t, 1000)
	result := Detect("a benign value", "203.0.113.7", "query_param")
	if result.IsThreat {
		t.Fatalf("a bare Detect call outside a request scope has no budget, got %v", result.Threats)
	}
}

func TestBudgetCountsOnlyThePassAndSpansPasses(t *testing.T) {
	jumpClock(t, 0.4)
	cfg := testConfig(t)
	cfg.Detection.MaxScanSeconds = 1.0
	budget := newDetectionScanBudget(cfg, "203.0.113.7")
	end := budget.beginPass()   // reads 0.4
	if budget.timeExhausted() { // reads 0.8: spent 0.4
		t.Fatal("0.4s of 1.0s is not exhausted")
	}
	end() // reads 1.2: spent 0.8 total
	end = budget.beginPass()
	if !budget.timeExhausted() { // 0.8 plus 0.4 is over the cap
		t.Fatal("time spent in an earlier pass must count toward the same budget")
	}
	end()
}

func TestScanClockIsCPUNotWallTime(t *testing.T) {
	if !clockIsThreadCPU {
		t.Skip("no per-thread CPU clock on this platform; wall-time fallback is covered separately")
	}
	budget := newDetectionScanBudget(nil, "203.0.113.7")
	budget.scanSeconds = 0.1
	end := budget.beginPass()
	defer end()
	time.Sleep(250 * time.Millisecond)
	if budget.timeExhausted() {
		t.Fatal("sleeping burns wall time, not CPU time, so it must not spend the budget")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !budget.timeExhausted() {
		if time.Now().After(deadline) {
			t.Fatal("busy CPU work must spend the budget")
		}
		for i := 0; i < 1_000_000; i++ {
			_ = math.Sqrt(float64(i))
		}
	}
}

func TestWallClockFallbackSpendsOnSleep(t *testing.T) {
	budget := newDetectionScanBudget(nil, "203.0.113.7")
	budget.clock = wallClockSeconds
	budget.scanSeconds = 0.1
	end := budget.beginPass()
	defer end()
	if budget.timeExhausted() {
		t.Fatal("a fresh pass must not be exhausted")
	}
	time.Sleep(150 * time.Millisecond)
	if !budget.timeExhausted() {
		t.Fatal("the documented wall-time fallback spends on elapsed time")
	}
}

func TestNilBudgetIsInert(t *testing.T) {
	var budget *detectionScanBudget
	budget.beginPass()()
	if budget.timeExhausted() {
		t.Fatal("a nil budget is never exhausted")
	}
}

func TestCustomPatternsHonorTheBudget(t *testing.T) {
	jumpClock(t, 1000)
	m := NewSusPatternsManager(nil)
	m.SeedCustomPattern(`zzz`)
	cfg := testConfig(t)
	cfg.Detection.MaxScanSeconds = 0.1
	threats := m.scanCustomPatterns("zzz", newDetectionScanBudget(cfg, "203.0.113.7"))
	if len(threats) != 1 || threats[0]["pattern"] != "scan_time_budget_exhausted" {
		t.Fatalf("an exhausted budget skips the runtime registry and records the budget threat, got %v", threats)
	}
}

// The budget threat counts toward the regex anomaly like any weighted
// regex-side threat (reference _regex_anomaly >= threshold): it flags the
// request at the engine's fixed 1.0 threshold with its default weight 1.0,
// and does not flag it when the pattern's weight is overridden below it.
func TestBudgetThreatIsFlaggedByWeightNotUnconditionally(t *testing.T) {
	jumpClock(t, 1000)
	cfg := testConfig(t)
	cfg.Detection.MaxScanSeconds = 0.1
	run := func() DetectResult {
		return DefaultSusPatternsManager.detect("a benign value", "203.0.113.7", "url_path", "", false, newDetectionScanBudget(cfg, "203.0.113.7"))
	}
	if !run().IsThreat {
		t.Fatal("weight 1.0 must flag the request")
	}
	weightOverrides[scanTimeBudgetExhaustedPattern] = 0.25
	t.Cleanup(func() { delete(weightOverrides, scanTimeBudgetExhaustedPattern) })
	if r := run(); r.IsThreat {
		t.Fatalf("a sub-threshold weight (summed over the view passes) must not flag the request, got %v", r.Threats)
	}
}

// The CPU clock is read when a pass opens, at slice boundaries and when it
// closes, not once per pattern: a pass over many patterns inside one slice
// reads it twice, and a stalled pattern adds one read per elapsed slice.
func TestCPUClockIsReadPerPassNotPerPattern(t *testing.T) {
	prevCPU, prevWall := scanCPUNow, scanWallNow
	t.Cleanup(func() { scanCPUNow, scanWallNow = prevCPU, prevWall })
	cpuReads, wall := 0, 0.0
	scanCPUNow = func() float64 { cpuReads++; return 0 }
	scanWallNow = func() float64 { return wall }
	budget := newDetectionScanBudget(nil, "203.0.113.7")
	end := budget.beginPass()
	for i := 0; i < 1000; i++ {
		if budget.timeExhausted() {
			t.Fatal("a zero CPU clock never exhausts the budget")
		}
		wall += 0.00001 // 10 us per pattern: 1000 patterns span 5 slices
	}
	end()
	if cpuReads < 2 || cpuReads > 10 {
		t.Fatalf("1000 patterns over ~5 slices must read the CPU clock a few times, got %d reads", cpuReads)
	}
	cpuReads = 0
	end = budget.beginPass()
	for i := 0; i < 1000; i++ {
		budget.timeExhausted()
	}
	end()
	if cpuReads != 2 {
		t.Fatalf("a pass inside one slice reads the CPU clock only at open and close, got %d reads", cpuReads)
	}
}

// A long pass stops within about one slice of the cap: the budget is
// checked against the charged time, which lags the true spend by at most one
// slice plus one pattern.
func TestLongPassStopsWithinOneSliceOfTheBudget(t *testing.T) {
	prevCPU, prevWall := scanCPUNow, scanWallNow
	t.Cleanup(func() { scanCPUNow, scanWallNow = prevCPU, prevWall })
	now := 0.0 // one fake clock drives both: each pattern costs 0.5 ms
	scanCPUNow = func() float64 { return now }
	scanWallNow = func() float64 { return now }
	budget := newDetectionScanBudget(nil, "203.0.113.7")
	budget.scanSeconds = 0.0105
	end := budget.beginPass()
	defer end()
	patterns := 0
	for !budget.timeExhausted() {
		patterns++
		now += 0.0005
		if patterns > 1000 {
			t.Fatal("the budget never stopped the pass")
		}
	}
	if overshoot := now - budget.scanSeconds; overshoot < 0 || overshoot > scanSliceSeconds+0.0005 {
		t.Fatalf("stopped %.4fs past the cap, want within one slice plus one pattern", overshoot)
	}
}
