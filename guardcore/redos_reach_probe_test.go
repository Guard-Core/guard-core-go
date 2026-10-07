package guardcore

// Tests mirroring tests/test_sus_patterns/test_redos_reach_probe.py,
// test_redos_probe_fill.py, test_redos_stray_chooser.py and
// test_redos_cost_arbiter.py (the deterministic parts; the timing verdicts
// are pinned by the conformance corpus).

import (
	"strings"
	"testing"
	"time"
)

func TestReachQuantifierRepeatRange(t *testing.T) {
	if low, high, next := reachQuantifierRepeatRange(`*ab`, 0); low != 0 || high != probeReachStressLen || next != 1 {
		t.Fatalf("star range wrong: %d %d %d", low, high, next)
	}
	if low, high, next := reachQuantifierRepeatRange(`+?ab`, 0); low != 1 || high != probeReachStressLen || next != 2 {
		t.Fatalf("lazy plus range wrong: %d %d %d", low, high, next)
	}
	if low, high, next := reachQuantifierRepeatRange(`?ab`, 0); low != 0 || high != 1 || next != 1 {
		t.Fatalf("optional range wrong: %d %d %d", low, high, next)
	}
	if low, high, next := reachQuantifierRepeatRange(`{2,5}ab`, 0); low != 2 || high != 5 || next != 5 {
		t.Fatalf("brace range wrong: %d %d %d", low, high, next)
	}
	if low, high, _ := reachQuantifierRepeatRange(`{2,}ab`, 0); low != 2 || high != probeReachStressLen {
		t.Fatalf("open brace range wrong: %d %d", low, high)
	}
	// the reference clamps the high to the cap then floors it at low
	if low, high, _ := reachQuantifierRepeatRange(`{7000,9000}ab`, 0); low != 7000 || high != 7000 {
		t.Fatalf("capped brace range wrong: %d %d", low, high)
	}
	if _, _, next := reachQuantifierRepeatRange(`ab`, 0); next != 0 {
		t.Fatalf("no quantifier range wrong: %d", next)
	}
	if _, _, next := reachQuantifierRepeatRange(`a`, 5); next != 5 {
		t.Fatalf("past-end range wrong: %d", next)
	}
	if _, _, next := reachQuantifierRepeatRange(`{x,y}a`, 0); next != 0 {
		t.Fatalf("malformed brace range wrong: %d", next)
	}
	if _, _, next := reachQuantifierRepeatRange(`{2,x}a`, 0); next != 0 {
		t.Fatalf("junk-high brace range wrong: %d", next)
	}
}

func TestReachBudgetClampedCount(t *testing.T) {
	budget := 100
	count, err := reachBudgetClampedCount(&budget, 2, 1, 100)
	if err != nil || count != 50 {
		t.Fatalf("clamp wrong: %d %v", count, err)
	}
	if _, err := reachBudgetClampedCount(&budget, 0, 1, 3); err != nil {
		t.Fatalf("zero unit wrong: %v", err)
	}
	huge := 1
	if _, err := reachBudgetClampedCount(&huge, 1, probeReachMaxLength+1, probeReachMaxLength+2); err == nil {
		t.Fatal("overflow should error")
	}
}

func TestReachGroupWalkTarget(t *testing.T) {
	if inner, skip, ok := reachGroupWalkTarget("abc"); !ok || skip || inner != "abc" {
		t.Fatalf("plain inner wrong: %q %v %v", inner, skip, ok)
	}
	if inner, _, ok := reachGroupWalkTarget("?:abc"); !ok || inner != "abc" {
		t.Fatalf("non-capping inner wrong: %q", inner)
	}
	if inner, _, ok := reachGroupWalkTarget("?P<n>abc"); !ok || inner != "abc" {
		t.Fatalf("named inner wrong: %q", inner)
	}
	if _, skip, ok := reachGroupWalkTarget("?=abc"); !ok || !skip {
		t.Fatalf("lookahead skip wrong: %v %v", skip, ok)
	}
	if _, skip, ok := reachGroupWalkTarget("?#c"); !ok || !skip {
		t.Fatalf("comment skip wrong: %v %v", skip, ok)
	}
	if inner, _, ok := reachGroupWalkTarget("?i:abc"); !ok || inner != "abc" {
		t.Fatalf("scoped flag inner wrong: %q", inner)
	}
	if _, skip, ok := reachGroupWalkTarget("?i"); !ok || !skip {
		t.Fatalf("flag-only skip wrong: %v %v", skip, ok)
	}
	if inner, skip, ok := reachGroupWalkTarget("?-i:abc"); !ok || skip || inner != "abc" {
		t.Fatalf("negative flag scoped wrong: %q %v %v", inner, skip, ok)
	}
	if _, _, ok := reachGroupWalkTarget("?P<unclosed"); ok {
		t.Fatal("unclosed name should fail")
	}
	// '?x' is the verbose flag group (aiLmsux includes x) - skipped
	if _, skip, ok := reachGroupWalkTarget("?x"); !ok || !skip {
		t.Fatalf("verbose flag group wrong: %v %v", skip, ok)
	}
	if _, _, ok := reachGroupWalkTarget("?y"); ok {
		t.Fatal("unknown extension should fail")
	}
}

func TestSynthesizeReachingProbe(t *testing.T) {
	probe, ok := synthesizeReachingProbe(`'[^']*'`)
	if !ok || !strings.HasPrefix(probe, "'") {
		t.Fatalf("quote probe wrong: %q %v", probe, ok)
	}
	// the probe ends with a breaking character not seen in the pattern
	last := probe[len(probe)-1]
	if strings.IndexByte(probe[:len(probe)-1], last) != -1 {
		t.Fatalf("breaking char not fresh: %q", probe)
	}
	if _, ok := synthesizeReachingProbe(`(unclosed`); ok {
		t.Fatal("unclosed group should fail synthesis")
	}
	if _, ok := synthesizeReachingProbe(`\1x`); ok {
		t.Fatal("unresolvable backref should fail synthesis")
	}
	if _, ok := synthesizeReachingProbe(`\N x`); ok {
		t.Fatal("rejected escape should fail synthesis")
	}
}

func TestSynthesizeReachingProbeBackref(t *testing.T) {
	probe, ok := synthesizeReachingProbe(`(\w)\1z`)
	if !ok {
		t.Fatal("backref synthesis failed")
	}
	if !strings.HasSuffix(probe, "z\x01") {
		t.Fatalf("backref probe wrong: %q", probe)
	}
}

func TestSynthesizeReachingProbeHex(t *testing.T) {
	probe, ok := synthesizeReachingProbe(`\x41+q`)
	if !ok || !strings.HasPrefix(probe, "A") {
		t.Fatalf("hex probe wrong: %q %v", probe, ok)
	}
	if _, ok := synthesizeReachingProbe(`\xzz+q`); ok {
		t.Fatal("bad hex should fail")
	}
}

func TestBuildStrayContext(t *testing.T) {
	ctx, err := buildStrayContext(`'[^']*'`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.prefix != "'" {
		t.Fatalf("leading prefix wrong: %q", ctx.prefix)
	}
	if ctx.patternUnion.isEmpty() {
		t.Fatal("pattern union empty")
	}
	if _, err := buildStrayContext("(unclosed", defaultPatternFlags); err == nil {
		t.Fatal("unclosed context should fail")
	}
}

func TestLeadingLiteralPrefix(t *testing.T) {
	if got := leadingLiteralPrefix(`foo.*bar`); got != "foo" {
		t.Fatalf("foo prefix wrong: %q", got)
	}
	if got := leadingLiteralPrefix(`(?:abc)`); got != "abc" {
		t.Fatalf("whole-pattern transparent unwrap wrong: %q", got)
	}
	if got := leadingLiteralPrefix(`(?:abc).*`); got != "" {
		t.Fatalf("partial transparent group must not unwrap: %q", got)
	}
	if got := leadingLiteralPrefix(`\[abc`); got != "[abc" {
		t.Fatalf("escaped prefix wrong: %q", got)
	}
	if got := leadingLiteralPrefix(`\dabc`); got != "" {
		t.Fatalf("category prefix wrong: %q", got)
	}
	if got := leadingLiteralPrefix(`.*x`); got != "" {
		t.Fatalf("dot prefix wrong: %q", got)
	}
}

func TestFillToLength(t *testing.T) {
	if got := fillToLength("pre", "a", "b", 2); got != "pr" {
		t.Fatalf("short fill wrong: %q", got)
	}
	if got := fillToLength("", "a", "z", 5); got != "aaaaz" {
		t.Fatalf("body fill wrong: %q", got)
	}
	if got := fillToLength("", "a", "z", 1); got != "a" {
		t.Fatalf("single fill wrong: %q", got)
	}
}

func TestRepeatProbeToLength(t *testing.T) {
	if got := repeatProbeToLength("ab", 5, "z"); got != "ababa" {
		t.Fatalf("non-divisible probe wrong: %q", got)
	}
	if got := repeatProbeToLength("ab", 4, "z"); got != "abaz" {
		t.Fatalf("divisible probe wrong: %q", got)
	}
	if got := repeatProbeToLength("aa", 4, "z"); got != "aaaz" {
		t.Fatalf("homogeneous probe wrong: %q", got)
	}
	if got := repeatProbeToLength("", 4, "z"); got != "" {
		t.Fatalf("empty unit wrong: %q", got)
	}
}

func TestPrefixedRepeatProbe(t *testing.T) {
	if got := prefixedRepeatProbe("pre", "ab", "z", false, 3); got != "pre" {
		t.Fatalf("short prefixed probe wrong: %q", got)
	}
	if got := prefixedRepeatProbe("", "ab", "z", false, 6); got != "ababaz" {
		t.Fatalf("unflooded probe wrong: %q", got)
	}
	if got := prefixedRepeatProbe("", "ab", "z", true, 6); got != "abazzz" {
		t.Fatalf("flooded probe wrong: %q", got)
	}
}

func TestDedupAndStride(t *testing.T) {
	builders := []probeBuilder{
		func(int) string { return "a" },
		func(int) string { return "a" },
		func(int) string { return "c" },
	}
	uniq := uniqueProbeSets(builders, []int{8})
	if len(uniq) != 2 {
		t.Fatalf("unique sets wrong: %v", uniq)
	}
	sampled := strideSampledProbeSets(make([][]string, 10), 3)
	if len(sampled) != 3 {
		t.Fatalf("stride wrong: %d", len(sampled))
	}
	full := strideSampledProbeSets([][]string{{"a"}, {"b"}}, 8)
	if len(full) != 2 {
		t.Fatalf("under-cap stride wrong: %d", len(full))
	}
}

func TestChooseRepeatUnitStray(t *testing.T) {
	ctx, err := buildStrayContext(`'[^']*'`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	stray, err := chooseRepeatUnitStray(ctx, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if stray == "" {
		t.Fatal("empty stray")
	}
	stray, err = chooseRepeatUnitStray(ctx, "")
	if err != nil || stray != reachProbeStrayByte {
		t.Fatalf("empty unit stray wrong: %q", stray)
	}
}

func TestChooseClassIntersectionStray(t *testing.T) {
	ctx, err := buildStrayContext(`a*a*`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	stray, err := chooseClassIntersectionStray(ctx, 'a', singleInterval('a'), singleInterval('a'), nil)
	if err != nil {
		t.Fatal(err)
	}
	if stray == "" {
		t.Fatal("empty class stray")
	}
}

func TestDedupCappedCandidates(t *testing.T) {
	got := dedupCappedCandidates([]string{"a", "a", "", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"})
	if len(got) != strayCandidateCap {
		t.Fatalf("cap wrong: %d", len(got))
	}
}

func TestFirstComplementCharAndStrayForPair(t *testing.T) {
	if c, ok := firstComplementChar(singleInterval('a')); !ok || c != "\x00" {
		t.Fatalf("first complement wrong: %q", c)
	}
	if _, ok := firstComplementChar(fullIntervals()); ok {
		t.Fatal("full set should have no complement member")
	}
	if got := strayForPair(fullIntervals(), fullIntervals()); got != reachProbeStrayByte {
		t.Fatalf("stray for full pair wrong: %q", got)
	}
}

func TestDedupStrings(t *testing.T) {
	got := dedupStrings([]string{"a", "b", "a"})
	if len(got) != 2 {
		t.Fatalf("dedup strings wrong: %v", got)
	}
}

func TestReachProbeCandidateBuilders(t *testing.T) {
	builders, err := reachProbeCandidateBuilders(`foo.*bar`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	if len(builders) == 0 {
		t.Fatal("no builders")
	}
	probe := builders[0](64)
	if len(probe) != 64 {
		t.Fatalf("builder length wrong: %d", len(probe))
	}
}

func TestReachProbePrefixBuilders(t *testing.T) {
	builders := reachProbePrefixBuilders(`foo.*bar`, nil)
	if len(builders) == 0 {
		t.Fatal("prefix builders empty")
	}
	if builders := reachProbePrefixBuilders(`(unclosed`, nil); builders != nil {
		t.Fatal("failed synthesis should have no prefix builders")
	}
}

func TestAmbiguousGroupFillBuilders(t *testing.T) {
	builders, err := ambiguousGroupFillBuilders(`(?:\w+\s?)+$`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(builders) == 0 {
		t.Fatal("ambiguous fill builders empty")
	}
	builders, err = ambiguousGroupFillBuilders("(unclosed", nil)
	if err != nil || builders != nil {
		t.Fatalf("unclosed builders wrong: %v %v", builders, err)
	}
}

func TestLiteralRunBuilders(t *testing.T) {
	builders := literalRunBuilders(`foo.*bar`, nil)
	if len(builders) == 0 {
		t.Fatal("run builders empty")
	}
	probe := builders[0](64)
	if len(probe) != 64 {
		t.Fatalf("run builder length wrong: %d", len(probe))
	}
}

func TestRepeatGroupUnits(t *testing.T) {
	pairs, err := repeatGroupUnits(`(\w+\.?)+`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pair := range pairs {
		if len(pair[1]) > 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("group units missing: %v", pairs)
	}
	pairs, err = repeatGroupUnits("(bad", defaultPatternFlags)
	if err != nil || pairs != nil {
		t.Fatalf("unparseable group units wrong: %v %v", pairs, err)
	}
}

func TestRepresentativeCharForNode(t *testing.T) {
	if ch, ok := representativeCharForNode(&reNode{op: opLiteral, ch: 'x'}, 0); !ok || ch != 'x' {
		t.Fatalf("literal rep wrong: %q %v", ch, ok)
	}
	if ch, ok := representativeCharForNode(&reNode{op: opIn, interval: rangeIntervals('a', 'c')}, 0); !ok || ch != 'a' {
		t.Fatalf("class rep wrong: %q %v", ch, ok)
	}
	if _, ok := representativeCharForNode(&reNode{op: opAt}, 0); ok {
		t.Fatal("anchor should have no representative")
	}
	if ch, ok := representativeCharForNode(&reNode{op: opIn, interval: singleInterval(1)}, 0); !ok || ch != 1 {
		t.Fatalf("non-printable rep wrong: %q %v", ch, ok)
	}
}

func TestRepeatReachingPrefixes(t *testing.T) {
	prefixes := repeatReachingPrefixes(`foo.*bar`, defaultPatternFlags)
	if len(prefixes) == 0 {
		t.Fatal("reaching prefixes empty")
	}
}

func TestTimeProbesSamples(t *testing.T) {
	compiled, err := compileRE(`abc`, regexp2OptionsForFlags(defaultPatternFlags), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	timing := timeProbes(compiled, []string{"abc"}, reachProbeSampleCount)
	if len(timing.samplesBySize) != 1 || len(timing.samplesBySize[0]) != 1 {
		t.Fatalf("fast probe samples wrong: %+v", timing.samplesBySize)
	}
	if timing.loadFactor <= 0 {
		t.Fatal("load factor not measured")
	}
}

func TestReachProbeVerdictFromSamples(t *testing.T) {
	// quadratic growth (ratio 4) extrapolates DOWN to a cap below 32000
	samples := [][]float64{{0.01, 0.02}, {0.04, 0.08}}
	over, extr, ratio, min32, med32 := reachProbeVerdictFromSamples(samples, 10000, 1.0)
	if over || ratio != 4.0 || min32 != 0.04 || med32 != 0.08 {
		t.Fatalf("verdict wrong: %v %v %v %v %v", over, extr, ratio, min32, med32)
	}
	if extr > 0.0041 || extr < 0.0038 {
		t.Fatalf("extrapolation wrong: %v", extr)
	}
	// explosive growth at the default cap extrapolates far over budget
	samples = [][]float64{{0.01}, {2.0}}
	over, _, ratio, _, _ = reachProbeVerdictFromSamples(samples, patternSafetyDefaultCap, 1.0)
	if !over || ratio != 200.0 {
		t.Fatalf("explosive verdict wrong: %v %v", over, ratio)
	}
}

func TestStructuralViolationOr(t *testing.T) {
	if got := structuralViolationOr("", "fallback"); got != "fallback" {
		t.Fatalf("fallback wrong: %q", got)
	}
	if got := structuralViolationOr("structural", "fallback"); got != "structural" {
		t.Fatalf("structural wrong: %q", got)
	}
}

func TestLoadFactor(t *testing.T) {
	if got := loadFactor(0); got != 1.0 {
		t.Fatalf("zero reference load wrong: %v", got)
	}
	if got := loadFactor(goReferenceScanSeconds); got != 1.0 {
		t.Fatalf("reference load wrong: %v", got)
	}
	if got := loadFactor(goReferenceScanSeconds * 100); got != loadFactorCeiling {
		t.Fatalf("ceiling load wrong: %v", got)
	}
	if got := loadFactor(goReferenceScanSeconds * 0.01); got != loadFactorFloor {
		t.Fatalf("floor load wrong: %v", got)
	}
}

func TestScaledProbeDeadline(t *testing.T) {
	if got := scaledProbeDeadlineSeconds(0.5); got != reachProbeCombinedTimeoutSeconds {
		t.Fatalf("min-load deadline wrong: %v", got)
	}
	if got := scaledProbeDeadlineSeconds(100); got != reachProbeDeadlineScaleCeilingSeconds {
		t.Fatalf("ceiling deadline wrong: %v", got)
	}
}

func TestMeasureHostLoadFactor(t *testing.T) {
	first := measureHostLoadFactor()
	second := measureHostLoadFactor()
	if first != second {
		t.Fatal("load factor must be cached")
	}
	if first < loadFactorFloor || first > loadFactorCeiling {
		t.Fatalf("load factor out of clamp: %v", first)
	}
}

func TestReachProbeSizesForStrategy(t *testing.T) {
	full := reachProbeSizesForStrategy("structural", false)
	if len(full) != 4 {
		t.Fatalf("ascending sizes wrong: %v", full)
	}
	verdict := reachProbeSizesForStrategy("", false)
	if len(verdict) != 2 {
		t.Fatalf("verdict sizes wrong: %v", verdict)
	}
	verdict = reachProbeSizesForStrategy("", true)
	if len(verdict) != 4 {
		t.Fatalf("risk sizes wrong: %v", verdict)
	}
}

func TestReachProbeCostReason(t *testing.T) {
	if got := reachProbeCostReason("structural", 1, 2, 100, 3, 4, 5); got != "structural" {
		t.Fatalf("structural reason wrong: %q", got)
	}
	reason := reachProbeCostReason("", 1.1781, 4.03, 10000, 1.2345, 2.3456, 0.9)
	if !strings.Contains(reason, "Pattern extrapolated CPU cost at cap (10000 chars) is 1.178s") {
		t.Fatalf("cost reason wrong: %q", reason)
	}
	if !strings.Contains(reason, "growth ratio 4.03x per doubling") {
		t.Fatalf("ratio text wrong: %q", reason)
	}
}

func TestReachProbeUnreachableReason(t *testing.T) {
	if got := reachProbeUnreachableReason("structural"); got != "structural" {
		t.Fatalf("structural unreachable wrong: %q", got)
	}
	got := reachProbeUnreachableReason("")
	if !strings.Contains(got, "could not construct a test string that reaches every") {
		t.Fatalf("unreachable reason wrong: %q", got)
	}
}
