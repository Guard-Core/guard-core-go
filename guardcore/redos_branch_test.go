package guardcore

// Second sweep: flag permutations, ASCII category predicates, terminator
// walk group forms, pairing-chain branches and builder edge shapes.

import (
	"strings"
	"testing"
	"time"
)

func TestParseFlagPermutations(t *testing.T) {
	// every flag letter in both polarities plus scoped forms
	parsed := mustParse(t, `(?imsux:a)`, 0)
	if len(parsed.nodes) == 0 {
		t.Fatal("scoped all-flags parse wrong")
	}
	parsed = mustParse(t, `(?imsuxa)`, 0)
	if parsed.flags&flagIgnoreCase == 0 || parsed.flags&flagMultiline == 0 ||
		parsed.flags&flagDotAll == 0 || parsed.flags&flagASCII == 0 || parsed.flags&flagVerbose == 0 {
		t.Fatalf("global flags wrong: %v", parsed.flags)
	}
	parsed = mustParse(t, `(?im-sx:a)`, 0)
	if len(parsed.nodes) == 0 {
		t.Fatal("mixed scoped parse wrong")
	}
	parsed = mustParse(t, `(?-imsux:a)`, 0)
	if len(parsed.nodes) == 0 {
		t.Fatal("negative-only scoped parse wrong")
	}
	parsed = mustParse(t, `(?L)`, 0)
	if parsed.flags&flagLocale == 0 {
		t.Fatal("locale flag wrong")
	}
	parsed = mustParse(t, `(?u)x`, 0)
	if len(parsed.nodes) != 1 {
		t.Fatal("unicode flag wrong")
	}
}

func TestASCIICategoryPredicates(t *testing.T) {
	// every ASCII category interval set is exercised through the cache
	if iv := cachedCategoryIntervals(catNotDigit, true); iv.contains('5') || !iv.contains('x') {
		t.Fatal("ascii not-digit wrong")
	}
	if iv := cachedCategoryIntervals(catSpace, true); !iv.contains(' ') || iv.contains('x') {
		t.Fatal("ascii space wrong")
	}
	if iv := cachedCategoryIntervals(catNotSpace, true); iv.contains(' ') || !iv.contains('x') {
		t.Fatal("ascii not-space wrong")
	}
	if iv := cachedCategoryIntervals(catWord, true); !iv.contains('_') || iv.contains('!') {
		t.Fatal("ascii word wrong")
	}
	if iv := cachedCategoryIntervals(catNotWord, true); iv.contains('a') || !iv.contains('!') {
		t.Fatal("ascii not-word wrong")
	}
}

func TestTerminatorWalkGroupForms(t *testing.T) {
	// non-capping group: prefix continues
	if _, found := detectUnreachableTerminatorScan(`(?:a)[^x]*x`); found {
		t.Fatal("non-capping prefix flagged")
	}
	// capturing group: prefix continues
	if _, found := detectUnreachableTerminatorScan(`(a)[^x]*x`); found {
		t.Fatal("capturing prefix flagged")
	}
	// alternation resets the prefix
	if _, found := detectUnreachableTerminatorScan(`a|[^x]*x`); found {
		t.Fatal("alternation reset flagged")
	}
	// escaped alnum with a quantifier keeps the prefix
	if _, found := detectUnreachableTerminatorScan(`\d*[^x]*x`); found {
		t.Fatal("escaped alnum quantified flagged")
	}
	// negated class without quantifier: no finding
	if _, found := detectUnreachableTerminatorScan(`[^x]x`); found {
		t.Fatal("unquantified scan flagged")
	}
	// anchor reset
	if _, found := detectUnreachableTerminatorScan(`^[^x]*x`); found {
		t.Fatal("anchor reset flagged")
	}
}

func TestUnreachableTerminatorExcludedScanForms2(t *testing.T) {
	// escaped alnum branch of the excluded-scan walk: the negated class
	// still covers its terminator
	if !unreachableTerminatorExcludedScan(`\d\{[^x]*x`) {
		t.Fatal("escaped form walk diverged")
	}
	// a negated class whose terminator is NOT fully covered rejects
	if unreachableTerminatorExcludedScan(`[^x]+y`) {
		t.Fatal("uncovered terminator misclassified")
	}
	// defensive no-loop branch
	if unreachableTerminatorExcludedScan("") {
		t.Fatal("empty pattern classified")
	}
}

func TestPairingChainBranches(t *testing.T) {
	ctx, err := buildStrayContext(`\w+\d+`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	// an unbounded atom followed by an overlapping unbounded atom: the
	// chain appends a (fill, stray) unit from the overlap
	units, err := classIntersectionProbeUnits(`\w+\d+`, defaultPatternFlags, ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) == 0 {
		t.Fatal("expected pairing units")
	}
	// an unbounded atom followed by a non-pairing boundary: crossing path
	units, err = classIntersectionProbeUnits(`\w+\b\w`, defaultPatternFlags, ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = units
}

func TestPairingUnitsFromNonPairingLeft(t *testing.T) {
	// a leading group means no pairing left slot: no units
	units, err := pairingUnitsFrom(patternSlots(`(?:a)+b`, defaultPatternFlags), 0, nil)
	if err != nil || units != nil {
		t.Fatalf("non-pairing left wrong: %v %v", units, err)
	}
}

func TestAdvancePairingChainOverlapPath(t *testing.T) {
	slots := patternSlots(`a*a?`, defaultPatternFlags)
	left := slots[0].(pairingAtom)
	var units []fillStray
	shared, exact, stop, err := advancePairingChain(&units, left, left.intervals, slots[1].(pairingAtom), left.intervals, nil, nil)
	if err != nil || stop {
		t.Fatalf("chain wrong: %v %v", stop, err)
	}
	if shared.isEmpty() {
		t.Fatal("shared emptied on optional overlap")
	}
	_ = exact
}

func TestFlattenAlternativesSingle(t *testing.T) {
	alts := [][]reSlot{{pairingAtom{intervals: singleInterval('a')}}}
	if got := flattenAlternatives(alts); len(got) != 1 {
		t.Fatalf("single alternative flatten wrong: %d", len(got))
	}
}

func TestGroupCrossingResultUnion(t *testing.T) {
	alts := [][]reSlot{
		{pairingAtom{intervals: rangeIntervals(1, 5)}},
		{pairingAtom{intervals: rangeIntervals(10, 15)}},
	}
	got := groupCrossingResult(alts, fullIntervals(), 0)
	if got == nil || !got.contains(3) || !got.contains(12) {
		t.Fatalf("crossing union wrong: %v", got)
	}
}

func TestAlternativeCrossingGroupBoundary(t *testing.T) {
	// boundary group slot with inner narrows through the crossing
	alt := []reSlot{nonPairingSlot{isBoundary: true, inner: [][]reSlot{{pairingAtom{intervals: rangeIntervals(2, 8)}}}}}
	got := alternativeCrossing(alt, fullIntervals(), 0)
	if got == nil || !got.contains(5) || got.contains(9) {
		t.Fatalf("boundary crossing wrong: %v", got)
	}
	// non-boundary group slot leaves the shared set alone
	alt = []reSlot{nonPairingSlot{isBoundary: false, inner: [][]reSlot{{pairingAtom{intervals: rangeIntervals(2, 8)}}}}}
	got = alternativeCrossing(alt, fullIntervals(), 0)
	if got == nil || !got.contains(maxCodePoint) {
		t.Fatalf("non-boundary crossing wrong: %v", got)
	}
	// boundary group with nil inner fails
	alt = []reSlot{nonPairingSlot{isBoundary: true}}
	if got := alternativeCrossing(alt, fullIntervals(), 0); got != nil {
		t.Fatalf("nil-inner boundary should fail: %v", got)
	}
}

func TestIncludeBoundedRepeatsPairingOnly(t *testing.T) {
	included := includeBoundedRepeats([]reSlot{pairingAtom{intervals: singleInterval('a'), maxRepeat: 3}})
	atom, ok := included[0].(pairingAtom)
	if !ok || !atom.unbounded {
		t.Fatalf("pairing include wrong: %+v", included[0])
	}
}

func TestBuildersLongRunsCap(t *testing.T) {
	// a pattern with more than the run-variant cap
	runs := adversarialLiteralRuns(strings.Repeat("ab", 40))
	if len(runs) > 40 {
		t.Fatalf("runs wrong: %d", len(runs))
	}
	builders := literalRunBuilders(`foo.*bar`, nil)
	if len(builders) == 0 {
		t.Fatal("builders empty")
	}
}

func TestReachProbePrefixBuildersShortBody(t *testing.T) {
	// a synthesized probe body shorter than the first cut length
	builders := reachProbePrefixBuilders(`a{2}`, nil)
	_ = builders
}

func TestRepeatGroupUnitsDeepNested(t *testing.T) {
	pairs, err := repeatGroupUnits(`((a+)b)+`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	if pairs == nil {
		t.Fatal("nested units nil")
	}
}

func TestAmbiguousGroupFillBuildersBranches(t *testing.T) {
	// ambiguous group with a representative-less atom
	builders, err := ambiguousGroupFillBuilders(`(?:\bx)+`, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = builders
	builders, err = ambiguousGroupFillBuilders(`(?:a+b)+`, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = builders
}

func TestAmbiguousGroupFillUnitRepChars(t *testing.T) {
	unit, ok := ambiguousGroupFillUnit(`a+b?`)
	if !ok || !strings.HasPrefix(unit, "a") {
		t.Fatalf("unit wrong: %q %v", unit, ok)
	}
}

func TestReachProbeCostVerdictStructuralAccept(t *testing.T) {
	// the corpus's measured-override shapes stay accepted in cost mode
	for _, pattern := range []string{`<script[^>]*>`, `\$\([^)]+\)`, `\$\{[^}]+\}`} {
		safe, reason := reachProbeCostVerdict(pattern, 10000, defaultPatternFlags)
		if !safe || reason != "Pattern appears safe" {
			t.Fatalf("excluded-scan override wrong for %q: %v %q", pattern, safe, reason)
		}
	}
}

func TestReferenceScanSecondsOneSample(t *testing.T) {
	if got := referenceScanSeconds(1); got <= 0 {
		t.Fatalf("single sample wrong: %v", got)
	}
}

func TestRepresentativeCharForAtomNonPrintable(t *testing.T) {
	// printable-first ordering and the candidate fallback
	if ch, ok := representativeCharForAtom(`\d`); !ok || ch != '0' {
		t.Fatalf("digit rep wrong: %q", ch)
	}
	if _, ok := representativeCharForAtom("[^"); ok {
		t.Fatal("malformed atom should have no representative")
	}
}

func TestTimeProbesTimeoutShortSample(t *testing.T) {
	compiled, err := compileRE(`x`, regexp2OptionsForFlags(defaultPatternFlags), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	timing := timeProbes(compiled, []string{strings.Repeat("x", 100)}, reachProbeSampleCount)
	if len(timing.samplesBySize[0]) != 1 {
		t.Fatalf("fast probe sample count wrong: %d", len(timing.samplesBySize[0]))
	}
}
