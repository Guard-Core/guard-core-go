package guardcore

// Branch-sweep tests for the static-safety layer: every error return,
// defensive branch and fallback path the validator exposes, exercised
// directly (the corpus pins the verdicts; this file pins the branches).

import (
	"strings"
	"testing"
	"time"
)

func TestWildcardAbsorbsLiteralEmptyClassSet(t *testing.T) {
	// a class whose printable set is empty (backspace-only) cannot absorb
	if _, found := detectAmbiguousLiteralBoundary(`[\b]*ab`); found {
		t.Fatal("empty-set class flagged")
	}
}

func TestParseFlatQuantifiedAtomsEdgeShapes(t *testing.T) {
	// '|' at the head rejects the flat parse
	if atoms := parseFlatQuantifiedAtomsWithText("|a"); atoms != nil {
		t.Fatalf("alternation head should reject: %+v", atoms)
	}
	// quantifier after class with lazy marker
	atoms := parseFlatQuantifiedAtomsWithText(`[ab]+?`)
	if len(atoms) != 1 || !atoms[0].unbounded {
		t.Fatalf("lazy class atom wrong: %+v", atoms)
	}
	// a trailing escape is its own atom span (reference _raw_atom_span)
	if atoms := parseFlatQuantifiedAtomsWithText(`a\`); atoms == nil || len(atoms) != 2 {
		t.Fatalf("trailing escape atom wrong: %+v", atoms)
	}
}

func TestBraceQuantifierVariabilityEdges(t *testing.T) {
	if _, ok := parseBraceQuantifierWithVariability("a{}", 1); ok {
		t.Fatal("empty brace should reject")
	}
	if _, ok := parseBraceQuantifierWithVariability("a{,}", 1); ok {
		t.Fatal("comma-only brace should reject")
	}
}

func TestLiteralRunPastEnd(t *testing.T) {
	run, end := literalRunAt(`abc`, 3)
	if run != "" || end != 3 {
		t.Fatalf("past-end run wrong: %q %d", run, end)
	}
}

func TestDetectAmbiguousOptionalTailError(t *testing.T) {
	deep := strings.Repeat("(", maxGroupNestingDepth+1) + "a" + strings.Repeat(")", maxGroupNestingDepth+1)
	if _, found, _ := detectAmbiguousOptionalTail(deep); !found {
		t.Fatal("depth rejection expected")
	}
}

func TestReferenceScanSecondsError(t *testing.T) {
	if got := referenceScanSeconds(0); got != 0 {
		t.Fatalf("zero samples wrong: %v", got)
	}
}

func TestTimeProbesTimeoutTrip(t *testing.T) {
	compiled, err := compileRE(`(\d|\w)*;`, regexp2OptionsForFlags(defaultPatternFlags), 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	timing := timeProbes(compiled, []string{strings.Repeat("0", 6000)}, reachProbeSampleCount)
	if len(timing.samplesBySize) != 1 || len(timing.samplesBySize[0]) != 1 {
		t.Fatalf("timeout trip samples wrong: %+v", timing.samplesBySize)
	}
	if timing.samplesBySize[0][0] < 0.04 {
		t.Fatalf("timeout sample should record the kill budget: %v", timing.samplesBySize[0])
	}
}

func TestFirstOverBudgetReasonCompileFailure(t *testing.T) {
	deadline := time.Now().Add(10 * time.Second)
	reason, over := firstOverBudgetReason("(unclosed", []probeBuilder{func(int) string { return "x" }}, 10000, "", deadline, defaultPatternFlags, false)
	if !over || !strings.HasPrefix(reason, "Pattern validation failed: ") {
		t.Fatalf("compile failure path wrong: %v %q", over, reason)
	}
}

func TestFirstOverBudgetReasonDeadlineExceeded(t *testing.T) {
	deadline := time.Now().Add(-time.Second)
	reason, over := firstOverBudgetReason(`'[^']*'`, []probeBuilder{func(int) string { return "x" }}, 10000, "structural", deadline, defaultPatternFlags, false)
	if !over || reason != "structural" {
		t.Fatalf("deadline path wrong: %v %q", over, reason)
	}
}

func TestFirstOverBudgetReasonInvalidTiming(t *testing.T) {
	deadline := time.Now().Add(10 * time.Second)
	// a compile whose engine errors on every search yields unusable rows
	compiled, err := compileRE(`x`, regexp2OptionsForFlags(defaultPatternFlags), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_ = compiled
	// a builder that produces probes longer than the compiled pattern can
	// handle is not a thing; instead exercise the invalid-rows path via a
	// zero-sample probe set
	builders := []probeBuilder{func(int) string { return "" }}
	reason, over := firstOverBudgetReason(`'[^']*'`, builders, 10000, "", deadline, defaultPatternFlags, false)
	if over {
		t.Fatalf("empty probes should not reject: %q", reason)
	}
}

func TestReachProbeCostVerdictCompileFailure(t *testing.T) {
	// x{3,2} is a literal brace sequence in the Python-re grammar that the
	// regexp2 timing engine rejects (min>max); the stray-context build
	// surfaces the engine error and the verdict fails closed on the builder
	// path
	safe, reason := reachProbeCostVerdict(`x{3,2}`, 10000, defaultPatternFlags)
	if safe || !strings.Contains(reason, "probe construction exceeded its deadline") {
		t.Fatalf("builder error path wrong: %v %q", safe, reason)
	}
}

func TestReachProbeCostVerdictUnreachableProbe(t *testing.T) {
	// a mandatory repeat beyond the probe budget fails synthesis
	safe, reason := reachProbeCostVerdict(`a{24001,}`, 10000, defaultPatternFlags)
	class := structuralViolationClass(reason)
	if safe || class != "unreachable_probe" {
		t.Fatalf("unreachable probe wrong: safe=%v class=%s (%q)", safe, class, reason)
	}
}

func TestReachProbeCostVerdictStructuralFlags(t *testing.T) {
	// structural flag + unreachable synthesis -> structural reason
	safe, reason := reachProbeCostVerdict(`foo.*(?:unclosed`, 10000, defaultPatternFlags)
	if safe {
		t.Fatalf("mixed path should not accept: %q", reason)
	}
}

func TestValidatePatternSafetyStringsProbeTimeout(t *testing.T) {
	// a hostile string trips the per-string threshold on a slow pattern
	safe, reason := ValidatePatternSafetyStrings(`(\d|\w)*z`, []string{strings.Repeat("0", 20000)})
	if safe {
		t.Fatalf("hostile probe string should reject: %q", reason)
	}
	if class := structuralViolationClass(reason); class != "probe_string_timeout" {
		t.Fatalf("timeout class wrong: %s (%q)", class, reason)
	}
}

func TestNodeIntervalsRepeatAndGroup(t *testing.T) {
	parsed := mustParse(t, `a*`, 0)
	if iv := nodeIntervals(&parsed.nodes[0], 0); !iv.contains('a') {
		t.Fatal("repeat intervals wrong")
	}
	parsed = mustParse(t, `(?:a|b)`, 0)
	if iv := nodeIntervals(&parsed.nodes[0], 0); !iv.contains('a') {
		t.Fatal("group intervals wrong")
	}
}

func TestRepresentativeCharForNodeFallback(t *testing.T) {
	// an atom whose intervals contain no printable char falls back to the
	// smallest member
	if ch, ok := representativeCharForAtom(`[\x01]`); !ok || ch != 1 {
		t.Fatalf("fallback rep wrong: %q %v", ch, ok)
	}
}

func TestRepeatUnitBuilderNilStray(t *testing.T) {
	builder := repeatUnitBuilder(nil, "ab")
	if got := builder(5); !strings.HasPrefix(got, "ab") {
		t.Fatalf("nil-ctx builder wrong: %q", got)
	}
}

func TestClassIntersectionBuildersEmpty(t *testing.T) {
	builders, err := classIntersectionBuilders(`abc`, defaultPatternFlags, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(builders) != 0 {
		t.Fatalf("literal-only pattern should have no class builders: %d", len(builders))
	}
}

func TestAmbiguousGroupFillUnitEdges(t *testing.T) {
	if unit, ok := ambiguousGroupFillUnit("(a)+"); ok {
		t.Fatalf("group inner should have no flat unit: %q", unit)
	}
	if unit, ok := ambiguousGroupFillUnit("a"); ok && unit != "a" {
		t.Fatalf("single atom unit wrong: %q", unit)
	}
	if _, ok := ambiguousGroupFillUnit(`\b+`); ok {
		t.Fatal("zero-width unit should not build")
	}
}

func TestReachProbeCandidateBuildersError(t *testing.T) {
	// an unclosed pattern fails during stray-context construction
	if _, err := reachProbeCandidateBuilders("(unclosed", defaultPatternFlags); err == nil {
		t.Fatal("unclosed pattern should fail builder construction")
	}
}

func TestDedupFillStrays(t *testing.T) {
	units := []fillStray{{fill: 'a', stray: "z"}, {fill: 'a', stray: "z"}, {fill: 'b', stray: "z"}}
	got := dedupFillStrays(units)
	if len(got) != 2 {
		t.Fatalf("dedup fill strays wrong: %v", got)
	}
}

func TestRunesToStrings(t *testing.T) {
	got := runesToStrings([]rune{'a', 'b'})
	if len(got) != 2 || got[0] != "a" {
		t.Fatalf("runes to strings wrong: %v", got)
	}
}

func TestRepeatGroupUnitsNested(t *testing.T) {
	pairs, err := repeatGroupUnits(`((a)+b)+`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	if pairs == nil {
		t.Fatal("nested group units nil")
	}
}

func TestEscapesAndClassesEdges(t *testing.T) {
	// category predicate default branch
	if !categoryPredicate(999, false)(42) {
		t.Fatal("unknown category should accept all")
	}
	// simple escape full set
	for _, c := range []byte{'n', 'r', 't', 'f', 'v', 'a'} {
		if _, ok := simpleEscapeChar(c); !ok {
			t.Fatalf("escape %c missing", c)
		}
	}
	if _, ok := simpleEscapeChar('q'); ok {
		t.Fatal("unknown escape accepted")
	}
	// hex escape widths
	if err := mustFailParse(t, `\u00`, defaultPatternFlags); err.msg == "" {
		t.Fatal("short u escape should fail")
	}
	if err := mustFailParse(t, `\U0000`, defaultPatternFlags); err.msg == "" {
		t.Fatal("short U escape should fail")
	}
	if err := mustFailParse(t, `\xZZ`, defaultPatternFlags); err.msg == "" {
		t.Fatal("bad hex digits should fail")
	}
	if mapWidth(4) != "u" || mapWidth(8) != "U" {
		t.Fatal("mapWidth wrong")
	}
}

func TestParseCharClassEdgeMembers(t *testing.T) {
	// escapes and categories inside classes
	mustParse(t, `[\x41-\x5A]`, 0)
	mustParse(t, `[\u0041]`, 0)
	mustParse(t, `[\U0001F600]`, 0)
	mustParse(t, `[\1-\5]`, 0)
	mustParse(t, `[\010]`, 0)
	if err := mustFailParse(t, `[z-\d]`, 0); err.msg == "" {
		t.Fatal("category high range should fail")
	}
	// ']' as the first member is a literal
	parsed := mustParse(t, `[]]`, 0)
	if !parsed.nodes[0].interval.contains(']') {
		t.Fatal("leading close bracket should be a member")
	}
	// '-' at the end is a literal
	parsed = mustParse(t, `[a-]`, 0)
	if !parsed.nodes[0].interval.contains('-') {
		t.Fatal("trailing dash should be a member")
	}
}

func TestParseQuantifierEdges(t *testing.T) {
	// quantifier overflow mirrors the reference's OverflowError
	err := mustFailParse(t, `a{99999999999999}`, defaultPatternFlags)
	if err.msg != "the repetition number is too large" {
		t.Fatalf("overflow quantifier wrong: %v", err)
	}
	// low > high is a malformed brace -> literal atom
	parsed := mustParse(t, `a{3,2}`, defaultPatternFlags)
	if len(parsed.nodes) != 6 {
		t.Fatalf("low>high literal wrong: %d", len(parsed.nodes))
	}
}

func TestParseInlineFlagEdges(t *testing.T) {
	// duplicate flags are accepted (the reference ORs them)
	mustParse(t, `(?ii)`, defaultPatternFlags)
	// negative-only group
	mustParse(t, `(?-i:x)`, flagIgnoreCase)
	// u flag accepted
	mustParse(t, `(?u)x`, 0)
}

func TestParseGroupEdges(t *testing.T) {
	if err := mustFailParse(t, `(?P<a`, defaultPatternFlags); err.msg == "" {
		t.Fatal("unterminated named group should fail")
	}
	// nested unclosed
	if err := mustFailParse(t, `(a(b`, defaultPatternFlags); err.msg != "missing ), unterminated subpattern" {
		t.Fatalf("nested unclosed wrong: %v", err)
	}
}

func TestParseLookaroundEdges(t *testing.T) {
	mustParse(t, `(?=(a))b`, 0)
	mustParse(t, `(?!(a))b`, 0)
	mustParse(t, `(?<=(a))b`, 0)
	mustParse(t, `(?<!(a))b`, 0)
}

func TestSkipVerboseEdges(t *testing.T) {
	parsed := mustParse(t, "(?x)a#comment-at-end", 0)
	if len(parsed.nodes) != 1 {
		t.Fatalf("verbose trailing comment wrong: %d", len(parsed.nodes))
	}
}

func TestSkipBraceQuantifierEdges(t *testing.T) {
	if got := skipBraceQuantifierAt(`{2}ab`, 0); got != 3 {
		t.Fatalf("exact brace skip wrong: %d", got)
	}
}

func TestTerminatorAtEnd(t *testing.T) {
	if _, ok := terminatorCharsAt(`abc`, 3); ok {
		t.Fatal("terminator past end should be undecidable")
	}
}

func TestBroadScanEmptyClass(t *testing.T) {
	if end, excluded, ok := broadScanExcludedChars(`[]x`, 0); ok {
		t.Fatalf("empty class should be undecidable: %d %v", end, excluded)
	}
}

func TestClassTerminatorFindingNoQuantifier(t *testing.T) {
	// an unquantified broad scan has no finding
	if finding, found := classTerminatorFinding(`.a`, 0, 1, map[rune]bool{'x': true}, map[rune]bool{}); found {
		t.Fatalf("unquantified scan flagged: %q", finding)
	}
}

func TestUnreachableTerminatorGroupForms(t *testing.T) {
	// named and lookahead groups reset or skip the prefix walk
	if _, found := detectUnreachableTerminatorScan(`(?P<n>a)[^x]*x`); found {
		t.Fatal("named-group prefix reset flagged")
	}
	if _, found := detectUnreachableTerminatorScan(`(?=a)[^x]*x`); found {
		t.Fatal("lookahead skip flagged")
	}
	// an unterminated lookahead scans as literals (the walk has no
	// balanced-paren requirement, matching the reference)
	if _, found := detectUnreachableTerminatorScan(`(?=a[^x]*x`); !found {
		t.Fatal("unterminated lookahead walk diverged")
	}
}

func TestUnreachableTerminatorExcludedScanForms(t *testing.T) {
	if unreachableTerminatorExcludedScan(`(?=a)[^x]*x`) {
		t.Fatal("lookahead form misclassified")
	}
	if unreachableTerminatorExcludedScan(`foo.*bar`) {
		t.Fatal("dot scan misclassified")
	}
}

func TestStrayContextSearchMatchesError(t *testing.T) {
	// a pattern the regexp2 engine cannot compile falls back through the
	// builder error path
	_, err := buildStrayContext(`\C`, defaultPatternFlags)
	if err == nil {
		t.Fatal("regexp2-incompatible pattern should fail context build")
	}
}

func TestSearchMatchesTimeoutCountsAsMatch(t *testing.T) {
	ctx, err := buildStrayContext(`(\d|\w)*;`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	// an exploding probe "matches" under the fail-closed rule
	if !ctx.searchMatches(strings.Repeat("0", 8000)) {
		t.Fatal("timeout probe should count as a match")
	}
}

func TestClassIntersectionStrayCandidatesOrder(t *testing.T) {
	tail := []*intervalSet{singleInterval('a')}
	candidates := classIntersectionStrayCandidates(tail, singleInterval('a'), singleInterval('a'), singleInterval('a'))
	if len(candidates) == 0 {
		t.Fatal("no candidates")
	}
}

func TestChooseClassIntersectionStrayFallback(t *testing.T) {
	ctx, err := buildStrayContext(`a*a*`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	// a full-interval pair has no complement: the fallback byte decides
	stray, err := chooseClassIntersectionStray(ctx, 'a', fullIntervals(), fullIntervals(), nil)
	if err != nil || stray != reachProbeStrayByte {
		t.Fatalf("fallback stray wrong: %q %v", stray, err)
	}
}

func TestIntervalSlotMethods(t *testing.T) {
	var slot reSlot = pairingAtom{}
	slot.isSlot()
	slot = nonPairingSlot{}
	slot.isSlot()
}

func TestPairingOrNonPairingShapes(t *testing.T) {
	// group-ref and anchor slots
	slot := pairingOrNonPairing(&reNode{op: opGroupRef, refIdx: 1}, 0, false, true, noMaxRepeat, false)
	np, ok := slot.(nonPairingSlot)
	if !ok || !np.isBoundary {
		t.Fatalf("group-ref slot wrong: %+v", slot)
	}
	slot = pairingOrNonPairing(&reNode{op: opAt}, 0, false, false, noMaxRepeat, false)
	np, ok = slot.(nonPairingSlot)
	if !ok || np.isBoundary {
		t.Fatalf("anchor slot wrong: %+v", slot)
	}
	slot = pairingOrNonPairing(&reNode{op: opAssert, body: []reNode{{op: opLiteral, ch: 'a'}}}, 0, false, false, noMaxRepeat, false)
	np, ok = slot.(nonPairingSlot)
	if !ok || np.inner == nil {
		t.Fatalf("assert slot wrong: %+v", slot)
	}
	slot = pairingOrNonPairing(&reNode{op: 999}, 0, false, false, noMaxRepeat, false)
	np, ok = slot.(nonPairingSlot)
	if !ok || !np.isBoundary {
		t.Fatalf("unknown op fallback wrong: %+v", slot)
	}
	slot = pairingOrNonPairing(&reNode{op: opBranch, branches: [][]reNode{{{op: opIn, interval: singleInterval('a')}}}}, 0, false, false, noMaxRepeat, false)
	np, ok = slot.(nonPairingSlot)
	if !ok || len(np.inner) != 1 {
		t.Fatalf("branch slot wrong: %+v", slot)
	}
}

func TestCanRepeatAndSlotVariableBounded(t *testing.T) {
	if !canRepeat(pairingAtom{unbounded: true}) {
		t.Fatal("unbounded cannot-repeat wrong")
	}
	if !canRepeat(pairingAtom{maxRepeat: 3}) {
		t.Fatal("bounded cannot-repeat wrong")
	}
	if canRepeat(pairingAtom{}) {
		t.Fatal("plain atom repeats")
	}
	if !canRepeat(nonPairingSlot{unbounded: true}) {
		t.Fatal("group cannot-repeat wrong")
	}
	if !slotVariableBounded(pairingAtom{variableBounded: true, maxRepeat: 5000}) {
		t.Fatal("variable bounded atom wrong")
	}
	if !slotVariableBounded(nonPairingSlot{variableBounded: true, maxRepeat: 5000}) {
		t.Fatal("variable bounded group wrong")
	}
}

func TestPatternComplementCharsDedup(t *testing.T) {
	chars := patternComplementChars(`\d\d`, defaultPatternFlags)
	if len(chars) != 1 {
		t.Fatalf("duplicate complement chars wrong: %v", chars)
	}
}

func TestPatternSlotsWalkSequence(t *testing.T) {
	slots := patternSlots(`abc`, 0)
	if len(slots) != 3 {
		t.Fatalf("literal slots wrong: %d", len(slots))
	}
}

func TestLazyMarkerLen(t *testing.T) {
	if lazyMarkerLen("a?b", 1) != 1 || lazyMarkerLen("ab", 1) != 0 {
		t.Fatal("lazy marker len wrong")
	}
}

func TestQuantifierSpanAllowsZeroForms(t *testing.T) {
	if _, zero := quantifierSpanAllowsZero(`{,3}ab`, 0); !zero {
		t.Fatal("open-low brace should allow zero")
	}
	if end, _ := quantifierSpanAllowsZero(`{3,ab`, 0); end != 0 {
		t.Fatalf("malformed brace span wrong: %d", end)
	}
}

func TestAdversarialRunEdgeForms(t *testing.T) {
	// escaping punctuation keeps the run open
	runs := adversarialLiteralRuns(`a\-b`)
	if len(runs) != 1 || runs[0] != "a-b" {
		t.Fatalf("escaped dash run wrong: %q", runs)
	}
	// empty pattern
	if runs := adversarialLiteralRuns(``); len(runs) != 0 {
		t.Fatalf("empty runs wrong: %q", runs)
	}
}

func TestUnwrapLeadingTransparentGroupEdges(t *testing.T) {
	if got := unwrapLeadingTransparentGroup(`(?:a`); got != `(?:a` {
		t.Fatalf("unbalanced unwrap wrong: %q", got)
	}
	if got := unwrapLeadingTransparentGroup(`(?P<n>a)`); got != `(?P<n>a)` {
		t.Fatalf("named unwrap wrong: %q", got)
	}
}

func TestValidatePatternSafetyStructure(t *testing.T) {
	// a pattern with a valid compile but a probe-time compile failure path
	safe, reason := ValidatePatternSafety(`\C`, []string{"x"}, 0, 0)
	if safe || reason == "" {
		t.Fatalf("regexp2-incompatible probe path wrong: %v %q", safe, reason)
	}
}

func TestParseEscapeAtomEdge(t *testing.T) {
	// a two-digit reference above the opened-group count rejects
	err := mustFailParse(t, `(a)\11`, defaultPatternFlags)
	if err.msg != "invalid group reference 11" {
		t.Fatalf("two-digit reference wrong: %v", err)
	}
	parsed := mustParse(t, `(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)\1k`, 0)
	if len(parsed.nodes) != 12 {
		t.Fatalf("backref + literal wrong: %d", len(parsed.nodes))
	}
}

func TestBuildStrayContextCompileIncompatible(t *testing.T) {
	// (?P=...) style patterns compile in Python but not regexp2; the
	// context build surfaces the engine error
	if _, err := buildStrayContext(`(?P=x)`, defaultPatternFlags); err == nil {
		t.Fatal("regexp2-incompatible pattern should fail")
	}
}

func TestCompileForProbeNamedGroups(t *testing.T) {
	if _, err := compileForProbe(`(?P<n>a)\Z`, defaultPatternFlags, time.Second); err != nil {
		t.Fatalf("named group probe compile wrong: %v", err)
	}
}

func TestReferenceScanSecondsWithWork(t *testing.T) {
	if got := referenceScanSeconds(2); got <= 0 {
		t.Fatalf("reference scan measurement wrong: %v", got)
	}
}

func TestMedianSamples(t *testing.T) {
	if got := median([]float64{1, 5, 9}); got != 5 {
		t.Fatalf("median wrong: %v", got)
	}
}
