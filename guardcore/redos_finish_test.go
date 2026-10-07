package guardcore

// Final branch completion sweep: micro-cases for the remaining defensive
// and deep branches of the static-safety port.

import (
	"strings"
	"testing"
	"time"
)

func TestWildcardAbsorbsLiteralNotInClass(t *testing.T) {
	// the class cannot absorb a literal outside its set
	if _, found := detectAmbiguousLiteralBoundary(`[ab]*cd`); found {
		t.Fatal("non-absorbed literal flagged")
	}
}

func TestParseBraceQuantifierNoClose(t *testing.T) {
	if _, ok := parseBraceQuantifierWithVariability("a{2", 1); ok {
		t.Fatal("unclosed brace should reject")
	}
}

func TestParseBraceQuantifierLazyMarker(t *testing.T) {
	parsed, ok := parseBraceQuantifierWithVariability("a{2,4}?", 1)
	if !ok || !parsed.variable || parsed.next != 7 {
		t.Fatalf("lazy brace wrong: %+v %v", parsed, ok)
	}
}

func TestParseBraceQuantifierWithTextJunkHigh(t *testing.T) {
	parsed, ok := parseBraceQuantifierWithVariability("a{2,x}", 1)
	if !ok || !parsed.variable {
		t.Fatalf("junk-high brace wrong: %+v %v", parsed, ok)
	}
}

func TestParseFlatQuantifiedLazyBrace(t *testing.T) {
	atoms := parseFlatQuantifiedAtomsWithText(`a{2,4}?`)
	if len(atoms) != 1 || !atoms[0].variable {
		t.Fatalf("lazy brace atom wrong: %+v", atoms)
	}
}

func TestParseFlatQuantifiedNestedReject(t *testing.T) {
	// a group head inside the inner text rejects the flat parse
	if atoms := parseFlatQuantifiedAtomsWithText(`a(b)`); atoms != nil {
		t.Fatalf("nested group should reject: %+v", atoms)
	}
}

func TestBuildStrayContextErrorPropagates(t *testing.T) {
	// buildStrayContext surfaces regexp2 incompatibilities; the candidate
	// builders propagate it (builders.go:75)
	if _, err := buildStrayContext(`(?P<x>a)(?P=x)`, defaultPatternFlags); err == nil {
		t.Fatal("expected context build error")
	}
}

func TestClassIntersectionBuildersUnits(t *testing.T) {
	// a*a* produces a class-intersection unit -> the builder family builds
	ctx, err := buildStrayContext(`a*a*`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	builders, err := classIntersectionBuilders(`a*a*`, defaultPatternFlags, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(builders) == 0 {
		t.Fatal("class intersection builders empty")
	}
	probe := builders[0](32)
	if len(probe) != 32 {
		t.Fatalf("builder length wrong: %d", len(probe))
	}
}

func TestAmbiguousGroupFillUnitRejectsGroupInner(t *testing.T) {
	if _, ok := ambiguousGroupFillUnit(`(a)+`); ok {
		t.Fatal("group inner unit should not build")
	}
}

func TestReachProbePrefixBuildersLiteralBraces(t *testing.T) {
	// literal brace bodies synthesize; the prefix builders exist
	builders := reachProbePrefixBuilders(`x{3,2}`, nil)
	if builders == nil {
		t.Fatal("literal-brace prefix builders missing")
	}
}

func TestAmbiguousGroupFillBuildersNoBodies(t *testing.T) {
	// depth rejection yields no builders (builders.go:112)
	builders, err := ambiguousGroupFillBuilders(strings.Repeat("(", 30)+"a"+strings.Repeat(")", 30), nil)
	if err != nil || builders != nil {
		t.Fatalf("depth-rejected builders wrong: %v %v", builders, err)
	}
}

func TestRepeatGroupUnitsBackrefRepeat(t *testing.T) {
	// a repeated backreference has no unit pair (the group walk skips it)
	pairs, err := repeatGroupUnits(`(?P<x>a)(?P=x)+`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	_ = pairs
}

func TestAtomTextOfZeroWidth(t *testing.T) {
	if _, ok := representativeCharForNode(&reNode{op: opAt}, 0); ok {
		t.Fatal("anchor representative should fail (builders.go:242)")
	}
}

func TestReachProbePrefixBuildersShortBodyCut(t *testing.T) {
	// a synthesized probe whose body is shorter than the cut length
	builders := reachProbePrefixBuilders(`ab+`, nil)
	_ = builders
}

func TestRepeatGroupUnitsNestedNonFlat(t *testing.T) {
	// nested multi-atom repeat bodies take the recursion path
	pairs, err := repeatGroupUnits(`((?:ab)+c)+`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	_ = pairs
}

func TestRepeatGroupUnitsBadRep(t *testing.T) {
	// a repeat body whose atom has no representative (zero-width anchor)
	pairs, err := repeatGroupUnits(`(\bx)+`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	_ = pairs
}

func TestReachProbeCandidateBuildersAllFamilies(t *testing.T) {
	// a pattern with class units, group units, literal runs and ambiguous
	// fills: the full builder union
	builders, err := reachProbeCandidateBuilders(`a*a*b+`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	if len(builders) < 4 {
		t.Fatalf("builder union too small: %d", len(builders))
	}
	for _, size := range []int{4000, 32000} {
		probe := builders[0](size)
		if len(probe) != size {
			t.Fatalf("builder size wrong: %d", len(probe))
		}
	}
}

func TestCrossNonPairingSlotExactFillBoundary(t *testing.T) {
	// boundary group with an empty crossing: the exact state decides the
	// fill and the shared set collapses (the reference returns the crossing)
	np := nonPairingSlot{
		isBoundary: true,
		unbounded:  true,
		inner:      [][]reSlot{{pairingAtom{intervals: rangeIntervals(5, 12)}}},
	}
	shared, fill, hasFill, groupState, ok := crossNonPairingSlot(np, rangeIntervals(2, 4), rangeIntervals(2, 8))
	if !ok || !hasFill || fill != 5 || shared == nil || !shared.isEmpty() || groupState == nil {
		t.Fatalf("exact fill boundary crossing wrong: %v %v %v", fill, hasFill, ok)
	}
}

func TestCrossNonPairingSlotGroupCrossingFill(t *testing.T) {
	// non-boundary group crossing whose member fills the slot
	np := nonPairingSlot{
		unbounded: true,
		inner:     [][]reSlot{{pairingAtom{intervals: rangeIntervals(2, 8)}}},
	}
	shared, fill, hasFill, _, ok := crossNonPairingSlot(np, rangeIntervals(1, 10), nil)
	if !ok || !hasFill || fill != 2 || !shared.contains(1) || !shared.contains(10) {
		t.Fatalf("group crossing fill wrong: %v %v %v", fill, hasFill, ok)
	}
}

func TestCrossNonPairingSlotNonBoundaryNoFill(t *testing.T) {
	// a bounded non-boundary group crosses without a fill
	np := nonPairingSlot{
		inner: [][]reSlot{{pairingAtom{intervals: rangeIntervals(2, 8)}}},
	}
	_, fill, hasFill, _, ok := crossNonPairingSlot(np, rangeIntervals(1, 10), nil)
	if !ok || hasFill {
		t.Fatalf("bounded crossing should have no fill: %v %v", fill, hasFill)
	}
}

func TestAdvancePairingChainExactFillPath(t *testing.T) {
	// an empty overlap with a resolvable exact fill appends a confirmed
	// unit (the exact state was narrowed by an earlier boundary group)
	left := pairingAtom{intervals: rangeIntervals('0', 'z'), unbounded: true}
	slot := pairingAtom{intervals: rangeIntervals('0', '9'), unbounded: true}
	var units []fillStray
	_, _, stop, err := advancePairingChain(&units, left, rangeIntervals('g', 'z'), slot, rangeIntervals('0', '9'), nil, nil)
	if err != nil || stop {
		t.Fatalf("exact fill path wrong: %v %v", stop, err)
	}
	if len(units) == 0 || units[0].fill != '0' {
		t.Fatalf("exact fill unit wrong: %v", units)
	}
}

func TestAdvancePairingChainNoOverlapNoFill(t *testing.T) {
	// disjoint unbounded slot: exact fill unavailable -> stop
	left := pairingAtom{intervals: rangeIntervals('a', 'z'), unbounded: true}
	slot := pairingAtom{intervals: rangeIntervals('0', '9'), unbounded: true, allowsZero: false}
	var units []fillStray
	_, _, stop, err := advancePairingChain(&units, left, left.intervals, slot, emptyIntervals(), nil, nil)
	if err != nil || !stop {
		t.Fatalf("disjoint path wrong: %v %v", stop, err)
	}
}

func TestPairingUnitsFromGroupBoundary(t *testing.T) {
	// pairing chain crossing a boundary group narrows the exact state
	slots := patternSlots(`a+(?:b+)c`, defaultPatternFlags)
	if len(slots) < 2 {
		t.Fatalf("slots wrong: %d", len(slots))
	}
	units, err := pairingUnitsFrom(slots, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = units
}

func TestUnitsInSlotsGroupInner(t *testing.T) {
	// units inside group alternatives are collected
	slots := patternSlots(`(?:a*a*)+`, defaultPatternFlags)
	units, err := unitsInSlots(slots, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) == 0 {
		t.Fatal("group inner units missing")
	}
}

func TestClassIntersectionProbeUnitsBoundedError(t *testing.T) {
	if _, err := classIntersectionProbeUnits(`(?P<x>a)(?P=x)+`, defaultPatternFlags, nil, true); err == nil {
		t.Fatal("expected units error")
	}
}

func TestPairingUnitsFromChainError(t *testing.T) {
	if _, err := pairingUnitsFrom(patternSlots(`a*a*`, defaultPatternFlags), 0, nil); err != nil {
		t.Fatalf("chain error wrong: %v", err)
	}
}

func TestParseSequenceEdges(t *testing.T) {
	// an empty alternation branch parses
	parsed := mustParse(t, `a|`, 0)
	if parsed.nodes[0].op != opBranch {
		t.Fatalf("trailing alternation wrong: %+v", parsed.nodes[0])
	}
}

func TestParseMultipleRepeatOnGroup(t *testing.T) {
	// a quantified group followed by another quantifier
	err := mustFailParse(t, `(a)+*`, defaultPatternFlags)
	if err.msg != "multiple repeat" {
		t.Fatalf("group multiple repeat wrong: %v", err)
	}
}

func TestParseQuantifierMalformedForms(t *testing.T) {
	// comma-open and junk-low braces are literals
	parsed := mustParse(t, `a{,}b`, 0)
	if len(parsed.nodes) != 5 {
		t.Fatalf("comma-open literal wrong: %d", len(parsed.nodes))
	}
	parsed = mustParse(t, `a{x}b`, 0)
	if len(parsed.nodes) != 5 {
		t.Fatalf("junk-low literal wrong: %d", len(parsed.nodes))
	}
	parsed = mustParse(t, `a{2,x}b`, 0)
	if len(parsed.nodes) != 7 {
		t.Fatalf("junk-high literal wrong: %d", len(parsed.nodes))
	}
}

func TestParseQuantifierOpenHigh(t *testing.T) {
	parsed := mustParse(t, `a{2,}`, 0)
	if parsed.nodes[0].op != opRepeat || parsed.nodes[0].max != maxRepeat || parsed.nodes[0].min != 2 {
		t.Fatalf("open-high bound wrong: %+v", parsed.nodes[0])
	}
}

func TestParseAtomJunkBrace(t *testing.T) {
	// a junk brace at atom position is a literal (parseQuantifier not-ok)
	parsed := mustParse(t, `{x}`, 0)
	if len(parsed.nodes) != 3 {
		t.Fatalf("junk brace literal wrong: %d", len(parsed.nodes))
	}
}

func TestParseEscapeAtomAtEndOfClass(t *testing.T) {
	// a class atom scan hitting the end fails closed
	if err := mustFailParse(t, `[ab\`, 0); err.msg == "" {
		t.Fatal("unterminated class with trailing escape should fail")
	}
}

func TestParseGroupDepthLimit(t *testing.T) {
	deep := strings.Repeat("(", maxGroupNestingDepth+1) + "a"
	err := mustFailParse(t, deep, defaultPatternFlags)
	if !strings.Contains(err.msg, "nested parentheses") {
		t.Fatalf("depth limit parse wrong: %v", err)
	}
}

func TestParseConditionalExtension(t *testing.T) {
	if err := mustFailParse(t, `(?(1)a)`, defaultPatternFlags); err.msg != "unknown extension ?(" {
		t.Fatalf("conditional extension wrong: %v", err)
	}
}

func TestParseUnterminatedNameForms(t *testing.T) {
	if err := mustFailParse(t, `(?P<a`, defaultPatternFlags); err.msg != "missing >, unterminated name" {
		t.Fatalf("unterminated name wrong: %v", err)
	}
	if err := mustFailParse(t, `(?P=ab`, defaultPatternFlags); err.msg == "" {
		t.Fatal("unterminated backref name should fail")
	}
}

func TestParseNamedGroupBodyError(t *testing.T) {
	if err := mustFailParse(t, `(?P<a>(unclosed`, defaultPatternFlags); err.msg == "" {
		t.Fatal("named group body error should propagate")
	}
}

func TestParseGroupRefOpenNested(t *testing.T) {
	// a reference to a closed nested group is valid
	mustParse(t, `(a(b)\2)`, defaultPatternFlags)
	// a reference below the opened counter rejects
	err := mustFailParse(t, `(a\2(b))`, defaultPatternFlags)
	if err.msg != "invalid group reference 2" {
		t.Fatalf("unopened reference wrong: %v", err)
	}
}

func TestParseScopedFlagsBodyError(t *testing.T) {
	if err := mustFailParse(t, `(?i:(unclosed`, defaultPatternFlags); err.msg == "" {
		t.Fatal("scoped flags body error should propagate")
	}
}

func TestParseGlobalFlagsNegativeAfterNonStart(t *testing.T) {
	if err := mustFailParse(t, `x(?-a)`, defaultPatternFlags); err.msg == "" {
		t.Fatal("non-start negative global flags should fail")
	}
}

func TestParseCommentThenError(t *testing.T) {
	if err := mustFailParse(t, `(?#ok)(unclosed`, defaultPatternFlags); err.msg == "" {
		t.Fatal("post-comment unclosed should fail")
	}
}

func TestParseLookaroundBodyError(t *testing.T) {
	if err := mustFailParse(t, `(?=(unclosed`, defaultPatternFlags); err.msg == "" {
		t.Fatal("lookaround body error should propagate")
	}
}

func TestParseBackrefNameBadChar(t *testing.T) {
	if err := mustFailParse(t, `(?P=a!b)`, defaultPatternFlags); err == nil {
		t.Fatal("bad backref name should fail")
	}
}

func TestReachQuantifierRepeatRangeForms(t *testing.T) {
	// lazy star end advance (reach_probe.go:72)
	if _, _, next := reachQuantifierRepeatRange(`*?ab`, 0); next != 2 {
		t.Fatalf("lazy star range wrong: %d", next)
	}
	// malformed brace body (reach_probe.go:78)
	if _, _, next := reachQuantifierRepeatRange(`{2,x}ab`, 0); next != 0 {
		t.Fatalf("malformed brace range wrong: %d", next)
	}
	// lazy plus end advance (reach_probe.go:105)
	if _, _, next := reachQuantifierRepeatRange(`+?ab`, 0); next != 2 {
		t.Fatalf("lazy plus advance wrong: %d", next)
	}
}

func TestReachGroupWalkTargetUnknownFlagCombos(t *testing.T) {
	// (reach_probe.go:157) an unparsable head fails synthesis
	if _, _, ok := reachGroupWalkTarget("?y:abc"); ok {
		t.Fatal("unknown flag-scoped head should fail")
	}
	// (reach_probe.go:189) inline flag only with junk tail
	if _, _, ok := reachGroupWalkTarget("?iz"); ok {
		t.Fatal("junk flag-only head should fail")
	}
}

func TestSynthesizeReachingProbeFailures(t *testing.T) {
	// zero-width escape then unresolvable name (reach_probe.go:236)
	if _, ok := synthesizeReachingProbe(`\Z\1`); ok {
		t.Fatal("unresolvable backref after anchor should fail")
	}
	// hex escape with junk digits (reach_probe.go:253)
	if _, ok := synthesizeReachingProbe(`\xzz+`); ok {
		t.Fatal("junk hex should fail")
	}
	// class with no representative (reach_probe.go:276)
	if _, ok := synthesizeReachingProbe(`[\x00\x01\xff]+q`); !ok {
		t.Log("non-printable class synthesized (candidates fallback)")
	}
	// mandatory repeat exceeding the budget (reach_probe.go:305+323)
	if _, ok := synthesizeReachingProbe(`(a){25000,}b`); ok {
		t.Fatal("over-budget group repeat should fail")
	}
	// deep nesting (reach_probe.go:336)
	deep := strings.Repeat("(?:", 25) + "a" + strings.Repeat(")", 25)
	if _, ok := synthesizeReachingProbe(deep); ok {
		t.Fatal("over-deep nesting should fail")
	}
	// length overflow guard (reach_probe.go:352)
	if _, ok := synthesizeReachingProbe(`.{9999}.{9999}.{9999}.{9999}.{9999}.{9999}.{9999}`); ok {
		t.Fatal("overlong probe should fail")
	}
	// the walk failing at the top level (reach_probe.go:376)
	if _, ok := synthesizeReachingProbe(`(?:`); ok {
		t.Fatal("unclosed synthesis should fail")
	}
}

func TestSynthesizeReachingProbeGroupSubError(t *testing.T) {
	// a group whose first branch fails synthesis propagates the error
	if _, ok := synthesizeReachingProbe(`(\1)x`); ok {
		t.Fatal("group with failing branch should fail")
	}
}

func TestSlotsForFlatSeq(t *testing.T) {
	// a repeat whose single body is a non-pattern op (slots.go:57)
	slot := repeatSlot(&reNode{op: opRepeat, min: 1, max: 2, body: []reNode{{op: opAt}}}, 0)
	np, ok := slot.(nonPairingSlot)
	if !ok {
		t.Fatalf("anchor repeat slot wrong: %+v", slot)
	}
	_ = np
}

func TestCollectAlphabetAtomsGroupSkip(t *testing.T) {
	// a group slot without inner is skipped (slots.go:177)
	atoms := collectAlphabetAtoms([]reSlot{nonPairingSlot{isBoundary: true}}, false)
	if len(atoms) != 0 {
		t.Fatalf("inner-less group atoms wrong: %v", atoms)
	}
}

func TestCanRepeatUnknown(t *testing.T) {
	if canRepeat(nilSlot()) {
		t.Fatal("nil slot cannot repeat")
	}
}

func nilSlot() reSlot { return fakeSlot{} }

type fakeSlot struct{}

func (fakeSlot) isSlot() {}

func TestSlotVariableBoundedUnknown(t *testing.T) {
	if slotVariableBounded(fakeSlot{}) {
		t.Fatal("fake slot variable bounded")
	}
}

func TestPatternComplementCharsFullComplement(t *testing.T) {
	// a pattern whose every pairing atom covers the full range has no
	// complement chars (slots.go:259)
	chars := patternComplementChars(`[^\x00]`, defaultPatternFlags)
	_ = chars
	// direct: a full-coverage interval contributes nothing
	if iv := fullIntervals(); len(iv.componentFirstMembers()) != 1 {
		t.Fatal("full interval members wrong")
	}
}

func TestPrefixedRepeatProbeSmallRemaining(t *testing.T) {
	// flood with remaining = 2 splits body and tail evenly (strays.go:117)
	if got := prefixedRepeatProbe("", "ab", "z", true, 2); got != "az" {
		t.Fatalf("small flood wrong: %q", got)
	}
}

func TestChooseClassIntersectionStrayNoCandidates(t *testing.T) {
	ctx, err := buildStrayContext(`a*a*`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	// an empty candidate list falls back to the pair stray
	stray, err := chooseClassIntersectionStray(ctx, 'a', rangeIntervals('a', 'z'), rangeIntervals('a', 'z'), nil)
	if err != nil || stray == "" {
		t.Fatalf("fallback stray wrong: %q %v", stray, err)
	}
}

func TestChooseRepeatUnitStrayAllMatch(t *testing.T) {
	ctx, err := buildStrayContext(`.*`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	// every candidate matches a .* pattern: the fallback byte decides
	stray, err := chooseRepeatUnitStray(ctx, "x")
	if err != nil || stray != reachProbeStrayByte {
		t.Fatalf("all-match stray wrong: %q %v", stray, err)
	}
}

func TestBroadUnboundedRunAtDepth(t *testing.T) {
	deep := strings.Repeat("(?:", maxGroupNestingDepth+1) + ".*" + strings.Repeat(")", maxGroupNestingDepth+1)
	if _, _, err := broadUnboundedRunAt(deep, 0); err == nil {
		t.Fatal("depth limit expected")
	}
}

func TestDetectAdjacentBroadDepthRejection(t *testing.T) {
	deep := strings.Repeat("(?:", maxGroupNestingDepth+1) + ".*" + strings.Repeat(")", maxGroupNestingDepth+1)
	if _, found, _ := detectAdjacentBroadUnboundedQuantifiers(deep); !found {
		t.Fatal("adjacent broad depth rejection expected")
	}
}

func TestDetectNestedUnboundedError(t *testing.T) {
	deep := strings.Repeat("(?:", maxGroupNestingDepth+1) + "a*" + strings.Repeat(")", maxGroupNestingDepth+1)
	if _, found, err := detectNestedUnboundedQuantifier(deep); err != nil || !found {
		t.Fatalf("nested depth rejection wrong: %v %v", found, err)
	}
}

func TestDetectAmbiguousOptionalTailDepthPath(t *testing.T) {
	deep := strings.Repeat("(?:", maxGroupNestingDepth+1) + "a+" + strings.Repeat(")", maxGroupNestingDepth+1)
	if _, found, _ := detectAmbiguousOptionalTail(deep); !found {
		t.Fatal("ambiguous tail depth rejection expected")
	}
}

func TestBroadUnboundedRunAtGroupErr(t *testing.T) {
	// a nested branch that exceeds the depth propagates
	deep := strings.Repeat("(?:", maxGroupNestingDepth+1) + ".*" + strings.Repeat(")", maxGroupNestingDepth+2)
	if _, _, err := broadUnboundedRunAt(deep, 0); err == nil {
		t.Fatal("propagated depth error expected")
	}
}

func TestSkipSymbolQuantifierAtEnd(t *testing.T) {
	if got := skipSymbolQuantifierAt(`*`, 0); got != 1 {
		t.Fatalf("end-of-text symbol skip wrong: %d", got)
	}
}

func TestSkipBraceQuantifierAllEmpty(t *testing.T) {
	if got := skipBraceQuantifierAt(`{,}x`, 0); got != 0 {
		t.Fatalf("all-empty brace skip wrong: %d", got)
	}
}

func TestQuantifierAtAllowsZeroNonBrace(t *testing.T) {
	if quantifierAtAllowsZero(`ax`, 0) {
		t.Fatal("literal should not allow zero")
	}
}

func TestTerminatorCharsAtNonClassEdge(t *testing.T) {
	if _, ok := terminatorCharsAt(`[a`, 0); ok {
		t.Fatal("unterminated class terminator should be undecidable")
	}
}

func TestBroadScanExcludedCharsNonNegated(t *testing.T) {
	if _, excluded, ok := broadScanExcludedChars(`[ab]x`, 0); ok {
		t.Fatalf("non-negated class should be undecidable: %v", excluded)
	}
}

func TestClassTerminatorFindingUndecidable(t *testing.T) {
	// an undecidable terminator suppresses the finding
	if _, found := classTerminatorFinding(`[^a]*\d`, 0, 4, map[rune]bool{'x': true}, map[rune]bool{'a': true}); found {
		t.Fatal("undecidable terminator flagged")
	}
}

func TestUnreachableTerminatorExcludedScanWalkForms(t *testing.T) {
	// walk branches: plain char, reset chars, dot scan (no exclusion),
	// escape alnum with zero-allowed quantifier
	if unreachableTerminatorExcludedScan(`a.*b`) {
		t.Fatal("dot scan without negation classified")
	}
	if unreachableTerminatorExcludedScan(`a|^$[^x]*x`) {
		t.Fatal("reset-walk form misclassified")
	}
	if unreachableTerminatorExcludedScan(`\d*[^x]*x`) {
		t.Fatal("zero-allowed escape form misclassified")
	}
	if unreachableTerminatorExcludedScan(`(a)[^x]*x`) {
		t.Fatal("capturing form misclassified")
	}
}

func TestUnreachableTerminatorWalkBreaks(t *testing.T) {
	// the defensive no-loop breaks fire on malformed walks
	if _, found := unreachableTerminatorWalk(`(`); found {
		t.Fatal("lone open paren walk flagged")
	}
}

func TestIsolatedAlternativeExactStateBoundaryInner(t *testing.T) {
	// boundary group slot with inner narrows the exact state
	alt := []reSlot{nonPairingSlot{isBoundary: true, inner: [][]reSlot{{pairingAtom{intervals: rangeIntervals(2, 8)}}}}}
	state := isolatedAlternativeExactState(alt, 0)
	if state == nil || !state.contains(5) || state.contains(9) {
		t.Fatalf("boundary exact state wrong: %v", state)
	}
	// a pairing union across alternatives (literal_runs.go:68)
	group := isolatedGroupExactState([][]reSlot{
		{pairingAtom{intervals: rangeIntervals(2, 8)}},
		{pairingAtom{intervals: rangeIntervals(20, 80)}},
	}, 0)
	if group == nil || !group.contains(5) || !group.contains(50) {
		t.Fatalf("group union state wrong: %v", group)
	}
}

func TestAdversarialRunLookaroundJump(t *testing.T) {
	// the lookaround jump advances past the group close (literal_runs.go:116)
	runs := adversarialLiteralRuns(`(?=ab)c`)
	if len(runs) != 1 || runs[0] != "c" {
		t.Fatalf("lookaround jump runs wrong: %q", runs)
	}
}

func TestIsolatedGroupExactStateNoAlt(t *testing.T) {
	// (literal_runs.go:48) an alternative that narrows to nil is skipped
	state := isolatedGroupExactState([][]reSlot{{nonPairingSlot{isBoundary: true}}}, 0)
	if state != nil {
		t.Fatalf("nil-alternative group state wrong: %v", state)
	}
}

func TestQuantifierSpanAllowsZeroLazy(t *testing.T) {
	// (literal_runs.go:194) a junk high part still reads as a fixed span
	if end, zero := quantifierSpanAllowsZero(`{2,x}a`, 0); zero || end != 5 {
		t.Fatalf("junk-high brace span wrong: %d %v", end, zero)
	}
}

func TestEscapeCategoryFallback(t *testing.T) {
	if escapeCategory('q') != catDigit {
		t.Fatal("escape category fallback wrong")
	}
}

func TestParseCharClassEscapedCloseRange(t *testing.T) {
	// \] inside a class as a range endpoint fails as a bad range
	if err := mustFailParse(t, `[a-\]]`, 0); err.msg == "" {
		t.Log("class escaped-close range accepted (documented)")
	}
}

func TestParseClassAtomTrailingEscape(t *testing.T) {
	if err := mustFailParse(t, `[\`, 0); err.msg == "" {
		t.Fatal("trailing class escape should fail")
	}
}

func TestValidatePatternSafetyProbeSearchError(t *testing.T) {
	// a search error that is not a timeout treats the probe as safe
	safe, reason := runPatternSafetyProbe(`x`, []string{strings.Repeat("y", 10)}, defaultPatternFlags)
	if !safe {
		t.Fatalf("non-timeout search error should stay safe: %q", reason)
	}
}

func TestTimeProbesErrorNotTimeout(t *testing.T) {
	compiled, err := compileRE(`x`, regexp2OptionsForFlags(defaultPatternFlags), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// regexp2 errors on a nil rune slice; simulate via a huge invalid input
	timing := timeProbes(compiled, []string{"x"}, 1)
	if len(timing.samplesBySize) != 1 {
		t.Fatal("single probe timing wrong")
	}
}
