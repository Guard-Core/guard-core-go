package guardcore

// Tests mirroring tests/test_sus_patterns/test_redos_repeat_alphabet.py and
// the parse-slots / class-interposition fixtures.

import "testing"

func TestPatternSlots(t *testing.T) {
	slots := patternSlots(`\d+`, defaultPatternFlags)
	if len(slots) != 1 {
		t.Fatalf("slot count wrong: %d", len(slots))
	}
	atom, ok := slots[0].(pairingAtom)
	if !ok || !atom.unbounded || !atom.intervals.contains('5') {
		t.Fatalf("digit atom wrong: %+v", slots[0])
	}
	if got := patternSlots("(unclosed", defaultPatternFlags); got != nil {
		t.Fatalf("unparseable pattern slots wrong: %v", got)
	}
}

func TestPatternSlotsGroupAndAssert(t *testing.T) {
	slots := patternSlots(`a(?=b)$`, defaultPatternFlags)
	if len(slots) != 3 {
		t.Fatalf("slot count wrong: %d", len(slots))
	}
	np, ok := slots[1].(nonPairingSlot)
	if !ok || np.inner == nil {
		t.Fatalf("assert slot wrong: %+v", slots[1])
	}
	boundary, ok := slots[2].(nonPairingSlot)
	if !ok || boundary.inner != nil {
		t.Fatalf("anchor slot wrong: %+v", slots[2])
	}
}

func TestPatternSlotsBranch(t *testing.T) {
	slots := patternSlots(`(?:\d|\w)*;`, defaultPatternFlags)
	if len(slots) != 2 {
		t.Fatalf("slot count wrong: %d", len(slots))
	}
	np, ok := slots[0].(nonPairingSlot)
	if !ok || len(np.inner) != 2 {
		t.Fatalf("branch slot wrong: %+v", slots[0])
	}
	_ = np
}

func TestRepeatSlotShape(t *testing.T) {
	slots := patternSlots(`a{2,4}`, defaultPatternFlags)
	atom := slots[0].(pairingAtom)
	if atom.unbounded || atom.allowsZero || atom.maxRepeat != 4 || !atom.variableBounded {
		t.Fatalf("bounded atom shape wrong: %+v", atom)
	}
	slots = patternSlots(`a*`, defaultPatternFlags)
	atom = slots[0].(pairingAtom)
	if !atom.unbounded || !atom.allowsZero {
		t.Fatalf("star atom shape wrong: %+v", atom)
	}
	// multi-body repeat becomes a group-like slot (boundary since '+' cannot
	// match empty)
	slots = patternSlots(`(?:ab)+`, defaultPatternFlags)
	np, ok := slots[0].(nonPairingSlot)
	if !ok || !np.isBoundary || np.inner == nil {
		t.Fatalf("multi-body repeat slot wrong: %+v", slots[0])
	}
}

func TestCollectPairingIntervalsAndClassUnion(t *testing.T) {
	union := patternClassUnion(`\d\w`, defaultPatternFlags)
	if !union.contains('5') || !union.contains('z') {
		t.Fatal("class union wrong")
	}
	empty := patternClassUnion("(unclosed", defaultPatternFlags)
	if !empty.isEmpty() {
		t.Fatal("unparseable union should be empty")
	}
}

func TestPatternComplementChars(t *testing.T) {
	chars := patternComplementChars(`\d`, defaultPatternFlags)
	if len(chars) == 0 || chars[0] != 0 {
		t.Fatalf("digit complement wrong: %v", chars)
	}
	if chars := patternComplementChars("(bad", defaultPatternFlags); chars != nil {
		t.Fatal("unparseable complement wrong")
	}
}

func TestRepeatAlphabetFills(t *testing.T) {
	fills := repeatAlphabetFills(`\d+`, defaultPatternFlags)
	if len(fills) == 0 || fills[0] != '0' {
		t.Fatalf("digit fills wrong: %v", fills)
	}
	fills = repeatAlphabetFills(`\w+`, defaultPatternFlags)
	if len(fills) == 0 || fills[0] != '0' {
		t.Fatalf("word fills wrong: %v", fills)
	}
	if fills := repeatAlphabetFills(`abc`, defaultPatternFlags); fills != nil {
		t.Fatalf("literal fills should be empty: %v", fills)
	}
	if fills := repeatAlphabetFills("(bad", defaultPatternFlags); fills != nil {
		t.Fatalf("unparseable fills wrong: %v", fills)
	}
	// (\w+\.?) fills: repeated alphabet = word ∪ dot
	fills = repeatAlphabetFills(`(\w+\.?)+`, defaultPatternFlags)
	if len(fills) < 2 {
		t.Fatalf("union fills wrong: %v", fills)
	}
}

func TestHasLargeBoundedRepeat(t *testing.T) {
	if !hasLargeBoundedRepeat(`a{4096,5000}`, defaultPatternFlags) {
		t.Fatal("large bounded repeat missed")
	}
	if hasLargeBoundedRepeat(`a{2,4}`, defaultPatternFlags) {
		t.Fatal("small bounded repeat flagged")
	}
	if hasLargeBoundedRepeat("(bad", defaultPatternFlags) {
		t.Fatal("unparseable repeat flagged")
	}
	// nested group boundary slot (variable bounded inside a group)
	if !hasLargeBoundedRepeat(`(?:a{4096,5000})`, defaultPatternFlags) {
		t.Fatal("nested large bounded repeat missed")
	}
	// an exact (non-variable) repeat is never large-bounded
	if hasLargeBoundedRepeat(`(?:a{5000})`, defaultPatternFlags) {
		t.Fatal("exact repeat flagged")
	}
}

func TestCollectAlphabetAtomsRecursion(t *testing.T) {
	slots := patternSlots(`(?:\d+)+`, defaultPatternFlags)
	atoms := collectAlphabetAtoms(slots, false)
	foundRepeated := false
	for _, atom := range atoms {
		if atom.repeated {
			foundRepeated = true
		}
	}
	if !foundRepeated {
		t.Fatalf("repeated atom not found: %+v", atoms)
	}
}

func TestSlotsHaveLargeBoundedRepeatNested(t *testing.T) {
	slots := patternSlots(`(?:a{4096,5000})`, defaultPatternFlags)
	if !slotsHaveLargeBoundedRepeat(slots) {
		t.Fatal("nested slot large repeat missed")
	}
	if slotsHaveLargeBoundedRepeat(patternSlots(`(?:a{5000})`, defaultPatternFlags)) {
		t.Fatal("exact repeat flagged")
	}
}

func TestWithRepeatShapeFallback(t *testing.T) {
	// non-pairing slots under a repeat collapse to the reference's opaque
	// boundary slot
	slot := pairingOrNonPairing(&reNode{op: opRepeat}, 0, true, true, noMaxRepeat, false)
	np, ok := slot.(nonPairingSlot)
	if !ok || !np.isBoundary {
		t.Fatalf("opaque repeat slot wrong: %+v", slot)
	}
}

func TestIncludeBoundedRepeats(t *testing.T) {
	slots := patternSlots(`\d{2,4}`, defaultPatternFlags)
	included := includeBoundedRepeats(slots)
	atom, ok := included[0].(pairingAtom)
	if !ok || !atom.unbounded {
		t.Fatalf("bounded repeat not included: %+v", included[0])
	}
	// nested group inner is included too
	slots = patternSlots(`(?:\d{2,4}a)+`, defaultPatternFlags)
	included = includeBoundedRepeats(slots)
	np, ok := included[0].(nonPairingSlot)
	if !ok || len(np.inner) == 0 {
		t.Fatalf("nested include wrong: %+v", included[0])
	}
	if atom, ok := np.inner[0][0].(pairingAtom); !ok || !atom.unbounded {
		t.Fatalf("nested inner atom not repeated: %+v", np.inner[0][0])
	}
}

func TestClassIntersectionProbeUnits(t *testing.T) {
	// a*a*: the second unbounded overlapping 'a' produces a (fill 'a') unit
	ctx, err := buildStrayContext(`a*a*`, defaultPatternFlags)
	if err != nil {
		t.Fatal(err)
	}
	units, err := classIntersectionProbeUnits(`a*a*`, defaultPatternFlags, ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, unit := range units {
		if unit.fill == 'A' && unit.stray == "\x00" {
			found = true
		}
	}
	if !found {
		t.Fatalf("overlap fill unit missing: %+v", units)
	}
	// [\w-]*-- has no class-intersection units (the literal '-' is bounded)
	units, err = classIntersectionProbeUnits(`[\w-]*--`, defaultPatternFlags, ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 0 {
		t.Fatalf("bounded literal should not produce units: %+v", units)
	}
	// nil ctx builds its own
	units, err = classIntersectionProbeUnits(`a*a*`, defaultPatternFlags, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if units == nil {
		t.Fatal("units nil")
	}
	if units, err := classIntersectionProbeUnits("(bad", defaultPatternFlags, nil, false); err != nil || units != nil {
		t.Fatalf("unparseable units wrong: %v %v", units, err)
	}
}

func TestCrossNonPairingSlot(t *testing.T) {
	// non-boundary slot without inner keeps the shared set
	shared, _, _, _, ok := crossNonPairingSlot(nonPairingSlot{isBoundary: false}, rangeIntervals(1, 5), nil)
	if !ok || shared != nil {
		// shared==nil because we passed nil; the call must succeed
		if !ok {
			t.Fatal("non-boundary innerless slot failed")
		}
	}
	// boundary slot without inner fails
	if _, _, _, _, ok := crossNonPairingSlot(nonPairingSlot{isBoundary: true}, nil, nil); ok {
		t.Fatal("boundary innerless slot should fail")
	}
	// boundary slot with an uncrossable group fails
	np := nonPairingSlot{isBoundary: true, inner: [][]reSlot{{pairingAtom{intervals: emptyIntervals()}}}}
	if _, _, _, _, ok := crossNonPairingSlot(np, rangeIntervals(1, 5), nil); ok {
		t.Fatal("uncrossable group should fail")
	}
}

func TestGroupCrossingDepth(t *testing.T) {
	if got := groupCrossingResult(nil, fullIntervals(), maxGroupCrossingDepth+1); got != nil {
		t.Fatal("depth limit should return nil")
	}
}

func TestExactStateMachinery(t *testing.T) {
	if got := narrowExactStateRaw(nil, fullIntervals()); got != nil {
		t.Fatal("nil state narrow wrong")
	}
	if got := narrowExactStateRaw(fullIntervals(), nil); got != nil {
		t.Fatal("nil right narrow wrong")
	}
	if _, ok := exactOverlapFillRaw(nil, fullIntervals()); ok {
		t.Fatal("nil state fill wrong")
	}
	if _, ok := exactOverlapFillRaw(fullIntervals(), nil); ok {
		t.Fatal("nil right fill wrong")
	}
	if ch, ok := exactOverlapFillRaw(rangeIntervals(1, 5), rangeIntervals(3, 9)); !ok || ch != 3 {
		t.Fatalf("exact fill wrong: %v %v", ch, ok)
	}
	// isolated alternative exact state with a boundary slot of no inner
	state := isolatedAlternativeExactState([]reSlot{nonPairingSlot{isBoundary: true}}, 0)
	if state != nil {
		t.Fatal("innerless boundary should yield nil state")
	}
	state = isolatedAlternativeExactState([]reSlot{pairingAtom{intervals: rangeIntervals(1, 3)}}, 0)
	if state == nil || !state.contains(2) || state.contains(4) {
		t.Fatalf("alternative state wrong: %v", state)
	}
}

func TestIsolatedGroupExactStateDepth(t *testing.T) {
	if got := isolatedGroupExactState(nil, maxGroupCrossingDepth+1); got != nil {
		t.Fatal("depth limit should return nil")
	}
	if got := isolatedGroupExactState(nil, 0); got != nil {
		t.Fatal("no alternatives should return nil")
	}
}
