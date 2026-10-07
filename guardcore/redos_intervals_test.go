package guardcore

// Tests mirroring tests/test_sus_patterns/test_redos_intervals.py: the
// interval algebra underpinning the ReDoS static safety layer.

import "testing"

func TestIntervalSetNormalizeMerges(t *testing.T) {
	iv := newIntervalSet([]redosInterval{{low: 5, high: 10}, {low: 11, high: 20}, {low: 1, high: 3}, {low: 0, high: 2}})
	if len(iv.intervals) != 2 {
		t.Fatalf("expected 2 merged intervals, got %d: %v", len(iv.intervals), iv.intervals)
	}
	if iv.intervals[0].low != 0 || iv.intervals[0].high != 3 {
		t.Fatalf("first merged interval wrong: %v", iv.intervals[0])
	}
	if iv.intervals[1].low != 5 || iv.intervals[1].high != 20 {
		t.Fatalf("second merged interval wrong: %v", iv.intervals[1])
	}
}

func TestIntervalSetEmpty(t *testing.T) {
	iv := emptyIntervals()
	if !iv.isEmpty() {
		t.Fatal("empty set reports non-empty")
	}
	if _, ok := iv.firstMember(); ok {
		t.Fatal("empty set has a first member")
	}
	if len(iv.componentFirstMembers()) != 0 {
		t.Fatal("empty set has component members")
	}
	if iv.contains(42) {
		t.Fatal("empty set contains a point")
	}
}

func TestIntervalSetFull(t *testing.T) {
	iv := fullIntervals()
	if !iv.contains(0) || !iv.contains(maxCodePoint) || !iv.contains(0x10FFFF) {
		t.Fatal("full set missing points")
	}
	if iv.isEmpty() {
		t.Fatal("full set empty")
	}
}

func TestIntervalSetSingleAndRange(t *testing.T) {
	s := singleInterval(65)
	if !s.contains(65) || s.contains(66) {
		t.Fatal("single interval membership wrong")
	}
	r := rangeIntervals(10, 20)
	if !r.contains(15) || r.contains(9) || r.contains(21) {
		t.Fatal("range membership wrong")
	}
	if empty := rangeIntervals(20, 10); !empty.isEmpty() {
		t.Fatal("inverted range should clamp to empty")
	}
	clamped := rangeIntervals(-5, maxCodePoint+10)
	if clamped.intervals[0].low != 0 || clamped.intervals[0].high != maxCodePoint {
		t.Fatal("range clamp wrong")
	}
}

func TestIntervalSetContainsBinarySearch(t *testing.T) {
	iv := newIntervalSet([]redosInterval{{low: 0, high: 10}, {low: 100, high: 200}, {low: 1000, high: 2000}})
	for _, cp := range []int{0, 10, 100, 150, 200, 1000, 2000} {
		if !iv.contains(cp) {
			t.Fatalf("missing %d", cp)
		}
	}
	for _, cp := range []int{11, 99, 201, 999, 2001, 5000} {
		if iv.contains(cp) {
			t.Fatalf("unexpected %d", cp)
		}
	}
}

func TestIntervalSetComponentFirstMembers(t *testing.T) {
	iv := newIntervalSet([]redosInterval{{low: 0, high: 10}, {low: 100, high: 200}})
	members := iv.componentFirstMembers()
	if len(members) != 2 || members[0] != 0 || members[1] != 100 {
		t.Fatalf("component first members wrong: %v", members)
	}
}

func TestIntervalSetUnionIntersectionComplementDifference(t *testing.T) {
	a := rangeIntervals(0, 100)
	b := rangeIntervals(50, 150)

	if got := a.union(b); got.intervals[0].low != 0 || got.intervals[0].high != 150 {
		t.Fatalf("union wrong: %v", got.intervals)
	}
	if got := a.intersection(b); got.intervals[0].low != 50 || got.intervals[0].high != 100 {
		t.Fatalf("intersection wrong: %v", got.intervals)
	}
	disjoint := rangeIntervals(500, 600)
	if got := a.intersection(disjoint); !got.isEmpty() {
		t.Fatalf("disjoint intersection not empty: %v", got.intervals)
	}
	comp := rangeIntervals(10, 20).complement()
	if comp.intervals[0].low != 0 || comp.intervals[0].high != 9 {
		t.Fatalf("complement head wrong: %v", comp.intervals)
	}
	last := comp.intervals[len(comp.intervals)-1]
	if last.low != 21 || last.high != maxCodePoint {
		t.Fatalf("complement tail wrong: %v", last)
	}
	diff := fullIntervals().difference(rangeIntervals(10, 20))
	if len(diff.intervals) != 2 {
		t.Fatalf("difference wrong: %v", diff.intervals)
	}
	if got := emptyIntervals().complement(); got.intervals[0].low != 0 || got.intervals[0].high != maxCodePoint {
		t.Fatalf("empty complement wrong")
	}
}

func TestIntervalSetUnionInterleaved(t *testing.T) {
	a := newIntervalSet([]redosInterval{{low: 0, high: 10}, {low: 40, high: 50}})
	b := newIntervalSet([]redosInterval{{low: 20, high: 30}, {low: 45, high: 60}})
	got := a.union(b)
	if len(got.intervals) != 3 {
		t.Fatalf("interleaved union wrong: %v", got.intervals)
	}
	if got.intervals[1].low != 20 || got.intervals[1].high != 30 {
		t.Fatalf("interleaved union middle wrong: %v", got.intervals[1])
	}
}

func TestIntervalSetAdjacentMergeBoundary(t *testing.T) {
	iv := newIntervalSet([]redosInterval{{low: 0, high: 9}, {low: 10, high: 20}})
	if len(iv.intervals) != 1 {
		t.Fatalf("adjacent intervals must merge: %v", iv.intervals)
	}
	iv = newIntervalSet([]redosInterval{{low: 0, high: 8}, {low: 10, high: 20}})
	if len(iv.intervals) != 2 {
		t.Fatalf("non-adjacent intervals must not merge: %v", iv.intervals)
	}
}

func TestCategoryIntervalsCached(t *testing.T) {
	digit := cachedCategoryIntervals(catDigit, false)
	if !digit.contains('0') || digit.contains('a') {
		t.Fatal("digit intervals wrong")
	}
	again := cachedCategoryIntervals(catDigit, false)
	if again != digit {
		t.Fatal("category intervals must be cached")
	}
	asciiDigit := cachedCategoryIntervals(catDigit, true)
	if !asciiDigit.contains('5') {
		t.Fatal("ascii digit intervals wrong")
	}
	word := cachedCategoryIntervals(catWord, false)
	if !word.contains('_') || !word.contains('z') || !word.contains('Z') {
		t.Fatal("word intervals wrong")
	}
	space := cachedCategoryIntervals(catSpace, false)
	if !space.contains(' ') {
		t.Fatal("space intervals wrong")
	}
	notWord := cachedCategoryIntervals(catNotWord, false)
	if notWord.contains('a') || !notWord.contains('!') {
		t.Fatal("not-word intervals wrong")
	}
	notDigit := cachedCategoryIntervals(catNotDigit, false)
	if notDigit.contains('7') || !notDigit.contains('x') {
		t.Fatal("not-digit intervals wrong")
	}
	notSpace := cachedCategoryIntervals(catNotSpace, false)
	if notSpace.contains('\t') || !notSpace.contains('q') {
		t.Fatal("not-space intervals wrong")
	}
}

func TestAnyIntervals(t *testing.T) {
	withFlag := anyIntervals(flagDotAll)
	if !withFlag.contains('\n') {
		t.Fatal("dotall any must contain newline")
	}
	without := anyIntervals(0)
	if without.contains('\n') || !without.contains('a') {
		t.Fatal("plain any membership wrong")
	}
}

func TestExpandIgnoreCase(t *testing.T) {
	iv := expandIgnoreCase(singleInterval('a'), 0)
	if iv.intervals[0].low != 'a' {
		t.Fatal("no-flag expand must be identity")
	}
	folded := expandIgnoreCase(singleInterval('a'), flagIgnoreCase)
	if !folded.contains('A') || !folded.contains('a') {
		t.Fatalf("ignorecase expand wrong: %v", folded.intervals)
	}
	wide := expandIgnoreCase(rangeIntervals(0, maxCodePoint), flagIgnoreCase)
	if !wide.contains('A') || !wide.contains(0) {
		t.Fatal("wide expand wrong")
	}
}

func TestMinInt(t *testing.T) {
	if minInt(1, 2) != 1 || minInt(2, 1) != 1 || minInt(1, 1) != 1 {
		t.Fatal("minInt wrong")
	}
}
