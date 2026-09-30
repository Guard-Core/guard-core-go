package guardcore

// Coverage tests for the engine scan-text helpers (engine.go).

import (
	"strings"
	"testing"

	"github.com/dlclark/regexp2"
)

func TestMustCompilePanicsOnBadPattern(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("bad patterns must panic")
		}
	}()
	mustCompile("[", 0, windowTimeout)
}

func TestScanTextByteOf(t *testing.T) {
	tx := newScanText("héllo")
	// byteOf returns the first byte offset after the given rune.
	if got := tx.byteOf(0); got != 1 {
		t.Fatalf("rune zero ends at byte one, got %d", got)
	}
	if got := tx.byteOf(1); got != 3 {
		t.Fatalf("rune one skips its continuation byte, got %d", got)
	}
	if got := tx.byteOf(2); got != 4 {
		t.Fatalf("rune two ends one byte later, got %d", got)
	}
	if got := tx.byteOf(99); got != len("héllo") {
		t.Fatalf("runes past the end clamp, got %d", got)
	}
}

func TestScanTextStrClamps(t *testing.T) {
	tx := newScanText("héllo")
	if got := tx.str(-5, 99); got != "héllo" {
		t.Fatalf("windows clamp at the edges, got %q", got)
	}
	if got := tx.str(3, 3); got != "" {
		t.Fatalf("empty windows are empty, got %q", got)
	}
	if got := tx.str(4, 2); got != "" {
		t.Fatalf("inverted windows are empty, got %q", got)
	}
	if got := tx.str(1, 2); got != "é" {
		t.Fatalf("rune windows decode, got %q", got)
	}
}

func TestRmatchMatched(t *testing.T) {
	tx := newScanText("abc")
	m := matchFromIndices(tx, 1, 2, "g")
	if m.matched() != "b" {
		t.Fatalf("matched echoes text, got %q", m.matched())
	}
}

func TestFindFirstAtAndSearchFromBounds(t *testing.T) {
	re := mustCompile(`b`, 0, windowTimeout)
	tx := newScanText("abc")
	// Negative starts refuse.
	if _, ok := findFirstAt(re, tx, -1, 3); ok {
		t.Fatal("negative starts refuse")
	}
	// Ceilings clamp before the start.
	if _, ok := findFirstAt(re, tx, 1, 1); ok {
		t.Fatal("clamped ceilings refuse")
	}
	// Starts past the text refuse.
	if _, ok := searchFrom(re, tx, 4); ok {
		t.Fatal("starts past the text refuse")
	}
	if m, ok := searchFrom(re, tx, 0); !ok || m.start() != 1 {
		t.Fatalf("healthy searches match, got %v %v", m, ok)
	}
	// Mismatched anchored starts refuse.
	if _, ok := findFirstAt(re, tx, 0, 3); ok {
		t.Fatal("anchored starts must align")
	}
}

func TestFirstAndLastIndexOfRune(t *testing.T) {
	rs := []rune("abca")
	if got := firstIndexOfRune(rs, 'a'); got != 0 {
		t.Fatalf("first indices locate, got %d", got)
	}
	if got := firstIndexOfRune(rs, 'z'); got != -1 {
		t.Fatalf("missing runes report -1, got %d", got)
	}
	if got := lastIndexOfRune(rs, 'a'); got != 3 {
		t.Fatalf("last indices locate, got %d", got)
	}
	if got := lastIndexOfRune(rs, 'z'); got != -1 {
		t.Fatalf("missing runes report -1, got %d", got)
	}
}

func TestCompileREIgnoreCase(t *testing.T) {
	re, err := compileREIgnoreCase("ABC", windowTimeout)
	if err != nil {
		t.Fatalf("compilation succeeds: %v", err)
	}
	m, err := re.FindStringMatchStartingAt("abc", 0)
	if err != nil || m == nil {
		t.Fatalf("ignore-case patterns match, got %v %v", m, err)
	}
	if _, err := compileREIgnoreCase("[", windowTimeout); err == nil {
		t.Fatal("bad patterns fail")
	}
}

func TestFindAllMatchesMonotonicDefence(t *testing.T) {
	// Zero-width matches advance the scan one rune at a time.
	re := mustCompile(`x*`, 0, windowTimeout)
	got := findAllMatches(re, newScanText("ab"))
	if len(got) != 3 {
		t.Fatalf("zero-width matches advance, got %d", len(got))
	}
	// Real patterns still scan normally.
	word := mustCompile(`\w+`, 0, windowTimeout)
	got = findAllMatches(word, newScanText("one two"))
	if len(got) != 2 {
		t.Fatalf("word matches split, got %d", len(got))
	}
	_ = regexp2.IgnoreCase
	_ = strings.TrimSpace
}
