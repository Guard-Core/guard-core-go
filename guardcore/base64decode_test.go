package guardcore

import (
	"testing"

	"github.com/dlclark/regexp2"
)

// findAllStrings must advance past zero-length matches: a regex that can
// match the empty string would otherwise loop forever at one position.
func TestFindAllStringsZeroLengthMatchProgresses(t *testing.T) {
	re := regexp2.MustCompile(`x*`, 0)
	got := findAllStrings(re, "abc")
	if len(got) != 4 {
		t.Fatalf("empty-match scan must progress one position per step, got %v", got)
	}
}
