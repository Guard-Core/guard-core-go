package guardcore

// Coverage tests for the body truncation helpers (truncation.go) and the
// preprocessor's decode/truncate paths (preprocessor.go).

import (
	"strings"
	"testing"
)

func TestExtractAttackRegionsBoundaries(t *testing.T) {
	// An indicator at the very start clamps the leading context window.
	t1 := newScanText("<script>x</script>")
	regions := extractAttackRegions(t1, 100000)
	if len(regions) == 0 || regions[0][0] != 0 {
		t.Fatalf("leading regions clamp at zero, got %v", regions)
	}
	// An indicator at the very end clamps the trailing context window.
	t2 := newScanText(strings.Repeat("x", 250) + "<script>")
	regions = extractAttackRegions(t2, 100000)
	if len(regions) == 0 || regions[len(regions)-1][1] != t2.n {
		t.Fatalf("trailing regions clamp at the text end, got %v", regions)
	}
	// A small maxContentLength caps the region budget at one and stops the
	// pattern sweep early.
	t3 := newScanText("<script>a</script> ; rm -rf /")
	regions = extractAttackRegions(t3, 100)
	if len(regions) != 1 {
		t.Fatalf("one-region budgets truncate the sweep, got %v", regions)
	}
	// A maxContentLength below 100 yields a zero-region budget: the merged
	// result is cut back to nothing.
	regions = extractAttackRegions(t3, 50)
	if len(regions) != 0 {
		t.Fatalf("zero budgets report no regions, got %v", regions)
	}
	// Clean text yields no regions.
	if regions := extractAttackRegions(newScanText("just plain words here"), 100000); regions != nil {
		t.Fatalf("clean text must produce no regions, got %v", regions)
	}
}

func TestExtractAndConcatenateAttackRegions(t *testing.T) {
	tx := newScanText("abcdefghij" + "0123456789" + "ABCDEFGH")
	// The full budget concatenates every region in order.
	got := extractAndConcatenateAttackRegions(tx, [][2]int{{0, 3}, {5, 8}}, 10)
	if got != "abc"+"fgh" {
		t.Fatalf("regions concatenate in order, got %q", got)
	}
	// A tight budget cuts mid-region and stops.
	got = extractAndConcatenateAttackRegions(tx, [][2]int{{0, 3}, {5, 8}}, 4)
	if got != "abcf" {
		t.Fatalf("tight budgets truncate the tail region, got %q", got)
	}
	// An exact budget consumes everything without spillover.
	got = extractAndConcatenateAttackRegions(tx, [][2]int{{0, 3}, {5, 8}}, 6)
	if got != "abcfgh" {
		t.Fatalf("exact budgets concatenate fully, got %q", got)
	}
	// No regions yields an empty string.
	if got := extractAndConcatenateAttackRegions(tx, nil, 10); got != "" {
		t.Fatalf("no regions yields empty output, got %q", got)
	}
}

func TestCapWithTail(t *testing.T) {
	rs := []rune("0123456789abcdefghijklmnopqrstuvwxyz")
	// A max under the tail size keeps only the tail bytes.
	got := capWithTail(rs, 10)
	if got != "qrstuvwxyz" {
		t.Fatalf("small budgets keep the tail, got %q", got)
	}
	// A max at the tail size keeps just the tail window.
	got = capWithTail(rs, 30)
	if got != "6789abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("budget-sized windows keep the tail, got %q", got)
	}
	// A max above the constant tail size keeps head plus tail.
	big := []rune(strings.Repeat("h", 4500) + strings.Repeat("t", 500))
	got = capWithTail(big, 4600)
	want := strings.Repeat("h", 4100) + strings.Repeat("t", 500)
	if got != want {
		t.Fatalf("large budgets keep head and tail, got %d chars want %d", len(got), len(want))
	}
}

func TestPreprocessorTruncateSafely(t *testing.T) {
	// Without pattern preservation the budget is a plain prefix cut.
	p := &preprocessor{maxContentLength: 100000, preserveAttackPatterns: false, maxFullScanBytes: 10}
	if got := p.truncateSafely(strings.Repeat("a", 50)); got != strings.Repeat("a", 10) {
		t.Fatalf("plain cuts take the prefix, got %q", got)
	}
	// With preservation but no attack regions the cut keeps head and tail.
	p = &preprocessor{maxContentLength: 100000, preserveAttackPatterns: true, maxFullScanBytes: 20}
	if got := p.truncateSafely(strings.Repeat("a", 50)); got != strings.Repeat("a", 20) {
		t.Fatalf("clean bodies keep the head window, got %q", got)
	}
	// A body whose attack regions exceed the budget concatenates them.
	p = &preprocessor{maxContentLength: 100000, preserveAttackPatterns: true, maxFullScanBytes: 100}
	body := "<script>" + strings.Repeat("x", 300) + "<script>"
	got := p.truncateSafely(body)
	if !strings.HasPrefix(got, "<script>") || len(got) >= len(body) {
		t.Fatalf("oversized attack regions concatenate, got %d chars", len(got))
	}
	// Under budget bodies pass through untouched.
	if got := p.truncateSafely("short"); got != "short" {
		t.Fatalf("short bodies pass through, got %q", got)
	}
}

func TestDecodeCommonEncodingsExhaustion(t *testing.T) {
	p := newPreprocessor(Config{MaxContentLength: 100000, PreserveAttackPatterns: true, MaxBodyInspectBytes: 4096})
	// Layered percent-encoding keeps changing for more passes than the
	// iteration budget allows, which must report the exhaustion flag.
	deep := "%" + strings.Repeat("25", 20) + "3Cscript%3E"
	_, exhausted := p.decodeCommonEncodings(deep)
	if !exhausted {
		t.Fatal("deeply layered encodings must report budget exhaustion")
	}
	// A single-layer payload stabilises without exhaustion.
	out, exhausted := p.decodeCommonEncodings("%3Cscript%3E")
	if exhausted {
		t.Fatal("single-layer payloads must not report exhaustion")
	}
	if !strings.Contains(out, "<script>") {
		t.Fatalf("percent escapes decode, got %q", out)
	}
	// HTML entities decode through the same loop.
	out, _ = p.decodeCommonEncodings("&lt;script&gt;")
	if !strings.Contains(out, "<script>") {
		t.Fatalf("html entities decode, got %q", out)
	}
}

func TestPreprocessURLDecodedNewlinePreserving(t *testing.T) {
	p := newPreprocessor(Config{MaxContentLength: 100000, PreserveAttackPatterns: false, MaxBodyInspectBytes: 4096})
	if out, exhausted := p.preprocessURLDecodedNewlinePreserving(""); out != "" || exhausted {
		t.Fatalf("empty bodies short-circuit, got %q %v", out, exhausted)
	}
	out, exhausted := p.preprocessURLDecodedNewlinePreserving("a=1%26b=%3Cscript%3E")
	if exhausted {
		t.Fatal("shallow payloads must not report exhaustion")
	}
	if !strings.Contains(out, "<script>") {
		t.Fatalf("decoded payloads keep their attacks visible, got %q", out)
	}
}
