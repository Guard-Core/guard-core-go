package guardcore

import "testing"

// The extractor must fire only on the tempered-loop alternation shapes and
// yield the required literals; any drift widens or narrows the skip set.
func TestExtractLeadingLiterals(t *testing.T) {
	fired := 0
	for i := range globalPatterns {
		p := &globalPatterns[i]
		lits := extractLeadingLiterals(p.source)
		if lits == nil {
			continue
		}
		fired++
		t.Logf("prefilter %d lits on cat=%s src=%.70s", len(lits), p.category, p.source)
		for _, lit := range lits {
			if len(lit) < 2 {
				t.Fatalf("too-short literal %q from %s", lit, p.source)
			}
		}
	}
	if fired < 6 {
		t.Fatalf("prefilter fired on %d patterns; the recon families must be covered", fired)
	}
	src := `\A(?=(?:(?!\n).)*\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?))rest`
	lits := extractLeadingLiterals(src)
	if lits == nil || lits[0] != "scan" || lits[1] != "attack" {
		t.Fatalf("lookahead shape extraction wrong: %v", lits)
	}
	if got := extractLeadingLiterals(`\bSELECT\b.*FROM`); got != nil {
		t.Fatalf("must not fire on ordinary patterns: %v", got)
	}
	if got := extractLeadingLiterals(`\A(?:(?!\n).)*(?:[a-z]+|boot)`); got != nil {
		t.Fatalf("must bail on class-led alternatives: %v", got)
	}
	// Skip correctness end to end: without any literal present the pattern
	// cannot match; with one present it behaves like the raw regex.
	p := &compiledPattern{prefilter: []string{"honeypot"}}
	body := newScanText("The quick brown fox jumps over the lazy dog.")
	if literalPrefilter(p.prefilter, body.s) {
		t.Fatal("must skip when no literal occurs")
	}
	if !literalPrefilter(p.prefilter, newScanText("deployed in a Honeypot zone").s) {
		t.Fatal("must run when a case-insensitive literal occurs")
	}
}
