package guardcore

// Coverage tests for the hand-written matchers (matchers.go).

import (
	"strings"
	"testing"
)

func TestCmdInjectionShellDashCFinditerValueBreaks(t *testing.T) {
	// A key with an empty value before the newline stops the chain walk.
	tx := newScanText("a\n  cmd=\n")
	if got := cmdInjectionShellDashCFinditer(tx); len(got) != 0 {
		t.Fatalf("value-less keys stop the walk, got %v", got)
	}
}

func TestLoadFileScanMatches(t *testing.T) {
	tx := newScanText("x; LOAD_FILE('/etc/passwd') y")
	got := loadFileScanMatches(tx)
	if len(got) == 0 || !strings.Contains(got[0].text(), "LOAD_FILE") {
		t.Fatalf("load_file probes match inside bounds, got %v", got)
	}
	if got := loadFileScanMatches(newScanText("no probes")); got != nil {
		t.Fatalf("clean text matches nothing, got %v", got)
	}
}

func TestCmdInjectionDollarScanMatches(t *testing.T) {
	tx := newScanText("a; $(id) b; ${home} c")
	got := cmdInjectionDollarScanMatches(tx)
	if len(got) != 2 {
		t.Fatalf("both dollar forms match, got %d", len(got))
	}
}

func TestGlobWildcardScanMatches(t *testing.T) {
	tx := newScanText("rm -f *.txt; cat fi?e")
	got := globWildcardScanMatches(tx)
	if len(got) != 2 {
		t.Fatalf("wildcard atoms match, got %d", len(got))
	}
	if got := globWildcardScanMatches(newScanText("plain")); got != nil {
		t.Fatalf("plain text matches nothing, got %v", got)
	}
}

func TestLDAPNullByteAttrNameStart(t *testing.T) {
	tx := newScanText("=*")
	if _, ok := ldapNullByteAttrNameStart(tx, 0); ok {
		t.Fatal("attribute-less equals positions fail")
	}
	tx = newScanText("1=*")
	if _, ok := ldapNullByteAttrNameStart(tx, 2); ok {
		t.Fatal("digit-led attributes fail")
	}
	tx = newScanText("uid=*")
	if got, ok := ldapNullByteAttrNameStart(tx, 3); !ok || got != 0 {
		t.Fatalf("letter-led attributes resolve, got %d %v", got, ok)
	}
}

func TestLDAPNullByteAttrFinditerBranches(t *testing.T) {
	// Subjects without wildcards or parens never match.
	if got := ldapNullByteAttrFinditer(newScanText("plain"), ldapNullByteAttrCompiled, ldapNullByteTailRE); got != nil {
		t.Fatalf("clean text yields nothing, got %v", got)
	}
	// Tails at the text start have no attribute value.
	if got := ldapNullByteAttrFinditer(newScanText("*))\x00"), ldapNullByteAttrCompiled, ldapNullByteTailRE); got != nil {
		t.Fatalf("valueless tails yield nothing, got %v", got)
	}
	// Values must sit behind an equals sign.
	if got := ldapNullByteAttrFinditer(newScanText("(*))\x00"), ldapNullByteAttrCompiled, ldapNullByteTailRE); got != nil {
		t.Fatalf("non-equals values yield nothing, got %v", got)
	}
	// Attribute names must be letter-led.
	if got := ldapNullByteAttrFinditer(newScanText("=1*))\x00"), ldapNullByteAttrCompiled, ldapNullByteTailRE); got != nil {
		t.Fatalf("digit-led names yield nothing, got %v", got)
	}
	// A well-formed null-byte probe matches once and swallows the tail run.
	tx := newScanText("uid=*))\x00b*))\x00")
	got := ldapNullByteAttrFinditer(tx, ldapNullByteAttrCompiled, ldapNullByteTailRE)
	if len(got) != 1 {
		t.Fatalf("one probe matches, got %d", len(got))
	}
	// The percent-encoded and raw-NUL tail variants share the walk.
	txe := newScanText("uid=*))%00")
	got = ldapNullByteAttrFinditer(txe, ldapNullByteAttrCompiled, ldapNullByteTailRE)
	if len(got) != 1 {
		t.Fatalf("percent null probes match, got %d", len(got))
	}
	txd := newScanText("uid=*))\x00")
	got = ldapNullByteAttrFinditer(txd, ldapNullByteDecodedAttrCompiled, ldapNullByteDecodedTailRE)
	if len(got) != 1 {
		t.Fatalf("raw null probes match, got %d", len(got))
	}
}

func TestQuoteSpliceFinditer(t *testing.T) {
	// Quote splices after a word match.
	tx := newScanText("ab''cd")
	got := quoteSpliceFinditer(tx)
	if len(got) != 1 || got[0].text() != "ab''cd" {
		t.Fatalf("quote splices match, got %v", got)
	}
	// Quotes without a leading word are ignored.
	if got := quoteSpliceFinditer(newScanText("'x")); got != nil {
		t.Fatalf("word-less quotes yield nothing, got %v", got)
	}
	// Quote runs inside an earlier match's span are consumed.
	tx = newScanText("ab''cd''ef")
	got = quoteSpliceFinditer(tx)
	if len(got) != 1 {
		t.Fatalf("overlapping quote runs fold, got %d", len(got))
	}
	// Quote runs followed by non-word characters are ignored.
	if got := quoteSpliceFinditer(newScanText("ab'';")); got != nil {
		t.Fatalf("non-word follow-ups yield nothing, got %v", got)
	}
}

func TestPickleIdentValidation(t *testing.T) {
	if pickleIdentIsFull("") || pickleIdentIsFull("-bad") || pickleIdentIsFull("bad-x") {
		t.Fatal("malformed idents fail")
	}
	if !pickleIdentIsFull("_ok1") || !pickleIdentIsFull("a1_b") {
		t.Fatal("plain idents pass")
	}
	if pickleIdentIsFull(strings.Repeat("a", 102)) {
		t.Fatal("oversized idents fail")
	}
}

func TestPickleGlobalGenericFinditerShortSubjects(t *testing.T) {
	if got := pickleGlobalGenericFinditer(newScanText("one line")); got != nil {
		t.Fatalf("subjects without two lines yield nothing, got %v", got)
	}
}

func TestFloorMax(t *testing.T) {
	if floorMax(-3) != 0 || floorMax(4) != 4 {
		t.Fatal("floorMax clamps negatives")
	}
}

func TestScanBacktickCandidateBody(t *testing.T) {
	// An unterminated opener fails.
	if _, ok := scanBacktickCandidateBody([]rune("`"), 0); ok {
		t.Fatal("unterminated bodies fail")
	}
	// Bodies ending in a lone backslash fail.
	if _, ok := scanBacktickCandidateBody([]rune("`a\\"), 0); ok {
		t.Fatal("trailing escapes fail")
	}
	// Newlines close the body.
	if _, ok := scanBacktickCandidateBody([]rune("`a\nb`"), 0); ok {
		t.Fatal("newlines fail bodies")
	}
	// Escaped pairs skip over the escaped rune.
	end, ok := scanBacktickCandidateBody([]rune("`a\\`b`"), 0)
	if !ok || end != 6 {
		t.Fatalf("escaped backticks skip, got %d %v", end, ok)
	}
}

func TestScanDollarSubstitutionBody(t *testing.T) {
	// Twin openers close the body as a failure.
	if _, ok := scanDollarSubstitutionBody([]rune("(a{b)"), 1, ')', '{'); ok {
		t.Fatal("twin openers fail bodies")
	}
	// Newlines fail bodies.
	if _, ok := scanDollarSubstitutionBody([]rune("(a\nb)"), 1, ')', '('); ok {
		t.Fatal("newlines fail bodies")
	}
	// Escaped pairs skip over the escaped rune.
	end, ok := scanDollarSubstitutionBody([]rune("(a\\)b)"), 1, ')', '(')
	if !ok || end != 6 {
		t.Fatalf("escaped closers skip, got %d %v", end, ok)
	}
}

func TestGluedBacktickAndDollarFinditer(t *testing.T) {
	tx := newScanText("x `cmd` y $(id) z ${home}")
	backticks := gluedBacktickCandidateFinditer(tx)
	if len(backticks) != 1 || backticks[0].text() != "`cmd`" {
		t.Fatalf("backtick candidates match, got %v", backticks)
	}
	dollars := gluedDollarSubstitutionCandidateFinditer(tx)
	if len(dollars) != 2 {
		t.Fatalf("dollar candidates match, got %d", len(dollars))
	}
}

func TestLDAPParenConjunctionFinditer(t *testing.T) {
	tx := newScanText("x (&(uid=a)(cn=b)) y")
	got := ldapParenConjunctionFinditer(tx)
	if len(got) != 1 || got[0].text() != "(&" {
		t.Fatalf("conjunction openers match, got %v", got)
	}
	if got := ldapParenConjunctionFinditer(newScanText("(uid=x)")); got != nil {
		t.Fatalf("plain filters yield nothing, got %v", got)
	}
}

func TestDetectWindowedMatchers(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"load_file", "; LOAD_FILE('/etc/passwd')"},
		{"dollar_subst", "; $(id); ${home}"},
		{"glob_atoms", "file*.txt and fi?e"},
		{"quote_splice", "ad''min"},
		{"null_byte", "uid=*))+\\x00"},
		{"dash_c", "\n sh -c id"},
	}
	for _, tc := range cases {
		// The sweep must run these windowed finders without panicking; the
		// branch-level tests above pin their exact behaviors.
		_ = Detect(tc.content, "", "request_body")
		_ = tc.name
	}
}
