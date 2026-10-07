package guardcore

// Tests mirroring tests/test_sus_patterns/test_redos_unreachable_terminator.py
// and the structural rule cases pinned by the safety corpus.

import "testing"

func TestSkipCharClass(t *testing.T) {
	if got := skipCharClass(`[abc]def`, 0); got != 5 {
		t.Fatalf("skipCharClass simple wrong: %d", got)
	}
	if got := skipCharClass(`[a\]b]x`, 0); got != 6 {
		t.Fatalf("skipCharClass escaped close wrong: %d", got)
	}
	if got := skipCharClass(`[abc`, 0); got != 4 {
		t.Fatalf("skipCharClass unterminated wrong: %d", got)
	}
}

func TestStripEscapesAndCharClasses(t *testing.T) {
	if got := stripEscapesAndCharClasses(`a\d[0-9]b`); got != "aXXb" {
		t.Fatalf("strip wrong: %q", got)
	}
}

func TestBranchIsUnboundedSingle(t *testing.T) {
	cases := map[string]bool{
		".*":    true,
		".+":    true,
		".{2,}": true,
		// the reference's `.[*+]` fullmatch accepts ANY first character
		"a*":     true,
		"z+":     true,
		"a?":     false,
		".":      false,
		".{1,2}": false,
	}
	for input, want := range cases {
		if got := branchIsUnboundedSingle(input); got != want {
			t.Fatalf("branchIsUnboundedSingle(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestAdvancePastEscapeOrCharClass(t *testing.T) {
	if got := advancePastEscapeOrCharClass(`\dabc`, 0); got != 2 {
		t.Fatalf("escape advance wrong: %d", got)
	}
	if got := advancePastEscapeOrCharClass(`[ab]c`, 0); got != 4 {
		t.Fatalf("class advance wrong: %d", got)
	}
	if got := advancePastEscapeOrCharClass(`abc`, 0); got != -1 {
		t.Fatalf("plain char advance wrong: %d", got)
	}
}

func TestFindGroupEnd(t *testing.T) {
	if got := findGroupEnd(`(a(b)c)d`, 0); got != 7 {
		t.Fatalf("nested group end wrong: %d", got)
	}
	if got := findGroupEnd(`(abc`, 0); got != -1 {
		t.Fatalf("unbalanced group end wrong: %d", got)
	}
	if got := findGroupEnd(`(a[)]b)c`, 0); got != 7 {
		t.Fatalf("class-protected close wrong: %d", got)
	}
}

func TestNormalizeGroupInner(t *testing.T) {
	if got, ok := normalizeGroupInner("?:abc"); !ok || got != "abc" {
		t.Fatalf("non-capping inner wrong: %q %v", got, ok)
	}
	if _, ok := normalizeGroupInner("?P=n"); ok {
		t.Fatal("backref group should not normalize")
	}
	if got, ok := normalizeGroupInner("?P<name>x"); !ok || got != "x" {
		t.Fatalf("named inner wrong: %q %v", got, ok)
	}
	if _, ok := normalizeGroupInner("?P<name"); ok {
		t.Fatal("unterminated name should not normalize")
	}
	if got, ok := normalizeGroupInner("plain"); !ok || got != "plain" {
		t.Fatalf("plain inner wrong: %q %v", got, ok)
	}
}

func TestUnwrapTransparentWrapper(t *testing.T) {
	if got := unwrapTransparentWrapper(`(?:(?:a|aa))`); got != `a|aa` {
		t.Fatalf("unwrap wrong: %q", got)
	}
	if got := unwrapTransparentWrapper(`(?:a|aa)+`); got != `(?:a|aa)+` {
		t.Fatalf("quantified unwrap must not fire: %q", got)
	}
	if got := unwrapTransparentWrapper(`(?P=n)`); got != `(?P=n)` {
		t.Fatalf("backref unwrap must not fire: %q", got)
	}
	if got := unwrapTransparentWrapper(`(a|aa)`); got != `a|aa` {
		t.Fatalf("capturing unwrap mirrors the reference: %q", got)
	}
	if got := unwrapTransparentWrapper(`(unclosed`); got != `(unclosed` {
		t.Fatalf("unbalanced unwrap must not fire: %q", got)
	}
}

func TestOuterQuantifierLen(t *testing.T) {
	if got := outerQuantifierLen("a*", 1); got != 1 {
		t.Fatalf("star len wrong: %d", got)
	}
	if got := outerQuantifierLen("a+?", 1); got != 1 {
		t.Fatalf("plus len wrong: %d", got)
	}
	if got := outerQuantifierLen("a{2,}?", 1); got != 4 {
		t.Fatalf("brace len wrong: %d", got)
	}
	if got := outerQuantifierLen("a{2}", 1); got != 0 {
		t.Fatalf("bounded brace len wrong: %d", got)
	}
	if got := outerQuantifierLen("ab", 1); got != 0 {
		t.Fatalf("no quantifier wrong: %d", got)
	}
}

func TestBranchesOverlapAndLiterals(t *testing.T) {
	if !branchesOverlap([]string{"a", "aa"}) {
		t.Fatal("prefix overlap missed")
	}
	if branchesOverlap([]string{"a", "b"}) {
		t.Fatal("disjoint branches flagged")
	}
	if !isPureLiteralBranch("abc") {
		t.Fatal("pure literal rejected")
	}
	if isPureLiteralBranch("a*") {
		t.Fatal("meta branch accepted")
	}
	if isPureLiteralBranch("") {
		t.Fatal("empty branch accepted")
	}
	if !overlappingLiteralBranches("a|aa") {
		t.Fatal("overlapping literals missed")
	}
	if overlappingLiteralBranches("a|b|c") {
		t.Fatal("non-overlapping literals flagged")
	}
	if overlappingLiteralBranches("a") {
		t.Fatal("single literal flagged")
	}
}

func TestSplitTopLevelAlternations(t *testing.T) {
	got := splitTopLevelAlternations("a|b(c|d)|e")
	if len(got) != 3 || got[0] != "a" || got[1] != "b(c|d)" || got[2] != "e" {
		t.Fatalf("split wrong: %q", got)
	}
	got = splitTopLevelAlternations(`[|]a|b`)
	if len(got) != 2 || got[0] != `[|]a` {
		t.Fatalf("class-protected split wrong: %q", got)
	}
}

func TestIterQuantifiedGroupBodies(t *testing.T) {
	bodies, err := iterQuantifiedGroupBodies(`(?:a*)+b`, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, body := range bodies {
		if body.inner == "a*" {
			found = true
		}
	}
	if !found {
		t.Fatalf("quantified body a* not found: %+v", bodies)
	}
	if _, err := iterQuantifiedGroupBodies("(unclosed", 0, 0); err != nil {
		t.Fatalf("unbalanced groups must be skipped: %v", err)
	}
}

func TestIterQuantifiedGroupBodiesDepthLimit(t *testing.T) {
	deep := "(unclosed"
	err := error(nil)
	_ = err
	// depth beyond the limit rejects with the reference reason
	_, err = iterQuantifiedGroupBodies("a", 0, maxGroupNestingDepth+1)
	if err == nil || err.Error() != nestingDepthRejectionReason {
		t.Fatalf("depth limit wrong: %v", err)
	}
	_ = deep
}

func TestDetectNestedUnboundedQuantifier(t *testing.T) {
	unsafe := []string{
		`(?:a*)*`,
		`(a+)+`,
		`(?:X+)*$`,
		`(?P<n>a*)*`,
		`(?:a|aa)+$`,
		`(?:X*)*`,
	}
	for _, pattern := range unsafe {
		if _, found, _ := detectNestedUnboundedQuantifier(pattern); !found {
			t.Fatalf("nested unbounded missed: %q", pattern)
		}
	}
	safe := []string{
		`(?:a*)?b`,
		`a*a`,
	}
	for _, pattern := range safe {
		if _, found, _ := detectNestedUnboundedQuantifier(pattern); found {
			t.Fatalf("nested unbounded false positive: %q", pattern)
		}
	}
}

func TestIsBroadCharClassInner(t *testing.T) {
	cases := map[string]bool{
		`^>`:   true,
		`^a`:   true,
		`^a\S`: false,
		`\s\S`: true,
		`\S\s`: true,
		`abc`:  false,
		`^\d`:  true,
		`^a\b`: true,
		`^\SW`: false,
	}
	for input, want := range cases {
		if got := isBroadCharClassInner(input); got != want {
			t.Fatalf("isBroadCharClassInner(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestBroadAtomSpan(t *testing.T) {
	if end, broad := broadAtomSpan(`.*x`, 0); end != 1 || !broad {
		t.Fatalf("dot span wrong: %d %v", end, broad)
	}
	if end, broad := broadAtomSpan(`\S+`, 0); end != 2 || !broad {
		t.Fatalf("upper shorthand span wrong: %d %v", end, broad)
	}
	if end, broad := broadAtomSpan(`\s+`, 0); end != 2 || broad {
		t.Fatalf("lower shorthand span wrong: %d %v", end, broad)
	}
	if end, broad := broadAtomSpan(`[^>]*`, 0); end != 4 || !broad {
		t.Fatalf("negated class span wrong: %d %v", end, broad)
	}
	if end, broad := broadAtomSpan(`a*`, 0); end != 1 || broad {
		t.Fatalf("literal span wrong: %d %v", end, broad)
	}
}

func TestBroadUnboundedRunAtGroups(t *testing.T) {
	// best branch only counts once per group
	count, spans, err := broadUnboundedRunAt(`(?:\S+|\w)`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(spans) != 1 || spans[0] != `\S` {
		t.Fatalf("group best-branch wrong: %d %v", count, spans)
	}
}

func TestDetectAdjacentBroadUnbounded(t *testing.T) {
	unsafe := []string{
		`.*x.*`,
		`[\s\S]*[\s\S]+$`,
		`<script[^>]*>[^<]*<\/script\s*>`,
		`[^<>]*(?:foo|bar)[^\"']*`,
		`[\s\S]*x[^%]+`,
		`[^>]*>[^<]*`,
		`(?:x|(?:y|[^>]*b[^<]*c))`,
	}
	for _, pattern := range unsafe {
		if _, found, _ := detectAdjacentBroadUnboundedQuantifiers(pattern); !found {
			t.Fatalf("adjacent broad missed: %q", pattern)
		}
	}
	safe := []string{
		`'[^']*'`,
		`'\s*(?:\s+)\s*--`,
		`.*x`,
	}
	for _, pattern := range safe {
		if _, found, _ := detectAdjacentBroadUnboundedQuantifiers(pattern); found {
			t.Fatalf("adjacent broad false positive: %q", pattern)
		}
	}
}

func TestDetectUnreachableTerminator(t *testing.T) {
	unsafe := []string{
		`<!\[CDATA\[.*?\]\]>`,
		`<script[^>]*>`,
		`\$\([^)]+\)`,
		`\$\{[^}]+\}`,
		`\(\s*[^)]+=`,
		`\(\s*[|&]\s*\(\s*[^)]+=[*]`,
		`foo.*bar`,
	}
	for _, pattern := range unsafe {
		if _, found := detectUnreachableTerminatorScan(pattern); !found {
			t.Fatalf("unreachable terminator missed: %q", pattern)
		}
	}
	safe := []string{
		`'[^']*'`,
		`'\s*(?:AND|OR)\s*--`,
		`abc`,
	}
	for _, pattern := range safe {
		if _, found := detectUnreachableTerminatorScan(pattern); found {
			t.Fatalf("unreachable terminator false positive: %q", pattern)
		}
	}
}

func TestUnreachableTerminatorExcludedScan(t *testing.T) {
	if !unreachableTerminatorExcludedScan(`\$\([^)]+\)`) {
		t.Fatal("negated-class scan with excluded terminator not detected")
	}
	if !unreachableTerminatorExcludedScan(`\$\{[^}]+\}`) {
		t.Fatal("brace negated-class scan not detected")
	}
	if !unreachableTerminatorExcludedScan(`<script[^>]*>`) {
		t.Fatal("script negated-class scan not detected")
	}
	if unreachableTerminatorExcludedScan(`foo.*bar`) {
		t.Fatal("dot scan misclassified as excluded")
	}
	if unreachableTerminatorExcludedScan(`<!\[CDATA\[.*?\]\]>`) {
		t.Fatal("cdata dot scan misclassified as excluded")
	}
}

func TestTerminatorHelpers(t *testing.T) {
	if got := skipSymbolQuantifierAt(`*?ab`, 0); got != 2 {
		t.Fatalf("symbol quantifier skip wrong: %d", got)
	}
	if got := skipBraceQuantifierAt(`{2,3}?ab`, 0); got != 6 {
		t.Fatalf("brace quantifier skip wrong: %d", got)
	}
	if got := skipBraceQuantifierAt(`{abc`, 0); got != 0 {
		t.Fatalf("malformed brace skip wrong: %d", got)
	}
	if got := skipBraceQuantifierAt(`{a,b}x`, 0); got != 0 {
		t.Fatalf("non-digit brace skip wrong: %d", got)
	}
	if got := skipQuantifierAt(`abc`, 0); got != 0 {
		t.Fatalf("plain skip wrong: %d", got)
	}
	if !quantifierAtAllowsZero(`{0,2}x`, 0) || !quantifierAtAllowsZero(`{,2}x`, 0) {
		t.Fatal("zero-allowing brace wrong")
	}
	if quantifierAtAllowsZero(`{2}x`, 0) || quantifierAtAllowsZero(`+x`, 0) {
		t.Fatal("non-zero quantifier misclassified")
	}
	if set, ok := terminatorCharsAt(`ab`, 0); !ok || !set['a'] {
		t.Fatalf("literal terminator wrong: %v %v", set, ok)
	}
	if _, ok := terminatorCharsAt(`\d`, 0); ok {
		t.Fatal("category terminator should be undecidable")
	}
	if set, ok := terminatorCharsAt(`\!`, 0); !ok || !set['!'] {
		t.Fatalf("escaped punctuation terminator wrong: %v %v", set, ok)
	}
	if _, ok := terminatorCharsAt("", 0); ok {
		t.Fatal("end-of-pattern terminator should be undecidable")
	}
	if _, ok := terminatorCharsAt(`[^a]`, 0); ok {
		t.Fatal("negated class terminator should be undecidable")
	}
	if _, ok := terminatorCharsAt(`[]`, 0); ok {
		t.Fatal("empty class terminator should be undecidable")
	}
	if set, ok := terminatorCharsAt(`[abc]`, 0); !ok || !set['b'] {
		t.Fatalf("class terminator wrong: %v %v", set, ok)
	}
	if end, excluded, ok := broadScanExcludedChars(`.x`, 0); end != 1 || !ok || len(excluded) != 0 {
		t.Fatalf("dot scan exclusion wrong: %d %v %v", end, excluded, ok)
	}
	if _, excluded, ok := broadScanExcludedChars(`[ab]x`, 0); ok {
		t.Fatalf("non-negated class should be undecidable: %v", excluded)
	}
}

func TestQuantifierSpanAllowsZero(t *testing.T) {
	if end, zero := quantifierSpanAllowsZero(`*ab`, 0); end != 1 || !zero {
		t.Fatalf("star span wrong: %d %v", end, zero)
	}
	if end, zero := quantifierSpanAllowsZero(`+ab`, 0); end != 1 || zero {
		t.Fatalf("plus span wrong: %d %v", end, zero)
	}
	if end, zero := quantifierSpanAllowsZero(`{2}ab`, 0); end != 3 || zero {
		t.Fatalf("exact brace span wrong: %d %v", end, zero)
	}
	if end, zero := quantifierSpanAllowsZero(`x`, 0); end != 0 || zero {
		t.Fatalf("non-quantifier span wrong: %d %v", end, zero)
	}
}

func TestSortedRunes(t *testing.T) {
	if got := sortedRunes(map[rune]bool{'b': true, 'a': true}); got != "ab" {
		t.Fatalf("sorted runes wrong: %q", got)
	}
}
