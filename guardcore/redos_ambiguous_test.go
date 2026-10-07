package guardcore

// Tests mirroring tests/test_sus_patterns/test_redos_literal_runs.py and the
// ambiguous-tail / literal-absorb corpus cases.

import "testing"

func TestLiteralRunAt(t *testing.T) {
	run, end := literalRunAt(`--rest`, 0)
	if run != "--rest" || end != 6 {
		t.Fatalf("literal run wrong: %q %d", run, end)
	}
	run, end = literalRunAt(`abc9-x`, 0)
	if run != "abc9-x" || end != 6 {
		t.Fatalf("alnum run wrong: %q %d", run, end)
	}
	run, _ = literalRunAt(`x`, 1)
	if run != "" {
		t.Fatalf("past-end run wrong: %q", run)
	}
}

func TestWildcardAbsorbsLiteral(t *testing.T) {
	// [\w-]*-- : the class absorbs the mandatory literal
	if finding, found := wildcardAbsorbsLiteral(`[\w-]*--`, 0, 5); !found || finding != `[\w-]* then literal '--'` {
		t.Fatalf("absorb wrong: %q %v", finding, found)
	}
	// [^']*' : the class excludes the literal -> no absorb
	if _, found := wildcardAbsorbsLiteral(`'[^']*'`, 0, 5); found {
		t.Fatal("exclusive class flagged as absorbing")
	}
	// single-char literal -> no finding
	if _, found := wildcardAbsorbsLiteral(`[\w]*a`, 0, 4); found {
		t.Fatal("single-char literal flagged")
	}
	// no quantifier -> no finding
	if _, found := wildcardAbsorbsLiteral(`[ab]cd`, 0, 3); found {
		t.Fatal("unquantified class flagged")
	}
	// empty class set -> no finding
	if _, found := wildcardAbsorbsLiteral(`\b*ab`, 0, 2); found {
		t.Fatal("zero-width class flagged")
	}
}

func TestDetectAmbiguousLiteralBoundary(t *testing.T) {
	if _, found := detectAmbiguousLiteralBoundary(`[\w-]*--`); !found {
		t.Fatal("literal absorb missed")
	}
	if _, found := detectAmbiguousLiteralBoundary(`[\w-]*config[\w-]*\.env`); !found {
		t.Fatal("config absorb missed")
	}
	if _, found := detectAmbiguousLiteralBoundary(`[a-z]+abc`); !found {
		t.Fatal("abc absorb missed")
	}
	if _, found := detectAmbiguousLiteralBoundary(`'[^']*'`); found {
		t.Fatal("exclusive class flagged")
	}
}

func TestParseFlatQuantifiedAtomsWithText(t *testing.T) {
	if atoms := parseFlatQuantifiedAtomsWithText("a+"); len(atoms) != 1 {
		t.Fatalf("flat atoms wrong: %+v", atoms)
	}
	if atoms := parseFlatQuantifiedAtomsWithText("(a)+"); atoms != nil {
		t.Fatal("group inner should reject flat parse")
	}
	if atoms := parseFlatQuantifiedAtomsWithText("a|b"); atoms != nil {
		t.Fatal("alternation should reject flat parse")
	}
	// the reference accepts any first brace part and marks the atom variable
	if atoms := parseFlatQuantifiedAtomsWithText("a{2,x}"); atoms == nil || !atoms[0].variable {
		t.Fatalf("brace-with-junk-high should parse variable: %+v", atoms)
	}
	atoms := parseFlatQuantifiedAtomsWithText(`\w+\s?`)
	if len(atoms) != 2 {
		t.Fatalf("two-atom parse wrong: %+v", atoms)
	}
	if !atoms[0].unbounded || !atoms[1].optional {
		t.Fatalf("atom shapes wrong: %+v", atoms)
	}
	atoms = parseFlatQuantifiedAtomsWithText(`a{2,4}`)
	if len(atoms) != 1 || atoms[0].optional || atoms[0].unbounded || !atoms[0].variable {
		t.Fatalf("brace atom wrong: %+v", atoms)
	}
	atoms = parseFlatQuantifiedAtomsWithText(`a{2}`)
	if len(atoms) != 1 || atoms[0].variable {
		t.Fatalf("exact brace atom wrong: %+v", atoms)
	}
}

func TestGroupInnerIsAmbiguous(t *testing.T) {
	ambiguous := []string{
		`\w+\s?`,
		`\d{1,3}\d{1,3}`,
		`[a-f]{2,4}`,
		`a+\s?`,
		`\d\d?`,
	}
	for _, inner := range ambiguous {
		if !groupInnerIsAmbiguous(inner) {
			t.Fatalf("ambiguous inner missed: %q", inner)
		}
	}
	unambiguous := []string{
		"a",
		"a+",
		"a*b",
		"(a)+",
		`\w+\s+`,
	}
	for _, inner := range unambiguous {
		if groupInnerIsAmbiguous(inner) {
			t.Fatalf("ambiguous false positive: %q", inner)
		}
	}
}

func TestDetectAmbiguousOptionalTail(t *testing.T) {
	unsafe := []string{
		`(?:\w+\s?)+$`,
		`((\d{1,3}\d{1,3}))+$`,
		`(?P<n>a+\s?)*`,
		`(?P<a>(?P<b>\d\d?))+$`,
		`([0-9A-F][0-9A-F]?)+$`,
		`([a-f]{2,4})+`,
		`(?:[\w.\-~%]+[/\\][\w.\-~%]*)*`,
		`(\w+\.?)+`,
	}
	for _, pattern := range unsafe {
		if _, found, err := detectAmbiguousOptionalTail(pattern); err != nil || !found {
			t.Fatalf("ambiguous tail missed: %q (err %v)", pattern, err)
		}
	}
	safe := []string{
		`'[^']*'`,
		`'\s*(?:(\s)\1z)+\s*--`,
		`'\s*(?:\d*(?!y)(z))+\s*--`,
	}
	for _, pattern := range safe {
		if _, found, _ := detectAmbiguousOptionalTail(pattern); found {
			t.Fatalf("ambiguous tail false positive: %q", pattern)
		}
	}
}

func TestAtomCharSet(t *testing.T) {
	set := atomCharSet(`[\w-]`)
	if !set['a'] || !set['-'] || !set['0'] {
		t.Fatal("word-dash class set wrong")
	}
	if set['!'] {
		t.Fatal("punctuation should not match word class")
	}
	if s := atomCharSet(`\d`); len(s) != 10 {
		t.Fatalf("digit set wrong: %d", len(s))
	}
	if s := atomCharSet("a"); len(s) != 1 || !s['a'] {
		t.Fatal("literal set wrong")
	}
	if s := atomCharSet(`\b`); len(s) != 0 {
		t.Fatalf("zero-width set wrong: %d", len(s))
	}
	if s := atomCharSet("ab"); len(s) != 0 {
		t.Fatal("multi-node set should be empty")
	}
	if s := atomCharSet("(unclosed"); len(s) != 0 {
		t.Fatal("unparseable atom set should be empty")
	}
	if s := atomCharSet(`.`); len(s) == 0 {
		t.Fatal("dotall any set empty")
	}
}

func TestRepresentativeCharForAtom(t *testing.T) {
	if ch, ok := representativeCharForAtom(`\d`); !ok || ch != '0' {
		t.Fatalf("digit representative wrong: %q %v", ch, ok)
	}
	if ch, ok := representativeCharForAtom(`[a-z]`); !ok || ch != 'a' {
		t.Fatalf("class representative wrong: %q %v", ch, ok)
	}
	if _, ok := representativeCharForAtom(`\b`); ok {
		t.Fatal("zero-width atom has no representative")
	}
	// non-printable class falls back to the candidate members
	if ch, ok := representativeCharForAtom(`[\x01]`); !ok || ch != 1 {
		t.Fatalf("non-printable representative wrong: %q %v", ch, ok)
	}
}

func TestAtomsOverlap(t *testing.T) {
	if !atomsOverlap(`\d`, `\w`) {
		t.Fatal("digit/word overlap missed")
	}
	if atomsOverlap(`\d`, `\s`) {
		t.Fatal("digit/space false overlap")
	}
	if atomsOverlap(`\b`, `\w`) {
		t.Fatal("zero-width overlap")
	}
}

func TestCandidateCharsForAtomText(t *testing.T) {
	if chars := candidateCharsForAtomText(`\d`); len(chars) == 0 || chars[0] != '0' {
		t.Fatalf("digit candidates wrong: %v", chars)
	}
	if chars := candidateCharsForAtomText("(bad"); chars != nil {
		t.Fatalf("unparseable candidates wrong: %v", chars)
	}
	if chars := candidateCharsForAtomText("ab"); chars != nil {
		t.Fatalf("multi-node candidates wrong: %v", chars)
	}
}

func TestNodeIntervals(t *testing.T) {
	parsed := mustParse(t, `a`, 0)
	if iv := nodeIntervals(&parsed.nodes[0], 0); !iv.contains('a') {
		t.Fatal("literal intervals wrong")
	}
	parsed = mustParse(t, `[^a]`, 0)
	if iv := nodeIntervals(&parsed.nodes[0], 0); iv.contains('a') {
		t.Fatal("negated intervals wrong")
	}
	parsed = mustParse(t, `(a|b)`, 0)
	branch := parsed.nodes[0]
	if iv := nodeIntervals(&branch, 0); !iv.contains('a') || !iv.contains('b') {
		t.Fatal("branch intervals wrong")
	}
	parsed = mustParse(t, `(?<=a)b`, 0)
	if iv := nodeIntervals(&parsed.nodes[0], 0); !iv.isEmpty() {
		t.Fatal("assert intervals should be empty")
	}
	parsed = mustParse(t, `ab`, 0)
	if iv := bodyIntervals(parsed.nodes, 0); iv.contains('a') || iv.contains('b') {
		t.Fatal("sequence intervals should be the intersection (empty)")
	}
	if iv := bodyIntervals(nil, 0); !iv.isEmpty() {
		t.Fatal("empty body intervals wrong")
	}
	switch nodeIntervals(&reNode{op: opGroupRef}, 0).isEmpty() {
	case false:
		t.Fatal("ref intervals should be empty")
	}
}

func TestAdversarialLiteralRuns(t *testing.T) {
	runs := adversarialLiteralRuns(`foo.*bar`)
	if len(runs) != 2 || runs[0] != "foo" || runs[1] != "bar" {
		t.Fatalf("foo.*bar runs wrong: %q", runs)
	}
	runs = adversarialLiteralRuns(`\$\([^)]+\)`)
	if len(runs) != 2 || runs[0] != "$(" || runs[1] != ")" {
		t.Fatalf("dollar runs wrong: %q", runs)
	}
	runs = adversarialLiteralRuns(`(?:ab)+c`)
	if len(runs) != 1 || runs[0] != "abc" {
		t.Fatalf("transparent group runs wrong: %q", runs)
	}
	runs = adversarialLiteralRuns(`(ab)+c`)
	if len(runs) < 1 {
		t.Fatal("capturing group runs empty")
	}
	runs = adversarialLiteralRuns(`(?<=ab)c`)
	if len(runs) != 1 || runs[0] != "c" {
		t.Fatalf("lookaround runs wrong: %q", runs)
	}
	runs = adversarialLiteralRuns(`a*b`)
	if len(runs) != 1 || runs[0] != "ab" {
		t.Fatalf("quantifier keeps the run open: %q", runs)
	}
	runs = adversarialLiteralRuns(`\d+x`)
	if len(runs) != 1 || runs[0] != "x" {
		t.Fatalf("mandatory escape runs wrong: %q", runs)
	}
	runs = adversarialLiteralRuns(`[ab]`)
	if len(runs) != 1 || runs[0] != "a" {
		t.Fatalf("narrow class run wrong: %q", runs)
	}
	runs = adversarialLiteralRuns(`[\s\S]`)
	if len(runs) != 0 {
		t.Fatalf("broad class run wrong: %q", runs)
	}
	runs = adversarialLiteralRuns(`a{2,3}b`)
	if len(runs) != 1 || runs[0] != "ab" {
		t.Fatalf("brace keeps the run open: %q", runs)
	}
	runs = adversarialLiteralRuns(`a{open`)
	if len(runs) != 1 || runs[0] != "aopen" {
		t.Fatalf("malformed brace is literal: %q", runs)
	}
	runs = adversarialLiteralRuns(`a|b`)
	if len(runs) != 2 {
		t.Fatalf("alternation runs wrong: %q", runs)
	}
}
