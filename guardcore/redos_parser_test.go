package guardcore

// Parser tests mirroring the reference oracle's compile gate: the corpus's
// compile_failed cases must reject, the corpus's accepted patterns must
// parse, and the error classification prefix must hold.

import "testing"

func mustParse(t *testing.T, pattern string, flags reFlags) *parsedPattern {
	t.Helper()
	parsed, err := parseRedosPattern(pattern, flags)
	if err != nil {
		t.Fatalf("parse %q failed: %v", pattern, err)
	}
	return parsed
}

func mustFailParse(t *testing.T, pattern string, flags reFlags) *redosParseError {
	t.Helper()
	_, err := parseRedosPattern(pattern, flags)
	if err == nil {
		t.Fatalf("parse %q unexpectedly succeeded", pattern)
	}
	parseErr, ok := err.(*redosParseError)
	if !ok {
		t.Fatalf("parse %q returned non-parse error: %T", pattern, err)
	}
	return parseErr
}

func TestParseCorpusAcceptedPatterns(t *testing.T) {
	accepted := []string{
		`'[^']*'`,
		`'\s*(?:\s+)\s*--`,
		`'\s*(?!x)\s*--`,
		`'\s*(?:(\s)\1z)+\s*--`,
		`'\s*(?:AND|OR)\s*--`,
		`'\s*(?:\d*(?!y)(z))+\s*--`,
		`'[^']*'|"[^"]*"`,
		`(?:\'[^\']*\'|\"[^\"]*\")`,
		`(?!x)`,
		`(?:AND|OR)`,
		`(?i)union\s+select`,
		`(?i:abc)d`,
		`(?<=a)b`,
		`(?<!a)b`,
		`(?#comment)x`,
		`a{2,`,
		`a{,3}`,
		`(?P<x>a)(?P=x)`,
		`\b`,
		`\x41\u0042\U00000043\101\0`,
		`[a-z\-]{2,4}?`,
		`[\w.-]+`,
		`[]]`,
		`[-a]`,
		`x*?`,
		`^$\A\Z\b\B`,
		`(?:a|b|c)*d{3}`,
	}
	for _, pattern := range accepted {
		mustParse(t, pattern, defaultPatternFlags)
	}
}

func TestParseCorpusCompileFailed(t *testing.T) {
	cases := []struct {
		pattern string
		message string
	}{
		{`(?:'[^\']*'|\"[^\"]*\")\s*=\s*\1`, "invalid group reference 1"},
		{`(?:\1)`, "invalid group reference 1"},
		{`(?P=n)`, "unknown group name 'n'"},
		{`(?P<1bad>x)`, "bad character in group name '1bad'"},
		{`(?>a)+`, "unknown extension ?>"},
		{`*leading`, "nothing to repeat"},
		{`+leading`, "nothing to repeat"},
		{`?leading`, "nothing to repeat"},
		{`{2}leading`, "nothing to repeat"},
		{`(unclosed`, "missing ), unterminated subpattern"},
		{`[invalid`, "unterminated character set"},
		{`x)`, "unbalanced parenthesis"},
		{`(a))`, "unbalanced parenthesis"},
		{`a**`, "multiple repeat"},
		{`(a\1)`, "cannot refer to an open group"},
		{`(?P<a>x)(?P<a>y)`, "redefinition of group name 'a'"},
		{`\q`, "bad escape \\q"},
		{`(?q)`, "unknown flag"},
		{`abc(?i)`, "global flags not at the start"},
		{`[\z]`, "bad escape"},
	}
	for _, tc := range cases {
		err := mustFailParse(t, tc.pattern, defaultPatternFlags)
		if len(err.Error()) < len(tc.message) || err.Error()[:len(tc.message)] != tc.message {
			t.Fatalf("parse %q error %q does not start with %q", tc.pattern, err.Error(), tc.message)
		}
	}
}

func TestParseErrorFormat(t *testing.T) {
	err := parseErrorAt("boom", 7)
	if err.Error() != "boom at position 7" {
		t.Fatalf("error format wrong: %q", err.Error())
	}
}

func TestParseGroupNumbersAndNames(t *testing.T) {
	parsed := mustParse(t, `(a)(?:b)(?P<two>c)`, 0)
	// sre_parse.State starts the counter at 1: two opened groups leave it
	// at 3, and backref validity checks against this counter.
	if parsed.groups != 3 {
		t.Fatalf("groups wrong: %d", parsed.groups)
	}
	if parsed.groupNames["two"] != 2 {
		t.Fatalf("group names wrong: %v", parsed.groupNames)
	}
}

func TestParseScopedFlags(t *testing.T) {
	parsed := mustParse(t, `(?i:a)bc`, 0)
	if len(parsed.nodes) != 3 {
		t.Fatalf("scoped flags node count wrong: %d", len(parsed.nodes))
	}
}

func TestParseCommentGroupSkipped(t *testing.T) {
	parsed := mustParse(t, `a(?#note)b`, 0)
	if len(parsed.nodes) != 2 {
		t.Fatalf("comment group not skipped: %d nodes", len(parsed.nodes))
	}
}

func TestParseGlobalFlagsAtStart(t *testing.T) {
	parsed := mustParse(t, `(?im)x`, 0)
	if parsed.flags&flagIgnoreCase == 0 || parsed.flags&flagMultiline == 0 {
		t.Fatalf("global flags not applied: %v", parsed.flags)
	}
	if len(parsed.nodes) != 1 {
		t.Fatalf("global flags left nodes: %d", len(parsed.nodes))
	}
}

func TestParseNegativeFlags(t *testing.T) {
	parsed := mustParse(t, `(?i-s:a)x`, flagIgnoreCase|flagDotAll)
	// scoped: outer flags keep the global defaults for x
	if len(parsed.nodes) != 2 {
		t.Fatalf("negative scoped flags parse wrong: %d", len(parsed.nodes))
	}
}

func TestParseVerboseMode(t *testing.T) {
	parsed := mustParse(t, "(?x) a b # comment\n c", 0)
	if len(parsed.nodes) != 3 {
		t.Fatalf("verbose parse wrong: %d nodes", len(parsed.nodes))
	}
	verboseNoNewline := mustParse(t, `(?x) a  b`, 0)
	if len(verboseNoNewline.nodes) != 2 {
		t.Fatalf("verbose parse (no trailing newline) wrong: %d", len(verboseNoNewline.nodes))
	}
}

func TestParseUnterminatedConstructs(t *testing.T) {
	if err := mustFailParse(t, `(?P<ab`, defaultPatternFlags); err.msg != "missing >, unterminated name" {
		t.Fatalf("unterminated named group wrong: %v", err)
	}
	if err := mustFailParse(t, `(?P`, defaultPatternFlags); err.msg != "unknown extension ?P" {
		t.Fatalf("bare ?P wrong: %v", err)
	}
	if err := mustFailParse(t, `(?`, defaultPatternFlags); err.msg != "unknown extension" {
		t.Fatalf("bare (? wrong: %v", err)
	}
	if err := mustFailParse(t, `(?#oops`, defaultPatternFlags); err.msg != "missing ), unterminated comment" {
		t.Fatalf("unterminated comment wrong: %v", err)
	}
	if err := mustFailParse(t, `(?P<a`, defaultPatternFlags); err.msg == "" {
		t.Fatal("unterminated group name should fail")
	}
	if err := mustFailParse(t, `(?i`, defaultPatternFlags); err.msg != "unknown flag" {
		t.Fatalf("unterminated flags wrong: %v", err)
	}
}

func TestParseOctalAndHexEscapes(t *testing.T) {
	parsed := mustParse(t, `\0\01\012\xff`, 0)
	if len(parsed.nodes) != 4 {
		t.Fatalf("octal/hex escape node count wrong: %d", len(parsed.nodes))
	}
	if err := mustFailParse(t, `\400`, 0); err.msg == "" {
		t.Fatal("out-of-range octal should fail")
	}
	if err := mustFailParse(t, `\x2`, 0); err.msg == "" {
		t.Fatal("short hex escape should fail")
	}
	if err := mustFailParse(t, `\xzz`, 0); err.msg == "" {
		t.Fatal("bad hex escape should fail")
	}
	if err := mustFailParse(t, `\`, 0); err.msg == "" {
		t.Fatal("trailing backslash should fail")
	}
	if err := mustFailParse(t, `\N`, 0); err.msg == "" {
		t.Fatal("named unicode escape should fail closed")
	}
}

func TestParseClassEscapes(t *testing.T) {
	mustParse(t, `[\d\w\s\D\W\S\b\x41\u0042\0\1\-\]]`, 0)
	if err := mustFailParse(t, `[\q]`, 0); err.msg == "" {
		t.Fatal("bad class escape should fail")
	}
	if err := mustFailParse(t, `[\N]`, 0); err.msg == "" {
		t.Fatal("class named escape should fail")
	}
	if err := mustFailParse(t, `[a-\d]`, 0); err.msg == "" {
		t.Fatal("class-category range should fail")
	}
	if err := mustFailParse(t, `[z-a]`, 0); err.msg == "" {
		t.Fatal("inverted range should fail")
	}
	if err := mustFailParse(t, `[ab`, 0); err.msg != "unterminated character set" {
		t.Fatalf("unterminated class wrong: %v", err)
	}
	parsed := mustParse(t, `[^a]`, 0)
	if len(parsed.nodes) != 1 {
		t.Fatal("negated class node count wrong")
	}
}

func TestParseLiteralFallbacks(t *testing.T) {
	// a malformed brace is a literal
	parsed := mustParse(t, `a{2,x`, 0)
	if len(parsed.nodes) != 5 {
		t.Fatalf("literal brace parse wrong: %d", len(parsed.nodes))
	}
	parsed = mustParse(t, `a{`, 0)
	if len(parsed.nodes) != 2 {
		t.Fatalf("open brace literal wrong: %d", len(parsed.nodes))
	}
	// punctuation escapes are literal
	parsed = mustParse(t, `\<\>\,`, 0)
	if len(parsed.nodes) != 3 {
		t.Fatalf("punctuation escapes wrong: %d", len(parsed.nodes))
	}
}

func TestParseQuantifierErrorsPosition(t *testing.T) {
	err := mustFailParse(t, `a**`, defaultPatternFlags)
	if err.pos != 2 {
		t.Fatalf("multiple repeat position wrong: %d", err.pos)
	}
	err = mustFailParse(t, `^*`, defaultPatternFlags)
	if err.msg != "nothing to repeat" {
		t.Fatalf("anchor quantifier wrong: %v", err)
	}
}

func TestParseGroupRefValidation(t *testing.T) {
	// \99 with 99 groups missing -> invalid reference (two digits consumed)
	err := mustFailParse(t, `\99`, defaultPatternFlags)
	if err.msg != "invalid group reference 99" {
		t.Fatalf("two-digit group reference wrong: %v", err)
	}
	// octal-looking \012 is a literal, not a reference
	mustParse(t, `\012`, 0)
}

func TestParseGroupNameErrors(t *testing.T) {
	err := mustFailParse(t, `(?P<>x)`, defaultPatternFlags)
	if err.msg != "missing group name" {
		t.Fatalf("empty group name wrong: %v", err)
	}
	err = mustFailParse(t, `(?P=a!b)`, defaultPatternFlags)
	if err.msg == "" {
		t.Fatal("bad name in reference should fail")
	}
}

func TestValidateGroupNameError(t *testing.T) {
	if err := validateGroupNameError("valid_name1", 0); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
	if err := validateGroupNameError("1bad", 0); err == nil {
		t.Fatal("digit-leading name accepted")
	}
	if err := validateGroupNameError("bad!name", 0); err == nil {
		t.Fatal("bad char name accepted")
	}
	if err := validateGroupNameError("", 0); err == nil {
		t.Fatal("empty name accepted")
	}
}

func TestParseUnknownExtensions(t *testing.T) {
	for _, pattern := range []string{`(?<name>x)`, `(?z)`, `(?P>x)`} {
		if err := mustFailParse(t, pattern, defaultPatternFlags); err.msg == "" {
			t.Fatalf("pattern %q should fail", pattern)
		}
	}
}

func TestParseLookaroundBodies(t *testing.T) {
	parsed := mustParse(t, `(?<=a+)b`, 0)
	if len(parsed.nodes) != 2 {
		t.Fatalf("lookbehind parse wrong: %d", len(parsed.nodes))
	}
	if !parsed.nodes[0].behind {
		t.Fatal("lookbehind flag wrong")
	}
	parsed = mustParse(t, `(?!x)y`, 0)
	if !parsed.nodes[0].negative || parsed.nodes[0].behind {
		t.Fatalf("negative lookahead flags wrong")
	}
}

func TestParseDecimalEscapeDisambiguation(t *testing.T) {
	// mirrors CPython's verified behavior
	mustParse(t, `\101`, 0) // octal 101 = 'A'
	if err := mustFailParse(t, `\998`, defaultPatternFlags); err.msg != "invalid group reference 99" {
		t.Fatalf("\\998 wrong: %v", err)
	}
	if err := mustFailParse(t, `\777`, defaultPatternFlags); err.msg != "octal escape value \\777 outside of range 0-0o377" {
		t.Fatalf("\\777 wrong: %v", err)
	}
	if err := mustFailParse(t, `\10`, defaultPatternFlags); err.msg != "invalid group reference 10" {
		t.Fatalf("\\10 wrong: %v", err)
	}
	err := mustFailParse(t, `a*??`, defaultPatternFlags)
	if err.msg != "multiple repeat" || err.pos != 3 {
		t.Fatalf("a*?? wrong: %v", err)
	}
	err = mustFailParse(t, `a{2}{3}`, defaultPatternFlags)
	if err.msg != "multiple repeat" || err.pos != 4 {
		t.Fatalf("a{2}{3} wrong: %v", err)
	}
	err = mustFailParse(t, `a*{2}`, defaultPatternFlags)
	if err.msg != "multiple repeat" || err.pos != 2 {
		t.Fatalf("a*{2} wrong: %v", err)
	}
}

func TestParsePatternShapes(t *testing.T) {
	// branch, repeat-of-group, and ref shapes the slots layer consumes
	parsed := mustParse(t, `(?:a|b)*c`, 0)
	if parsed.nodes[0].op != opRepeat || parsed.nodes[0].max != maxRepeat {
		t.Fatalf("unbounded repeat wrong: %+v", parsed.nodes[0])
	}
	parsed = mustParse(t, `a{2,4}`, 0)
	if parsed.nodes[0].min != 2 || parsed.nodes[0].max != 4 || parsed.nodes[0].lazy {
		t.Fatalf("bounded repeat wrong: %+v", parsed.nodes[0])
	}
	parsed = mustParse(t, `a+?`, 0)
	if !parsed.nodes[0].lazy {
		t.Fatal("lazy marker wrong")
	}
	parsed = mustParse(t, `a|b|c`, 0)
	if parsed.nodes[0].op != opBranch || len(parsed.nodes[0].branches) != 3 {
		t.Fatal("branch shape wrong")
	}
	parsed = mustParse(t, `\d`, 0)
	if parsed.nodes[0].interval == nil || !parsed.nodes[0].interval.contains('5') {
		t.Fatal("category interval missing")
	}
	parsed = mustParse(t, `[^a]`, 0)
	if parsed.nodes[0].interval.contains('a') || !parsed.nodes[0].interval.contains('b') {
		t.Fatal("negated class interval wrong")
	}
}
