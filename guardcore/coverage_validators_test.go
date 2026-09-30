package guardcore

// Coverage tests for the candidate validators (validators.go). Every
// validator is exercised directly with hand-built matches so the branch
// geometry (quoting, gluing, boundaries, legacy IP decoding) is covered
// independently of the registry sweep.

import (
	"testing"
)

func TestCountShellOperators(t *testing.T) {
	cases := []struct {
		token string
		want  int
	}{
		{"plain", 0},
		{"a;b", 1},
		{"a|b", 1},
		{"a||b", 1},
		{"a&b", 1},
		{"a&&b", 1},
		{";;", 2},
		{"|||", 2},
		{"a;b|c&&d&e", 4},
	}
	for _, tc := range cases {
		if got := countShellOperators(tc.token); got != tc.want {
			t.Fatalf("countShellOperators(%q) = %d, want %d", tc.token, got, tc.want)
		}
	}
}

func TestStrongSQLKeywordGluedToPair(t *testing.T) {
	// A strong keyword ending exactly at the opening backtick proves glue.
	if !strongSQLKeywordGluedToPair(newScanText("SELECT`x`"), 6, 9) {
		t.Fatal("keyword-prefixed pairs prove glue")
	}
	// A strong keyword starting exactly at the closing backtick proves
	// glue on the suffix side.
	if !strongSQLKeywordGluedToPair(newScanText("`x`FROM y"), 0, 3) {
		t.Fatal("keyword-suffixed pairs prove glue")
	}
	// Neutral neighbours prove nothing.
	if strongSQLKeywordGluedToPair(newScanText("abc`x`def"), 3, 6) {
		t.Fatal("neutral windows prove nothing")
	}
	// Multi-word keywords glue too.
	if !strongSQLKeywordGluedToPair(newScanText("ORDER BY`x`"), 8, 11) {
		t.Fatal("multi-word keywords glue")
	}
}

func backtickMatch(t *testing.T, full string, start, end int, context string) bool {
	t.Helper()
	tx := newScanText(full)
	return gluedBacktickPairIsInjection(matchFromIndices(tx, start, end, ""), context)
}

func TestGluedBacktickPairIsInjection(t *testing.T) {
	// Two or more shell operators inside the token is an injection.
	if !backtickMatch(t, "x`a;b;c`y", 1, 8, "request_body") {
		t.Fatal("multi-operator tokens are injections")
	}
	// Tokens glued to SQL keywords are deliberately not flagged.
	if backtickMatch(t, "SELECT`ab`", 6, 10, "request_body") {
		t.Fatal("sql-glued pairs are exempt")
	}
	// A metacharacter window (shell operator followed by a word) flags.
	if !backtickMatch(t, "x`ab`&&y", 1, 5, "request_body") {
		t.Fatal("metacharacter windows are injections")
	}
	// Standalone tokens with nothing glued are ignored.
	if backtickMatch(t, "`safe`", 0, 6, "request_body") {
		t.Fatal("unglued tokens are ignored")
	}
	// Word-glued tokens in ambiguous contexts flag.
	if !backtickMatch(t, "x`safe`y", 1, 7, "query_param") {
		t.Fatal("word-glued tokens in query contexts flag")
	}
	// The same token in a body context stays clean.
	if backtickMatch(t, "x`safe`y", 1, 7, "request_body") {
		t.Fatal("word-glued tokens in body contexts stay clean")
	}
	// A clause-initial backtick run appended at a sentence end flags even
	// without word gluing.
	if !backtickMatch(t, "End. `ab`", 5, 9, "request_body") {
		t.Fatal("appended clauses flag")
	}
	// Non-printable token contents fail the printable gate first.
	tx := newScanText("x`\x00\x01`y")
	if gluedBacktickPairIsInjection(matchFromIndices(tx, 1, 6, ""), "query_param") {
		t.Fatal("non-printable tokens are ignored")
	}
}

func dollarMatch(t *testing.T, full string, start, end int, context string) bool {
	t.Helper()
	tx := newScanText(full)
	return dollarSubstitutionPairIsInjection(matchFromIndices(tx, start, end, ""), context)
}

func TestDollarSubstitutionPairIsInjection(t *testing.T) {
	// Backtick-quoted substitutions are shell-idiom literals, not
	// injections.
	if dollarMatch(t, "x`$(a)b", 2, 5, "query_param") {
		t.Fatal("backtick-quoted prefixes are exempt")
	}
	if dollarMatch(t, "x$(a)`y", 1, 5, "query_param") {
		t.Fatal("backtick-quoted suffixes are exempt")
	}
	// IFS is always an injection.
	if !dollarMatch(t, "${IFS}", 0, 6, "request_body") {
		t.Fatal("ifs substitutions are injections")
	}
	if !dollarMatch(t, "$(IFS)", 0, 6, "request_body") {
		t.Fatal("parenthesised ifs are injections")
	}
	// Braced tokens that are not bare parameter names flag.
	if !dollarMatch(t, "x${a b}y", 1, 7, "request_body") {
		t.Fatal("spaced brace tokens are injections")
	}
	// Parenthesised tokens carrying metacharacters flag.
	if !dollarMatch(t, "x$(a;b)y", 1, 6, "request_body") {
		t.Fatal("metacharacter substitutions are injections")
	}
	// SQL-glued clean substitutions are exempt.
	if dollarMatch(t, "SELECT$(date)x", 6, 12, "query_param") {
		t.Fatal("sql-glued substitutions are exempt")
	}
	// Clean substitutions in ambiguous contexts flag.
	if !dollarMatch(t, "$(date)", 0, 7, "url_path") {
		t.Fatal("clean substitutions in url contexts flag")
	}
	// The same substitution in a body context stays clean.
	if dollarMatch(t, "$(date)", 0, 7, "request_body") {
		t.Fatal("clean substitutions in body contexts stay clean")
	}
}

func TestBraceExpansionIsDangerousCommand(t *testing.T) {
	brace := func(t *testing.T, text string) bool {
		t.Helper()
		tx := newScanText(text)
		return braceExpansionIsDangerousCommand(matchFromIndices(tx, 0, len([]rune(text)), ""), "request_body")
	}
	// Alphabetic expansion items flag.
	if !brace(t, "{a,b,c}") {
		t.Fatal("alphabetic brace items flag")
	}
	// Word-shaped items without letters (numeric, paths) stay clean.
	if brace(t, "{1,2,3}") {
		t.Fatal("numeric brace items stay clean")
	}
	if brace(t, "{../1,/2}") {
		t.Fatal("path brace items stay clean")
	}
	if !brace(t, "{../etc,/bin}") {
		t.Fatal("lettered path items flag")
	}
	// Items that are not word-shaped are skipped but later items count.
	if !brace(t, "{a b,c}") {
		t.Fatal("later word items still flag")
	}
	// Malformed braces never flag.
	if brace(t, "abc") || brace(t, "{}") || brace(t, "{x") {
		t.Fatal("malformed braces stay clean")
	}
}

func globMatch(t *testing.T, full string, start, end int, context string) bool {
	t.Helper()
	tx := newScanText(full)
	return globWildcardTokenIsDangerousCommand(matchFromIndices(tx, start, end, ""), context)
}

func TestGlobWildcardTokenIsDangerousCommand(t *testing.T) {
	// Tokens whose wildcards are not word-embedded stay clean.
	if globMatch(t, "*", 0, 1, "query_param") {
		t.Fatal("bare wildcards stay clean")
	}
	// A word-shaped token followed by a non-boundary rune stays clean.
	if globMatch(t, "ab*cd9", 0, 5, "query_param") {
		t.Fatal("mid-word tokens stay clean")
	}
	// A boundary character before the token flags.
	if !globMatch(t, "; ab*cd", 2, 7, "query_param") {
		t.Fatal("shell-boundary tokens flag")
	}
	// Value-start body contexts treat any leading token as a command.
	if !globMatch(t, "ab*cd", 0, 5, "request_body") {
		t.Fatal("body-leading tokens flag")
	}
	// Body tokens with a non-empty prefix stay clean.
	if globMatch(t, "x ab*cd", 2, 7, "request_body") {
		t.Fatal("prefixed body tokens stay clean")
	}
	// Everything else stays clean.
	if globMatch(t, "ab*cd", 0, 5, "query_param") {
		t.Fatal("plain query tokens stay clean")
	}
	// Question-mark wildcards count as word-embedded too.
	if !globMatch(t, "; a?c", 2, 5, "query_param") {
		t.Fatal("question-mark tokens flag after boundaries")
	}
}

func TestLDAPOps(t *testing.T) {
	// Forward extent stops at quotes and newlines.
	tx := newScanText("(a\"b)")
	if got := ldapFilterExpressionForwardExtent(tx, 0, 5); got != 2 {
		t.Fatalf("quotes bound the forward extent, got %d", got)
	}
	// Unbalanced close parens bound the extent at depth zero.
	tx = newScanText(")(a=b)")
	if got := ldapFilterExpressionForwardExtent(tx, 0, 6); got != 0 {
		t.Fatalf("depth-zero close parens bound the extent, got %d", got)
	}
	// Balanced groups run to the scan limit.
	tx = newScanText("(a=b)")
	if got := ldapFilterExpressionForwardExtent(tx, 0, 5); got != 5 {
		t.Fatalf("balanced groups run to the limit, got %d", got)
	}
	// The next-candidate limit clamps to the next regex match.
	re := mustCompile(`b`, 0, windowTimeout)
	tx = newScanText("(a)b(c)")
	if got := ldapNextCandidateScanLimit(re, tx, 2); got != 4 {
		t.Fatalf("candidate limits stop at the next match, got %d", got)
	}
	if got := ldapNextCandidateScanLimit(re, newScanText("(a)"), 2); got != 3 {
		t.Fatalf("candidate limits default to the text end, got %d", got)
	}
}

func TestLDAPWildcardChainIsInjection(t *testing.T) {
	// Matches without a close paren never chain.
	tx0 := newScanText("abc")
	if ldapWildcardChainIsInjection(matchFromIndices(tx0, 0, 3, "")) {
		t.Fatal("close-paren-less matches stay clean")
	}
	// A chain whose backward window proves no clause end and whose depth
	// stays open is not an injection.
	tx := newScanText("(a(b*c)")
	m := matchFromIndices(tx, 3, 7, "")
	m.re = mustCompile(`b\*c\)`, 0, windowTimeout)
	if ldapWildcardChainIsInjection(m) {
		t.Fatal("unproven chains stay clean")
	}
	// A backward window ending in attribute-equals-wildcard proves the
	// clause and accepts the chain.
	tx = newScanText("(a=1)(b=x*)")
	m = matchFromIndices(tx, 5, 11, "")
	m.re = mustCompile(`b=x\*`, 0, windowTimeout)
	if !ldapWildcardChainIsInjection(m) {
		t.Fatal("clause-terminated wildcards evaluate")
	}
}

func TestLegacyIPv4Decoding(t *testing.T) {
	cases := []struct {
		part  string
		want  uint32
		valid bool
	}{
		{"0x1a", 26, true},
		{"0XFF", 0, false}, // hex digits must be lowercase after the prefix
		{"0x", 0, false},
		{"0xg", 0, false},
		{"0x1ffffffff", 0, false},
		{"010", 8, true},
		{"018", 0, false},
		{"077777777777", 0, false},
		{"42", 42, true},
		{"4a", 0, false},
		{"99999999999", 0, false},
		{"", 0, true},
	}
	for _, tc := range cases {
		got, ok := decodeLegacyIPv4Part(tc.part)
		if ok != tc.valid || (ok && got != tc.want) {
			t.Fatalf("decodeLegacyIPv4Part(%q) = %d %v, want %d %v", tc.part, got, ok, tc.want, tc.valid)
		}
	}
}

func TestLegacyIPv4HostDecoding(t *testing.T) {
	cases := []struct {
		host  string
		want  uint32
		valid bool
	}{
		{"127.0.0.1", 0x7F000001, true},
		{"0x7f.1", 0x7F000001, true},
		{"2130706433", 0x7F000001, true},
		{"1.2.3.4", 0x01020304, true},
		{"169254", 0, false}, // bare small integers are hostnames
		{"0123456", 42798, true},
		{"256.1", 0, false},     // leading parts must fit a byte
		{"1.2.3.256", 0, false}, // final part must fit the tail bits
		{"1.2.3.4.5", 0, false}, // at most four parts
		{"a.b", 0, false},       // non-numeric parts fail
		{"1.2.x", 0, false},
	}
	for _, tc := range cases {
		got, ok := decodeLegacyIPv4Host(tc.host)
		if ok != tc.valid || (ok && got != tc.want) {
			t.Fatalf("decodeLegacyIPv4Host(%q) = %d %v, want %d %v", tc.host, got, ok, tc.want, tc.valid)
		}
	}
}

func TestLegacyIPv4MatchIsBlocked(t *testing.T) {
	legacy := func(t *testing.T, full, g1 string) bool {
		t.Helper()
		tx := newScanText(full)
		m := matchFromIndices(tx, 0, len(g1), g1)
		m.re = mustCompile(legacyIPv4HostSource, 0, windowTimeout)
		return legacyIPv4MatchIsBlocked(m, "url_path")
	}
	// Loopback, link-local, private, and datagram ranges block.
	if !legacy(t, "http://127.0.0.1/", "127.0.0.1") {
		t.Fatal("loopback aliases block")
	}
	if !legacy(t, "http://2130706433/", "2130706433") {
		t.Fatal("decimal loopback aliases block")
	}
	// Public addresses pass.
	if legacy(t, "http://8.8.8.8/", "8.8.8.8") {
		t.Fatal("public addresses pass")
	}
	// Undecodable hosts pass the legacy gate.
	if legacy(t, "http://example.com/", "example") {
		t.Fatal("non-numeric hosts pass")
	}
}
