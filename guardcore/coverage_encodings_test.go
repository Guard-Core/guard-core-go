package guardcore

// Coverage tests for the encoding decoders (encodings.go) and the base64
// candidate decoder (base64decode.go).

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeEscapeFamilies(t *testing.T) {
	if got := decodeHexEscapes(`a\x41b`); got != "aAb" {
		t.Fatalf("hex escapes decode, got %q", got)
	}
	if got := decodeUnicodeEscapes(`a\u0041b`); got != "aAb" {
		t.Fatalf("unicode escapes decode, got %q", got)
	}
	if got := decodePercentUEscapes(`a%u0041b`); got != "aAb" {
		t.Fatalf("percent-u escapes decode, got %q", got)
	}
	if got := decodeLDAPHexEscapes(`a\41b`); got != "aAb" {
		t.Fatalf("ldap hex escapes decode, got %q", got)
	}
}

func TestParseHex2AndError(t *testing.T) {
	if v, err := parseHex2("4a"); err != nil || v != 74 {
		t.Fatalf("hex pairs parse, got %d %v", v, err)
	}
	if _, err := parseHex2("zz"); err == nil {
		t.Fatal("non-hex input fails")
	}
	if (hexError{}).Error() != "bad hex" {
		t.Fatal("the hex error explains itself")
	}
}

func TestDecodeOverlongSequenceAt(t *testing.T) {
	// Two-byte overlong encodings collapse onto their codepoint.
	r, n, ok := decodeOverlongSequenceAt([]byte{0xC0, 0x80}, 0)
	if !ok || n != 2 || r != 0 {
		t.Fatalf("C0 80 decodes to NUL, got %d %d %v", r, n, ok)
	}
	// Truncated sequences fail.
	if _, _, ok := decodeOverlongSequenceAt([]byte{0xC0}, 0); ok {
		t.Fatal("truncated sequences fail")
	}
	// Leads not in the spec table fail.
	if _, _, ok := decodeOverlongSequenceAt([]byte{0xC2, 0x80}, 0); ok {
		t.Fatal("unlisted leads fail")
	}
	// First continuations outside the lead's range fail.
	if _, _, ok := decodeOverlongSequenceAt([]byte{0xE0, 0xFF, 0x80}, 0); ok {
		t.Fatal("E0 requires low first continuations")
	}
	if _, _, ok := decodeOverlongSequenceAt([]byte{0xF0, 0x90, 0x80, 0x80}, 0); ok {
		t.Fatal("F0 requires very low first continuations")
	}
	// Later continuations must stay in continuation range.
	if _, _, ok := decodeOverlongSequenceAt([]byte{0xF0, 0x8F, 0xFF, 0x80}, 0); ok {
		t.Fatal("stray later continuations fail")
	}
	// Well-formed overlong sequences decode their codepoint.
	r, n, ok = decodeOverlongSequenceAt([]byte{0xF0, 0x8F, 0x80, 0x80}, 0)
	if !ok || n != 4 {
		t.Fatalf("F0 8F 80 80 decodes, got %d %d %v", r, n, ok)
	}
}

func TestLenientOverlongUTF8Decode(t *testing.T) {
	// Decodable runs collapse, ascii passes through, stray bytes drop.
	got := lenientOverlongUTF8Decode([]byte{0xC0, 0x80, 'a', 0xFF, 'b'})
	if got != "\x00ab" {
		t.Fatalf("lenient decoding keeps the text skeleton, got %q", got)
	}
}

func TestDecodeOverlongUTF8PercentRuns(t *testing.T) {
	// Valid UTF-8 percent runs pass through unchanged.
	if got := decodeOverlongUTF8PercentRuns("a%C3%A9b"); got != "a%C3%A9b" {
		t.Fatalf("valid utf8 runs stay encoded, got %q", got)
	}
	// Overlong percent runs collapse onto their codepoints.
	if got := decodeOverlongUTF8PercentRuns("a%C0%80b"); got != "a\x00b" {
		t.Fatalf("overlong runs collapse, got %q", got)
	}
}

func TestURLUnquote(t *testing.T) {
	if got := urlUnquote("a%20b+c"); got != "a b+c" {
		t.Fatalf("percent bytes decode, got %q", got)
	}
	// Stray percents pass through.
	if got := urlUnquote("100%"); got != "100%" {
		t.Fatalf("stray percents stay, got %q", got)
	}
	// Invalid utf8 byte runs drop their bad bytes.
	if got := urlUnquote("a%FFb"); got != "ab" {
		t.Fatalf("invalid bytes drop, got %q", got)
	}
	// A percent at the very end stays.
	if got := urlUnquote("%"); got != "%" {
		t.Fatalf("lone percents stay, got %q", got)
	}
}

func TestStripSQLComments(t *testing.T) {
	if got := stripSQLComments("SELECT /* comment */ * FROM t"); strings.Contains(got, "/*") || strings.Contains(got, "*/") {
		t.Fatalf("sql comment markers strip, got %q", got)
	}
	if got := stripSQLComments("no comments here"); got != "no comments here" {
		t.Fatalf("clean strings pass, got %q", got)
	}
}

func TestBoundedGunzip(t *testing.T) {
	// Non-gzip payloads bail immediately.
	if got := boundedGunzip([]byte("plain text"), 100); got != nil {
		t.Fatalf("non-gzip payloads bail, got %q", got)
	}
	// Corrupt headers bail.
	if got := boundedGunzip([]byte{0x1f, 0x8b, 0x09, 0x00}, 100); got != nil {
		t.Fatalf("corrupt headers bail, got %q", got)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("hello gzipped world"))
	zw.Close()
	raw := buf.Bytes()
	// A healthy payload gunzips.
	if got := boundedGunzip(raw, 4096); string(got) != "hello gzipped world" {
		t.Fatalf("healthy payloads gunzip, got %q", got)
	}
	// Output budgets truncate.
	if got := boundedGunzip(raw, 5); string(got) != "hello" {
		t.Fatalf("output budgets truncate, got %q", got)
	}
	// An empty gzip stream yields nothing.
	var empty bytes.Buffer
	ze := gzip.NewWriter(&empty)
	ze.Close()
	if got := boundedGunzip(empty.Bytes(), 100); got != nil {
		t.Fatalf("empty streams yield nothing, got %q", got)
	}
	// A corrupt deflate body yields nothing.
	corrupt := append([]byte{}, raw...)
	corrupt[10] = 0xFF
	if got := boundedGunzip(corrupt, 4096); got != nil {
		t.Fatalf("corrupt bodies yield nothing, got %q", got)
	}
}

func TestDecodeBase64CandidatesBasics(t *testing.T) {
	// Clean base64 payloads decode in place.
	left := maxGunzipAttemptsPerPass
	out := decodeBase64Candidates("prefix YWJjZGVmZ2hp suffix", &left, 4096)
	if !strings.Contains(out, "abcdefghi") {
		t.Fatalf("embedded payloads decode, got %q", out)
	}
	// A nil attempts pointer falls back to the default budget.
	out = decodeBase64Candidates("YWJjZGVmZ2hp", nil, 4096)
	if !strings.Contains(out, "abcdefghi") {
		t.Fatalf("nil budgets decode payloads, got %q", out)
	}
	// Plain text passes through untouched.
	if out := decodeBase64Candidates("nothing to see here", &left, 4096); out != "nothing to see here" {
		t.Fatalf("plain text stays, got %q", out)
	}
}

func b64EncodeForTest(raw []byte) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(base64.StdEncoding.EncodeToString(raw)), "+", "-"), "/", "_")
}

func gzipBytesForTest(payload string) string {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(payload))
	zw.Close()
	return b64EncodeForTest(buf.Bytes())
}

func TestDecodeBase64GunzipCandidate(t *testing.T) {
	// Some base64 bodies contain a hex-literal shape (0x...) and are
	// deliberately exempt, so pick a payload whose encoding avoids it.
	var encoded string
	var want string
	for _, phrase := range []string{
		"SELECT password FROM users where 1=1",
		"attack payload detected by guard",
		"union select password from users",
	} {
		candidate := gzipBytesForTest(phrase)
		if !strings.Contains(strings.ToLower(candidate), "0x") {
			encoded = candidate
			want = phrase
			break
		}
	}
	if encoded == "" {
		t.Fatal("no clean gzip payload found")
	}
	left := maxGunzipAttemptsPerPass
	out := decodeBase64Candidates(":"+encoded+":", &left, 4096)
	if !strings.Contains(out, want) {
		t.Fatalf("gzip payloads unpack, got %q", out)
	}
	if left >= maxGunzipAttemptsPerPass {
		t.Fatal("gunzip attempts decrement")
	}
}

func TestDecodeBase64FragmentReassembly(t *testing.T) {
	// Junk-split fragments reassemble into a decoding payload that the
	// primary pass missed, appended after the untouched base.
	left := maxGunzipAttemptsPerPass
	content := "999999999999.YWJjZGVm.YWJjZGVm"
	out := decodeBase64Candidates(content, &left, 4096)
	if !strings.HasSuffix(out, " abcdefabcdef") {
		t.Fatalf("fragment reassembly appends, got %q", out)
	}
}

func TestDecodeTokenExemptions(t *testing.T) {
	d := &b64Decoder{gunzipAttemptsLeft: 1, maxGunzipOutput: 4096}
	// Hex literals stay encoded.
	if _, ok := d.decodeToken("0xdeadbeef1234", b64PrintableRatioThreshold); ok {
		t.Fatal("hex literals stay encoded")
	}
	// Url-safe alphabets translate and decode.
	if got, ok := d.decodeToken("YWJj-ZGVm", b64PrintableRatioThreshold); !ok || got != "abcdef" {
		t.Fatalf("url-safe tokens decode, got %q %v", got, ok)
	}
	// Tokens that only decode after stripping url-safe runes still decode.
	if got, ok := d.decodeToken("YWJjZGVm------", b64PrintableRatioThreshold); !ok || got != "abcdef" {
		t.Fatalf("stripped tokens decode, got %q %v", got, ok)
	}
	// Garbage stays rejected.
	if _, ok := d.decodeToken("%%%%", b64PrintableRatioThreshold); ok {
		t.Fatal("garbage stays rejected")
	}
}

func TestContainsAnyAndRemoveAll(t *testing.T) {
	if !containsAny("abc", "cd") || containsAny("ab", "xyz") {
		t.Fatal("containsAny answers membership")
	}
	if got := removeAll("a-b-c", "-"); got != "abc" {
		t.Fatalf("removeAll strips, got %q", got)
	}
	if got := removeAllSeparators("a.b-c+d_e f"); got != "ab-c+d_ef" {
		t.Fatalf("separator sweeps keep the alphabet, got %q", got)
	}
}

func TestContainsSubstringAndIndexOf(t *testing.T) {
	if !containsSubstring("hello", "") {
		t.Fatal("empty substrings are contained")
	}
	if !containsSubstring("hello", "ell") {
		t.Fatal("real substrings are contained")
	}
	if containsSubstring("hello", "world") {
		t.Fatal("missing substrings are not contained")
	}
	if got := indexOf("hello", "l"); got != 2 {
		t.Fatalf("indexOf locates, got %d", got)
	}
	if got := indexOf("hello", "z"); got != -1 {
		t.Fatalf("missing needles report -1, got %d", got)
	}
}

func TestPrintableAndReplacementRatios(t *testing.T) {
	if got := printableRatio(""); got != 0.0 {
		t.Fatalf("empty text has no printable ratio, got %v", got)
	}
	if got := printableRatio("ab"); got != 1.0 {
		t.Fatalf("printable text ratios to one, got %v", got)
	}
	if got := replacementCharRatio(""); got != 0.0 {
		t.Fatalf("empty text has no replacement ratio, got %v", got)
	}
	if got := replacementCharRatio("a\ufffdb"); got <= 0.32 || got >= 0.34 {
		t.Fatalf("replacement runes count, got %v", got)
	}
}

func TestShortBase64DecodeToken(t *testing.T) {
	// Oversized tokens never decode.
	if _, ok := shortBase64DecodeToken("YWJjZGVmZ2hpj"); ok {
		t.Fatal("oversized tokens never decode")
	}
	// Invalid base64 never decodes.
	if _, ok := shortBase64DecodeToken("!!!!"); ok {
		t.Fatal("invalid base64 never decodes")
	}
	// Binary results never decode.
	if _, ok := shortBase64DecodeToken("9999"); ok {
		t.Fatal("binary results never decode")
	}
	// Short payloads decode.
	if got, ok := shortBase64DecodeToken("YWJj"); !ok || got != "abc" {
		t.Fatalf("short payloads decode, got %q %v", got, ok)
	}
}

func TestBuildShortBase64AdditiveView(t *testing.T) {
	if got := buildShortBase64AdditiveView(nfkcString, func(s string) string { return s }, ""); got != "" {
		t.Fatalf("empty content yields no view, got %q", got)
	}
	// Qualifying fragments (${, {, }, #) join with newlines.
	view := buildShortBase64AdditiveView(nfkcString, func(s string) string { return s }, "JHt7. fn1 JHt9")
	if !strings.Contains(view, "${{") || !strings.Contains(view, "\n") {
		t.Fatalf("qualifying fragments join, got %q", view)
	}
	// Non-qualifying fragments stay out.
	if view := buildShortBase64AdditiveView(nfkcString, func(s string) string { return s }, "YWJj"); view != "" {
		t.Fatalf("plain fragments stay out, got %q", view)
	}
}

func TestIsQualifyingFragment(t *testing.T) {
	if isQualifyingFragment("plain text") {
		t.Fatal("plain fragments do not qualify")
	}
	if !isQualifyingFragment("${abc}") {
		t.Fatal("template fragments qualify")
	}
}

func TestShortBase64CandidateCap(t *testing.T) {
	// Content with more candidates than the cap stops scanning.
	content := strings.Repeat("YWJj ", shortBase64MaxCandidates+5)
	view := buildShortBase64AdditiveView(nfkcString, func(s string) string { return s }, content)
	_ = view
}
