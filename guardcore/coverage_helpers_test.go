package guardcore

// Coverage tests for small pure helpers across the detection engine.

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPrintableIslandRune(t *testing.T) {
	accept := []rune{'\t', '\n', '\r', 'a', '~', 0x20, 0x7e, 0xa1, 0xd7ff, 0xe000, 0xfffc, 0xfffe, 0xffff, 0x10000, 0x10ffff}
	for _, r := range accept {
		if !printableIslandRune(r) {
			t.Fatalf("rune %#x must be island-printable", r)
		}
	}
	reject := []rune{0x00, 0x1f, 0x7f, 0xa0, 0xd800, 0xfffd, 0xfffd}
	for _, r := range reject {
		if printableIslandRune(r) {
			t.Fatalf("rune %#x must not be island-printable", r)
		}
	}
}

func TestMatchIsBinaryDense(t *testing.T) {
	var nilPrefix binaryPrefix
	if nilPrefix.matchIsBinaryDense(0, 1) {
		t.Fatal("a nil prefix disables the gate")
	}
	// binaryPrefix carries cumulative artifact counts: the gate compares
	// bp[high]-bp[low] against the density limit.
	dense := binaryPrefix(make([]int32, 140))
	for i := 3; i < 140; i++ {
		dense[i] = 4
	}
	if !dense.matchIsBinaryDense(66, 67) {
		t.Fatal("a dense window must trip the gate")
	}
	sparse := binaryPrefix(make([]int32, 140))
	if sparse.matchIsBinaryDense(66, 67) {
		t.Fatal("a sparse window must pass the gate")
	}
	// Window bounds clamp at the slice edges.
	edge := binaryPrefix(make([]int32, 140))
	for i := 1; i <= 66; i++ {
		edge[i] = 4
	}
	if !edge.matchIsBinaryDense(0, 1) {
		t.Fatal("edge windows clamp at zero")
	}
	if edge.matchIsBinaryDense(100, 101) {
		t.Fatal("edge windows clamp at the end")
	}
}

func TestCanonicalIPText(t *testing.T) {
	v4 := netip.MustParseAddr("10.1.2.3")
	if got := canonicalIPText(v4); got != "10.1.2.3" {
		t.Fatalf("plain v4 passes through, got %q", got)
	}
	mapped := netip.AddrFrom16(v4.As16()).WithZone("")
	if !mapped.Is4In6() {
		t.Fatal("the 16-byte form of a v4 must be 4-in-6")
	}
	if got := canonicalIPText(mapped); got != "10.1.2.3" {
		t.Fatalf("4-in-6 addresses unmap, got %q", got)
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	if got := canonicalIPText(v6); got != "2001:db8::1" {
		t.Fatalf("plain v6 passes through, got %q", got)
	}
	zoned := netip.MustParseAddr("fe80::1%eth0")
	if got := canonicalIPText(zoned); !strings.Contains(got, "%eth0") {
		t.Fatalf("zoned addresses keep their zone, got %q", got)
	}
}

func TestHexValue(t *testing.T) {
	if hexValue('0') != 0 || hexValue('9') != 9 || hexValue('A') != 10 || hexValue('F') != 15 || hexValue('a') != 10 || hexValue('f') != 15 {
		t.Fatal("hex digits must decode")
	}
}

func TestGoQuoteMeta(t *testing.T) {
	if got := goQuoteMeta("a.b*c"); got != `a\.b\*c` {
		t.Fatalf("metacharacters escape, got %q", got)
	}
	if got := goQuoteMeta("ab/"); got != `ab\/` {
		t.Fatalf("slashes escape too, got %q", got)
	}
	if got := goQuoteMeta("plain"); got != "plain" {
		t.Fatalf("plain text passes through, got %q", got)
	}
}

func TestNormalizeContextAndSplitFirst(t *testing.T) {
	if got := normalizeContext(""); got != "unknown" {
		t.Fatalf("empty contexts normalize to unknown, got %q", got)
	}
	if got := normalizeContext("url_path"); got != "url_path" {
		t.Fatalf("known contexts pass through, got %q", got)
	}
	if got := normalizeContext("url_path:junk"); got != "url_path" {
		t.Fatalf("context suffixes split off, got %q", got)
	}
	if got := normalizeContext("made_up_context"); got != "unknown" {
		t.Fatalf("unknown contexts normalize, got %q", got)
	}
	if got := splitFirst("a:b:c"); got != "a" {
		t.Fatalf("splitFirst takes the first segment, got %q", got)
	}
	if got := splitFirst("nocolon"); got != "nocolon" {
		t.Fatalf("strings without colons pass through, got %q", got)
	}
}

func TestIsASCIIdigits(t *testing.T) {
	if isASCIIdigits("") {
		t.Fatal("empty strings are not digits")
	}
	if !isASCIIdigits("12345") {
		t.Fatal("digits pass")
	}
	if isASCIIdigits("12a45") {
		t.Fatal("letters fail")
	}
}

func TestEngineHelpersStripForwardedEntryPort(t *testing.T) {
	cases := [][2]string{
		{"203.0.113.9:4711", "203.0.113.9"},
		{"203.0.113.9", "203.0.113.9"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[broken", "[broken"},
		{"[x]:notaport", "[x]:notaport"},
		{"a:b:c", "a:b:c"},
		{"host:", "host:"},
	}
	for _, tc := range cases {
		if got := stripForwardedEntryPort(tc[0]); got != tc[1] {
			t.Fatalf("stripForwardedEntryPort(%q) = %q, want %q", tc[0], got, tc[1])
		}
	}
}

func TestRuneSliceString(t *testing.T) {
	rs := []rune("hello")
	if got := runeSliceString(rs, 1, 3); got != "el" {
		t.Fatalf("slices take the range, got %q", got)
	}
	if got := runeSliceString(rs, -2, 99); got != "hello" {
		t.Fatalf("bounds clamp, got %q", got)
	}
}

func TestTemplateRuneHelpers(t *testing.T) {
	rs := []rune("hello world")
	if got := indexOfRuneSeq(rs, []rune("world"), 0); got != 6 {
		t.Fatalf("sequences are found, got %d", got)
	}
	if got := indexOfRuneSeq(rs, []rune("nope"), 0); got != -1 {
		t.Fatalf("missing sequences report -1, got %d", got)
	}
	if got := indexOfRuneSeq(rs, []rune("o"), 5); got != 7 {
		t.Fatalf("searches start at the offset, got %d", got)
	}
	if got := indexOfRune(rs, 'o', 5); got != 7 {
		t.Fatalf("single runes search from the offset, got %d", got)
	}
	if got := indexOfRune(rs, 'z', 0); got != -1 {
		t.Fatalf("missing runes report -1, got %d", got)
	}
	if got := lastIndexOfRuneFrom(rs, 'o', len(rs)); got != 7 {
		t.Fatalf("backwards searches find the last, got %d", got)
	}
	if got := lastIndexOfRuneFrom(rs, 'o', 6); got != 4 {
		t.Fatalf("backwards searches respect the bound, got %d", got)
	}
	if got := lastIndexOfRuneFrom(rs, 'z', len(rs)); got != -1 {
		t.Fatalf("missing runes report -1, got %d", got)
	}
	if !startsWithRuneSeq(rs, []rune("hello"), 0) {
		t.Fatal("prefixes match at zero")
	}
	if !startsWithRuneSeq(rs, []rune("world"), 6) {
		t.Fatal("prefixes match at offsets")
	}
	if startsWithRuneSeq(rs, []rune("world!"), 6) {
		t.Fatal("overruning sequences fail")
	}
	if startsWithRuneSeq(rs, []rune("ell"), 2) {
		t.Fatal("mismatched sequences fail")
	}
}

func TestHeadersDeleteLen(t *testing.T) {
	headers := NewHeaders()
	headers.Set("X-Test", "1")
	headers.Set("X-Other", "2")
	if headers.Len() != 2 {
		t.Fatalf("length counts entries, got %d", headers.Len())
	}
	headers.Delete("x-test")
	if headers.Len() != 1 {
		t.Fatal("delete is case-insensitive")
	}
	if _, ok := headers.Get("X-Test"); ok {
		t.Fatal("the deleted entry is gone")
	}
}

func TestGuardRequestAccessors(t *testing.T) {
	req := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Method = "post"
		opts.RawQuery = "a=1&b=2"
		opts.Body = []byte("payload")
	})
	if req.Method() != "POST" {
		t.Fatalf("methods uppercase, got %q", req.Method())
	}
	if !strings.HasPrefix(req.URLFull(), "http://example.com/api") {
		t.Fatalf("full urls compose, got %q", req.URLFull())
	}
	if replaced := req.URLReplaceScheme("https"); !strings.HasPrefix(replaced, "https://") {
		t.Fatalf("scheme replacement works, got %q", replaced)
	}
	if full := req.URLFull(); req.URLReplaceScheme("") != full {
		t.Fatal("empty scheme replacement is a no-op")
	}
	params := req.QueryParams()
	if params["a"] != "1" || params["b"] != "2" {
		t.Fatalf("raw queries parse, got %v", params)
	}
	body, err := req.Body()
	if err != nil || string(body) != "payload" {
		t.Fatalf("bodies read once, got %q %v", body, err)
	}
	// A second read replays the cached body.
	body, err = req.Body()
	if err != nil || string(body) != "payload" {
		t.Fatalf("cached bodies replay, got %q %v", body, err)
	}
	// A request with neither method nor query falls back to defaults.
	bare := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Method = ""
	})
	if bare.Method() != "GET" {
		t.Fatalf("empty methods default to GET, got %q", bare.Method())
	}
	if params := bare.QueryParams(); len(params) != 0 {
		t.Fatalf("missing queries yield no params, got %v", params)
	}
	if schemeless := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) { opts.Scheme = "" }); strings.HasPrefix(schemeless.URLFull(), "http://") == false {
		t.Fatal("missing schemes default to http")
	}
	// A BodyFunc-supplied body reads through the hook.
	dynamic := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Body = nil
		opts.BodyFunc = func() ([]byte, error) { return []byte("dynamic"), nil }
	})
	got, err := dynamic.Body()
	if err != nil || string(got) != "dynamic" {
		t.Fatalf("body funcs supply the payload, got %q %v", got, err)
	}
	// State lazily creates the request state.
	empty := &guardRequest{}
	if empty.State() == nil {
		t.Fatal("state lazily initializes")
	}
}

func TestResponseSetHeaderCreatesMap(t *testing.T) {
	resp := &Response{}
	resp.SetHeader("X-A", "1")
	resp.SetHeader("X-B", "2")
	if resp.Headers["X-A"] != "1" || resp.Headers["X-B"] != "2" {
		t.Fatalf("set initializes the header map, got %v", resp.Headers)
	}
}
