package guardcore

// Coverage tests for small helper surfaces: the scan window iterator,
// route config lookups, request query parsing, canonical IP text and the
// CORS response header builder.

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBoundedFinditer(t *testing.T) {
	re := mustCompile(`\w+`, 0, windowTimeout)
	bound := scanBound{
		prefix: mustCompile(`\w+`, 0, windowTimeout),
		term:   mustCompile(`>`, 0, windowTimeout),
	}
	// Candidates inside the window match in order.
	t1 := newScanText("ab> cd>")
	got := boundedFinditer(re, t1, bound)
	if len(got) != 2 || got[0].text() != "ab" || got[1].text() != "cd" {
		t.Fatalf("in-window candidates match in order, got %v", got)
	}
	// Candidates opening after the last terminator are out of the window.
	t2 := newScanText("word > tail")
	got = boundedFinditer(re, t2, bound)
	if len(got) != 1 || got[0].text() != "word" {
		t.Fatalf("post-window candidates are dropped, got %v", got)
	}
	// Zero-length matches advance the scan by one rune.
	re0 := mustCompile(`y*`, 0, windowTimeout)
	bound0 := scanBound{
		prefix: mustCompile(`z`, 0, windowTimeout),
		term:   mustCompile(`>`, 0, windowTimeout),
	}
	t3 := newScanText("zz>z")
	got = boundedFinditer(re0, t3, bound0)
	if len(got) != 2 || got[0].text() != "" || got[1].text() != "" {
		t.Fatalf("zero-length matches yield empty hits, got %d", len(got))
	}
	// Missing terminators or prefixes bail out.
	emptyBound := scanBound{prefix: bound.prefix, term: mustCompile(`\znothing`, 0, windowTimeout)}
	if got := boundedFinditer(re, t1, emptyBound); got != nil {
		t.Fatalf("missing terminators yield nothing, got %v", got)
	}
	noPrefix := scanBound{prefix: mustCompile(`\znothing`, 0, windowTimeout), term: bound.term}
	if got := boundedFinditer(re, t1, noPrefix); got != nil {
		t.Fatalf("missing prefixes yield nothing, got %v", got)
	}
}

func TestRuneSliceStringEmptyWindow(t *testing.T) {
	rs := []rune("hello")
	if got := runeSliceString(rs, 3, 1); got != "" {
		t.Fatalf("inverted windows are empty, got %q", got)
	}
	if got := runeSliceString(rs, 5, 5); got != "" {
		t.Fatalf("empty windows are empty, got %q", got)
	}
}

func TestRequiredHeadersLookup(t *testing.T) {
	headers := RequiredHeaders{
		{Name: "X-Api-Version", Value: "2"},
		{Name: "X-Tenant", Value: "acme"},
	}
	if got, ok := headers.Lookup("X-Tenant"); !ok || got != "acme" {
		t.Fatalf("known headers resolve, got %q %v", got, ok)
	}
	if got, ok := headers.Lookup("X-Missing"); ok || got != "" {
		t.Fatalf("unknown headers miss, got %q %v", got, ok)
	}
	if got, ok := (RequiredHeaders)(nil).Lookup("X-Any"); ok || got != "" {
		t.Fatalf("empty header sets miss, got %q %v", got, ok)
	}
}

func TestRouteRegistryNilReceiverConfigs(t *testing.T) {
	var registry *RouteRegistry
	if got := registry.RouteConfigs(); got != nil {
		t.Fatalf("nil registries expose no configs, got %v", got)
	}
}

func TestQueryParamsParseFailureYieldsEmpty(t *testing.T) {
	req := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.RawQuery = "%zz=1"
	})
	if params := req.QueryParams(); len(params) != 0 {
		t.Fatalf("unparseable queries yield no params, got %v", params)
	}
}

func TestCanonicalIPTextMappedWithZone(t *testing.T) {
	addr, err := netip.ParseAddr("::ffff:10.1.2.3%eth0")
	if err != nil {
		t.Fatalf("mapped zoned addresses parse: %v", err)
	}
	if !addr.Is4In6() || addr.Zone() == "" {
		t.Fatalf("test address must be mapped and zoned, got %v", addr)
	}
	got := canonicalIPText(addr)
	if !strings.HasPrefix(got, "::ffff:") || !strings.HasSuffix(got, "%eth0") {
		t.Fatalf("mapped zoned addresses keep their form, got %q", got)
	}
}

func TestCORSBuildResponseHeadersBranches(t *testing.T) {
	policy := &CORSPolicy{
		allowOrigins:     map[string]bool{"https://good.example": true},
		allowMethods:     []string{"GET", "POST"},
		allowHeaders:     []string{"content-type"},
		allowCredentials: true,
		exposeHeaders:    []string{"X-Request-Id"},
	}
	headers := NewHeaders()
	headers.Set("Origin", "https://evil.example")
	if got := policy.buildResponseHeaders(headers); got != nil {
		t.Fatalf("disallowed origins get no cors headers, got %v", got)
	}

	headers = NewHeaders()
	headers.Set("Origin", "https://good.example")
	got := policy.buildResponseHeaders(headers)
	if got == nil {
		t.Fatal("allowed origins get cors headers")
	}
	if got["Access-Control-Allow-Origin"] != "https://good.example" {
		t.Fatalf("allowed origins echo, got %v", got)
	}
	if got["Access-Control-Allow-Credentials"] != "true" {
		t.Fatalf("credential policies flag themselves, got %v", got)
	}
	if got["Access-Control-Expose-Headers"] != "X-Request-Id" {
		t.Fatalf("exposed headers list, got %v", got)
	}
	if got["Access-Control-Max-Age"] != "3600" {
		t.Fatalf("max age is fixed at 3600, got %v", got)
	}

	// Empty origin values behave like a missing origin.
	headers = NewHeaders()
	headers.Set("Origin", "")
	if got := policy.buildResponseHeaders(headers); got != nil {
		t.Fatalf("empty origins get no cors headers, got %v", got)
	}

	// Injecting onto a response composes onto the existing header set.
	resp := &Response{}
	headers = NewHeaders()
	headers.Set("Origin", "https://good.example")
	policy.injectResponseHeaders(resp, headers)
	if resp.Headers["Access-Control-Allow-Origin"] != "https://good.example" {
		t.Fatalf("injection composes headers, got %v", resp.Headers)
	}
}
