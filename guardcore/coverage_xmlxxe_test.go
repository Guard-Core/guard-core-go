package guardcore

// Coverage tests for the XML/XXE windowed detectors (xmlxxe.go). The
// finditer helpers mirror Python's regex-driven scans, so every branch is
// exercised with hand-built DTD payloads.

import (
	"reflect"
	"testing"
)

func TestFirstAtOrAfter(t *testing.T) {
	got, ok := firstAtOrAfter([]int{2, 5, 9}, 5)
	if !ok || got != 5 {
		t.Fatalf("exact hit must return the value, got %d %v", got, ok)
	}
	got, ok = firstAtOrAfter([]int{2, 5, 9}, 6)
	if !ok || got != 9 {
		t.Fatalf("floor between entries must round up, got %d %v", got, ok)
	}
	got, ok = firstAtOrAfter(nil, 0)
	if ok || got != 0 {
		t.Fatalf("empty slices find nothing, got %d %v", got, ok)
	}
	got, ok = firstAtOrAfter([]int{1, 2}, 10)
	if ok || got != 0 {
		t.Fatalf("floors past the end find nothing, got %d %v", got, ok)
	}
}

func TestXMLInternalEntityFinditer(t *testing.T) {
	// A DOCTYPE with an internal subset containing an ENTITY is flagged.
	t1 := newScanText("<!DOCTYPE x [<!ENTITY a SYSTEM \"b\">]>")
	got := xmlInternalEntityFinditer(t1)
	if len(got) != 1 {
		t.Fatalf("internal entity DTD must match once, got %v", got)
	}
	if want := "<!DOCTYPE x [<!ENTITY"; got[0].text() != want {
		t.Fatalf("match spans the doctype through the entity, got %q want %q", got[0].text(), want)
	}
	// DOCTYPE without an internal subset (no bracket boundary) is ignored.
	if got := xmlInternalEntityFinditer(newScanText("<!DOCTYPE x >tail")); len(got) != 0 {
		t.Fatalf("external doctypes must not match, got %v", got)
	}
	// Internal subset without an entity is ignored.
	if got := xmlInternalEntityFinditer(newScanText("<!DOCTYPE x [foo")); len(got) != 0 {
		t.Fatalf("subsets without entities must not match, got %v", got)
	}
	// The entity search keeps earlier matches when a later doctype's
	// subset runs out.
	t2 := newScanText("<!DOCTYPE [<!ENTITY a>]><!DOCTYPE y [z")
	got = xmlInternalEntityFinditer(t2)
	if len(got) != 1 {
		t.Fatalf("earlier matches survive a later unmatched subset, got %d", len(got))
	}
	// A doctype opening inside the previous boundary search's span is
	// consumed by that span.
	t4 := newScanText("<!DOCTYPE x<!DOCTYPE y [<!ENTITY a>]>")
	got = xmlInternalEntityFinditer(t4)
	if len(got) != 1 || got[0].start() != 0 {
		t.Fatalf("nested doctypes fold into the outer span, got %d matches", len(got))
	}
	// The boundary search stops with earlier matches intact.
	t3 := newScanText("<!DOCTYPE [<!ENTITY a>]><!DOCTYPE y")
	got = xmlInternalEntityFinditer(t3)
	if len(got) != 1 {
		t.Fatalf("earlier matches survive an unterminated doctype, got %d", len(got))
	}
	// No doctype at all.
	if got := xmlInternalEntityFinditer(newScanText("<!ENTITY a>")); len(got) != 0 {
		t.Fatalf("entities without doctypes must not match, got %v", got)
	}
}

func TestXMLQuotedURLEnd(t *testing.T) {
	class12 := func(t scanText) []int {
		var out []int
		for _, m := range findAllMatches(xmlClass12RE, t) {
			out = append(out, m.start())
		}
		return out
	}
	class3 := func(t scanText) []int {
		var out []int
		for _, m := range findAllMatches(xmlClass3RE, t) {
			out = append(out, m.start())
		}
		return out
	}
	// A quoted URL closed by a quote then an angle bracket resolves.
	t1 := newScanText("x\"http://a.b/c\">")
	final, ok := xmlQuotedURLEnd(t1, 9, class12(t1), class3(t1))
	if !ok || final != 15 {
		t.Fatalf("quoted url ends at the bracket, got %d %v", final, ok)
	}
	// No closing quote at all.
	t2 := newScanText("x\"http://a.b/c")
	if _, ok := xmlQuotedURLEnd(t2, 9, class12(t2), class3(t2)); ok {
		t.Fatal("unclosed urls do not resolve")
	}
	// The quote sits exactly at the scheme end (empty URL).
	t3 := newScanText("x\"http://\"")
	if _, ok := xmlQuotedURLEnd(t3, 9, class12(t3), class3(t3)); ok {
		t.Fatal("empty quoted urls do not resolve")
	}
	// The next class-3 rune is the angle bracket itself.
	t4 := newScanText("x\"http://a>")
	if _, ok := xmlQuotedURLEnd(t4, 9, class12(t4), class3(t4)); ok {
		t.Fatal("bracket-terminated urls do not resolve")
	}
	// Closing quote but no bracket afterwards.
	t5 := newScanText("x\"http://a.b\"")
	if _, ok := xmlQuotedURLEnd(t5, 9, class12(t5), class3(t5)); ok {
		t.Fatal("urls without trailing brackets do not resolve")
	}
	// The bracket after the closing quote is an internal-subset opener.
	t6 := newScanText("x\"http://a\"[")
	if _, ok := xmlQuotedURLEnd(t6, 9, class12(t6), class3(t6)); ok {
		t.Fatal("subset-opened urls do not resolve")
	}
}

func TestXMLSchemeCompletionEnd(t *testing.T) {
	classes := func(t scanText) ([]int, []int) {
		var class12, class3 []int
		for _, m := range findAllMatches(xmlClass12RE, t) {
			class12 = append(class12, m.start())
		}
		for _, m := range findAllMatches(xmlClass3RE, t) {
			class3 = append(class3, m.start())
		}
		return class12, class3
	}
	// Scheme start at position zero is rejected outright.
	t1 := newScanText("http://a.b\"n")
	if end, ok := xmlSchemeCompletionEnd(t1, 0, nil, nil); ok || end != 0 {
		t.Fatal("zero offsets do not resolve")
	}
	// The rune before the scheme must be a quote.
	t2 := newScanText("zhttp://a.b")
	if end, ok := xmlSchemeCompletionEnd(t2, 1, nil, nil); ok || end != 0 {
		t.Fatal("unquoted schemes do not resolve")
	}
	// The scheme regex must anchor exactly at the offset.
	t3 := newScanText("\"ftp://a.b\"")
	if end, ok := xmlSchemeCompletionEnd(t3, 1, nil, nil); ok || end != 0 {
		t.Fatal("non-http schemes do not resolve")
	}
	// w3.org URLs are deliberately exempted.
	t4 := newScanText("\"http://www.w3.org/2001\">")
	c12, c3 := classes(t4)
	if end, ok := xmlSchemeCompletionEnd(t4, 1, c12, c3); ok || end != 0 {
		t.Fatal("w3.org schemes must not resolve")
	}
	// A fully quoted http URL with a closing bracket resolves.
	t5 := newScanText("\"http://a.b/c\">")
	c12, c3 = classes(t5)
	end, ok := xmlSchemeCompletionEnd(t5, 1, c12, c3)
	if !ok || end != 14 {
		t.Fatalf("complete schemes resolve to the bracket, got %d %v", end, ok)
	}
}

func xmlPublicDTDCase(t *testing.T, input string, wantSpans [][2]string) {
	t.Helper()
	got := xmlPublicExternalDTDFinditer(newScanText(input))
	if len(got) != len(wantSpans) {
		t.Fatalf("input %q: got %d matches (%v), want %d", input, len(got), got, len(wantSpans))
	}
	for i, want := range wantSpans {
		if got[i].text() != want[0] {
			t.Fatalf("input %q: match %d = %q, want %q", input, i, got[i].text(), want[0])
		}
		if got[i].start() < 0 {
			t.Fatalf("input %q: match %d has negative start", input, i)
		}
	}
}

func TestXMLPublicExternalDTDFinditer(t *testing.T) {
	// Missing doctype or PUBLIC keywords bail out early.
	xmlPublicDTDCase(t, "<!DOCTYPE html>", nil)
	xmlPublicDTDCase(t, "PUBLIC \"x\" \"http://a.b/c\">", nil)
	// Doctype + PUBLIC but no http URL to complete.
	xmlPublicDTDCase(t, "<!DOCTYPE a PUBLIC \"b\">", nil)
	// The canonical external DTD probe matches once.
	xmlPublicDTDCase(t, "<!DOCTYPE html PUBLIC \"-//a//b\" \"http://x.y/z\">",
		[][2]string{{`<!DOCTYPE html PUBLIC "-//a//b" "http://x.y/z">`, ""}})
	// A scheme whose completion fails (no closing bracket) yields nothing.
	xmlPublicDTDCase(t, "<!DOCTYPE a PUBLIC \"b\" \"http://x.y/z\"", nil)
	// A second PUBLIC inside the first match's span is consumed.
	xmlPublicDTDCase(t, "<!DOCTYPE a PUBLIC \"b\" \"http://x.y/z\" PUBLIC \"f\">",
		[][2]string{{`<!DOCTYPE a PUBLIC "b" "http://x.y/z" PUBLIC "f">`, ""}})
	// A PUBLIC directly adjacent to DOCTYPE is too close to be a DTD probe.
	xmlPublicDTDCase(t, "<!DOCTYPEPUBLIC \"b\" \"http://x.y/z\">", nil)
	// A PUBLIC whose run was opened before the doctype is ignored.
	xmlPublicDTDCase(t, "x\"http://c.d/e\"> <!DOCTYPE a PUBLIC \"y\">", nil)
	// A completed quote living outside the PUBLIC's run is ignored.
	xmlPublicDTDCase(t, "<!DOCTYPE a PUBLIC \"b\" [\"http://c.d/e\"]>", nil)
	// A doctype inside the same bracket run as the PUBLIC still matches.
	xmlPublicDTDCase(t, "x[<!DOCTYPE a PUBLIC \"b\" \"http://c.d/e\">",
		[][2]string{{`<!DOCTYPE a PUBLIC "b" "http://c.d/e">`, ""}})
}

func TestXMLPublicExternalDTDMatchSpans(t *testing.T) {
	// The reported match spans from the doctype start through the final
	// bracket of the completed scheme URL.
	t1 := newScanText(`<!DOCTYPE html PUBLIC "-//a//b" "http://x.y/z">`)
	got := xmlPublicExternalDTDFinditer(t1)
	if len(got) != 1 {
		t.Fatalf("expected one match, got %v", got)
	}
	if got[0].start() != 0 || got[0].end() != t1.n {
		t.Fatalf("span covers the whole declaration, got [%d,%d) n=%d", got[0].start(), got[0].end(), t1.n)
	}
	if !reflect.DeepEqual(got[0].runes(), t1.rs) {
		t.Fatal("matches carry the scanned runes")
	}
}
