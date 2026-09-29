package guardcore

// Coverage tests for the template/SSTI detectors (templates.go).

import (
	"strings"
	"testing"
)

func TestTemplateRegionsUnclosed(t *testing.T) {
	// An opening with no closing barrier terminates the region sweep.
	if got := templateRegions(newScanText("{{ unclosed"), "{{", "}}"); len(got) != 0 {
		t.Fatalf("unclosed templates yield no regions, got %v", got)
	}
	// Regions never overlap: the cursor advances past each barrier.
	t1 := newScanText("{{a}}{{b}}")
	got := templateRegions(t1, "{{", "}}")
	if len(got) != 2 || got[0].start != 0 || got[1].start != 5 {
		t.Fatalf("adjacent regions split, got %v", got)
	}
}

func TestRuneSearchNegativeOffsets(t *testing.T) {
	rs := []rune("abcabc")
	// Negative offsets clamp to zero.
	if got := indexOfRuneSeq(rs, []rune("abc"), -5); got != 0 {
		t.Fatalf("negative offsets clamp, got %d", got)
	}
	if got := indexOfRune(rs, 'b', -5); got != 1 {
		t.Fatalf("negative offsets clamp, got %d", got)
	}
	// Bound clamps above the length behave like the length.
	if got := lastIndexOfRuneFrom(rs, 'c', 99); got != 5 {
		t.Fatalf("oversized bounds clamp, got %d", got)
	}
}

func TestTemplateKeywordMatches(t *testing.T) {
	// A keyword call at the end of a curly body matches its frame.
	t1 := newScanText("prefix {{ request eval }} suffix")
	got := templateKeywordMatches(t1, "{{", "}}")
	if len(got) != 1 || got[0].text() != "{{ request eval }}" {
		t.Fatalf("keyword bodies match their frame, got %v", got)
	}
	// Bodies without keywords are skipped.
	if got := templateKeywordMatches(newScanText("{{ harmless }}"), "{{", "}}"); len(got) != 0 {
		t.Fatalf("keywordless bodies must not match, got %v", got)
	}
	// The percent-brace flavor shares the same sweep.
	t2 := newScanText("{% id system %}")
	got = templateKeywordMatches(t2, "{%", "%}")
	if len(got) != 1 || got[0].text() != "{% id system %}" {
		t.Fatalf("percent keyword bodies match, got %v", got)
	}
}

func TestTemplateAfterDates(t *testing.T) {
	// A date inside the region anchors the scan at the next opening.
	t1 := newScanText("{{ 2024-05-01 {{ 1+2 }}")
	if got := templateAfterDates(t1, "{{", 0, 21); got != 14 {
		t.Fatalf("dates re-anchor to the next opening, got %d", got)
	}
	// Regions without dates keep the original start.
	t2 := newScanText("{{ 1+2 }}")
	if got := templateAfterDates(t2, "{{", 0, 7); got != 0 {
		t.Fatalf("dateless regions keep their start, got %d", got)
	}
}

func TestTemplateExpressionMatches(t *testing.T) {
	cases := []struct {
		kind  string
		input string
		want  string
	}{
		{"dollar", "${system('id')}", "${system('id')}"},
		{"curly", "{{ compute(42 * 3) }}", "{{ compute(42 * 3) }}"},
		{"hash", "#{exec(cmd)}", "#{exec(cmd)}"},
		{"asp", "<% eval(request) %>", "<% eval(request) %>"},
	}
	for _, tc := range cases {
		got := templateExpressionMatches(newScanText(tc.input), tc.kind)
		if len(got) != 1 || got[0].text() != tc.want {
			t.Fatalf("kind %s on %q: got %v want %q", tc.kind, tc.input, got, tc.want)
		}
	}
	// A date-prefixed curly region re-anchors to the inner opening before
	// matching.
	t1 := newScanText("{{ 2024-05-01 {{ 7 * 6 }}")
	got := templateExpressionMatches(t1, "curly")
	if len(got) != 1 {
		t.Fatalf("date-anchored curly regions match once, got %v", got)
	}
	// An inner opening that never re-appears after the date is skipped.
	if got := templateExpressionMatches(newScanText("{{ 2024-05-01 7 * 6 }}"), "curly"); len(got) != 0 {
		t.Fatalf("dangling date anchors must not match, got %v", got)
	}
	// Bodies without indicators are skipped.
	if got := templateExpressionMatches(newScanText("${ friendly }"), "dollar"); len(got) != 0 {
		t.Fatalf("indicatorless bodies must not match, got %v", got)
	}
	// Overlapping candidates advance past the first accepted frame.
	t2 := newScanText("${a(1)}${b(2)}")
	if got := templateExpressionMatches(t2, "dollar"); len(got) != 2 {
		t.Fatalf("sequential expressions match individually, got %d", len(got))
	}
}

func TestTemplateFrameQuoting(t *testing.T) {
	// Regex metacharacters in the delimiters are quoted, not interpreted.
	t1 := newScanText("a.b*eval(x)*c")
	got, ok := templateFrame(t1, "a.b*", "*c", 0, t1.n)
	if !ok || got.text() != "a.b*eval(x)*c" {
		t.Fatalf("metacharacter delimiters quote cleanly, got %q %v", got.text(), ok)
	}
	// A frame that never closes does not match.
	if _, ok := templateFrame(newScanText("a.b*eval"), "a.b*", "*c", 0, 8); ok {
		t.Fatal("unclosed frames do not match")
	}
}

func TestAppendRuneQuotedMeta(t *testing.T) {
	metas := `\.+*?()|[]{}^$/-`
	for _, r := range metas {
		got := string(appendRuneQuoted(nil, r))
		if got != `\`+string(r) {
			t.Fatalf("meta rune %q must escape, got %q", r, got)
		}
	}
	if got := string(appendRuneQuoted(nil, 'a')); got != "a" {
		t.Fatalf("plain runes pass through, got %q", got)
	}
	// Every escaped rune set survives a round-trip through compileRE.
	var b []rune
	for _, r := range metas {
		b = appendRuneQuoted(b, r)
	}
	if _, err := compileRE(string(b), 0, templateTimeout); err != nil {
		t.Fatalf("quoted metas must compile, got %v", err)
	}
	if !strings.Contains(string(b), `\-`) {
		t.Fatal("dashes escape too")
	}
}
