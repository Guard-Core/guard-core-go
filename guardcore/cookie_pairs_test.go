package guardcore

import (
	"reflect"
	"testing"
)

// mixedCookiePair is one cookie pair that carries both regex and semantic
// threats, to prove the semantic opt-out applies per pair while regex scans.
const mixedCookiePair = "${x} <t> (y) [z] {w} a://b c://d <b>call(f(x))</b> union select concat(database(),table_name) from information_schema.tables where 1=1 {{render(jinja(template(mustache(handlebars(ejs(pug(twig)))))))}}"

func TestSplitCookieHeader(t *testing.T) {
	got := splitCookieHeader("a=1;  b=2;;\r\nc=3; ")
	want := []string{"a=1", "b=2", "\r\nc=3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pairs: got %q want %q", got, want)
	}
}

func TestSessionCookieHeaderIsNotFlagged(t *testing.T) {
	cfg := newDetectConfig(t, nil)
	if r := Detect(sessionCookieHeader(), "203.0.113.7", "header"); !r.IsThreat || r.ThreatScore < 0.7 {
		t.Fatalf("control: the unsplit header must reproduce the 0.711 score, got %v %.3f", r.IsThreat, r.ThreatScore)
	}
	if semanticScanFired(t, cfg, nil, map[string]string{"cookie": sessionCookieHeader()}) {
		t.Fatal("a logged-in Cookie header must not be flagged: each pair scans on its own")
	}
	if !semanticScanFired(t, cfg, nil, map[string]string{"x-session": sessionCookieHeader()}) {
		t.Fatal("control: the same value in a non-Cookie header keeps scanning as one value")
	}
}

func TestAttackInOneCookieIsStillDetected(t *testing.T) {
	cfg := newDetectConfig(t, nil)
	for name, tc := range map[string]struct{ cookie, category string }{
		"xss":  {"theme=dark; q=<script>alert(1)</script>", "xss"},
		"sqli": {"theme=dark; id=1' OR 1=1--", "sqli"},
		"crlf": {"theme=dark;\r\nSet-Cookie: admin=1", "http_split"},
	} {
		categories := runDetectThreatHeaders(t, cfg, map[string]string{"Cookie": tc.cookie})
		if !containsString(categories, tc.category) {
			t.Fatalf("%s: attack in one cookie must still detect %s, got %v", name, tc.category, categories)
		}
	}
}

func TestSemanticExclusionAppliesToEachCookiePair(t *testing.T) {
	header := map[string]string{"cookie": "theme=dark; " + mixedCookiePair}
	regex, semantic := scanThreatCounts(t, newDetectConfig(t, nil), nil, header)
	if regex == 0 || semantic == 0 {
		t.Fatalf("control: the pair must trip both analyzers, got regex=%d semantic=%d", regex, semantic)
	}
	cfg := newDetectConfig(t, func(c *SecurityConfig) {
		c.ExcludedSemanticDetectionHeaders = map[string]bool{"Cookie": true}
	})
	regex, semantic = scanThreatCounts(t, cfg, nil, header)
	if semantic != 0 || regex == 0 {
		t.Fatalf("a semantic-excluded Cookie header must skip only the semantic analyzer for each pair, got regex=%d semantic=%d", regex, semantic)
	}
}

func TestCookiePairsCountAgainstValueBudget(t *testing.T) {
	cfg := newDetectConfig(t, func(c *SecurityConfig) { c.Detection.MaxScanValues = 2 })
	// path takes one unit, the first pair the second; the pair holding the
	// attack is the third value and is skipped once the cap is spent.
	if categories := runDetectThreatHeaders(t, cfg, map[string]string{"cookie": "a=1; b=2; c=<script>alert(1)</script>"}); len(categories) != 0 {
		t.Fatalf("each cookie pair must count against the value budget, got %v", categories)
	}
}
