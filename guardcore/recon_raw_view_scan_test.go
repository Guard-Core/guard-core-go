package guardcore

// Port of tests/test_sus_patterns/test_recon_raw_view_scan.py (guard-core
// upstream fix/raw-view-recon-scan): the processed views fold LDAP hex
// escapes ("\de" -> U+00DE) before the pattern tables run, so
// separator-prefixed recon probes such as "\default" never reach a recon row
// there. The recon rows are additionally scanned against the
// signal-preserving raw view, the #116 leading-separator gate applies to
// raw-view matches exactly as everywhere else, and a row matching both the
// processed and the raw view on the same text is counted once.

import (
	"strconv"
	"strings"
	"testing"
)

var rawViewBackslashProbes = []string{`\default`, `\report.asp`, `\README.md`}

var rawViewBareWords = []string{"default", "SAP", "actuator", "README.md"}

// rawViewValueContexts covers the direct value contexts plus the body field
// and embedded JSON leaf contexts this engine scans through.
var rawViewValueContexts = []string{
	"query_param",
	"request_body",
	"request_body:form_field",
	"request_body:multipart_field",
	"request_body:embedded_json",
	"query_param:embedded_json",
}

func assertRawViewRecon(t *testing.T, value, context string) {
	t.Helper()
	result := Detect(value, "127.0.0.1", context)
	if !result.IsThreat {
		t.Fatalf("value %q in context %q: expected recon detection (threats=%v)", value, context, result.Threats)
	}
	found := false
	for _, threat := range result.Threats {
		if threat["category"] == "recon" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("value %q in context %q: expected a recon-category threat, got %v", value, context, result.Threats)
	}
}

func assertRawViewClean(t *testing.T, value, context string) {
	t.Helper()
	result := Detect(value, "127.0.0.1", context)
	if result.IsThreat {
		t.Fatalf("value %q in context %q: unexpected threat (score=%v threats=%v)", value, context, result.ThreatScore, result.Threats)
	}
}

func TestBackslashProbeValueDetectsOnTheRawView(t *testing.T) {
	for _, value := range rawViewBackslashProbes {
		for _, context := range rawViewValueContexts {
			assertRawViewRecon(t, value, context)
		}
	}
}

func TestBareWordValueStaysInnocentOnTheRawView(t *testing.T) {
	for _, value := range rawViewBareWords {
		for _, context := range rawViewValueContexts {
			assertRawViewClean(t, value, context)
		}
	}
}

func TestBackslashDefaultAsTheURLPathValueIsRecon(t *testing.T) {
	// A backslash-prefixed probe is recon as a URL path value; the raw view
	// must not lose it to the hex decoder.
	assertRawViewRecon(t, `\default`, "url_path")
}

func TestSlashBackslashURLPathStaysCleanOnBothViews(t *testing.T) {
	// "/\default" is not a probe shape on any view: the leading slash
	// already satisfies the path prefix, so the row cannot rematch on
	// "\default".
	assertRawViewClean(t, `/\default`, "url_path")
}

func reconThreatMatches(result DetectResult) []string {
	var matches []string
	for _, threat := range result.Threats {
		if threat["category"] == "recon" {
			match, _ := threat["match"].(string)
			matches = append(matches, match)
		}
	}
	return matches
}

func TestHexDecodedSeparatorProbeStillDetectsOnce(t *testing.T) {
	// "\2fdefault" decodes to "/default" on the processed views; the raw
	// view does not match it, and the decoded sighting stays a single recon
	// hit.
	result := Detect(`\2fdefault`, "127.0.0.1", "query_param")
	matches := reconThreatMatches(result)
	if len(matches) != 1 || matches[0] != "/default" {
		t.Fatalf("expected exactly one recon hit on /default, got %v (threats=%v)", matches, result.Threats)
	}
}

func TestRowMatchingBothViewsIsCountedOnce(t *testing.T) {
	// "\report.asp" survives preprocessing intact: the processed views and
	// the raw view both match it, and the raw-view merge must not
	// double-count it.
	result := Detect(`\report.asp`, "127.0.0.1", "query_param")
	matches := reconThreatMatches(result)
	if len(matches) != 1 || matches[0] != `\report.asp` {
		t.Fatalf("expected exactly one recon hit on \\report.asp, got %v", matches)
	}
	if !result.IsThreat {
		t.Fatalf("expected the value to detect")
	}
	if result.ThreatScore != 1.0 {
		t.Fatalf("the deduplicated sighting must score exactly 1.0, got %v", result.ThreatScore)
	}
}

func TestTwoRowProbeKeepsTheReferenceMultiset(t *testing.T) {
	for _, value := range []string{"/default.asp", `\default.asp`} {
		result := Detect(value, "127.0.0.1", "query_param")
		matches := reconThreatMatches(result)
		if len(matches) != 2 {
			t.Fatalf("value %q: expected exactly two recon hits, got %v (threats=%v)", value, matches, result.Threats)
		}
		if matches[0] != value || matches[1] != value {
			t.Fatalf("value %q: expected both hits on the whole value, got %v", value, matches)
		}
	}
}

func TestHexFoldedRunStaysClean(t *testing.T) {
	// "\de\ad\be\ef" folds to non-ASCII text on the processed views and is
	// not a probe on the raw view either; folding must not create a recon
	// hit.
	assertRawViewClean(t, `\de\ad\be\ef`, "query_param")
}

func TestReconRawViewPatternSourcesDerivation(t *testing.T) {
	for _, def := range patternTable {
		if got := reconRawViewPatternSources[def.Pattern]; got != (def.Category == "recon") {
			t.Fatalf("row %q: raw-view membership %v does not match category %q", def.Pattern, got, def.Category)
		}
	}
	if len(reconRawViewPatternSources) == 0 {
		t.Fatalf("expected the recon raw-view set to be populated")
	}
}

// bodyDetectCategories routes a raw body with headers through detectThreat
// and returns the enabled categories of the resulting verdict.
func bodyDetectCategories(t *testing.T, cfg *SecurityConfig, contentType string, body []byte) []string {
	t.Helper()
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Method = "POST"
		opts.Header = map[string]string{
			"content-type":   contentType,
			"content-length": strconv.Itoa(len(body)),
		}
		opts.Body = body
	})
	categories, _ := detectThreat(req, cfg, resolveDetectionExclusions(cfg, nil))
	return categories
}

func assertCategoriesContain(t *testing.T, categories []string, want string) {
	t.Helper()
	for _, category := range categories {
		if category == want {
			return
		}
	}
	t.Fatalf("expected %s in categories, got %v", want, categories)
}

func TestBackslashProbeReachesReconThroughBodyExtraction(t *testing.T) {
	cfg := testConfig(t)
	for _, value := range rawViewBackslashProbes {
		form := []byte("system=" + value)
		if categories := bodyDetectCategories(t, cfg, "application/x-www-form-urlencoded", form); len(categories) == 0 {
			t.Fatalf("form body %q: expected a detection", form)
		} else {
			assertCategoriesContain(t, categories, "recon")
		}
		jsonBody := []byte(`{"system":"` + strings.ReplaceAll(value, `\`, `\\`) + `"}`)
		if categories := bodyDetectCategories(t, cfg, "application/json", jsonBody); len(categories) == 0 {
			t.Fatalf("json body %s: expected a detection", jsonBody)
		} else {
			assertCategoriesContain(t, categories, "recon")
		}
	}
}

func TestBareWordBodyValuesStayInnocentThroughBodyExtraction(t *testing.T) {
	cfg := testConfig(t)
	for _, value := range rawViewBareWords {
		form := []byte("system=" + value)
		if categories := bodyDetectCategories(t, cfg, "application/x-www-form-urlencoded", form); len(categories) != 0 {
			t.Fatalf("form body %q: unexpected detection %v", form, categories)
		}
		jsonBody := []byte(`{"system":"` + value + `"}`)
		if categories := bodyDetectCategories(t, cfg, "application/json", jsonBody); len(categories) != 0 {
			t.Fatalf("json body %s: unexpected detection %v", jsonBody, categories)
		}
	}
}

func TestEmbeddedJSONLeafFollowsTheProbeGate(t *testing.T) {
	// A JSON payload embedded in a form field walks to its leaves; the
	// backslash probe detects through the raw view while the bare word
	// stays innocent (the leaf context keeps the leading-separator gate).
	cfg := testConfig(t)
	// The embedded payload carries a JSON-escaped backslash, so the walk
	// decodes it back to "\default" on the leaf.
	probing := []byte(`v={"url":"\\default"}`)
	if categories := bodyDetectCategories(t, cfg, "application/x-www-form-urlencoded", probing); len(categories) == 0 {
		t.Fatalf("embedded JSON probe %s: expected a detection", probing)
	} else {
		assertCategoriesContain(t, categories, "recon")
	}
	innocent := []byte(`v={"url":"default"}`)
	if categories := bodyDetectCategories(t, cfg, "application/x-www-form-urlencoded", innocent); len(categories) != 0 {
		t.Fatalf("embedded JSON bare word %s: unexpected detection %v", innocent, categories)
	}
}
