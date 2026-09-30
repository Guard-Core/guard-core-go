package guardcore

// Coverage tests for the semantic analyzer (semantic.go) and the pattern
// registry internals (registry.go).

import (
	"strings"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
)

func TestSemanticExtractTokensLimits(t *testing.T) {
	// Very large inputs truncate to the first fifty thousand runes.
	big := strings.Repeat("a ", 60000)
	tokens := semanticExtractTokens(big)
	if len(tokens) == 0 {
		t.Fatal("large inputs still tokenize")
	}
	// Fifty or more structural matches stop the structure sweep.
	structured := strings.Repeat("<b>", 12) + strings.Repeat(" fn(x)", 12) +
		strings.Repeat(" ;;x", 12) + strings.Repeat(" ../", 12) + strings.Repeat(" http://a", 12)
	tokens = semanticExtractTokens(structured)
	if len(tokens) < 50 {
		t.Fatalf("structure matches join the token set, got %d", len(tokens))
	}
	// Token sets cap at one thousand.
	if got := semanticExtractTokens(strings.Repeat("word ", 1200) + "<b>"); len(got) != 1000 {
		t.Fatalf("token sets cap at one thousand, got %d", len(got))
	}
}

func TestCollapseSpaces(t *testing.T) {
	if got := collapseSpaces("a \t\n\r b"); got != "a b" {
		t.Fatalf("space runs collapse, got %q", got)
	}
	if got := collapseSpaces(""); got != "" {
		t.Fatalf("empty input stays empty, got %q", got)
	}
}

func TestCalculateEntropyLimits(t *testing.T) {
	if got := calculateEntropy(""); got != 0.0 {
		t.Fatalf("empty inputs have zero entropy, got %v", got)
	}
	// Long inputs clamp to the first ten thousand runes.
	if got := calculateEntropy(strings.Repeat("ab", 6000)); got <= 0.9 || got >= 1.1 {
		t.Fatalf("two-symbol entropy stays near one bit, got %v", got)
	}
}

func TestDetectEncodingLayersLimits(t *testing.T) {
	if got := detectEncodingLayers("ab"); got != 0 {
		t.Fatalf("plain text has no layers, got %d", got)
	}
	if got := detectEncodingLayers(strings.Repeat("%41%42", 6000)); got != 1 {
		t.Fatalf("layer detection clamps long inputs, got %d", got)
	}
}

func TestGetStructuralPatternBoost(t *testing.T) {
	if got := getStructuralPatternBoost("xss", "<b>hi</b>"); got != 0.3 {
		t.Fatalf("xss tags boost, got %v", got)
	}
	if got := getStructuralPatternBoost("sql", "select x from y"); got != 0.3 {
		t.Fatalf("sql keywords boost, got %v", got)
	}
	if got := getStructuralPatternBoost("command", "a; b"); got != 0.3 {
		t.Fatalf("command chains boost, got %v", got)
	}
	if got := getStructuralPatternBoost("path", "../etc/passwd"); got != 0.3 {
		t.Fatalf("traversals boost, got %v", got)
	}
	if got := getStructuralPatternBoost("made_up", "anything"); got != 0.0 {
		t.Fatalf("unknown types do not boost, got %v", got)
	}
	if got := getStructuralPatternBoost("sql", "hello world"); got != 0.0 {
		t.Fatalf("clean content does not boost, got %v", got)
	}
}

func TestSemanticAnalyzeScoreClamp(t *testing.T) {
	// Every xss keyword plus a tag pushes the base probability past one.
	content := "script javascript onerror onload onclick onmouseover alert eval document cookie window location <b>"
	analysis := semanticAnalyze(content)
	probs := analysis["attack_probabilities"].(map[string]any)
	if probs["xss"] != 1.0 {
		t.Fatalf("saturated probabilities clamp at one, got %v", probs["xss"])
	}
	// Semantic analysis of clean text reports no obfuscation.
	clean := semanticAnalyze("hello world from the docs")
	if clean["is_obfuscated"] != false {
		t.Fatalf("clean text is not obfuscated, got %v", clean["is_obfuscated"])
	}
}

func TestDetectObfuscationBranches(t *testing.T) {
	// Binary content short-circuits to clean.
	if detectObfuscation(strings.Repeat("\x00\x01\x02\x03", 100)) {
		t.Fatal("binary content is not obfuscation")
	}
	// Stacked encodings flag.
	if !detectObfuscation("%41%42%43QUJD0x1234\\u0041&amp;") {
		t.Fatal("stacked encodings flag as obfuscation")
	}
	// Special-character density above forty percent flags.
	if !detectObfuscation("!!!!####%%%%$$$$&&&&") {
		t.Fatal("special-dense content flags")
	}
	// Very long unbroken runs flag.
	if !detectObfuscation(strings.Repeat("A", 120)) {
		t.Fatal("long runs flag")
	}
	// High-entropy content flags: thirty-two distinct symbols carry five
	// bits of entropy, above the 4.5 threshold.
	if !detectObfuscation("abcdefghijklmnopqrstuvwxyzABCDEF") {
		t.Fatal("high-entropy content flags")
	}
}

func TestCodeInjectionRiskBranches(t *testing.T) {
	if got := codeInjectionRisk(""); got != 0.0 {
		t.Fatalf("clean content has no risk, got %v", got)
	}
	// Every signal stacks: the documented maximum is 0.8, so the clamp at
	// one can never fire from scanned content.
	full := "{{a}}f(x)$v==eval"
	if got := codeInjectionRisk(full); got != 0.8 {
		t.Fatalf("all signals stack to 0.8, got %v", got)
	}
}

func TestExtractSuspiciousPatternsContextClamp(t *testing.T) {
	// A match at the very start clamps its context window.
	patterns := extractSuspiciousPatterns("<b>tail")
	if len(patterns) == 0 {
		t.Fatal("tags yield patterns")
	}
	if patterns[0]["position"] != 0 {
		t.Fatalf("leading patterns anchor at zero, got %v", patterns[0]["position"])
	}
}

func TestMaxInt(t *testing.T) {
	if maxInt(0, 1) != 1 || maxInt(2, 1) != 2 || maxInt(1, 1) != 1 {
		t.Fatal("maxInt returns the larger side")
	}
}

func TestSemanticThreatScoreBounds(t *testing.T) {
	if got := semanticThreatScore(map[string]any{}); got != 0.0 {
		t.Fatalf("empty analyses score zero, got %v", got)
	}
	// Out-of-range synthetic values exercise every cap in one call.
	analysis := map[string]any{
		"attack_probabilities": map[string]any{"xss": 2.0},
		"is_obfuscated":        true,
		"encoding_layers":      5,
		"code_injection_risk":  5.0,
		"suspicious_patterns":  []map[string]any{{}},
	}
	if got := semanticThreatScore(analysis); got != 1.0 {
		t.Fatalf("scores clamp at one, got %v", got)
	}
	// Pattern lists cap at 0.1.
	analysis = map[string]any{
		"suspicious_patterns": []map[string]any{{}, {}, {}, {}},
	}
	if got := semanticThreatScore(analysis); got != 0.1 {
		t.Fatalf("pattern scores cap at 0.1, got %v", got)
	}
}

func TestLooksLikeBinaryContent(t *testing.T) {
	if looksLikeBinaryContent("") {
		t.Fatal("empty content is not binary")
	}
	if looksLikeBinaryContent("plain text") {
		t.Fatal("plain text is not binary")
	}
	if !looksLikeBinaryContent("\x00\x01\x02\x03\x04\x05\x06\x07") {
		t.Fatal("control bytes are binary")
	}
}

func TestPatternExcludedFromViewPlain(t *testing.T) {
	// The plain view never excludes a pattern.
	if patternExcludedFromView("anything", viewPlain) {
		t.Fatal("plain views exclude nothing")
	}
	if patternExcludedFromView("not_a_real_pattern_source", viewMain) {
		t.Fatal("main views keep non-excluded patterns")
	}
	if !patternExcludedFromView("not_a_real_pattern_source", viewRaw) {
		t.Fatal("raw views drop plain patterns")
	}
	if !patternExcludedFromView("not_a_real_pattern_source", viewURLDecoded) {
		t.Fatal("url-decoded views keep only url-decoded patterns")
	}
}

func TestSourceExtensionPathIsProbe(t *testing.T) {
	if !sourceExtensionPathIsProbe("url_path") {
		t.Fatal("plain paths are probes")
	}
	if sourceExtensionPathIsProbe("request_body" + embeddedJSONLeafContextSuffix) {
		t.Fatal("embedded json leaves are not probes")
	}
}

func TestDetectSensitiveSourceExtension(t *testing.T) {
	// A source file reference in the url path is a probe.
	result := Detect("app/main.py", "", "url_path")
	found := false
	for _, threat := range result.Threats {
		if threat["pattern"] == sensitiveSourceExtensionPathSource {
			found = true
		}
	}
	if !found {
		t.Fatalf("source extensions in paths flag: %v", result.Threats)
	}
	// The same reference inside an embedded json leaf is exempt.
	leaf := Detect("app/main.py", "", "query_param"+embeddedJSONLeafContextSuffix)
	for _, threat := range leaf.Threats {
		if threat["pattern"] == sensitiveSourceExtensionPathSource {
			t.Fatal("embedded json leaves stay clean")
		}
	}
}

func TestDetectLDAPOperatorBreakouts(t *testing.T) {
	// LDAP operator breakouts route through their validator closures.
	cases := []struct {
		name    string
		content string
		source  string
	}{
		{"wildcard_equals", "uid=x*)(uid=z", ldapWildcardEqualsSource},
		{"paren_breakout", "q)(!(", ldapParenBreakoutSource},
		{"paren_conjunction", "(&(uid=x*)", ldapParenConjunctionSource},
	}
	for _, tc := range cases {
		result := Detect(tc.content, "", "request_body")
		found := false
		for _, threat := range result.Threats {
			if threat["pattern"] == tc.source {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: expected a sighting of %s in %v", tc.name, tc.source, result.Threats)
		}
	}
}

func TestCheckRegexPatternsEnabledCategories(t *testing.T) {
	// A nil category set keeps every pattern.
	_, matchedAll, _ := checkRegexPatterns(newScanText("<script>a</script>"), "request_body", nil, viewMain)
	if len(matchedAll) == 0 {
		t.Fatal("clean sweeps still match scripts")
	}
	// A disabled category set drops its patterns.
	_, matchedNone, _ := checkRegexPatterns(newScanText("<script>a</script>"), "request_body", map[string]bool{"sqli": true}, viewMain)
	if len(matchedNone) != 0 {
		t.Fatalf("disabled categories drop their patterns, got %v", matchedNone)
	}
}

func TestSafeFindAllTimeoutAndZeroWidth(t *testing.T) {
	// A pattern whose match deadline has already elapsed reports a timeout.
	p := &compiledPattern{
		source:   "timeout_probe",
		re:       mustCompile(`(a+)+$`, 0, time.Nanosecond),
		contexts: map[string]bool{"request_body": true},
		category: "custom",
	}
	t1 := newScanText(strings.Repeat("a", 40) + "!")
	matches, timeout := safeFindAll(p, t1)
	if !timeout {
		t.Fatal("expired deadlines report timeouts")
	}
	if matches != nil {
		t.Fatal("timed-out scans report no matches")
	}

	// Zero-width matches advance the scan one rune at a time.
	zp := &compiledPattern{
		source:   "zero_probe",
		re:       mustCompile(`x*`, 0, windowTimeout),
		contexts: map[string]bool{"request_body": true},
		category: "custom",
	}
	zm, ztimeout := safeFindAll(zp, newScanText("ab"))
	if ztimeout {
		t.Fatal("healthy scans do not time out")
	}
	if len(zm) != 3 {
		t.Fatalf("zero-width matches advance rune-wise, got %d", len(zm))
	}
}

func TestCheckRegexPatternTimeoutThreat(t *testing.T) {
	// Registering an already-expired pattern proves the timeout threat
	// path; the probe is removed afterwards.
	saved := globalPatterns
	defer func() { globalPatterns = saved }()
	globalPatterns = append(saved, compiledPattern{
		source:   "timeout_probe",
		re:       mustCompile(`(a+)+$`, 0, time.Nanosecond),
		contexts: map[string]bool{"request_body": true},
		category: "custom",
	})
	threats, matched, timeouts := checkRegexPatterns(newScanText(strings.Repeat("a", 40)+"!"), "request_body", nil, viewMain)
	found := false
	for i, source := range timeouts {
		if source == "timeout_probe" {
			found = true
			if i >= len(threats) || threats[i]["type"] != "pattern_timeout" {
				t.Fatal("timeout threats carry the pattern_timeout type")
			}
		}
	}
	if !found {
		t.Fatal("expired patterns report timeouts")
	}
	if len(matched) == 0 {
		t.Fatal("timeout threats still count as matches")
	}
}

func TestPatternTableCompilesClean(t *testing.T) {
	// Every table pattern must compile: the registry init's error skip is
	// a defensive guard this test keeps honest.
	for _, def := range patternTable {
		if _, err := compileRE(def.Pattern, regexp2.IgnoreCase, windowTimeout); err != nil {
			t.Fatalf("pattern %q must compile: %v", def.Pattern, err)
		}
	}
}

func TestBuildTimeoutThreat(t *testing.T) {
	p := &compiledPattern{source: "boom", category: "sqli"}
	threat := buildTimeoutThreat(p)
	if threat["type"] != "pattern_timeout" || threat["pattern"] != "boom" {
		t.Fatalf("timeout threats describe their pattern, got %v", threat)
	}
}
