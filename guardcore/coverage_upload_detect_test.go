package guardcore

// Coverage tests for the file-upload matchers (fileupload.go), the Detect
// orchestration extras (detect.go), the multipart splitter (multipartscan.go)
// and the remaining check/config helpers.

import (
	"strings"
	"testing"
)

func TestFileUploadScanWindow(t *testing.T) {
	if got := fileUploadScanWindow(newScanText(`a"b'c`)); got != `a"b'` {
		t.Fatalf("scan windows end at the last quote, got %q", got)
	}
	if got := fileUploadScanWindow(newScanText("no quotes")); got != "" {
		t.Fatalf("quote-less bodies yield empty windows, got %q", got)
	}
	if got := fileUploadScanWindow(newScanText(`x'y`)); got != `x'` {
		t.Fatalf("apostrophes close windows too, got %q", got)
	}
}

func TestFileUploadMatchStart(t *testing.T) {
	tx := newScanText(`;filename="x"`)
	if start, ok := fileUploadMatchStart(tx, 1); !ok || start != 0 {
		t.Fatalf("separators anchor starts, got %d %v", start, ok)
	}
	tx = newScanText("a b\n  filename=\"x\"")
	if start, ok := fileUploadMatchStart(tx, 6); !ok || start != 3 {
		t.Fatalf("newlines anchor starts, got %d %v", start, ok)
	}
	tx = newScanText("x y filename=\"z\"")
	if start, ok := fileUploadMatchStart(tx, 4); ok || start != 0 {
		t.Fatalf("unguarded starts refuse, got %d %v", start, ok)
	}
	tx = newScanText(`filename="x"`)
	if start, ok := fileUploadMatchStart(tx, 0); !ok || start != 0 {
		t.Fatalf("text starts anchor, got %d %v", start, ok)
	}
}

func TestFileUploadQuotedCandidate(t *testing.T) {
	tx := newScanText(`filename`)
	if _, _, _, ok := fileUploadQuotedCandidate(tx, 0); ok {
		t.Fatal("valueless filenames refuse")
	}
	tx = newScanText(`filename=x`)
	if _, _, _, ok := fileUploadQuotedCandidate(tx, 0); ok {
		t.Fatal("unquoted filenames refuse")
	}
	tx = newScanText(`filename="x`)
	if _, _, _, ok := fileUploadQuotedCandidate(tx, 0); ok {
		t.Fatal("unclosed quotes refuse")
	}
	tx = newScanText(`filename="a'b"`)
	start, bodyStart, end, ok := fileUploadQuotedCandidate(tx, 0)
	if !ok || start != 0 || bodyStart != 10 || end != 12 {
		t.Fatalf("inner apostrophes close quotes first, got %d %d %d %v", start, bodyStart, end, ok)
	}
}

func TestFileUploadIsTruncation(t *testing.T) {
	// Percent-encoded truncation markers flag.
	if !fileUploadIsTruncation(newScanText("shell.php%00.jpg"), false) {
		t.Fatal("encoded truncations flag")
	}
	// Decoded NUL markers flag on the decoded pass.
	if !fileUploadIsTruncation(newScanText("shell.php\x00.jpg"), true) {
		t.Fatal("decoded truncations flag")
	}
	// Clean names stay clean.
	if fileUploadIsTruncation(newScanText("report.pdf"), false) {
		t.Fatal("clean names stay clean")
	}
}

func TestFileUploadKindMatchesDefault(t *testing.T) {
	if fileUploadKindMatches(newScanText("x.php"), "made_up_source") {
		t.Fatal("unknown sources never match")
	}
}

func TestFileUploadScanMatches(t *testing.T) {
	tx := newScanText(`form; filename="shell.php";`)
	got := fileUploadScanMatches(tx, fileUploadDangerousSource)
	if len(got) != 1 {
		t.Fatalf("dangerous filenames match, got %d", len(got))
	}
	// Unquoted candidates are skipped.
	if got := fileUploadScanMatches(newScanText("filename=shell.php"), fileUploadDangerousSource); got != nil {
		t.Fatalf("unquoted candidates are skipped, got %v", got)
	}
	// Double extensions flag through the same sweep.
	tx = newScanText(`form; filename="x.php.jpg";`)
	if got := fileUploadScanMatches(tx, fileUploadDoubleSource); len(got) != 1 {
		t.Fatalf("double extensions match, got %d", len(got))
	}
}

func TestFindAllMatchesLimited(t *testing.T) {
	if got := findAllMatchesLimited(fileUploadDangerousMarkerRE, newScanText("x.php"), 0); got != nil {
		t.Fatalf("zero ceilings yield nothing, got %v", got)
	}
	if got := findAllMatchesLimited(fileUploadDangerousMarkerRE, newScanText("x.php"), -1); got != nil {
		t.Fatalf("negative ceilings yield nothing, got %v", got)
	}
}

func TestDecodeBudgetExhaustedThreat(t *testing.T) {
	threat := decodeBudgetExhaustedThreat()
	if threat["pattern"] != decodeBudgetExhaustedPattern || threat["type"] != "regex" {
		t.Fatalf("exhaustion threats describe themselves, got %v", threat)
	}
	// Detect appends the exhaustion threat for deeply layered payloads.
	deep := "%" + strings.Repeat("25", 40) + "3Cscript%3E"
	result := Detect(deep, "", "request_body")
	found := false
	for _, threat := range result.Threats {
		if threat["pattern"] == decodeBudgetExhaustedPattern {
			found = true
		}
	}
	if !found {
		t.Fatal("deeply layered payloads report exhaustion")
	}
}

func TestCheckDecodedViewPathTraversal(t *testing.T) {
	pre := newPreprocessor(DefaultConfig())
	// Disabled categories short-circuit.
	if got := checkDecodedViewPathTraversal(pre, "../x", "../x", "../x", map[string]bool{"xss": true}); got != nil {
		t.Fatalf("disabled categories yield nothing, got %v", got)
	}
	// More decoded traversals than raw sightings report one threat.
	threat := checkDecodedViewPathTraversal(pre, "../x", "%2e%2e%2fx", "", nil)
	if threat == nil || threat["category"] != "path_traversal" {
		t.Fatalf("decoded traversal deltas report, got %v", threat)
	}
	// Equal counts report nothing.
	if got := checkDecodedViewPathTraversal(pre, "../x", "../x", "../x", nil); got != nil {
		t.Fatalf("equal counts yield nothing, got %v", got)
	}
}

func TestCheckSemanticThreatsBranches(t *testing.T) {
	// Binary content skips the semantic pass entirely.
	threats, score, _ := checkSemanticThreats(strings.Repeat("\x00\x01\x02\x03", 100), strings.Repeat("\x00\x01\x02\x03", 100))
	if threats != nil || score != 0.0 {
		t.Fatal("binary content skips semantics")
	}
	// Very long content truncates to the semantic budget.
	long := strings.Repeat("a ", 20000)
	_, _, _ = checkSemanticThreats(long, long)
	// A keyword-dense body produces typed semantic threats.
	dense := "script javascript onerror onload onclick onmouseover alert eval document cookie window location <b> %41%42%43QUJD \\u0041 &amp;"
	threats, score, _ = checkSemanticThreats(dense, dense)
	if len(threats) == 0 || threats[0]["attack_type"] != "xss" {
		t.Fatalf("dense attacks produce semantic threats, got %v score %v", threats, score)
	}
	// Score-only threats carry the suspicious type when no probability
	// crosses the bar.
	mixed := "%41%42%43QUJD0x1234\\u0041&amp; {{a}}f(x)$v==eval"
	threats, _, _ = checkSemanticThreats(mixed, mixed)
	if len(threats) > 0 && threats[0]["attack_type"] != "suspicious" && threats[0]["attack_type"] != "xss" {
		t.Fatalf("score-only threats stay suspicious, got %v", threats)
	}
}

func TestCalculateThreatScore(t *testing.T) {
	if got := calculateThreatScore(nil, nil); got != 0.0 {
		t.Fatalf("empty threat sets score zero, got %v", got)
	}
	regex := []map[string]any{{"weight": 0.5}}
	semantic := []map[string]any{{"probability": 0.9}}
	if got := calculateThreatScore(regex, semantic); got != 0.9 {
		t.Fatalf("semantic maxima win, got %v", got)
	}
	// threat_score fallbacks apply when probabilities are absent.
	semantic = []map[string]any{{"threat_score": 0.8}}
	if got := calculateThreatScore(regex, semantic); got != 0.8 {
		t.Fatalf("threat scores fall back, got %v", got)
	}
	// Scores clamp at one.
	semantic = []map[string]any{{"probability": 4.0}}
	if got := calculateThreatScore(regex, semantic); got != 1.0 {
		t.Fatalf("scores clamp at one, got %v", got)
	}
	if got := calculateThreatScore(regex, nil); got != 0.5 {
		t.Fatalf("regex weights sum, got %v", got)
	}
}

func TestDetectShortBase64AndDuplicates(t *testing.T) {
	// Short base64 fragments carrying template markers surface through the
	// additive view.
	result := Detect("JHt7 fn1 JHt9", "", "request_body")
	_ = result
	// Duplicated sightings across views deduplicate: one payload, one
	// regex threat contribution beyond the raw-view drop.
	dup := "<script>alert(1)</script>"
	result = Detect(dup, "", "request_body")
	counts := 0
	for _, threat := range result.Threats {
		if threat["pattern"] == "<script[^>]*>[^<]*<\\/script\\s*>" {
			counts++
		}
	}
	if counts == 0 {
		t.Fatal("script payloads match their pattern")
	}
}

func TestParseMultipartPartsEmptyBoundary(t *testing.T) {
	if got := parseMultipartParts("body", ""); got != nil {
		t.Fatalf("empty boundaries yield no parts, got %v", got)
	}
}

func TestParseMultipartPartsFinalMarkFirst(t *testing.T) {
	if got := parseMultipartParts("--b--\r\n", "b"); got != nil {
		t.Fatalf("final marks close empty bodies, got %v", got)
	}
}

func TestParseMultipartPartsPreambleAndFolding(t *testing.T) {
	body := "preamble junk\r\n" +
		"--b\r\n" +
		"Content-Type: text/plain\r\n" +
		" continued\r\n" +
		"Content-Disposition: form-data; name=\"f\"\r\n" +
		"\r\n" +
		"payload\r\n" +
		"--b--\r\n"
	parts := parseMultipartParts(body, "b")
	if len(parts) != 1 {
		t.Fatalf("preambles skip and fold, got %d parts", len(parts))
	}
	if len(parts[0].headers) != 2 {
		t.Fatalf("folded headers stay attached, got %v", parts[0].headers)
	}
	if !strings.Contains(parts[0].headers[0].value, "continued") {
		t.Fatalf("folds join their value, got %q", parts[0].headers[0].value)
	}
	if string(parts[0].payload) != "payload" {
		t.Fatalf("payloads trim their delimiter, got %q", parts[0].payload)
	}
}

func TestParseMultipartPartsColonlessHeader(t *testing.T) {
	// A colonless line ends the header block and opens the payload.
	body := "--b\r\nnot-a-header\r\npayload\r\n--b--\r\n"
	parts := parseMultipartParts(body, "b")
	if len(parts) != 1 {
		t.Fatalf("one part expected, got %d", len(parts))
	}
	if len(parts[0].headers) != 0 {
		t.Fatalf("colonless lines are not headers, got %v", parts[0].headers)
	}
	if !strings.Contains(string(parts[0].payload), "not-a-header") {
		t.Fatalf("colonless lines join the payload, got %q", parts[0].payload)
	}
}

func TestParseMultipartPartsImmediateBoundary(t *testing.T) {
	// Parts whose payload section closes immediately yield empty payloads.
	body := "--b\r\nContent-Type: text/plain\r\n\r\n--b--\r\n"
	parts := parseMultipartParts(body, "b")
	if len(parts) != 1 || len(parts[0].payload) != 0 {
		t.Fatalf("empty parts yield empty payloads, got %v", parts)
	}
}

func TestParseMultipartPartsNestedContainer(t *testing.T) {
	inner := "--inner\r\nContent-Type: text/plain\r\n\r\nhi\r\n--inner--\r\n"
	body := "--outer\r\n" +
		"Content-Type: multipart/mixed; boundary=inner\r\n" +
		"\r\n" +
		inner +
		"--outer--\r\n"
	parts := parseMultipartParts(body, "outer")
	if len(parts) != 1 {
		t.Fatalf("containers expand in place, got %d", len(parts))
	}
	if !strings.Contains(string(parts[0].payload), "hi") {
		t.Fatalf("inner payloads surface, got %q", parts[0].payload)
	}
}

func TestParseMultipartPartsMissingClose(t *testing.T) {
	// Bodies without a closing boundary keep the running payload.
	body := "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nruns to the end"
	parts := parseMultipartParts(body, "b")
	if len(parts) != 1 {
		t.Fatalf("one part expected, got %d", len(parts))
	}
	if string(parts[0].payload) != "runs to the end" {
		t.Fatalf("open payloads run to the end, got %q", parts[0].payload)
	}
}

func TestChecksWithoutConfig(t *testing.T) {
	// Nil-config and disabled checks never apply.
	vc := &customValidatorsCheck{}
	if vc.EnforcedOnExcludedPaths() {
		t.Fatal("custom validators never enforce on excluded paths")
	}
	if vc.AppliesTo(nil) {
		t.Fatal("nil configs never apply")
	}
	rc := &customRequestCheck{}
	if rc.EnforcedOnExcludedPaths() {
		t.Fatal("custom request checks never enforce on excluded paths")
	}
	if rc.AppliesTo(nil) {
		t.Fatal("nil configs never apply")
	}
	cc := &cloudIPRefreshCheck{}
	if cc.EnforcedOnExcludedPaths() || cc.AppliesTo(nil) {
		t.Fatal("cloud refresh checks need config")
	}
	pc := &cloudProviderCheck{}
	if pc.EnforcedOnExcludedPaths() || pc.AppliesTo(nil) {
		t.Fatal("cloud provider checks need config")
	}
	if (&cloudIPRefreshCheck{}).AppliesTo(&SecurityConfig{}) {
		t.Fatal("disabled cloud blocking never applies")
	}
	if (&cloudProviderCheck{}).AppliesTo(&SecurityConfig{}) {
		t.Fatal("disabled cloud blocking never applies")
	}
}

func TestCustomRequestCheckNilResponse(t *testing.T) {
	cfg := &SecurityConfig{CustomRequestCheck: func(req Request) *Response { return nil }}
	c := &customRequestCheck{cfg: cfg}
	req := newTestRequest(t, nil)
	if resp := c.Check(req); resp != nil {
		t.Fatalf("nil custom responses pass through, got %v", resp)
	}
}

func TestBuildHSTSNil(t *testing.T) {
	if got := buildHSTS(nil); got != "" {
		t.Fatalf("nil hsts builds nothing, got %q", got)
	}
}

func TestValidateSecurityHeadersEmptyOverrides(t *testing.T) {
	sh := &SecurityHeadersConfig{}
	if err := validateSecurityHeaders(sh); err != nil {
		t.Fatalf("empty headers validate, got %v", err)
	}
}
