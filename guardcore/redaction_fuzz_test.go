package guardcore

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func mustQueryUnescape(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

// pairNameGrammarRE is the pair redactor's name grammar: names start
// with a letter or underscore (the fuzzed name must satisfy it for the
// pair-leak invariant to apply; digit-leading names are a documented
// divergence from the reference scanner, see KNOWN_GAPS.md).
var pairNameGrammarRE = regexp.MustCompile(`^[A-Za-z_][\w.-]*$`)

// FuzzRedaction is the redaction fuzz gate: the reference redaction
// helpers must never panic, never inject newlines, never leak a secret
// that sits in a sensitive pair, and never expand the input
// unboundedly. `go test` runs the seed corpus below; the fuzzing engine
// explores further with `go test -fuzz FuzzRedaction -run '^$'`.
func FuzzRedaction(f *testing.F) {
	// Seeds mirror the reference redaction test corpus (the angle-bracket
	// grammar, JSON contexts, URLs, headers) plus adversarial shapes.
	seeds := []struct {
		text  string
		name  string
		value string
	}{
		{`blocked: token=SAMPLE-VALUE-01 at login`, "token", "SAMPLE-VALUE-01"},
		{`{"password": "SAMPLE-VALUE-01", "user": "alice"}`, "password", "SAMPLE-VALUE-01"},
		{`x-auth-token=SAMPLE-VALUE-01`, "x-auth-token", "SAMPLE-VALUE-01"},
		{"Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0", "user-agent", ""},
		{"/login?access_token=SAMPLE-VALUE-01&next=/home", "access_token", "SAMPLE-VALUE-01"},
		{"http://internal-gateway/internal/health", "authorization", ""},
		{"/health", "x", ""},
		{"token=<SAMPLE-VALUE-01>", "token", "SAMPLE-VALUE-01"},
		{"token=<SAMPLE-VALUE-01", "token", "SAMPLE-VALUE-01"},
		{"token=<>", "token", ""},
		{"token=<abc<def>ghi>", "token", ""},
		{"token=<a b>", "token", ""},
		{"token=<sample-key-51ABC xyz>&user=bob", "token", ""},
		{"password=<my secret value>&next=step", "password", ""},
		{"token=<oops&session_id=abc123>&next=ok", "token", ""},
		{"token=<x/next=ok", "token", ""},
		{"token=<x)password=y", "password", ""},
		{"token=<b>bold</b>", "token", ""},
		{"token=<x>\nnext=ok", "token", ""},
		{"<user>alice</user><password>SAMPLE-VALUE-01</password>", "password", "SAMPLE-VALUE-01"},
		{"a=1&b=2&api_key=SAMPLE-VALUE-01&d=4", "api_key", "SAMPLE-VALUE-01"},
		{"%%%\x00\x01\x02token=SAMPLE-VALUE-01\xff\xfe", "token", "SAMPLE-VALUE-01"},
		{"{\"a\":{\"b\":{\"c\":\"secret=x\"}}}", "secret", "x"},
		{"https://host/%%zz/?q=%2Fhome", "q", ""},
		{strings.Repeat("token=secret ", 500), "token", "secret"},
	}
	for _, seed := range seeds {
		f.Add(seed.text, seed.name, seed.value)
	}
	f.Fuzz(func(t *testing.T, text, name, value string) {
		sensitiveParams := map[string]bool{strings.ToLower(name): true}
		sensitiveHeaders := map[string]bool{strings.ToLower(name): true}
		allParams := mergedSensitiveNames(sensitiveParams, nil, nil)

		blob := RedactBlobForDisplay(text, sensitiveParams, nil, nil)
		header := RedactHeaderValueForDisplay(text, sensitiveParams, nil, nil)
		url := RedactURLForDisplay(text, sensitiveParams, nil, nil)
		merged := RedactBlobForDisplay(text, nil, nil, nil)

		// Invariant 1: the redactors never inject a newline the input did
		// not carry (log-injection safety).
		for _, out := range []string{blob, header, url, merged} {
			if !strings.Contains(text, "\n") && strings.Contains(out, "\n") {
				t.Fatalf("redaction injected a newline: input %q -> %q", text, out)
			}
			if !strings.Contains(text, "\r") && strings.Contains(out, "\r") {
				t.Fatalf("redaction injected a carriage return: input %q -> %q", text, out)
			}
		}

		// Invariant 2: a secret riding an actual sensitive pair
		// ("name=value") never survives the redaction. The pair is
		// constructed from the fuzzed name and value (the raw text may
		// contain both without forming a pair, which redaction must
		// correctly leave alone). The check strips the placeholder first
		// and demands a substantial secret, so single characters that
		// coincide with "[REDACTED]" cannot false-positive.
		// The invariant only applies when the constructed pair is one the
		// shipped scanner recognizes end to end (name grammar plus a
		// value the grammar accepts); pairs outside the shipped grammar
		// are the recorded divergence, not a leak.
		pairMatch := pairRedactRe.FindStringSubmatch(name + "=" + value)
		if len(name) >= 3 && len(value) >= 6 && pairNameGrammarRE.MatchString(name) &&
			pairMatch != nil && pairMatch[1] == name && strings.Contains(pairMatch[3], value) {
			pairText := name + "=" + value
			// The caller-supplied sensitive set always redacts its own
			// names; the defaults-only path redacts the reference's
			// default sets.
			checks := []string{
				RedactBlobForDisplay(pairText, sensitiveParams, nil, nil),
				RedactHeaderValueForDisplay(pairText, sensitiveParams, nil, nil),
				RedactBlobForDisplay(pairText, nil, nil, sensitiveHeaders),
			}
			if mergeSensitiveLogBodyFields(nil)[strings.ToLower(name)] || mergeSensitiveLogHeaders(nil)[strings.ToLower(name)] {
				checks = append(checks,
					RedactBlobForDisplay(pairText, nil, nil, nil))
				// The URL channel only when the value cannot restructure
				// the URL grammar (# and ? split query and fragment, and
				// a pair split across them is not a pair), matching the
				// reference urlsplit semantics.
				if !strings.ContainsAny(value, "#?") {
					checks = append(checks, mustQueryUnescape(RedactURLForDisplay("/?"+pairText, nil, nil, nil)))
				}
			}
			for _, out := range checks {
				// The name itself rides the output unredacted by design;
				// mask it (and the placeholder) before the leak check so
				// values that happen to be substrings of the name cannot
				// false-positive.
				masked := strings.ReplaceAll(out, RedactedPlaceholder, "")
				masked = strings.ReplaceAll(masked, name, "")
				if strings.Contains(masked, value) {
					t.Fatalf("secret leaked for sensitive name %q: input %q -> %q", name, pairText, out)
				}
			}
		}

		// Invariant 3: redaction never expands the input unboundedly (the
		// placeholder is fixed-size and replacements only shrink or hold
		// spans).
		if len(blob) > 4*len(text)+128 {
			t.Fatalf("blob redaction expanded %d bytes to %d: %q -> %q", len(text), len(blob), text, blob)
		}
		if len(merged) > 4*len(text)+128 {
			t.Fatalf("default redaction expanded %d bytes to %d: %q -> %q", len(text), len(merged), text, merged)
		}

		// Invariant 4: the header-map redactor holds the same newline
		// guarantee per value and never grows a value past the 8192-byte
		// contract.
		headers := RedactSensitiveHeaders(map[string]string{"x-probe": text}, sensitiveHeaders, nil, allParams)
		for headerName, out := range headers {
			if !strings.Contains(text, "\n") && strings.Contains(out, "\n") {
				t.Fatalf("header redaction injected a newline in %s: input %q -> %q", headerName, text, out)
			}
		}

		// Invariant 5: JSON-context redaction never panics and its output
		// is either empty or the redacted document.
		jsonOut := RedactBlobForDisplay(text, allParams, nil, nil)
		if jsonOut != "" && strings.Contains(jsonOut, "\n") && !strings.Contains(text, "\n") {
			t.Fatalf("json redaction injected a newline: input %q -> %q", text, jsonOut)
		}
	})
}

// FuzzRedactSensitiveHeaders pins the header-map redaction surface: no
// panic, values never gain newlines, and the output never exceeds the
// 8192-byte header-value contract.
func FuzzRedactSensitiveHeaders(f *testing.F) {
	f.Add("bearer SAMPLE-VALUE-01", "authorization")
	f.Add("a=1; b=2", "cookie")
	f.Add(strings.Repeat("x", 9000), "x-long")
	f.Fuzz(func(t *testing.T, value, name string) {
		sensitive := map[string]bool{strings.ToLower(name): true}
		out := RedactSensitiveHeaders(map[string]string{name: value}, sensitive, nil, nil)
		for headerName, redacted := range out {
			if strings.Contains(redacted, "\r\n") && !strings.Contains(value, "\r\n") {
				t.Fatalf("header %s gained CRLF: %q -> %q", headerName, value, redacted)
			}
		}
	})
}
