package guardcore

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// semanticOnlyValue is a JWT-bearing cookie string the semantic analyzer
// flags without any regex category.
func semanticOnlyValue() string {
	enc := base64.RawURLEncoding.EncodeToString
	claims := `{"sub": "3f2c1b9e-8a47-4d2e-9c1f-5b6a7d8e9f01", "name": "Jane Doe (Acme)", "email": "jane.doe@example.com", "roles": ["admin"], "iat": 1792000000, "exp": 1792000900}`
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	jwt := enc([]byte(`{"alg": "ES256", "typ": "JWT"}`)) + "." + enc([]byte(claims)) + "." + enc(sig)
	return "session=" + jwt + "; theme=system; _ga=GA1.1.123456789.1792000000"
}

const xssPayload = "<script>alert(1)</script>"

func detectFor(t *testing.T, cfg *SecurityConfig, mutate func(*RequestOptions)) ([]string, string) {
	t.Helper()
	req := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) { mutate(opts) })
	return detectThreat(req, cfg, resolveDetectionExclusions(cfg, nil))
}

func TestDetectThreatSemanticOnlyIsReported(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	cats, trigger := detectFor(t, cfg, func(o *RequestOptions) { o.RawQuery = "q=" + url.QueryEscape(semanticOnlyValue()) })
	if len(cats) == 0 {
		t.Fatalf("semantic-only threat must be reported with a category, got %v", cats)
	}
	if !strings.HasPrefix(trigger, "Query param 'q': Semantic attack: ") {
		t.Fatalf("unexpected trigger %q", trigger)
	}
}

func TestDetectThreatKeepsScanningAfterUnreportableValue(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	// SSRF in an excluded proxy header is category-skipped; the body (always
	// scanned after every header) carries the attack, so the result does not
	// depend on header map order.
	cats, trigger := detectFor(t, cfg, func(o *RequestOptions) {
		o.Method = "POST"
		o.Header = map[string]string{"x-forwarded-host": "http://169.254.169.254/latest/meta-data/"}
		o.Body = []byte(xssPayload)
	})
	if len(cats) != 1 || cats[0] != "xss" || !strings.HasPrefix(trigger, "Request body: ") {
		t.Fatalf("categories=%v trigger=%q", cats, trigger)
	}
}

func TestDetectThreatDisabledCategoryDoesNotEndScan(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.EnabledDetectionCategories = []string{"xss"}
	// Query value matches only a disabled category (sql_injection); the body
	// XSS must still be found.
	cats, _ := detectFor(t, cfg, func(o *RequestOptions) {
		o.Method = "POST"
		o.RawQuery = "q=" + url.QueryEscape("1' UNION SELECT password FROM users--")
		o.Body = []byte(xssPayload)
	})
	if len(cats) != 1 || cats[0] != "xss" {
		t.Fatalf("categories=%v", cats)
	}
}

func TestDetectThreatSemanticValueBeforeXSSIsNotClean(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	// The semantic-only value (issue #161 session string) is scanned before
	// the body. Like the reference it is reported as suspicious and the scan
	// ends there; what must never happen is the clean result the old code
	// returned, which hid the body XSS entirely.
	for name, mutate := range map[string]func(*RequestOptions){
		"query": func(o *RequestOptions) { o.RawQuery = "q=" + url.QueryEscape(semanticOnlyValue()) },
		"x-session header": func(o *RequestOptions) {
			o.Header = map[string]string{"x-session": semanticOnlyValue()}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cats, trigger := detectFor(t, cfg, func(o *RequestOptions) {
				o.Method = "POST"
				mutate(o)
				o.Body = []byte(xssPayload)
			})
			if len(cats) == 0 {
				t.Fatalf("request with a semantic-only value and a body XSS scanned clean: categories=%v trigger=%q", cats, trigger)
			}
		})
	}
}

func TestDetectThreatNilEnabledMeansAllCategories(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	cats, _ := detectThreat(newTestRequest(t, func(o *RequestOptions, _ *RequestState) {
		o.Header = map[string]string{"x-evil": xssPayload}
	}), cfg, routeDetectionExclusions{excludedHeaders: map[string]bool{}, scanBody: true})
	if len(cats) != 1 || cats[0] != "xss" {
		t.Fatalf("categories=%v", cats)
	}
}

func TestDetectThreatThreatWithoutResultThreatsIsUncategorized(t *testing.T) {
	cats, trigger := reportableThreat(DetectResult{IsThreat: true}, nil, nil, "L: ")
	if len(cats) != 1 || cats[0] != "uncategorized" || trigger != "L: Threat detected" {
		t.Fatalf("categories=%v trigger=%q", cats, trigger)
	}
}
