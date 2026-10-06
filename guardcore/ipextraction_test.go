package guardcore

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// resetForwardedWarnings clears the once-per-process warning gates so a
// test can assert log output deterministically.
func resetForwardedWarnings() {
	forwardedHeaderPreemptedOnce = sync.Once{}
	forwardedHeaderTooShortOnce = sync.Once{}
	forwardedHeaderSelectedOnce = sync.Once{}
	forwardedHeaderOvercountsOnce = sync.Once{}
}

func newIPExtractionEngine(t *testing.T, mutate func(*SecurityConfig)) (*Engine, *recordingAgent) {
	t.Helper()
	return newEventTestEngine(t, mutate)
}

func xffRequest(path, peer, forwardedFor string) Request {
	header := map[string]string{}
	if forwardedFor != "" {
		header["X-Forwarded-For"] = forwardedFor
	}
	return NewRequestFactory().CreateRequest(RequestOptions{
		Path:       path,
		Scheme:     "http",
		Host:       "example.com",
		Method:     "GET",
		ClientHost: peer,
		Header:     header,
	})
}

// TestExtractClientIPUntrustedPeerKeepsPeerAndEmitsSpoof: an untrusted
// peer carrying X-Forwarded-For is a spoof attempt; the canonical peer
// wins and the suspicious_request event fires with handler ip_extraction.
func TestExtractClientIPUntrustedPeerKeepsPeerAndEmitsSpoof(t *testing.T) {
	resetForwardedWarnings()
	engine, agent := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req := xffRequest("/api", "203.0.113.17", "198.51.100.77, 203.0.113.99")
	ip := extractClientIP(req, engine.Config)
	if ip != "203.0.113.17" {
		t.Fatalf("untrusted peer must keep its own address, got %q", ip)
	}
	if req.State().ClientIP != "203.0.113.17" {
		t.Fatalf("untrusted resolution must cache, got %q", req.State().ClientIP)
	}
	event := findEvent(agent, EventSuspiciousRequest)
	if event == nil {
		t.Fatalf("spoof attempt must emit suspicious_request, got %v", agent.eventTypes())
	}
	if event.HandlerName != "ip_extraction" || event.ActionTaken != "spoofing_detected" {
		t.Fatalf("identity drifted: %+v", event)
	}
	// The event reason carries the redacted display chain.
	if want := "Potential IP spoof attempt: X-Forwarded-For header 198.51.100.77, 203.0.113.99"; event.Reason != want {
		t.Fatalf("reason drifted: %q, want %q", event.Reason, want)
	}
}

// TestExtractClientIPUntrustedPeerSilentWithoutXFF: no forwarded chain, no
// event.
func TestExtractClientIPUntrustedPeerSilentWithoutXFF(t *testing.T) {
	resetForwardedWarnings()
	engine, agent := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req := xffRequest("/api", "203.0.113.17", "")
	if ip := extractClientIP(req, engine.Config); ip != "203.0.113.17" {
		t.Fatalf("plain peer must pass through, got %q", ip)
	}
	if findEvent(agent, EventSuspiciousRequest) != nil {
		t.Fatalf("no XFF means no spoof event, got %v", agent.eventTypes())
	}
}

// TestExtractClientIPTrustedPeerMultiHopDepth: a trusted peer with a
// two-hop chain resolves the depth entry counting from the right. With
// chain [client, proxy1] and depth 2 the client entry is selected; with
// depth 1 the proxy hop itself would be.
func TestExtractClientIPTrustedPeerMultiHopDepth(t *testing.T) {
	resetForwardedWarnings()
	engine, agent := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1", "192.0.2.2"}
		c.TrustedProxyDepth = 2
	})
	req := xffRequest("/api", "192.0.2.1", "203.0.113.5, 192.0.2.2")
	if ip := extractClientIP(req, engine.Config); ip != "203.0.113.5" {
		t.Fatalf("depth 2 must select the client entry, got %q", ip)
	}
	if findEvent(agent, EventSuspiciousRequest) != nil {
		t.Fatalf("trusted peers never trip the spoof gate, got %v", agent.eventTypes())
	}
	// Depth 1 on the same chain selects the proxy hop to the right of
	// the client.
	engine2, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
		c.TrustedProxyDepth = 1
	})
	req2 := xffRequest("/api", "192.0.2.1", "203.0.113.5, 192.0.2.2")
	if ip := extractClientIP(req2, engine2.Config); ip != "192.0.2.2" {
		t.Fatalf("depth 1 must select the rightmost hop, got %q", ip)
	}
}

// TestExtractClientIPTrustedPeerDepth1: default depth 1 takes the
// rightmost hop.
func TestExtractClientIPTrustedPeerDepth1(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req := xffRequest("/api", "192.0.2.1", "203.0.113.5, 198.51.100.9")
	if ip := extractClientIP(req, engine.Config); ip != "198.51.100.9" {
		t.Fatalf("depth 1 must take the rightmost hop, got %q", ip)
	}
}

// TestExtractClientIPDepthCapChainTooShort: a chain shorter than
// trusted_proxy_depth falls back to the connecting peer.
func TestExtractClientIPDepthCapChainTooShort(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
		c.TrustedProxyDepth = 3
	})
	req := xffRequest("/api", "192.0.2.1", "203.0.113.5")
	if ip := extractClientIP(req, engine.Config); ip != "192.0.2.1" {
		t.Fatalf("chain shorter than depth must keep the peer, got %q", ip)
	}
}

// TestExtractClientIPDepthOvercountsRunsRightToLeft: when entries to the
// right of the depth selection are not trusted proxies, the declared
// depth over-counts the real hops and the rightmost non-trusted hop wins.
func TestExtractClientIPDepthOvercountsRunsRightToLeft(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
		c.TrustedProxyDepth = 1
	})
	// The rightmost entry is NOT a trusted proxy: the depth over-counted,
	// so the walk takes the rightmost non-trusted hop (the same entry
	// here) - a malformed rightmost hop would keep the peer instead.
	req := xffRequest("/api", "192.0.2.1", "203.0.113.5, 198.51.100.9")
	if ip := extractClientIP(req, engine.Config); ip != "198.51.100.9" {
		t.Fatalf("right-to-left walk must take the rightmost non-trusted hop, got %q", ip)
	}
}

// TestExtractClientIPAllTrustedChainKeepsPeer: every hop trusted means no
// resolvable client; the connecting peer wins.
func TestExtractClientIPAllTrustedChainKeepsPeer(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1", "192.0.2.2"}
	})
	// depth 1 selects the rightmost (trusted) hop: no over-count, the
	// selected-entry warning fires and the reference returns the trusted
	// hop itself.
	req := xffRequest("/api", "192.0.2.1", "192.0.2.2")
	if ip := extractClientIP(req, engine.Config); ip != "192.0.2.2" {
		t.Fatalf("depth-selected entry is returned even when trusted, got %q", ip)
	}

	// A depth pointing past the trusted run walks right-to-left, finds
	// only trusted hops and keeps the peer.
	engine2, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1", "192.0.2.2"}
		c.TrustedProxyDepth = 3
	})
	req2 := xffRequest("/api", "192.0.2.1", "203.0.113.5, 192.0.2.2")
	if ip := extractClientIP(req2, engine2.Config); ip != "192.0.2.1" {
		t.Fatalf("a malformed non-trusted hop must keep the peer, got %q", ip)
	}
}

// TestExtractClientIPMalformedHopKeepsPeer: a malformed rightmost hop
// (not an address, metacharacters) resolves to nothing and keeps the
// peer.
func TestExtractClientIPMalformedHopKeepsPeer(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req := xffRequest("/api", "192.0.2.1", "not-an-ip")
	if ip := extractClientIP(req, engine.Config); ip != "192.0.2.1" {
		t.Fatalf("malformed hop must keep the peer, got %q", ip)
	}
	req2 := xffRequest("/api", "192.0.2.1", "203.0.113.[5]")
	if ip := extractClientIP(req2, engine.Config); ip != "192.0.2.1" {
		t.Fatalf("metachar hop must keep the peer, got %q", ip)
	}
}

// TestExtractClientIPCIDRTrustedProxy: trusted_proxies entries match by
// CIDR prefix.
func TestExtractClientIPCIDRTrustedProxy(t *testing.T) {
	resetForwardedWarnings()
	engine, agent := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"10.0.0.0/8"}
	})
	req := xffRequest("/api", "10.1.2.3", "203.0.113.5")
	if ip := extractClientIP(req, engine.Config); ip != "203.0.113.5" {
		t.Fatalf("CIDR-trusted peer must walk the chain, got %q", ip)
	}
	// Outside the prefix: spoof arm.
	req2 := xffRequest("/api", "203.0.113.17", "198.51.100.7")
	if ip := extractClientIP(req2, engine.Config); ip != "203.0.113.17" {
		t.Fatalf("peer outside the CIDR must keep its own address, got %q", ip)
	}
	if findEvent(agent, EventSuspiciousRequest) == nil {
		t.Fatalf("the outside-CIDR peer must trip the spoof gate, got %v", agent.eventTypes())
	}
}

// TestExtractClientIPCanonicalization: mapped proxy peers match IPv4
// CIDR trust entries through the mapped form (the reference's version
// mismatch raises, the port resolves it sanely), while a bare trust entry
// matches by exact text like the reference.
func TestExtractClientIPCanonicalization(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"10.0.0.0/8"}
	})
	req := xffRequest("/api", "::ffff:10.1.2.3", "203.0.113.5:5678")
	if ip := extractClientIP(req, engine.Config); ip != "203.0.113.5" {
		t.Fatalf("mapped CIDR-trusted peer must walk the chain, got %q", ip)
	}
	// A bare entry matches textually only: the mapped spelling of the
	// same address is NOT trusted (reference _proxy_matches equality).
	engine2, agent2 := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req2 := xffRequest("/api", "::ffff:192.0.2.1", "198.51.100.9")
	// Untrusted, so the canonical (unmapped) connecting address wins -
	// trust matching is textual, result canonicalization is not.
	if ip := extractClientIP(req2, engine2.Config); ip != "192.0.2.1" {
		t.Fatalf("a bare entry must match textually only, got %q", ip)
	}
	if findEvent(agent2, EventSuspiciousRequest) == nil {
		t.Fatalf("the textually-untrusted peer must trip the spoof gate, got %v", agent2.eventTypes())
	}
}

// TestExtractClientIPNoTrustedProxiesKeepsCanonicalPeer: without
// configured trusted proxies the canonical connecting address wins even
// with an XFF header (the preempted warning fires once).
func TestExtractClientIPNoTrustedProxiesKeepsCanonicalPeer(t *testing.T) {
	resetForwardedWarnings()
	engine, agent := newIPExtractionEngine(t, nil)
	req := xffRequest("/api", "::ffff:203.0.113.17", "198.51.100.77")
	if ip := extractClientIP(req, engine.Config); ip != "203.0.113.17" {
		t.Fatalf("canonical peer must win without trusted proxies, got %q", ip)
	}
	if findEvent(agent, EventSuspiciousRequest) != nil {
		t.Fatalf("agentless spoof arm without proxies must stay silent on events, got %v", agent.eventTypes())
	}
}

// TestExtractClientIPCacheWins: a cached identity short-circuits the
// resolution.
func TestExtractClientIPCacheWins(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req := xffRequest("/api", "192.0.2.1", "203.0.113.5")
	req.State().ClientIP = "198.51.100.1"
	if ip := extractClientIP(req, engine.Config); ip != "198.51.100.1" {
		t.Fatalf("cached identity must win, got %q", ip)
	}
}

// TestExtractClientIPNoPeer: a request without a connecting address keeps
// the empty identity (checks skip it downstream).
func TestExtractClientIPNoPeer(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"192.0.2.1"}
	})
	req := xffRequest("/api", "", "203.0.113.5")
	if ip := extractClientIP(req, engine.Config); ip != "" {
		t.Fatalf("a missing peer must not resolve, got %q", ip)
	}
}

// TestExtractClientIPRateLimitKeysOnResolvedIP proves the wiring reaches
// the rate limiter: behind a trusted proxy, the quota consumes the
// X-Forwarded-For client, not the proxy peer.
func TestExtractClientIPRateLimitKeysOnResolvedIP(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"10.0.0.1"}
		c.EnableRateLimiting = true
		c.RateLimit = 2
		c.RateLimitWindow = 60
	})
	clientA := xffRequest("/api", "10.0.0.1", "203.0.113.5")
	if resp := engine.Check(clientA); resp != nil {
		t.Fatalf("first client-A request must pass, got %+v", resp)
	}
	// A second request object, same resolved client, same proxy peer.
	if resp := engine.Check(xffRequest("/api", "10.0.0.1", "203.0.113.5")); resp != nil {
		t.Fatalf("second client-A request must pass, got %+v", resp)
	}
	blocked := engine.Check(xffRequest("/api", "10.0.0.1", "203.0.113.5"))
	if blocked == nil || blocked.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third client-A request must trip the quota, got %+v", blocked)
	}
	// A different forwarded client behind the same proxy has its own key.
	if resp := engine.Check(xffRequest("/api", "10.0.0.1", "203.0.113.6")); resp != nil {
		t.Fatalf("client B must not inherit client A's quota, got %+v", resp)
	}
	// The resolution cached into the request state is the XFF client.
	if got := clientA.State().ClientIP; got != "203.0.113.5" {
		t.Fatalf("state cache drifted: %q", got)
	}
}

// TestExtractClientIPBanKeysOnResolvedIP proves the penetration-detection
// autoban path bans the resolved client, not the proxy peer.
func TestExtractClientIPBanKeysOnResolvedIP(t *testing.T) {
	resetForwardedWarnings()
	engine, _ := newIPExtractionEngine(t, func(c *SecurityConfig) {
		c.TrustedProxies = []string{"10.0.0.1"}
		c.EnableIPBanning = true
		c.AutoBanThreshold = 1
		c.AutoBanDuration = 60
		c.EnableRateLimiting = false
	})
	// An SQL injection attempt from the forwarded client, seen through
	// the trusted proxy: detection attributes the violation to the
	// resolved identity and the threshold ban applies to it.
	req := NewRequestFactory().CreateRequest(RequestOptions{
		Path:       "/api",
		Scheme:     "http",
		Host:       "example.com",
		Method:     "GET",
		ClientHost: "10.0.0.1",
		Header:     map[string]string{"X-Forwarded-For": "203.0.113.5"},
		QueryParams: map[string]string{
			"id": "1 UNION SELECT username, password FROM users--",
		},
	})
	if resp := engine.Check(req); resp == nil {
		t.Fatal("the injection attempt must block")
	}
	if !engine.Ban.IsIPBanned("203.0.113.5") {
		t.Fatal("the forwarded client must be the banned identity")
	}
	if engine.Ban.IsIPBanned("10.0.0.1") {
		t.Fatal("the proxy peer must not be banned")
	}
}

// TestDisplayForwardedChainRedactsUnparseableHops pins the display-chain
// redaction the spoof reason quotes (parseable hops keep their original
// spacing, unparseable ones collapse to the placeholder).
func TestDisplayForwardedChainRedactsUnparseableHops(t *testing.T) {
	got := displayForwardedChain("203.0.113.5, <script>, 198.51.100.9:8123")
	want := "203.0.113.5,[REDACTED], 198.51.100.9:8123"
	if got != want {
		t.Fatalf("display chain drifted: %q, want %q", got, want)
	}
}

// TestIsTrustedProxyUnit pins the trust table.
func TestIsTrustedProxyUnit(t *testing.T) {
	proxies := []string{"10.0.0.0/8", "192.0.2.1"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"192.0.2.1", true},
		{"192.0.2.2", false},
		{"11.0.0.1", false},
		{"not-an-ip", false},
	}
	for _, tc := range cases {
		if got := isTrustedProxy(tc.ip, proxies); got != tc.want {
			t.Fatalf("isTrustedProxy(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestForwardedHeaderCandidateUnit pins depth selection and the port
// strip.
func TestForwardedHeaderCandidateUnit(t *testing.T) {
	if _, ok := forwardedHeaderCandidate("1.1.1.1", 2); ok {
		t.Fatal("a one-entry chain has no depth-2 candidate")
	}
	candidate, ok := forwardedHeaderCandidate(" 1.1.1.1, 2.2.2.2:99 ", 1)
	if !ok || candidate != "2.2.2.2" {
		t.Fatalf("depth-1 candidate drifted: %q ok=%v", candidate, ok)
	}
	if got := extractFromForwardedHeader("1.1.1.1, [::1]:8443", 1); got != "::1" {
		t.Fatalf("bracketed IPv6 hop must canonicalize: %q", got)
	}
}

// TestResolveForwardedChainRightToLeftUnit pins the walk and the
// all-trusted/malformed outcomes.
func TestResolveForwardedChainRightToLeftUnit(t *testing.T) {
	proxies := []string{"10.0.0.0/8"}
	if got := resolveForwardedChainRightToLeft(forwardedHeaderIPs("203.0.113.5, 10.0.0.9"), proxies); got != "203.0.113.5" {
		t.Fatalf("walk drifted: %q", got)
	}
	if got := resolveForwardedChainRightToLeft(forwardedHeaderIPs("10.0.0.1, 10.0.0.9"), proxies); got != "" {
		t.Fatalf("an all-trusted chain resolves to nothing, got %q", got)
	}
	if got := resolveForwardedChainRightToLeft(forwardedHeaderIPs("10.0.0.1, b@d"), proxies); got != "" {
		t.Fatalf("a malformed non-trusted hop resolves to nothing, got %q", got)
	}
}

// TestForwardedWarningsOncePerProcess pins the once-only warning gates.
func TestForwardedWarningsOncePerProcess(t *testing.T) {
	resetForwardedWarnings()
	var b strings.Builder
	oldWriter := log.Default().Writer()
	log.SetOutput(&b)
	defer log.SetOutput(oldWriter)

	warnForwardedHeaderChainTooShort("203.0.113.5", 1)
	warnForwardedHeaderChainTooShort("198.51.100.9", 1)
	warnForwardedHeaderSelectedEntryTrustedProxy("192.0.2.2")
	warnForwardedHeaderDepthOvercountsHops(2, "203.0.113.5, 198.51.100.9")
	warnForwardedHeaderPreempted("203.0.113.17", "203.0.113.17, 198.51.100.9")
	warnForwardedHeaderPreempted("198.51.100.1", "198.51.100.1")
	warnForwardedHeaderPreempted("203.0.113.20", "") // no chain: never warns

	out := b.String()
	if n := strings.Count(out, "fewer than the"); n != 1 {
		t.Fatalf("chain-too-short must warn once, got %d\n%s", n, out)
	}
	if n := strings.Count(out, "itself listed in trusted_proxies"); n != 1 {
		t.Fatalf("selected-entry warning must fire once, got %d\n%s", n, out)
	}
	if n := strings.Count(out, "over-counts the"); n != 1 {
		t.Fatalf("over-count warning must fire once, got %d\n%s", n, out)
	}
	if n := strings.Count(out, "already appears inside its own"); n != 1 {
		t.Fatalf("preempted warning must fire once for the first qualifying pair, got %d\n%s", n, out)
	}
}
