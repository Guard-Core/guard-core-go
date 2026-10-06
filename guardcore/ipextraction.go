package guardcore

import (
	"log"
	"net/netip"
	"strings"
	"sync"
)

// Trusted-proxy client IP extraction, the line-by-line port of the
// reference guard_core/_utils/ip_extraction.py: when the direct peer is a
// configured trusted proxy (CIDR-aware), the X-Forwarded-For chain is
// resolved right-to-left under trusted_proxy_depth; an untrusted peer with
// a forwarded chain is a spoof attempt (suspicious_request, handler
// ip_extraction); every downstream consumer (rate limits, bans, geo,
// behavioral keys) keys on the resolved identity through the
// RequestState.ClientIP cache.

// proxyMatches mirrors _proxy_matches: a CIDR entry matches by prefix
// membership, a bare entry matches by exact text equality with the
// connecting address.
func proxyMatches(connectingIP string, connectingIPObj netip.Addr, proxy string) bool {
	if strings.Contains(proxy, "/") {
		prefix, err := netip.ParsePrefix(proxy)
		if err != nil {
			return false
		}
		return prefix.Contains(connectingIPObj) || prefix.Contains(connectingIPObj.Unmap())
	}
	return connectingIP == proxy
}

// isTrustedProxy mirrors _is_trusted_proxy: an unparseable connecting
// address is never trusted (the reference catches ValueError and returns
// False).
func isTrustedProxy(connectingIP string, trustedProxies []string) bool {
	addr, err := netip.ParseAddr(connectingIP)
	if err != nil {
		return false
	}
	for _, proxy := range trustedProxies {
		if proxyMatches(connectingIP, addr, proxy) {
			return true
		}
	}
	return false
}

// forwardedHeaderCandidateHasMetachar mirrors
// _forwarded_header_candidate_has_metachar: a hop carrying glob or bracket
// metacharacters is malformed input, never an address.
func forwardedHeaderCandidateHasMetachar(candidate string) bool {
	return strings.ContainsAny(candidate, `*?[]\`)
}

// forwardedHeaderCandidateAddr mirrors _forwarded_header_candidate_addr.
func forwardedHeaderCandidateAddr(candidate string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(candidate)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// forwardedHeaderCandidate mirrors _forwarded_header_candidate: the entry
// trusted_proxy_depth selects counting from the right (1-based), port
// stripped. A chain shorter than the depth has no candidate.
func forwardedHeaderCandidate(forwardedFor string, proxyDepth int) (string, bool) {
	ips := forwardedHeaderIPs(forwardedFor)
	if len(ips) < proxyDepth {
		return "", false
	}
	return ips[len(ips)-proxyDepth], true
}

// extractFromForwardedHeader mirrors _extract_from_forwarded_header: the
// depth-selected entry canonicalized, or "" when the chain is empty, too
// short, unparseable, or carries metacharacters.
func extractFromForwardedHeader(forwardedFor string, proxyDepth int) string {
	if forwardedFor == "" {
		return ""
	}
	candidate, ok := forwardedHeaderCandidate(forwardedFor, proxyDepth)
	if !ok {
		return ""
	}
	addr, ok := forwardedHeaderCandidateAddr(candidate)
	if !ok {
		return ""
	}
	if forwardedHeaderCandidateHasMetachar(candidate) {
		return ""
	}
	return canonicalIPText(addr)
}

// forwardedHeaderIPs mirrors _forwarded_header_ips: every comma-separated
// entry trimmed and port-stripped.
func forwardedHeaderIPs(forwardedFor string) []string {
	parts := strings.Split(forwardedFor, ",")
	ips := make([]string, 0, len(parts))
	for _, ip := range parts {
		ips = append(ips, stripForwardedEntryPort(strings.TrimSpace(ip)))
	}
	return ips
}

// forwardedHeaderRightSideUnlistedCount mirrors
// _forwarded_header_right_side_unlisted_count: how many entries to the
// right of the depth-selected one are NOT configured trusted proxies.
func forwardedHeaderRightSideUnlistedCount(ips []string, proxyDepth int, trustedProxies []string) int {
	start := len(ips) - proxyDepth + 1
	if start < 0 {
		start = 0
	}
	count := 0
	for _, entry := range ips[start:] {
		if !isTrustedProxy(CanonicalizeIP(entry), trustedProxies) {
			count++
		}
	}
	return count
}

// resolveForwardedChainRightToLeft mirrors
// _resolve_forwarded_chain_right_to_left: the rightmost non-trusted hop is
// the client; "" (None) when every hop is trusted or a non-trusted hop is
// malformed.
func resolveForwardedChainRightToLeft(ips []string, trustedProxies []string) string {
	for i := len(ips) - 1; i >= 0; i-- {
		entry := ips[i]
		if isTrustedProxy(CanonicalizeIP(entry), trustedProxies) {
			continue
		}
		addr, ok := forwardedHeaderCandidateAddr(entry)
		if !ok || forwardedHeaderCandidateHasMetachar(entry) {
			return ""
		}
		return canonicalIPText(addr)
	}
	return ""
}

// isPrivateOrLoopback mirrors _is_private_or_loopback: private, loopback,
// or link-local addresses downgrade the spoof warning to debug level.
func isPrivateOrLoopback(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// displayForwardedChain mirrors _display_forwarded_chain: parseable hops
// stay as written, unparseable ones collapse to [REDACTED].
func displayForwardedChain(value string) string {
	var displayed []string
	for _, part := range strings.Split(value, ",") {
		candidate := stripForwardedEntryPort(strings.TrimSpace(part))
		if _, ok := forwardedHeaderCandidateAddr(candidate); ok {
			displayed = append(displayed, part)
		} else {
			displayed = append(displayed, RedactedPlaceholder)
		}
	}
	return strings.Join(displayed, ",")
}

// The warning gates mirror the reference's module-level
// _forwarded_header_*_warned flags: each drift condition logs exactly one
// warning per process, quoting the first triggering arguments.
var (
	forwardedHeaderPreemptedOnce  sync.Once
	forwardedHeaderTooShortOnce   sync.Once
	forwardedHeaderSelectedOnce   sync.Once
	forwardedHeaderOvercountsOnce sync.Once
)

// warnForwardedHeaderPreempted mirrors _warn_forwarded_header_preempted:
// the connecting address already appearing inside its own X-Forwarded-For
// chain means the application server resolved the client before
// guard-core ran; a rotating chain defeats rate limiting and banning.
// The first qualifying pair is what the single warning quotes.
func warnForwardedHeaderPreempted(connectingIP, forwardedFor string) {
	if forwardedFor == "" {
		return
	}
	for _, entry := range strings.Split(forwardedFor, ",") {
		if strings.TrimSpace(entry) != connectingIP {
			continue
		}
		forwardedHeaderPreemptedOnce.Do(func() {
			log.Printf(
				"The connecting IP (%s) already appears inside its own "+
					"X-Forwarded-For chain: the application server resolved the client "+
					"from that header before guard-core ran. While it is, the address "+
					"guard-core sees is whatever the client claimed, so a rotating "+
					"X-Forwarded-For defeats rate limiting and IP banning. Declare the "+
					"proxy via trusted_proxies / trusted_proxy_depth so guard-core "+
					"resolves the real client itself. If enforce_https is also used, "+
					"set TrustXForwardedProto with the same trusted_proxies, otherwise "+
					"HTTPS detection breaks on TLS-terminating hosts. This warning is "+
					"logged once.",
				sanitizeForLog(connectingIP),
			)
		})
		return
	}
}

// warnForwardedHeaderChainTooShort mirrors
// _warn_forwarded_header_chain_too_short.
func warnForwardedHeaderChainTooShort(forwardedFor string, chainLength int) {
	forwardedHeaderTooShortOnce.Do(func() {
		log.Printf(
			"The X-Forwarded-For chain has only %d entries, fewer than the "+
				"configured trusted_proxy_depth; chain was %s; falling back to the "+
				"connecting peer as the client. This warning is logged once.",
			chainLength,
			sanitizeForLog(displayForwardedChain(forwardedFor)),
		)
	})
}

// warnForwardedHeaderSelectedEntryTrustedProxy mirrors
// _warn_forwarded_header_selected_entry_trusted_proxy.
func warnForwardedHeaderSelectedEntryTrustedProxy(entry string) {
	forwardedHeaderSelectedOnce.Do(func() {
		log.Printf(
			"trusted_proxy_depth selected %s from the X-Forwarded-For chain, "+
				"but that address is itself listed in trusted_proxies; the chain "+
				"likely has more proxy hops than trusted_proxy_depth accounts for. "+
				"This warning is logged once.",
			sanitizeForLog(entry),
		)
	})
}

// warnForwardedHeaderDepthOvercountsHops mirrors
// _warn_forwarded_header_depth_overcounts_hops.
func warnForwardedHeaderDepthOvercountsHops(unlistedRightEntries int, forwardedFor string) {
	forwardedHeaderOvercountsOnce.Do(func() {
		log.Printf(
			"trusted_proxy_depth selected an entry from the X-Forwarded-For "+
				"chain with %d entry/entries to its right that are not listed in "+
				"trusted_proxies; chain was %s; the declared depth over-counts the "+
				"real proxy hops. Set trusted_proxy_depth to the number of proxies "+
				"that append to X-Forwarded-For. This warning is logged once.",
			unlistedRightEntries,
			sanitizeForLog(displayForwardedChain(forwardedFor)),
		)
	})
}

// handleUntrustedProxy mirrors _handle_untrusted_proxy: the spoof warning
// (debug level for private/loopback peers, warning otherwise) plus the
// handler-direct suspicious_request event, then the canonical peer wins.
func handleUntrustedProxy(cfg *SecurityConfig, req Request, connectingIP, canonicalConnectingIP, forwardedFor string) string {
	if forwardedFor != "" {
		warnForwardedHeaderPreempted(connectingIP, forwardedFor)
		displayForwardedFor := displayForwardedChain(forwardedFor)
		message := "Potential IP spoof attempt: X-Forwarded-For header " +
			displayForwardedFor + " received from untrusted IP " + connectingIP
		if isPrivateOrLoopback(connectingIP) {
			log.Printf("[debug] %s", sanitizeForLog(message))
		} else {
			log.Printf("[warning] %s", sanitizeForLog(message))
		}
		if bus := busFor(cfg); bus != nil {
			bus.SendHandlerEventRequest(EventSuspiciousRequest, "ip_extraction", req,
				"spoofing_detected",
				"Potential IP spoof attempt: X-Forwarded-For header "+displayForwardedFor,
				"", nil)
		}
	}
	return canonicalConnectingIP
}

// resolveClientIPFromForwardedChain mirrors
// _resolve_client_ip_from_forwarded_chain: the depth-selected hop wins;
// a depth that over-counts hops falls back to the right-to-left walk; a
// chain shorter than the depth, a malformed resolution, or an all-trusted
// chain keep the connecting peer.
func resolveClientIPFromForwardedChain(canonicalConnectingIP, forwardedFor string, proxyDepth int, trustedProxies []string) string {
	if forwardedFor == "" {
		return canonicalConnectingIP
	}

	ips := forwardedHeaderIPs(forwardedFor)
	chainLength := len(ips)

	if chainLength < proxyDepth {
		warnForwardedHeaderChainTooShort(forwardedFor, chainLength)
		return canonicalConnectingIP
	}

	if len(trustedProxies) > 0 {
		unlistedRightEntries := forwardedHeaderRightSideUnlistedCount(ips, proxyDepth, trustedProxies)
		if unlistedRightEntries > 0 {
			warnForwardedHeaderDepthOvercountsHops(unlistedRightEntries, forwardedFor)
			resolved := resolveForwardedChainRightToLeft(ips, trustedProxies)
			if resolved != "" {
				return resolved
			}
			return canonicalConnectingIP
		}
	}

	clientIP := extractFromForwardedHeader(forwardedFor, proxyDepth)
	if clientIP != "" {
		if isTrustedProxy(clientIP, trustedProxies) {
			warnForwardedHeaderSelectedEntryTrustedProxy(clientIP)
		}
		return clientIP
	}

	return canonicalConnectingIP
}

// extractClientIP mirrors extract_client_ip: the cached identity wins,
// a missing peer falls back to empty (walking the chain only under the
// reference's unix-socket convention), an untrusted peer with a forwarded
// chain is a spoof attempt, and a trusted peer runs the chain walk. The
// resolution caches into RequestState.ClientIP so every downstream
// consumer (rate limits, bans, geo, behavioral keys) keys on one identity.
func extractClientIP(req Request, cfg *SecurityConfig) string {
	state := req.State()
	if state != nil && state.ClientIP != "" {
		return state.ClientIP
	}

	host := req.ClientHost()
	if host == "" {
		forwardedFor := headerForwardedFor(req)
		if containsEntry(cfg.TrustedProxies, "unix") {
			return resolveClientIPFromForwardedChain(
				UnknownClientIdentity, forwardedFor,
				cfg.TrustedProxyDepth, cfg.TrustedProxies,
			)
		}
		return ""
	}

	connectingIP := host
	canonicalConnectingIP := CanonicalizeIP(connectingIP)
	forwardedFor := headerForwardedFor(req)

	if len(cfg.TrustedProxies) == 0 {
		warnForwardedHeaderPreempted(connectingIP, forwardedFor)
		return canonicalConnectingIP
	}

	if !isTrustedProxy(connectingIP, cfg.TrustedProxies) {
		resolved := handleUntrustedProxy(cfg, req, connectingIP, canonicalConnectingIP, forwardedFor)
		if state != nil {
			state.ClientIP = resolved
		}
		return resolved
	}

	resolved := resolveClientIPFromForwardedChain(
		canonicalConnectingIP, forwardedFor,
		cfg.TrustedProxyDepth, cfg.TrustedProxies,
	)
	if state != nil {
		state.ClientIP = resolved
	}
	return resolved
}

// headerForwardedFor reads the X-Forwarded-For chain from the request
// headers.
func headerForwardedFor(req Request) string {
	forwarded, _ := req.Headers().Get("X-Forwarded-For")
	return forwarded
}

// containsEntry answers exact string membership.
func containsEntry(entries []string, want string) bool {
	for _, entry := range entries {
		if entry == want {
			return true
		}
	}
	return false
}
