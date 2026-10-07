package guardcore

import (
	"log"
	"net/netip"
)

// The websocket handshake guard, mirroring fastapi-guard's
// guard/websocket.py (guard_websocket / make_guard_websocket): the six
// close reasons, the handshake check sequence (identity, ban, IP
// allow-list, the "ws" rate limit, shared-counts penetration detection)
// and the fail-open / fail-secure redis containment.

// WebSocket close codes, the reference status.WS_1008_POLICY_VIOLATION
// and status.WS_1013_TRY_AGAIN_LATER.
const (
	WebSocketClosePolicyViolation = 1008
	WebSocketCloseTryAgainLater   = 1013
)

// WebSocketCloseReason is the close verdict a websocket guard hands the
// adapter: the handshake closes with this code and reason. The reference
// carries the same pair as WebSocketCloseReason(code, reason).
type WebSocketCloseReason struct {
	Code   int
	Reason string
}

// The reference WS_CLOSE_* table (guard/websocket.py).
var (
	WSCloseIPBanned             = WebSocketCloseReason{WebSocketClosePolicyViolation, "IP banned"}
	WSCloseIPNotAllowed         = WebSocketCloseReason{WebSocketClosePolicyViolation, "IP not allowed"}
	WSCloseRateLimitExceeded    = WebSocketCloseReason{WebSocketClosePolicyViolation, "Rate limit exceeded"}
	WSCloseClientAddressUnknown = WebSocketCloseReason{WebSocketClosePolicyViolation, "Client address could not be determined"}
	WSCloseSecurityCheckFailed  = WebSocketCloseReason{WebSocketCloseTryAgainLater, "Security check failed"}
	WSCloseSuspiciousActivity   = WebSocketCloseReason{WebSocketClosePolicyViolation, "Suspicious activity detected"}
)

// wsDetectionCheckFailedStatusCode is the reference
// _DETECTION_CHECK_FAILED_STATUS_CODE: a 500 from the detection pipeline
// means the check itself malfunctioned (fail-secure), which closes with
// the try-again-later reason instead of the suspicious-activity one.
const wsDetectionCheckFailedStatusCode = 500

// GuardWebSocket runs the reference websocket handshake checks
// (_run_websocket_checks, fastapi-guard guard/websocket.py): identity
// resolution, the fail-secure unknown-address close, the ban check, the
// is_ip_allowed verdict, the "ws"-endpoint rate limit for
// non-whitelisted IPs, and the penetration detection pass over the
// handshake request with the HTTP pipeline's suspicious counts.
//
// The adapter builds the Request with Method "WEBSOCKET" and an empty
// body (the reference _WebSocketGuardRequest) over a fresh RequestState
// and closes the handshake with the returned reason; nil allows the
// upgrade.
//
// Redis containment mirrors _guarded_redis_call where the Go surface can
// observe an error: the rate limit honors redis_fail_open (warn + allow)
// and fail_secure (error log + 1013 close). The ban probe's Go surface is
// bool-only and resolves Redis failures fail-open (checkRedisExact), so
// it always behaves like the redis_fail_open arm.
func (e *Engine) GuardWebSocket(req Request) *WebSocketCloseReason {
	cfg := e.Config
	e.resolveClientIdentity(req)
	ip := resolveClientIP(req)

	if ip == "" && cfg.FailSecure {
		return &WSCloseClientAddressUnknown
	}

	if e.Ban != nil && e.Ban.IsIPBanned(ip) {
		return &WSCloseIPBanned
	}

	if !e.webSocketIPAllowed(ip) {
		return &WSCloseIPNotAllowed
	}

	state := req.State()
	whitelisted := ip != "" && len(cfg.Whitelist) > 0
	state.IsWhitelisted = whitelisted

	if ip != "" && len(cfg.Whitelist) == 0 {
		if cfg.EnableRedis && !e.Redis.connected() {
			// The reference make_guard_websocket warns once when
			// enable_redis is set without a usable handler; the Go analogue
			// is the engine's redis manager never having connected.
			e.wsRedisWarn.Do(func() {
				log.Printf("enable_redis=True but the engine's redis manager is not connected; the websocket rate limit uses the in-memory store")
			})
		}
		allowed, err := e.RateLimit.CheckRateLimitByIP(ip, "ws")
		if err != nil {
			// The reference _guarded_redis_call's fail-open arm lives inside
			// the rate limit manager (redisRequestCount contains the error
			// behind redis_fail_open with the in-memory fallback warning), so
			// an error surfaced here reaches the fail-secure decision
			// directly.
			log.Printf("Error in check_rate_limit_by_ip: %v", err)
			if cfg.FailSecure {
				log.Printf("Blocking websocket handshake due to check_rate_limit_by_ip error in fail-secure mode")
				return &WSCloseSecurityCheckFailed
			}
			allowed = true
		}
		if !allowed {
			return &WSCloseRateLimitExceeded
		}
	}

	return e.guardWebSocketDetection(req)
}

// webSocketIPAllowed mirrors is_ip_allowed (check_ip_access with no skip
// flags, guard_core/_utils/access_control.py): the unknown-identity rule,
// the global IP lists with the whitelist gate, the country stage with the
// loopback exemption (cleared by a global whitelist match), the
// cloud-provider stage, an unparseable address denied like the
// reference's ValueError arm.
func (e *Engine) webSocketIPAllowed(ip string) bool {
	cfg := e.Config
	if ip == "" {
		// _check_unknown_identity_access: an unknown identity passes only
		// when neither the IP whitelist nor the country whitelist can deny.
		return len(cfg.Whitelist) == 0 && len(cfg.WhitelistCountries) == 0
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		// The reference ip_address(ip) ValueError denies.
		return false
	}
	if len(cfg.Whitelist) > 0 {
		// A whitelist match skips the country stage (_ip_in_list ->
		// skip_countries); a miss denies outright.
		return ipMatchesList(ip, cfg.Whitelist)
	}
	if len(cfg.Blacklist) > 0 && ipMatchesList(ip, cfg.Blacklist) {
		return false
	}
	if (len(cfg.BlockedCountries) > 0 || len(cfg.WhitelistCountries) > 0) && cfg.GeoIPHandler != nil {
		if !isLoopbackIP(ip) {
			country, ok := cfg.GeoIPHandler.GetCountry(ip)
			if !ok || country == "" {
				// No geolocation denies under a country allowlist.
				if len(cfg.WhitelistCountries) > 0 {
					return false
				}
			} else if len(cfg.WhitelistCountries) > 0 {
				if !containsCountry(cfg.WhitelistCountries, country) {
					return false
				}
			} else if containsCountry(cfg.BlockedCountries, country) {
				return false
			}
		}
	}
	if len(cfg.BlockCloudProviders) > 0 && e.Cloud != nil && e.Cloud.IsCloudIP(ip, cfg.BlockCloudProviders) {
		return false
	}
	return true
}

// guardWebSocketDetection mirrors _run_penetration_detection: the path
// exclusion scoping, then a single-check pipeline over the suspicious
// activity check sharing the HTTP pipeline's counts store (the reference
// _resolve_shared_suspicious_counts hands the HTTP middleware's
// suspicious_request_counts dict to the detection middleware; here both
// checks are built over the same store). The detection check runs with an
// inert event stream (the reference builds its detection middleware over
// SecurityEventBus with a None agent handler, so detection-time
// penetration_attempt events go nowhere); the on_block hook and the ban
// escalation stay live. A 500 from the pipeline means the check itself
// failed (fail-secure) and closes try-again-later; any other block closes
// policy-violation suspicious.
func (e *Engine) guardWebSocketDetection(req Request) *WebSocketCloseReason {
	if e.suspiciousCounts == nil {
		return nil
	}
	check := &suspiciousActivityCheck{cfg: e.Config, ban: e.Ban, counts: e.suspiciousCounts, inertBus: true}
	if e.exclusions.matches(req.URLPath()) {
		req.State().ExclusionScoped = true
	}
	pipeline := NewSecurityCheckPipeline([]SecurityCheck{check}, e.Config, nil)
	if resp := pipeline.Execute(req); resp != nil {
		if resp.StatusCode == wsDetectionCheckFailedStatusCode {
			return &WSCloseSecurityCheckFailed
		}
		return &WSCloseSuspiciousActivity
	}
	return nil
}

// isLoopbackIP mirrors _is_loopback: unparseable addresses are not
// loopback.
func isLoopbackIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}
