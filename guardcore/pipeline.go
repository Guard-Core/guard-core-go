package guardcore

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

const (
	IPBanBlockedStatus    = 403
	IPBanBlockedMessage   = "IP address banned"
	RestrictionBlockedMsg = "Forbidden"
	SuspiciousBlockedMsg  = "Suspicious activity detected"
	SuspiciousBannedMsg   = "IP has been banned"
)

var onBlockExcludedCheckNames = map[string]bool{
	"custom_request": true, "custom_validators": true, "https_enforcement": true,
}

type SecurityCheck interface {
	CheckName() string
	AppliesTo(cfg *SecurityConfig) bool
	EnforcedOnExcludedPaths() bool
	Check(req Request) *Response
}

type unsupportedCheck struct {
	name     string
	excluded bool
	applies  func(cfg *SecurityConfig) bool
}

func (c *unsupportedCheck) CheckName() string                  { return c.name }
func (c *unsupportedCheck) EnforcedOnExcludedPaths() bool      { return c.excluded }
func (c *unsupportedCheck) AppliesTo(cfg *SecurityConfig) bool { return c.applies(cfg) }
func (c *unsupportedCheck) Check(req Request) *Response {
	panic(&UnsupportedFeatureError{
		Feature: c.name,
		Reason:  "check reached execution although the port does not implement it yet",
	})
}

type ipSecurityCheck struct {
	cfg  *SecurityConfig
	ban  *IPBanManager
	name string
}

func (c *ipSecurityCheck) CheckName() string                  { return c.name }
func (c *ipSecurityCheck) EnforcedOnExcludedPaths() bool      { return true }
func (c *ipSecurityCheck) AppliesTo(cfg *SecurityConfig) bool { return true }

func (c *ipSecurityCheck) Check(req Request) *Response {
	cfg := c.cfg
	state := req.State()
	ip := resolveClientIP(req)
	if ip == "" {
		return nil
	}
	if !state.HasBypass("ip_ban") && c.ban != nil && c.ban.IsIPBanned(ip) {
		// The hook payload carries the reference log-format reason with an
		// empty trigger_info (the reference checks pass no trigger_info to
		// log_activity, and its non-passive stash therefore holds "").
		reason := fmt.Sprintf("Banned IP attempted access: %s", ip)
		stashBlock(state, reason, "")
		if cfg.PassiveMode {
			firePassiveBlockHook(cfg, req, c.CheckName(), reason, "")
			return nil
		}
		return createErrorResponse(cfg, 403, IPBanBlockedMessage)
	}
	if state.ExclusionScoped {
		// The reference passes route_config=None on the exclusion-scoped
		// path (IpSecurityCheck.check), so no route IP or country rules run
		// there and the global lists decide alone.
		return c.checkGlobal(req, ip, false, false)
	}
	if state.HasBypass("ip") {
		return nil
	}
	route := state.RouteConfig
	routeOverridesIPLists := false
	skipCountries := false
	if route != nil {
		if resp := c.checkRouteIPAccess(req, ip, route); resp != nil {
			return resp
		}
		routeOverridesIPLists = len(route.IPWhitelist) > 0
		// A route allow_countries match clears the global country stage for
		// the request, exactly like the route IP whitelist clears the global
		// IP lists (the reference _route_country_whitelist_matched).
		skipCountries = routeCountryAccess(ip, route, cfg.GeoIPHandler) == countryAllowed
	}
	return c.checkGlobal(req, ip, routeOverridesIPLists, skipCountries)
}

// checkRouteIPAccess mirrors check_route_ip_access (the reference
// guard_core/core/checks/helpers.py plus its TypeScript port
// checkRouteIpAccess): the route blacklist is consulted first so its matches
// are denied before any whitelist verdict can clear them, a configured
// route whitelist takes over the route verdict (a miss denies, a match
// passes the route stage), and the route country verdict combines with the
// IP verdict: any deny denies, otherwise any allow passes. The global lists
// are still enforced afterwards by checkGlobal, so a route whitelist match
// never relaxes the global blacklist or the global whitelist gate; it only
// clears the identity flags.
func (c *ipSecurityCheck) checkRouteIPAccess(req Request, ip string, route *RouteConfig) *Response {
	ipBlocked := false
	if len(route.IPBlacklist) > 0 && ipMatchesList(ip, route.IPBlacklist) {
		ipBlocked = true
	} else if len(route.IPWhitelist) > 0 && !ipMatchesList(ip, route.IPWhitelist) {
		ipBlocked = true
	}
	verdict, country, ruleType := routeCountryAccessDetail(ip, route, c.cfg.GeoIPHandler)
	if verdict == countryDenied {
		// The reference emits country_blocked from IPInfoManager
		// .check_country_access (guard_core/handlers/ipinfo_handler.py) with
		// the matched rule's reason, action and rule_type.
		reason := fmt.Sprintf("Country %s is blocked", country)
		if ruleType == "country_whitelist" {
			reason = fmt.Sprintf("Country %s not in allowed list", country)
		}
		fireGeoEvent(c.cfg, GeoEvent{
			EventType:   EventCountryBlocked,
			IPAddress:   ip,
			ActionTaken: "request_blocked",
			Reason:      reason,
			Country:     country,
			RuleType:    ruleType,
			HandlerName: ipinfoHandlerName,
		})
		ipBlocked = true
	}
	if ipBlocked {
		// The reference ip_security route-denial path emits
		// decorator_violation (ip_security.py _classify_route_ip_denial plus
		// emit_access_denied_event) before the 403.
		decoratorType, violationType := classifyRouteIPDenial(route, c.cfg.GeoIPHandler, ip)
		fireGeoEvent(c.cfg, GeoEvent{
			EventType:   EventDecoratorViolation,
			IPAddress:   ip,
			ActionTaken: "request_blocked",
			Reason:      fmt.Sprintf("IP %s blocked", ip),
			HandlerName: ipinfoHandlerName,
			Metadata: map[string]any{
				"decorator_type": decoratorType,
				"violation_type": violationType,
				"passive_mode":   c.cfg.PassiveMode,
			},
		})
		return c.denyRoute(req, ip)
	}
	return nil
}

// classifyRouteIPDenial mirrors _classify_route_ip_denial
// (guard_core/core/checks/implementations/ip_security.py): an IP-list deny
// or a non-country route deny reports access_control/ip_restriction; a
// country-only deny reports block_countries or allow_countries with the
// country_restriction violation type.
func classifyRouteIPDenial(route *RouteConfig, resolver CountryResolver, ip string) (string, string) {
	verdict, _, _ := routeCountryAccessDetail(ip, route, resolver)
	if verdict != countryDenied || len(route.IPWhitelist) > 0 || len(route.IPBlacklist) > 0 {
		return "access_control", "ip_restriction"
	}
	if len(route.BlockedCountries) > 0 {
		if country, ok := resolver.GetCountry(ip); ok && country != "" && containsCountry(route.BlockedCountries, country) {
			return "block_countries", "country_restriction"
		}
	}
	return "allow_countries", "country_restriction"
}

// fireGeoEvent dispatches a GeoEvent to the config's OnGeoEvent hook (the Go
// stand-in for the reference event bus), recovering from a panicking hook
// like fireBlockHook does.
func fireGeoEvent(cfg *SecurityConfig, ev GeoEvent) {
	// The bus forwards the geo event family handler-direct (ipinfo/cloud),
	// bypassing the agent_enable_events gate exactly like the reference.
	emitGeoEventToBus(cfg, ev)
	if cfg == nil || cfg.OnGeoEvent == nil {
		return
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("on_geo_event hook raised: %v", r)
			}
		}()
		cfg.OnGeoEvent(ev)
	}()
}

func (c *ipSecurityCheck) denyRoute(req Request, ip string) *Response {
	reason := fmt.Sprintf("IP not allowed by route config: %s", ip)
	stashBlock(req.State(), reason, "")
	if c.cfg.PassiveMode {
		firePassiveBlockHook(c.cfg, req, c.CheckName(), reason, "")
		return nil
	}
	return createErrorResponse(c.cfg, 403, RestrictionBlockedMsg)
}

// countryVerdict mirrors the True/False/None returns of the reference
// check_country_access: denied, allowed, or no verdict (no rules or no
// resolver).
type countryVerdict int8

const (
	countryNoRules countryVerdict = iota
	countryDenied
	countryAllowed
)

// routeCountryAccess answers the plain verdict of routeCountryAccessDetail.
func routeCountryAccess(ip string, route *RouteConfig, resolver CountryResolver) countryVerdict {
	verdict, _, _ := routeCountryAccessDetail(ip, route, resolver)
	return verdict
}

// routeCountryAccessDetail mirrors check_country_access
// (guard_core/core/checks/helpers.py): the route blocked_countries list
// denies its match, a route whitelist_countries list answers membership
// outright (an unresolved country denies), anything else stays neutral.
// Unlike the global country stage there is no loopback exemption here,
// exactly like the reference. The extra returns carry the country and the
// matched rule type ("country_blacklist" / "country_whitelist") the
// reference country_blocked event reports; the unresolved-country deny
// under an allowlist reports no rule type (the reference check_country_access
// returns False there without emitting).
func routeCountryAccessDetail(ip string, route *RouteConfig, resolver CountryResolver) (countryVerdict, string, string) {
	if resolver == nil || route == nil {
		return countryNoRules, "", ""
	}
	country := ""
	resolved := false
	if len(route.BlockedCountries) > 0 {
		if code, ok := resolver.GetCountry(ip); ok {
			country, resolved = code, true
			if code != "" && containsCountry(route.BlockedCountries, code) {
				return countryDenied, code, "country_blacklist"
			}
		}
	}
	if len(route.WhitelistCountries) > 0 {
		if !resolved {
			country, resolved = resolver.GetCountry(ip)
		}
		if !resolved || country == "" {
			return countryDenied, "", ""
		}
		if containsCountry(route.WhitelistCountries, country) {
			return countryAllowed, country, ""
		}
		return countryDenied, country, "country_whitelist"
	}
	return countryNoRules, "", ""
}

// checkGlobal mirrors the reference _resolve_global_ip_access plus
// check_ip_access (guard_core/_utils/access_control.py): the global IP
// lists decide first, then the country stage (skipped for a global
// whitelist match or a route allow_countries match), then the exempt flag
// is only set once every deny check passed.
func (c *ipSecurityCheck) checkGlobal(req Request, ip string, routeOverridesIPLists, skipCountries bool) *Response {
	state := req.State()
	whitelist := c.cfg.Whitelist
	blacklist := c.cfg.Blacklist
	// exempt_ips only ever sets a flag after every deny check passed: it must
	// never open the whitelist gate or add a deny path of its own (parity with
	// guard-core's _resolve_is_exempt, which gates on the allowed verdict).
	// A route-level IPWhitelist overrides the global lists for the identity
	// flags exactly like the reference skip_ip_lists gate
	// (_resolve_is_whitelisted/_resolve_is_exempt): both flags stay unset for
	// the request even when the IP passes.
	if len(whitelist) > 0 {
		if !ipMatchesList(ip, whitelist) {
			return c.deny(req, ip, genericListBlockReason(ip))
		}
		state.IsWhitelisted = !routeOverridesIPLists
		state.IsExempt = !routeOverridesIPLists && ipMatchesList(ip, c.cfg.ExemptIPs)
		// A global whitelist match skips the country stage (the reference
		// sets skip_countries from the whitelist membership), so a whitelisted
		// IP is never country blocked.
		skipCountries = true
	}
	if len(blacklist) > 0 && ipMatchesList(ip, blacklist) {
		return c.deny(req, ip, genericListBlockReason(ip))
	}
	if !skipCountries {
		if reason, blocked := globalCountryVerdict(c.cfg, ip); blocked {
			return c.deny(req, ip, reason)
		}
	}
	state.IsExempt = !routeOverridesIPLists && ipMatchesList(ip, c.cfg.ExemptIPs)
	return nil
}

// genericListBlockReason mirrors _GENERIC_LIST_BLOCK_REASON
// (guard_core/_utils/access_control.py): the single reason string the
// reference reports for a global whitelist miss, a blacklist hit, an
// unresolved country under an allowlist, and an unparseable IP.
func genericListBlockReason(ip string) string {
	return fmt.Sprintf("IP %s not in global allowlist/blocklist", ip)
}

// globalCountryVerdict mirrors _resolve_country_verdict plus
// _check_blocked_countries_detail (guard_core/_utils/access_control.py):
// loopback IPs are exempt, an unresolved country fails closed only when the
// allowlist is restrictive (the blocklist mode cannot confirm a country and
// lets the request pass), and the allowlist takes precedence over the
// blocklist. The returned reason matches the reference block reasons.
func globalCountryVerdict(cfg *SecurityConfig, ip string) (string, bool) {
	blocked := cfg.BlockedCountries
	allowed := cfg.WhitelistCountries
	if len(blocked) == 0 && len(allowed) == 0 {
		return "", false
	}
	resolver := cfg.GeoIPHandler
	if resolver == nil {
		return "", false
	}
	if addr, err := netip.ParseAddr(ip); err == nil && addr.IsLoopback() {
		return "", false
	}
	country, resolved := resolver.GetCountry(ip)
	if !resolved {
		if len(allowed) > 0 {
			return genericListBlockReason(ip), true
		}
		return "", false
	}
	if len(allowed) > 0 {
		if containsCountry(allowed, country) {
			return "", false
		}
		return fmt.Sprintf("IP from blocked country: %s", country), true
	}
	if containsCountry(blocked, country) {
		return fmt.Sprintf("IP from blocked country: %s", country), true
	}
	return "", false
}

// deny mirrors the reference _check_global_ip_restrictions block path: the
// hook reason composes "IP not allowed: {ip} - {access reason}" with an
// empty trigger_info (the reference check passes no trigger_info to
// log_activity), and the passive mode still fires the hook with a null
// status before allowing the request through.
func (c *ipSecurityCheck) deny(req Request, ip, accessReason string) *Response {
	reason := fmt.Sprintf("IP not allowed: %s - %s", ip, accessReason)
	stashBlock(req.State(), reason, "")
	// Reference ip_security.py global-restriction path: ip_blocked with
	// filter_type global.
	emitBusEvent(c.cfg, EventIPBlocked, req, blockedOrLoggedAction(c.cfg.PassiveMode), reason,
		map[string]any{"filter_type": "global"})
	if c.cfg.PassiveMode {
		firePassiveBlockHook(c.cfg, req, c.CheckName(), reason, "")
		return nil
	}
	return createErrorResponse(c.cfg, 403, RestrictionBlockedMsg)
}

type rateLimitCheck struct {
	cfg     *SecurityConfig
	manager *RateLimitManager
}

func (c *rateLimitCheck) CheckName() string             { return "rate_limit" }
func (c *rateLimitCheck) EnforcedOnExcludedPaths() bool { return true }
func (c *rateLimitCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg.EnableRateLimiting || len(cfg.EndpointRateLimits) > 0
}

func (c *rateLimitCheck) Check(req Request) *Response {
	state := req.State()
	if state.IsWhitelisted || state.IsExempt || state.HasBypass("rate_limit") {
		return nil
	}
	ip := resolveClientIP(req)
	if ip == "" {
		return nil
	}
	cfg := c.cfg
	outcome, err := c.manager.CheckRateLimit(ip, req.URLPath(), routeRateConfigFrom(state.RouteConfig), nil)
	if err != nil {
		panic(err)
	}
	if outcome == nil || !outcome.Blocked {
		return nil
	}
	// The hook reason mirrors the reference ratelimit_handler log format: the
	// tripped tier's request count and window, with an empty trigger_info.
	reason := fmt.Sprintf("Rate limit exceeded for IP: %s (%d requests in %ds window)", ip, outcome.Count, outcome.Window)
	stashBlock(state, reason, "")
	c.emitRateLimitEvent(req, ip, reason, outcome)
	if cfg.PassiveMode {
		firePassiveBlockHook(cfg, req, "rate_limit", reason, "")
		return nil
	}
	resp := createErrorResponse(cfg, 429, "Too many requests")
	// The reference pins Retry-After on the 429 body from the tier window
	// that tripped (guard_core/handlers/ratelimit_handler.py).
	resp.SetHeader("Retry-After", outcome.RetryAfter())
	return resp
}

// emitRateLimitEvent mirrors the reference rate-limit event sites: the
// global tier reports rate_limited (handler rate_limit, metadata with the
// count, limit and window); dynamic endpoint tiers report
// dynamic_rule_violation; route and geo tiers report decorator_violation
// with their decorator classification. Passive mode downgrades every
// action to logged_only.
func (c *rateLimitCheck) emitRateLimitEvent(req Request, ip, reason string, outcome *RateLimitOutcome) {
	bus := busFor(c.cfg)
	if bus == nil {
		return
	}
	action := blockedOrLoggedAction(c.cfg.PassiveMode)
	switch outcome.Tier {
	case "endpoint":
		safeEndpoint := redactEndpointForDisplay(req.URLPath(), c.cfg)
		emitBusEvent(c.cfg, EventDynamicRuleViolation, req, action,
			fmt.Sprintf("Endpoint-specific rate limit exceeded: %d requests per %ds for %s", outcome.Count, outcome.Window, safeEndpoint),
			map[string]any{
				"rule_type":  "endpoint_rate_limit",
				"endpoint":   safeEndpoint,
				"rate_limit": outcome.Count,
				"window":     outcome.Window,
			})
	case "route":
		emitAccessDeniedEvent(c.cfg, req, reason, "rate_limiting", c.cfg.PassiveMode,
			map[string]any{
				"violation_type": "rate_limit",
				"rate_limit":     c.tierLimit(outcome),
				"window":         outcome.Window,
			})
	case "geo":
		emitAccessDeniedEvent(c.cfg, req, reason, "geo_rate_limiting", c.cfg.PassiveMode,
			map[string]any{
				"violation_type": "geo_rate_limit",
				"rate_limit":     c.tierLimit(outcome),
				"window":         outcome.Window,
			})
	default:
		// Global tier: the reference manager event with the request
		// count and the configured limit and window.
		if req.State() != nil {
			// keep the envelope endpoint/method fields accurate
		}
		emitRateLimitedHandlerEvent(c.cfg, req, ip, reason, outcome, c.cfg.RateLimit, c.cfg.RateLimitWindow)
	}
}

// tierLimit resolves the limit that tripped for the endpoint/route/geo
// tiers from the live config and the resolved route.
func (c *rateLimitCheck) tierLimit(outcome *RateLimitOutcome) int {
	if outcome == nil {
		return 0
	}
	return outcome.Count
}

// emitRateLimitedHandlerEvent mirrors the ratelimit_handler event: the
// handler-direct envelope carries endpoint, method, response_time and the
// count metadata.
func emitRateLimitedHandlerEvent(cfg *SecurityConfig, req Request, ip, reason string, outcome *RateLimitOutcome, limit, window int) {
	bus := busFor(cfg)
	if bus == nil {
		return
	}
	metadata := map[string]any{
		"request_count": outcome.Count,
		"rate_limit":    limit,
		"window":        window,
	}
	if path := req.URLPath(); path != "" {
		metadata["endpoint"] = redactEndpointForDisplay(path, cfg)
		metadata["method"] = req.Method()
	}
	bus.SendHandlerEvent(EventRateLimited, RateLimitHandlerName, ip, blockedOrLoggedAction(cfg.PassiveMode), reason, metadata)
}

// routeRateConfigFrom adapts the resolved RouteConfig rate-limit tier into
// the manager's RouteRateConfig (the reference passes route_config.rate_limit
// / rate_limit_window into the tiered check).
func routeRateConfigFrom(route *RouteConfig) *RouteRateConfig {
	if route == nil || route.RateLimit == 0 {
		return nil
	}
	cfg := &RouteRateConfig{RateLimit: &route.RateLimit}
	if route.RateLimitWindow != 0 {
		cfg.RateLimitWindow = &route.RateLimitWindow
	}
	cfg.GeoRateLimits = route.GeoRateLimits
	return cfg
}

type suspiciousActivityCheck struct {
	cfg    *SecurityConfig
	ban    *IPBanManager
	counts *suspiciousCountStore
}

type suspiciousCountStore struct {
	mu sync.Mutex
	m  map[string]map[string]int
}

func (c *suspiciousActivityCheck) CheckName() string             { return "suspicious_activity" }
func (c *suspiciousActivityCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *suspiciousActivityCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg.EnablePenetrationDetection
}

func (c *suspiciousActivityCheck) Check(req Request) *Response {
	state := req.State()
	if state.IsWhitelisted {
		return nil
	}
	ip := resolveClientIP(req)
	if ip == "" {
		return nil
	}
	cfg := c.cfg
	if state.HasBypass("penetration") {
		return nil
	}
	// The per-route enable_suspicious_detection decorator wins over the
	// global flag for routed requests (_get_effective_penetration_setting,
	// guard_core/core/checks/helpers.py): route true enables detection on
	// this route even when the global flag is off, route false disables it
	// even when the global flag is on.
	route := state.RouteConfig
	penetrationEnabled := cfg.EnablePenetrationDetection
	if route != nil {
		penetrationEnabled = route.EnableSuspiciousDetection
	}
	if !penetrationEnabled {
		return nil
	}
	categories, triggerInfo := detectThreat(req, cfg, resolveDetectionExclusions(cfg, route))
	if len(categories) == 0 {
		return nil
	}
	if cfg.PassiveMode {
		// The reference passive-mode handler
		// (_handle_suspicious_passive_mode) fires the hook directly with the
		// detection trigger_info and a null status.
		emitBusEvent(cfg, EventPenetrationAttempt, req, "logged_only",
			fmt.Sprintf("Suspicious activity detected: %s: %s", ip, triggerInfo),
			map[string]any{"request_count": c.totalCountFor(ip)})
		firePassiveBlockHook(cfg, req, "suspicious_activity", fmt.Sprintf("Suspicious activity detected: %s", ip), triggerInfo)
		return nil
	}
	// Active mode: the reason embeds the detection trigger_info while the
	// stash trigger_info stays empty, exactly like the reference
	// _handle_suspicious_active_mode log_activity call
	// (guard_core/core/checks/implementations/suspicious_activity.py).
	stashBlock(state, fmt.Sprintf("Suspicious activity detected for IP: %s - %s", ip, triggerInfo), "")
	// Reference suspicious_activity.py active path: penetration_attempt
	// with the per-IP request count.
	emitBusEvent(cfg, EventPenetrationAttempt, req, "request_blocked",
		fmt.Sprintf("Penetration attempt detected: %s", triggerInfo),
		map[string]any{"request_count": c.totalCountFor(ip)})
	if applied := c.registerViolations(cfg, req, ip, categories); applied {
		return createErrorResponse(cfg, 403, SuspiciousBannedMsg)
	}
	return createErrorResponse(cfg, 400, SuspiciousBlockedMsg)
}

// totalCountFor mirrors _total_count_for_ip: the sum of every detection
// category count kept for the IP.
func (c *suspiciousActivityCheck) totalCountFor(ip string) int {
	c.counts.mu.Lock()
	defer c.counts.mu.Unlock()
	total := 0
	for _, count := range c.counts.m[ip] {
		total += count
	}
	return total
}

func (c *suspiciousActivityCheck) registerViolations(cfg *SecurityConfig, req Request, ip string, categories []string) bool {
	c.counts.mu.Lock()
	perIP := c.counts.m[ip]
	if perIP == nil {
		perIP = map[string]int{}
		c.counts.m[ip] = perIP
	}
	for _, category := range categories {
		perIP[category]++
	}
	categoriesCopy := make(map[string]int, len(perIP))
	for k, v := range perIP {
		categoriesCopy[k] = v
	}
	c.counts.mu.Unlock()

	if !cfg.EnableIPBanning || c.ban == nil {
		return false
	}
	for _, category := range categories {
		threshold := cfg.AutoBanThreshold
		duration := cfg.AutoBanDuration
		if entry, ok := cfg.ThreatBanConfig[category]; ok {
			threshold = entry.Threshold
			duration = entry.Duration
		}
		c.counts.mu.Lock()
		count := c.counts.m[ip][category]
		c.counts.mu.Unlock()
		if count < threshold {
			continue
		}
		applied, err := c.ban.Ban(ip, duration, "penetration:"+category)
		if err != nil {
			// Reference helpers.py _emit_ban_escalation_failed:
			// ip_ban_failed with action ban_not_applied.
			emitBusEvent(cfg, EventIPBanFailed, req, "ban_not_applied",
				fmt.Sprintf("Escalation ban failed for %s: %v", ip, err), nil)
			continue
		}
		if !applied {
			continue
		}
		return true
	}
	return false
}

// detectThreat returns the threat categories plus the reference
// DetectionResult.trigger_info: the component label ("Request body: ",
// "Header 'x': ", "URL path: ", ...) followed by the first threat's message
// (_build_threat_message, guard_core/_utils/detection_scan.py), the string
// the reference suspicious-activity hook payloads carry in trigger_info.
func detectThreat(req Request, cfg *SecurityConfig, exclusions routeDetectionExclusions) ([]string, string) {
	enabled := exclusions.enabledCategories
	type value struct {
		content        string
		context        string
		label          string
		forcedCategory string
		skipCategories map[string]bool
	}
	var values []value
	if path := req.URLPath(); path != "" {
		values = append(values, value{content: path, context: "url_path", label: "URL path: "})
	}
	for key, v := range req.QueryParams() {
		if exclusions.excludedParams[strings.ToLower(key)] {
			continue
		}
		values = append(values, value{content: v, context: "query_param", label: fmt.Sprintf("Query param '%s': ", key)})
	}
	// Excluded headers (the hardcoded proxy identity set merged with
	// cfg.ExcludedDetectionHeaders) are not skipped outright: like the
	// reference's _scan_excluded_header_component, they scan with every
	// enabled category except the ones their value is known to
	// false-positive (ssrf for address-carrying headers and for address
	// chain values), so an attack payload in the same header still detects.
	excludedHeaders := exclusions.excludedHeaders
	headers := req.Headers()
	for name := range headers.Map() {
		if hv, ok := headers.Get(name); ok && hv != "" {
			v := value{content: hv, context: "header", label: fmt.Sprintf("Header '%s': ", strings.ToLower(name))}
			if excludedHeaders[strings.ToLower(name)] {
				v.skipCategories = excludedHeaderSkipCategories(name, hv)
			}
			values = append(values, v)
		}
	}
	// Body surface (guard-core 4.0.4 parity): the capped body is extracted
	// into form fields, multipart parts (binary-dense file parts reduced to
	// printable islands), JSON walk leaves, or one whole-value blob and each
	// value is scanned with its context, after the whole request surface
	// exactly like the reference. detection_scan_body=false (the reference
	// _resolve_scan_body / _scan_body_surface gate) skips the surface
	// entirely while headers, params, and the URL path still scan.
	if exclusions.scanBody {
		bodyValues := extractRequestBodyValues(req, cfg, exclusions.excludedBodyFields)
		for _, v := range bodyValues {
			label := v.label
			if label == "" {
				label = "Request body: "
			}
			values = append(values, value{content: v.content, context: v.context, label: label, forcedCategory: v.forcedCategory})
		}
	}
	for _, v := range values {
		if v.forcedCategory != "" {
			// JSON mongo-operator keys hit straight from the walk, like
			// body_json_scan._mongo_operator_key_hit.
			return []string{v.forcedCategory}, fmt.Sprintf("JSON operator key '%s': matched pattern '%s'", v.content, mongoOperatorKeyRE.String())
		}
		result := Detect(v.content, resolveClientIP(req), v.context)
		if !result.IsThreat {
			continue
		}
		var categories []string
		seen := map[string]bool{}
		for _, threat := range result.Threats {
			category, _ := threat["category"].(string)
			if category == "" || !enabled[category] || v.skipCategories[category] || seen[category] {
				continue
			}
			seen[category] = true
			categories = append(categories, category)
		}
		if len(categories) == 0 {
			return nil, ""
		}
		sort.Strings(categories)
		return categories, v.label + threatMessage(firstThreatOf(result))
	}
	return nil, ""
}

// firstThreatOf picks the first threat of the detection result, the one the
// reference _check_value_enhanced uses for its trigger message.
func firstThreatOf(result DetectResult) map[string]any {
	if len(result.Threats) == 0 {
		return nil
	}
	return result.Threats[0]
}

// threatMessage mirrors _build_threat_message
// (guard_core/_utils/detection_scan.py).
func threatMessage(threat map[string]any) string {
	if threat == nil {
		return "Threat detected"
	}
	kind, _ := threat["type"].(string)
	switch kind {
	case "semantic":
		attackType, _ := threat["attack_type"].(string)
		if attackType == "" {
			attackType = "suspicious"
		}
		score := 0.0
		if v, ok := threat["probability"].(float64); ok {
			score = v
		} else if v, ok := threat["threat_score"].(float64); ok {
			score = v
		}
		return fmt.Sprintf("Semantic attack: %s (score: %.2f)", attackType, score)
	case "pattern_timeout":
		pattern, _ := threat["pattern"].(string)
		return fmt.Sprintf("Pattern exceeded scan time budget: '%s'", pattern)
	case "regex":
		pattern, _ := threat["pattern"].(string)
		return fmt.Sprintf("Value matched pattern '%s'", pattern)
	}
	return "Threat detected"
}

// extractRequestBodyValues reads the (already replay-buffered) request body
// once, caps it at the inspection budget, and routes it through the body
// extraction. A body read error leaves the body unscanned, like the
// reference's failed body read reporting a detection miss.
func extractRequestBodyValues(req Request, cfg *SecurityConfig, excludedBodyFields map[string]bool) []bodyScanValue {
	if cfg == nil {
		return nil
	}
	body, err := req.Body()
	if err != nil || len(body) == 0 {
		return nil
	}
	if budget := cfg.Detection.MaxBodyInspectBytes; budget > 0 && len(body) > budget {
		body = body[:budget]
	}
	contentType, _ := req.Headers().Get("content-type")
	return extractBodyScanValues(string(body), contentType, cfg, excludedBodyFields)
}

func stashBlock(state *RequestState, reason, triggerInfo string) {
	state.BlockStash = &BlockStash{Reason: reason, TriggerInfo: triggerInfo}
}

func createErrorResponse(cfg *SecurityConfig, statusCode int, defaultMessage string) *Response {
	message := defaultMessage
	if cfg != nil {
		if custom, ok := cfg.CustomErrorResponses[statusCode]; ok && custom != "" {
			message = custom
		}
	}
	response := NewResponseFactory().CreateResponse(message, statusCode)
	// The reference error factory applies the security headers on every error
	// response (guard_core/core/responses/factory.py apply_security_headers).
	for name, value := range responseHeaders(cfg) {
		response.SetHeader(name, value)
	}
	return response
}

func errorResponse(cfg *SecurityConfig, statusCode int, message string) *Response {
	response := NewResponseFactory().CreateResponse(message, statusCode)
	for name, value := range responseHeaders(cfg) {
		response.SetHeader(name, value)
	}
	return response
}

func resolveClientIP(req Request) string {
	state := req.State()
	if state.ClientIP != "" {
		return canonicalizeIPString(state.ClientIP)
	}
	if host := req.ClientHost(); host != "" {
		return canonicalizeIPString(host)
	}
	return ""
}

func firePassiveBlockHook(cfg *SecurityConfig, req Request, checkName, reason, triggerInfo string) {
	fireBlockHook(cfg, req, checkName, reason, triggerInfo, true, 0)
}

// blockHookStatusCode maps the status code into the hook payload: the
// reference carries null whenever no block status applies (every passive
// dispatch passes None, guard_core/_utils/block_events.py build_block_payload
// via _dispatch_block_hook) and the integer response status otherwise.
func blockHookStatusCode(statusCode int) any {
	if statusCode == 0 {
		return nil
	}
	return statusCode
}

func fireBlockHook(cfg *SecurityConfig, req Request, checkName, reason, triggerInfo string, passiveMode bool, statusCode int) {
	if cfg == nil || cfg.OnBlock == nil || onBlockExcludedCheckNames[checkName] {
		return
	}
	ip := resolveClientIP(req)
	if ip == "" {
		ip = UnknownClientIdentity
	}
	payload := map[string]any{
		"check_name":   checkName,
		"reason":       reason,
		"trigger_info": triggerInfo,
		"passive_mode": passiveMode,
		"client_ip":    ip,
		"path":         req.URLPath(),
		"method":       req.Method(),
		"status_code":  blockHookStatusCode(statusCode),
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("on_block hook raised: %v", r)
			}
		}()
		cfg.OnBlock(req, payload)
	}()
}

func fireBlockHookForced(cfg *SecurityConfig, req Request, checkName, reason, triggerInfo string, passiveMode bool, statusCode int) {
	if cfg == nil || cfg.OnBlock == nil {
		return
	}
	ip := resolveClientIP(req)
	if ip == "" {
		ip = UnknownClientIdentity
	}
	payload := map[string]any{
		"check_name":   checkName,
		"reason":       reason,
		"trigger_info": triggerInfo,
		"passive_mode": passiveMode,
		"client_ip":    ip,
		"path":         req.URLPath(),
		"method":       req.Method(),
		"status_code":  blockHookStatusCode(statusCode),
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("on_block hook raised: %v", r)
			}
		}()
		cfg.OnBlock(req, payload)
	}()
}

type SecurityCheckPipeline struct {
	mu                     sync.RWMutex
	checks                 []SecurityCheck
	config                 *SecurityConfig
	rebuildChecks          func() []SecurityCheck
	watchedContainerFields []string
	mutedCheckLogs         map[string]bool
	builtRevision          uint64
	builtSignature         []int
	routeRevision          func() uint64
	builtRouteRevision     uint64
	logger                 *log.Logger
}

var watchedContainerFields = []string{"block_cloud_providers", "blocked_user_agents", "endpoint_rate_limits"}

func NewSecurityCheckPipeline(checks []SecurityCheck, cfg *SecurityConfig, rebuild func() []SecurityCheck) *SecurityCheckPipeline {
	p := &SecurityCheckPipeline{
		checks:                 checks,
		config:                 cfg,
		rebuildChecks:          rebuild,
		watchedContainerFields: watchedContainerFields,
		mutedCheckLogs:         map[string]bool{},
		logger:                 log.Default(),
	}
	if cfg != nil {
		p.builtRevision = cfg.Revision()
		p.builtSignature = p.containerSignature(cfg)
		for name := range cfg.MutedCheckLogs {
			p.mutedCheckLogs[name] = true
		}
	}
	return p
}

func (p *SecurityCheckPipeline) SetRouteRevisionSource(source func() uint64) {
	p.mu.Lock()
	p.routeRevision = source
	if source != nil {
		p.builtRouteRevision = source()
	}
	p.mu.Unlock()
}

func (p *SecurityCheckPipeline) containerSignature(cfg *SecurityConfig) []int {
	sig := make([]int, len(p.watchedContainerFields))
	for i, field := range p.watchedContainerFields {
		switch field {
		case "block_cloud_providers":
			sig[i] = len(cfg.BlockCloudProviders)
		case "blocked_user_agents":
			sig[i] = len(cfg.BlockedUserAgents)
		case "endpoint_rate_limits":
			sig[i] = len(cfg.EndpointRateLimits)
		}
	}
	return sig
}

func (p *SecurityCheckPipeline) IsStale() bool { return p.isStale() }

func (p *SecurityCheckPipeline) isStale() bool {
	if p.config == nil || p.rebuildChecks == nil {
		return false
	}
	if p.config.Revision() != p.builtRevision {
		return true
	}
	current := p.containerSignature(p.config)
	for i := range current {
		if current[i] != p.builtSignature[i] {
			return true
		}
	}
	if p.routeRevision != nil && p.routeRevision() != p.builtRouteRevision {
		return true
	}
	return false
}

func (p *SecurityCheckPipeline) rebuildIfStale() error {
	p.mu.Lock()
	stale := p.isStale()
	p.mu.Unlock()
	if !stale {
		return nil
	}
	cfg := p.config
	revision := cfg.Revision()
	signature := p.containerSignature(cfg)
	muted := map[string]bool{}
	for name := range cfg.MutedCheckLogs {
		muted[name] = true
	}
	checks := p.rebuildChecks()
	routeRev := uint64(0)
	if p.routeRevision != nil {
		routeRev = p.routeRevision()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checks = checks
	p.mutedCheckLogs = muted
	p.builtRevision = revision
	p.builtSignature = signature
	p.builtRouteRevision = routeRev
	return nil
}

func (p *SecurityCheckPipeline) CheckNames() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	names := make([]string, len(p.checks))
	for i, c := range p.checks {
		names[i] = c.CheckName()
	}
	return names
}

func (p *SecurityCheckPipeline) Execute(req Request) *Response {
	if err := p.rebuildIfStale(); err != nil {
		return p.handleRebuildError(req, err)
	}
	exclusionScoped := req.State().ExclusionScoped
	p.mu.RLock()
	checks := p.checks
	muted := p.mutedCheckLogs
	p.mu.RUnlock()

	for _, check := range checks {
		if exclusionScoped && !check.EnforcedOnExcludedPaths() {
			continue
		}
		resp, err := runCheck(check, req)
		if err != nil {
			if errorResponse := p.handleCheckError(check, req, err, muted); errorResponse != nil {
				return errorResponse
			}
			continue
		}
		if resp == nil {
			continue
		}
		if !muted[check.CheckName()] {
			p.logger.Printf("Request blocked by %s (path=%s method=%s)", check.CheckName(), req.URLPath(), req.Method())
		}
		cfg := p.config
		var reason, triggerInfo string
		if stash := req.State().BlockStash; stash != nil {
			reason = stash.Reason
			triggerInfo = stash.TriggerInfo
		}
		fireBlockHook(cfg, req, check.CheckName(), reason, triggerInfo, false, resp.StatusCode)
		return resp
	}
	return nil
}

func runCheck(check SecurityCheck, req Request) (resp *Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			if panicErr, ok := r.(error); ok {
				err = panicErr
				return
			}
			err = fmt.Errorf("%v", r)
		}
	}()
	return check.Check(req), nil
}

func (p *SecurityCheckPipeline) handleCheckError(check SecurityCheck, req Request, err error, muted map[string]bool) *Response {
	cfg := p.config
	var redisErr *GuardRedisError
	if errors.As(err, &redisErr) && cfg != nil && cfg.RedisFailOpen {
		if !muted[check.CheckName()] {
			p.logger.Printf("Skipping check %s: Redis unavailable, failing open (redis_fail_open=True)", check.CheckName())
		}
		return nil
	}
	if !muted[check.CheckName()] {
		p.logger.Printf("Error in security check %s (%T): %v", check.CheckName(), err, err)
	}
	if cfg == nil || cfg.FailSecure {
		if !muted[check.CheckName()] {
			p.logger.Printf("Blocking request due to check error in fail-secure mode: %s", check.CheckName())
		}
		message := "Security check failed"
		if cfg != nil {
			if custom, ok := cfg.CustomErrorResponses[500]; ok && custom != "" {
				message = custom
			}
		}
		return errorResponse(cfg, 500, message)
	}
	return nil
}

func (p *SecurityCheckPipeline) handleRebuildError(req Request, err error) *Response {
	p.logger.Printf("Error rebuilding security checks: %v", err)
	cfg := p.config
	if cfg == nil || !cfg.FailSecure {
		return nil
	}
	p.mu.RLock()
	empty := len(p.checks) == 0
	p.mu.RUnlock()
	if empty {
		panic(err)
	}
	message := "Security check failed"
	if custom, ok := cfg.CustomErrorResponses[500]; ok && custom != "" {
		message = custom
	}
	return errorResponse(cfg, 500, message)
}

func RateLimitConfigFromSecurityConfig(cfg *SecurityConfig) RateLimitConfig {
	return RateLimitConfig{
		EnableRateLimiting:     cfg.EnableRateLimiting,
		RateLimit:              cfg.RateLimit,
		RateLimitWindow:        cfg.RateLimitWindow,
		EndpointRateLimits:     cfg.EndpointRateLimits,
		EnableRateLimitAutoBan: cfg.EnableRateLimitAutoBan,
		PassiveMode:            cfg.PassiveMode,
		EnableIPBanning:        cfg.EnableIPBanning,
		AutoBanThreshold:       cfg.AutoBanThreshold,
		AutoBanDuration:        cfg.AutoBanDuration,
		ThreatBanConfig:        cfg.ThreatBanConfig,
		RedisFailOpen:          cfg.RedisFailOpen,
	}
}

// BuildDefaultPipeline assembles the fixed slot order. The
// suspicious-count store is owned by the caller (the Engine) so the
// behavioral processor's correlate_with_detection reads the same per-IP
// category counts the suspicious_activity check writes, mirroring the
// reference reading middleware.suspicious_request_counts.
func BuildDefaultPipeline(cfg *SecurityConfig, ban *IPBanManager, rateLimit *RateLimitManager, routes *RouteRegistry) (*SecurityCheckPipeline, *suspiciousCountStore) {
	if cfg == nil {
		return nil, nil
	}
	if routes == nil {
		routes = NewRouteRegistry()
	}
	counts := &suspiciousCountStore{m: map[string]map[string]int{}}
	build := func() []SecurityCheck { return buildChecks(cfg, ban, rateLimit, routes, counts) }
	pipeline := NewSecurityCheckPipeline(build(), cfg, build)
	pipeline.SetRouteRevisionSource(routes.Revision)
	return pipeline, counts
}

func buildChecks(cfg *SecurityConfig, ban *IPBanManager, rateLimit *RateLimitManager, routes *RouteRegistry, counts *suspiciousCountStore) []SecurityCheck {
	routeConfigs := routes.RouteConfigs()
	specs := []struct {
		name     string
		excluded bool
		applies  func(cfg *SecurityConfig) bool
		build    func(cfg *SecurityConfig) SecurityCheck
	}{
		{"route_config", true, func(*SecurityConfig) bool { return true }, func(cfg *SecurityConfig) SecurityCheck {
			return &routeConfigCheck{cfg: cfg, registry: routes}
		}},
		{"emergency_mode", false, func(cfg *SecurityConfig) bool { return cfg.EmergencyMode || cfg.EnableDynamicRules }, func(cfg *SecurityConfig) SecurityCheck {
			return &emergencyModeCheck{cfg: cfg}
		}},
		{"https_enforcement", false, func(cfg *SecurityConfig) bool {
			return cfg.EnforceHTTPS || anyRoute(routeConfigs, func(rc *RouteConfig) bool { return rc.RequireHTTPS })
		}, func(cfg *SecurityConfig) SecurityCheck {
			return &httpsEnforcementCheck{cfg: cfg}
		}},
		{"request_logging", false, func(cfg *SecurityConfig) bool { return cfg.LogRequestLevel != "" }, func(cfg *SecurityConfig) SecurityCheck {
			return &requestLoggingCheck{cfg: cfg, logger: log.Default()}
		}},
		{"request_size_content", false, func(*SecurityConfig) bool { return requestSizeContentApplies(routeConfigs) }, func(cfg *SecurityConfig) SecurityCheck {
			return &requestSizeContentCheck{cfg: cfg, routes: routeConfigs}
		}},
		{"required_headers", false, func(*SecurityConfig) bool { return requiredHeadersApplies(routeConfigs) }, func(cfg *SecurityConfig) SecurityCheck {
			return &requiredHeadersCheck{cfg: cfg, routes: routeConfigs}
		}},
		{"authentication", false, func(*SecurityConfig) bool { return authenticationApplies(routeConfigs) }, func(cfg *SecurityConfig) SecurityCheck {
			return &authenticationCheck{cfg: cfg, routes: routeConfigs}
		}},
		{"referrer", false, func(*SecurityConfig) bool { return referrerApplies(routeConfigs) }, func(cfg *SecurityConfig) SecurityCheck {
			return &referrerCheck{cfg: cfg, routes: routeConfigs}
		}},
		{"custom_validators", false, func(*SecurityConfig) bool { return customValidatorsApplies(routeConfigs) }, func(cfg *SecurityConfig) SecurityCheck {
			return &customValidatorsCheck{cfg: cfg, logger: log.Default(), routes: routeConfigs}
		}},
		{"time_window", false, func(*SecurityConfig) bool { return timeWindowApplies(routeConfigs) }, func(cfg *SecurityConfig) SecurityCheck {
			return &timeWindowCheck{cfg: cfg, routes: routeConfigs}
		}},
		{"cloud_ip_refresh", false, func(cfg *SecurityConfig) bool { return cloudApplies(cfg, routeConfigs) }, func(cfg *SecurityConfig) SecurityCheck {
			return &cloudIPRefreshCheck{cfg: cfg, manager: DefaultCloudManager}
		}},
		{"ip_security", true, func(*SecurityConfig) bool { return true }, func(cfg *SecurityConfig) SecurityCheck {
			return &ipSecurityCheck{cfg: cfg, ban: ban, name: "ip_security"}
		}},
		{"cloud_provider", false, func(cfg *SecurityConfig) bool { return cloudApplies(cfg, routeConfigs) }, func(cfg *SecurityConfig) SecurityCheck {
			return &cloudProviderCheck{cfg: cfg, manager: DefaultCloudManager}
		}},
		{"user_agent", false, func(cfg *SecurityConfig) bool { return userAgentApplies(cfg, routeConfigs) }, func(cfg *SecurityConfig) SecurityCheck {
			return &userAgentCheck{cfg: cfg, routes: routeConfigs}
		}},
		{"rate_limit", true, func(cfg *SecurityConfig) bool { return cfg.EnableRateLimiting || len(cfg.EndpointRateLimits) > 0 }, func(cfg *SecurityConfig) SecurityCheck {
			return &rateLimitCheck{cfg: cfg, manager: rateLimit}
		}},
		{"suspicious_activity", false, func(cfg *SecurityConfig) bool {
			// Reference SuspiciousActivityCheck.applies_to: the global flag
			// or any route's enable_suspicious_detection decorator forces
			// the check into the pipeline (the per-request route verdict
			// then decides).
			return cfg.EnablePenetrationDetection || anyRoute(routeConfigs, func(rc *RouteConfig) bool { return rc.EnableSuspiciousDetection })
		}, func(cfg *SecurityConfig) SecurityCheck {
			return &suspiciousActivityCheck{cfg: cfg, ban: ban, counts: counts}
		}},
		{"custom_request", false, func(cfg *SecurityConfig) bool { return cfg.CustomRequestCheck != nil }, func(cfg *SecurityConfig) SecurityCheck {
			return &customRequestCheck{cfg: cfg, logger: log.Default()}
		}},
	}
	var checks []SecurityCheck
	for _, spec := range specs {
		if !spec.applies(cfg) {
			continue
		}
		if spec.build == nil {
			checks = append(checks, &unsupportedCheck{name: spec.name, excluded: spec.excluded, applies: spec.applies})
			continue
		}
		checks = append(checks, spec.build(cfg))
	}
	return checks
}
