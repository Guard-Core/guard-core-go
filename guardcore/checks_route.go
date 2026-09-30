package guardcore

import (
	"fmt"
	"strings"
)

const unresolvedRouteReason = "Route resolution failed; per-route decorator config could not be applied"

type routeConfigCheck struct {
	cfg      *SecurityConfig
	registry *RouteRegistry
}

func (c *routeConfigCheck) CheckName() string             { return "route_config" }
func (c *routeConfigCheck) EnforcedOnExcludedPaths() bool { return true }
func (c *routeConfigCheck) AppliesTo(*SecurityConfig) bool {
	return true
}

func (c *routeConfigCheck) Check(req Request) *Response {
	state := req.State()
	state.RouteConfig = c.registry.Get(state.GuardRouteID)
	if ip := resolveClientIP(req); ip != "" {
		state.ClientIP = ip
	}
	if c.cfg.RouteResolutionStrict && state.RouteUnresolved {
		stashBlock(state, unresolvedRouteReason, "")
		// Reference route_config.py: route_unresolved.
		emitBusEvent(c.cfg, EventRouteUnresolved, req, blockedOrLoggedAction(c.cfg.PassiveMode), unresolvedRouteReason, nil)
		if c.cfg.PassiveMode {
			firePassiveBlockHook(c.cfg, req, "route_config", unresolvedRouteReason, "")
			return nil
		}
		return createErrorResponse(c.cfg, 500, "Route resolution failed")
	}
	return nil
}

type emergencyModeCheck struct {
	cfg *SecurityConfig
}

func (c *emergencyModeCheck) CheckName() string             { return "emergency_mode" }
func (c *emergencyModeCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *emergencyModeCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg.EmergencyMode || cfg.EnableDynamicRules
}

func (c *emergencyModeCheck) Check(req Request) *Response {
	cfg := c.cfg
	if !cfg.EmergencyMode {
		return nil
	}
	state := req.State()
	clientIP := state.ClientIP
	if clientIP == "" {
		clientIP = resolveClientIP(req)
	}
	isWhitelisted := clientIP != "" && ipMatchesList(clientIP, cfg.EmergencyWhitelist)
	if isWhitelisted {
		return nil
	}
	hookReason := "[EMERGENCY MODE] Access denied for IP " + clientIP
	stashBlock(state, hookReason, "")
	// Reference emergency_mode.py: the emergency_mode_block event carries
	// its own reason, distinct from the log_activity string, plus the
	// whitelist size and the active flag.
	emitBusEvent(cfg, EventEmergencyModeBlock, req, blockedOrLoggedAction(cfg.PassiveMode),
		fmt.Sprintf("[EMERGENCY MODE] IP %s not in whitelist", clientIP),
		map[string]any{
			"emergency_whitelist_count": len(cfg.EmergencyWhitelist),
			"emergency_active":          true,
		})
	if cfg.PassiveMode {
		firePassiveBlockHook(cfg, req, "emergency_mode", hookReason, "")
		return nil
	}
	return createErrorResponse(cfg, 503, "Service temporarily unavailable")
}

type httpsEnforcementCheck struct {
	cfg *SecurityConfig
}

func (c *httpsEnforcementCheck) CheckName() string             { return "https_enforcement" }
func (c *httpsEnforcementCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *httpsEnforcementCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg.EnforceHTTPS
}

func (c *httpsEnforcementCheck) isTrustedProxy(connectingIP string) bool {
	return ipMatchesList(connectingIP, c.cfg.TrustedProxies)
}

func (c *httpsEnforcementCheck) isRequestHTTPS(req Request) bool {
	isHTTPS := req.URLScheme() == "https"
	cfg := c.cfg
	if cfg.TrustXForwardedProto && len(cfg.TrustedProxies) > 0 {
		if host := req.ClientHost(); host != "" && c.isTrustedProxy(host) {
			if proto, ok := req.Headers().Get("X-Forwarded-Proto"); ok && strings.EqualFold(proto, "https") {
				isHTTPS = true
			}
		}
	}
	return isHTTPS
}

func (c *httpsEnforcementCheck) Check(req Request) *Response {
	cfg := c.cfg
	routeConfig := req.State().RouteConfig
	httpsRequired := cfg.EnforceHTTPS
	if routeConfig != nil {
		httpsRequired = routeConfig.RequireHTTPS
	}
	if !httpsRequired {
		return nil
	}
	if c.isRequestHTTPS(req) {
		return nil
	}
	if cfg.PassiveMode {
		return nil
	}
	// Reference middleware_events.send_https_violation_event: route-level
	// require_https reports decorator_violation, global enforcement
	// reports https_enforced; both action https_redirect.
	if bus := busFor(cfg); bus != nil {
		bus.SendHTTPSViolationEvent(req, routeConfig)
	}
	return NewResponseFactory().CreateRedirectResponse(req.URLReplaceScheme("https"), 301)
}
