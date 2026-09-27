package guardcore

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

type requestSizeContentCheck struct {
	cfg    *SecurityConfig
	routes []*RouteConfig
}

func (c *requestSizeContentCheck) CheckName() string             { return "request_size_content" }
func (c *requestSizeContentCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *requestSizeContentCheck) AppliesTo(cfg *SecurityConfig) bool {
	return false
}

func requestSizeContentApplies(routes []*RouteConfig) bool {
	return anyRoute(routes, func(rc *RouteConfig) bool {
		return rc.MaxRequestSize > 0 || len(rc.AllowedContentTypes) > 0
	})
}

func (c *requestSizeContentCheck) Check(req Request) *Response {
	cfg := c.cfg
	routeConfig := req.State().RouteConfig
	if routeConfig == nil {
		return nil
	}
	if routeConfig.MaxRequestSize > 0 {
		contentLength, ok := req.Headers().Get("Content-Length")
		if ok && contentLength != "" {
			size, err := strconv.Atoi(strings.TrimSpace(contentLength))
			if err != nil {
				panic(fmt.Errorf("request_size_content: invalid content-length %q: %w", contentLength, err))
			}
			if int64(size) > routeConfig.MaxRequestSize {
				reason := fmt.Sprintf("Request size %s exceeds limit: %d", contentLength, routeConfig.MaxRequestSize)
				stashBlock(req.State(), reason, "")
				if cfg.PassiveMode {
					firePassiveBlockHook(cfg, req, "request_size_content", reason, "")
					return nil
				}
				return createErrorResponse(cfg, 413, "Request too large")
			}
		}
	}
	if len(routeConfig.AllowedContentTypes) > 0 {
		contentType, _ := req.Headers().Get("Content-Type")
		if idx := strings.Index(contentType, ";"); idx != -1 {
			contentType = contentType[:idx]
		}
		allowed := false
		for _, candidate := range routeConfig.AllowedContentTypes {
			if candidate == contentType {
				allowed = true
				break
			}
		}
		if !allowed {
			reason := fmt.Sprintf("Invalid content type: %s", contentType)
			stashBlock(req.State(), reason, "")
			if cfg.PassiveMode {
				firePassiveBlockHook(cfg, req, "request_size_content", reason, "")
				return nil
			}
			return createErrorResponse(cfg, 415, "Unsupported content type")
		}
	}
	return nil
}

type requiredHeadersCheck struct {
	cfg    *SecurityConfig
	routes []*RouteConfig
}

func (c *requiredHeadersCheck) CheckName() string              { return "required_headers" }
func (c *requiredHeadersCheck) EnforcedOnExcludedPaths() bool  { return false }
func (c *requiredHeadersCheck) AppliesTo(*SecurityConfig) bool { return false }

func requiredHeadersApplies(routes []*RouteConfig) bool {
	return anyRoute(routes, func(rc *RouteConfig) bool { return len(rc.RequiredHeaders) > 0 })
}

func (c *requiredHeadersCheck) Check(req Request) *Response {
	cfg := c.cfg
	routeConfig := req.State().RouteConfig
	if routeConfig == nil || len(routeConfig.RequiredHeaders) == 0 {
		return nil
	}
	for _, entry := range routeConfig.RequiredHeaders {
		actual, _ := req.Headers().Get(entry.Name)
		if actual == "" {
			return c.reportViolation(cfg, req, entry.Name, fmt.Sprintf("Missing required header: %s", entry.Name), "missing_header")
		}
		if entry.Value != "required" && actual != entry.Value {
			return c.reportViolation(cfg, req, entry.Name, fmt.Sprintf("Header '%s' does not match the required value", entry.Name), "mismatched_header")
		}
	}
	return nil
}

func (c *requiredHeadersCheck) reportViolation(cfg *SecurityConfig, req Request, header, reason, headerField string) *Response {
	stashBlock(req.State(), reason, "")
	if cfg.PassiveMode {
		firePassiveBlockHook(cfg, req, "required_headers", reason, "")
		return nil
	}
	return createErrorResponse(cfg, 400, reason)
}

type authenticationCheck struct {
	cfg    *SecurityConfig
	routes []*RouteConfig
}

func (c *authenticationCheck) CheckName() string              { return "authentication" }
func (c *authenticationCheck) EnforcedOnExcludedPaths() bool  { return false }
func (c *authenticationCheck) AppliesTo(*SecurityConfig) bool { return false }

func authenticationApplies(routes []*RouteConfig) bool {
	return anyRoute(routes, func(rc *RouteConfig) bool {
		return rc.AuthRequired != "" || rc.APIKeyRequired || rc.AuthorizationHeaderRequired != ""
	})
}

func extractCredential(authHeader, authType string) (string, string) {
	if authType == "bearer" {
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return "", "Missing or invalid Bearer token"
		}
		return authHeader[len("Bearer "):], ""
	}
	if authType == "basic" {
		if !strings.HasPrefix(authHeader, "Basic ") {
			return "", "Missing or invalid Basic authentication"
		}
		return authHeader[len("Basic "):], ""
	}
	if authHeader == "" {
		return "", fmt.Sprintf("Missing %s authentication", authType)
	}
	return authHeader, ""
}

func (c *authenticationCheck) handleAuthFailure(cfg *SecurityConfig, req Request, routeConfig *RouteConfig, authReason, violationType string) *Response {
	reason := fmt.Sprintf("Authentication failure: %s", authReason)
	stashBlock(req.State(), reason, "")
	if cfg.PassiveMode {
		firePassiveBlockHook(cfg, req, "authentication", reason, "")
		return nil
	}
	return createErrorResponse(cfg, 401, "Authentication required")
}

func (c *authenticationCheck) Check(req Request) *Response {
	cfg := c.cfg
	routeConfig := req.State().RouteConfig
	if routeConfig == nil {
		return nil
	}
	authHeader, _ := req.Headers().Get("Authorization")
	if scheme := routeConfig.AuthorizationHeaderRequired; scheme != "" {
		if credential, reason := extractCredential(authHeader, scheme); credential == "" {
			return c.handleAuthFailure(cfg, req, routeConfig, reason, "authorization_header")
		}
		return nil
	}
	if routeConfig.AuthRequired == "" && !routeConfig.APIKeyRequired {
		return nil
	}
	var verifier AuthVerifier
	var credential string
	var reason string
	if routeConfig.AuthRequired != "" {
		verifier = routeConfig.AuthVerifier
		if verifier == nil {
			verifier = cfg.AuthVerifier
		}
		credential, reason = extractCredential(authHeader, routeConfig.AuthRequired)
		if credential == "" {
			return c.handleAuthFailure(cfg, req, routeConfig, reason, "require_auth")
		}
	} else {
		verifier = routeConfig.APIKeyVerifier
		if verifier == nil {
			verifier = cfg.AuthVerifier
		}
		credential, _ = req.Headers().Get(routeConfig.APIKeyHeader)
		if credential == "" {
			return c.handleAuthFailure(cfg, req, routeConfig, "Missing API key", "require_auth")
		}
	}
	if verifier == nil {
		return c.handleAuthFailure(cfg, req, routeConfig, "No auth verifier configured", "require_auth")
	}
	result, err := verifier(req, credential)
	if err != nil {
		return c.handleAuthFailure(cfg, req, routeConfig, "Authentication error", "require_auth")
	}
	if result == nil || isEmptyPrincipal(result) {
		return c.handleAuthFailure(cfg, req, routeConfig, "Authentication failed", "require_auth")
	}
	req.State().AuthPrincipal = result
	return nil
}

func isEmptyPrincipal(v any) bool {
	s, ok := v.(string)
	return ok && s == ""
}

type referrerCheck struct {
	cfg    *SecurityConfig
	routes []*RouteConfig
}

func (c *referrerCheck) CheckName() string              { return "referrer" }
func (c *referrerCheck) EnforcedOnExcludedPaths() bool  { return false }
func (c *referrerCheck) AppliesTo(*SecurityConfig) bool { return false }

func referrerApplies(routes []*RouteConfig) bool {
	return anyRoute(routes, func(rc *RouteConfig) bool { return len(rc.RequireReferrer) > 0 })
}

func normalizeAllowedReferrerDomain(entry string) string {
	if strings.Contains(entry, "://") {
		if parsed, err := url.Parse(entry); err == nil {
			return strings.ToLower(parsed.Host)
		}
	}
	normalized := strings.ToLower(entry)
	if idx := strings.Index(normalized, "/"); idx != -1 {
		return normalized[:idx]
	}
	return normalized
}

func isReferrerDomainAllowed(referrer string, allowedDomains []string) bool {
	parsed, err := url.Parse(referrer)
	if err != nil {
		return false
	}
	referrerDomain := strings.ToLower(parsed.Host)
	for _, allowedDomain := range allowedDomains {
		normalized := normalizeAllowedReferrerDomain(allowedDomain)
		if referrerDomain == normalized || strings.HasSuffix(referrerDomain, "."+normalized) {
			return true
		}
	}
	return false
}

func (c *referrerCheck) Check(req Request) *Response {
	cfg := c.cfg
	routeConfig := req.State().RouteConfig
	if routeConfig == nil || len(routeConfig.RequireReferrer) == 0 {
		return nil
	}
	referrer, _ := req.Headers().Get("Referer")
	if referrer == "" {
		reason := "Missing referrer header"
		stashBlock(req.State(), reason, "")
		if cfg.PassiveMode {
			firePassiveBlockHook(cfg, req, "referrer", reason, "")
			return nil
		}
		return createErrorResponse(cfg, 403, "Referrer required")
	}
	if !isReferrerDomainAllowed(referrer, routeConfig.RequireReferrer) {
		reason := fmt.Sprintf("Invalid referrer: %s", referrer)
		stashBlock(req.State(), reason, "")
		if cfg.PassiveMode {
			firePassiveBlockHook(cfg, req, "referrer", reason, "")
			return nil
		}
		return createErrorResponse(cfg, 403, "Invalid referrer")
	}
	return nil
}

type timeWindowCheck struct {
	cfg    *SecurityConfig
	routes []*RouteConfig
	nowFn  func() time.Time
}

func (c *timeWindowCheck) CheckName() string              { return "time_window" }
func (c *timeWindowCheck) EnforcedOnExcludedPaths() bool  { return false }
func (c *timeWindowCheck) AppliesTo(*SecurityConfig) bool { return false }

func timeWindowApplies(routes []*RouteConfig) bool {
	return anyRoute(routes, func(rc *RouteConfig) bool { return len(rc.TimeRestrictions) > 0 })
}

func (c *timeWindowCheck) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

func (c *timeWindowCheck) checkTimeWindow(restrictions map[string]string) bool {
	start, ok := restrictions["start"]
	if !ok {
		return true
	}
	end, ok := restrictions["end"]
	if !ok {
		return true
	}
	location, err := time.LoadLocation(restrictions["timezone"])
	if err != nil {
		location = time.UTC
	}
	current := c.now().In(location).Format("15:04")
	if start > end {
		return current >= start || current <= end
	}
	return start <= current && current <= end
}

func (c *timeWindowCheck) Check(req Request) *Response {
	cfg := c.cfg
	routeConfig := req.State().RouteConfig
	if routeConfig == nil || len(routeConfig.TimeRestrictions) == 0 {
		return nil
	}
	if !c.checkTimeWindow(routeConfig.TimeRestrictions) {
		reason := "Access outside allowed time window"
		stashBlock(req.State(), reason, "")
		if cfg.PassiveMode {
			firePassiveBlockHook(cfg, req, "time_window", reason, "")
			return nil
		}
		return createErrorResponse(cfg, 403, "Access not allowed at this time")
	}
	return nil
}

type userAgentCheck struct {
	cfg    *SecurityConfig
	routes []*RouteConfig
}

func (c *userAgentCheck) CheckName() string             { return "user_agent" }
func (c *userAgentCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *userAgentCheck) AppliesTo(cfg *SecurityConfig) bool {
	return len(cfg.BlockedUserAgents) > 0 || cfg.EnableDynamicRules
}

func userAgentApplies(cfg *SecurityConfig, routes []*RouteConfig) bool {
	return len(cfg.BlockedUserAgents) > 0 || cfg.EnableDynamicRules ||
		anyRoute(routes, func(rc *RouteConfig) bool { return len(rc.BlockedUserAgents) > 0 })
}

const maxUserAgentMatchLength = 512

func userAgentMatchesBlockedPattern(userAgent string, patterns []string) bool {
	subject := userAgent
	if len(subject) > maxUserAgentMatchLength {
		subject = subject[:maxUserAgentMatchLength]
	}
	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if compiled.MatchString(subject) {
			return true
		}
	}
	return false
}

func (c *userAgentCheck) Check(req Request) *Response {
	cfg := c.cfg
	state := req.State()
	if state.IsWhitelisted || state.IsExempt {
		return nil
	}
	routeConfig := state.RouteConfig
	userAgent, _ := req.Headers().Get("User-Agent")
	blocked := false
	if routeConfig != nil && len(routeConfig.BlockedUserAgents) > 0 {
		blocked = userAgentMatchesBlockedPattern(userAgent, routeConfig.BlockedUserAgents)
	}
	if !blocked && userAgentMatchesBlockedPattern(userAgent, cfg.BlockedUserAgents) {
		blocked = true
	}
	if !blocked {
		return nil
	}
	reason := fmt.Sprintf("Blocked user agent: %s", userAgent)
	stashBlock(state, reason, "")
	if cfg.PassiveMode {
		firePassiveBlockHook(cfg, req, "user_agent", reason, "")
		return nil
	}
	return createErrorResponse(cfg, 403, "User-Agent not allowed")
}
