package guardcore

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

// CORS handling, ported from the reference CorsHandler
// (guard_core/handlers/cors_handler.py) and its adapter dispatch contract
// (fastapi-guard guard/middleware.py _handle_preflight/_inject_cors_headers):
// a preflight short-circuits the request after the security pipeline ran,
// every response the engine returns composes the CORS headers on top of the
// security-header set, and a disallowed origin on a normal request simply
// gets no CORS headers (the browser enforces).

const preflightRequestHeader = "access-control-request-method"

// CORSPolicy is the resolved CORS configuration, the port of CorsHandler's
// initialized state. Methods are uppercased, header names lowercased, and
// the allow lists answer membership exactly like the reference.
type CORSPolicy struct {
	allowAllOrigins  bool
	allowOrigins     map[string]bool
	allowMethods     []string
	allowHeaders     []string
	allowAllHeaders  bool
	allowCredentials bool
	maxAge           int
	exposeHeaders    []string
}

func newCORSPolicy(cfg *SecurityConfig) *CORSPolicy {
	if cfg == nil || !cfg.EnableCORS {
		return nil
	}
	origins := cfg.CORSAllowOrigins
	allowAllOrigins := false
	for _, origin := range origins {
		if origin == "*" {
			allowAllOrigins = true
		}
	}
	allowHeaders := cfg.CORSAllowHeaders
	allowAllHeaders := false
	for _, header := range allowHeaders {
		if header == "*" {
			allowAllHeaders = true
		}
	}
	allowMethods := cfg.CORSAllowMethods
	if len(allowMethods) == 0 {
		// The reference falls back to ["GET"] when the configured method
		// list is empty (config.cors_allow_methods or ["GET"]).
		allowMethods = []string{"GET"}
	}
	maxAge := cfg.CORSMaxAge
	if maxAge == 0 {
		maxAge = 600
	}
	originsSet := make(map[string]bool, len(origins))
	for _, origin := range origins {
		originsSet[origin] = true
	}
	allowCredentials := cfg.CORSAllowCredentials
	if allowAllOrigins && allowCredentials {
		// The reference _compute_cors_config
		// (guard_core/handlers/_security_headers_config.py) downgrades the
		// wildcard + credentials misconfiguration at resolution time instead
		// of rejecting the configuration: it logs the error and drops the
		// credentials flag, so the wildcard policy answers without the
		// allow-credentials header (the browser blocks credentialed CORS).
		log.Printf("CORS config error: Wildcard origin disallowed with credentials")
		allowCredentials = false
	}
	return &CORSPolicy{
		allowAllOrigins:  allowAllOrigins,
		allowOrigins:     originsSet,
		allowMethods:     allowMethods,
		allowHeaders:     allowHeaders,
		allowAllHeaders:  allowAllHeaders,
		allowCredentials: allowCredentials,
		maxAge:           maxAge,
		exposeHeaders:    cfg.CORSExposeHeaders,
	}
}

func (p *CORSPolicy) isOriginAllowed(origin string) bool {
	if p.allowAllOrigins {
		return true
	}
	return p.allowOrigins[origin]
}

// IsPreflight mirrors is_preflight: an OPTIONS request carrying the
// access-control-request-method header.
func IsPreflight(req Request) bool {
	if !strings.EqualFold(req.Method(), "OPTIONS") {
		return false
	}
	_, ok := req.Headers().Get(preflightRequestHeader)
	return ok
}

// buildPreflightResponse mirrors CorsHandler.build_preflight_response: the
// CORS verdict headers are always attached (even to the 400 rejection),
// failures are listed in the body, and success answers 200 "OK".
func (p *CORSPolicy) buildPreflightResponse(req Request) *Response {
	headers := req.Headers()
	origin, _ := headers.Get("origin")
	requestedMethod := ""
	if method, ok := headers.Get(preflightRequestHeader); ok {
		requestedMethod = strings.ToUpper(method)
	}
	requestedHeadersRaw, _ := headers.Get("access-control-request-headers")
	var requestedHeaders []string
	for _, header := range strings.Split(requestedHeadersRaw, ",") {
		trimmed := strings.TrimSpace(header)
		if trimmed != "" {
			requestedHeaders = append(requestedHeaders, strings.ToLower(trimmed))
		}
	}

	resp := &Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("OK")}
	resp.SetHeader("Vary", "Origin")

	var failures []string
	if p.isOriginAllowed(origin) {
		allowedOrigin := origin
		if p.allowAllOrigins && !p.allowCredentials {
			allowedOrigin = "*"
		}
		resp.SetHeader("Access-Control-Allow-Origin", allowedOrigin)
	} else {
		failures = append(failures, "origin")
	}
	if !containsValue(p.allowMethods, requestedMethod) {
		failures = append(failures, "method")
	}
	if p.allowAllHeaders {
		if requestedHeadersRaw != "" {
			resp.SetHeader("Access-Control-Allow-Headers", requestedHeadersRaw)
		}
	} else {
		for _, header := range requestedHeaders {
			if !containsValue(p.allowHeaders, header) {
				failures = append(failures, "headers")
				break
			}
		}
	}

	resp.SetHeader("Access-Control-Allow-Methods", strings.Join(p.allowMethods, ", "))
	resp.SetHeader("Access-Control-Max-Age", strconv.Itoa(p.maxAge))
	if p.allowCredentials {
		resp.SetHeader("Access-Control-Allow-Credentials", "true")
	}

	if len(failures) > 0 {
		resp.StatusCode = 400
		resp.Body = []byte(fmt.Sprintf("Disallowed CORS: %s", strings.Join(failures, ", ")))
	}
	return resp
}

// buildResponseHeaders mirrors CorsHandler.build_response_headers: no CORS
// headers without an Origin header or for a disallowed origin (the browser
// enforces the policy), "*" only for a wildcard policy without credentials,
// and the echo of the request origin otherwise.
func (p *CORSPolicy) buildResponseHeaders(headers Headers) map[string]string {
	origin, ok := headers.Get("origin")
	if !ok || origin == "" {
		return nil
	}

	result := map[string]string{"Vary": "Origin"}

	if p.allowAllOrigins && !p.allowCredentials {
		result["Access-Control-Allow-Origin"] = "*"
	} else if p.isOriginAllowed(origin) {
		result["Access-Control-Allow-Origin"] = origin
	} else {
		return nil
	}

	// The reference get_cors_headers always composes the full CORS surface
	// on a CORS-enabled response (guard_core/handlers/_security_headers_cors.py
	// _build_cors_headers): methods, headers and a hardcoded 3600 max-age.
	result["Access-Control-Allow-Methods"] = strings.Join(p.allowMethods, ", ")
	if p.allowAllHeaders {
		result["Access-Control-Allow-Headers"] = "*"
	} else {
		result["Access-Control-Allow-Headers"] = strings.Join(p.allowHeaders, ", ")
	}
	result["Access-Control-Max-Age"] = "3600"

	if p.allowCredentials {
		result["Access-Control-Allow-Credentials"] = "true"
	}
	if len(p.exposeHeaders) > 0 {
		result["Access-Control-Expose-Headers"] = strings.Join(p.exposeHeaders, ", ")
	}
	return result
}

// injectResponseHeaders applies buildResponseHeaders onto an existing
// response, mirroring the adapter's _inject_cors_headers on every response
// path (blocked responses included, composing on top of the engine's
// security-header set).
func (p *CORSPolicy) injectResponseHeaders(resp *Response, headers Headers) {
	for name, value := range p.buildResponseHeaders(headers) {
		resp.SetHeader(name, value)
	}
}

// containsValue answers exact membership; the reference lists are compared
// with `in` after the policy normalized the case at construction.
func containsValue(entries []string, value string) bool {
	for _, entry := range entries {
		if entry == value {
			return true
		}
	}
	return false
}

// validateCORS normalizes the lists in place: methods uppercased, header
// names lowercased, exactly like CorsHandler._init_enabled. The wildcard +
// credentials combination is NOT rejected here: the reference pipeline
// response path (SecurityHeadersManager._compute_cors_config,
// guard_core/handlers/_security_headers_config.py) accepts the configuration
// at construction, logs an error, and drops the credentials flag so the
// wildcard policy blocks credentialed CORS at response time. newCORSPolicy
// applies the same downgrade.
func validateCORS(cfg *SecurityConfig) error {
	if !cfg.EnableCORS {
		return nil
	}
	for i, method := range cfg.CORSAllowMethods {
		cfg.CORSAllowMethods[i] = strings.ToUpper(method)
	}
	for i, header := range cfg.CORSAllowHeaders {
		cfg.CORSAllowHeaders[i] = strings.ToLower(header)
	}
	return nil
}
