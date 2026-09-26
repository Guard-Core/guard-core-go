package guardcore

import (
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

type UnsupportedFeatureError struct {
	Feature string
	Reason  string
}

func (e *UnsupportedFeatureError) Error() string {
	return fmt.Sprintf("unsupported feature %q enabled: %s (fail-closed per conformance.md)", e.Feature, e.Reason)
}

const (
	DefaultRedisPrefix        = "guard_core:"
	DefaultRedisURL           = "redis://localhost:6379"
	DefaultTrustedProxyDepth  = 1
	UnknownClientIdentity     = "unknown"
	BlockedStatusSecurityFail = 500

	// DefaultDetectionBinaryMinRunLength mirrors the default of the
	// detection_binary_min_run_length SecurityConfig field (guard-core
	// 4.0.4, upstream commit 5f399234): the shortest printable run inside a
	// binary-dense multipart file-part payload that still reaches the
	// pattern scan.
	DefaultDetectionBinaryMinRunLength = 16

	// DefaultCORSMaxAge mirrors the cors_max_age SecurityConfig default
	// (_security_config_fields.py); a configured 0 falls back to it like
	// the reference `config.cors_max_age or 600`.
	DefaultCORSMaxAge = 600

	// DefaultBehaviorMaxResponseBodyInspectBytes mirrors the
	// behavior_max_response_body_inspect_bytes default
	// (_security_config_fields.py); a configured 0 falls back to it, and
	// configured values must stay within [1024, 10485760] like the
	// reference ge/le bounds.
	DefaultBehaviorMaxResponseBodyInspectBytes = 262144
)

var AllDetectionCategories = []string{
	"xss", "sqli", "dir_traversal", "path_traversal", "cmd_injection",
	"file_inclusion", "ldap", "xml", "ssrf", "nosql", "file_upload",
	"template", "http_split", "sensitive_file", "cms_probing", "recon",
	"proto_pollution", "code_injection", "deserialization",
}

var ValidThreatBanCategories = func() map[string]bool {
	m := map[string]bool{"rate_limit": true}
	for _, c := range AllDetectionCategories {
		m[c] = true
	}
	return m
}()

var DefaultExcludePaths = []string{
	"/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static",
}

var CheckNameValues = []string{
	"route_config", "emergency_mode", "https_enforcement", "request_logging",
	"request_size_content", "required_headers", "authentication", "referrer",
	"custom_validators", "time_window", "cloud_ip_refresh", "ip_security",
	"cloud_provider", "user_agent", "rate_limit", "suspicious_activity",
	"custom_request",
}

var ValidBypassChecks = map[string]bool{
	"all": true, "ip_ban": true, "ip": true, "clouds": true,
	"rate_limit": true, "penetration": true,
}

var ValidLogLevels = map[string]bool{
	"INFO": true, "DEBUG": true, "WARNING": true, "ERROR": true, "CRITICAL": true,
}

type SecurityConfig struct {
	TrustedProxies       []string
	TrustedProxyDepth    int
	TrustXForwardedProto bool
	Whitelist            []string
	ExemptIPs            []string
	Blacklist            []string

	EnableRedis   bool
	RedisURL      string
	RedisPrefix   string
	RedisFailOpen bool

	EnableIPBanning        bool
	AutoBanThreshold       int
	AutoBanDuration        int
	ThreatBanConfig        map[string]ThreatBanEntry
	EnableRateLimitAutoBan bool

	EnableRateLimiting bool
	RateLimit          int
	RateLimitWindow    int
	EndpointRateLimits map[string]RateLimitEntry

	EnablePenetrationDetection  bool
	EnabledDetectionCategories  []string
	ExcludedDetectionHeaders    map[string]bool
	ExcludedDetectionParams     map[string]bool
	ExcludedDetectionBodyFields map[string]bool
	// DetectionScanBody mirrors the reference detection_scan_body
	// SecurityConfig field (default true; nil is the default): when false
	// the body surface is not scanned at all. A route's DetectionScanBody
	// overrides it per route (see RouteConfig).
	DetectionScanBody           *bool
	DetectionBinaryMinRunLength int
	Detection                   Config

	PassiveMode           bool
	FailSecure            bool
	RouteResolutionStrict bool
	ExcludePaths          []string
	CustomErrorResponses  map[int]string
	SecurityHeaders       *SecurityHeadersConfig

	OnBlock func(req Request, payload map[string]any)

	MutedCheckLogs         map[string]bool
	LogSensitiveHeaders    map[string]bool
	LogSensitiveParams     map[string]bool
	LogSensitiveBodyFields map[string]bool

	EnforceHTTPS       bool
	EmergencyMode      bool
	EmergencyWhitelist []string
	AuthVerifier       AuthVerifier
	EnableDynamicRules bool
	EnableAgent        bool
	EnableCORS         bool

	// CORS surface, mirrored from the reference cors_* SecurityConfig
	// fields (_security_config_fields.py): default origins/headers are the
	// wildcard, default methods cover the six common verbs, default
	// max_age is 600. Validate() uppercases the methods, lowercases the
	// header names, and rejects the wildcard+credentials misconfiguration.
	CORSAllowOrigins     []string
	CORSAllowMethods     []string
	CORSAllowHeaders     []string
	CORSAllowCredentials bool
	CORSExposeHeaders    []string
	CORSMaxAge           int

	BlockCloudProviders []string
	BlockedUserAgents   []string
	WhitelistCountries  []string
	BlockedCountries    []string

	// GeoIP country rules resolve through GeoIPHandler; when it is nil and
	// country rules are configured, Validate builds a GeoIPManager over
	// GeoIPDBPath (the reference _resolve_geo_ip_handler building an
	// IPInfoManager from ipinfo_db_path). Country rules with neither a
	// handler nor a database path fail config construction.
	GeoIPDBPath  string
	GeoIPHandler CountryResolver

	// IPInfo lifecycle surface, mirrored from the reference IPInfoManager
	// (guard_core/handlers/ipinfo_handler.py): a non-empty IPInfoToken turns
	// the built-in GeoIPManager into the full download/refresh lifecycle
	// (bearer-authenticated download of the free country_asn database with
	// exponential-backoff retries, an atomic temp-file write, the Redis
	// ("ipinfo","database") cache copy with the max-age TTL, and mtime-based
	// staleness refresh). GeoIPDBPath overrides the default
	// data/ipinfo/country_asn.mmdb location, and IPInfoMaxAge overrides the
	// reference default of 86400 seconds. An empty token keeps the
	// local-file-only mode of the GeoIPDBPath contract.
	IPInfoToken  string
	IPInfoMaxAge int

	// OnGeoEvent is the engine-level geo event hook, the Go stand-in for the
	// reference event-bus subscribers: it receives every country_blocked,
	// geo_lookup_failed and decorator_violation event with the reference
	// event names and fields (see GeoEvent). Nil means no subscriber.
	OnGeoEvent func(GeoEvent)

	// Behavior-rules surface, mirrored from the reference
	// _security_config_fields.py: GlobalBehaviorRules applies to every
	// route in addition to any route-specific rules (RouteConfig.BehaviorRules);
	// BehaviorScanResponseBody gates reading response bodies for
	// return_pattern rules whose pattern is not a status: pattern (default
	// off: zero behavior change unless enabled, and Validate rejects such
	// rules while it is off, mirroring the reference's fail-closed
	// _validate_return_pattern_requires_scan); the inspect-bytes cap bounds
	// how much of the leading response body is held for pattern inspection.
	// Both rule sets and the scan flag are validated together by
	// validateBehaviorRulesAgainstScanFlag, mirroring
	// _validate_global_behavior_rule_assignment.
	GlobalBehaviorRules                 []BehaviorRuleConfig
	BehaviorScanResponseBody            bool
	BehaviorMaxResponseBodyInspectBytes int
	CustomRequestCheck                  func(req Request) *Response
	LogRequestLevel                     string
	LogSuspiciousLevel                  string

	CloudIPRefreshInterval int

	revision atomic.Uint64
}

func DefaultSecurityConfig() *SecurityConfig {
	categories := make([]string, len(AllDetectionCategories))
	copy(categories, AllDetectionCategories)
	return &SecurityConfig{
		TrustedProxyDepth:                   DefaultTrustedProxyDepth,
		EnableRedis:                         true,
		RedisURL:                            DefaultRedisURL,
		RedisPrefix:                         DefaultRedisPrefix,
		EnableIPBanning:                     true,
		AutoBanThreshold:                    DefaultAutoBanThreshold,
		AutoBanDuration:                     DefaultAutoBanDuration,
		ThreatBanConfig:                     map[string]ThreatBanEntry{},
		EnableRateLimiting:                  true,
		RateLimit:                           DefaultRateLimit,
		RateLimitWindow:                     DefaultRateLimitWindow,
		EndpointRateLimits:                  map[string]RateLimitEntry{},
		EnablePenetrationDetection:          true,
		EnabledDetectionCategories:          categories,
		ExcludedDetectionHeaders:            map[string]bool{},
		ExcludedDetectionParams:             map[string]bool{},
		ExcludedDetectionBodyFields:         map[string]bool{},
		DetectionBinaryMinRunLength:         DefaultDetectionBinaryMinRunLength,
		Detection:                           DefaultConfig(),
		FailSecure:                          true,
		ExcludePaths:                        append([]string(nil), DefaultExcludePaths...),
		CustomErrorResponses:                map[int]string{},
		SecurityHeaders:                     DefaultSecurityHeaders(),
		MutedCheckLogs:                      map[string]bool{},
		LogSensitiveHeaders:                 map[string]bool{},
		LogSensitiveParams:                  map[string]bool{},
		LogSensitiveBodyFields:              map[string]bool{},
		CORSAllowOrigins:                    []string{"*"},
		CORSAllowMethods:                    []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		CORSAllowHeaders:                    []string{"*"},
		CORSMaxAge:                          DefaultCORSMaxAge,
		BehaviorMaxResponseBodyInspectBytes: DefaultBehaviorMaxResponseBodyInspectBytes,
		CloudIPRefreshInterval:              DefaultCloudIPRefreshInterval,
	}
}

func NewSecurityConfig(mutate func(*SecurityConfig)) (*SecurityConfig, error) {
	cfg := DefaultSecurityConfig()
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *SecurityConfig) Revision() uint64 { return c.revision.Load() }

func (c *SecurityConfig) BumpRevision() { c.revision.Add(1) }

func (c *SecurityConfig) unsupported(feature, reason string) error {
	return &UnsupportedFeatureError{Feature: feature, Reason: reason}
}

// validateBehaviorRules mirrors the BehaviorRuleConfig constraints and the
// global-rule assignment validation: each rule is normalized (window and
// action defaults) and checked against the pydantic bounds, and any
// return_pattern rule needing the response body fails construction while
// behavior_scan_response_body is off (_validate_global_behavior_rule_assignment
// runs against both fields' final values, which a whole-config Validate
// covers in one pass).
func (c *SecurityConfig) validateBehaviorRules() error {
	for i := range c.GlobalBehaviorRules {
		if err := ValidateBehaviorRuleConfig(&c.GlobalBehaviorRules[i]); err != nil {
			return fmt.Errorf("global_behavior_rules[%d]: %w", i, err)
		}
	}
	if err := validateBehaviorRulesAgainstScanFlag(c.GlobalBehaviorRules, c.BehaviorScanResponseBody, "global_behavior_rules"); err != nil {
		return err
	}
	if c.BehaviorMaxResponseBodyInspectBytes == 0 {
		c.BehaviorMaxResponseBodyInspectBytes = DefaultBehaviorMaxResponseBodyInspectBytes
	} else if c.BehaviorMaxResponseBodyInspectBytes < 1024 || c.BehaviorMaxResponseBodyInspectBytes > 10485760 {
		return fmt.Errorf("behavior_max_response_body_inspect_bytes: must be between 1024 and 10485760, got %d", c.BehaviorMaxResponseBodyInspectBytes)
	}
	return nil
}

func (c *SecurityConfig) Validate() error {
	if c.EnableDynamicRules {
		return c.unsupported("enable_dynamic_rules", "dynamic rules are not implemented in this port yet")
	}
	if c.EnableAgent {
		return c.unsupported("enable_agent", "Guard Agent telemetry is not implemented in this port yet")
	}
	if err := c.validateBehaviorRules(); err != nil {
		return err
	}
	if err := validateCORS(c); err != nil {
		return err
	}
	if len(c.WhitelistCountries) > 0 && len(c.BlockedCountries) > 0 {
		// The reference warns (UserWarning) instead of erroring: the
		// allowlist is restrictive and shadows the blocklist.
		log.Printf("blocked_countries is ignored when whitelist_countries is non-empty: a non-empty whitelist_countries is restrictive (only listed countries pass), so blocked_countries has no effect. Use one or the other.")
	}
	c.WhitelistCountries = normalizeCountryList(c.WhitelistCountries)
	c.BlockedCountries = normalizeCountryList(c.BlockedCountries)
	if c.IPInfoToken == "" && c.IPInfoMaxAge != 0 {
		return fmt.Errorf("ipinfo_max_age is set but ipinfo_token is empty: the download lifecycle needs an IPInfo token (the reference IPInfoManager raises ValueError: 'IPInfo token is required!')")
	}
	if c.IPInfoToken != "" {
		if c.IPInfoMaxAge < 0 {
			return fmt.Errorf("ipinfo_max_age: must be >= 1, got %d", c.IPInfoMaxAge)
		}
		if c.IPInfoMaxAge == 0 {
			c.IPInfoMaxAge = DefaultIPInfoMaxAge
		}
	}
	if (len(c.BlockedCountries) > 0 || len(c.WhitelistCountries) > 0) && c.GeoIPHandler == nil {
		if c.GeoIPDBPath == "" && c.IPInfoToken == "" {
			return fmt.Errorf("geo_ip_handler is required if blocked_countries or whitelist_countries is set (set GeoIPDBPath to an MMDB database or inject a GeoIPHandler)")
		}
		maxAge := c.IPInfoMaxAge
		if maxAge <= 0 {
			maxAge = DefaultIPInfoMaxAge
		}
		c.GeoIPHandler = NewIPInfoManager(c.IPInfoToken, c.GeoIPDBPath, maxAge, c)
	}
	for _, selector := range c.BlockCloudProviders {
		provider, _, _ := strings.Cut(selector, ":!")
		if !ValidCloudProviders[provider] {
			return fmt.Errorf("block_cloud_providers: unknown cloud provider %q (valid: %v; a bare name blocks the whole provider, suffix ':!region' carves out a region exception)", selector, AllCloudProviders)
		}
	}
	if level := strings.ToUpper(c.LogRequestLevel); level != "" {
		if !ValidLogLevels[level] {
			return fmt.Errorf("log_request_level: invalid level %q (want INFO/DEBUG/WARNING/ERROR/CRITICAL)", c.LogRequestLevel)
		}
		c.LogRequestLevel = level
	}
	if level := strings.ToUpper(c.LogSuspiciousLevel); level != "" {
		if !ValidLogLevels[level] {
			return fmt.Errorf("log_suspicious_level: invalid level %q (want INFO/DEBUG/WARNING/ERROR/CRITICAL)", c.LogSuspiciousLevel)
		}
		c.LogSuspiciousLevel = level
	} else {
		c.LogSuspiciousLevel = "WARNING"
	}

	if c.TrustedProxyDepth < 1 {
		return fmt.Errorf("trusted_proxy_depth: must be >= 1, got %d", c.TrustedProxyDepth)
	}
	for _, pattern := range c.BlockedUserAgents {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("blocked_user_agents: invalid pattern %q: %w", pattern, err)
		}
	}
	if err := validateIPList("trusted_proxies", c.TrustedProxies); err != nil {
		return err
	}
	if err := validateIPList("whitelist", c.Whitelist); err != nil {
		return err
	}
	if err := validateIPList("exempt_ips", c.ExemptIPs); err != nil {
		return err
	}
	if err := validateIPList("blacklist", c.Blacklist); err != nil {
		return err
	}
	if c.AutoBanThreshold < 1 {
		return fmt.Errorf("auto_ban_threshold: must be >= 1, got %d", c.AutoBanThreshold)
	}
	if c.AutoBanDuration < 1 {
		return fmt.Errorf("auto_ban_duration: must be >= 1, got %d", c.AutoBanDuration)
	}
	for category, entry := range c.ThreatBanConfig {
		if !ValidThreatBanCategories[category] {
			return fmt.Errorf("threat_ban_config: unknown category %q", category)
		}
		if entry.Threshold < 1 {
			return fmt.Errorf("threat_ban_config[%s]: threshold must be >= 1, got %d", category, entry.Threshold)
		}
		if entry.Duration < 1 {
			return fmt.Errorf("threat_ban_config[%s]: duration must be >= 1, got %d", category, entry.Duration)
		}
	}
	if c.RateLimit < 1 {
		return fmt.Errorf("rate_limit: must be >= 1, got %d", c.RateLimit)
	}
	if c.RateLimitWindow < 1 {
		return fmt.Errorf("rate_limit_window: must be >= 1, got %d", c.RateLimitWindow)
	}
	for endpoint, entry := range c.EndpointRateLimits {
		if entry.Requests < 1 {
			return fmt.Errorf("endpoint_rate_limits[%s]: requests must be >= 1, got %d", endpoint, entry.Requests)
		}
		if entry.Window < 1 {
			return fmt.Errorf("endpoint_rate_limits[%s]: window must be >= 1, got %d", endpoint, entry.Window)
		}
	}
	validCategories := map[string]bool{}
	for _, cat := range AllDetectionCategories {
		validCategories[cat] = true
	}
	for _, cat := range c.EnabledDetectionCategories {
		if !validCategories[cat] {
			return fmt.Errorf("enabled_detection_categories: unknown category %q", cat)
		}
	}
	if c.EnablePenetrationDetection && len(c.EnabledDetectionCategories) == 0 {
		return fmt.Errorf("enabled_detection_categories: detection is enabled but no categories are enabled, so it can never match")
	}
	if c.DetectionBinaryMinRunLength < 4 || c.DetectionBinaryMinRunLength > 1024 {
		// Python constrains the field with pydantic ge=4 / le=1024.
		return fmt.Errorf("detection_binary_min_run_length: must be within [4, 1024], got %d", c.DetectionBinaryMinRunLength)
	}
	for name := range c.MutedCheckLogs {
		if !isKnownCheckName(name) {
			return fmt.Errorf("muted_check_logs: unknown check name %q", name)
		}
	}
	for i, entry := range c.ExcludePaths {
		if len(entry) == 0 || entry[0] != '/' {
			return fmt.Errorf("exclude_paths[%d]: %q is not an absolute path", i, entry)
		}
	}
	if err := validateSecurityHeaders(c.SecurityHeaders); err != nil {
		return err
	}
	if c.Detection.CompilerTimeout <= 0 {
		c.Detection.CompilerTimeout = 2 * time.Second
	}
	if c.Detection.MaxContentLength <= 0 {
		c.Detection.MaxContentLength = 10000
	}
	if c.Detection.MaxBodyInspectBytes <= 0 {
		c.Detection.MaxBodyInspectBytes = 262144
	}
	if c.CloudIPRefreshInterval <= 0 {
		c.CloudIPRefreshInterval = DefaultCloudIPRefreshInterval
	}
	if c.CloudIPRefreshInterval < MinCloudIPRefreshInterval {
		c.CloudIPRefreshInterval = MinCloudIPRefreshInterval
	}
	if c.CloudIPRefreshInterval > MaxCloudIPRefreshInterval {
		c.CloudIPRefreshInterval = MaxCloudIPRefreshInterval
	}
	if c.RedisURL == "" {
		c.RedisURL = DefaultRedisURL
	}
	if c.RedisPrefix == "" {
		c.RedisPrefix = DefaultRedisPrefix
	}
	if c.EndpointRateLimits == nil {
		c.EndpointRateLimits = map[string]RateLimitEntry{}
	}
	if c.ThreatBanConfig == nil {
		c.ThreatBanConfig = map[string]ThreatBanEntry{}
	}
	if c.CustomErrorResponses == nil {
		c.CustomErrorResponses = map[int]string{}
	}
	if c.MutedCheckLogs == nil {
		c.MutedCheckLogs = map[string]bool{}
	}
	if c.LogSensitiveHeaders == nil {
		c.LogSensitiveHeaders = map[string]bool{}
	}
	if c.LogSensitiveParams == nil {
		c.LogSensitiveParams = map[string]bool{}
	}
	if c.LogSensitiveBodyFields == nil {
		c.LogSensitiveBodyFields = map[string]bool{}
	}
	return nil
}

func validateIPList(field string, entries []string) error {
	for _, entry := range entries {
		if strings.HasSuffix(entry, "/0") {
			if _, err := netip.ParsePrefix(entry); err != nil {
				return fmt.Errorf("%s: invalid IP or CIDR %q", field, entry)
			}
			continue
		}
		if _, err := netip.ParseAddr(entry); err != nil {
			if _, perr := netip.ParsePrefix(entry); perr != nil {
				return fmt.Errorf("%s: invalid IP or CIDR %q", field, entry)
			}
		}
	}
	return nil
}

// normalizeCountryList mirrors the reference coerce_country_set
// (guard_core/_security_config_geo_validators.py): every entry is uppercased
// and duplicates collapse (frozenset semantics). ISO codes are not
// format-validated, exactly like the reference.
func normalizeCountryList(entries []string) []string {
	if len(entries) == 0 {
		return entries
	}
	seen := make(map[string]bool, len(entries))
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		code := strings.ToUpper(entry)
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out
}

// containsCountry answers exact membership, the reference
// `country in blocked_countries` check.
func containsCountry(entries []string, code string) bool {
	for _, entry := range entries {
		if entry == code {
			return true
		}
	}
	return false
}

func isKnownCheckName(name string) bool {
	for _, known := range CheckNameValues {
		if known == name {
			return true
		}
	}
	return false
}

func canonicalizeIPString(value string) string {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return value
	}
	return addr.String()
}

func ipMatchesList(ip string, entries []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry, "/0") || strings.Contains(entry, "/") {
			prefix, perr := netip.ParsePrefix(entry)
			if perr != nil {
				continue
			}
			if prefix.Contains(addr.Unmap()) || prefix.Contains(addr) {
				return true
			}
			continue
		}
		if canonicalizeIPString(entry) == addr.String() {
			return true
		}
	}
	return false
}

func redactURLForDisplay(path string, query map[string]string, sensitiveParams map[string]bool) string {
	if len(query) == 0 || len(sensitiveParams) == 0 {
		return path
	}
	var b strings.Builder
	b.WriteString(path)
	first := true
	for k, v := range query {
		if first {
			b.WriteByte('?')
			first = false
		} else {
			b.WriteByte('&')
		}
		b.WriteString(urlQueryEscape(k))
		b.WriteByte('=')
		if sensitiveParams[strings.ToLower(k)] {
			b.WriteString("[REDACTED]")
		} else {
			b.WriteString(urlQueryEscape(v))
		}
	}
	return b.String()
}

func urlQueryEscape(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}
