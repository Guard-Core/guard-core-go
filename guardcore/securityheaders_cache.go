package guardcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Redis-backed security-headers configuration cache, ported from the
// reference SecurityHeadersCacheMixin (guard_core/handlers/
// _security_headers_cache.py) plus the manager's headers TTL cache
// (security_headers_handler.py): an in-memory TTL cache over the computed
// header set, the reference cache-key grammar, and the cross-worker
// sync of the CSP / HSTS / custom-header blocks through Redis
// (namespace security_headers, keys csp_config / hsts_config /
// custom_headers, 86400s TTL on writes, no TTL on load).

const (
	// HeadersCacheMaxSize and HeadersCacheTTL mirror the manager's
	// TTLCache(maxsize=1000, ttl=300).
	HeadersCacheMaxSize = 1000
	HeadersCacheTTL     = 300 * time.Second

	// HeadersConfigCacheTTL mirrors _cache_configuration's ttl=86400.
	HeadersConfigCacheTTL = 86400

	// HeadersRedisNamespace is the reference namespace.
	HeadersRedisNamespace = "security_headers"
)

// headersCacheEntry is one cached header set with its expiry.
type headersCacheEntry struct {
	headers  map[string]string
	expires  time.Time
	inserted int64
}

// headersTTLCache is the manager's headers_cache: a bounded map with a
// per-entry TTL. Eviction drops expired entries lazily and then the
// oldest-inserted at capacity (the reference cachetools TTLCache evicts
// expired-first and LRU; the insertion-order tiebreak is the documented
// divergence - the observable contract, a bounded cache whose entries
// expire after the TTL, holds).
type headersTTLCache struct {
	mu       sync.Mutex
	entries  map[string]headersCacheEntry
	order    []string
	clock    func() time.Time
	maxSize  int
	ttl      time.Duration
	requests int
	hits     int
}

func newHeadersTTLCache(maxSize int, ttl time.Duration) *headersTTLCache {
	return &headersTTLCache{
		entries: map[string]headersCacheEntry{},
		clock:   time.Now,
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// get returns the cached headers when present and unexpired.
func (c *headersTTLCache) get(key string) (map[string]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if c.clock().After(entry.expires) {
		delete(c.entries, key)
		c.dropOrder(key)
		return nil, false
	}
	c.hits++
	return entry.headers, true
}

// set stores the header set under the key, evicting the oldest-inserted
// entry at capacity.
func (c *headersTTLCache) set(key string, headers map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxSize {
		c.evictOldest()
	}
	c.entries[key] = headersCacheEntry{
		headers:  headers,
		expires:  c.clock().Add(c.ttl),
		inserted: int64(len(c.order)),
	}
	c.order = append(c.order, key)
}

func (c *headersTTLCache) evictOldest() {
	for _, key := range c.order {
		if _, exists := c.entries[key]; exists {
			delete(c.entries, key)
			c.dropOrder(key)
			return
		}
	}
}

func (c *headersTTLCache) dropOrder(key string) {
	for i, candidate := range c.order {
		if candidate == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// purge drops every entry (the manager reset path).
func (c *headersTTLCache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]headersCacheEntry{}
	c.order = nil
}

// len reports the live entry count (expired entries included; the purge
// happens lazily on access, like the reference).
func (c *headersTTLCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// SecurityHeadersManager is the ported SecurityHeadersManager state
// machine: the resolved header configuration (overridable from Redis),
// the headers TTL cache, and the Redis sync. Safe for concurrent use.
type SecurityHeadersManager struct {
	mu sync.Mutex

	// state is the resolved configuration the header set builds from.
	state *SecurityHeadersConfig
	// boundDefault is the configuration the manager was constructed with;
	// Reset restores it.
	boundDefault *SecurityHeadersConfig

	cache *headersTTLCache
	redis *RedisManager
	log   *log.Logger
	// agent is the handler the SecurityHeadersEventsMixin events ride
	// (initialize_agent); nil keeps every emission a no-op.
	agent AgentHandler
	// keyPrefix mirrors the reference cfg_{id(config)}_ prefix: a stable
	// per-instance token so concurrent managers never share cache keys.
	keyPrefix string
}

// NewSecurityHeadersManager binds the resolved configuration (the
// reference manager's configured state).
func NewSecurityHeadersManager(state *SecurityHeadersConfig) *SecurityHeadersManager {
	defaults := DefaultSecurityHeaders()
	if state == nil {
		state = defaults
	}
	return &SecurityHeadersManager{
		state:        state,
		boundDefault: state,
		cache:        newHeadersTTLCache(HeadersCacheMaxSize, HeadersCacheTTL),
		log:          log.Default(),
		keyPrefix:    fmt.Sprintf("cfg_%p_", state),
	}
}

// SetRedis attaches the Redis handler (initialize_redis's assignment
// step; the load and cache-back run in InitializeRedis).
func (m *SecurityHeadersManager) SetRedis(redis *RedisManager) {
	m.mu.Lock()
	m.redis = redis
	m.mu.Unlock()
}

// GenerateCacheKey mirrors _generate_cache_key: no path yields
// "default", otherwise "path_" over the sha256 of the lowercased,
// slash-stripped path, truncated to 16 hex chars; the whole key carries
// the per-instance prefix the reference derives from id(config).
func (m *SecurityHeadersManager) GenerateCacheKey(requestPath string) string {
	var base string
	if requestPath == "" {
		base = "default"
	} else {
		normalized := strings.ToLower(strings.Trim(requestPath, "/"))
		sum := sha256.Sum256([]byte(normalized))
		base = "path_" + hex.EncodeToString(sum[:])[:16]
	}
	return m.keyPrefix + base
}

// InitializeRedis mirrors initialize_redis: attach the handler, load the
// cached configuration, then cache the current configuration back.
func (m *SecurityHeadersManager) InitializeRedis(redis *RedisManager) {
	m.SetRedis(redis)
	m.LoadCachedConfig()
	m.CacheConfiguration()
}

// LoadCachedConfig mirrors _load_cached_config: each block loads
// independently and a failure anywhere logs a warning and keeps the
// current state.
func (m *SecurityHeadersManager) LoadCachedConfig() {
	m.mu.Lock()
	redis := m.redis
	state := m.state
	m.mu.Unlock()
	if redis == nil {
		return
	}
	if raw, err := redis.GetKey(HeadersRedisNamespace, "csp_config"); err != nil {
		m.log.Printf("Failed to load cached header config: %v", err)
	} else if raw != "" {
		var csp []CSPDirective
		if err := json.Unmarshal([]byte(raw), &csp); err != nil {
			m.log.Printf("Failed to load cached header config: %v", err)
		} else {
			m.mu.Lock()
			state.CSP = csp
			m.mu.Unlock()
		}
	}
	if raw, err := redis.GetKey(HeadersRedisNamespace, "hsts_config"); err != nil {
		m.log.Printf("Failed to load cached header config: %v", err)
	} else if raw != "" {
		var hsts HSTSConfig
		if err := json.Unmarshal([]byte(raw), &hsts); err != nil {
			m.log.Printf("Failed to load cached header config: %v", err)
		} else {
			m.mu.Lock()
			state.HSTS = &hsts
			m.mu.Unlock()
		}
	}
	if raw, err := redis.GetKey(HeadersRedisNamespace, "custom_headers"); err != nil {
		m.log.Printf("Failed to load cached header config: %v", err)
	} else if raw != "" {
		var custom map[string]string
		if err := json.Unmarshal([]byte(raw), &custom); err != nil {
			m.log.Printf("Failed to load cached header config: %v", err)
		} else {
			validated := make(map[string]string, len(custom))
			for name, value := range custom {
				validName, err := validateHeaderName(name)
				if err != nil {
					m.log.Printf("Failed to load cached header config: %v", err)
					continue
				}
				validValue, err := validateHeaderValue(value)
				if err != nil {
					m.log.Printf("Failed to load cached header config: %v", err)
					continue
				}
				validated[validName] = validValue
			}
			m.mu.Lock()
			state.Custom = validated
			m.mu.Unlock()
		}
	}
}

// CacheConfiguration mirrors _cache_configuration: every non-empty block
// persists as JSON with the 86400s TTL; failures log, never raise.
func (m *SecurityHeadersManager) CacheConfiguration() {
	m.mu.Lock()
	redis := m.redis
	state := m.state
	m.mu.Unlock()
	if redis == nil {
		return
	}
	ttl := HeadersConfigCacheTTL
	if len(state.CSP) > 0 {
		if payload, err := json.Marshal(state.CSP); err == nil {
			if err := redis.SetKey(HeadersRedisNamespace, "csp_config", string(payload), &ttl); err != nil {
				m.log.Printf("Failed to cache header configuration: %v", err)
			}
		}
	}
	if state.HSTS != nil {
		if payload, err := json.Marshal(state.HSTS); err == nil {
			if err := redis.SetKey(HeadersRedisNamespace, "hsts_config", string(payload), &ttl); err != nil {
				m.log.Printf("Failed to cache header configuration: %v", err)
			}
		}
	}
	if len(state.Custom) > 0 {
		if payload, err := json.Marshal(state.Custom); err == nil {
			if err := redis.SetKey(HeadersRedisNamespace, "custom_headers", string(payload), &ttl); err != nil {
				m.log.Printf("Failed to cache header configuration: %v", err)
			}
		}
	}
}

// SetAgentHandler attaches the agent handler the mixin events ride (the
// reference initialize_agent); nil keeps every emission a no-op.
func (m *SecurityHeadersManager) SetAgentHandler(agent AgentHandler) {
	m.mu.Lock()
	m.agent = agent
	m.mu.Unlock()
}

// GetHeaders mirrors get_headers: disabled configuration yields no
// headers, a cache hit returns the stored map, and a miss computes
// through the shared responseHeaders builder, caches the result and
// emits security_headers_applied (only on misses, only for non-empty
// paths, only with a handler attached - SecurityHeadersEventsMixin.
// _send_headers_applied_event's gate).
func (m *SecurityHeadersManager) GetHeaders(requestPath string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	m.mu.Lock()
	state := m.state
	agent := m.agent
	m.mu.Unlock()
	if state == nil || !state.Enabled {
		return map[string]string{}
	}
	key := m.GenerateCacheKey(requestPath)
	if cached, ok := m.cache.get(key); ok {
		return cached
	}
	headers := responseHeaders(&SecurityConfig{SecurityHeaders: state})
	m.cache.set(key, headers)
	if agent != nil && requestPath != "" {
		m.sendHeadersAppliedEvent(requestPath, headers)
	}
	return headers
}

// sendHeadersAppliedEvent mirrors _send_headers_applied_event: handler
// security_headers, action headers_added, no ip, and the path/headers
// metadata; failures are logged, never raised.
func (m *SecurityHeadersManager) sendHeadersAppliedEvent(path string, headers map[string]string) {
	m.mu.Lock()
	agent := m.agent
	m.mu.Unlock()
	if agent == nil {
		return
	}
	event := SecurityEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   EventSecurityHeadersApplied,
		ActionTaken: "headers_added",
		HandlerName: "security_headers",
		Metadata: map[string]any{
			"path":          redactEndpointForDisplay(path, nil),
			"headers_count": len(headers),
			"has_csp":       headers["Content-Security-Policy"] != "",
			"has_hsts":      headers["Strict-Transport-Security"] != "",
		},
	}
	if err := agent.SendEvent(event); err != nil {
		m.log.Printf("Failed to send headers event to agent: %v", err)
	}
}

// ValidateCSPReport mirrors validate_csp_report: the three required
// fields gate the verdict, the sanitized fields reach the warn log and
// the csp_violation event rides whenever a handler is attached. The
// return answers "is this a well-formed report".
func (m *SecurityHeadersManager) ValidateCSPReport(report map[string]any) bool {
	cspReport, _ := report["csp-report"].(map[string]any)
	for _, field := range []string{"document-uri", "violated-directive", "blocked-uri"} {
		if _, ok := cspReport[field]; !ok {
			return false
		}
	}
	safeDirective := safeCSPDirective(cspReport["violated-directive"])
	safeBlockedURI := safeCSPURI(cspReport["blocked-uri"])
	safeDocumentURI := safeCSPURI(cspReport["document-uri"])
	m.log.Printf("CSP Violation: %s blocked %s on %s", safeDirective, safeBlockedURI, safeDocumentURI)
	m.mu.Lock()
	agent := m.agent
	m.mu.Unlock()
	if agent != nil {
		m.sendCSPViolationEvent(cspReport)
	}
	return true
}

// sendCSPViolationEvent mirrors _send_csp_violation_event: handler
// security_headers, action logged, the sanitized report fields in
// metadata (source_file str()-ed like python, line_number int-or-nil).
func (m *SecurityHeadersManager) sendCSPViolationEvent(report map[string]any) {
	m.mu.Lock()
	agent := m.agent
	m.mu.Unlock()
	if agent == nil {
		return
	}
	metadata := map[string]any{
		"document_uri":       safeCSPURI(report["document-uri"]),
		"violated_directive": safeCSPDirective(report["violated-directive"]),
		"blocked_uri":        safeCSPURI(report["blocked-uri"]),
		"source_file":        safeCSPURI(report["source-file"]),
		"line_number":        safeCSPLineNumber(report["line-number"]),
	}
	event := SecurityEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   EventCSPViolation,
		ActionTaken: "logged",
		HandlerName: "security_headers",
		Metadata:    metadata,
	}
	if err := agent.SendEvent(event); err != nil {
		m.log.Printf("Failed to send CSP violation event to agent: %v", err)
	}
}

// safeCSPURI mirrors _safe_csp_uri: the value is str()-ed (python None
// becomes "None") and endpoint-redacted with the default sets.
func safeCSPURI(value any) string {
	return redactEndpointForDisplay(pythonStr(value), nil)
}

// safeCSPDirective mirrors _safe_csp_directive: header-value redaction
// over the str()-ed value.
func safeCSPDirective(value any) string {
	return RedactHeaderValueForDisplay(pythonStr(value), nil, nil, nil)
}

// safeCSPLineNumber mirrors _safe_csp_line_number: an integer value or nil.
func safeCSPLineNumber(value any) any {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return nil
}

// pythonStr mirrors python str(): nil renders "None", bools "true"/"false".
func pythonStr(value any) string {
	if value == nil {
		return "None"
	}
	if b, ok := value.(bool); ok {
		if b {
			return "true"
		}
		return "false"
	}
	return fmt.Sprint(value)
}

// CacheStats reports the cache hit/miss counters (observability for the
// TTL semantics the tests pin).
func (m *SecurityHeadersManager) CacheStats() (requests, hits, size int) {
	m.cache.mu.Lock()
	defer m.cache.mu.Unlock()
	return m.cache.requests, m.cache.hits, len(m.cache.entries)
}

// Reset mirrors reset: the cache and the override state clear, the
// bound default configuration returns, and the Redis security_headers
// keys are deleted.
func (m *SecurityHeadersManager) Reset() {
	m.cache.purge()
	m.mu.Lock()
	m.state = m.boundDefault
	redis := m.redis
	m.mu.Unlock()
	if redis != nil {
		if _, err := redis.DeletePattern(HeadersRedisNamespace + ":*"); err != nil {
			m.log.Printf("Failed to clear Redis cache: %v", err)
		}
	}
	m.SetRedis(nil)
}
