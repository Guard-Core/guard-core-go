package guardcore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	DefaultRateLimit        = 10
	DefaultRateLimitWindow  = 60
	DefaultAutoBanThreshold = 10
	DefaultAutoBanDuration  = 3600
	maxTrackedRateLimitKeys = 10000
	RateLimitBlockedStatus  = 429
	RateLimitBlockedMessage = "Too many requests"
)

type RateLimitEntry struct {
	Requests int
	Window   int
}

type ThreatBanEntry struct {
	Threshold int
	Duration  int
}

type RateLimitConfig struct {
	EnableRateLimiting     bool
	RateLimit              int
	RateLimitWindow        int
	EndpointRateLimits     map[string]RateLimitEntry
	EnableRateLimitAutoBan bool
	PassiveMode            bool
	EnableIPBanning        bool
	AutoBanThreshold       int
	AutoBanDuration        int
	ThreatBanConfig        map[string]ThreatBanEntry
	RedisFailOpen          bool
}

func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		EnableRateLimiting:     true,
		RateLimit:              DefaultRateLimit,
		RateLimitWindow:        DefaultRateLimitWindow,
		EndpointRateLimits:     map[string]RateLimitEntry{},
		EnableRateLimitAutoBan: false,
		PassiveMode:            false,
		EnableIPBanning:        false,
		AutoBanThreshold:       DefaultAutoBanThreshold,
		AutoBanDuration:        DefaultAutoBanDuration,
		ThreatBanConfig:        map[string]ThreatBanEntry{},
		RedisFailOpen:          false,
	}
}

const rateLimitScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_start = now - window

redis.call('ZADD', key, now, now)

redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

local count = redis.call('ZCARD', key)

redis.call('EXPIRE', key, window * 2)

return count
`

type RateLimitRedis interface {
	ScriptLoad(script string) (string, error)
	EvalSha(sha, key string, now float64, window, limit int) (int64, error)
	PipelineRateLimit(key, member string, now, windowStart float64, window int) (int64, error)
}

func IsNoScriptError(err error) bool {
	return err != nil && strings.Contains(strings.ToUpper(err.Error()), "NOSCRIPT")
}

func (m *RedisManager) ensureRateLimitClient() (redis.UniversalClient, error) {
	if m.client == nil {
		if err := m.Initialize(); err != nil {
			return nil, err
		}
	}
	return m.client, nil
}

func (m *RedisManager) ScriptLoad(script string) (string, error) {
	client, err := m.ensureRateLimitClient()
	if err != nil {
		return "", err
	}
	sha, err := client.ScriptLoad(m.ctx, script).Result()
	if err != nil {
		return "", newGuardRedisError("Redis operation failed")
	}
	return sha, nil
}

func (m *RedisManager) EvalSha(sha, key string, now float64, window, limit int) (int64, error) {
	client, err := m.ensureRateLimitClient()
	if err != nil {
		return 0, err
	}
	count, err := client.EvalSha(m.ctx, sha, []string{key}, now, window, limit).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}

func (m *RedisManager) PipelineRateLimit(key, member string, now, windowStart float64, window int) (int64, error) {
	client, err := m.ensureRateLimitClient()
	if err != nil {
		return 0, err
	}
	pipe := client.TxPipeline()
	pipe.ZAdd(m.ctx, key, redis.Z{Score: now, Member: member})
	pipe.ZRemRangeByScore(m.ctx, key, "0", formatExpiry(windowStart))
	card := pipe.ZCard(m.ctx, key)
	pipe.Expire(m.ctx, key, time.Duration(window*2)*time.Second)
	if _, err := pipe.Exec(m.ctx); err != nil {
		return 0, err
	}
	return card.Val(), nil
}

var rateLimitFailOpenWarned atomic.Bool

func resetRateLimitFailOpenWarned() { rateLimitFailOpenWarned.Store(false) }

func warnRedisFailOpenInMemoryFallback(logger *log.Logger) {
	if rateLimitFailOpenWarned.Swap(true) {
		return
	}
	logger.Printf("Redis unavailable for rate limiting; using the in-memory window (redis_fail_open=True); with several workers the effective limit is workers x rate_limit")
}

func hashIdentitySegment(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func rateLimitRedisKey(prefix, clientIP, endpointPath string) string {
	if endpointPath != "" {
		return prefix + "rate_limit:rate:" + clientIP + ":" + hashIdentitySegment(endpointPath)
	}
	return prefix + "rate_limit:rate:" + clientIP
}

type lruStore[V any] struct {
	mu    sync.Mutex
	items map[string]V
	order []string
}

func newLRUStore[V any]() *lruStore[V] {
	return &lruStore[V]{items: make(map[string]V)}
}

func (s *lruStore[V]) getOrCreate(key string, create func() V) V {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.items[key]; ok {
		delete(s.items, key)
		s.order = append(s.order, key)
		s.items[key] = v
		return v
	}
	if len(s.items) >= maxTrackedRateLimitKeys {
		victim := s.order[0]
		s.order = s.order[1:]
		delete(s.items, victim)
	}
	v := create()
	s.items[key] = v
	s.order = append(s.order, key)
	return v
}

func (s *lruStore[V]) set(key string, v V) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[key]; !ok {
		if len(s.items) >= maxTrackedRateLimitKeys {
			victim := s.order[0]
			s.order = s.order[1:]
			delete(s.items, victim)
		}
		s.order = append(s.order, key)
	}
	s.items[key] = v
}

func (s *lruStore[V]) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

func (s *lruStore[V]) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = make(map[string]V)
	s.order = nil
}

func inMemoryRequestCount(store *lruStore[[]float64], key string, windowStart, currentTime float64) int {
	timestamps := store.getOrCreate(key, func() []float64 { return nil })
	i := 0
	for i < len(timestamps) && timestamps[i] <= windowStart {
		i++
	}
	timestamps = timestamps[i:]
	requestCount := len(timestamps)
	timestamps = append(timestamps, currentTime)
	store.set(key, timestamps)
	return requestCount
}

type RateLimitManager struct {
	mu              sync.Mutex
	cfg             RateLimitConfig
	redis           RedisHandler
	rlRedis         RateLimitRedis
	ban             *IPBanManager
	timestamps      *lruStore[[]float64]
	byIPTimestamps  *lruStore[[]float64]
	autobanCounts   *lruStore[int]
	scriptSHA       string
	logger          *log.Logger
	OnScriptReload  func()
	now             func() float64
	scriptReloadLog func()
	eventBus        *SecurityEventBus
	passiveMode     bool
}

// SetEventBus attaches the agent event stream so the manager emits the
// reference rate_limit handler events (rate_limited,
// rate_limit_script_reloaded).
func (m *RateLimitManager) SetEventBus(bus *SecurityEventBus, passiveMode bool) {
	m.mu.Lock()
	m.eventBus = bus
	m.passiveMode = passiveMode
	m.mu.Unlock()
}

func NewRateLimitManager(cfg RateLimitConfig, redisHandler RedisHandler, banManager *IPBanManager) *RateLimitManager {
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = DefaultRateLimit
	}
	if cfg.RateLimitWindow <= 0 {
		cfg.RateLimitWindow = DefaultRateLimitWindow
	}
	if cfg.AutoBanThreshold <= 0 {
		cfg.AutoBanThreshold = DefaultAutoBanThreshold
	}
	if cfg.AutoBanDuration <= 0 {
		cfg.AutoBanDuration = DefaultAutoBanDuration
	}
	return &RateLimitManager{
		cfg:            cfg,
		redis:          redisHandler,
		timestamps:     newLRUStore[[]float64](),
		byIPTimestamps: newLRUStore[[]float64](),
		autobanCounts:  newLRUStore[int](),
		ban:            banManager,
		logger:         log.Default(),
		now:            func() float64 { return float64(time.Now().UnixNano()) / 1e9 },
	}
}

func (m *RateLimitManager) initializeRateLimitRedis(h RedisHandler) {
	if rl, ok := h.(RateLimitRedis); ok {
		m.rlRedis = rl
	}
}

func (m *RateLimitManager) InitializeRedis(redisHandler RedisHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.redis = redisHandler
	if redisHandler == nil || !redisHandler.Enabled() {
		return
	}
	m.initializeRateLimitRedis(redisHandler)
	if m.rlRedis == nil {
		return
	}
	sha, err := m.rlRedis.ScriptLoad(rateLimitScript)
	if err != nil {
		m.logger.Printf("Failed to load rate limiting Lua script: %v", err)
		return
	}
	m.scriptSHA = sha
	m.logger.Printf("Rate limiting Lua script loaded successfully")
}

func (m *RateLimitManager) SetAgentHandlerHook(fn func()) {
	m.OnScriptReload = fn
}

func (m *RateLimitManager) emitScriptReloaded() {
	m.logger.Printf("Rate limit Lua script reloaded after NOSCRIPT")
	// Reference ratelimit_handler._emit_script_reloaded_event:
	// rate_limit_script_reloaded, handler rate_limit, ip system.
	m.mu.Lock()
	bus, passiveMode := m.eventBus, m.passiveMode
	m.mu.Unlock()
	if bus != nil {
		bus.SendHandlerEvent(EventRateLimitScriptReloaded, RateLimitHandlerName, "system", "script_reloaded",
			"NOSCRIPT recovery: Lua script re-cached on Redis", nil)
	}
	if m.OnScriptReload != nil {
		m.OnScriptReload()
	}
	_ = passiveMode
}

func (m *RateLimitManager) redisRequestCount(clientIP string, currentTime, windowStart float64, window, limit int, endpointPath string, forcePipeline bool) (int, bool, error) {
	m.mu.Lock()
	redisHandler := m.redis
	rlRedis := m.rlRedis
	sha := m.scriptSHA
	failOpen := m.cfg.RedisFailOpen
	m.mu.Unlock()

	if redisHandler == nil || !redisHandler.Enabled() || rlRedis == nil {
		return 0, false, nil
	}

	keyName := rateLimitRedisKey(redisHandler.Prefix(), clientIP, endpointPath)
	var count int64
	var err error

	if sha != "" && !forcePipeline {
		count, err = rlRedis.EvalSha(sha, keyName, currentTime, window, limit)
		if err != nil && IsNoScriptError(err) {
			newSHA, loadErr := rlRedis.ScriptLoad(rateLimitScript)
			if loadErr != nil {
				err = loadErr
			} else {
				m.mu.Lock()
				m.scriptSHA = newSHA
				m.mu.Unlock()
				m.emitScriptReloaded()
				count, err = rlRedis.EvalSha(newSHA, keyName, currentTime, window, limit)
			}
		}
	} else {
		member := strconv.FormatFloat(currentTime, 'f', -1, 64)
		count, err = rlRedis.PipelineRateLimit(keyName, member, currentTime, windowStart, window)
	}

	if err != nil {
		if failOpen {
			warnRedisFailOpenInMemoryFallback(m.logger)
			return 0, false, nil
		}
		m.logger.Printf("Redis rate limiting error: %v", err)
		return 0, true, &GuardRedisError{StatusCode: 503, Message: "Redis rate limiting unavailable"}
	}
	return int(count), true, nil
}

type rateLimitTier struct {
	name         string
	limit        int
	window       int
	endpointPath string
}

type RouteRateConfig struct {
	RateLimit       *int
	RateLimitWindow *int
	GeoRateLimits   map[string]RateLimitEntry
}

func (m *RateLimitManager) tiersFor(clientIP, urlPath string, route *RouteRateConfig, countryOfIP func(string) string) []rateLimitTier {
	var tiers []rateLimitTier
	if entry, ok := m.cfg.EndpointRateLimits[urlPath]; ok {
		tiers = append(tiers, rateLimitTier{name: "endpoint", limit: entry.Requests, window: entry.Window, endpointPath: urlPath})
	}
	if route != nil && route.RateLimit != nil {
		window := 60
		if route.RateLimitWindow != nil {
			window = *route.RateLimitWindow
		}
		tiers = append(tiers, rateLimitTier{name: "route", limit: *route.RateLimit, window: window, endpointPath: urlPath})
	}
	if route != nil && len(route.GeoRateLimits) > 0 {
		if countryOfIP != nil {
			country := countryOfIP(clientIP)
			entry, ok := route.GeoRateLimits[country]
			if !ok {
				entry, ok = route.GeoRateLimits["*"]
			}
			if ok {
				tiers = append(tiers, rateLimitTier{name: "geo", limit: entry.Requests, window: entry.Window, endpointPath: urlPath})
			}
		}
	}
	tiers = append(tiers, rateLimitTier{name: "global", limit: m.cfg.RateLimit, window: m.cfg.RateLimitWindow, endpointPath: ""})
	return tiers
}

type RateLimitOutcome struct {
	Blocked    bool
	Count      int
	Window     int
	Tier       string
	StatusCode int
	Message    string
}

func (o *RateLimitOutcome) RetryAfter() string {
	return strconv.Itoa(o.Window)
}

func (m *RateLimitManager) runTier(clientIP string, tier rateLimitTier) (blocked bool, count int, err error) {
	currentTime := m.now()
	windowStart := currentTime - float64(tier.window)

	redisCount, handled, redisErr := m.redisRequestCount(clientIP, currentTime, windowStart, tier.window, tier.limit, tier.endpointPath, false)
	if redisErr != nil {
		return false, 0, redisErr
	}
	if handled {
		if redisCount > tier.limit {
			return true, redisCount, nil
		}
		return false, redisCount, nil
	}

	key := clientIP
	if tier.endpointPath != "" {
		key = clientIP + ":" + hashIdentitySegment(tier.endpointPath)
	}
	requestCount := inMemoryRequestCount(m.timestamps, key, windowStart, currentTime)
	if requestCount >= tier.limit {
		return true, requestCount + 1, nil
	}
	return false, requestCount, nil
}

func (m *RateLimitManager) CheckRateLimit(clientIP, urlPath string, route *RouteRateConfig, countryOfIP func(string) string) (*RateLimitOutcome, error) {
	if !m.cfg.EnableRateLimiting {
		return &RateLimitOutcome{Blocked: false}, nil
	}
	m.mu.Lock()
	tiers := m.tiersFor(clientIP, urlPath, route, countryOfIP)
	m.mu.Unlock()
	var lastCount int
	var lastTier rateLimitTier
	for _, tier := range tiers {
		blocked, count, err := m.runTier(clientIP, tier)
		if err != nil {
			return nil, err
		}
		lastCount = count
		lastTier = tier
		if blocked {
			return &RateLimitOutcome{
				Blocked:    true,
				Count:      count,
				Window:     tier.window,
				Tier:       tier.name,
				StatusCode: RateLimitBlockedStatus,
				Message:    RateLimitBlockedMessage,
			}, nil
		}
	}
	return &RateLimitOutcome{Blocked: false, Count: lastCount, Window: lastTier.window, Tier: lastTier.name}, nil
}

func validateRateLimitPrimitiveInput(ip, endpointPath string) error {
	if _, err := netip.ParseAddr(ip); err != nil {
		return errors.New("check_rate_limit_by_ip: invalid ip " + strconv.Quote(ip))
	}
	if strings.Contains(endpointPath, ":") {
		return errors.New("check_rate_limit_by_ip: endpoint_path must not contain ':'")
	}
	return nil
}

func (m *RateLimitManager) CheckRateLimitByIP(ip, endpointPath string) (bool, error) {
	if err := validateRateLimitPrimitiveInput(ip, endpointPath); err != nil {
		return false, err
	}
	if !m.cfg.EnableRateLimiting {
		return true, nil
	}

	currentTime := m.now()
	windowStart := currentTime - float64(m.cfg.RateLimitWindow)

	allowed := false
	count, handled, err := m.redisRequestCount(ip, currentTime, windowStart, m.cfg.RateLimitWindow, m.cfg.RateLimit, endpointPath, true)
	if err != nil {
		return false, err
	}
	if handled {
		allowed = count <= m.cfg.RateLimit
	} else {
		key := ip
		if endpointPath != "" {
			key = ip + ":" + hashIdentitySegment(endpointPath)
		}
		requestCount := inMemoryRequestCount(m.byIPTimestamps, key, windowStart, currentTime)
		allowed = requestCount < m.cfg.RateLimit
	}

	if !allowed {
		m.feedRateLimitAutoban(ip)
	}
	return allowed, nil
}

func (m *RateLimitManager) feedRateLimitAutoban(ip string) {
	if !m.cfg.EnableRateLimitAutoBan || !m.cfg.EnableIPBanning {
		return
	}
	if m.cfg.PassiveMode {
		return
	}
	if m.ban == nil {
		return
	}
	if m.ban.IsIPBanned(ip) {
		return
	}
	count := m.autobanCounts.getOrCreate(ip, func() int { return 0 }) + 1
	m.autobanCounts.set(ip, count)
	ipCounts := map[string]int{"rate_limit": count}
	banned := m.resolveAndApplyThresholdBan(ip, ipCounts)
	if banned {
		m.logger.Printf("check_rate_limit_by_ip: auto-banned %s (rate_limit_exceeded)", ip)
	}
}

func (m *RateLimitManager) resolveAndApplyThresholdBan(ip string, ipCounts map[string]int) bool {
	if !m.cfg.EnableIPBanning {
		return false
	}
	if entry, ok := m.cfg.ThreatBanConfig["rate_limit"]; ok {
		if ipCounts["rate_limit"] >= entry.Threshold {
			applied, err := m.ban.Ban(ip, entry.Duration, "rate_limit_exceeded:rate_limit")
			if err != nil {
				m.logger.Printf("check_rate_limit_by_ip: auto-ban failed for %s: %v", ip, err)
				return false
			}
			return applied
		}
	}
	total := 0
	for _, v := range ipCounts {
		total += v
	}
	if total < m.cfg.AutoBanThreshold {
		return false
	}
	applied, err := m.ban.Ban(ip, m.cfg.AutoBanDuration, "rate_limit_exceeded")
	if err != nil {
		m.logger.Printf("check_rate_limit_by_ip: auto-ban failed for %s: %v", ip, err)
		return false
	}
	return applied
}

func (m *RateLimitManager) Reset() {
	m.mu.Lock()
	redisHandler := m.redis
	enabled := m.cfg.EnableRateLimiting
	m.mu.Unlock()
	_ = enabled

	m.timestamps.clear()
	m.byIPTimestamps.clear()
	m.autobanCounts.clear()

	if redisHandler != nil && redisHandler.Enabled() {
		if _, err := redisHandler.DeletePattern("rate_limit:rate:*"); err != nil {
			m.logger.Printf("Failed to reset Redis rate limits: %v", err)
		}
	}

	m.mu.Lock()
	m.redis = nil
	m.rlRedis = nil
	m.mu.Unlock()
}

func (m *RateLimitManager) TrackedKeyCount() int { return m.timestamps.len() }
func (m *RateLimitManager) ByIPKeyCount() int    { return m.byIPTimestamps.len() }
func (m *RateLimitManager) AutobanCount(ip string) int {
	return m.autobanCounts.getOrCreate(ip, func() int { return 0 })
}
