package guardcore

import (
	"errors"
	"io"
	"log"
	"slices"
	"sync"
	"time"
)

type Engine struct {
	Config    *SecurityConfig
	Routes    *RouteRegistry
	Redis     *RedisManager
	Ban       *IPBanManager
	RateLimit *RateLimitManager
	Cloud     *CloudManager
	CORS      *CORSPolicy
	Behavior  *BehaviorTracker

	pipeline       *SecurityCheckPipeline
	behaviorProc   *BehavioralProcessor
	exclusions     exclusionMatcher
	initializeOnce sync.Once
	initializeErr  error
}

func NewEngine(cfg *SecurityConfig) (*Engine, error) {
	if cfg == nil {
		return nil, errors.New("config must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	routes := NewRouteRegistry()
	redisManager := NewRedisManager(RedisConfig{URL: cfg.RedisURL, Prefix: cfg.RedisPrefix, EnableRedis: cfg.EnableRedis})
	ban := NewIPBanManager(redisManager, cfg.TrustedProxies)
	rateLimit := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), redisManager, ban)
	pipeline, counts := BuildDefaultPipeline(cfg, ban, rateLimit, routes)
	tracker := NewBehaviorTracker(cfg, redisManager, ban, log.Default())
	behavioral := NewBehavioralProcessor(cfg, tracker, counts, log.Default())
	return &Engine{
		Config:       cfg,
		Routes:       routes,
		Redis:        redisManager,
		Ban:          ban,
		RateLimit:    rateLimit,
		Behavior:     tracker,
		behaviorProc: behavioral,
		Cloud:        DefaultCloudManager,
		CORS:         newCORSPolicy(cfg),
		pipeline:     pipeline,
		exclusions: exclusionMatcher{
			cfg: cfg,
		},
	}, nil
}

func (e *Engine) Initialize() error {
	e.initializeOnce.Do(func() {
		e.initializeErr = e.startup()
	})
	return e.initializeErr
}

func (e *Engine) startup() error {
	if !e.Config.EnableRedis {
		e.initializeGeoLifecycle(nil)
		return e.refreshCloudRangesWithoutRedis()
	}
	if err := e.Redis.Initialize(); err != nil {
		if e.Config.RedisFailOpen {
			log.Printf("Redis unavailable during initialization, failing open: %v", err)
			e.initializeGeoLifecycle(nil)
			return e.refreshCloudRangesWithoutRedis()
		}
		return err
	}
	if len(e.Config.BlockCloudProviders) > 0 {
		if err := e.Cloud.InitializeRedis(e.Redis, e.Config.BlockCloudProviders, e.Config.CloudIPRefreshInterval); err != nil {
			return err
		}
	}
	if err := e.Ban.InitializeRedis(e.Redis); err != nil {
		return err
	}
	e.RateLimit.InitializeRedis(e.Redis)
	e.initializeGeoLifecycle(e.Redis)
	return nil
}

// initializeGeoLifecycle runs the reference geo_ip_handler initialization at
// middleware startup (handler_initializer steps: initialize_redis when Redis
// is up, plain initialize otherwise): the IPInfo download/refresh lifecycle
// executes here, and the first lookup only falls back to it lazily.
func (e *Engine) initializeGeoLifecycle(redis *RedisManager) {
	if lifecycle, ok := e.Config.GeoIPHandler.(GeoIPLifecycle); ok && e.Config.IPInfoToken != "" {
		lifecycle.InitializeGeo(redis)
	}
}

func (e *Engine) refreshCloudRangesWithoutRedis() error {
	if len(e.Config.BlockCloudProviders) == 0 {
		return nil
	}
	return e.Cloud.RefreshAsync(e.Config.BlockCloudProviders, e.Config.CloudIPRefreshInterval)
}

// Check runs the security pipeline. With CORS enabled it mirrors the
// reference adapter dispatch (fastapi-guard guard/middleware.py): a preflight
// request executes the pipeline first and is then answered by the CORS
// handler's short-circuit (200 "OK" or 400 "Disallowed CORS: ..."), and every
// blocked response composes the CORS headers on top of the engine's
// security-header set exactly like _inject_cors_headers.
func (e *Engine) Check(req Request) *Response {
	state := req.State()
	if e.CORS != nil && IsPreflight(req) {
		// The reference dispatch runs the preflight branch before the
		// passthrough handler marks the request exclusion-scoped, so the
		// pipeline executes unscoped here.
		if blocking := e.pipeline.Execute(req); blocking != nil {
			e.CORS.injectResponseHeaders(blocking, req.Headers())
			return blocking
		}
		return e.CORS.buildPreflightResponse(req)
	}
	if e.exclusions.matches(req.URLPath()) {
		state.ExclusionScoped = true
	}
	if routeConfig := e.Routes.Get(state.GuardRouteID); routeConfig != nil && routeConfig.HasBypass("all") && !e.Config.PassiveMode {
		return nil
	}
	resp := e.pipeline.Execute(req)
	if resp == nil {
		// The request passed the pipeline: usage/frequency behavior rules
		// track it (the reference runs process_usage_rules from the
		// adapter middleware on requests the checks did not block).
		e.behaviorProc.ProcessUsageRules(req, resolveClientIP(req), state.RouteConfig, behaviorClock())
	}
	if resp != nil && e.CORS != nil {
		e.CORS.injectResponseHeaders(resp, req.Headers())
	}
	return resp
}

// ProcessResponse mirrors the reference response factory's behavioral phase
// (guard_core/core/responses/factory.py process_response): after the adapter
// produced its response, the route's return_pattern rules run first, then
// the global ones. Return rules never modify the response; a matched rule
// dispatches its configured action (ban/log/throttle/alert). The adapter
// calls this on every pass-through response it sends.
func (e *Engine) ProcessResponse(req Request, resp *Response) {
	if e.behaviorProc == nil || resp == nil {
		return
	}
	now := behaviorClock()
	clientIP := resolveClientIP(req)
	state := req.State()
	e.behaviorProc.ProcessReturnRules(req, resp, clientIP, state.RouteConfig, now)
	e.behaviorProc.ProcessGlobalReturnRules(req, resp, clientIP, now)
}

// behaviorClock is time.Now as a float Unix timestamp, matching the
// reference's time.time() sliding-window arithmetic.
func behaviorClock() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (e *Engine) CreateErrorResponse(statusCode int, defaultMessage string) *Response {
	return createErrorResponse(e.Config, statusCode, defaultMessage)
}

// ResponseHeaders computes the security headers the adapter must put on every
// normal (pass-through) response, mirroring the reference where the response
// factory applies security_headers_manager.get_headers on the way out
// (guard_core/core/responses/factory.py process_response). Blocked responses
// already carry the headers: the pipeline's error factory applies them
// engine-side. An empty map means the feature is disabled.
func (e *Engine) ResponseHeaders() map[string]string {
	return responseHeaders(e.Config)
}

// CORSResponseHeaders computes the CORS headers the adapter must put on a
// normal (pass-through) response for this request, mirroring the reference
// _inject_cors_headers over CorsHandler.build_response_headers. It returns
// nil when CORS is disabled, when the request carries no Origin header, or
// when the origin is disallowed (the browser enforces the policy). Blocked
// responses returned from Check already carry these headers.
func (e *Engine) CORSResponseHeaders(req Request) map[string]string {
	if e.CORS == nil {
		return nil
	}
	return e.CORS.buildResponseHeaders(req.Headers())
}

func (e *Engine) Close() error {
	if closer, ok := e.Config.GeoIPHandler.(io.Closer); ok {
		// The built-in manager's Close only releases the MMDB handle; its
		// error must not mask the Redis shutdown.
		if err := closer.Close(); err != nil {
			_ = e.Redis.Close()
			return err
		}
	}
	return e.Redis.Close()
}

type exclusionMatcher struct {
	mu      sync.Mutex
	cfg     *SecurityConfig
	source  []string
	entries []string
}

func (m *exclusionMatcher) matches(path string) bool {
	normalized, ok := normalizeURLPath(path)
	if !ok {
		return false
	}
	return pathMatchesExclusions(normalized, m.current())
}

func (m *exclusionMatcher) current() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !slices.Equal(m.source, m.cfg.ExcludePaths) {
		m.source = append([]string(nil), m.cfg.ExcludePaths...)
		m.entries = nil
		for _, entry := range m.cfg.ExcludePaths {
			if normalized, ok := normalizeURLPath(entry); ok {
				m.entries = append(m.entries, normalized)
			}
		}
	}
	return m.entries
}
