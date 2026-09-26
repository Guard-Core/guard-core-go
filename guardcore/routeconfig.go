package guardcore

import (
	"sync"
	"sync/atomic"
)

type AuthVerifier func(req Request, credential string) (any, error)

type RequiredHeader struct {
	Name  string
	Value string
}

type RequiredHeaders []RequiredHeader

func (h RequiredHeaders) Lookup(name string) (string, bool) {
	for _, entry := range h {
		if entry.Name == name {
			return entry.Value, true
		}
	}
	return "", false
}

type RouteConfig struct {
	RateLimit                   int
	RateLimitWindow             int
	IPWhitelist                 []string
	IPBlacklist                 []string
	BlockedCountries            []string
	WhitelistCountries          []string
	BypassedChecks              []string
	RequireHTTPS                bool
	AuthRequired                string
	BlockedUserAgents           []string
	RequiredHeaders             RequiredHeaders
	BlockCloudProviders         []string
	MaxRequestSize              int64
	AllowedContentTypes         []string
	TimeRestrictions            map[string]string
	EnableSuspiciousDetection   bool
	RequireReferrer             []string
	APIKeyRequired              bool
	AuthVerifier                AuthVerifier
	APIKeyVerifier              AuthVerifier
	APIKeyHeader                string
	AuthorizationHeaderRequired string
	GeoRateLimits               map[string]RateLimitEntry
	CustomValidators            []func(req Request) *Response

	// BehaviorRules carries the route's behavior rules (the reference
	// route_config.behavior_rules list the behavioral decorators append
	// to). Rules must be validated with ValidateBehaviorRuleConfig; the
	// processor drops invalid rules with a warning instead of running
	// them.
	BehaviorRules []BehaviorRuleConfig
}

func (r *RouteConfig) HasBypass(name string) bool {
	for _, b := range r.BypassedChecks {
		if b == name || b == "all" {
			return true
		}
	}
	return false
}

func ShouldBypassCheck(name string, routeConfig *RouteConfig) bool {
	return routeConfig != nil && routeConfig.HasBypass(name)
}

type RouteRegistry struct {
	mu       sync.RWMutex
	routes   map[string]*RouteConfig
	revision atomic.Uint64
}

func NewRouteRegistry() *RouteRegistry {
	return &RouteRegistry{routes: map[string]*RouteConfig{}}
}

func (r *RouteRegistry) Revision() uint64 { return r.revision.Load() }

func (r *RouteRegistry) Get(routeID string) *RouteConfig {
	if r == nil || routeID == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.routes[routeID]
}

func (r *RouteRegistry) Register(routeID string, mutate func(*RouteConfig)) *RouteConfig {
	rc := &RouteConfig{EnableSuspiciousDetection: true}
	if mutate != nil {
		mutate(rc)
	}
	r.mu.Lock()
	r.routes[routeID] = rc
	r.mu.Unlock()
	r.revision.Add(1)
	return rc
}

func (r *RouteRegistry) RouteConfigs() []*RouteConfig {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*RouteConfig, 0, len(r.routes))
	for _, rc := range r.routes {
		out = append(out, rc)
	}
	return out
}

func anyRoute(routes []*RouteConfig, predicate func(*RouteConfig) bool) bool {
	for _, rc := range routes {
		if predicate(rc) {
			return true
		}
	}
	return false
}

type RouteConfigResolver struct {
	registry *RouteRegistry
}

func NewRouteConfigResolver(registry *RouteRegistry) *RouteConfigResolver {
	return &RouteConfigResolver{registry: registry}
}

func (r *RouteConfigResolver) GetRouteConfig(state *RequestState) *RouteConfig {
	if state == nil {
		return nil
	}
	return r.registry.Get(state.GuardRouteID)
}
