package guardcore

import (
	"fmt"
)

const CloudBlockedMsg = "Cloud provider IP not allowed"

func cloudBlockingEnabled(cfg *SecurityConfig) bool {
	return len(cfg.BlockCloudProviders) > 0 || cfg.EnableDynamicRules
}

func cloudApplies(cfg *SecurityConfig, routes []*RouteConfig) bool {
	return cloudBlockingEnabled(cfg) ||
		anyRoute(routes, func(rc *RouteConfig) bool { return len(rc.BlockCloudProviders) > 0 })
}

func cloudProvidersToCheck(routeConfig *RouteConfig, global []string) []string {
	if routeConfig != nil && len(routeConfig.BlockCloudProviders) > 0 {
		return routeConfig.BlockCloudProviders
	}
	if len(global) > 0 {
		return global
	}
	return nil
}

// routeCloudsOverride marks the routes whose own cloud selectors replace the
// global block list for a request, the only cloud blocking an exempt IP skips.
func routeCloudsOverride(routeConfig *RouteConfig) bool {
	return routeConfig != nil && len(routeConfig.BlockCloudProviders) > 0
}

type cloudIPRefreshCheck struct {
	cfg     *SecurityConfig
	manager *CloudManager
}

func (c *cloudIPRefreshCheck) CheckName() string             { return "cloud_ip_refresh" }
func (c *cloudIPRefreshCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *cloudIPRefreshCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg != nil && cloudBlockingEnabled(cfg)
}

func (c *cloudIPRefreshCheck) Check(req Request) *Response {
	providers := cloudProvidersToCheck(req.State().RouteConfig, c.cfg.BlockCloudProviders)
	if len(providers) == 0 {
		return nil
	}
	ttl := c.cfg.CloudIPRefreshInterval
	now := c.manager.nowUnix()
	if now-c.manager.LastRefreshStamp() <= int64(ttl) {
		return nil
	}
	previous := c.manager.LastRefreshStamp()
	c.manager.SetLastRefreshStamp(now)
	scheduled := c.manager.ScheduleRefresh(providers, ttl, func() error {
		return c.manager.RefreshAsync(providers, ttl)
	})
	if !scheduled {
		c.manager.SetLastRefreshStamp(previous)
	}
	return nil
}

type cloudProviderCheck struct {
	cfg     *SecurityConfig
	manager *CloudManager
}

func (c *cloudProviderCheck) CheckName() string             { return "cloud_provider" }
func (c *cloudProviderCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *cloudProviderCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg != nil && cloudBlockingEnabled(cfg)
}

func (c *cloudProviderCheck) Check(req Request) *Response {
	state := req.State()
	if state.IsWhitelisted {
		return nil
	}
	// An exempt IP skips only per-route cloud blocks; the global
	// block_cloud_providers list still applies to it, mirroring the reference
	// where the global list is enforced before the exempt flag can matter.
	if state.IsExempt && routeCloudsOverride(state.RouteConfig) {
		return nil
	}
	ip := resolveClientIP(req)
	if ip == "" {
		return nil
	}
	if ShouldBypassCheck("clouds", state.RouteConfig) {
		return nil
	}
	providers := cloudProvidersToCheck(state.RouteConfig, c.cfg.BlockCloudProviders)
	if len(providers) == 0 {
		return nil
	}
	if !c.manager.IsCloudIP(ip, providers) {
		return nil
	}
	cfg := c.cfg
	LogActivity(req, LogOptions{
		LogType:             "suspicious",
		Reason:              fmt.Sprintf("Blocked cloud provider IP: %s", ip),
		Level:               cfg.LogSuspiciousLevel,
		PassiveMode:         cfg.PassiveMode,
		CheckName:           c.CheckName(),
		MutedCheckLogs:      cfg.MutedCheckLogs,
		OnBlock:             cfg.OnBlock,
		SensitiveHeaders:    cfg.LogSensitiveHeaders,
		SensitiveParams:     cfg.LogSensitiveParams,
		SensitiveBodyFields: cfg.LogSensitiveBodyFields,
	})
	c.emitCloudBlockEvents(req, ip, providers, state.RouteConfig)
	if !cfg.PassiveMode {
		return createErrorResponse(cfg, 403, CloudBlockedMsg)
	}
	return nil
}

// emitCloudBlockEvents mirrors cloud_provider.py _emit_cloud_block_events
// plus middleware_events.send_cloud_detection_events: the cloud handler's
// cloud_blocked event always rides (handler-direct, envelope metadata with
// the matched provider and network), and a route-tier block adds the
// decorator_violation classified block_clouds/cloud_provider with the
// checked provider list.
func (c *cloudProviderCheck) emitCloudBlockEvents(req Request, ip string, providers []string, routeConfig *RouteConfig) {
	bus := busFor(c.cfg)
	if bus == nil {
		return
	}
	action := blockedOrLoggedAction(c.cfg.PassiveMode)
	if provider, network, ok := c.manager.GetCloudProviderDetails(ip, providers); ok {
		bus.SendHandlerEvent(EventCloudBlocked, CloudHandlerName, ip, action,
			fmt.Sprintf("IP belongs to blocked cloud provider: %s", provider),
			map[string]any{"cloud_provider": provider, "network": network})
	}
	if routeConfig != nil && len(routeConfig.BlockCloudProviders) > 0 {
		emitAccessDeniedEvent(c.cfg, req, fmt.Sprintf("Cloud provider IP %s blocked", ip), "block_clouds", c.cfg.PassiveMode,
			map[string]any{"violation_type": "cloud_provider", "blocked_providers": providers})
	}
}

func (m *CloudManager) nowUnix() int64 { return m.nowFunc().Unix() }

func (m *CloudManager) InitializeRedis(redis RedisHandler, providers []string, ttl int) error {
	if redis == nil {
		return fmt.Errorf("redis handler must not be nil")
	}
	m.SetRedisHandler(redis)
	m.mu.Lock()
	current := m.store
	m.mu.Unlock()
	if current == nil {
		m.SetStore(NewRedisCloudIPStore(redis))
	}
	return m.RefreshAsync(providers, ttl)
}
