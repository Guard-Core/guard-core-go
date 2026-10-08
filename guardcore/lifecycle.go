package guardcore

// The adapter lifecycle row's engine side (fastapi-guard guard/middleware.py):
// mark_initialized (:131) and agent_stats (:256). The reference middleware
// owns an initialization flag the lifespan and the first request race on;
// this port's gate is the Engine's initialize-once, so marking initialized
// consumes it. The reference agent_stats property answers
// {"enabled": false, "degraded": agent_degraded} without a handler and
// {"enabled": true, "degraded": false, **handler_stats} with one, merging
// the wired agent handler's get_stats() dict.

// AgentStatsProvider is the optional stats surface of a wired agent
// handler (the reference get_stats() duck-call on agent_handler): a
// handler exposing its counters through AgentStats is merged into
// Engine.AgentStats. guard-agent-go's *Agent implements it with the
// reference dict shape.
type AgentStatsProvider interface {
	AgentStats() map[string]any
}

// MarkInitialized marks the engine initialized without running the
// startup I/O (the reference mark_initialized: a stack warmed externally
// tells the middleware to consider itself initialized). A later
// Initialize becomes a no-op; an engine whose Initialize already failed
// stays failed (the once is already consumed there).
func (e *Engine) MarkInitialized() {
	e.initializeOnce.Do(func() {})
}

// AgentStats mirrors the reference agent_stats property: without a wired
// handler {"enabled": false, "degraded": <degraded>}; with one
// {"enabled": true, "degraded": false} merged with the handler's
// AgentStats() dict when it provides the surface. The Go degraded state
// is the engine's non-strict agent-init failure (the agentInitFailure
// degrade arm): an enabled config whose handler wiring was rejected, so
// EnableAgent with no handler wired.
func (e *Engine) AgentStats() map[string]any {
	if e.Config.AgentHandler == nil {
		return map[string]any{"enabled": false, "degraded": e.Config.EnableAgent}
	}
	stats := map[string]any{"enabled": true, "degraded": false}
	if provider, ok := e.Config.AgentHandler.(AgentStatsProvider); ok {
		for key, value := range provider.AgentStats() {
			stats[key] = value
		}
	}
	return stats
}
