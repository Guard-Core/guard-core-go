package guardcore

import "sync"

// The cross-instance middleware state registry, ported from fastapi-guard
// guard/_middleware_state.py (register_state / get_state /
// clear_state_registry over the (id(config), id(decorator)) keyed
// _STATE_REGISTRY): machinery warmed by one initialized security stack is
// shared with every later stack built from the same config instead of
// re-initialized, so a second engine (a second app server, a rebuilt
// middleware, a websocket-side guard) adopts the first one's redis pool,
// ban/rate-limit managers, pipeline and counters.
//
// The reference MiddlewareState dataclass carries ten machinery fields
// (security_pipeline, composite_handler, event_bus, metrics_collector,
// response_factory, validator, bypass_handler, behavioral_processor,
// handler_initializer, agent_handler); in this port every one of those
// surfaces hangs off the Engine, so the warmed state is the engine itself.

// MiddlewareState is one warmed security stack's shared machinery (the
// reference MiddlewareState): the initialized engine whose managers,
// pipeline and counters every adopting instance reuses.
type MiddlewareState struct {
	Engine *Engine
}

// middlewareStateKey mirrors the reference _state_key pair: the config
// identity plus the decorator identity. Map equality on the interface
// gives pointer values object identity (the reference id()) and collapses
// nil into one key (the reference decorator=None lookups).
type middlewareStateKey struct {
	config    *SecurityConfig
	decorator any
}

var (
	middlewareStateMu       sync.RWMutex
	middlewareStateRegistry = map[middlewareStateKey]*MiddlewareState{}
)

// RegisterMiddlewareState records state under the (config, decorator)
// key, mirroring the reference register_state. The engine's Initialize
// calls this after a successful startup; hosts and tests may pre-register
// (the reference test_websocket.py register_state arm) or re-register a
// warmed stack.
func RegisterMiddlewareState(cfg *SecurityConfig, decorator any, state *MiddlewareState) {
	middlewareStateMu.Lock()
	defer middlewareStateMu.Unlock()
	middlewareStateRegistry[middlewareStateKey{config: cfg, decorator: decorator}] = state
}

// GetMiddlewareState returns the state registered under the (config,
// decorator) key or nil, mirroring the reference get_state.
func GetMiddlewareState(cfg *SecurityConfig, decorator any) *MiddlewareState {
	middlewareStateMu.RLock()
	defer middlewareStateMu.RUnlock()
	return middlewareStateRegistry[middlewareStateKey{config: cfg, decorator: decorator}]
}

// ClearMiddlewareStateRegistry drops every registered state, mirroring
// the reference clear_state_registry (the test-isolation seam: registered
// engines are retained until cleared).
func ClearMiddlewareStateRegistry() {
	middlewareStateMu.Lock()
	defer middlewareStateMu.Unlock()
	middlewareStateRegistry = map[middlewareStateKey]*MiddlewareState{}
}
