package guardcore

import (
	"errors"
	"testing"
)

// The cross-instance middleware state registry (fastapi-guard
// guard/_middleware_state.py): register_state / get_state /
// clear_state_registry over the (config, decorator) identity pair, with
// the engine's Initialize as the adopt-or-register consumer (the
// reference _ensure_initialized and _warm_middleware_or_adopt) and the
// websocket detection pass as the counts consumer (the reference
// _resolve_shared_suspicious_counts).

func TestMiddlewareStateRegistryRoundTrip(t *testing.T) {
	ClearMiddlewareStateRegistry()
	defer ClearMiddlewareStateRegistry()
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	decorator := NewRouteRegistry()
	if GetMiddlewareState(cfg, decorator) != nil {
		t.Fatal("an unregistered key must miss")
	}
	RegisterMiddlewareState(cfg, decorator, &MiddlewareState{Engine: engine})
	got := GetMiddlewareState(cfg, decorator)
	if got == nil || got.Engine != engine {
		t.Fatal("the registered state must round-trip")
	}
	// A different decorator identity must miss: the reference
	// (id(config), id(decorator)) keying keeps same-config stacks with
	// different decorators separate.
	if GetMiddlewareState(cfg, NewRouteRegistry()) != nil {
		t.Fatal("a different decorator identity must miss")
	}
	// The nil-decorator key is its own entry (the reference
	// decorator=None lookups).
	if GetMiddlewareState(cfg, nil) != nil {
		t.Fatal("the nil-decorator key must not collide with a set decorator")
	}
	RegisterMiddlewareState(cfg, nil, &MiddlewareState{Engine: engine})
	if GetMiddlewareState(cfg, nil) == nil {
		t.Fatal("the nil-decorator key must register separately")
	}
}

func TestClearMiddlewareStateRegistry(t *testing.T) {
	ClearMiddlewareStateRegistry()
	defer ClearMiddlewareStateRegistry()
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	RegisterMiddlewareState(cfg, nil, &MiddlewareState{Engine: engine})
	ClearMiddlewareStateRegistry()
	if GetMiddlewareState(cfg, nil) != nil {
		t.Fatal("the clear must drop every registered state")
	}
}

func TestEngineInitializeRegistersState(t *testing.T) {
	ClearMiddlewareStateRegistry()
	defer ClearMiddlewareStateRegistry()
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	registered := GetMiddlewareState(cfg, nil)
	if registered == nil || registered.Engine != engine {
		t.Fatal("a successful initialize must register its engine under the (config, nil) key")
	}
}

func TestEngineInitializeAdoptsWarmState(t *testing.T) {
	ClearMiddlewareStateRegistry()
	defer ClearMiddlewareStateRegistry()
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	first, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("first engine: %v", err)
	}
	if err := first.Initialize(); err != nil {
		t.Fatalf("first initialize: %v", err)
	}
	second, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("second engine: %v", err)
	}
	if err := second.Initialize(); err != nil {
		t.Fatalf("second initialize: %v", err)
	}
	if second.Redis != first.Redis || second.Ban != first.Ban || second.RateLimit != first.RateLimit {
		t.Fatal("the adopting engine must share the warm state's redis pool and managers")
	}
	if second.Routes != first.Routes || second.Cloud != first.Cloud || second.CORS != first.CORS || second.Behavior != first.Behavior {
		t.Fatal("the adopting engine must share the warm state's registry, cloud manager, CORS policy and tracker")
	}
	if second.pipeline != first.pipeline || second.behaviorProc != first.behaviorProc || second.suspiciousCounts != first.suspiciousCounts {
		t.Fatal("the adopting engine must share the warm state's pipeline, behavioral processor and counters")
	}
	if second.DynamicRules != first.DynamicRules {
		t.Fatal("the adopting engine must share the warm state's dynamic-rule manager surface")
	}
}

func TestEngineInitializeRespectsDecoratorKeying(t *testing.T) {
	ClearMiddlewareStateRegistry()
	defer ClearMiddlewareStateRegistry()
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	shared := NewRouteRegistry()
	first, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("first engine: %v", err)
	}
	first.MiddlewareStateDecorator = shared
	if err := first.Initialize(); err != nil {
		t.Fatalf("first initialize: %v", err)
	}
	second, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("second engine: %v", err)
	}
	second.MiddlewareStateDecorator = shared
	if err := second.Initialize(); err != nil {
		t.Fatalf("second initialize: %v", err)
	}
	if second.Redis != first.Redis {
		t.Fatal("same config and same decorator must adopt the warm state (the reference (config, id(decorator)) hit)")
	}
	third, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("third engine: %v", err)
	}
	third.MiddlewareStateDecorator = NewRouteRegistry()
	if err := third.Initialize(); err != nil {
		t.Fatalf("third initialize: %v", err)
	}
	if third.Redis == first.Redis {
		t.Fatal("a distinct decorator must not adopt (the reference (config, id(decorator)) miss)")
	}
}

func TestEngineInitializeFailureRegistersNothing(t *testing.T) {
	ClearMiddlewareStateRegistry()
	defer ClearMiddlewareStateRegistry()
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = true
		c.RedisURL = "redis://127.0.0.1:1"
		c.RedisFailOpen = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := engine.Initialize(); err == nil {
		t.Fatal("the unreachable redis must fail the startup")
	} else {
		var redisErr *GuardRedisError
		if !errors.As(err, &redisErr) {
			t.Fatalf("the failure must surface the redis error, got %v", err)
		}
	}
	if GetMiddlewareState(cfg, nil) != nil {
		t.Fatal("a failed startup must not register state (the reference retries on the next attempt)")
	}
}

func TestWebSocketGuardSharesRegisteredCounts(t *testing.T) {
	ClearMiddlewareStateRegistry()
	defer ClearMiddlewareStateRegistry()
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	httpEngine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("http engine: %v", err)
	}
	if err := httpEngine.Initialize(); err != nil {
		t.Fatalf("http initialize: %v", err)
	}
	wsEngine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("ws engine: %v", err)
	}
	if got := wsEngine.sharedSuspiciousCounts(); got != httpEngine.suspiciousCounts {
		t.Fatal("the websocket guard must adopt the registered HTTP stack's counts store (the reference _resolve_shared_suspicious_counts)")
	}
	// Without a registered state the engine's own store answers.
	if got := httpEngine.sharedSuspiciousCounts(); got != httpEngine.suspiciousCounts {
		t.Fatal("the fallback must be the engine's own counts store")
	}
}
