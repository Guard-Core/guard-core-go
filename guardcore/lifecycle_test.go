package guardcore

import (
	"testing"
)

// The engine-side adapter lifecycle surface (fastapi-guard
// guard/middleware.py mark_initialized and agent_stats).

type statsAgent struct {
	recordingAgent
	stats map[string]any
}

func (s *statsAgent) AgentStats() map[string]any { return s.stats }

func TestEngineMarkInitializedSkipsStartup(t *testing.T) {
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
	// The redis endpoint is unreachable, so a real startup would fail
	// closed: MarkInitialized must make Initialize a no-op.
	engine.MarkInitialized()
	if err := engine.Initialize(); err != nil {
		t.Fatalf("a marked-initialized engine must skip the startup I/O, got %v", err)
	}
}

func TestEngineAgentStatsAgentless(t *testing.T) {
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
	stats := engine.AgentStats()
	if stats["enabled"] != false || stats["degraded"] != false {
		t.Fatalf("an agentless engine must report enabled=false degraded=false, got %v", stats)
	}
}

func TestEngineAgentStatsDegraded(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.AgentStrict = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("the non-strict degrade must construct, got %v", err)
	}
	stats := engine.AgentStats()
	if stats["enabled"] != false || stats["degraded"] != true {
		t.Fatalf("the degraded engine must report enabled=false degraded=true, got %v", stats)
	}
}

func TestEngineAgentStatsEnabledMergesHandlerStats(t *testing.T) {
	handler := &statsAgent{stats: map[string]any{"running": true, "events_sent": int64(7)}}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.AgentHandler = handler
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	stats := engine.AgentStats()
	if stats["enabled"] != true || stats["degraded"] != false {
		t.Fatalf("a wired handler must report enabled=true degraded=false, got %v", stats)
	}
	if stats["running"] != true || stats["events_sent"] != int64(7) {
		t.Fatalf("the handler stats must merge into the payload, got %v", stats)
	}
}

func TestEngineAgentStatsEnabledWithoutProviderSurface(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableAgent = true
		c.AgentHandler = &recordingAgent{}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	stats := engine.AgentStats()
	if stats["enabled"] != true || stats["degraded"] != false {
		t.Fatalf("a handler without the stats surface must still report enabled, got %v", stats)
	}
	if _, merged := stats["running"]; merged {
		t.Fatal("no handler stats must merge without the provider surface")
	}
}
