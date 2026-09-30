package guardcore

// Redis manager unit coverage: disabled and broken-client paths. The live
// server paths live in coverage_redis_live_test.go (integration-tagged).

import (
	"testing"
	"time"
)

func TestDefaultRedisConfig(t *testing.T) {
	cfg := DefaultRedisConfig()
	if cfg.URL != "redis://localhost:6379" || cfg.Prefix != "guard_core:" || !cfg.EnableRedis {
		t.Fatalf("defaults compose, got %+v", cfg)
	}
}

func TestNewRedisManagerPrefixDefault(t *testing.T) {
	m := NewRedisManager(RedisConfig{URL: "redis://localhost:6379", EnableRedis: false})
	if m.Prefix() != "guard_core:" {
		t.Fatalf("prefixes default, got %q", m.Prefix())
	}
	if m.Enabled() {
		t.Fatal("disabled managers report disabled")
	}
}

func TestRedisManagerDisabledPaths(t *testing.T) {
	m := NewRedisManager(RedisConfig{EnableRedis: false})
	// Disabled managers no-op every operation.
	if err := m.Initialize(); err != nil {
		t.Fatalf("disabled initialization is a no-op, got %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("closing unused managers is a no-op, got %v", err)
	}
	if err := m.SetKey("ns", "k", "v", nil); err != nil {
		t.Fatalf("disabled sets no-op, got %v", err)
	}
	if value, err := m.GetKey("ns", "k"); err != nil || value != "" {
		t.Fatalf("disabled gets return empty, got %q %v", value, err)
	}
	if err := m.SetPX("k", "v", time.Second); err != nil {
		t.Fatalf("disabled setpx no-ops, got %v", err)
	}
	if _, err := m.PTTL("k"); err != nil {
		t.Fatalf("disabled pttl no-ops, got %v", err)
	}
	if _, err := m.DeleteKeys("k"); err != nil {
		t.Fatalf("disabled deletes no-op, got %v", err)
	}
}

func TestRedisManagerInitializeFailures(t *testing.T) {
	// Malformed URLs fail parsing.
	m := NewRedisManager(RedisConfig{URL: "://bad", EnableRedis: true})
	if err := m.Initialize(); err == nil {
		t.Fatal("malformed urls fail")
	}
	// Unreachable servers fail the ping.
	dead := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1", EnableRedis: true})
	if err := dead.Initialize(); err == nil {
		t.Fatal("unreachable servers fail")
	}
	if err := dead.Close(); err != nil {
		t.Fatalf("closing failed managers is a no-op, got %v", err)
	}
	// Operations on unconnected managers surface the connection error.
	if _, err := dead.GetKey("ns", "k"); err == nil {
		t.Fatal("unconnected gets fail")
	}
	if _, err := dead.ScriptLoad("return 1"); err == nil {
		t.Fatal("unconnected script loads fail")
	}
	if _, err := dead.EvalSha("sha", "k", 1, 60, 10); err == nil {
		t.Fatal("unconnected evals fail")
	}
	if _, err := dead.PipelineRateLimit("k", "m", 1, 0, 60); err == nil {
		t.Fatal("unconnected pipelines fail")
	}
	if _, err := dead.RecordSlidingWindowHit("ns", "k", 1, 0, 60); err == nil {
		t.Fatal("unconnected window hits fail")
	}
}

func TestRedisManagerGuardRedisErrorMessage(t *testing.T) {
	err := newGuardRedisError("Redis operation failed")
	if err.Error() != "guardredis error 503: Redis operation failed" {
		t.Fatalf("errors describe themselves, got %q", err.Error())
	}
}
