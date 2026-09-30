//go:build integration

package guardcore

import (
	"os"
	"testing"
	"time"
)

// Live-Redis coverage for the security-headers configuration cache
// (REDIS_HOST-guarded like the other integration suites).

func newHeadersIntegrationManager(t *testing.T) (*SecurityHeadersManager, *RedisManager) {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	mgr := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test:", EnableRedis: true})
	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Redis initialize failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = mgr.DeletePattern(HeadersRedisNamespace + ":*")
		_ = mgr.Close()
	})
	state := DefaultSecurityHeaders()
	state.Custom = map[string]string{"X-Deploy-Stamp": "integration"}
	state.CSP = []CSPDirective{{Name: "default-src", Sources: []string{"'self'"}}}
	manager := NewSecurityHeadersManager(state)
	return manager, mgr
}

func TestSecurityHeadersRedisCacheRoundTrip(t *testing.T) {
	manager, mgr := newHeadersIntegrationManager(t)
	manager.InitializeRedis(mgr)

	// The configuration blocks persist with the 86400s TTL.
	for _, key := range []string{"csp_config", "custom_headers"} {
		raw, err := mgr.GetKey(HeadersRedisNamespace, key)
		if err != nil || raw == "" {
			t.Fatalf("%s must persist: %q %v", key, raw, err)
		}
		ttl, err := mgr.PTTL(mgr.Prefix() + HeadersRedisNamespace + ":" + key)
		if err != nil {
			t.Fatal(err)
		}
		if ttl <= 0 || ttl > HeadersConfigCacheTTL*time.Second {
			t.Fatalf("%s TTL drifted: %v", key, ttl)
		}
	}

	// A fresh manager loads the cached configuration from Redis.
	manager2 := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager2.SetRedis(mgr)
	manager2.LoadCachedConfig()
	headers := manager2.GetHeaders("")
	if headers["Content-Security-Policy"] != "default-src 'self'" {
		t.Fatalf("the cached CSP must override the loaded state: %q", headers["Content-Security-Policy"])
	}
	if headers["X-Deploy-Stamp"] != "integration" {
		t.Fatalf("the cached custom headers must load: %q", headers["X-Deploy-Stamp"])
	}
}

func TestSecurityHeadersRedisResetClearsKeys(t *testing.T) {
	manager, mgr := newHeadersIntegrationManager(t)
	manager.InitializeRedis(mgr)
	keys, err := mgr.Keys(HeadersRedisNamespace + ":*")
	if err != nil || len(keys) == 0 {
		t.Fatalf("the configuration keys must exist before reset: %v %v", keys, err)
	}
	manager.Reset()
	keys, err = mgr.Keys(HeadersRedisNamespace + ":*")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("reset must clear the Redis keys: %v", keys)
	}
}

func TestSecurityHeadersRedisUnreachableFailsSoft(t *testing.T) {
	// A down Redis: load and cache failures log and the manager keeps
	// serving headers from its local state.
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	down := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1/0", EnableRedis: true})
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a down Redis must fail soft: %v", r)
		}
	}()
	manager.InitializeRedis(down)
	if headers := manager.GetHeaders(""); len(headers) == 0 {
		t.Fatal("headers must still compute with a down Redis")
	}
}
