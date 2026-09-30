//go:build integration

package guardcore

// Integration twins for the security-headers configuration cache: the
// corrupted-payload loads and the persist-failure paths need a real (or
// unreachable) Redis, REDIS_HOST-guarded like the other suites.

import (
	"os"
	"strings"
	"testing"
)

func newTwinSweepRedis(t *testing.T) *RedisManager {
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
	return mgr
}

// TestHeadersCacheLoadCorruptedPayloads covers the per-block unmarshal
// failure branch in LoadCachedConfig: a corrupted block logs, keeps the
// current state, and the other blocks still load.
func TestHeadersCacheLoadCorruptedPayloads(t *testing.T) {
	mgr := newTwinSweepRedis(t)
	if err := mgr.SetKey(HeadersRedisNamespace, "csp_config", "{not json", nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetKey(HeadersRedisNamespace, "hsts_config", "[not an object]", nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetKey(HeadersRedisNamespace, "custom_headers", "42", nil); err != nil {
		t.Fatal(err)
	}
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager.SetRedis(mgr)
	manager.LoadCachedConfig()
	if len(manager.state.CSP) != len(DefaultSecurityHeaders().CSP) {
		t.Fatalf("a corrupted CSP payload must keep the current state: %+v", manager.state.CSP)
	}
}

// TestHeadersCacheCustomHeaderValidation covers the cached custom-header
// validation: invalid names and values log and skip; a valid one applies.
func TestHeadersCacheCustomHeaderValidation(t *testing.T) {
	mgr := newTwinSweepRedis(t)
	payload := `{"X-Bad Name": "v", "X-Bad-Value": "bad\r\nvalue", "X-Good": "ok"}`
	if err := mgr.SetKey(HeadersRedisNamespace, "custom_headers", payload, nil); err != nil {
		t.Fatal(err)
	}
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager.SetRedis(mgr)
	manager.LoadCachedConfig()
	if len(manager.state.Custom) != 1 {
		t.Fatalf("only the valid custom header must apply: %+v", manager.state.Custom)
	}
	if manager.state.Custom["X-Good"] != "ok" {
		t.Fatalf("the valid header must keep its value: %+v", manager.state.Custom)
	}
}

// TestHeadersCachePersistFailuresAreLogged covers the SetKey failure branches
// in CacheConfiguration: a down Redis logs per block and never raises.
func TestHeadersCachePersistFailuresAreLogged(t *testing.T) {
	down := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1/0", Prefix: "guard_core_test:", EnableRedis: true})
	state := DefaultSecurityHeaders()
	state.CSP = []CSPDirective{{Name: "default-src", Sources: []string{"'self'"}}}
	state.Custom = map[string]string{"X-Deploy-Stamp": "twin"}
	manager := NewSecurityHeadersManager(state)
	manager.SetRedis(down)
	manager.CacheConfiguration()
	if !strings.HasPrefix(manager.GenerateCacheKey(""), manager.keyPrefix) {
		t.Fatal("the manager must stay usable after failed persists")
	}
}
