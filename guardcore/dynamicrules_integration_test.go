//go:build integration

package guardcore

import (
	"os"
	"testing"
	"time"
)

// Live-Redis coverage for the dynamic-rule last-known persistence: the
// Redis read/write/hydration paths need a real server (guard them on
// REDIS_HOST like the other integration suites).

func newDynamicRulesIntegrationManager(t *testing.T) (*DynamicRuleManager, *SecurityConfig, *RedisManager) {
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
		_, _ = mgr.Delete(DynamicRulesRedisNamespace, LastKnownRulesKey)
		_ = mgr.Close()
	})
	cfg, _ := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableDynamicRules = true
		c.GeoIPHandler = fakeCountryResolver{"203.0.113.50": "CN"}
	})
	cfg.installAgentStream()
	manager := NewDynamicRuleManager(cfg, mgr, NewIPBanManager(mgr, nil), busFor(cfg))
	return manager, cfg, mgr
}

func TestDynamicRulesRedisPersistenceRoundTrip(t *testing.T) {
	manager, _, mgr := newDynamicRulesIntegrationManager(t)
	rules := sampleRules()
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	stored, err := mgr.GetKey(DynamicRulesRedisNamespace, LastKnownRulesKey)
	if err != nil || stored == "" {
		t.Fatalf("the snapshot must persist to redis with no TTL: %q %v", stored, err)
	}
	if _, err := LoadLastKnownRulesSnapshot(stored); err != nil {
		t.Fatalf("the stored payload must parse: %v", err)
	}

	// Hydration reads the snapshot back from Redis.
	manager2, cfg2, _ := newDynamicRulesIntegrationManager(t)
	manager2.HydrateLastKnownRules()
	if manager2.CurrentRules() == nil || manager2.CurrentRules().RuleID != rules.RuleID {
		t.Fatalf("hydration must restore from Redis: %+v", manager2.CurrentRules())
	}
	if cfg2.RateLimit != 5 {
		t.Fatalf("the hydrated config carries the rule values: %d", cfg2.RateLimit)
	}
}

func TestDynamicRulesRedisExpiredSnapshotSkipped(t *testing.T) {
	manager, _, mgr := newDynamicRulesIntegrationManager(t)
	rules := sampleRules()
	expired := time.Now().UTC().Add(-time.Hour)
	rules.ExpiresAt = &expired
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.GetKey(DynamicRulesRedisNamespace, LastKnownRulesKey); err != nil {
		t.Fatal(err)
	}
	// UpdateRules rejects expired-on-receipt deliveries before persisting;
	// seed the snapshot directly so hydration must skip it.
	payload := DumpLastKnownRulesSnapshot(*rules)
	if err := mgr.SetKey(DynamicRulesRedisNamespace, LastKnownRulesKey, payload, nil); err != nil {
		t.Fatal(err)
	}
	manager2, _, _ := newDynamicRulesIntegrationManager(t)
	manager2.HydrateLastKnownRules()
	if manager2.CurrentRules() != nil {
		t.Fatal("an expired Redis snapshot must be skipped during hydration")
	}
}

func TestDynamicRulesRedisLiveSnapshotApplied(t *testing.T) {
	manager, _, mgr := newDynamicRulesIntegrationManager(t)
	// Seed a live (unexpired) snapshot directly.
	rules := sampleRules()
	rules.ExpiresAt = ptrTime(time.Now().UTC().Add(time.Hour))
	if err := mgr.SetKey(DynamicRulesRedisNamespace, LastKnownRulesKey, DumpLastKnownRulesSnapshot(*rules), nil); err != nil {
		t.Fatal(err)
	}
	manager.HydrateLastKnownRules()
	if manager.CurrentRules() == nil {
		t.Fatal("the live Redis snapshot must hydrate")
	}
	// The nil-return path of readRedisPayload: an empty key reads as no
	// payload.
	if _, err := mgr.Delete(DynamicRulesRedisNamespace, LastKnownRulesKey); err != nil {
		t.Fatal(err)
	}
	if payload := manager.readRedisPayload(); payload != "" {
		t.Fatalf("an absent key reads empty: %q", payload)
	}
}
