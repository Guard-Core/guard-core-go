package guardcore

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func overlayRules(version int, id string) *DynamicRules {
	return &DynamicRules{RuleID: id, Version: version, Timestamp: time.Now().UTC(), TTL: 300, IPBanDuration: 3600}
}

func overlayApply(t *testing.T, m *DynamicRuleManager, rules *DynamicRules) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.applyRulesLocked(rules); err != nil {
		t.Fatalf("apply v%d failed: %v", rules.Version, err)
	}
	m.currentRules.Store(rules)
}

func overlayManager(t *testing.T, mutate func(*SecurityConfig)) (*SecurityConfig, *DynamicRuleManager) {
	t.Helper()
	cfg, _ := dynamicTestConfig(t, mutate)
	return cfg, NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
}

func TestDynamicRuleEmergencyHalvingDoesNotCompoundAcrossVersions(t *testing.T) {
	cfg, m := overlayManager(t, func(c *SecurityConfig) { c.AutoBanThreshold = 16 })
	var seen []int
	for version := 1; version <= 3; version++ {
		rules := overlayRules(version, "r1")
		rules.EmergencyMode = true
		overlayApply(t, m, rules)
		seen = append(seen, cfg.AutoBanThreshold)
	}
	if !reflect.DeepEqual(seen, []int{8, 8, 8}) {
		t.Fatalf("emergency halving compounded: %v", seen)
	}
	if m.activeBase == nil || m.activeBase.autoBanThreshold != 16 {
		t.Fatalf("active base must keep the true threshold: %+v", m.activeBase)
	}
}

func TestDynamicRuleCollectionValuesDoNotAccumulateAcrossVersions(t *testing.T) {
	cfg, m := overlayManager(t, func(c *SecurityConfig) {
		c.BlockedUserAgents = []string{"base-bot"}
		c.BlockCloudProviders = []string{"AWS"}
	})
	v1 := overlayRules(1, "r1")
	v1.BlockedUserAgents = []string{"bot-a"}
	v1.BlockedCloudProviders = []string{"GCP"}
	v1.BlockedCountries = []string{"AA"}
	v1.EndpointRateLimits = map[string][2]int{"/a": {1, 60}}
	overlayApply(t, m, v1)
	v2 := overlayRules(2, "r1")
	v2.BlockedUserAgents = []string{"bot-b"}
	v2.BlockedCloudProviders = []string{"Azure"}
	v2.BlockedCountries = []string{"BB"}
	v2.EndpointRateLimits = map[string][2]int{"/b": {2, 60}}
	overlayApply(t, m, v2)

	if !reflect.DeepEqual(cfg.BlockedUserAgents, []string{"bot-b"}) {
		t.Fatalf("user agents accumulated: %v", cfg.BlockedUserAgents)
	}
	if !reflect.DeepEqual(cfg.BlockCloudProviders, []string{"Azure"}) {
		t.Fatalf("cloud providers accumulated: %v", cfg.BlockCloudProviders)
	}
	if !reflect.DeepEqual(cfg.BlockedCountries, []string{"BB"}) {
		t.Fatalf("countries accumulated: %v", cfg.BlockedCountries)
	}
	if !reflect.DeepEqual(cfg.EndpointRateLimits, map[string]RateLimitEntry{"/b": {Requests: 2, Window: 60}}) {
		t.Fatalf("endpoint limits accumulated: %v", cfg.EndpointRateLimits)
	}
}

func TestDynamicRuleNewVersionDropsChangeFromPreviousVersion(t *testing.T) {
	cfg, m := overlayManager(t, func(c *SecurityConfig) {
		c.RateLimit = 100
		c.EnableIPBanning = true
		c.AutoBanThreshold = 5
	})
	v1 := overlayRules(1, "r1")
	v1.GlobalRateLimit = intPtr(7)
	v1.EnableIPBanning = boolPtr(false)
	v1.AutoBanThreshold = intPtr(2)
	overlayApply(t, m, v1)
	if cfg.RateLimit != 7 || cfg.EnableIPBanning {
		t.Fatalf("v1 not applied: %d %v", cfg.RateLimit, cfg.EnableIPBanning)
	}

	v2 := overlayRules(2, "r1")
	v2.GlobalRateLimit = intPtr(9)
	overlayApply(t, m, v2)
	if cfg.RateLimit != 9 || !cfg.EnableIPBanning || cfg.AutoBanThreshold != 5 {
		t.Fatalf("v1 change leaked into v2: %d %v %d", cfg.RateLimit, cfg.EnableIPBanning, cfg.AutoBanThreshold)
	}
}

func TestDynamicRuleDifferentRuleIDOverlaysTheBase(t *testing.T) {
	cfg, m := overlayManager(t, func(c *SecurityConfig) {
		c.RateLimit = 100
		c.AutoBanThreshold = 16
	})
	r1 := overlayRules(1, "r1")
	r1.EmergencyMode = true
	overlayApply(t, m, r1)
	r2 := overlayRules(1, "r2")
	r2.GlobalRateLimit = intPtr(3)
	overlayApply(t, m, r2)

	if cfg.RateLimit != 3 || cfg.AutoBanThreshold != 16 || cfg.EmergencyMode {
		t.Fatalf("r1 leaked into r2: %d %d %v", cfg.RateLimit, cfg.AutoBanThreshold, cfg.EmergencyMode)
	}
}

func TestDynamicRuleFailedApplyRollsBackToTheActiveVersion(t *testing.T) {
	cfg, m := overlayManager(t, func(c *SecurityConfig) {
		c.RateLimit = 100
		c.AutoBanThreshold = 16
	})
	v1 := overlayRules(1, "r1")
	v1.GlobalRateLimit = intPtr(7)
	v1.AutoBanThreshold = intPtr(4)
	overlayApply(t, m, v1)

	m.applyFault = func() { panic(errors.New("boom")) }
	v2 := overlayRules(2, "r1")
	v2.GlobalRateLimit = intPtr(9)
	m.mu.Lock()
	err := m.applyRulesLocked(v2)
	m.mu.Unlock()
	if err == nil {
		t.Fatal("a failed apply must return an error")
	}
	if cfg.RateLimit != 7 || cfg.AutoBanThreshold != 4 {
		t.Fatalf("rollback must restore the active version: %d %d", cfg.RateLimit, cfg.AutoBanThreshold)
	}
	if m.activeBase == nil || m.activeBase.rateLimit != 100 {
		t.Fatalf("active base must stay the true base: %+v", m.activeBase)
	}
}

func TestDynamicRuleExpiryRestoresTheTrueBaseAfterSeveralVersions(t *testing.T) {
	cfg, m := overlayManager(t, func(c *SecurityConfig) { c.AutoBanThreshold = 16 })
	v1 := overlayRules(1, "r1")
	v1.EmergencyMode = true
	overlayApply(t, m, v1)
	v2 := overlayRules(2, "r1")
	v2.EmergencyMode = true
	past := time.Now().UTC().Add(-time.Second)
	v2.ExpiresAt = &past
	overlayApply(t, m, v2)
	if cfg.AutoBanThreshold != 8 {
		t.Fatalf("v2 threshold = %d, want 8", cfg.AutoBanThreshold)
	}

	m.mu.Lock()
	m.checkRuleExpiry()
	m.mu.Unlock()

	if cfg.AutoBanThreshold != 16 || cfg.EmergencyMode {
		t.Fatalf("expiry must restore the true base: %d %v", cfg.AutoBanThreshold, cfg.EmergencyMode)
	}
	if m.CurrentRules() != nil || m.activeBase != nil {
		t.Fatal("expiry must clear the active rule and base")
	}
}

func TestDynamicRuleNewVersionAfterHydrationOverlaysTheBase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	hydrated := overlayRules(1, "r1")
	hydrated.EmergencyMode = true
	if err := os.WriteFile(path, []byte(DumpLastKnownRulesSnapshot(*hydrated)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, m := overlayManager(t, func(c *SecurityConfig) {
		c.AutoBanThreshold = 16
		c.DynamicRulesCachePath = path
	})
	m.HydrateLastKnownRules()
	if cfg.AutoBanThreshold != 8 {
		t.Fatalf("hydrated threshold = %d, want 8", cfg.AutoBanThreshold)
	}

	v2 := overlayRules(2, "r1")
	v2.EmergencyMode = true
	if err := m.UpdateRules(func() (*DynamicRules, error) { return v2, nil }); err != nil {
		t.Fatal(err)
	}
	if m.CurrentRules() == nil || m.CurrentRules().Version != 2 {
		t.Fatalf("v2 must be current: %+v", m.CurrentRules())
	}
	if cfg.AutoBanThreshold != 8 {
		t.Fatalf("v2 after hydration compounded: %d", cfg.AutoBanThreshold)
	}
}

func TestDynamicRuleSuspiciousPatternsAreNotDuplicatedAcrossVersions(t *testing.T) {
	_, m := overlayManager(t, nil)
	pattern := "overlay-unique-marker-[0-9]{3}"
	DefaultSusPatternsManager.RemovePattern(pattern, false)
	t.Cleanup(func() { DefaultSusPatternsManager.RemovePattern(pattern, false) })
	for version := 1; version <= 3; version++ {
		rules := overlayRules(version, "r1")
		rules.SuspiciousPatterns = []string{pattern}
		overlayApply(t, m, rules)
	}
	count := 0
	for _, p := range DefaultSusPatternsManager.GetDefaultPatterns() {
		if p == pattern {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("pattern registered %d times, want 1", count)
	}
}
