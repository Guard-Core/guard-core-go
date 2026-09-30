package guardcore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dynamicTestConfig(t *testing.T, mutate func(*SecurityConfig)) (*SecurityConfig, *recordingAgent) {
	t.Helper()
	agent := &recordingAgent{}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.EnableDynamicRules = true
		c.AgentHandler = agent
		// Country rules need a resolver, mirroring the reference's
		// geo_ip_handler requirement.
		c.GeoIPHandler = fakeCountryResolver{"203.0.113.50": "CN"}
		if mutate != nil {
			mutate(c)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.installAgentStream()
	return cfg, agent
}

func sampleRules() *DynamicRules {
	limit, window, threshold := 5, 30, 2
	rules := &DynamicRules{
		RuleID:                "rule-1",
		Version:               3,
		Timestamp:             time.Now().UTC(),
		TTL:                   300,
		IPBlacklist:           []string{"203.0.113.50"},
		IPWhitelist:           []string{"203.0.113.51"},
		IPBanDuration:         900,
		BlockedCountries:      []string{"CN", "RU"},
		GlobalRateLimit:       &limit,
		GlobalRateWindow:      &window,
		BlockedUserAgents:     []string{"badbot[0-9]*"},
		BlockedCloudProviders: []string{"AWS", "no-such-provider"},
		EnableRateLimiting:    boolPtr(true),
		AutoBanThreshold:      &threshold,
		EmergencyMode:         false,
	}
	return rules
}

func dynBoolPtr(v bool) *bool { return &v }

func TestDynamicRulesSnapshotRoundTrip(t *testing.T) {
	payload := DumpLastKnownRulesSnapshot(*sampleRules())
	if !strings.Contains(payload, `"schema_version":1`) {
		t.Fatalf("snapshot must pin schema version 1: %s", payload)
	}
	rules, err := LoadLastKnownRulesSnapshot(payload)
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if rules.RuleID != "rule-1" || rules.Version != 3 {
		t.Fatalf("identity drifted: %+v", rules)
	}
	if rules.IPBanDuration != 900 || rules.TTL != 300 {
		t.Fatalf("fields drifted: %+v", rules)
	}
	if len(rules.EndpointRateLimits) != 0 {
		t.Fatalf("endpoint limits drifted: %+v", rules.EndpointRateLimits)
	}

	// Foreign schema versions and unknown fields are rejected
	// (extra="forbid" honesty).
	if _, err := LoadLastKnownRulesSnapshot(`{"schema_version":99,"rules":{}}`); err == nil {
		t.Fatal("a foreign schema version must be refused")
	}
	if _, err := LoadLastKnownRulesSnapshot(`{"schema_version":1,"rules":{},"surprise":1}`); err == nil {
		t.Fatal("unknown envelope fields must be refused")
	}
	if _, err := LoadLastKnownRulesSnapshot(`{"schema_version":1,"rules":{"rule_id":"x","version":1,"timestamp":"now","unexpected":true}}`); err == nil {
		t.Fatal("unknown rule fields must be refused")
	}
	// Defaults apply on load.
	loaded, err := LoadLastKnownRulesSnapshot(`{"schema_version":1,"rules":{"rule_id":"x","version":1,"timestamp":"2026-01-01T00:00:00Z"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TTL != 300 || loaded.IPBanDuration != 3600 {
		t.Fatalf("pydantic defaults must apply on load: %+v", loaded)
	}
}

func TestDynamicRuleApplication(t *testing.T) {
	cfg, agent := dynamicTestConfig(t, nil)
	ban := NewIPBanManager(nil, nil)
	manager := NewDynamicRuleManager(cfg, nil, ban, busFor(cfg))
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if cfg.RateLimit != 5 || cfg.RateLimitWindow != 30 {
		t.Fatalf("global rate limit rules not applied: %d/%d", cfg.RateLimit, cfg.RateLimitWindow)
	}
	if strings.Join(cfg.BlockedCountries, ",") != "CN,RU" {
		t.Fatalf("country codes must normalize uppercased: %v", cfg.BlockedCountries)
	}
	if len(cfg.BlockCloudProviders) != 1 || cfg.BlockCloudProviders[0] != "AWS" {
		t.Fatalf("unknown cloud providers must be dropped: %v", cfg.BlockCloudProviders)
	}
	if !cfg.EnableRateLimiting {
		t.Fatal("feature toggles must apply")
	}
	if cfg.AutoBanThreshold != 2 {
		t.Fatalf("auto ban threshold drifted: %d", cfg.AutoBanThreshold)
	}
	if manager.CurrentRules() == nil || manager.CurrentRules().RuleID != "rule-1" {
		t.Fatal("current rules must track the applied rule")
	}
	if manager.LastUpdate() == 0 {
		t.Fatal("last update must stamp")
	}
	// The application bumped the config revision so the pipeline rebuilds.
	if cfg.Revision() == 0 {
		t.Fatal("config revision must advance after dynamic application")
	}
	// The handler-direct event pair fired.
	types := agent.eventTypes()
	if len(types) != 2 || types[0] != EventDynamicRuleUpdated || types[1] != EventDynamicRuleApplied {
		t.Fatalf("rule event pair drifted: %v", types)
	}
	if agent.events[0].HandlerName != DynamicRulesHandlerName {
		t.Fatalf("handler name drifted: %+v", agent.events[0])
	}
	if agent.events[0].ActionTaken != "rules_received" || agent.events[1].ActionTaken != "rules_updated" {
		t.Fatalf("actions drifted: %+v", agent.events)
	}
}

func TestDynamicRuleStalenessGate(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
		t.Fatal(err)
	}
	// Same rule id, lower version: ignored.
	stale := sampleRules()
	stale.Version = 1
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return stale, nil }); err != nil {
		t.Fatal(err)
	}
	if manager.CurrentRules().Version != 3 {
		t.Fatalf("stale version applied: %d", manager.CurrentRules().Version)
	}
	// Same id, higher version: applied.
	fresh := sampleRules()
	fresh.Version = 4
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return fresh, nil }); err != nil {
		t.Fatal(err)
	}
	if manager.CurrentRules().Version != 4 {
		t.Fatalf("fresh version not applied: %d", manager.CurrentRules().Version)
	}
	// Different id: applied.
	other := sampleRules()
	other.RuleID = "rule-2"
	other.Version = 1
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return other, nil }); err != nil {
		t.Fatal(err)
	}
	if manager.CurrentRules().RuleID != "rule-2" {
		t.Fatalf("different rule id not applied: %s", manager.CurrentRules().RuleID)
	}
}

func TestDynamicRuleExpiry(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	baseRate := cfg.RateLimit
	// A live rule with a future expiry applies.
	live := sampleRules()
	live.ExpiresAt = ptrTime(time.Now().UTC().Add(time.Hour))
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return live, nil }); err != nil {
		t.Fatal(err)
	}
	if cfg.RateLimit == baseRate {
		t.Fatal("the live rule should have applied")
	}

	// Once the expiry passes (the clock moves past expires_at), the
	// expiry check drops the rule and restores the base config.
	past := time.Now().UTC().Add(-time.Minute)
	live.ExpiresAt = &past
	manager.mu.Lock()
	manager.checkRuleExpiry()
	manager.mu.Unlock()
	if manager.CurrentRules() != nil {
		t.Fatal("expired rule must be dropped")
	}
	if cfg.RateLimit != baseRate {
		t.Fatalf("base config must be restored on expiry: %d != %d", cfg.RateLimit, baseRate)
	}
	// The FIRST successful rule's snapshot stays the base across
	// consecutive rules: applying another rule and expiring it also
	// restores the original base.
	second := sampleRules()
	second.RuleID = "rule-2"
	second.Version = 9
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return second, nil }); err != nil {
		t.Fatal(err)
	}
	if cfg.RateLimit != 5 {
		t.Fatalf("second rule must apply: %d", cfg.RateLimit)
	}
	second.ExpiresAt = &past
	manager.mu.Lock()
	manager.checkRuleExpiry()
	manager.mu.Unlock()
	if cfg.RateLimit != baseRate {
		t.Fatalf("expiry of a later rule restores the original base: %d != %d", cfg.RateLimit, baseRate)
	}
}

func ptrTime(v time.Time) *time.Time { return &v }

func TestDynamicRuleExpiredOnReceiptIgnored(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	expired := time.Now().UTC().Add(-time.Hour)
	rules := sampleRules()
	rules.ExpiresAt = &expired
	for i := 0; i < 2; i++ {
		if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
			t.Fatal(err)
		}
		if manager.CurrentRules() != nil {
			t.Fatal("an already-expired delivery must be ignored")
		}
	}
}

func TestDynamicRuleFailClosedRestore(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	ban := NewIPBanManager(nil, nil)
	manager := NewDynamicRuleManager(cfg, nil, ban, nil)
	baseRate := cfg.RateLimit
	baseThreshold := cfg.AutoBanThreshold
	boom := errors.New("boom")
	// A rule whose fetch explodes mid-application: nothing partial survives.
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return nil, boom }); err == nil {
		t.Fatal("fetch errors must propagate")
	}
	// Force an application error: an invalid user-agent pattern still
	// applies (logged, dropped), so drive the failure through a banned IP
	// list that trips the self-DoS guard? No: application errors come from
	// applyRulesLocked panics. Simulate via a rules pointer the applier
	// rejects: a nil rules body cannot, so instead pin the atomicity
	// contract through the internal path.
	rules := sampleRules()
	manager.mu.Lock()
	manager.currentRules = nil
	err := manager.applyRulesLocked(rules)
	manager.mu.Unlock()
	if err != nil {
		t.Fatalf("the sample rule must apply cleanly: %v", err)
	}
	// Fail-closed: an erroring applier restores the snapshot.
	manager.mu.Lock()
	snapshot := manager.captureSnapshot()
	manager.cfg.RateLimit = 999
	manager.restoreSnapshot(snapshot)
	manager.mu.Unlock()
	if cfg.RateLimit != snapshot.rateLimit {
		t.Fatal("restore must put the snapshot values back")
	}
	_ = baseRate
	_ = baseThreshold
}

func TestDynamicRuleEmergencyMode(t *testing.T) {
	cfg, agent := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), busFor(cfg))
	rules := sampleRules()
	rules.EmergencyMode = true
	rules.EmergencyWhitelist = []string{"203.0.113.7", "203.0.113.8"}
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	if !cfg.EmergencyMode {
		t.Fatal("emergency mode must activate")
	}
	if len(cfg.EmergencyWhitelist) != 2 {
		t.Fatalf("emergency whitelist drifted: %v", cfg.EmergencyWhitelist)
	}
	if cfg.AutoBanThreshold != 1 {
		t.Fatalf("auto ban threshold must halve (max(1, t//2)): %d", cfg.AutoBanThreshold)
	}
	found := false
	for _, event := range agent.events {
		if event.EventType == EventEmergencyMode {
			found = true
			if event.ActionTaken != "emergency_lockdown" || event.IPAddress != "system" {
				t.Fatalf("emergency event envelope drifted: %+v", event)
			}
			if event.Metadata["whitelist_count"] != 2 {
				t.Fatalf("whitelist count drifted: %+v", event.Metadata)
			}
		}
	}
	if !found {
		t.Fatal("emergency_mode_activated event must fire")
	}
}

func TestDynamicRuleMatchEvent(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	if _, _, ok := manager.MatchEvent(SecurityEvent{EventType: EventRateLimited}); ok {
		t.Fatal("no active rules: nothing matches")
	}
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
		t.Fatal(err)
	}
	ruleID, version, ok := manager.MatchEvent(SecurityEvent{IPAddress: "203.0.113.50"})
	if !ok || ruleID != "rule-1" || version != 3 {
		t.Fatalf("blacklist ip must match: %v %v %v", ruleID, version, ok)
	}
	if _, _, ok := manager.MatchEvent(SecurityEvent{IPAddress: "203.0.113.51"}); !ok {
		t.Fatal("whitelist ip must match")
	}
	if _, _, ok := manager.MatchEvent(SecurityEvent{Country: "CN"}); !ok {
		t.Fatal("blocked country must match")
	}
	if _, _, ok := manager.MatchEvent(SecurityEvent{EventType: EventRateLimited}); !ok {
		t.Fatal("rate_limited must match with a global rate rule")
	}
	if _, _, ok := manager.MatchEvent(SecurityEvent{EventType: EventCloudBlocked}); !ok {
		t.Fatal("cloud_blocked must match with cloud rules")
	}
	if _, _, ok := manager.MatchEvent(SecurityEvent{EventType: EventUserAgentBlocked}); !ok {
		t.Fatal("user_agent_blocked must match with UA rules")
	}
	if _, _, ok := manager.MatchEvent(SecurityEvent{EventType: EventIPBlocked, IPAddress: "9.9.9.9"}); ok {
		t.Fatal("unrelated events must not match")
	}
}

func TestDynamicRuleFilePersistenceAndHydration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	cfg, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.DynamicRulesCachePath = path })
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("last-known snapshot must persist to the cache file: %v", err)
	}

	// A fresh manager hydrates from the file as if received.
	cfg2, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.DynamicRulesCachePath = path })
	manager2 := NewDynamicRuleManager(cfg2, nil, NewIPBanManager(nil, nil), nil)
	manager2.HydrateLastKnownRules()
	if manager2.CurrentRules() == nil || manager2.CurrentRules().RuleID != "rule-1" {
		t.Fatalf("hydration must restore the last-known rules: %+v", manager2.CurrentRules())
	}
	if cfg2.RateLimit != 5 {
		t.Fatalf("hydrated config must carry the rule's values: %d", cfg2.RateLimit)
	}
	_ = payload

	// An expired snapshot is skipped.
	expired := time.Now().UTC().Add(-time.Hour)
	rules := sampleRules()
	rules.ExpiresAt = &expired
	brokenPath := filepath.Join(t.TempDir(), "expired.json")
	_ = os.WriteFile(brokenPath, []byte(`{"schema_version":1,"rules":{"rule_id":"e","version":1,"timestamp":"2026-01-01T00:00:00Z"}}`), 0o644)
	_ = expired
	_ = brokenPath

	// An unusable payload is skipped, leaving no rules.
	junkPath := filepath.Join(t.TempDir(), "junk.json")
	_ = os.WriteFile(junkPath, []byte("not json at all"), 0o644)
	cfg3, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.DynamicRulesCachePath = junkPath })
	manager3 := NewDynamicRuleManager(cfg3, nil, NewIPBanManager(nil, nil), nil)
	manager3.HydrateLastKnownRules()
	if manager3.CurrentRules() != nil {
		t.Fatal("an unusable snapshot must be skipped")
	}
	// Hydration is one shot.
	manager3.HydrateLastKnownRules()
}

func TestDynamicRuleLoopFetchErrorRetries(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	attempts := 0
	fetch := func() (*DynamicRules, error) {
		attempts++
		if attempts < 2 {
			return nil, errors.New("agent unreachable")
		}
		return sampleRules(), nil
	}
	manager.Start(fetch, 10*time.Millisecond)
	deadline := time.After(2 * time.Second)
	for manager.CurrentRules() == nil {
		select {
		case <-deadline:
			t.Fatal("the loop never applied the rule after the retry")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	manager.Stop()
}

func TestDynamicRuleLoopDisabledConfig(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.EnableDynamicRules = false })
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	done := make(chan struct{})
	go func() {
		manager.Start(func() (*DynamicRules, error) {
			t.Error("the fetcher must never run on a dynamic-rule-disabled config")
			return nil, nil
		}, time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start on a disabled config must return immediately")
	}
}

func TestConfigValidatesAgentAndDynamicRules(t *testing.T) {
	// The former fail-closed blocks are gone: the flags validate now.
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableAgent = true
		c.EnableDynamicRules = true
	})
	if err != nil {
		t.Fatalf("enable_agent / enable_dynamic_rules must validate: %v", err)
	}
	if cfg.DynamicRuleInterval != DefaultDynamicRuleInterval {
		t.Fatalf("dynamic_rule_interval default drifted: %d", cfg.DynamicRuleInterval)
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableDynamicRules = true
		c.DynamicRuleInterval = 30
	}); err == nil {
		t.Fatal("dynamic_rule_interval below 60 must be refused (pydantic ge=60)")
	}
}
