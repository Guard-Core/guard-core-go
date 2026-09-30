package guardcore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDynamicRuleCheckExpiryNotYetExpired covers the expiry gate's
// live-rule early return: a rule with a future expiry survives the check.
func TestDynamicRuleCheckExpiryNotYetExpired(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	live := sampleRules()
	live.ExpiresAt = ptrTime(time.Now().UTC().Add(time.Hour))
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return live, nil }); err != nil {
		t.Fatal(err)
	}
	// The next update cycle runs checkRuleExpiry against the live rule.
	second := sampleRules()
	second.RuleID = "rule-next"
	second.Version = 9
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return second, nil }); err != nil {
		t.Fatal(err)
	}
	if manager.CurrentRules().RuleID != "rule-next" {
		t.Fatalf("the live rule must survive its expiry check until it actually expires: %s", manager.CurrentRules().RuleID)
	}
}

// TestDynamicRuleApplyInFlight covers the application re-entrancy guard.
func TestDynamicRuleApplyInFlight(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	manager.mu.Lock()
	manager.applying = true
	err := manager.applyRulesLocked(sampleRules())
	manager.mu.Unlock()
	if err == nil {
		t.Fatal("a re-entrant application must be refused")
	}
}

// TestDynamicRuleBanFailureLogged covers the per-IP ban error path
// (negative durations trip the manager's assertion).
func TestDynamicRuleBanFailureLogged(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	rules := sampleRules()
	rules.IPBanDuration = -1
	manager.mu.Lock()
	err := manager.applyRulesLocked(rules)
	manager.mu.Unlock()
	if err != nil {
		t.Fatalf("per-IP failures are logged and skipped, not fatal: %v", err)
	}
}

// TestDynamicRuleBanRefusalLogged covers the refusal branch: a loopback
// ban is refused by the self-DoS guard, so applied lands false and the
// skip is logged.
func TestDynamicRuleBanRefusalLogged(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	rules := sampleRules()
	rules.IPBlacklist = []string{"127.0.0.1"}
	rules.IPWhitelist = nil
	manager.mu.Lock()
	err := manager.applyRulesLocked(rules)
	manager.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

// TestDynamicRuleUnbanFailureLogged covers the whitelist-unban error path
// via a failing Redis handler.
func TestDynamicRuleUnbanFailureLogged(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	failing := &fakeRedis{data: map[string]fakeEntry{}}
	failing.fail = true
	ban := NewIPBanManager(failing, nil)
	manager := NewDynamicRuleManager(cfg, nil, ban, nil)
	rules := sampleRules()
	rules.IPBlacklist = nil
	rules.IPWhitelist = []string{"203.0.113.51"}
	manager.mu.Lock()
	err := manager.applyRulesLocked(rules)
	manager.mu.Unlock()
	if err != nil {
		t.Fatalf("unban failures are logged and skipped: %v", err)
	}
}

// TestDynamicRuleWhitelistCountries applies the allowlist branch.
func TestDynamicRuleWhitelistCountries(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	rules := sampleRules()
	rules.WhitelistCountries = []string{"de", "fr"}
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.WhitelistCountries, ",") != "DE,FR" {
		t.Fatalf("whitelist countries must normalize: %v", cfg.WhitelistCountries)
	}
}

// TestDynamicRuleEndpointRateLimits applies the per-endpoint branch, and
// a second application snapshots the now-populated endpoint map (the deep
// copy the fail-closed restore relies on).
func TestDynamicRuleEndpointRateLimits(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	rules := sampleRules()
	rules.EndpointRateLimits = map[string][2]int{"/api/heavy": {7, 30}}
	rules.GlobalRateLimit = nil
	rules.GlobalRateWindow = nil
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	entry, ok := cfg.EndpointRateLimits["/api/heavy"]
	if !ok || entry.Requests != 7 || entry.Window != 30 {
		t.Fatalf("endpoint rate limits drifted: %+v", cfg.EndpointRateLimits)
	}
	// A second rule snapshots the populated map; the restore puts the
	// first rule's endpoints back.
	second := sampleRules()
	second.RuleID = "rule-2"
	second.Version = 9
	second.EndpointRateLimits = map[string][2]int{"/api/other": {1, 10}}
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return second, nil }); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	snapshot := manager.captureSnapshot()
	manager.mu.Unlock()
	if _, ok := snapshot.endpointRateLimits["/api/other"]; !ok {
		t.Fatalf("the snapshot must deep-copy the live endpoint map: %+v", snapshot.endpointRateLimits)
	}
	manager.restoreSnapshot(snapshot)
	if _, ok := cfg.EndpointRateLimits["/api/other"]; !ok {
		t.Fatalf("the restore must put the captured endpoints back: %+v", cfg.EndpointRateLimits)
	}
}

// TestDynamicRuleFeatureToggles applies every override.
func TestDynamicRuleFeatureToggles(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	on := dynBoolPtr(true)
	off := dynBoolPtr(false)
	threshold, duration := 9, 1800
	rules := sampleRules()
	rules.EnablePenetrationDetection = off
	rules.EnableIPBanning = off
	rules.EnableRateLimiting = on
	rules.EnableRateLimitAutoBan = on
	rules.AutoBanThreshold = &threshold
	rules.AutoBanDuration = &duration
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	if cfg.EnablePenetrationDetection || cfg.EnableIPBanning {
		t.Fatal("the off toggles must apply")
	}
	if !cfg.EnableRateLimiting || !cfg.EnableRateLimitAutoBan {
		t.Fatal("the on toggles must apply")
	}
	if cfg.AutoBanThreshold != 9 || cfg.AutoBanDuration != 1800 {
		t.Fatalf("numeric overrides drifted: %d/%d", cfg.AutoBanThreshold, cfg.AutoBanDuration)
	}
}

// TestDynamicRuleEmergencyWithoutBus covers the emergency activation when
// no bus is installed (the log-only path).
func TestDynamicRuleEmergencyWithoutBus(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	rules := sampleRules()
	rules.EmergencyMode = true
	rules.EmergencyWhitelist = []string{"203.0.113.7"}
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	if !cfg.EmergencyMode {
		t.Fatal("emergency mode must activate without a bus")
	}
}

// TestDynamicRulePersistFileFailure covers the cache-file write failure
// path (the target directory does not exist).
func TestDynamicRulePersistFileFailure(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, func(c *SecurityConfig) {
		c.DynamicRulesCachePath = "/no/such/dir/rules.json"
	})
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil }); err != nil {
		t.Fatalf("a failing cache file must not fail the application: %v", err)
	}
}

// TestDynamicRuleHydrationApplyFailure covers the hydration error path.
func TestDynamicRuleHydrationApplyFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	payload := DumpLastKnownRulesSnapshot(*sampleRules())
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, _ := dynamicTestConfig(t, func(c *SecurityConfig) { c.DynamicRulesCachePath = path })
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	manager.mu.Lock()
	manager.applying = true // force the application to refuse
	manager.mu.Unlock()
	manager.HydrateLastKnownRules()
	if manager.CurrentRules() != nil {
		t.Fatal("a failed hydration must not leave active rules")
	}
}

// TestDynamicRuleReadRedisPayloadDown covers the enabled-but-unreachable
// Redis read error path during hydration.
func TestDynamicRuleReadRedisPayloadDown(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	down := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1/0", EnableRedis: true})
	manager := NewDynamicRuleManager(cfg, down, NewIPBanManager(nil, nil), nil)
	if payload := manager.readRedisPayload(); payload != "" {
		t.Fatalf("a down Redis must read empty: %q", payload)
	}
	// A nonexistent cache file reads empty without noise.
	if readFilePayload(filepath.Join(t.TempDir(), "missing.json"), manager.log) != "" {
		t.Fatal("a missing file reads empty")
	}
}

// TestDynamicRuleLoopDefaultsInterval covers the zero-interval fallback:
// the loop resolves the config default and its first tick runs
// immediately. The failing fetch then parks the loop for
// min(60, interval), where the stop lands deterministically.
func TestDynamicRuleLoopDefaultsInterval(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	if cfg.DynamicRuleInterval != DefaultDynamicRuleInterval {
		t.Fatalf("interval default drifted: %d", cfg.DynamicRuleInterval)
	}
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	started := make(chan struct{})
	fetch := func() (*DynamicRules, error) {
		select {
		case started <- struct{}{}:
		case <-time.After(time.Second):
		}
		return nil, errTransport{}
	}
	manager.Start(fetch, 0)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("the loop's first tick must run immediately")
	}
	manager.Stop()
}

// panickingAgent blows up inside SendEvent to exercise the reference's
// application-exception semantics (restore, log, fail the application).
type panickingAgent struct{}

func (panickingAgent) SendEvent(SecurityEvent) error { panic("agent transport exploded") }

func (panickingAgent) SendMetric(SecurityMetric) error { return nil }

// TestDynamicRuleApplicationExceptionRestoresSnapshot pins the fail-closed
// contract end to end: an exception mid-application (here: the agent
// panicking while the emergency event sends) restores the pre-rule
// snapshot and fails the update - no partial application survives.
func TestDynamicRuleApplicationExceptionRestoresSnapshot(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	// Swap the installed stream's handler for the panicking one.
	cfg.agent.handler = panickingAgent{}
	cfg.agent.bus = &SecurityEventBus{handler: cfg.agent.handler, cfg: cfg, filter: EventFilter{}}
	baseRate := cfg.RateLimit
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), cfg.agent.bus)
	rules := sampleRules()
	rules.EmergencyMode = true
	rules.EmergencyWhitelist = []string{"203.0.113.7"}
	err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil })
	if err == nil {
		t.Fatal("the application exception must fail the update")
	}
	if !strings.Contains(err.Error(), "dynamic rule application failed") {
		t.Fatalf("the failure must report the application error: %v", err)
	}
	if cfg.RateLimit != baseRate {
		t.Fatalf("the snapshot must be restored: %d != %d", cfg.RateLimit, baseRate)
	}
	if manager.CurrentRules() != nil {
		t.Fatal("a failed application must not leave active rules")
	}
}

// TestDynamicRuleUpdateRulesApplicationRefused covers the UpdateRules
// error path when the application refuses (re-entrancy).
func TestDynamicRuleUpdateRulesApplicationRefused(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	manager.mu.Lock()
	manager.applying = true
	manager.mu.Unlock()
	err := manager.UpdateRules(func() (*DynamicRules, error) { return sampleRules(), nil })
	if err == nil {
		t.Fatal("the refused application must surface through UpdateRules")
	}
	if manager.CurrentRules() != nil {
		t.Fatal("no rules may activate from a refused application")
	}
}

// TestDynamicRuleEmergencyWhitelistTruncation covers the first-10 slice
// of the emergency event whitelist.
func TestDynamicRuleEmergencyWhitelistTruncation(t *testing.T) {
	cfg, agent := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), busFor(cfg))
	whitelist := []string{
		"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4",
		"203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8",
		"203.0.113.9", "203.0.113.10", "203.0.113.11",
	}
	rules := sampleRules()
	rules.EmergencyMode = true
	rules.EmergencyWhitelist = whitelist
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	if len(cfg.EmergencyWhitelist) != 11 {
		t.Fatalf("the full whitelist must land on the config: %d", len(cfg.EmergencyWhitelist))
	}
	var emitted map[string]any
	for _, event := range agent.events {
		if event.EventType == EventEmergencyMode {
			emitted = event.Metadata
		}
	}
	if emitted == nil {
		t.Fatal("the emergency event must fire")
	}
	if emitted["whitelist_count"] != 11 {
		t.Fatalf("whitelist_count must carry the full size: %+v", emitted)
	}
	shown, _ := emitted["whitelist"].([]string)
	if len(shown) != 10 {
		t.Fatalf("the event whitelist must cap at 10 entries: %d", len(shown))
	}
}

// TestDynamicRuleGlobalRateLimitWithoutWindow covers the window fallback
// when a rule carries a limit but no window.
func TestDynamicRuleGlobalRateLimitWithoutWindow(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	baseWindow := cfg.RateLimitWindow
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	limit := 12
	rules := sampleRules()
	rules.GlobalRateLimit = &limit
	rules.GlobalRateWindow = nil
	if err := manager.UpdateRules(func() (*DynamicRules, error) { return rules, nil }); err != nil {
		t.Fatal(err)
	}
	if cfg.RateLimit != 12 || cfg.RateLimitWindow != baseWindow {
		t.Fatalf("limit-only rules keep the live window: %d/%d", cfg.RateLimit, cfg.RateLimitWindow)
	}
}

// TestDynamicRuleReadFilePayloadError covers the unreadable-file log
// branch (a directory in place of the cache file).
func TestDynamicRuleReadFilePayloadError(t *testing.T) {
	cfg, _ := dynamicTestConfig(t, nil)
	manager := NewDynamicRuleManager(cfg, nil, NewIPBanManager(nil, nil), nil)
	dir := t.TempDir()
	if payload := readFilePayload(dir, manager.log); payload != "" {
		t.Fatal("a directory path reads empty")
	}
}
