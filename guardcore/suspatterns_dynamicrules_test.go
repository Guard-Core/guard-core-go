package guardcore

// Tests mirroring the reference dynamic-rule application tests for
// suspicious_patterns (_apply_pattern_rules via UpdateRules): validated
// additions land in the runtime registry, unsafe patterns are rejected
// with the rejection honesty, and the patterns participate in detection.

import (
	"os"
	"strings"
	"testing"
)

func TestDynamicRulesSuspiciousPatternsApplied(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager

	redisMgr := NewRedisManager(RedisConfig{Prefix: "guard_core:test_susp:", EnableRedis: false})
	defer func() { _ = redisMgr.Close() }()
	ban := NewIPBanManager(nil, nil)
	dynamic := NewDynamicRuleManager(&SecurityConfig{}, redisMgr, ban, nil)

	rules := &DynamicRules{SuspiciousPatterns: []string{
		"dynpattern-[a-z]+",
		`(.*)+`,
	}}
	dynamic.applyBlockingRules(rules)

	customs := m.GetCustomPatterns()
	if len(customs) != 0 {
		t.Fatalf("dynamic rules add as default patterns, not customs: %v", customs)
	}
	defaults := m.GetDefaultPatterns()
	if len(defaults) != 1 || defaults[0] != "dynpattern-[a-z]+" {
		t.Fatalf("unsafe pattern rejected, safe one missing: %v", defaults)
	}
	// the runtime pattern participates in detection
	matched, pattern := m.DetectPatternMatch("hit dynpattern-abc now", "203.0.113.7", "request_body", "")
	if !matched || pattern != "dynpattern-[a-z]+" {
		t.Fatalf("dynamic pattern detection wrong: %v %q", matched, pattern)
	}
}

func TestDynamicRulesSuspiciousPatternsAllRejected(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager

	redisMgr := NewRedisManager(RedisConfig{Prefix: "guard_core:test_susp2:", EnableRedis: false})
	defer func() { _ = redisMgr.Close() }()
	ban := NewIPBanManager(nil, nil)
	dynamic := NewDynamicRuleManager(&SecurityConfig{}, redisMgr, ban, nil)

	dynamic.applyBlockingRules(&DynamicRules{SuspiciousPatterns: []string{`(.*)+`, `*bad`}})
	if got := m.GetAllPatterns(); len(got) != 0 {
		t.Fatalf("rejected patterns leaked: %v", got)
	}
}

func newSusPatternsLiveRedis(t *testing.T) *RedisManager {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	m := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test_susp:", EnableRedis: true})
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestSusPatternsRedisRestore(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager

	redisMgr := newSusPatternsLiveRedis(t)
	if err := redisMgr.Initialize(); err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	defer func() {
		_, _ = redisMgr.Delete("patterns", "custom")
		_ = redisMgr.Close()
	}()

	// persistence: an added custom pattern lands in Redis
	m.InitializeRedis(redisMgr)
	if !m.AddPattern("restoreme-[a-z]+", true) {
		t.Fatal("custom add failed")
	}
	stored, err := redisMgr.GetKey("patterns", "custom")
	if err != nil || !strings.Contains(stored, "restoreme-[a-z]+") {
		t.Fatalf("custom pattern not persisted: %q %v", stored, err)
	}

	// restore: a fresh manager restores the persisted pattern
	fresh := NewSusPatternsManager(nil)
	fresh.InitializeRedis(redisMgr)
	customs := fresh.GetCustomPatterns()
	if len(customs) != 1 || customs[0] != "restoreme-[a-z]+" {
		t.Fatalf("restore wrong: %v", customs)
	}
}

func TestSusPatternsRedisRestoreSkipsUnsafe(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager

	redisMgr := newSusPatternsLiveRedis(t)
	if err := redisMgr.Initialize(); err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	defer func() {
		_, _ = redisMgr.Delete("patterns", "custom")
		_ = redisMgr.Close()
	}()
	if err := redisMgr.SetKey("patterns", "custom", `(.*)+`, nil); err != nil {
		t.Fatal(err)
	}
	m.InitializeRedis(redisMgr)
	if len(m.GetCustomPatterns()) != 0 {
		t.Fatalf("unsafe persisted pattern restored: %v", m.GetCustomPatterns())
	}
}

func TestSusPatternsAddEventAgentless(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	// no agent handler: adds succeed with no emission path
	if !m.AddPattern("agentless-[a-z]+", true) {
		t.Fatal("agentless add failed")
	}
}
