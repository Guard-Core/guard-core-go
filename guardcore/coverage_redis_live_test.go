package guardcore

// Live-redis coverage for the manager operations and the rate limiter's
// redis paths. Integration-tagged; skips without REDIS_HOST.

import (
	"os"
	"testing"
	"time"
)

func newLiveRedisManager(t *testing.T) *RedisManager {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	m := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test:", EnableRedis: true})
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestRedisManagerLiveOperations(t *testing.T) {
	m := newLiveRedisManager(t)
	if err := m.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	// Set with and without TTLs, then read back.
	ttl := 60
	if err := m.SetKey("cov", "ttl", "v1", &ttl); err != nil {
		t.Fatalf("ttl set: %v", err)
	}
	if err := m.SetKey("cov", "plain", "v2", nil); err != nil {
		t.Fatalf("plain set: %v", err)
	}
	value, err := m.GetKey("cov", "ttl")
	if err != nil || value != "v1" {
		t.Fatalf("gets read back, got %q %v", value, err)
	}
	// Deletes report their cardinality.
	deleted, err := m.Delete("cov", "ttl")
	if err != nil || deleted != 1 {
		t.Fatalf("deletes count, got %d %v", deleted, err)
	}
	// Keys and pattern deletes sweep the namespace.
	if err := m.SetKey("cov", "sweep1", "x", nil); err != nil {
		t.Fatalf("sweep set: %v", err)
	}
	if err := m.SetKey("cov", "sweep2", "x", nil); err != nil {
		t.Fatalf("sweep set: %v", err)
	}
	keys, err := m.Keys("cov:*")
	if err != nil || len(keys) < 2 {
		t.Fatalf("keys list, got %v %v", keys, err)
	}
	deleted, err = m.DeletePattern("cov:sweep*")
	if err != nil || deleted != 2 {
		t.Fatalf("pattern deletes count, got %d %v", deleted, err)
	}
	// Pattern deletes with no matches are no-ops.
	deleted, err = m.DeletePattern("cov:nothing*")
	if err != nil || deleted != 0 {
		t.Fatalf("empty pattern deletes no-op, got %d %v", deleted, err)
	}
	// Scans walk the keyspace.
	if err := m.SetKey("cov", "scan", "x", nil); err != nil {
		t.Fatalf("scan set: %v", err)
	}
	scanned, err := m.ScanMatch("*cov:scan")
	if err != nil || len(scanned) != 1 {
		t.Fatalf("scans find keys, got %v %v", scanned, err)
	}
	// PTTL on a live key reports a positive duration.
	if err := m.SetPX("cov:px", "x", 30*time.Second); err != nil {
		t.Fatalf("setpx: %v", err)
	}
	ttlDur, err := m.PTTL("cov:px")
	if err != nil || ttlDur <= 0 {
		t.Fatalf("pttl reads live keys, got %v %v", ttlDur, err)
	}
	// Bulk deletes count.
	deleted, err = m.DeleteKeys("cov:px", m.Prefix()+"cov:plain", m.Prefix()+"cov:scan")
	if err != nil || deleted != 3 {
		t.Fatalf("bulk deletes count, got %d %v", deleted, err)
	}
	// Sliding window hits count cardinality.
	count, err := m.RecordSlidingWindowHit("covwin", "k", 1000, 900, 60)
	if err != nil || count != 1 {
		t.Fatalf("window hits count, got %d %v", count, err)
	}
	count, err = m.RecordSlidingWindowHit("covwin", "k", 1001, 900, 60)
	if err != nil || count != 2 {
		t.Fatalf("window hits accumulate, got %d %v", count, err)
	}
	_, _ = m.DeletePattern("cov:*")
	_, _ = m.DeletePattern("covwin:*")
}

func TestRedisManagerLiveScriptsAndRateLimit(t *testing.T) {
	m := newLiveRedisManager(t)
	if err := m.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	sha, err := m.ScriptLoad("return 1")
	if err != nil || sha == "" {
		t.Fatalf("script loads, got %q %v", sha, err)
	}
	count, err := m.EvalSha(sha, "cov:evalkey", 1000, 60, 10)
	if err != nil || count != 1 {
		t.Fatalf("evals run, got %d %v", count, err)
	}
	// Unknown scripts surface the NOSCRIPT error.
	if _, err = m.EvalSha("0123456789abcdef0123456789abcdef01234567", "cov:evalkey", 1000, 60, 10); err == nil {
		t.Fatal("unknown scripts surface errors")
	}
	// Nil replies fold to zero counts.
	nilSHA, err := m.ScriptLoad("return nil")
	if err != nil {
		t.Fatalf("nil script loads: %v", err)
	}
	count, err = m.EvalSha(nilSHA, "cov:evalkey", 1000, 60, 10)
	if err != nil || count != 0 {
		t.Fatalf("nil replies fold to zero, got %d %v", count, err)
	}
	// Pipelined window hits count cardinality.
	count, err = m.PipelineRateLimit("cov:pipe", "m1", 1000, 900, 60)
	if err != nil || count != 1 {
		t.Fatalf("pipelines count, got %d %v", count, err)
	}
	_, _ = m.DeletePattern("cov:*")
}

func TestRateLimitManagerLiveRedisTiers(t *testing.T) {
	m := newLiveRedisManager(t)
	if err := m.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.RateLimit = 2
		c.RateLimitWindow = 60
		c.RedisFailOpen = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), m, nil)
	rl.now = func() float64 { return 5000.0 }

	// The redis tier drives the global limit.
	mk := func() string { return "203.0.113.231" }
	if out, err := rl.CheckRateLimit(mk(), "/live", nil, nil); err != nil || out.Blocked {
		t.Fatalf("first requests pass, got %+v %v", out, err)
	}
	if out, err := rl.CheckRateLimit(mk(), "/live", nil, nil); err != nil || out.Blocked {
		t.Fatalf("second requests pass, got %+v %v", out, err)
	}
	out, err := rl.CheckRateLimit(mk(), "/live", nil, nil)
	if err != nil || !out.Blocked || out.Tier != "global" {
		t.Fatalf("third requests block on the global tier, got %+v %v", out, err)
	}
	// The agent hook wires through script reloads.
	hooked := 0
	rl.SetAgentHandlerHook(func() { hooked++ })
	rl.emitScriptReloaded()
	if hooked != 1 {
		t.Fatalf("script reload hooks fire, got %d", hooked)
	}
	// Reset clears the stores and detaches redis.
	rl.Reset()
	rl.mu.Lock()
	detached := rl.redis == nil
	rl.mu.Unlock()
	if !detached {
		t.Fatal("resets detach redis")
	}
}

func TestRateLimitManagerLiveFailClosedErrors(t *testing.T) {
	dead := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1", Prefix: "guard_core_test:", EnableRedis: true})
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.RateLimit = 2
		c.RateLimitWindow = 60
		c.RedisFailOpen = false
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), dead, nil)
	rl.InitializeRedis(dead)
	rl.now = func() float64 { return 6000.0 }
	// Fail-closed managers surface the redis error instead of falling back.
	if _, err := rl.CheckRateLimit("203.0.113.232", "/dead", nil, nil); err == nil {
		t.Fatal("fail-closed checks surface redis errors")
	}
	var redisErr *GuardRedisError
	if _, err := rl.CheckRateLimit("203.0.113.232", "/dead", nil, nil); !asGuardRedisError(err, &redisErr) {
		t.Fatalf("errors stay typed, got %v", err)
	}
	// The ByIP primitive fails the same way.
	if _, err := rl.CheckRateLimitByIP("203.0.113.232", "path"); err == nil {
		t.Fatal("fail-closed by-ip checks surface redis errors")
	}
}

func asGuardRedisError(err error, target *(*GuardRedisError)) bool {
	if e, ok := err.(*GuardRedisError); ok {
		*target = e
		return true
	}
	return false
}

func TestRateLimitManagerInitializeRedisLive(t *testing.T) {
	m := newLiveRedisManager(t)
	if err := m.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	cfg := RateLimitConfig{EnableRateLimiting: true, RateLimit: 5, RateLimitWindow: 60, RedisFailOpen: true}
	rl := NewRateLimitManager(cfg, nil, nil)
	rl.InitializeRedis(m)
	rl.mu.Lock()
	loaded := rl.scriptSHA != ""
	rl.mu.Unlock()
	if !loaded {
		t.Fatal("initialization loads the rate limit script")
	}
	// Re-initializing with a disabled handler stores the handler but skips
	// the rate-limit wiring.
	off := NewRedisManager(RedisConfig{EnableRedis: false})
	rl.InitializeRedis(off)
	rl.mu.Lock()
	stored := rl.redis == off
	rl.mu.Unlock()
	if !stored {
		t.Fatal("disabled handlers still register")
	}
}

func TestIPBanManagerLiveRedisChecks(t *testing.T) {
	m := newLiveRedisManager(t)
	if err := m.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	ban := NewIPBanManager(m, nil)
	if err := ban.InitializeRedis(m); err != nil {
		t.Fatalf("initialize redis: %v", err)
	}
	// Redis bans propagate into the local cache and back.
	if err := m.SetKey("banned_ips", "203.0.113.240", "4000000000", nil); err != nil {
		t.Fatalf("seed ban: %v", err)
	}
	if !ban.IsIPBanned("203.0.113.240") {
		t.Fatal("seeded redis bans register")
	}
	// Garbage ban values parse as misses.
	if err := m.SetKey("banned_ips", "203.0.113.241", "garbage", nil); err != nil {
		t.Fatalf("seed garbage: %v", err)
	}
	if ban.IsIPBanned("203.0.113.241") {
		t.Fatal("garbage ban values never register")
	}
	// Resets sweep the redis namespace.
	if err := ban.Reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if ban.IsIPBanned("203.0.113.240") {
		t.Fatal("resets clear redis bans")
	}
	// Migrations fold legacy keyed bans onto canonical addresses. The
	// legacy key needs a live TTL: persistent keys delete instead.
	if err := m.SetPX(m.Prefix()+"banned_ips:0:0:0:0:0:ffff:c0a8:101", "4000000000", time.Hour); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	ban.migrateLegacyBanKeys()
	if !ban.IsIPBanned("192.168.1.1") {
		t.Fatal("legacy keys migrate onto canonical addresses")
	}
	_, _ = m.DeletePattern("banned_ips:*")
}
