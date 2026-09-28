package guardcore

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeZSet struct {
	mu       sync.Mutex
	members  map[string]map[string]float64
	ttls     map[string]time.Time
	loadErr  error
	evalErr  error
	failMode string
	calls    []string
}

func newFakeZSet() *fakeZSet {
	return &fakeZSet{members: map[string]map[string]float64{}, ttls: map[string]time.Time{}}
}

func (f *fakeZSet) record(op string) {
	f.calls = append(f.calls, op)
}

func (f *fakeZSet) ScriptLoad(script string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("scriptload")
	if f.loadErr != nil {
		return "", f.loadErr
	}
	f.evalErr = nil
	return "feedbeef", nil
}

func (f *fakeZSet) applyError(err error) error {
	if f.failMode == "generic" {
		return fmt.Errorf("connection refused")
	}
	return err
}

func (f *fakeZSet) EvalSha(sha, key string, now float64, window, limit int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("evalsha:" + key)
	if f.evalErr != nil {
		if strings.Contains(strings.ToUpper(f.evalErr.Error()), "NOSCRIPT") && f.failMode != "generic" {
			return 0, f.evalErr
		}
		return 0, f.applyError(f.evalErr)
	}
	members, ok := f.members[key]
	if !ok {
		members = map[string]float64{}
		f.members[key] = members
	}
	members[formatExpiry(now)] = now
	windowStart := now - float64(window)
	for member, score := range members {
		if member != formatExpiry(now) && score <= windowStart {
			delete(members, member)
		}
	}
	f.ttls[key] = time.Now().Add(time.Duration(window*2) * time.Second)
	return int64(len(members)), nil
}

func (f *fakeZSet) PipelineRateLimit(key, member string, now, windowStart float64, window int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("pipeline:" + key)
	if f.failMode != "" {
		return 0, fmt.Errorf("connection refused")
	}
	members, ok := f.members[key]
	if !ok {
		members = map[string]float64{}
		f.members[key] = members
	}
	members[member] = now
	for m, score := range members {
		if m != member && score <= windowStart {
			delete(members, m)
		}
	}
	f.ttls[key] = time.Now().Add(time.Duration(window*2) * time.Second)
	return int64(len(members)), nil
}

func (f *fakeZSet) zcard(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.members[key])
}

func newRateLimitTestManager(t *testing.T, cfg RateLimitConfig, redisHandler RedisHandler, rl RateLimitRedis, clock *float64) *RateLimitManager {
	t.Helper()
	mgr := NewRateLimitManager(cfg, redisHandler, nil)
	mgr.now = func() float64 { return *clock }
	if redisHandler != nil && rl != nil {
		mgr.rlRedis = rl
	}
	return mgr
}

func rlIntPtr(v int) *int { return &v }

func stepper(start float64) func() float64 {
	current := start
	return func() float64 {
		v := current
		current++
		return v
	}
}

func TestRedisPathCountsCurrentHitAndBlocksAtLimitPlusOne(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 3
	cfg.RateLimitWindow = 60
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)

	for i := 0; i < 3; i++ {
		outcome, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Blocked {
			t.Fatalf("hit %d unexpectedly blocked", i+1)
		}
		clock++
	}
	outcome, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Blocked {
		t.Fatal("4th hit should be blocked with limit 3")
	}
	if outcome.Count != 4 {
		t.Errorf("count = %d, want 4 (includes current hit)", outcome.Count)
	}
	if outcome.StatusCode != 429 || outcome.Message != "Too many requests" {
		t.Errorf("outcome = %+v", outcome)
	}
	if got := outcome.RetryAfter(); got != "60" {
		t.Errorf("Retry-After = %q, want \"60\"", got)
	}
}

func TestInMemoryPathPreAppendCompareLogsCountPlusOne(t *testing.T) {
	clock := 1000.0
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 2
	cfg.RateLimitWindow = 60
	mgr := newRateLimitTestManager(t, cfg, nil, nil, &clock)

	for i := 0; i < 2; i++ {
		outcome, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Blocked {
			t.Fatalf("hit %d unexpectedly blocked", i+1)
		}
		clock++
	}
	outcome, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Blocked {
		t.Fatal("3rd hit should be blocked with limit 2")
	}
	if outcome.Count != 3 {
		t.Errorf("reported count = %d, want 3 (pre-append count + 1)", outcome.Count)
	}
}

func TestInclusiveWindowEvictionBoundary(t *testing.T) {
	clock := 1000.0
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 100
	cfg.RateLimitWindow = 60
	mgr := newRateLimitTestManager(t, cfg, nil, nil, &clock)

	outcome, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Blocked {
		t.Fatal("seed hit blocked")
	}

	clock = 1000 + 60
	outcome, err = mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Count != 0 {
		t.Errorf("timestamp exactly at window_start must be evicted (inclusive): pre-append count = %d, want 0", outcome.Count)
	}

	clock = 1000 + 60.5
	outcome, err = mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Count != 1 {
		t.Errorf("timestamp just inside window must survive: pre-append count = %d, want 1", outcome.Count)
	}
}

func TestRedisInclusiveWindowEvictionBoundary(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 100
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)

	if _, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil); err != nil {
		t.Fatal(err)
	}

	clock = 1060.5
	if _, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	if zs.zcard("guard_core:rate_limit:rate:1.2.3.4") != 1 {
		t.Error("score exactly at window_start must be evicted (ZREMRANGEBYSCORE inclusive)")
	}
}

func TestTierCompositionSharedEndpointRouteBucket(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	cfg.EndpointRateLimits["/login"] = RateLimitEntry{Requests: 100, Window: 30}
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)

	mgr.now = stepper(1000)
	route := &RouteRateConfig{RateLimit: rlIntPtr(5), RateLimitWindow: rlIntPtr(60)}

	outcome, err := mgr.CheckRateLimit("1.2.3.4", "/login", route, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Blocked {
		t.Fatal("unexpected block")
	}

	endpointKey := rateLimitRedisKey("guard_core:", "1.2.3.4", "/login")
	if zs.zcard(endpointKey) != 2 {
		t.Fatalf("endpoint and route tiers must share one bucket per (ip, path); got %d members", zs.zcard(endpointKey))
	}
	globalKey := rateLimitRedisKey("guard_core:", "1.2.3.4", "")
	if zs.zcard(globalKey) != 1 {
		t.Fatalf("global tier uses its own bucket; got %d members", zs.zcard(globalKey))
	}
}

func TestFirstBlockShortCircuitsLaterTiers(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 0
	cfg.RateLimitWindow = 60
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)
	mgr.cfg.RateLimit = 0

	outcome, err := mgr.CheckRateLimit("1.2.3.4", "/x", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Blocked || outcome.Tier != "global" {
		t.Fatalf("expected global-tier block, got %+v", outcome)
	}
	if zs.zcard(rateLimitRedisKey("guard_core:", "1.2.3.4", "/x")) != 0 {
		t.Error("blocked on first tier must not record hits in later tiers")
	}
}

func TestGeoTierCountryFallbackWildcard(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 100
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)
	mgr.now = stepper(1000)

	route := &RouteRateConfig{GeoRateLimits: map[string]RateLimitEntry{
		"US": {Requests: 1, Window: 60},
		"*":  {Requests: 1, Window: 60},
	}}

	outcome, err := mgr.CheckRateLimit("1.2.3.4", "/x", route, func(string) string { return "DE" })
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Blocked {
		t.Fatal("first DE hit under wildcard limit should pass")
	}
	outcome, err = mgr.CheckRateLimit("1.2.3.4", "/x", route, func(string) string { return "DE" })
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Blocked || outcome.Tier != "geo" || outcome.Window != 60 {
		t.Fatalf("expected geo wildcard block, got %+v", outcome)
	}

	zs2 := newFakeZSet()
	mgr2 := newRateLimitTestManager(t, cfg, newFakeRedis(), zs2, &clock)
	mgr2.now = stepper(2000)
	outcome, err = mgr2.CheckRateLimit("1.2.3.5", "/x", route, func(string) string { return "US" })
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Blocked {
		t.Fatal("first US hit should pass")
	}
	outcome, err = mgr2.CheckRateLimit("1.2.3.5", "/x", route, func(string) string { return "US" })
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Blocked || outcome.Tier != "geo" {
		t.Fatalf("expected US geo block, got %+v", outcome)
	}
}

func TestGeoTierNoMatchingCountryNoLimit(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)

	route := &RouteRateConfig{GeoRateLimits: map[string]RateLimitEntry{
		"US": {Requests: 1, Window: 60},
	}}
	for i := 0; i < 5; i++ {
		outcome, err := mgr.CheckRateLimit("1.2.3.4", "/x", route, func(string) string { return "DE" })
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Blocked {
			t.Fatal("no wildcard fallback means no geo limit")
		}
		clock++
	}
}

func TestFailClosedRaisesGuardRedisError(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	zs.failMode = "generic"
	cfg := DefaultRateLimitConfig()
	cfg.RedisFailOpen = false
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)

	_, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
	gerr, ok := err.(*GuardRedisError)
	if !ok {
		t.Fatalf("want GuardRedisError, got %v", err)
	}
	if gerr.StatusCode != 503 || gerr.Message != "Redis rate limiting unavailable" {
		t.Errorf("err = %+v", gerr)
	}
}

func TestFailOpenFallsBackToMemoryOncePerProcess(t *testing.T) {
	resetRateLimitFailOpenWarned()
	clock := 1000.0
	zs := newFakeZSet()
	zs.failMode = "generic"
	cfg := DefaultRateLimitConfig()
	cfg.RedisFailOpen = true
	cfg.RateLimit = 1
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)

	outcome, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
	if err != nil {
		t.Fatalf("fail-open must swallow redis errors: %v", err)
	}
	if outcome.Blocked {
		t.Fatal("first memory hit should pass")
	}
	if mgr.TrackedKeyCount() != 1 {
		t.Error("fail-open must fall back to the in-memory window")
	}
	resetRateLimitFailOpenWarned()
}

func TestScriptReloadOnNoScriptError(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	zs.evalErr = fmt.Errorf("NOSCRIPT No matching script. Please use EVAL.")
	cfg := DefaultRateLimitConfig()
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)
	mgr.scriptSHA = "stalesha"
	reloads := 0
	mgr.OnScriptReload = func() { reloads++ }

	outcome, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Blocked {
		t.Fatal("unexpected block")
	}
	if reloads != 1 {
		t.Errorf("reloads = %d, want 1", reloads)
	}
	if mgr.scriptSHA != "feedbeef" {
		t.Errorf("sha = %q, want reloaded sha", mgr.scriptSHA)
	}
	loads := 0
	for _, c := range zs.calls {
		if c == "scriptload" {
			loads++
		}
	}
	if loads != 1 {
		t.Errorf("script loads = %d, want 1", loads)
	}
}

func TestScriptLoadFailureFallsBackToPipeline(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)
	mgr.scriptSHA = ""

	outcome, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Blocked {
		t.Fatal("unexpected block")
	}
	found := false
	for _, c := range zs.calls {
		if strings.HasPrefix(c, "pipeline:") {
			found = true
		}
	}
	if !found {
		t.Error("empty sha must use the MULTI pipeline fallback")
	}
}

func TestEndpointBucketUsesSha256HexOfPath(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)

	if _, err := mgr.CheckRateLimitByIP("1.2.3.4", "/api/x"); err != nil {
		t.Fatal(err)
	}
	want := rateLimitRedisKey("guard_core:", "1.2.3.4", "/api/x")
	if zs.zcard(want) != 1 {
		t.Fatalf("missing member under %s (calls=%v)", want, zs.calls)
	}
	if !strings.HasSuffix(want, "1.2.3.4:"+hashIdentitySegment("/api/x")) {
		t.Errorf("key %s must be {prefix}rate_limit:rate:{ip}:{sha256hex(path)}", want)
	}
}

func TestPrimitiveValidationBeforeSideEffects(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)

	if _, err := mgr.CheckRateLimitByIP("not-an-ip", ""); err == nil {
		t.Error("invalid ip must raise ValueError equivalent")
	}
	if _, err := mgr.CheckRateLimitByIP("1.2.3.4", "a:b"); err == nil {
		t.Error("endpoint_path with ':' must raise ValueError equivalent")
	}
	if zs.zcard(rateLimitRedisKey("guard_core:", "1.2.3.4", "")) != 0 {
		t.Error("rejected input must not record a hit")
	}
	if mgr.ByIPKeyCount() != 0 {
		t.Error("rejected input must not touch the in-memory store")
	}
}

func TestPrimitiveDisabledRateLimitingAlwaysTrue(t *testing.T) {
	clock := 1000.0
	cfg := DefaultRateLimitConfig()
	cfg.EnableRateLimiting = false
	cfg.RateLimit = 0
	mgr := newRateLimitTestManager(t, cfg, nil, nil, &clock)

	for i := 0; i < 3; i++ {
		allowed, err := mgr.CheckRateLimitByIP("1.2.3.4", "")
		if err != nil || !allowed {
			t.Fatalf("disabled rate limiting must return true: allowed=%v err=%v", allowed, err)
		}
	}
}

func TestPrimitivePipelinePathAlwaysUsed(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)
	mgr.scriptSHA = "cacheda"

	if _, err := mgr.CheckRateLimitByIP("1.2.3.4", ""); err != nil {
		t.Fatal(err)
	}
	pipelines := 0
	for _, c := range zs.calls {
		if strings.HasPrefix(c, "pipeline:") {
			pipelines++
		}
	}
	if pipelines != 1 {
		t.Errorf("primitive must always use the pipeline path, got %d pipeline calls", pipelines)
	}
}

func TestPrimitiveSharesGlobalBucketInMemory(t *testing.T) {
	clock := 1000.0
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 2
	mgr := newRateLimitTestManager(t, cfg, nil, nil, &clock)

	if allowed, _ := mgr.CheckRateLimitByIP("1.2.3.4", ""); !allowed {
		t.Fatal("hit 1 should pass")
	}
	clock++
	if allowed, _ := mgr.CheckRateLimitByIP("1.2.3.4", ""); !allowed {
		t.Fatal("hit 2 should pass")
	}
	clock++
	if allowed, _ := mgr.CheckRateLimitByIP("1.2.3.4", ""); allowed {
		t.Fatal("hit 3 should be limited")
	}
}

func TestLRUCapEvictsOldestBucket(t *testing.T) {
	clock := 1000.0
	cfg := DefaultRateLimitConfig()
	mgr := newRateLimitTestManager(t, cfg, nil, nil, &clock)

	for i := 0; i < maxTrackedRateLimitKeys+1; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
		if _, err := mgr.CheckRateLimit(ip, "", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if mgr.TrackedKeyCount() > maxTrackedRateLimitKeys {
		t.Errorf("store cap = %d, want <= %d", mgr.TrackedKeyCount(), maxTrackedRateLimitKeys)
	}
}

func TestAutobanFlatThresholdAndDuration(t *testing.T) {
	clock := 1000.0
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 1
	cfg.EnableRateLimitAutoBan = true
	cfg.EnableIPBanning = true
	store := newFakeRedis()
	ban := NewIPBanManager(store, nil)
	mgr := NewRateLimitManager(cfg, nil, ban)
	mgr.now = func() float64 { return clock }

	allowed, err := mgr.CheckRateLimitByIP("9.9.9.9", "")
	if err != nil || !allowed {
		t.Fatalf("hit 1 must pass: %v %v", allowed, err)
	}
	clock++
	if allowed, _ := mgr.CheckRateLimitByIP("9.9.9.9", ""); allowed {
		t.Fatal("hit 2 must be limited")
	}
	if ban.IsIPBanned("9.9.9.9") {
		t.Fatal("1 violation under flat threshold 10 must not ban")
	}
	for i := 0; i < 9; i++ {
		clock++
		if allowed, _ := mgr.CheckRateLimitByIP("9.9.9.9", ""); allowed {
			t.Fatalf("violation %d must be limited", i+2)
		}
		_ = i
	}
	if !ban.IsIPBanned("9.9.9.9") {
		t.Fatal("10 violations must cross flat threshold and ban")
	}
	value, err := store.GetKey("banned_ips", "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if value == "" {
		t.Fatal("ban key missing")
	}
}

func TestAutobanThreatConfigOverridesFlat(t *testing.T) {
	clock := 1000.0
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 1
	cfg.EnableRateLimitAutoBan = true
	cfg.EnableIPBanning = true
	cfg.ThreatBanConfig["rate_limit"] = ThreatBanEntry{Threshold: 3, Duration: 7200}
	ban := NewIPBanManager(newFakeRedis(), nil)
	mgr := NewRateLimitManager(cfg, nil, ban)
	mgr.now = func() float64 { return clock }

	if allowed, _ := mgr.CheckRateLimitByIP("9.9.9.9", ""); !allowed {
		t.Fatal("hit 1 must pass")
	}
	clock++
	if allowed, _ := mgr.CheckRateLimitByIP("9.9.9.9", ""); allowed {
		t.Fatal("hit 2 must be limited")
	}
	if ban.IsIPBanned("9.9.9.9") {
		t.Fatal("2 violations under threshold 3 must not ban")
	}
	for i := 0; i < 2; i++ {
		clock++
		if allowed, _ := mgr.CheckRateLimitByIP("9.9.9.9", ""); allowed {
			t.Fatalf("limited hit %d must be limited", i+3)
		}
	}
	if !ban.IsIPBanned("9.9.9.9") {
		t.Fatal("3 violations must cross threat_ban_config threshold and ban")
	}
}

func TestAutobanGatesOffWhenDisabledPassiveOrNoBanning(t *testing.T) {
	clock := 1000.0
	base := DefaultRateLimitConfig()
	base.RateLimit = 1

	cases := []struct {
		name string
		mut  func(c *RateLimitConfig)
	}{
		{"no autoban", func(c *RateLimitConfig) { c.EnableRateLimitAutoBan = false }},
		{"no ip banning", func(c *RateLimitConfig) { c.EnableIPBanning = false }},
		{"passive mode", func(c *RateLimitConfig) { c.PassiveMode = true }},
	}
	for _, tc := range cases {
		cfg := base
		cfg.EnableRateLimitAutoBan = true
		cfg.EnableIPBanning = true
		tc.mut(&cfg)
		ban := NewIPBanManager(newFakeRedis(), nil)
		mgr := NewRateLimitManager(cfg, nil, ban)
		mgr.now = func() float64 { return clock }
		for i := 0; i < 15; i++ {
			_, _ = mgr.CheckRateLimitByIP("9.9.9.9", "")
		}
		if ban.IsIPBanned("9.9.9.9") {
			t.Errorf("%s: must never ban", tc.name)
		}
		if cfg.PassiveMode && mgr.AutobanCount("9.9.9.9") != 0 {
			t.Error("passive mode must suppress autoban counting entirely")
		}
	}
}

func TestAutobanAlreadyBannedShortCircuit(t *testing.T) {
	clock := 1000.0
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 1
	cfg.EnableRateLimitAutoBan = true
	cfg.EnableIPBanning = true
	ban := NewIPBanManager(newFakeRedis(), nil)
	if _, err := ban.Ban("9.9.9.9", 3600, "preset"); err != nil {
		t.Fatal(err)
	}
	mgr := NewRateLimitManager(cfg, nil, ban)
	mgr.now = func() float64 { return clock }

	for i := 0; i < 20; i++ {
		_, _ = mgr.CheckRateLimitByIP("9.9.9.9", "")
	}
	if mgr.AutobanCount("9.9.9.9") != 0 {
		t.Errorf("already-banned IP must not grow the autoban counter, got %d", mgr.AutobanCount("9.9.9.9"))
	}
}

func TestAutobanFiresOnceAcrossManyViolations(t *testing.T) {
	clock := 1000.0
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 1
	cfg.EnableRateLimitAutoBan = true
	cfg.EnableIPBanning = true
	ban := NewIPBanManager(newFakeRedis(), nil)
	mgr := NewRateLimitManager(cfg, nil, ban)
	mgr.now = func() float64 { return clock }

	_, _ = mgr.CheckRateLimitByIP("9.9.9.9", "")
	clock++
	for i := 0; i < 15; i++ {
		if allowed, _ := mgr.CheckRateLimitByIP("9.9.9.9", ""); allowed {
			t.Fatal("must stay limited")
		}
		clock++
	}
	if !ban.IsIPBanned("9.9.9.9") {
		t.Fatal("threshold crossing must ban")
	}
	if got := mgr.AutobanCount("9.9.9.9"); got != 10 {
		t.Errorf("autoban count = %d, want exactly the threshold crossing count 10 (banned IP short-circuits after)", got)
	}
}

type fakeCombinedStore struct {
	*fakeRedis
	*fakeZSet
}

func (f *fakeCombinedStore) DeletePattern(pattern string) (int64, error) {
	f.fakeZSet.mu.Lock()
	defer f.fakeZSet.mu.Unlock()
	suffix := "guard_core:" + pattern
	suffix = suffix[:len(suffix)-1]
	var n int64
	for k := range f.fakeZSet.members {
		if len(k) >= len(suffix) && k[:len(suffix)] == suffix {
			delete(f.fakeZSet.members, k)
			delete(f.fakeZSet.ttls, k)
			n++
		}
	}
	return n, nil
}

func TestResetClearsMemoryAndRedisKeys(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	store := &fakeCombinedStore{newFakeRedis(), zs}
	cfg := DefaultRateLimitConfig()
	mgr := newRateLimitTestManager(t, cfg, store, store, &clock)

	if _, err := mgr.CheckRateLimit("1.2.3.4", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	mgr.Reset()
	if zs.zcard(rateLimitRedisKey("guard_core:", "1.2.3.4", "")) != 0 {
		t.Error("reset must delete shared Redis rate keys")
	}
	if mgr.TrackedKeyCount() != 0 {
		t.Error("reset must clear in-memory deques")
	}
}

func TestTierFourHitsAcrossThreeKeys(t *testing.T) {
	clock := 1000.0
	zs := newFakeZSet()
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 100
	cfg.EndpointRateLimits["/p"] = RateLimitEntry{Requests: 100, Window: 60}
	mgr := newRateLimitTestManager(t, cfg, newFakeRedis(), zs, &clock)

	mgr.now = stepper(1000)
	route := &RouteRateConfig{RateLimit: rlIntPtr(100), RateLimitWindow: rlIntPtr(60), GeoRateLimits: map[string]RateLimitEntry{
		"*": {Requests: 100, Window: 60},
	}}
	if _, err := mgr.CheckRateLimit("1.2.3.4", "/p", route, func(string) string { return "US" }); err != nil {
		t.Fatal(err)
	}

	endpointKey := rateLimitRedisKey("guard_core:", "1.2.3.4", "/p")
	globalKey := rateLimitRedisKey("guard_core:", "1.2.3.4", "")
	total := zs.zcard(endpointKey) + zs.zcard(globalKey)
	if total != 4 {
		t.Errorf("four tiers = 4 hits across keys; endpoint+route+geo bucket=%d global=%d total=%d, want 4", zs.zcard(endpointKey), zs.zcard(globalKey), total)
	}
}
