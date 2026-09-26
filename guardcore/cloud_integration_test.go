//go:build integration

package guardcore

import (
	"os"
	"testing"
	"time"
)

func resetDefaultCloudManagerForTest() {
	m := DefaultCloudManager
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store = nil
	m.redisHandler = nil
	m.ipRanges = map[string]cloudRangeSet{}
	m.lastUpdated = map[string]time.Time{}
	m.emptyRangesWarnedAt = map[string]time.Time{}
	m.refreshInFlight = false
	m.lastRefreshStamp = 0
	m.testFetcher = nil
}

func newCloudIntegrationPipeline(t *testing.T, mutate func(*SecurityConfig)) (*SecurityCheckPipeline, *RedisManager) {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	redis := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test:", EnableRedis: true})
	if err := redis.Initialize(); err != nil {
		t.Skipf("Redis at %s:6379 busy or unavailable (%v); skipping integration test", host, err)
	}
	t.Cleanup(func() {
		_, _ = redis.DeletePattern("cloud_ip_v2:*")
		_, _ = redis.DeletePattern("cloud_ranges_v2:*")
		_, _ = redis.DeletePattern("banned_ips:*")
		_, _ = redis.DeletePattern("rate_limit:rate:*")
		_ = redis.Close()
		resetDefaultCloudManagerForTest()
	})
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(redis, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), redis, ban)
	rl.InitializeRedis(redis)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, nil)
	return pipeline, redis
}

func TestIntegrationCloudCacheHitPathBlocks(t *testing.T) {
	pipeline, redis := newCloudIntegrationPipeline(t, func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS"}
	})
	seed := NewRedisCloudIPStore(redis)
	if err := seed.Set("AWS", []string{"198.51.100.0/24"}, 300); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	DefaultCloudManager.mu.Lock()
	DefaultCloudManager.testFetcher = func(string) (cloudRangeSet, error) {
		panic("cache hit path must not fetch")
	}
	DefaultCloudManager.mu.Unlock()
	if err := DefaultCloudManager.InitializeRedis(redis, []string{"AWS"}, 300); err != nil {
		t.Fatalf("InitializeRedis: %v", err)
	}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "198.51.100.7"
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != CloudBlockedMsg {
		t.Fatalf("cached cloud range must block with 403 %q, got %+v", CloudBlockedMsg, resp)
	}
	waitForCondition(t, 5*time.Second, func() bool { return !DefaultCloudManager.Refreshing() },
		"scheduled background refresh must drain before cleanup removes the shared cache")
}

func TestIntegrationCloudRefreshOnInterval(t *testing.T) {
	pipeline, redis := newCloudIntegrationPipeline(t, func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS"}
		c.CloudIPRefreshInterval = 60
	})
	DefaultCloudManager.mu.Lock()
	DefaultCloudManager.testFetcher = func(string) (cloudRangeSet, error) {
		return cloudTestRangeSet(t, nil, "203.0.114.0/24"), nil
	}
	DefaultCloudManager.mu.Unlock()
	DefaultCloudManager.SetStore(NewRedisCloudIPStore(redis))
	DefaultCloudManager.SetLastRefreshStamp(time.Now().Unix() - 61)

	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "192.0.2.1"
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("request before refresh completes must fail open, got %+v", resp)
	}
	waitForCondition(t, 5*time.Second, func() bool { return DefaultCloudManager.hasRanges("AWS") },
		"refresh-on-interval must install fetched ranges in the background")
	cached, err := redis.GetKey("cloud_ip_v2", "AWS")
	if err != nil || cached == "" {
		t.Fatalf("refreshed ranges must be persisted under cloud_ip_v2:AWS: %q %v", cached, err)
	}
	blocked := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.114.9"
	})
	resp := pipeline.Execute(blocked)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != CloudBlockedMsg {
		t.Fatalf("refreshed cloud range must block with 403 %q, got %+v", CloudBlockedMsg, resp)
	}
}

func TestIntegrationCloudCrossInstanceCacheSharing(t *testing.T) {
	pipeline, redis := newCloudIntegrationPipeline(t, func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"GCP"}
	})
	writer := NewCloudManager()
	writer.SetStore(NewRedisCloudIPStore(redis))
	writer.testFetcher = func(string) (cloudRangeSet, error) {
		return cloudTestRangeSet(t, nil, "198.51.100.0/24"), nil
	}
	if err := writer.RefreshAsync([]string{"GCP"}, 300); err != nil {
		t.Fatalf("writer instance refresh: %v", err)
	}
	resetDefaultCloudManagerForTest()
	DefaultCloudManager.mu.Lock()
	DefaultCloudManager.testFetcher = func(string) (cloudRangeSet, error) {
		panic("second instance must read the shared cache, not fetch")
	}
	DefaultCloudManager.mu.Unlock()
	if err := DefaultCloudManager.InitializeRedis(redis, []string{"GCP"}, 300); err != nil {
		t.Fatalf("InitializeRedis: %v", err)
	}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "198.51.100.7"
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != CloudBlockedMsg {
		t.Fatalf("ranges written by another instance must block through this one, got %+v", resp)
	}
	waitForCondition(t, 5*time.Second, func() bool { return !DefaultCloudManager.Refreshing() },
		"scheduled background refresh must drain before cleanup removes the shared cache")
}

func TestIntegrationCloudMissFailsOpenUntilRefresh(t *testing.T) {
	pipeline, redis := newCloudIntegrationPipeline(t, func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"DigitalOcean"}
	})
	raw, err := redis.GetKey("cloud_ip_v2", "DigitalOcean")
	if err != nil || raw != "" {
		t.Fatalf("cache must start empty for the provider: %q %v", raw, err)
	}
	DefaultCloudManager.SetLastRefreshStamp(time.Now().Unix())
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.113.77"
	})
	if resp := pipeline.Execute(req); resp != nil {
		t.Fatalf("an unpopulated cache must fail open: %+v", resp)
	}
}
