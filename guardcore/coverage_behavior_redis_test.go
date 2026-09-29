package guardcore

// Redis-backed behavior tracking paths (integration-tagged; they skip
// without REDIS_HOST like the rest of the integration suite).

import (
	"os"
	"testing"
)

func newBehaviorRedisTracker(t *testing.T, cfg *SecurityConfig) (*BehaviorTracker, *RedisManager) {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	mgr := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test:", EnableRedis: true})
	return NewBehaviorTracker(cfg, mgr, nil, nil), mgr
}

func TestBehaviorTrackerRedisWindows(t *testing.T) {
	cfg := behaviorTestConfig(t, func(c *SecurityConfig) { c.RedisFailOpen = true })
	tracker, mgr := newBehaviorRedisTracker(t, cfg)
	defer mgr.Close()

	rule := BehaviorRuleConfig{RuleType: "usage", Threshold: 2, Window: 60}
	// The redis window reports strictly-greater counts.
	if tracker.TrackEndpointUsage("redis-ep", "203.0.113.201", rule, 1000) {
		t.Fatal("first redis hits stay under the threshold")
	}
	tracker.TrackEndpointUsage("redis-ep", "203.0.113.201", rule, 1001)
	if !tracker.TrackEndpointUsage("redis-ep", "203.0.113.201", rule, 1002) {
		t.Fatal("third redis hits cross the threshold")
	}

	// Return patterns ride the same redis windows.
	returnRule := BehaviorRuleConfig{RuleType: "return_pattern", Threshold: 1, Window: 60, Pattern: "status:500"}
	resp := &Response{StatusCode: 500}
	if tracker.TrackReturnPattern("redis-ep", "203.0.113.201", resp, returnRule, 1000, 0) {
		t.Fatal("first redis returns stay at the threshold")
	}
	if !tracker.TrackReturnPattern("redis-ep", "203.0.113.201", resp, returnRule, 1001, 0) {
		t.Fatal("second redis returns cross the threshold")
	}
}

func TestBehaviorTrackerRedisFailClosed(t *testing.T) {
	cfg := behaviorTestConfig(t, func(c *SecurityConfig) { c.RedisFailOpen = false })
	tracker, mgr := newBehaviorRedisTracker(t, cfg)
	// A manager pointed at a dead port reports unavailable and the
	// fail-closed tracker reports false.
	dead := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1", Prefix: "guard_core_test:", EnableRedis: true})
	tracker.redis = dead
	if tracker.TrackEndpointUsage("redis-ep", "203.0.113.202", BehaviorRuleConfig{RuleType: "usage", Threshold: 1, Window: 60}, 1000) {
		t.Fatal("fail-closed trackers report false on redis errors")
	}
	if tracker.TrackReturnPattern("redis-ep", "203.0.113.202", &Response{StatusCode: 500}, BehaviorRuleConfig{RuleType: "return_pattern", Threshold: 1, Window: 60, Pattern: "status:500"}, 1000, 0) {
		t.Fatal("fail-closed return tracking reports false on redis errors")
	}
	_ = mgr
}
