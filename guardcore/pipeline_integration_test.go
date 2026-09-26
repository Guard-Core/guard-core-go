//go:build integration

package guardcore

import (
	"os"
	"testing"
	"time"
)

func newPipelineIntegration(t *testing.T, mutate func(*SecurityConfig)) *SecurityCheckPipeline {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	redis := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test:", EnableRedis: true})
	if err := redis.Initialize(); err != nil {
		t.Fatalf("Redis initialize failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = redis.DeletePattern("banned_ips:*")
		_, _ = redis.DeletePattern("rate_limit:rate:*")
		_ = redis.Close()
	})
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ban := NewIPBanManager(redis, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), redis, ban)
	rl.InitializeRedis(redis)
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, nil)
	return pipeline
}

func TestIntegrationPipelineBlocksBannedIP(t *testing.T) {
	pipeline := newPipelineIntegration(t, nil)
	bannedIP := "203.0.113.50"
	host := os.Getenv("REDIS_HOST")
	redis := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test:", EnableRedis: true})
	if err := redis.Initialize(); err != nil {
		t.Fatalf("redis: %v", err)
	}
	defer redis.Close()
	banManager := NewIPBanManager(redis, nil)
	applied, err := banManager.Ban(bannedIP, 60, "integration-test")
	if err != nil || !applied {
		t.Fatalf("ban not applied: %v %v", applied, err)
	}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = bannedIP
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != IPBanBlockedMessage {
		t.Fatalf("banned IP must be blocked with 403 'IP address banned', got %+v", resp)
	}
}

func TestIntegrationPipelineRateLimited(t *testing.T) {
	pipeline := newPipelineIntegration(t, func(c *SecurityConfig) {
		c.RateLimit = 2
		c.RateLimitWindow = 60
	})
	ip := "203.0.113.51"
	for i := 0; i < 2; i++ {
		req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
			opts.ClientHost = ip
		})
		if resp := pipeline.Execute(req); resp != nil {
			t.Fatalf("request %d must pass, got %+v", i+1, resp)
		}
	}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ip
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 429 {
		t.Fatalf("third request must be rate limited with 429, got %+v", resp)
	}
}

func TestIntegrationPipelinePenetrationDetected(t *testing.T) {
	pipeline := newPipelineIntegration(t, func(c *SecurityConfig) {
		c.AutoBanThreshold = 1000
	})
	ip := "203.0.113.52"
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ip
		opts.Path = "/search"
		opts.RawQuery = "q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
		opts.QueryParams = map[string]string{"q": "1' UNION SELECT username,password FROM users--"}
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 400 || string(resp.Body) != SuspiciousBlockedMsg {
		t.Fatalf("penetration attempt must be blocked with 400 'Suspicious activity detected', got %+v", resp)
	}
}

func TestIntegrationPipelineBanFeedAcrossInstances(t *testing.T) {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	redis := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test:", EnableRedis: true})
	if err := redis.Initialize(); err != nil {
		t.Fatalf("redis: %v", err)
	}
	defer redis.Close()
	writer := NewIPBanManager(redis, nil)
	reader := NewIPBanManager(redis, nil)
	applied, err := writer.Ban("203.0.113.53", 30, "cross-instance")
	if err != nil || !applied {
		t.Fatalf("ban: %v %v", applied, err)
	}
	time.Sleep(50 * time.Millisecond)
	if !reader.IsIPBanned("203.0.113.53") {
		t.Fatalf("ban must be visible through a second manager sharing redis")
	}
}
