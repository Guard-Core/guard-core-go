//go:build integration

package guardcore

import (
	"os"
	"testing"
)

func newRouteIntegrationPipeline(t *testing.T, mutate func(*SecurityConfig), register func(*RouteRegistry)) (*SecurityCheckPipeline, *RouteRegistry) {
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
	registry := NewRouteRegistry()
	if register != nil {
		register(registry)
	}
	pipeline, _ := BuildDefaultPipeline(cfg, ban, rl, registry)
	return pipeline, registry
}

func TestIntegrationRoutePipelineOverRedis(t *testing.T) {
	pipeline, _ := newRouteIntegrationPipeline(t, nil, func(registry *RouteRegistry) {
		registry.Register("/api/data", func(rc *RouteConfig) {
			rc.RequiredHeaders = RequiredHeaders{{Name: "X-Client", Value: "required"}}
			rc.MaxRequestSize = 128
			rc.AllowedContentTypes = []string{"application/json"}
		})
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/api/data"
		opts.Header = map[string]string{"Content-Type": "application/json", "Content-Length": "10"}
	})
	resp := pipeline.Execute(req)
	if resp == nil || resp.StatusCode != 400 || string(resp.Body) != "Missing required header: X-Client" {
		t.Fatalf("route required headers must block over redis pipeline, got %+v", resp)
	}
	good := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/api/data"
		opts.Header = map[string]string{"X-Client": "web", "Content-Type": "application/json", "Content-Length": "10"}
	})
	if resp := pipeline.Execute(good); resp != nil {
		t.Fatalf("satisfied route must pass, got %+v", resp)
	}
	oversize := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/api/data"
		opts.Header = map[string]string{"X-Client": "web", "Content-Length": "512", "Content-Type": "application/json"}
	})
	if resp := pipeline.Execute(oversize); resp == nil || resp.StatusCode != 413 {
		t.Fatalf("oversize must 413, got %+v", resp)
	}
	badType := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.GuardRouteID = "/api/data"
		opts.Header = map[string]string{"X-Client": "web", "Content-Length": "10", "Content-Type": "text/plain"}
	})
	if resp := pipeline.Execute(badType); resp == nil || resp.StatusCode != 415 {
		t.Fatalf("bad content type must 415, got %+v", resp)
	}
}

func TestIntegrationEmergencyAndHTTPSOverRedis(t *testing.T) {
	pipeline, _ := newRouteIntegrationPipeline(t, func(cfg *SecurityConfig) {
		cfg.EmergencyMode = true
		cfg.EnforceHTTPS = true
		cfg.EmergencyWhitelist = []string{"203.0.113.9"}
	}, nil)
	req := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) { opts.ClientHost = "198.51.100.77" })
	resp := pipeline.Execute(req)
	if resp.StatusCode != 503 || string(resp.Body) != "Service temporarily unavailable" {
		t.Fatalf("emergency mode must 503 first, got %+v", resp)
	}
	safe := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Scheme = "https"
	})
	if resp := pipeline.Execute(safe); resp != nil {
		t.Fatalf("https request must pass emergency/https checks, got %+v", resp)
	}
}

func TestIntegrationRouteRevisionRebuildOverRedis(t *testing.T) {
	pipeline, registry := newRouteIntegrationPipeline(t, nil, nil)
	before := pipeline.CheckNames()
	registry.Register("/secure", func(rc *RouteConfig) { rc.RequireHTTPS = true })
	if !pipeline.IsStale() {
		t.Fatalf("route revision must mark pipeline stale")
	}
	req := newTestRequest(t, nil)
	_ = pipeline.Execute(req)
	after := pipeline.CheckNames()
	if len(after) <= len(before) {
		t.Fatalf("rebuild must add https_enforcement slot: before=%v after=%v", before, after)
	}
	found := false
	for _, n := range after {
		if n == "https_enforcement" {
			found = true
		}
	}
	if !found {
		t.Fatalf("https_enforcement missing after rebuild: %v", after)
	}
}
