//go:build integration

package guardcore

// The redis_connection / redis_error family (the reference
// redis_handler._send_redis_event seam) driven against the live Redis.

import (
	"os"
	"testing"
)

func integrationRedisHost() string {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		return "127.0.0.1"
	}
	return host
}

func TestIntegrationRedisConnectionEvents(t *testing.T) {
	newIntegrationRedis(t) // gates the suite on REDIS_HOST
	agent := &recordingAgent{}
	manager := NewRedisManager(RedisConfig{
		URL:         "redis://" + integrationRedisHost() + ":6379/0",
		Prefix:      "guard_core:",
		EnableRedis: true,
	})
	manager.SetAgentHandler(agent)
	if err := manager.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer func() { _ = manager.Close() }()
	if len(agent.events) != 1 {
		t.Fatalf("the established connection must announce once, got %+v", agent.events)
	}
	event := agent.events[0]
	if event.EventType != EventRedisConnection || event.ActionTaken != "connection_established" {
		t.Fatalf("identity drifted: %+v", event)
	}
	if event.IPAddress != "system" || event.HandlerName != "redis" {
		t.Fatalf("handler-direct envelope drifted: %+v", event)
	}
	if want := "Redis connection successfully established"; event.Reason != want {
		t.Fatalf("reason drifted: %q, want %q", event.Reason, want)
	}
	if event.Metadata["redis_url"] != "redis://"+integrationRedisHost()+":6379/0" {
		t.Fatalf("redis_url metadata drifted: %+v", event.Metadata)
	}
}

func TestIntegrationRedisConnectionErrorEvent(t *testing.T) {
	agent := &recordingAgent{}
	manager := NewRedisManager(RedisConfig{
		URL:         "redis://localhost:59999/0",
		Prefix:      "guard_core:",
		EnableRedis: true,
	})
	manager.SetAgentHandler(agent)
	if err := manager.Initialize(); err == nil {
		t.Fatal("the closed port must fail the initialize")
	}
	if len(agent.events) != 1 {
		t.Fatalf("the failed connection must announce once, got %+v", agent.events)
	}
	event := agent.events[0]
	if event.EventType != EventRedisError || event.ActionTaken != "connection_failed" {
		t.Fatalf("identity drifted: %+v", event)
	}
	if event.Metadata["error_type"] != "connection_error" {
		t.Fatalf("error_type metadata drifted: %+v", event.Metadata)
	}
	if event.Metadata["redis_url"] != "redis://localhost:59999/0" {
		t.Fatalf("redis_url metadata drifted: %+v", event.Metadata)
	}
	if !startsWith(event.Reason, "Redis connection failed: ") {
		t.Fatalf("reason must carry the dial error, got %q", event.Reason)
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
