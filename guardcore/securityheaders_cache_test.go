package guardcore

import (
	"strings"
	"testing"
	"time"
)

func TestHeadersCacheKeyGrammar(t *testing.T) {
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	if key := manager.GenerateCacheKey(""); !strings.HasSuffix(key, "default") {
		t.Fatalf("an empty path must yield the default key: %q", key)
	}
	// The path normalizes (lowercase, outer slashes stripped) before the
	// hash, and the hash truncates to 16 hex chars.
	key := manager.GenerateCacheKey("/API/Data/")
	if !strings.HasPrefix(key, manager.keyPrefix+"path_") {
		t.Fatalf("path keys carry the path_ prefix: %q", key)
	}
	suffix := strings.TrimPrefix(key, manager.keyPrefix+"path_")
	if len(suffix) != 16 {
		t.Fatalf("the hash truncates to 16 hex chars: %q", suffix)
	}
	if key != manager.GenerateCacheKey("api/data") {
		t.Fatalf("normalization must fold case and outer slashes: %q", key)
	}
	// Distinct instances never share keys (the reference cfg_{id} prefix).
	other := NewSecurityHeadersManager(DefaultSecurityHeaders())
	if other.GenerateCacheKey("") == manager.GenerateCacheKey("") {
		t.Fatal("distinct managers must not share cache keys")
	}
}

func TestHeadersCacheTTLAndCapacity(t *testing.T) {
	cache := newHeadersTTLCache(2, 50*time.Millisecond)
	now := time.Now()
	cache.clock = func() time.Time { return now }

	cache.set("a", map[string]string{"x": "1"})
	if _, ok := cache.get("a"); !ok {
		t.Fatal("a fresh entry hits")
	}
	// Expiry: past the TTL the entry is gone.
	now = now.Add(51 * time.Millisecond)
	if _, ok := cache.get("a"); ok {
		t.Fatal("the entry must expire after the TTL")
	}
	if cache.size() != 0 {
		t.Fatalf("the expired entry must drop: %d", cache.size())
	}

	// Capacity: the oldest-inserted entry evicts at max size.
	cache.set("a", map[string]string{"x": "1"})
	cache.set("b", map[string]string{"x": "2"})
	cache.set("c", map[string]string{"x": "3"})
	if _, ok := cache.get("a"); ok {
		t.Fatal("the oldest entry must evict at capacity")
	}
	if _, ok := cache.get("c"); !ok {
		t.Fatal("the newest entry must survive")
	}
}

func TestSecurityHeadersManagerCacheRoundTrip(t *testing.T) {
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	first := manager.GetHeaders("")
	if len(first) == 0 {
		t.Fatal("the default header set must compute")
	}
	requests, hits, size := manager.CacheStats()
	if requests != 1 || hits != 0 || size != 1 {
		t.Fatalf("the first read must miss and populate: %d/%d/%d", requests, hits, size)
	}
	second := manager.GetHeaders("")
	for name, value := range first {
		if second[name] != value {
			t.Fatalf("the cached set must match: %s", name)
		}
	}
	requests, hits, _ = manager.CacheStats()
	if requests != 2 || hits != 1 {
		t.Fatalf("the second read must hit: %d/%d", requests, hits)
	}

	// The cache is keyed per path: a different path computes separately.
	byPath := manager.GetHeaders("/api")
	if len(byPath) != len(first) {
		t.Fatalf("path keys compute the same header set for one config: %d vs %d", len(byPath), len(first))
	}
}

func TestSecurityHeadersManagerNilStateFallsBackToDefaults(t *testing.T) {
	manager := NewSecurityHeadersManager(nil)
	headers := manager.GetHeaders("")
	if headers["X-Content-Type-Options"] != "nosniff" {
		t.Fatalf("a nil state must bind the reference defaults: %+v", headers)
	}
}

func TestSecurityHeadersManagerDisabled(t *testing.T) {
	state := DefaultSecurityHeaders()
	state.Enabled = false
	manager := NewSecurityHeadersManager(state)
	if headers := manager.GetHeaders(""); len(headers) != 0 {
		t.Fatalf("a disabled configuration yields no headers, got %d", len(headers))
	}
	var nilManager *SecurityHeadersManager
	if headers := nilManager.GetHeaders(""); len(headers) != 0 {
		t.Fatal("a nil manager yields no headers")
	}
}

func TestSecurityHeadersManagerStateOverride(t *testing.T) {
	state := DefaultSecurityHeaders()
	manager := NewSecurityHeadersManager(state)
	// The loaded Redis configuration overrides the bound state, and the
	// next cache miss picks it up (the cross-worker sync contract).
	state.Custom = map[string]string{"X-Loaded-Later": "yes"}
	manager.cache.purge()
	headers := manager.GetHeaders("")
	if headers["X-Loaded-Later"] != "yes" {
		t.Fatalf("the override must reach the computed headers: %+v", headers)
	}
}

func TestSecurityHeadersManagerLoadConfigValidation(t *testing.T) {
	// Without Redis attached the load is a no-op.
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager.LoadCachedConfig()
	if headers := manager.GetHeaders(""); headers["X-Content-Type-Options"] != "nosniff" {
		t.Fatal("the defaults must survive a handler-less load")
	}
	// Invalid custom headers in a payload are rejected per entry, not
	// fatally, through the shared validators.
	if _, err := validateHeaderName("bad header\nname"); err == nil {
		t.Fatal("the name validator must reject injection attempts")
	}
	if _, err := validateHeaderValue("value\r\nX-Evil: 1"); err == nil {
		t.Fatal("the value validator must reject CRLF injection")
	}
}

func TestSecurityHeadersManagerResetWithDownRedis(t *testing.T) {
	// A down handler: the reset's key-clear failure logs and the local
	// reset still completes.
	manager := NewSecurityHeadersManager(DefaultSecurityHeaders())
	manager.GetHeaders("")
	manager.SetRedis(NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1/0", EnableRedis: true}))
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a down Redis must fail soft on reset: %v", r)
		}
	}()
	manager.Reset()
	if manager.cache.size() != 0 {
		t.Fatal("the local cache must purge regardless of Redis")
	}
}

func TestSecurityHeadersManagerResetWithoutRedis(t *testing.T) {
	state := DefaultSecurityHeaders()
	state.Custom = map[string]string{"X-Extra": "1"}
	manager := NewSecurityHeadersManager(state)
	manager.GetHeaders("")
	manager.Reset()
	if manager.cache.size() != 0 {
		t.Fatal("reset must purge the cache")
	}
	if manager.redis != nil {
		t.Fatal("reset detaches the Redis handler, like the reference")
	}
}
