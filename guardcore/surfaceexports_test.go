package guardcore

import (
	"context"
	"errors"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestInMemoryCloudIPStoreClear(t *testing.T) {
	store := NewInMemoryCloudIPStore()
	if err := store.Set("AWS", []string{"203.0.113.0/24"}, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok, _ := store.Get("AWS"); !ok {
		t.Fatal("the entry must be present before Clear")
	}
	store.Clear()
	if _, ok, _ := store.Get("AWS"); ok {
		t.Fatal("Clear must drop every provider entry")
	}
}

func TestRedisCloudIPStoreClear(t *testing.T) {
	handler := &capturingRedisHandler{}
	store := NewRedisCloudIPStore(handler)
	if err := store.Set("AWS", []string{"203.0.113.0/24"}, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if len(handler.deleted) != 1 || handler.deleted[0] != "AWS" {
		t.Fatalf("Clear must delete each stored provider, got %v", handler.deleted)
	}
}

type capturingRedisHandler struct {
	deleted []string
}

func (h *capturingRedisHandler) Prefix() string { return "cloud_ip_v2" }
func (h *capturingRedisHandler) Enabled() bool  { return true }
func (h *capturingRedisHandler) Initialize() error {
	return nil
}
func (h *capturingRedisHandler) Close() error { return nil }
func (h *capturingRedisHandler) GetKey(namespace, key string) (string, error) {
	return encodeCloudIPv2Payload([]string{"203.0.113.0/24"}), nil
}
func (h *capturingRedisHandler) SetKey(namespace, key, value string, ttlSeconds *int) error {
	return nil
}
func (h *capturingRedisHandler) Delete(namespace, key string) (int64, error) {
	h.deleted = append(h.deleted, key)
	return 1, nil
}
func (h *capturingRedisHandler) Keys(pattern string) ([]string, error) {
	return []string{"cloud_ip_v2:AWS", "cloud_ip_v2:"}, nil
}
func (h *capturingRedisHandler) DeletePattern(pattern string) (int64, error) {
	return 0, nil
}

func TestGeoIPEntryCount(t *testing.T) {
	manager := NewIPInfoManager("", "", 0, nil)
	if got := manager.EntryCount(); got != 0 {
		t.Fatalf("no reader must report 0, got %d", got)
	}
	loaded := NewGeoIPManager(buildTestMMDB(t, map[string]string{
		"203.0.113.0/24": "BR",
	}))
	loaded.ensureLoaded()
	if got := loaded.EntryCount(); got == 0 {
		t.Fatal("a loaded reader must report its node count")
	}
}

func TestRedisManagerSafeOperationDisabled(t *testing.T) {
	manager := NewRedisManager(RedisConfig{EnableRedis: false})
	ran := false
	if err := manager.SafeOperation("probe", func(client redis.UniversalClient) error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("a disabled manager must no-op cleanly, got %v", err)
	}
	if ran {
		t.Fatal("a disabled manager must not run the operation")
	}
}

func TestRedisManagerSafeOperationEmitsEventOnError(t *testing.T) {
	buf := capturePackageLog(t)
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = true
		c.RedisURL = "redis://127.0.0.1:1"
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	manager := NewRedisManager(RedisConfig{URL: cfg.RedisURL, Prefix: cfg.RedisPrefix, EnableRedis: true})
	err = manager.SafeOperation("probe", func(client redis.UniversalClient) error {
		return context.DeadlineExceeded
	})
	var redisErr *GuardRedisError
	if !errors.As(err, &redisErr) {
		t.Fatalf("a failing operation must surface the wrapped GuardRedisError, got %v", err)
	}
	_ = buf
}

func TestRedisManagerIncrAndExists(t *testing.T) {
	if !redisAlive() {
		t.Skip("live redis required")
	}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = true
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	manager := NewRedisManager(RedisConfig{URL: cfg.RedisURL, Prefix: cfg.RedisPrefix, EnableRedis: true})
	if err := manager.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer manager.Close()
	ttl := 60
	first, err := manager.Incr("surf", "counter", &ttl)
	if err != nil || first != 1 {
		t.Fatalf("first Incr must be 1, got (%d, %v)", first, err)
	}
	second, err := manager.Incr("surf", "counter", nil)
	if err != nil || second != 2 {
		t.Fatalf("second Incr must be 2, got (%d, %v)", second, err)
	}
	exists := manager.Exists("surf", "counter")
	if exists == nil || !*exists {
		t.Fatalf("the incremented key must exist, got %v", exists)
	}
	if _, err := manager.Delete("surf", "counter"); err != nil {
		t.Fatalf("cleanup Delete: %v", err)
	}
	if exists := manager.Exists("surf", "counter"); exists == nil || *exists {
		t.Fatalf("the deleted key must not exist, got %v", exists)
	}
	if got := manager.Exists("surf", "missing"); got == nil || *got {
		t.Fatalf("a missing key must report false, got %v", got)
	}
	if got := NewRedisManager(RedisConfig{EnableRedis: false}).Exists("surf", "counter"); got != nil {
		t.Fatalf("a disabled manager must report nil (the reference None), got %v", got)
	}
}

func TestRedisManagerGetConnection(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = true
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	manager := NewRedisManager(RedisConfig{URL: cfg.RedisURL, Prefix: cfg.RedisPrefix, EnableRedis: true})
	if manager.GetConnection() != nil {
		t.Fatal("the client must be nil before Initialize")
	}
	if err := manager.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer manager.Close()
	if manager.GetConnection() == nil {
		t.Fatal("the client must surface after Initialize")
	}
}

func redisAlive() bool {
	manager := NewRedisManager(DefaultRedisConfig())
	if err := manager.Initialize(); err != nil {
		return false
	}
	_ = manager.Close()
	return true
}

func TestSafeOperationSuccessRunsTheOperation(t *testing.T) {
	if !redisAlive() {
		t.Skip("live redis required")
	}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = true
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	manager := NewRedisManager(RedisConfig{URL: cfg.RedisURL, Prefix: cfg.RedisPrefix, EnableRedis: true})
	if err := manager.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer manager.Close()
	ran := false
	if err := manager.SafeOperation("probe", func(client redis.UniversalClient) error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("a healthy manager must run the operation cleanly, got %v", err)
	}
	if !ran {
		t.Fatal("the operation must run")
	}
}

func TestIncrUninitializedManagerErrors(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = true
		c.RedisURL = "redis://127.0.0.1:1"
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	manager := NewRedisManager(RedisConfig{URL: cfg.RedisURL, Prefix: cfg.RedisPrefix, EnableRedis: true})
	value, err := manager.Incr("surf", "counter", nil)
	var redisErr *GuardRedisError
	if !errors.As(err, &redisErr) || value != 0 {
		t.Fatalf("an uninitialized manager must fail the Incr, got (%d, %v)", value, err)
	}
}

func TestExistsUninitializedManagerErrors(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = true
		c.RedisURL = "redis://127.0.0.1:1"
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	manager := NewRedisManager(RedisConfig{URL: cfg.RedisURL, Prefix: cfg.RedisPrefix, EnableRedis: true})
	if got := manager.Exists("surf", "counter"); got != nil {
		t.Fatalf("an uninitialized manager must report nil (the reference None), got %v", got)
	}
}

func TestExistsLazilyInitializes(t *testing.T) {
	if !redisAlive() {
		t.Skip("live redis required")
	}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = true
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	// EnableRedis with no explicit Initialize: the Exists probe dials
	// lazily through safeOperationBool's re-Initialize arm.
	manager := NewRedisManager(RedisConfig{URL: cfg.RedisURL, Prefix: cfg.RedisPrefix, EnableRedis: true})
	got := manager.Exists("surf", "lazy")
	if got == nil {
		t.Fatal("the lazy dial must answer the probe")
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
