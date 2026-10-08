package guardcore

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// The manager surface exports, closing the reference surface rows the
// original port deliberately skipped: the cloud stores' clear, the geo
// manager's entry_count, and the redis manager's get_connection /
// safe_operation / incr / exists (guard_core/handlers/cloud_ip_stores.py,
// ipinfo_handler.py entry_count, redis_handler.py).

// Clear drops every provider entry from the in-memory store, mirroring the
// reference InMemoryCloudIpStore.clear.
func (s *InMemoryCloudIPStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[string][]string{}
	s.expiresAt = map[string]time.Time{}
}

// Clear drops every stored provider key, mirroring the reference
// RedisCloudIpStore.clear: the prefix-scoped keys are listed and each
// provider entry deleted.
func (s *RedisCloudIPStore) Clear() error {
	keys, err := s.redis.Keys(s.prefix + ":*")
	if err != nil {
		return err
	}
	for _, key := range keys {
		provider := key[len(s.prefix)+1:]
		if provider == "" {
			continue
		}
		if _, err := s.redis.Delete(s.prefix, provider); err != nil {
			return err
		}
	}
	return nil
}

// EntryCount returns the node count of the loaded MMDB reader, mirroring
// the reference entry_count; 0 without a reader.
func (m *GeoIPManager) EntryCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.reader == nil {
		return 0
	}
	return int(m.reader.Metadata.NodeCount)
}

// GetConnection exposes the underlying go-redis client (the reference
// get_connection hands the pooled connection to adapter callbacks); nil
// until a connection is established. The manager owns the client's
// lifecycle - Close shuts it down.
func (m *RedisManager) GetConnection() redis.UniversalClient {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.client
}

// SafeOperation runs op inside the manager's error containment, mirroring
// the reference safe_operation: a disabled manager yields nil without
// running; a failing operation emits the redis_error event
// (safe_operation_failed with the function name) and returns the wrapped
// GuardRedisError.
func (m *RedisManager) SafeOperation(functionName string, op func(client redis.UniversalClient) error) error {
	if !m.cfg.EnableRedis {
		return nil
	}
	if err := m.safeOperation(op); err != nil {
		m.emitRedisEvent(EventRedisError, "safe_operation_failed",
			"Redis safe operation failed",
			map[string]any{"error_type": "safe_operation_error", "function_name": functionName})
		return err
	}
	return nil
}

// Incr increments the namespaced key and returns the post-increment value
// (the reference incr; ttlSeconds sets the expiry on a fresh key).
func (m *RedisManager) Incr(namespace, key string, ttlSeconds *int) (int64, error) {
	m.mu.Lock()
	client := m.client
	m.mu.Unlock()
	if client == nil {
		return 0, newGuardRedisError("Redis operation failed")
	}
	fullKey := m.cfg.Prefix + namespace + ":" + key
	value, err := client.Incr(context.Background(), fullKey).Result()
	if err != nil {
		return 0, newGuardRedisError("Redis operation failed")
	}
	if ttlSeconds != nil && value == 1 {
		client.Expire(context.Background(), fullKey, time.Duration(*ttlSeconds)*time.Second)
	}
	return value, nil
}

// Exists reports the namespaced key's presence (the reference exists); nil
// when redis is disabled (the reference's None).
func (m *RedisManager) Exists(namespace, key string) *bool {
	if !m.cfg.EnableRedis {
		return nil
	}
	exists, err := m.safeOperationBool(func(client redis.UniversalClient) (bool, error) {
		count, err := client.Exists(context.Background(), m.cfg.Prefix+namespace+":"+key).Result()
		return count > 0, err
	})
	if err != nil {
		return nil
	}
	return &exists
}

// safeOperationBool is Exists' boolean flavor of the containment: a
// redis.Nil-style miss reports false instead of an error, any other
// failure wraps like safeOperation.
func (m *RedisManager) safeOperationBool(op func(client redis.UniversalClient) (bool, error)) (bool, error) {
	m.mu.Lock()
	client := m.client
	m.mu.Unlock()
	if client == nil {
		if err := m.Initialize(); err != nil {
			return false, err
		}
		m.mu.Lock()
		client = m.client
		m.mu.Unlock()
	}
	ok, err := op(client)
	if err != nil {
		return false, newGuardRedisError("Redis operation failed")
	}
	return ok, nil
}
