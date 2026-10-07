package guardcore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisConnectTimeout = 2 * time.Second
	redisSocketTimeout  = 2 * time.Second
	redisDialKeepAlive  = 30 * time.Second
)

type GuardRedisError struct {
	StatusCode int
	Message    string
}

func (e *GuardRedisError) Error() string {
	return fmt.Sprintf("guardredis error %d: %s", e.StatusCode, e.Message)
}

func newGuardRedisError(message string) *GuardRedisError {
	return &GuardRedisError{StatusCode: 503, Message: message}
}

type RedisConfig struct {
	URL         string
	Prefix      string
	EnableRedis bool
}

func DefaultRedisConfig() RedisConfig {
	return RedisConfig{URL: "redis://localhost:6379", Prefix: "guard_core:", EnableRedis: true}
}

type RedisHandler interface {
	Prefix() string
	Enabled() bool
	Initialize() error
	Close() error
	GetKey(namespace, key string) (string, error)
	SetKey(namespace, key, value string, ttlSeconds *int) error
	Delete(namespace, key string) (int64, error)
	Keys(pattern string) ([]string, error)
	DeletePattern(pattern string) (int64, error)
}

type RedisAdmin interface {
	ScanMatch(pattern string) ([]string, error)
	PTTL(key string) (time.Duration, error)
	SetPX(key, value string, ttl time.Duration) error
	DeleteKeys(keys ...string) (int64, error)
}

type RedisManager struct {
	cfg    RedisConfig
	client redis.UniversalClient
	ctx    context.Context

	// mu guards agent (and lazily created clients); the reference manager
	// serializes connects through _connection_lock.
	mu    sync.Mutex
	agent AgentHandler
}

func NewRedisManager(cfg RedisConfig) *RedisManager {
	if cfg.Prefix == "" {
		cfg.Prefix = "guard_core:"
	}
	return &RedisManager{cfg: cfg, ctx: context.Background()}
}

func (m *RedisManager) Prefix() string { return m.cfg.Prefix }

func (m *RedisManager) Enabled() bool { return m.cfg.EnableRedis }

// connected reports whether Initialize has established the client
// connection (a configured-but-never-connected manager reports Enabled
// true and connected false). Initialize owns the write; callers run the
// guard after startup, so no lock is taken here.
func (m *RedisManager) connected() bool {
	return m.client != nil
}

func (m *RedisManager) Initialize() error {
	if !m.cfg.EnableRedis {
		return nil
	}
	opts, err := redis.ParseURL(m.cfg.URL)
	if err != nil {
		m.emitRedisEvent(EventRedisError, "connection_failed",
			fmt.Sprintf("Redis connection failed: %v", err),
			map[string]any{"redis_url": redactRedisURL(m.cfg.URL), "error_type": "connection_error"})
		return newGuardRedisError("Redis connection failed")
	}
	opts.DialTimeout = redisConnectTimeout
	opts.ReadTimeout = redisSocketTimeout
	opts.WriteTimeout = redisSocketTimeout
	opts.ConnMaxIdleTime = 5 * time.Minute
	client := redis.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(m.ctx, redisConnectTimeout+redisSocketTimeout)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		m.emitRedisEvent(EventRedisError, "connection_failed",
			fmt.Sprintf("Redis connection failed: %v", err),
			map[string]any{"redis_url": redactRedisURL(m.cfg.URL), "error_type": "connection_error"})
		return newGuardRedisError("Redis connection failed")
	}
	m.client = client
	m.emitRedisEvent(EventRedisConnection, "connection_established",
		"Redis connection successfully established",
		map[string]any{"redis_url": redactRedisURL(m.cfg.URL)})
	return nil
}

// SetAgentHandler attaches the agent handler the connection events ride
// (the reference initialize_agent); without one the emissions are no-ops.
func (m *RedisManager) SetAgentHandler(handler AgentHandler) {
	m.mu.Lock()
	m.agent = handler
	m.mu.Unlock()
}

// emitRedisEvent mirrors _send_redis_event: handler-direct, ip "system",
// handler "redis", kwargs in metadata, send failures logged never raised.
func (m *RedisManager) emitRedisEvent(eventType, actionTaken, reason string, kwargs map[string]any) {
	m.mu.Lock()
	handler := m.agent
	m.mu.Unlock()
	if handler == nil {
		return
	}
	event := SecurityEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   eventType,
		IPAddress:   "system",
		ActionTaken: actionTaken,
		Reason:      reason,
		HandlerName: "redis",
		Metadata:    kwargs,
	}
	if err := handler.SendEvent(event); err != nil {
		log.Printf("Failed to send redis event to agent: %v", err)
	}
}

// redactRedisURL mirrors _redact_redis_url: credentials dropped from the
// netloc, host (bracketed when IPv6), port, path, query and fragment kept.
func redactRedisURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		if i := strings.Index(rawURL, "://"); i > 0 {
			return rawURL[:i+3] + "<unparseable>"
		}
		return "<unparseable>"
	}
	if parsed.Host == "" {
		return rawURL
	}
	host := parsed.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if parsed.Port() != "" {
		host += ":" + parsed.Port()
	}
	redacted := &url.URL{Scheme: parsed.Scheme, Host: host, Path: parsed.Path, RawQuery: parsed.RawQuery, Fragment: parsed.Fragment}
	return redacted.String()
}

func (m *RedisManager) Close() error {
	if m.client == nil {
		return nil
	}
	err := m.client.Close()
	m.client = nil
	return err
}

func (m *RedisManager) fullKey(namespace, key string) string {
	return m.cfg.Prefix + namespace + ":" + key
}

func (m *RedisManager) safeOperation(op func(client redis.UniversalClient) error) error {
	if !m.cfg.EnableRedis {
		return nil
	}
	if m.client == nil {
		if err := m.Initialize(); err != nil {
			return err
		}
	}
	if err := op(m.client); err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return newGuardRedisError("Redis operation failed")
	}
	return nil
}

func (m *RedisManager) GetKey(namespace, key string) (string, error) {
	if !m.cfg.EnableRedis {
		return "", nil
	}
	var value string
	err := m.safeOperation(func(client redis.UniversalClient) error {
		var err error
		value, err = client.Get(m.ctx, m.fullKey(namespace, key)).Result()
		return err
	})
	if err != nil {
		return "", err
	}
	return value, nil
}

func (m *RedisManager) SetKey(namespace, key, value string, ttlSeconds *int) error {
	return m.safeOperation(func(client redis.UniversalClient) error {
		fullKey := m.fullKey(namespace, key)
		if ttlSeconds != nil && *ttlSeconds > 0 {
			return client.Set(m.ctx, fullKey, value, time.Duration(*ttlSeconds)*time.Second).Err()
		}
		return client.Set(m.ctx, fullKey, value, 0).Err()
	})
}

func (m *RedisManager) Delete(namespace, key string) (int64, error) {
	var deleted int64
	err := m.safeOperation(func(client redis.UniversalClient) error {
		var err error
		deleted, err = client.Del(m.ctx, m.fullKey(namespace, key)).Result()
		return err
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func (m *RedisManager) Keys(pattern string) ([]string, error) {
	var keys []string
	err := m.safeOperation(func(client redis.UniversalClient) error {
		var err error
		keys, err = client.Keys(m.ctx, m.cfg.Prefix+pattern).Result()
		return err
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (m *RedisManager) DeletePattern(pattern string) (int64, error) {
	keys, err := m.Keys(pattern)
	if err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, nil
	}
	var deleted int64
	err = m.safeOperation(func(client redis.UniversalClient) error {
		var err error
		deleted, err = client.Del(m.ctx, keys...).Result()
		return err
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func (m *RedisManager) ScanMatch(pattern string) ([]string, error) {
	var keys []string
	err := m.safeOperation(func(client redis.UniversalClient) error {
		var iterErr error
		var cursor uint64
		for {
			var batch []string
			batch, cursor, iterErr = client.Scan(m.ctx, cursor, pattern, 100).Result()
			if iterErr != nil {
				return iterErr
			}
			keys = append(keys, batch...)
			if cursor == 0 {
				return nil
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (m *RedisManager) PTTL(key string) (time.Duration, error) {
	var ttl time.Duration
	err := m.safeOperation(func(client redis.UniversalClient) error {
		var err error
		ttl, err = client.PTTL(m.ctx, key).Result()
		return err
	})
	if err != nil {
		return 0, err
	}
	return ttl, nil
}

func (m *RedisManager) SetPX(key, value string, ttl time.Duration) error {
	return m.safeOperation(func(client redis.UniversalClient) error {
		return client.Set(m.ctx, key, value, ttl).Err()
	})
}

func (m *RedisManager) DeleteKeys(keys ...string) (int64, error) {
	var deleted int64
	err := m.safeOperation(func(client redis.UniversalClient) error {
		var err error
		deleted, err = client.Del(m.ctx, keys...).Result()
		return err
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// RecordSlidingWindowHit mirrors
// redis_handler.record_sliding_window_hit: one ZADD with a random member,
// prune entries strictly older than window_start (exclusive lower bound,
// like Python's "(window_start"), then return the ZCARD. The full key
// layout is prefix + namespace + ":" + key, matching the Python handler's
// composition so the two engines share keys.
func (m *RedisManager) RecordSlidingWindowHit(namespace, key string, now, windowStart float64, window int) (int64, error) {
	client, err := m.ensureRateLimitClient()
	if err != nil {
		return 0, err
	}
	fullKey := m.fullKey(namespace, key)
	member := make([]byte, 16)
	if _, err := rand.Read(member); err != nil {
		return 0, err
	}
	pipe := client.TxPipeline()
	pipe.ZAdd(m.ctx, fullKey, redis.Z{Score: now, Member: hex.EncodeToString(member)})
	pipe.ZRemRangeByScore(m.ctx, fullKey, "-inf", "("+formatExpiry(windowStart))
	card := pipe.ZCard(m.ctx, fullKey)
	pipe.Expire(m.ctx, fullKey, time.Duration(window)*time.Second)
	if _, err := pipe.Exec(m.ctx); err != nil {
		return 0, err
	}
	return card.Val(), nil
}
