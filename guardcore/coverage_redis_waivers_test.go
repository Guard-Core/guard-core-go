package guardcore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

// A RateLimitRedis client that answers NOSCRIPT for the cached-SHA path and
// then refuses the reload, so redisRequestCount takes the load-failure arm.
type noscriptThenLoadFailsClient struct {
	scriptLoadErr error
}

func (c *noscriptThenLoadFailsClient) ScriptLoad(string) (string, error) {
	return "", c.scriptLoadErr
}

func (c *noscriptThenLoadFailsClient) EvalSha(string, string, float64, int, int) (int64, error) {
	return 0, errors.New("NOSCRIPT no matching script. Please use EVAL")
}

func (c *noscriptThenLoadFailsClient) PipelineRateLimit(string, string, float64, float64, int) (int64, error) {
	return 0, nil
}

func TestRedisRequestCountNoscriptReloadFailureIsFailOpen(t *testing.T) {
	m := NewRateLimitManager(RateLimitConfig{RateLimit: 5, RateLimitWindow: 60, RedisFailOpen: true}, nil, nil)
	m.rlRedis = &noscriptThenLoadFailsClient{scriptLoadErr: errors.New("load exploded")}
	m.redis = newFakeRedisHandler()
	// Pre-seed the cached SHA so the EvalSha branch (not the pipeline
	// fallback) runs, which is where the NOSCRIPT reload arm lives.
	m.scriptSHA = "cached-sha"

	count, limited, err := m.redisRequestCount("1.2.3.4", 1000, 940, 60, 5, "/x", false)
	if err != nil {
		t.Fatalf("load failure must not surface as an error: %v", err)
	}
	if limited {
		t.Fatal("a failed reload must not limit")
	}
	if count != 0 {
		t.Fatalf("a failed reload must report zero count, got %d", count)
	}
	if m.scriptSHA != "cached-sha" {
		t.Fatal("a failed reload must not update the cached SHA")
	}
}

// A UniversalClient fake whose Keys succeeds and whose Del fails, so
// DeletePattern takes the delete-error arm after a successful scan.
type keysOkDelFailsClient struct {
	redis.UniversalClient
}

func (c *keysOkDelFailsClient) Keys(context.Context, string) *redis.StringSliceCmd {
	cmd := redis.NewStringSliceCmd(context.Background())
	cmd.SetVal([]string{"guard_core:agent:a", "guard_core:agent:b"})
	return cmd
}

func (c *keysOkDelFailsClient) Del(context.Context, ...string) *redis.IntCmd {
	cmd := redis.NewIntCmd(context.Background())
	cmd.SetErr(errors.New("del exploded"))
	return cmd
}

func TestDeletePatternSurfacesDeleteErrors(t *testing.T) {
	m := NewRedisManager(RedisConfig{Prefix: "guard_core:", EnableRedis: true})
	m.client = &keysOkDelFailsClient{}

	deleted, err := m.DeletePattern("agent:*")
	if err == nil {
		t.Fatal("a failing Del must surface its error")
	}
	if deleted != 0 {
		t.Fatalf("a failing Del deletes nothing, got %d", deleted)
	}
	if !strings.Contains(err.Error(), "Redis operation failed") {
		t.Fatalf("unexpected wrapped error: %v", err)
	}
}
