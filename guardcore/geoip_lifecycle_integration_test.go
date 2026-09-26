//go:build integration

package guardcore

// Redis-backed pieces of the IPInfo lifecycle (the ("ipinfo","database")
// cache copy and its max-age TTL), mirroring the reference
// IPInfoManager.initialize / _download_database Redis handling.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIntegrationIPInfoRedisCacheCopy(t *testing.T) {
	redisMgr := newIntegrationRedis(t)
	content := mmdbBytesForTest(t, map[string]string{"203.0.113.0/24": "US"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)

	dbPath := t.TempDir() + "/country_asn.mmdb"
	newManager := func(dataURL string) *GeoIPManager {
		mgr := &GeoIPManager{
			DBPath:  dbPath,
			Token:   "test-token",
			MaxAge:  3600,
			Redis:   redisMgr,
			dataURL: dataURL,
			sleep:   func(time.Duration) {},
		}
		return mgr
	}

	first := newManager(srv.URL)
	first.Initialize()
	if country, ok := first.GetCountry("203.0.113.9"); !ok || country != "US" {
		t.Fatalf("downloaded database did not resolve: %q %v", country, ok)
	}
	cached, err := redisMgr.GetKey("ipinfo", "database")
	if err != nil || cached == "" {
		t.Fatalf("database not cached in Redis: err=%v len=%d", err, len(cached))
	}
	ttl, err := redisMgr.PTTL(redisMgr.Prefix() + "ipinfo:database")
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 || ttl > time.Hour {
		t.Fatalf("cache TTL not bounded by the max age: %v", ttl)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// A sibling worker with an unreachable download endpoint boots from the
	// Redis copy (the reference initialize preferring the cached database).
	second := newManager("http://127.0.0.1:1/unreachable")
	second.Initialize()
	if country, ok := second.GetCountry("203.0.113.9"); !ok || country != "US" {
		t.Fatalf("Redis cache copy did not serve the database: %q %v", country, ok)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
