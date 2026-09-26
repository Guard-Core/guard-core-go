package guardcore

// Tests for the IPInfo download/refresh/Redis-cache lifecycle and the geo
// event surface, ported from the reference IPInfoManager
// (guard_core/handlers/ipinfo_handler.py). The MMDB fixtures reuse the
// in-test builder from geoip_test.go; the download endpoint is overridden
// with an httptest server through the manager's test seam.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newTestIPInfoConfig builds an engine config with country rules resolved
// through a token-lifecycle GeoIPManager whose download endpoint is the
// given test server and whose retry backoff does not sleep.
func newTestIPInfoConfig(t *testing.T, dbPath, token string, mutate func(cfg *SecurityConfig, mgr *GeoIPManager)) (*SecurityConfig, *GeoIPManager) {
	t.Helper()
	var mgr *GeoIPManager
	cfg, err := NewSecurityConfig(func(cfg *SecurityConfig) {
		cfg.IPInfoToken = token
		cfg.GeoIPDBPath = dbPath
		cfg.BlockedCountries = []string{"US"}
		mgr = NewIPInfoManager(token, dbPath, DefaultIPInfoMaxAge, cfg)
		mgr.sleep = func(time.Duration) {}
		cfg.GeoIPHandler = mgr
		if mutate != nil {
			mutate(cfg, mgr)
		}
	})
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	return cfg, mgr
}

func servingMMDBServer(t *testing.T, tsv *testServerContents) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing bearer auth on download: %q", got)
		}
		content := tsv.current()
		if content == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type testServerContents struct {
	mu      sync.Mutex
	content []byte
}

func (s *testServerContents) current() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.content
}

func (s *testServerContents) set(content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.content = content
}

func collectGeoEvents() (func(GeoEvent), func() []GeoEvent) {
	var mu sync.Mutex
	var events []GeoEvent
	return func(ev GeoEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		}, func() []GeoEvent {
			mu.Lock()
			defer mu.Unlock()
			return append([]GeoEvent(nil), events...)
		}
}

func TestIPInfoLifecycleDownloadsAndServesCountry(t *testing.T) {
	contents := &testServerContents{}
	contents.set(mmdbBytesForTest(t, map[string]string{"203.0.113.0/24": "US"}))
	srv := servingMMDBServer(t, contents)
	dbPath := filepath.Join(t.TempDir(), "nested", "country_asn.mmdb")
	record, collect := collectGeoEvents()
	cfg, mgr := newTestIPInfoConfig(t, dbPath, "test-token", func(cfg *SecurityConfig, m *GeoIPManager) {
		m.dataURL = srv.URL
		cfg.OnGeoEvent = record
		cfg.EnableRedis = false
	})

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// The downloaded database landed at the configured (nested) path.
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("downloaded database missing: %v", err)
	}
	status := mgr.GetStatus()
	if ready, _ := status["ready"].(bool); !ready {
		t.Fatalf("manager not ready after initialize: %+v", status)
	}
	if fmt.Sprint(status["entries"]) == "0" {
		t.Fatalf("expected non-zero entry count, got %+v", status)
	}

	// The country_blocked / decorator_violation events are emitted from the
	// route-decorator country stage (the reference IPInfoManager
	// .check_country_access hop), so the denial is driven through a route.
	engine.Routes.Register("geo-route", func(rc *RouteConfig) {
		rc.BlockedCountries = []string{"US"}
	})
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.113.9"
		state.GuardRouteID = "geo-route"
	})
	resp := engine.Check(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != RestrictionBlockedMsg {
		t.Fatalf("expected 403 Forbidden from country block, got %+v", resp)
	}
	events := collect()
	var countryBlocked, decoratorViolation bool
	for _, ev := range events {
		switch ev.EventType {
		case EventCountryBlocked:
			countryBlocked = true
			if ev.IPAddress != "203.0.113.9" || ev.Country != "US" || ev.ActionTaken != "request_blocked" ||
				ev.Reason != "Country US is blocked" || ev.RuleType != "country_blacklist" ||
				ev.HandlerName != ipinfoHandlerName {
				t.Fatalf("unexpected country_blocked event: %+v", ev)
			}
		case EventDecoratorViolation:
			decoratorViolation = true
			if ev.Reason != "IP 203.0.113.9 blocked" || ev.IPAddress != "203.0.113.9" {
				t.Fatalf("unexpected decorator_violation event: %+v", ev)
			}
			if ev.Metadata["decorator_type"] != "block_countries" || ev.Metadata["violation_type"] != "country_restriction" {
				t.Fatalf("unexpected decorator classification: %+v", ev.Metadata)
			}
		}
	}
	if !countryBlocked || !decoratorViolation {
		t.Fatalf("missing events (country_blocked=%v decorator_violation=%v): %+v", countryBlocked, decoratorViolation, events)
	}

	// A non-blocked-country IP passes and emits nothing.
	passed := engine.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "198.51.100.7"
		state.GuardRouteID = "geo-route"
	}))
	if passed != nil {
		t.Fatalf("expected pass-through, got %+v", passed)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestIPInfoLifecycleDownloadFailureKeepsExistingReader(t *testing.T) {
	contents := &testServerContents{content: nil} // always 500
	srv := servingMMDBServer(t, contents)
	dbPath := filepath.Join(t.TempDir(), "country_asn.mmdb")
	// A pre-existing good database stays in place when the download fails.
	goodDB := mmdbBytesForTest(t, map[string]string{"203.0.113.0/24": "US"})
	if err := os.WriteFile(dbPath, goodDB, 0o644); err != nil {
		t.Fatal(err)
	}
	// Age the file past the max age so the download path runs.
	stale := time.Now().Add(-time.Duration(DefaultIPInfoMaxAge+60) * time.Second)
	if err := os.Chtimes(dbPath, stale, stale); err != nil {
		t.Fatal(err)
	}
	record, collect := collectGeoEvents()
	cfg, mgr := newTestIPInfoConfig(t, dbPath, "test-token", func(cfg *SecurityConfig, m *GeoIPManager) {
		m.dataURL = srv.URL
		cfg.OnGeoEvent = record
		cfg.EnableRedis = false
	})
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// The failed download is soft: like the reference, the reader stays
	// whatever it was (none, on a cold start) and lookups miss instead of
	// raising; the error line and event still report the failure.
	if _, ok := mgr.GetCountry("203.0.113.9"); ok {
		t.Fatal("expected a lookup miss after a failed initialization")
	}
	var sawDownloadFailed bool
	for _, ev := range collect() {
		if ev.EventType == EventGeoLookupFailed && ev.ActionTaken == "database_download_failed" {
			sawDownloadFailed = true
			if ev.IPAddress != "system" ||
				ev.Reason != "Failed to download IPInfo database: HTTPError (HTTP 500)" ||
				ev.HandlerName != ipinfoHandlerName {
				t.Fatalf("unexpected geo_lookup_failed event: %+v", ev)
			}
		}
	}
	if !sawDownloadFailed {
		t.Fatalf("expected geo_lookup_failed database_download_failed event, got %+v", collect())
	}

	// Recovery: once the server serves again, Refresh swaps a working
	// reader in.
	contents.set(goodDB)
	mgr.RefreshGeo()
	if country, ok := mgr.GetCountry("203.0.113.9"); !ok || country != "US" {
		t.Fatalf("reader did not recover on refresh: %q %v", country, ok)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestIPInfoRefreshSwapsReaderAndFailsSoft(t *testing.T) {
	contents := &testServerContents{}
	contents.set(mmdbBytesForTest(t, map[string]string{"203.0.113.0/24": "US"}))
	srv := servingMMDBServer(t, contents)
	dbPath := filepath.Join(t.TempDir(), "country_asn.mmdb")
	_, mgr := newTestIPInfoConfig(t, dbPath, "test-token", func(cfg *SecurityConfig, m *GeoIPManager) {
		m.dataURL = srv.URL
	})

	mgr.Initialize()
	if country, ok := mgr.GetCountry("203.0.113.9"); !ok || country != "US" {
		t.Fatalf("initial database mismatch: %q %v", country, ok)
	}
	firstRefreshed := mgr.GetStatus()["last_refreshed"].(time.Time)

	// A successful refresh swaps the reader over to the new content.
	contents.set(mmdbBytesForTest(t, map[string]string{"203.0.113.0/24": "CA"}))
	mgr.RefreshGeo()
	if country, ok := mgr.GetCountry("203.0.113.9"); !ok || country != "CA" {
		t.Fatalf("refresh did not swap the reader: %q %v", country, ok)
	}
	if second := mgr.GetStatus()["last_refreshed"].(time.Time); !second.After(firstRefreshed) {
		t.Fatalf("last_refreshed not advanced on refresh: %v -> %v", firstRefreshed, second)
	}

	// A failed refresh keeps the current reader (reference fail-soft).
	contents.set(nil)
	mgr.RefreshGeo()
	if country, ok := mgr.GetCountry("203.0.113.9"); !ok || country != "CA" {
		t.Fatalf("failed refresh clobbered the reader: %q %v", country, ok)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestIPInfoMaxAgeStalenessControlsDownload(t *testing.T) {
	contents := &testServerContents{}
	contents.set(mmdbBytesForTest(t, map[string]string{"203.0.113.0/24": "US"}))
	var downloads int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads++
		_, _ = w.Write(contents.current())
	}))
	t.Cleanup(srv.Close)
	dbPath := filepath.Join(t.TempDir(), "country_asn.mmdb")
	_, mgr := newTestIPInfoConfig(t, dbPath, "test-token", func(cfg *SecurityConfig, m *GeoIPManager) {
		m.dataURL = srv.URL
	})

	mgr.Initialize()
	if downloads != 1 {
		t.Fatalf("expected one download on a missing database, got %d", downloads)
	}

	// A fresh database is not re-downloaded.
	mgr.Initialize()
	if downloads != 1 {
		t.Fatalf("fresh database re-downloaded: %d downloads", downloads)
	}

	// A database older than the max age is refreshed.
	stale := time.Now().Add(-time.Duration(DefaultIPInfoMaxAge+60) * time.Second)
	if err := os.Chtimes(dbPath, stale, stale); err != nil {
		t.Fatal(err)
	}
	mgr.Initialize()
	if downloads != 2 {
		t.Fatalf("stale database not re-downloaded: %d downloads", downloads)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestIPInfoTokenConfigurationValidation(t *testing.T) {
	// max_age without a token fails construction (the reference
	// IPInfoManager raises ValueError on an empty token).
	if _, err := NewSecurityConfig(func(cfg *SecurityConfig) {
		cfg.IPInfoMaxAge = 3600
	}); err == nil {
		t.Fatal("expected ipinfo_max_age without token to fail config construction")
	}
	// A negative max_age fails construction.
	if _, err := NewSecurityConfig(func(cfg *SecurityConfig) {
		cfg.IPInfoToken = "tok"
		cfg.IPInfoMaxAge = -1
	}); err == nil {
		t.Fatal("expected negative ipinfo_max_age to fail config construction")
	}
	// A token with the default max age is valid and the manager is built
	// with the reference default database path when none is set.
	cfg, err := NewSecurityConfig(func(cfg *SecurityConfig) {
		cfg.IPInfoToken = "tok"
		cfg.BlockedCountries = []string{"US"}
	})
	if err != nil {
		t.Fatalf("token config rejected: %v", err)
	}
	mgr, ok := cfg.GeoIPHandler.(*GeoIPManager)
	if !ok {
		t.Fatalf("expected built-in GeoIPManager, got %T", cfg.GeoIPHandler)
	}
	if mgr.MaxAge != DefaultIPInfoMaxAge {
		t.Fatalf("max age default not applied: %d", mgr.MaxAge)
	}
	if mgr.DBPath != DefaultIPInfoDBPath {
		t.Fatalf("default db path not applied: %q", mgr.DBPath)
	}
}

func TestIPInfoLocalOnlyModeStillValid(t *testing.T) {
	// No token: a GeoIPDBPath alone keeps the PR #23 local-file contract and
	// no lifecycle runs at engine startup.
	dbPath := filepath.Join(t.TempDir(), "country_asn.mmdb")
	if err := os.WriteFile(dbPath, mmdbBytesForTest(t, map[string]string{"203.0.113.0/24": "US"}), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := NewSecurityConfig(func(cfg *SecurityConfig) {
		cfg.GeoIPDBPath = dbPath
		cfg.BlockedCountries = []string{"US"}
	})
	if err != nil {
		t.Fatalf("local-only config rejected: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if resp := engine.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.113.9"
	})); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("expected local database to serve the country verdict, got %+v", resp)
	}
}

// mmdbBytesForTest wraps buildTestMMDB with a plain-bytes signature so the
// lifecycle tests can serve the fixture over HTTP.
func mmdbBytesForTest(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	path := buildTestMMDB(t, entries)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read MMDB fixture: %v", err)
	}
	return content
}
