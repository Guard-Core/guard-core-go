package guardcore

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// Lifecycle defaults and names mirrored from
// guard_core/handlers/ipinfo_handler.py.
const (
	// DefaultIPInfoDBPath is the reference default db_path
	// ("data/ipinfo/country_asn.mmdb").
	DefaultIPInfoDBPath = "data/ipinfo/country_asn.mmdb"
	// DefaultIPInfoMaxAge is the reference default max_age: one day.
	DefaultIPInfoMaxAge = 86400
	// ipinfoHandlerName is the reference _IPINFO_HANDLER_NAME stamped on
	// every geo event.
	ipinfoHandlerName = "ipinfo"
	// ipinfoDataURL is the reference _download_database endpoint: the free
	// country_asn database.
	ipinfoDataURL = "https://ipinfo.io/data/free/country_asn.mmdb"
)

// parentDir returns the directory part of path ("" when there is none).
func parentDir(path string) string {
	return filepath.Dir(path)
}

// GeoEvent is the observable geo-lifecycle event surface, the Go stand-in for
// the reference's SecurityEvent records sent through the event bus from
// IPInfoManager._send_geo_event (guard_core/handlers/ipinfo_handler.py) and
// the decorator_violation access-denied event of the ip_security check. The
// fields mirror the reference event names and payload keys: event_type
// (country_blocked / geo_lookup_failed / decorator_violation), ip_address,
// action_taken, reason, country, rule_type, handler_name ("ipinfo") and the
// free-form metadata carried as event kwargs.
type GeoEvent struct {
	EventType   string
	IPAddress   string
	ActionTaken string
	Reason      string
	Country     string
	RuleType    string
	HandlerName string
	Metadata    map[string]any
}

// GeoIP country resolution, ported from the reference IPInfoManager
// (guard_core/handlers/ipinfo_handler.py) and the GeoIPHandler protocol
// (guard_core/protocols/geo_ip_protocol.py). The country verdict itself
// lives in the ip_security check (pipeline.go), mirroring the reference
// _resolve_country_verdict / check_country_access in
// guard_core/_utils/access_control.py and guard_core/core/checks/helpers.py.

// CountryResolver mirrors the lookup half of the reference GeoIPHandler
// protocol: GetCountry returns the ISO country code for ip, or ok=false when
// the IP can not be resolved. Like the reference get_country it must be
// cheap, run inline per request, and report a miss instead of raising.
type CountryResolver interface {
	GetCountry(ip string) (string, bool)
}

// GeoIPManager is the built-in CountryResolver: a lazily opened MMDB reader
// over GeoIPDBPath, porting the reference IPInfoManager. Without a Token it
// is the local-MMDB-or-injected-resolver contract of PR #23: the engine reads
// a locally provisioned database. With a Token configured it runs the full
// reference lifecycle (Initialize below): the database is downloaded from the
// ipinfo free country_asn endpoint with bearer auth and exponential-backoff
// retries, cached in Redis under ("ipinfo", "database") with the max-age TTL
// so sibling workers skip the download, refreshed when the local file is
// older than the max age, and swapped atomically (temp file + rename, the
// reference _write_database_atomically). A missing or corrupted database is a
// soft failure: every lookup reports a miss, exactly like the reference
// reader returning None after a failed initialization.
type GeoIPManager struct {
	DBPath string
	// Token is the IPInfo token; empty means local-file-only mode (no
	// download, no Redis copy), which stays a valid configuration.
	Token string
	// MaxAge is the database freshness window in seconds (the reference
	// max_age, default 86400): the download runs when the local file's mtime
	// is older, and the Redis cache copy expires with this TTL.
	MaxAge int
	// Redis, when set, serves the cached database copy on Initialize and
	// receives the fresh download (the reference redis_handler).
	Redis *RedisManager

	// cfg carries the OnGeoEvent hook; nil in standalone (test) use.
	cfg *SecurityConfig

	// initOnce runs the lifecycle (token mode) or the plain file open (local
	// mode) exactly once; Initialize/InitializeRedis drive it early at
	// engine startup, the first lookup is the lazy fallback.
	initOnce sync.Once
	// lifecycle state, guarded by mu like the reader.
	mu            sync.RWMutex
	reader        *maxminddb.Reader
	failed        bool
	initialized   bool
	lastRefreshed time.Time

	// test seams: clock, retry backoff sleep, HTTP transport and the
	// download endpoint override.
	now              func() time.Time
	sleep            func(time.Duration)
	customHTTPClient *http.Client
	dataURL          string
}

// GeoIPLifecycle is the optional surface an injected CountryResolver can
// implement to take part in the engine's startup and refresh lifecycle (the
// reference initialize_redis / initialize / refresh trio on GeoIPHandler).
type GeoIPLifecycle interface {
	// InitializeGeo runs the reference initialize_redis semantics: attaching
	// the Redis handler (nil when Redis is disabled) and initializing.
	InitializeGeo(redis *RedisManager)
	// RefreshGeo runs the reference refresh(): re-download and swap the
	// reader, keeping the existing one on failure.
	RefreshGeo()
}

// NewGeoIPManager returns a resolver over the MMDB file at dbPath. The file
// is opened on the first lookup, not here.
func NewGeoIPManager(dbPath string) *GeoIPManager {
	return &GeoIPManager{DBPath: dbPath}
}

// NewIPInfoManager returns a lifecycle-enabled resolver over dbPath (empty
// for the reference default data/ipinfo/country_asn.mmdb) with the reference
// max_age window, mirroring IPInfoManager.__new__ (which raises ValueError on
// an empty token; here an empty token fails config construction before this
// constructor runs).
func NewIPInfoManager(token, dbPath string, maxAge int, cfg *SecurityConfig) *GeoIPManager {
	if dbPath == "" {
		dbPath = DefaultIPInfoDBPath
	}
	return &GeoIPManager{DBPath: dbPath, Token: token, MaxAge: maxAge, cfg: cfg}
}

// mmdbRecord mirrors the record shape the reference get_country reads: a
// top-level "country" string (the ipinfo country_asn.mmdb layout). A
// GeoLite2-style nested country.iso_code decodes to an empty string here and
// resolves as a miss, like the reference reading a top-level key.
type mmdbRecord struct {
	Country string `maxminddb:"country"`
}

// ensureLoaded opens the database once. In token mode the full lifecycle
// (Initialize) runs instead; in local mode a corrupted database is removed
// and reported like the reference _open_database_or_none, and a missing
// database only means lookups miss.
func (m *GeoIPManager) ensureLoaded() {
	m.initOnce.Do(func() {
		if m.Token != "" {
			m.Initialize()
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		m.openLocked()
	})
}

// openLocked opens the database file and applies the reader, the reference
// _open_database_or_none plus _apply_opened_reader: a corrupted database is
// removed with the reference log line, a successful open stamps
// last_refreshed and clears the initialization-failed flag.
func (m *GeoIPManager) openLocked() {
	reader, err := maxminddb.Open(m.DBPath)
	if err != nil {
		if removeErr := os.Remove(m.DBPath); removeErr == nil {
			log.Printf("IPInfo database at %s is corrupted, removing: %v", m.DBPath, err)
		} else {
			log.Printf("IPInfo database at %s is unavailable: %v", m.DBPath, err)
		}
		m.failed = true
		return
	}
	m.reader = reader
	m.failed = false
	m.initialized = true
	m.lastRefreshed = m.nowUTC()
}

func (m *GeoIPManager) nowUTC() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *GeoIPManager) sleepBackoff(d time.Duration) {
	if m.sleep != nil {
		m.sleep(d)
		return
	}
	time.Sleep(d)
}

// emitGeoEvent sends ev through the config's OnGeoEvent hook, the Go
// counterpart of the reference _send_geo_event event-bus hop; without a
// registered hook (or outside engine wiring) it is a no-op.
func (m *GeoIPManager) emitGeoEvent(ev GeoEvent) {
	if m.cfg == nil || m.cfg.OnGeoEvent == nil {
		return
	}
	fireGeoEvent(m.cfg, ev)
}

// Initialize mirrors IPInfoManager.initialize: make sure the parent
// directory exists, prefer the Redis-cached database copy, download when the
// local file is missing or older than the max age, and open whatever ended
// up on disk. A download failure keeps any existing reader, logs the
// reference error line and emits the geo_lookup_failed (system,
// database_download_failed) event, exactly like the reference fail-soft
// initialization path.
func (m *GeoIPManager) Initialize() {
	defer func() {
		m.mu.Lock()
		m.initialized = true
		m.mu.Unlock()
	}()
	if dir := parentDir(m.DBPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("IPInfo database directory %s could not be created: %v", dir, err)
		}
	}
	if m.Redis != nil {
		cached, err := m.Redis.GetKey("ipinfo", "database")
		if err != nil {
			log.Printf("Cached GeoIP database unavailable: %v", err)
		} else if cached != "" {
			if err := m.writeDatabaseAtomically([]byte(cached)); err != nil {
				log.Printf("Cached GeoIP database could not be written: %v", err)
			} else {
				m.mu.Lock()
				m.openLocked()
				m.mu.Unlock()
				return
			}
		}
	}
	if m.dbOutdated() {
		if err := m.downloadDatabase(); err != nil {
			log.Printf("IPInfo database download failed, keeping existing reader: %s", describeDownloadError(err))
			m.emitGeoEvent(GeoEvent{
				EventType:   EventGeoLookupFailed,
				IPAddress:   "system",
				ActionTaken: "database_download_failed",
				Reason:      "Failed to download IPInfo database: " + describeDownloadError(err),
				HandlerName: ipinfoHandlerName,
			})
			return
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(m.DBPath); err == nil {
		m.openLocked()
	}
}

// InitializeGeo implements GeoIPLifecycle: attach the Redis handler (nil
// when Redis is disabled, like the reference initialize_redis only running
// under an initialized redis_handler) and initialize immediately.
func (m *GeoIPManager) InitializeGeo(redis *RedisManager) {
	m.Redis = redis
	m.initOnce.Do(func() { m.Initialize() })
}

// RefreshGeo implements GeoIPLifecycle.
func (m *GeoIPManager) RefreshGeo() { m.Refresh() }

// Refresh mirrors IPInfoManager.refresh: re-download the database, keep the
// existing reader on failure (reference "IPInfo refresh failed" error log),
// and swap the freshly opened reader in atomically on success.
func (m *GeoIPManager) Refresh() {
	defer func() {
		m.mu.Lock()
		m.initialized = true
		m.mu.Unlock()
	}()
	if err := m.downloadDatabase(); err != nil {
		log.Printf("IPInfo refresh failed: %s", describeDownloadError(err))
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(m.DBPath); err != nil {
		return
	}
	old := m.reader
	m.openLocked()
	if old != nil {
		_ = old.Close()
	}
}

// downloadDatabase mirrors _download_database: GET the free country_asn
// database with the bearer token, three attempts with 1s/2s/4s backoff, an
// atomic write on success, and the fresh content cached in Redis with the
// max-age TTL (a Redis failure is a warning, not an error).
func (m *GeoIPManager) downloadDatabase() error {
	const (
		downloadRetries  = 3
		backoffStartSecs = 1
	)
	dataURL := m.dataURL
	if dataURL == "" {
		dataURL = ipinfoDataURL
	}
	if m.Token == "" {
		return errors.New("ipinfo token is required")
	}
	client := m.httpClient()
	var lastErr error
	backoff := time.Duration(backoffStartSecs) * time.Second
	for attempt := 0; attempt < downloadRetries; attempt++ {
		req, err := http.NewRequest(http.MethodGet, dataURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+m.Token)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			content, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				lastErr = readErr
			} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
				lastErr = &downloadStatusError{status: resp.StatusCode}
			} else {
				if err := m.writeDatabaseAtomically(content); err != nil {
					return err
				}
				if m.Redis != nil {
					ttl := m.MaxAge
					if err := m.Redis.SetKey("ipinfo", "database", string(content), &ttl); err != nil {
						log.Printf("Failed to cache GeoIP database in Redis: %v", err)
					}
				}
				return nil
			}
		}
		if attempt == downloadRetries-1 {
			return lastErr
		}
		m.sleepBackoff(backoff)
		backoff *= 2
	}
	return lastErr
}

// downloadStatusError carries the HTTP status of a failed download so the
// reference _describe_download_error rendering ("HTTPError (HTTP 403)") can
// be reproduced.
type downloadStatusError struct{ status int }

func (e *downloadStatusError) Error() string {
	return fmt.Sprintf("HTTPError (HTTP %d)", e.status)
}

// describeDownloadError mirrors _describe_download_error: the exception type
// name plus the HTTP status when one is known.
func describeDownloadError(err error) string {
	var statusErr *downloadStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Error()
	}
	return strings.TrimPrefix(fmt.Sprintf("%T", err), "*guardcore.")
}

func (m *GeoIPManager) httpClient() *http.Client {
	if m.customHTTPClient != nil {
		return m.customHTTPClient
	}
	return http.DefaultClient
}

// dbOutdated mirrors _is_db_outdated: a missing file is outdated, and a file
// whose mtime is older than the max age is outdated too.
func (m *GeoIPManager) dbOutdated() bool {
	info, err := os.Stat(m.DBPath)
	if err != nil {
		return true
	}
	age := m.nowUTC().Sub(info.ModTime())
	return age > time.Duration(m.MaxAge)*time.Second
}

// writeDatabaseAtomically mirrors _write_database_atomically: write to a
// sibling .tmp file and rename over the target, cleaning the temp file up on
// failure.
func (m *GeoIPManager) writeDatabaseAtomically(content []byte) error {
	tmpPath := m.DBPath + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0o644); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, m.DBPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// GetStatus mirrors IPInfoManager.get_status: readiness, last refresh
// timestamp and the database entry count.
func (m *GeoIPManager) GetStatus() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := map[string]any{
		"ready":          m.reader != nil,
		"last_refreshed": m.lastRefreshed,
		"entries":        0,
	}
	if m.reader != nil {
		status["entries"] = m.reader.Metadata.NodeCount
	}
	return status
}

// GetCountry resolves ip to its ISO country code, mirroring the reference
// get_country: an unavailable reader warns and misses, an unparseable IP or
// a failing lookup misses instead of raising (with the reference
// geo_lookup_failed event emitted through the engine hook).
func (m *GeoIPManager) GetCountry(ip string) (string, bool) {
	m.ensureLoaded()
	m.mu.RLock()
	reader, failed := m.reader, m.failed
	m.mu.RUnlock()
	if reader == nil {
		if failed {
			log.Printf("Geo-IP reader unavailable after a failed initialization attempt; returning no country for %s. Check the IPInfo token and network reachability, then call refresh() to retry.", ip)
		} else {
			log.Printf("Geo-IP reader uninitialized; returning no country for %s", ip)
		}
		return "", false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	var record mmdbRecord
	if err := reader.Lookup(parsed, &record); err != nil {
		log.Printf("Geographic lookup failed for %s: %v", ip, err)
		m.emitGeoEvent(GeoEvent{
			EventType:   EventGeoLookupFailed,
			IPAddress:   ip,
			ActionTaken: "lookup_failed",
			Reason:      fmt.Sprintf("Geographic lookup failed: %T", err),
			HandlerName: ipinfoHandlerName,
		})
		return "", false
	}
	if record.Country == "" {
		return "", false
	}
	return record.Country, true
}

// Close releases the database handle, mirroring IPInfoManager.close.
func (m *GeoIPManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader == nil {
		return nil
	}
	err := m.reader.Close()
	m.reader = nil
	return err
}
