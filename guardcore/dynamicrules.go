package guardcore

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Dynamic rules, ported from the reference agent-synced rule surface
// (guard_core/handlers/dynamic_rule_handler.py plus
// _dynamic_rule_application.py, _dynamic_rule_events.py,
// _dynamic_rule_snapshot.py, _dynamic_rule_persistence.py and
// guard_core/_dynamic_rules.py): rules fetched from the Guard Agent
// replace parts of the live config at runtime, with the reference's
// fail-closed application semantics.
//
// Fail-closed means two things here, exactly as in the reference:
//
//   - Partial application MUST NOT survive: the affected config fields are
//     deep-copied before the rule applies and restored whole on any
//     application error, which propagates (update_rules logs it and keeps
//     the previous active rules).
//   - Redis unavailability never silently degrades rule state: reads and
//     writes to the last-known snapshot are loud (logged), the engine's
//     own startup fail-closed gate (EnableRedis without redis_fail_open)
//     still refuses to start without Redis, and hydration falls through
//     to the optional local cache file.
const (
	// DynamicRulesRedisNamespace and LastKnownRulesKey mirror
	// _dynamic_rule_persistence.py.
	DynamicRulesRedisNamespace = "dynamic_rules"
	LastKnownRulesKey          = "last_known"

	// LastKnownRulesSnapshotSchemaVersion mirrors
	// LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION.
	LastKnownRulesSnapshotSchemaVersion = 1

	// dynamicRulesRetryFloor mirrors _rule_update_loop's min(60, interval)
	// retry delay.
	dynamicRulesRetryFloorSeconds = 60
)

// DynamicRules mirrors the reference model (guard_core/_dynamic_rules.py).
// Feature-toggle overrides are pointers: nil means "leave the live field
// alone".
type DynamicRules struct {
	RuleID    string     `json:"rule_id"`
	Version   int        `json:"version"`
	Timestamp time.Time  `json:"timestamp"`
	ExpiresAt *time.Time `json:"expires_at"`
	TTL       int        `json:"ttl"`

	IPBlacklist   []string `json:"ip_blacklist"`
	IPWhitelist   []string `json:"ip_whitelist"`
	IPBanDuration int      `json:"ip_ban_duration"`

	BlockedCountries   []string `json:"blocked_countries"`
	WhitelistCountries []string `json:"whitelist_countries"`

	GlobalRateLimit    *int              `json:"global_rate_limit"`
	GlobalRateWindow   *int              `json:"global_rate_window"`
	EndpointRateLimits map[string][2]int `json:"endpoint_rate_limits"`

	BlockedCloudProviders []string `json:"blocked_cloud_providers"`
	BlockedUserAgents     []string `json:"blocked_user_agents"`
	SuspiciousPatterns    []string `json:"suspicious_patterns"`

	EnablePenetrationDetection *bool `json:"enable_penetration_detection"`
	EnableIPBanning            *bool `json:"enable_ip_banning"`
	EnableRateLimiting         *bool `json:"enable_rate_limiting"`
	AutoBanThreshold           *int  `json:"auto_ban_threshold"`
	AutoBanDuration            *int  `json:"auto_ban_duration"`
	EnableRateLimitAutoBan     *bool `json:"enable_rate_limit_auto_ban"`

	EmergencyMode      bool     `json:"emergency_mode"`
	EmergencyWhitelist []string `json:"emergency_whitelist"`
}

// normalize mirrors the pydantic field defaults for a fetched rule.
func (r *DynamicRules) normalize() {
	if r.TTL == 0 {
		r.TTL = 300
	}
	if r.IPBanDuration == 0 {
		r.IPBanDuration = 3600
	}
}

// validate mirrors the pydantic ge=1 constraints on the delivery fields
// (guard_core/_dynamic_rules.py): an auto_ban_threshold or
// auto_ban_duration of zero or less is a model-construction
// ValidationError in the reference, which rejects the WHOLE delivery
// (the update loop keeps the previous rules); this port answers the same
// rejection from the same fields. Absent (nil) overrides stay neutral.
func (r *DynamicRules) validate() error {
	if r.AutoBanThreshold != nil && *r.AutoBanThreshold < 1 {
		return fmt.Errorf("auto_ban_threshold must be >= 1, got %d", *r.AutoBanThreshold)
	}
	if r.AutoBanDuration != nil && *r.AutoBanDuration < 1 {
		return fmt.Errorf("auto_ban_duration must be >= 1, got %d", *r.AutoBanDuration)
	}
	return nil
}

// lastKnownRulesSnapshot is the persistence envelope
// (LastKnownRulesSnapshot with extra="forbid").
type lastKnownRulesSnapshot struct {
	SchemaVersion int          `json:"schema_version"`
	Rules         DynamicRules `json:"rules"`
}

// DumpLastKnownRulesSnapshot mirrors dump_last_known_rules_snapshot. The
// envelope shape is statically serializable (fixed field types, no
// interface values), so encoding cannot fail; the reference's error
// return exists for its dynamic pydantic model and has no counterpart
// here.
func DumpLastKnownRulesSnapshot(rules DynamicRules) string {
	payload, _ := json.Marshal(lastKnownRulesSnapshot{
		SchemaVersion: LastKnownRulesSnapshotSchemaVersion,
		Rules:         rules,
	})
	return string(payload)
}

// LoadLastKnownRulesSnapshot mirrors load_last_known_rules_snapshot: the
// schema version is pinned and unknown fields are rejected
// (extra="forbid"), so a foreign payload never half-parses.
func LoadLastKnownRulesSnapshot(payload string) (DynamicRules, error) {
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot lastKnownRulesSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return DynamicRules{}, err
	}
	if snapshot.SchemaVersion != LastKnownRulesSnapshotSchemaVersion {
		return DynamicRules{}, fmt.Errorf("unsupported last-known dynamic rules snapshot schema version: %d", snapshot.SchemaVersion)
	}
	// The reference revalidates the mirrored rules through DynamicRules
	// (ge=1 on the auto-ban fields), so an unusable snapshot is skipped
	// for the next store rather than half-applied.
	if err := snapshot.Rules.validate(); err != nil {
		return DynamicRules{}, err
	}
	snapshot.Rules.normalize()
	return snapshot.Rules, nil
}

// configSnapshot holds the _SNAPSHOT_FIELDS deep copy for the fail-closed
// restore path.
type configSnapshot struct {
	blockedCountries    []string
	whitelistCountries  []string
	rateLimit           int
	rateLimitWindow     int
	endpointRateLimits  map[string]RateLimitEntry
	blockCloudProviders []string
	blockedUserAgents   []string

	enablePenetrationDetection bool
	enableIPBanning            bool
	enableRateLimiting         bool
	emergencyMode              bool
	emergencyWhitelist         []string
	autoBanThreshold           int
	autoBanDuration            int
	enableRateLimitAutoBan     bool
}

// DynamicRulesProvider is the agent-handler capability the update loop
// fetches rules through (the reference agent_handler.get_dynamic_rules).
type DynamicRulesProvider interface {
	GetDynamicRules() (*DynamicRules, error)
}

// DynamicRuleManager mirrors dynamic_rule_handler.DynamicRuleManager.
type DynamicRuleManager struct {
	cfg   *SecurityConfig
	redis *RedisManager
	ban   *IPBanManager
	bus   *SecurityEventBus
	log   *log.Logger

	mu              sync.Mutex
	currentRules    *DynamicRules
	lastUpdate      float64
	activeBase      *configSnapshot
	lastSkippedRule string
	lastSkippedVers int
	hasSkippedRule  bool
	hydrated        bool
	applying        bool

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
	started  bool

	// nowFunc is the test seam for the update clock.
	nowFunc func() float64
}

// NewDynamicRuleManager wires the manager. Redis may be nil (rules still
// apply; persistence is skipped with a logged error, like the reference
// when no redis_handler is attached).
func NewDynamicRuleManager(cfg *SecurityConfig, redis *RedisManager, ban *IPBanManager, bus *SecurityEventBus) *DynamicRuleManager {
	return &DynamicRuleManager{
		cfg:    cfg,
		redis:  redis,
		ban:    ban,
		bus:    bus,
		log:    log.Default(),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
		nowFunc: func() float64 {
			return float64(time.Now().UnixNano()) / 1e9
		},
	}
}

// CurrentRules returns the active rule set, if any.
func (m *DynamicRuleManager) CurrentRules() *DynamicRules {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentRules
}

// LastUpdate returns the wall-clock seconds of the last applied rule.
func (m *DynamicRuleManager) LastUpdate() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastUpdate
}

// HasExpired answers whether rules carries an expiry in the past (naive
// timestamps are already UTC in the port).
func (m *DynamicRuleManager) hasExpired(rules *DynamicRules) bool {
	if rules == nil || rules.ExpiresAt == nil {
		return false
	}
	return time.Now().UTC().After(*rules.ExpiresAt)
}

// shouldUpdateRules mirrors _should_update_rules: apply only when no
// current rule exists, the rule_id differs, or the version is strictly
// greater.
func (m *DynamicRuleManager) shouldUpdateRules(rules *DynamicRules) bool {
	current := m.currentRules
	if current == nil {
		return true
	}
	return !(rules.RuleID == current.RuleID && rules.Version <= current.Version)
}

// rejectIfAlreadyExpired mirrors _reject_if_already_expired: expired
// deliveries are ignored with a warn-once per rule_id+version.
func (m *DynamicRuleManager) rejectIfAlreadyExpired(rules *DynamicRules) bool {
	if !m.hasExpired(rules) {
		return false
	}
	if !m.hasSkippedRule || m.lastSkippedRule != rules.RuleID || m.lastSkippedVers != rules.Version {
		m.hasSkippedRule = true
		m.lastSkippedRule = rules.RuleID
		m.lastSkippedVers = rules.Version
		m.log.Printf("Dynamic rule %s v%d already expired on receipt; ignoring", rules.RuleID, rules.Version)
	}
	return true
}

// checkRuleExpiry mirrors _check_rule_expiry: past expiry, the active
// rule is dropped and the base config restored (the FIRST successful
// rule's snapshot, retained across consecutive rules).
func (m *DynamicRuleManager) checkRuleExpiry() {
	rules := m.currentRules
	if rules == nil || rules.ExpiresAt == nil {
		return
	}
	if !time.Now().UTC().After(*rules.ExpiresAt) {
		return
	}
	if m.activeBase != nil {
		m.restoreSnapshot(m.activeBase)
		m.cfg.BumpRevision()
	}
	m.log.Printf("Dynamic rule %s v%d expired; restored base config", rules.RuleID, rules.Version)
	m.currentRules = nil
	m.activeBase = nil
}

// UpdateRules mirrors update_rules: expire, fetch, gate, emit
// dynamic_rule_updated, apply, remember, emit dynamic_rule_applied. The
// fetcher error and the application error are both contained here (the
// previous rules stay active), exactly like the reference's caught
// update loop body.
func (m *DynamicRuleManager) UpdateRules(fetch func() (*DynamicRules, error)) error {
	if !m.cfg.EnableDynamicRules {
		return nil
	}
	m.mu.Lock()
	m.checkRuleExpiry()
	m.mu.Unlock()

	rules, err := fetch()
	if err != nil {
		return fmt.Errorf("fetch dynamic rules: %w", err)
	}
	if rules == nil {
		return nil
	}
	// The reference validates the delivery at model construction
	// (DynamicRules ge=1 on the auto-ban fields): an invalid delivery is
	// rejected whole and the update loop keeps the previous rules.
	if err := rules.validate(); err != nil {
		return err
	}
	rules.normalize()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rejectIfAlreadyExpired(rules) {
		return nil
	}
	if !m.shouldUpdateRules(rules) {
		return nil
	}

	m.sendRuleEvent(EventDynamicRuleUpdated, "rules_received",
		fmt.Sprintf("Received updated rules %s v%d", rules.RuleID, rules.Version),
		rules, map[string]any{
			"rule_id":          rules.RuleID,
			"version":          rules.Version,
			"previous_version": m.currentRulesVersion(),
		})

	m.log.Printf("Applying dynamic rules: %s v%d", rules.RuleID, rules.Version)
	if err := m.applyRulesLocked(rules); err != nil {
		m.log.Printf("Failed to update dynamic rules: %v", err)
		return err
	}

	m.currentRules = rules
	m.lastUpdate = m.nowFunc()

	m.sendRuleEvent(EventDynamicRuleApplied, "rules_updated",
		fmt.Sprintf("Applied dynamic rules %s v%d", rules.RuleID, rules.Version),
		rules, map[string]any{
			"rule_id":        rules.RuleID,
			"version":        rules.Version,
			"ip_bans":        len(rules.IPBlacklist),
			"country_blocks": len(rules.BlockedCountries),
			"emergency_mode": rules.EmergencyMode,
		})
	return nil
}

func (m *DynamicRuleManager) currentRulesVersion() int {
	if m.currentRules == nil {
		return 0
	}
	return m.currentRules.Version
}

// sendRuleEvent mirrors the _dynamic_rule_events.py emitters: the
// dynamic_rules handler events bypass the bus's agent gate, and a send
// failure (including a panicking transport) is caught and logged, never
// propagated - exactly like the reference's try/except wrappers.
func (m *DynamicRuleManager) sendRuleEvent(eventType, actionTaken, reason string, rules *DynamicRules, metadata map[string]any) {
	if m.bus == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			m.log.Printf("Failed to send rule %s event: %v", actionTaken, r)
		}
	}()
	m.bus.SendHandlerEvent(eventType, DynamicRulesHandlerName, "system", actionTaken, reason, metadata)
}

// captureSnapshot deep-copies the _SNAPSHOT_FIELDS.
func (m *DynamicRuleManager) captureSnapshot() *configSnapshot {
	cfg := m.cfg
	snapshot := &configSnapshot{
		blockedCountries:           append([]string(nil), cfg.BlockedCountries...),
		whitelistCountries:         append([]string(nil), cfg.WhitelistCountries...),
		rateLimit:                  cfg.RateLimit,
		rateLimitWindow:            cfg.RateLimitWindow,
		endpointRateLimits:         copyEndpointRateLimits(cfg.EndpointRateLimits),
		blockCloudProviders:        append([]string(nil), cfg.BlockCloudProviders...),
		blockedUserAgents:          append([]string(nil), cfg.BlockedUserAgents...),
		enablePenetrationDetection: cfg.EnablePenetrationDetection,
		enableIPBanning:            cfg.EnableIPBanning,
		enableRateLimiting:         cfg.EnableRateLimiting,
		emergencyMode:              cfg.EmergencyMode,
		emergencyWhitelist:         append([]string(nil), cfg.EmergencyWhitelist...),
		autoBanThreshold:           cfg.AutoBanThreshold,
		autoBanDuration:            cfg.AutoBanDuration,
		enableRateLimitAutoBan:     cfg.EnableRateLimitAutoBan,
	}
	return snapshot
}

func copyEndpointRateLimits(source map[string]RateLimitEntry) map[string]RateLimitEntry {
	out := make(map[string]RateLimitEntry, len(source))
	for k, v := range source {
		out[k] = v
	}
	return out
}

// restoreSnapshot puts a snapshot back (the _restore_config path).
func (m *DynamicRuleManager) restoreSnapshot(snapshot *configSnapshot) {
	cfg := m.cfg
	cfg.BlockedCountries = append([]string(nil), snapshot.blockedCountries...)
	cfg.WhitelistCountries = append([]string(nil), snapshot.whitelistCountries...)
	cfg.RateLimit = snapshot.rateLimit
	cfg.RateLimitWindow = snapshot.rateLimitWindow
	cfg.EndpointRateLimits = copyEndpointRateLimits(snapshot.endpointRateLimits)
	cfg.BlockCloudProviders = append([]string(nil), snapshot.blockCloudProviders...)
	cfg.BlockedUserAgents = append([]string(nil), snapshot.blockedUserAgents...)
	cfg.EnablePenetrationDetection = snapshot.enablePenetrationDetection
	cfg.EnableIPBanning = snapshot.enableIPBanning
	cfg.EnableRateLimiting = snapshot.enableRateLimiting
	cfg.EmergencyMode = snapshot.emergencyMode
	cfg.EmergencyWhitelist = append([]string(nil), snapshot.emergencyWhitelist...)
	cfg.AutoBanThreshold = snapshot.autoBanThreshold
	cfg.AutoBanDuration = snapshot.autoBanDuration
	cfg.EnableRateLimitAutoBan = snapshot.enableRateLimitAutoBan
}

// applyRulesLocked mirrors _apply_rules under the manager lock: snapshot,
// apply in the reference order (IP rules, blocking rules, rate limits,
// feature toggles, emergency mode), and restore the snapshot whole on any
// application failure - partial application MUST NOT survive. The
// reference converts an application exception exactly this way (restore,
// log, raise); the individual steps themselves log and continue per rule,
// like the reference.
func (m *DynamicRuleManager) applyRulesLocked(rules *DynamicRules) (err error) {
	if m.applying {
		return fmt.Errorf("dynamic rule application already in flight")
	}
	m.applying = true
	defer func() { m.applying = false }()

	snapshot := m.captureSnapshot()
	failed := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				m.restoreSnapshot(snapshot)
				m.log.Printf("Failed to apply dynamic rules: %v", r)
				failed = true
			}
		}()
		m.applyIPRules(rules)
		m.applyBlockingRules(rules)
		m.applyRateLimitRules(rules)
		m.applyFeatureToggles(rules)
		if rules.EmergencyMode {
			m.activateEmergencyMode(rules.EmergencyWhitelist)
		}
	}()
	if failed {
		return fmt.Errorf("dynamic rule application failed: snapshot restored")
	}

	if m.currentRules == nil && m.activeBase == nil {
		// _capture_active_base_snapshot: the FIRST successful rule's
		// snapshot is retained as the base so expiry restores pre-rule
		// state even across consecutive rules.
		m.activeBase = snapshot
	}
	m.persistLastKnownRules(rules)
	m.cfg.BumpRevision()
	return nil
}

// applyIPRules mirrors _apply_ip_rules: blacklist entries ban with the
// dynamic_rule reason, whitelist entries unban (refusals and errors are
// logged per IP, not fatal, like the reference).
func (m *DynamicRuleManager) applyIPRules(rules *DynamicRules) {
	for _, ip := range rules.IPBlacklist {
		if m.ban == nil {
			m.log.Printf("Failed to ban IP %s: no ip_ban_manager attached", ip)
			continue
		}
		applied, err := m.ban.Ban(ip, rules.IPBanDuration, "dynamic_rule")
		if err != nil {
			m.log.Printf("Failed to ban IP %s: %v", ip, err)
			continue
		}
		if applied {
			m.log.Printf("Dynamic rule: Banned IP %s for %ds", ip, rules.IPBanDuration)
		}
	}
	for _, ip := range rules.IPWhitelist {
		if m.ban == nil {
			m.log.Printf("Failed to whitelist IP %s: no ip_ban_manager attached", ip)
			continue
		}
		if err := m.ban.Unban(ip); err != nil {
			m.log.Printf("Failed to whitelist IP %s: %v", ip, err)
			continue
		}
		m.log.Printf("Dynamic rule: Whitelisted IP %s", ip)
	}
}

// applyBlockingRules mirrors _apply_blocking_rules: country rules (warn
// and skip without a geo resolver and no token), cloud providers filtered
// against the registry by bare selector name, user-agent patterns
// validated, suspicious patterns logged-and-skipped (the detection
// pattern table is compile-time in this port).
func (m *DynamicRuleManager) applyBlockingRules(rules *DynamicRules) {
	if len(rules.BlockedCountries) > 0 || len(rules.WhitelistCountries) > 0 {
		if m.cfg.GeoIPHandler == nil && m.cfg.IPInfoToken == "" {
			m.log.Printf("Dynamic rule: country rules cannot take effect (blocked=%v, allowed=%v); no geo_ip_handler or ipinfo_token is configured to resolve IPs to countries", rules.BlockedCountries, rules.WhitelistCountries)
		} else {
			if len(rules.BlockedCountries) > 0 {
				m.cfg.BlockedCountries = normalizeCountryList(rules.BlockedCountries)
				m.log.Printf("Dynamic rule: Blocked countries %v", sortedCopy(m.cfg.BlockedCountries))
			}
			if len(rules.WhitelistCountries) > 0 {
				m.cfg.WhitelistCountries = normalizeCountryList(rules.WhitelistCountries)
				m.log.Printf("Dynamic rule: Whitelisted countries %v", sortedCopy(m.cfg.WhitelistCountries))
			}
		}
	}
	if len(rules.BlockedCloudProviders) > 0 {
		var valid []string
		for _, provider := range rules.BlockedCloudProviders {
			bare, _, _ := strings.Cut(provider, ":!")
			if ValidCloudProviders[bare] {
				valid = append(valid, provider)
			} else {
				m.log.Printf("Dynamic rule: ignored unknown cloud providers %v", []string{provider})
			}
		}
		m.cfg.BlockCloudProviders = valid
		if len(valid) > 0 {
			m.log.Printf("Dynamic rule: Blocked cloud providers %v", valid)
		}
	}
	if len(rules.BlockedUserAgents) > 0 {
		var valid []string
		for _, pattern := range rules.BlockedUserAgents {
			if _, err := regexp.Compile(pattern); err != nil {
				m.log.Printf("Dynamic rule: rejected blocked_user_agents pattern failing the validator: %q: %v", pattern, err)
				continue
			}
			valid = append(valid, pattern)
		}
		m.cfg.BlockedUserAgents = valid
		m.log.Printf("Dynamic rule: Blocked user agents %d pattern(s)", len(valid))
	}
	if len(rules.SuspiciousPatterns) > 0 {
		// The reference adds these to the runtime sus-patterns registry;
		// this port's detection patterns are a compile-time table, so the
		// field is honored as a logged no-op with the same rejection
		// honesty (never silently swallowed).
		m.log.Printf("Dynamic rule: suspicious_patterns applied to no runtime registry in this port (patterns: %d, skipped)", len(rules.SuspiciousPatterns))
	}
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

// applyRateLimitRules mirrors _apply_rate_limit_rules.
func (m *DynamicRuleManager) applyRateLimitRules(rules *DynamicRules) {
	if rules.GlobalRateLimit != nil && *rules.GlobalRateLimit > 0 {
		m.cfg.RateLimit = *rules.GlobalRateLimit
		if rules.GlobalRateWindow != nil && *rules.GlobalRateWindow > 0 {
			m.cfg.RateLimitWindow = *rules.GlobalRateWindow
		}
		m.log.Printf("Dynamic rule: Global rate limit %d per %ds", rules.GlobalRateLimit, derefInt(rules.GlobalRateWindow, m.cfg.RateLimitWindow))
	}
	if len(rules.EndpointRateLimits) > 0 {
		endpoints := make(map[string]RateLimitEntry, len(rules.EndpointRateLimits))
		for endpoint, limits := range rules.EndpointRateLimits {
			endpoints[endpoint] = RateLimitEntry{Requests: limits[0], Window: limits[1]}
		}
		m.cfg.EndpointRateLimits = endpoints
		m.log.Printf("Dynamic rule: Applied endpoint-specific rate limits for %d endpoints", len(endpoints))
	}
}

func derefInt(v *int, fallback int) int {
	if v == nil {
		return fallback
	}
	return *v
}

// applyFeatureToggles mirrors _apply_feature_toggles: only non-nil
// overrides touch the live config.
func (m *DynamicRuleManager) applyFeatureToggles(rules *DynamicRules) {
	if rules.EnablePenetrationDetection != nil {
		m.cfg.EnablePenetrationDetection = *rules.EnablePenetrationDetection
		m.log.Printf("Dynamic rule: Penetration detection %v", *rules.EnablePenetrationDetection)
	}
	if rules.EnableIPBanning != nil {
		m.cfg.EnableIPBanning = *rules.EnableIPBanning
		m.log.Printf("Dynamic rule: IP banning %v", *rules.EnableIPBanning)
	}
	if rules.EnableRateLimiting != nil {
		m.cfg.EnableRateLimiting = *rules.EnableRateLimiting
		m.log.Printf("Dynamic rule: Rate limiting %v", *rules.EnableRateLimiting)
	}
	if rules.EnableRateLimitAutoBan != nil {
		m.cfg.EnableRateLimitAutoBan = *rules.EnableRateLimitAutoBan
		m.log.Printf("Dynamic rule: Rate-limit auto-ban %v", *rules.EnableRateLimitAutoBan)
	}
	if rules.AutoBanThreshold != nil {
		m.cfg.AutoBanThreshold = *rules.AutoBanThreshold
		m.log.Printf("Dynamic rule: Auto-ban threshold %d", *rules.AutoBanThreshold)
	}
	if rules.AutoBanDuration != nil {
		m.cfg.AutoBanDuration = *rules.AutoBanDuration
		m.log.Printf("Dynamic rule: Auto-ban duration %d", *rules.AutoBanDuration)
	}
}

// activateEmergencyMode mirrors _activate_emergency_mode: the whitelist
// lands, the auto-ban threshold halves (max(1, t // 2)), and the
// emergency_mode_activated event carries the whitelist count and the
// first 10 entries.
func (m *DynamicRuleManager) activateEmergencyMode(whitelist []string) {
	m.cfg.EmergencyMode = true
	m.cfg.EmergencyWhitelist = append([]string(nil), whitelist...)
	m.cfg.AutoBanThreshold = maxInt(1, m.cfg.AutoBanThreshold/2)
	m.log.Printf("[EMERGENCY MODE] activated via dynamic rules")
	shown := whitelist
	if len(shown) > 10 {
		shown = shown[:10]
	}
	if m.bus != nil {
		m.bus.SendHandlerEvent(EventEmergencyMode, DynamicRulesHandlerName, "system", "emergency_lockdown",
			"[EMERGENCY MODE] activated via dynamic rules", map[string]any{
				"whitelist_count": len(whitelist),
				"whitelist":       shown,
			})
	}
}

// persistLastKnownRules mirrors _persist_last_known_rules: the snapshot
// goes to Redis (no TTL) and, when configured, atomically to the cache
// file. Failures are logged, never fatal.
func (m *DynamicRuleManager) persistLastKnownRules(rules *DynamicRules) {
	payload := DumpLastKnownRulesSnapshot(*rules)
	if m.redis != nil && m.redis.Enabled() {
		if err := m.redis.SetKey(DynamicRulesRedisNamespace, LastKnownRulesKey, payload, nil); err != nil {
			m.log.Printf("Failed to persist dynamic rules to Redis: %v", err)
		}
	}
	if m.cfg.DynamicRulesCachePath == "" {
		return
	}
	if err := writeAtomicFile(m.cfg.DynamicRulesCachePath, payload); err != nil {
		m.log.Printf("Failed to persist dynamic rules to cache file %s: %v", m.cfg.DynamicRulesCachePath, err)
	}
}

// writeAtomicFile mirrors _write_last_known_rules_file: tmp file in the
// target directory, then rename.
func writeAtomicFile(path, payload string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Write and close failures on a freshly created temp file only happen
	// on ENOSPC/EIO-class conditions; they cannot be induced in-process,
	// so these two guards are defensive hygiene with the same cleanup
	// contract (remove the temp, surface the error).
	if _, err := tmp.WriteString(payload); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// HydrateLastKnownRules mirrors _hydrate_last_known_rules: Redis first,
// then the file; expired or unparseable payloads are skipped trying the
// next store, and the first usable snapshot applies as if received. One
// shot per manager.
func (m *DynamicRuleManager) HydrateLastKnownRules() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hydrated {
		return
	}
	m.hydrated = true
	rules := m.loadLastKnownRules()
	if rules == nil {
		return
	}
	if err := m.applyRulesLocked(rules); err != nil {
		m.log.Printf("Failed to hydrate last-known dynamic rules: %v", err)
		return
	}
	m.currentRules = rules
	m.lastUpdate = m.nowFunc()
	m.log.Printf("Hydrated last-known dynamic rules %s v%d before the update loop started", rules.RuleID, rules.Version)
}

// loadLastKnownRules mirrors _load_last_known_rules: Redis first, then
// the file; expired or unparseable payloads fall through.
func (m *DynamicRuleManager) loadLastKnownRules() *DynamicRules {
	if payload := m.readRedisPayload(); payload != "" {
		if rules := m.parseLastKnownRules(payload); rules != nil {
			if m.hasExpired(rules) {
				m.log.Printf("Discarding expired last-known dynamic rules %s v%d; trying the next store", rules.RuleID, rules.Version)
			} else {
				return rules
			}
		}
	}
	if m.cfg.DynamicRulesCachePath != "" {
		if payload := readFilePayload(m.cfg.DynamicRulesCachePath, m.log); payload != "" {
			if rules := m.parseLastKnownRules(payload); rules != nil {
				if m.hasExpired(rules) {
					m.log.Printf("Discarding expired last-known dynamic rules %s v%d; trying the next store", rules.RuleID, rules.Version)
				} else {
					return rules
				}
			}
		}
	}
	return nil
}

func (m *DynamicRuleManager) readRedisPayload() string {
	if m.redis == nil || !m.redis.Enabled() {
		return ""
	}
	raw, err := m.redis.GetKey(DynamicRulesRedisNamespace, LastKnownRulesKey)
	if err != nil {
		m.log.Printf("Failed to read last-known dynamic rules from Redis: %v", err)
		return ""
	}
	return raw
}

func readFilePayload(path string, logger *log.Logger) string {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Printf("Failed to read dynamic rules cache file %s: %v", path, err)
		}
		return ""
	}
	return string(data)
}

func (m *DynamicRuleManager) parseLastKnownRules(payload string) *DynamicRules {
	rules, err := LoadLastKnownRulesSnapshot(payload)
	if err != nil {
		m.log.Printf("Discarding unusable last-known dynamic rules payload: %v", err)
		return nil
	}
	return &rules
}

// MatchEvent mirrors match_event: the active rule answers for the event
// when its IP is in the rule's lists, its country is blocked, or its type
// rides a rule the manager applied.
func (m *DynamicRuleManager) MatchEvent(event SecurityEvent) (string, int, bool) {
	rules := m.CurrentRules()
	if rules == nil {
		return "", 0, false
	}
	if m.eventMatchesIP(event, rules) || m.eventMatchesCountry(event, rules) || m.eventMatchesType(event, rules) {
		return rules.RuleID, rules.Version, true
	}
	return "", 0, false
}

func (m *DynamicRuleManager) eventMatchesIP(event SecurityEvent, rules *DynamicRules) bool {
	if event.IPAddress == "" {
		return false
	}
	return dynamicRulesContains(rules.IPBlacklist, event.IPAddress) || dynamicRulesContains(rules.IPWhitelist, event.IPAddress)
}

func (m *DynamicRuleManager) eventMatchesCountry(event SecurityEvent, rules *DynamicRules) bool {
	return event.Country != "" && dynamicRulesContains(rules.BlockedCountries, event.Country)
}

func (m *DynamicRuleManager) eventMatchesType(event SecurityEvent, rules *DynamicRules) bool {
	switch event.EventType {
	case EventRateLimited:
		return rules.GlobalRateLimit != nil || len(rules.EndpointRateLimits) > 0
	case EventCloudBlocked:
		return len(rules.BlockedCloudProviders) > 0
	case EventUserAgentBlocked:
		return len(rules.BlockedUserAgents) > 0
	}
	return false
}

func dynamicRulesContains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

// Start launches the reference's _rule_update_loop: every interval a
// fetch, on error a retry after min(60, interval). The fetcher is
// injected (the reference calls agent_handler.get_dynamic_rules); a nil
// interval falls back to the config value.
func (m *DynamicRuleManager) Start(fetch func() (*DynamicRules, error), interval time.Duration) {
	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	if !m.cfg.EnableDynamicRules {
		close(m.doneCh)
		return
	}
	if interval <= 0 {
		interval = time.Duration(m.cfg.DynamicRuleInterval) * time.Second
	}
	retry := interval
	if floor := dynamicRulesRetryFloorSeconds * time.Second; retry > floor {
		retry = floor
	}
	go func() {
		defer close(m.doneCh)
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-timer.C:
			}
			err := m.UpdateRules(fetch)
			wait := interval
			if err != nil {
				m.log.Printf("Error in dynamic rule update loop: %v", err)
				wait = retry
			}
			timer.Reset(wait)
		}
	}()
}

// Stop mirrors stop(): the loop drains and the goroutine exits. A manager
// whose loop never started (Start not called) drains immediately.
func (m *DynamicRuleManager) Stop() {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		started := m.started
		m.mu.Unlock()
		close(m.stopCh)
		if started {
			<-m.doneCh
			m.log.Printf("Stopped dynamic rule update loop")
		}
	})
}
