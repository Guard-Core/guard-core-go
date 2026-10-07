package guardcore

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// Behavior-rules surface, ported from the reference engine:
//
//   - config fields global_behavior_rules / behavior_scan_response_body /
//     behavior_max_response_body_inspect_bytes
//     (guard_core/_security_config_fields.py) and the BehaviorRuleConfig model
//     plus the global-rule assignment validation
//     (guard_core/_security_config_field_validators.py, models.py
//     _validate_global_behavior_rule_assignment)
//   - the tracker and action dispatch
//     (guard_core/handlers/behavior_handler.py,
//     guard_core/handlers/_behavior_action_dispatch.py,
//     guard_core/handlers/_behavior_response_pattern.py,
//     guard_core/handlers/_behavior_json_pattern.py)
//   - the processor semantics
//     (guard_core/core/behavioral/processor.py)

// ValidBehaviorRuleTypes mirrors the BehaviorRuleConfig.rule_type literal.
var ValidBehaviorRuleTypes = map[string]bool{
	"usage":          true,
	"return_pattern": true,
	"frequency":      true,
}

// ValidBehaviorActions mirrors the BehaviorRuleConfig.action literal.
var ValidBehaviorActions = map[string]bool{
	"ban":      true,
	"log":      true,
	"throttle": true,
	"alert":    true,
}

const (
	// DefaultBehaviorWindow mirrors BehaviorRuleConfig.window's default of
	// 3600 seconds; a configured 0 falls back to it like the pydantic
	// default.
	DefaultBehaviorWindow = 3600

	// DefaultBehaviorAction mirrors BehaviorRuleConfig.action's default.
	DefaultBehaviorAction = "log"

	// DefaultBehaviorBanDurationSeconds mirrors _execute_ban_action's
	// fallback when a ban rule carries no ban_duration.
	DefaultBehaviorBanDurationSeconds = 3600

	// Tracker bounds mirror _MAX_TRACKED_ENDPOINTS and
	// _MAX_TRACKED_CLIENTS_PER_ENDPOINT (behavior_handler.py): the local
	// stores hold at most this many endpoint buckets and client rows per
	// endpoint.
	maxTrackedEndpoints          = 10000
	maxTrackedClientsPerEndpoint = 10000

	behaviorPatternRegexTimeout = time.Second
)

// BehaviorRuleConfig mirrors the reference BehaviorRuleConfig model
// (guard_core/_security_config_field_validators.py). The Go port uses one
// struct for both the configured and the runtime rule (the reference's
// config_to_rule copies field by field with no transformation).
type BehaviorRuleConfig struct {
	RuleType string
	// Threshold is the number of events within Window that trips the rule;
	// the reference requires >= 1.
	Threshold int
	// Window is the sliding window in seconds; 0 falls back to
	// DefaultBehaviorWindow.
	Window int
	// Pattern is only meaningful for return_pattern rules: "status:<code>",
	// "json:<path>==<expected>", "regex:<pattern>", or a bare substring.
	Pattern string
	// Action is one of ban/log/throttle/alert; "" falls back to
	// DefaultBehaviorAction.
	Action string
	// BanDuration in seconds for ban rules; 0 falls back to
	// DefaultBehaviorBanDurationSeconds at dispatch time.
	BanDuration int
	// CorrelateWithDetection halves the effective threshold for global
	// return_pattern rules while the IP has prior detection-category hits.
	CorrelateWithDetection bool
}

// ValidateBehaviorRuleConfig normalizes defaults and enforces the reference's
// pydantic constraints: rule_type and action literals, threshold >= 1,
// window >= 1, ban_duration >= 1.
func ValidateBehaviorRuleConfig(rule *BehaviorRuleConfig) error {
	if !ValidBehaviorRuleTypes[rule.RuleType] {
		return fmt.Errorf("behavior rule rule_type: must be one of usage, return_pattern, frequency (got %q)", rule.RuleType)
	}
	if rule.Threshold < 1 {
		return fmt.Errorf("behavior rule threshold: must be >= 1, got %d", rule.Threshold)
	}
	if rule.Window == 0 {
		rule.Window = DefaultBehaviorWindow
	}
	if rule.Window < 1 {
		return fmt.Errorf("behavior rule window: must be >= 1, got %d", rule.Window)
	}
	if rule.Action == "" {
		rule.Action = DefaultBehaviorAction
	}
	if !ValidBehaviorActions[rule.Action] {
		return fmt.Errorf("behavior rule action: must be one of ban, log, throttle, alert (got %q)", rule.Action)
	}
	if rule.BanDuration < 0 {
		return fmt.Errorf("behavior rule ban_duration: must be >= 1, got %d", rule.BanDuration)
	}
	// ban_duration stays 0 (= unset, like the reference's None) here; the
	// dispatch falls back to DefaultBehaviorBanDurationSeconds only when a
	// ban action actually fires.
	return nil
}

// returnPatternRequiresResponseBody mirrors
// return_pattern_requires_response_body: every pattern that is not a
// status: pattern needs the response body to evaluate.
func returnPatternRequiresResponseBody(pattern string) bool {
	return !strings.HasPrefix(pattern, "status:")
}

// validateBehaviorRulesAgainstScanFlag mirrors
// _validate_return_pattern_requires_scan via
// _validate_global_behavior_rule_assignment: a return_pattern rule whose
// pattern needs the response body is rejected when
// behavior_scan_response_body is False, because it would silently never
// match. status: patterns are unaffected by the flag.
func validateBehaviorRulesAgainstScanFlag(rules []BehaviorRuleConfig, scanResponseBody bool, fieldName string) error {
	for _, rule := range rules {
		if rule.RuleType != "return_pattern" || rule.Pattern == "" {
			continue
		}
		if !returnPatternRequiresResponseBody(rule.Pattern) {
			continue
		}
		if scanResponseBody {
			continue
		}
		return fmt.Errorf(
			"%s: return_pattern rule with pattern %q requires reading the response body, but behavior_scan_response_body is False. This rule would never match: set behavior_scan_response_body=True to enable response-body inspection, or use a status: pattern instead",
			fieldName, rule.Pattern,
		)
	}
	return nil
}

// BehaviorTracker mirrors guard_core/handlers/behavior_handler.py
// BehaviorTracker: sliding-window usage counts and return-pattern hits per
// (endpoint, client), backed by Redis when available and by bounded local
// maps otherwise.
type BehaviorTracker struct {
	cfg   *SecurityConfig
	redis *RedisManager
	ban   *IPBanManager
	log   *log.Logger

	mu             sync.Mutex
	usageCounts    map[string]map[string][]float64
	returnPatterns map[string]map[string][]float64
}

func NewBehaviorTracker(cfg *SecurityConfig, redis *RedisManager, ban *IPBanManager, logger *log.Logger) *BehaviorTracker {
	if logger == nil {
		logger = log.Default()
	}
	return &BehaviorTracker{
		cfg:            cfg,
		redis:          redis,
		ban:            ban,
		log:            logger,
		usageCounts:    map[string]map[string][]float64{},
		returnPatterns: map[string]map[string][]float64{},
	}
}

// recordSlidingWindowHit mirrors redis_handler.record_sliding_window_hit:
// one ZADD with a random member, prune strictly-older-than-window-start
// entries, return the cardinality. The caller compares count > threshold
// exactly like track_endpoint_usage / track_return_pattern.
func (t *BehaviorTracker) recordSlidingWindowHit(namespace, key string, now, windowStart float64, window int) (int64, error) {
	if t.redis == nil || !t.redis.Enabled() {
		return 0, errBehaviorRedisUnavailable
	}
	return t.redis.RecordSlidingWindowHit(namespace, key, now, windowStart, window)
}

var errBehaviorRedisUnavailable = fmt.Errorf("redis unavailable for behavior tracking")

// TrackEndpointUsage mirrors BehaviorTracker.track_endpoint_usage: it
// records a hit and reports whether the rule threshold is now exceeded
// (strictly greater, like the reference).
func (t *BehaviorTracker) TrackEndpointUsage(endpointID, clientIP string, rule BehaviorRuleConfig, now float64) bool {
	windowStart := now - float64(rule.Window)
	if t.redis != nil && t.redis.Enabled() {
		key := "behavior:usage:" + hashIdentitySegment(endpointID) + ":" + hashIdentitySegment(clientIP)
		count, err := t.recordSlidingWindowHit("behavior_usage", key, now, windowStart, rule.Window)
		if err == nil {
			return count > int64(rule.Threshold)
		}
		if !t.cfg.RedisFailOpen {
			// Fail closed like the pipeline's redis handling: an
			// unavailable store must not quietly disable the rule.
			t.log.Printf("behavior tracking: redis unavailable (%v)", err)
			return false
		}
	}
	count := t.trackLocal(t.usageCounts, endpointID, clientIP, now, windowStart)
	return count > rule.Threshold
}

// TrackReturnPattern mirrors BehaviorTracker.track_return_pattern: the
// pattern must match first; only matching responses advance the sliding
// window. effectiveThreshold <= 0 means "use the rule threshold".
func (t *BehaviorTracker) TrackReturnPattern(endpointID, clientIP string, resp *Response, rule BehaviorRuleConfig, now float64, effectiveThreshold int) bool {
	if rule.Pattern == "" {
		return false
	}
	if effectiveThreshold <= 0 {
		effectiveThreshold = rule.Threshold
	}
	matched, evaluated := t.CheckResponsePattern(resp, rule.Pattern)
	if !evaluated || !matched {
		return false
	}
	windowStart := now - float64(rule.Window)
	if t.redis != nil && t.redis.Enabled() {
		key := "behavior:return:" + hashIdentitySegment(endpointID) + ":" + hashIdentitySegment(clientIP) + ":" + hashIdentitySegment(rule.Pattern)
		count, err := t.recordSlidingWindowHit("behavior_returns", key, now, windowStart, rule.Window)
		if err == nil {
			return count > int64(effectiveThreshold)
		}
		if !t.cfg.RedisFailOpen {
			t.log.Printf("behavior tracking: redis unavailable (%v)", err)
			return false
		}
	}
	patternKey := endpointID + ":" + rule.Pattern
	count := t.trackLocal(t.returnPatterns, patternKey, clientIP, now, windowStart)
	return count > effectiveThreshold
}

// trackLocal prunes and appends one timestamp in the bounded local store and
// returns the new in-window count.
func (t *BehaviorTracker) trackLocal(store map[string]map[string][]float64, bucket, key string, now, windowStart float64) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	rows, ok := store[bucket]
	if !ok {
		if len(store) >= maxTrackedEndpoints {
			evictOneKey(store)
		}
		rows = map[string][]float64{}
		store[bucket] = rows
	}
	timestamps, ok := rows[key]
	if !ok && len(rows) >= maxTrackedClientsPerEndpoint {
		evictOneKey(rows)
	}
	kept := timestamps[:0]
	for _, ts := range timestamps {
		if ts >= windowStart {
			kept = append(kept, ts)
		}
	}
	timestamps = append(kept, now)
	rows[key] = timestamps
	return len(timestamps)
}

// GetRecentEventCount mirrors BehaviorTracker.get_recent_event_count
// (guard_core/handlers/behavior_handler.py): the number of locally tracked
// usage timestamps for the ip that fall inside the sliding window, summed
// across every endpoint bucket. An empty ip answers 0 (the reference's
// early return). The event enricher calls this for the
// guard.behavior.recent_event_count correlation column.
func (t *BehaviorTracker) GetRecentEventCount(ip string, windowSeconds int) int {
	if t == nil || ip == "" {
		return 0
	}
	cutoff := float64(time.Now().UnixNano())/float64(time.Second) - float64(windowSeconds)
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, clients := range t.usageCounts {
		for _, ts := range clients[ip] {
			if ts >= cutoff {
				count++
			}
		}
	}
	return count
}

// evictOneKey bounds the local stores when they hit the reference's
// _MAX_TRACKED_* caps. Python evicts LRU-first via _lru_pop_or_create; the
// Go map has no order, so one arbitrary entry is dropped, which bounds
// memory identically even though the victim choice differs.
func evictOneKey[V any](m map[string]V) {
	for k := range m {
		delete(m, k)
		return
	}
}

// CheckResponsePattern mirrors _check_response_pattern
// (_behavior_response_pattern.py). The second return value mirrors the
// reference's tri-state: evaluated=false stands for the None outcome (the
// body could not be inspected, so the hit is not counted), evaluated=true
// carries the match verdict.
func (t *BehaviorTracker) CheckResponsePattern(resp *Response, pattern string) (matched, evaluated bool) {
	defer func() {
		if r := recover(); r != nil {
			t.log.Printf("Error checking response pattern: %v", r)
			matched, evaluated = false, true
		}
	}()
	if strings.HasPrefix(pattern, "status:") {
		expected, err := parseStatusPattern(pattern)
		if err != nil {
			return false, true
		}
		return resp.StatusCode == expected, true
	}

	if !t.cfg.BehaviorScanResponseBody {
		// The reference returns None before touching the body: with the
		// scan flag off, non-status patterns are not evaluated at all
		// (config construction rejects such rules, so this is a defensive
		// path for runtime-built rules).
		return false, false
	}
	maxBytes := t.cfg.BehaviorMaxResponseBodyInspectBytes
	if maxBytes <= 0 {
		maxBytes = DefaultBehaviorMaxResponseBodyInspectBytes
	}
	if resp == nil || len(resp.Body) == 0 {
		return false, true
	}
	body := resp.Body
	if len(body) > maxBytes {
		body = body[:maxBytes]
	}
	bodyStr := string(body)

	if rest, ok := strings.CutPrefix(pattern, "json:"); ok {
		var parsed any
		if err := json.Unmarshal([]byte(bodyStr), &parsed); err != nil {
			return false, true
		}
		return matchJSONPattern(parsed, rest), true
	}
	if rest, ok := strings.CutPrefix(pattern, "regex:"); ok {
		re, err := compileREIgnoreCase(rest, behaviorPatternRegexTimeout)
		if err != nil {
			t.log.Printf("Error checking response pattern: %v", err)
			return false, true
		}
		match, err := re.FindStringMatch(bodyStr)
		if err != nil {
			t.log.Printf("Error checking response pattern: %v", err)
			return false, true
		}
		return match != nil, true
	}
	return strings.Contains(strings.ToLower(bodyStr), strings.ToLower(pattern)), true
}

func parseStatusPattern(pattern string) (int, error) {
	rest, _ := strings.CutPrefix(pattern, "status:")
	var status int
	_, err := fmt.Sscanf(rest, "%d", &status)
	if err != nil {
		return 0, fmt.Errorf("invalid status pattern %q: %w", pattern, err)
	}
	return status, nil
}

// matchJSONPattern mirrors BehaviorJsonPatternMixin._match_json_pattern:
// "path.to.field==expected" with case-insensitive comparison, a "[]"
// segment matching any array element, and any structural mismatch or parse
// failure counting as no-match.
func matchJSONPattern(data any, pattern string) bool {
	path, expected, ok := strings.Cut(pattern, "==")
	if !ok {
		return false
	}
	path = strings.TrimSpace(path)
	expected = strings.Trim(strings.TrimSpace(expected), `"'`)

	current := data
	for _, part := range strings.Split(path, ".") {
		if strings.HasSuffix(part, "[]") {
			return matchJSONArray(current, strings.TrimSuffix(part, "[]"), expected)
		}
		asMap, ok := current.(map[string]any)
		if !ok {
			return false
		}
		next, ok := asMap[part]
		if !ok {
			return false
		}
		current = next
	}
	return strings.EqualFold(jsonScalarToString(current), expected)
}

func matchJSONArray(current any, part, expected string) bool {
	asMap, ok := current.(map[string]any)
	if !ok {
		return false
	}
	list, ok := asMap[part].([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if strings.EqualFold(jsonScalarToString(item), expected) {
			return true
		}
	}
	return false
}

// jsonScalarToString mirrors Python str() over the JSON-decoded scalar: the
// empty string renders as the empty string, booleans as lowercase true/false,
// and floats via Go's shortest round-trip formatting (Python repr).
func jsonScalarToString(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case bool:
		if value {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprintf("%v", value)
	case nil:
		return "None"
	default:
		return fmt.Sprintf("%v", value)
	}
}

// ApplyAction mirrors the BehaviorActionDispatchMixin: passive mode only
// logs, active mode bans (ban_duration override, else 3600s, reason
// "behavioral_violation"), alerts, or logs. The reference additionally
// emits agent security events, which this port does not model yet (the
// agent surface is still fail-closed).
func (t *BehaviorTracker) ApplyAction(rule BehaviorRuleConfig, clientIP, endpointID, details string) {
	// Reference _behavior_action_dispatch: the behavioral_violation event
	// rides every action path (passive included, action_taken
	// logged_only), handler behavior, metadata with the rule identity,
	// rule_type promoted to the envelope column. The active-mode
	// action_taken is the rule action itself ("log"/"alert"/"throttle"),
	// "ban" on a successful ban and "tracked" on the self-DoS refusal.
	if t.cfg.PassiveMode {
		t.emitBehaviorEvent(rule, clientIP, endpointID, details, "logged_only")
		t.logPassiveModeAction(rule, clientIP, details)
		return
	}
	switch rule.Action {
	case "ban":
		duration := rule.BanDuration
		if duration <= 0 {
			duration = DefaultBehaviorBanDurationSeconds
		}
		applied := false
		var err error
		if t.ban != nil {
			applied, err = t.ban.Ban(clientIP, duration, "behavioral_violation")
		}
		if err != nil || !applied {
			t.emitBehaviorEvent(rule, clientIP, endpointID, details, "tracked")
			return
		}
		t.emitBehaviorEvent(rule, clientIP, endpointID, details, "ban")
		t.logAtSuspiciousLevel(fmt.Sprintf("IP %s banned for behavioral violation: %s", clientIP, details))
	case "alert":
		t.emitBehaviorEvent(rule, clientIP, endpointID, details, "alert")
		t.log.Printf("ALERT - Behavioral anomaly: %s", details)
	case "log":
		t.emitBehaviorEvent(rule, clientIP, endpointID, details, "log")
		t.logAtSuspiciousLevel(fmt.Sprintf("Behavioral anomaly detected: %s", details))
	case "throttle":
		t.emitBehaviorEvent(rule, clientIP, endpointID, details, "throttle")
		t.logAtSuspiciousLevel(fmt.Sprintf("Throttling IP %s: %s", clientIP, details))
	}
}

// emitBehaviorEvent sends the behavioral_violation handler event with the
// reference envelope: the rule_type kwarg stays in metadata and is
// promoted to the envelope column (_send_behavior_event).
func (t *BehaviorTracker) emitBehaviorEvent(rule BehaviorRuleConfig, clientIP, endpointID, details, actionTaken string) {
	if bus := busFor(t.cfg); bus != nil {
		bus.SendHandlerEventFull(EventBehaviorViolation, BehaviorHandlerName, clientIP, actionTaken,
			fmt.Sprintf("Behavioral rule violated: %s", details),
			rule.RuleType,
			map[string]any{
				"endpoint":  endpointID,
				"rule_type": rule.RuleType,
				"threshold": rule.Threshold,
				"window":    rule.Window,
			})
	}
}

func (t *BehaviorTracker) logPassiveModeAction(rule BehaviorRuleConfig, clientIP, details string) {
	prefix := "[PASSIVE MODE] "
	if rule.Action == "alert" {
		t.log.Printf("%sALERT - Behavioral anomaly: %s", prefix, details)
		return
	}
	switch rule.Action {
	case "ban":
		t.logAtSuspiciousLevel(fmt.Sprintf("%sWould ban IP %s for behavioral violation: %s", prefix, clientIP, details))
	case "log":
		t.logAtSuspiciousLevel(fmt.Sprintf("%sBehavioral anomaly detected: %s", prefix, details))
	case "throttle":
		t.logAtSuspiciousLevel(fmt.Sprintf("%sWould throttle IP %s: %s", prefix, clientIP, details))
	}
}

// logAtSuspiciousLevel mirrors _log_at_level over log_suspicious_level; the
// Go logger has fixed levels, so the configured level name annotates the
// line.
func (t *BehaviorTracker) logAtSuspiciousLevel(message string) {
	level := t.cfg.LogSuspiciousLevel
	if level == "" {
		level = "WARNING"
	}
	t.log.Printf("[%s] %s", level, message)
}

// BehavioralProcessor mirrors guard_core/core/behavioral/processor.py:
// usage/frequency rules run on the request path, return_pattern rules run on
// the response path, and the global rules apply to every route.
type BehavioralProcessor struct {
	cfg     *SecurityConfig
	tracker *BehaviorTracker
	counts  *suspiciousCountStore
	log     *log.Logger
}

func NewBehavioralProcessor(cfg *SecurityConfig, tracker *BehaviorTracker, counts *suspiciousCountStore, logger *log.Logger) *BehavioralProcessor {
	if logger == nil {
		logger = log.Default()
	}
	return &BehavioralProcessor{cfg: cfg, tracker: tracker, counts: counts, log: logger}
}

// GetEndpointID mirrors get_endpoint_id: the request's per-endpoint route
// id (state.GuardRouteID) wins, then the runtime-provided guard_endpoint_id
// (state extras), else "METHOD:redacted-path". The route-id preference is
// the per-route behavioral counter contract (guard-core #141/#142): every
// endpoint that owns a route id keys its usage/return counters on it.
func (p *BehavioralProcessor) GetEndpointID(req Request) string {
	if req == nil {
		return ""
	}
	state := req.State()
	if state != nil {
		if state.GuardRouteID != "" {
			return state.GuardRouteID
		}
		if id, ok := state.Extras["guard_endpoint_id"].(string); ok && id != "" {
			return id
		}
	}
	safePath := RedactURLForDisplay(req.URLPath(), p.cfg.LogSensitiveParams, p.cfg.LogSensitiveBodyFields, p.cfg.LogSensitiveHeaders)
	return req.Method() + ":" + safePath
}

// behaviorRulesForRequest returns the rules the reference evaluates on the
// request path: only the route's decorator rules (process_usage_rules
// iterates route_config.behavior_rules); global rules feed only the return
// stage.
func routeRulesForStage(rules []BehaviorRuleConfig, kinds ...string) []BehaviorRuleConfig {
	var out []BehaviorRuleConfig
	for _, rule := range rules {
		for _, kind := range kinds {
			if rule.RuleType == kind {
				out = append(out, rule)
				break
			}
		}
	}
	return out
}

// ProcessUsageRules mirrors process_usage_rules: it evaluates the route's
// usage and frequency rules for this request and dispatches the configured
// action on threshold excess. Exclusion-scoped requests never track (the
// reference's _behavior_tracker returns None for them).
func (p *BehavioralProcessor) ProcessUsageRules(req Request, clientIP string, route *RouteConfig, now float64) {
	if p.tracker == nil || req == nil {
		return
	}
	if state := req.State(); state == nil || state.ExclusionScoped {
		return
	}
	if route == nil || len(route.BehaviorRules) == 0 {
		return
	}
	endpointID := p.GetEndpointID(req)
	for _, rule := range routeRulesForStage(route.BehaviorRules, "usage", "frequency") {
		if !p.tracker.TrackEndpointUsage(endpointID, clientIP, rule, now) {
			continue
		}
		details := fmt.Sprintf("%d calls in %ds", rule.Threshold, rule.Window)
		reason := fmt.Sprintf("Behavioral %s threshold exceeded: %s", rule.RuleType, details)
		p.log.Printf("behavioral_action_triggered: %s (endpoint=%s action=%s)", reason, endpointID, rule.Action)
		// Reference processor.process_usage_rules: decorator_violation with
		// decorator_type behavioral and the rule classification.
		emitBusEvent(p.cfg, EventDecoratorViolation, req, blockedOrLoggedAction(p.cfg.PassiveMode), reason,
			map[string]any{
				"decorator_type": "behavioral",
				"violation_type": rule.RuleType,
				"threshold":      rule.Threshold,
				"window":         rule.Window,
				"action":         rule.Action,
				"endpoint_id":    endpointID,
			})
		p.tracker.ApplyAction(rule, clientIP, endpointID, fmt.Sprintf("Usage threshold exceeded: %s", details))
	}
}

// ProcessReturnRules mirrors process_return_rules for the route's
// return_pattern rules.
func (p *BehavioralProcessor) ProcessReturnRules(req Request, resp *Response, clientIP string, route *RouteConfig, now float64) {
	if p.tracker == nil || req == nil {
		return
	}
	if state := req.State(); state == nil || state.ExclusionScoped {
		return
	}
	if route == nil {
		return
	}
	endpointID := p.GetEndpointID(req)
	for _, rule := range routeRulesForStage(route.BehaviorRules, "return_pattern") {
		if !p.tracker.TrackReturnPattern(endpointID, clientIP, resp, rule, now, 0) {
			continue
		}
		details := fmt.Sprintf("%d for '%s' in %ds", rule.Threshold, rule.Pattern, rule.Window)
		reason := fmt.Sprintf("Return pattern threshold exceeded: %s", details)
		p.log.Printf("behavioral_action_triggered: %s (endpoint=%s action=%s)", reason, endpointID, rule.Action)
		emitBusEvent(p.cfg, EventDecoratorViolation, req, blockedOrLoggedAction(p.cfg.PassiveMode), reason,
			map[string]any{
				"decorator_type": "behavioral",
				"violation_type": "return_pattern",
				"threshold":      rule.Threshold,
				"window":         rule.Window,
				"action":         rule.Action,
				"endpoint_id":    endpointID,
				"pattern":        rule.Pattern,
			})
		p.tracker.ApplyAction(rule, clientIP, endpointID, fmt.Sprintf("Return pattern threshold exceeded: %s", details))
	}
}

// ProcessGlobalReturnRules mirrors process_global_return_rules over the
// config's global rules, including the correlate_with_detection threshold
// halving driven by the suspicious-activity counts for the client IP.
func (p *BehavioralProcessor) ProcessGlobalReturnRules(req Request, resp *Response, clientIP string, now float64) {
	if p.tracker == nil || req == nil {
		return
	}
	if state := req.State(); state == nil || state.ExclusionScoped {
		return
	}
	rules := routeRulesForStage(p.cfg.GlobalBehaviorRules, "return_pattern")
	if len(rules) == 0 {
		return
	}
	endpointID := p.GetEndpointID(req)
	correlatedCategories := p.collectCorrelatedCategories(clientIP)
	for _, rule := range rules {
		correlationActive := rule.CorrelateWithDetection && len(correlatedCategories) > 0
		effectiveThreshold := rule.Threshold
		if correlationActive {
			effectiveThreshold = rule.Threshold / 2
			if effectiveThreshold < 1 {
				effectiveThreshold = 1
			}
		}
		if !p.tracker.TrackReturnPattern(endpointID, clientIP, resp, rule, now, effectiveThreshold) {
			continue
		}
		correlated := ""
		if correlationActive {
			correlated = " (correlated)"
		}
		details := fmt.Sprintf("%d for '%s' in %ds%s", effectiveThreshold, rule.Pattern, rule.Window, correlated)
		reason := fmt.Sprintf("Global return pattern threshold exceeded: %s", details)
		p.log.Printf("behavioral_action_triggered: %s (decorator_type=behavioral_global endpoint=%s action=%s correlated=%v)", reason, endpointID, rule.Action, correlationActive)
		kwargs := map[string]any{
			"decorator_type": "behavioral_global",
			"violation_type": "return_pattern",
			"threshold":      effectiveThreshold,
			"window":         rule.Window,
			"action":         rule.Action,
			"endpoint_id":    endpointID,
			"pattern":        rule.Pattern,
		}
		if correlationActive {
			kwargs["correlation"] = true
			kwargs["correlated_categories"] = correlatedCategories
		}
		emitBusEvent(p.cfg, EventDecoratorViolation, req, blockedOrLoggedAction(p.cfg.PassiveMode), reason, kwargs)
		p.tracker.ApplyAction(rule, clientIP, endpointID, reason)
	}
}

// collectCorrelatedCategories mirrors _collect_correlated_categories: the
// detection categories with a positive suspicious count for the IP, sorted.
func (p *BehavioralProcessor) collectCorrelatedCategories(clientIP string) []string {
	if p.counts == nil {
		return nil
	}
	p.counts.mu.Lock()
	perIP := p.counts.m[clientIP]
	categories := make([]string, 0, len(perIP))
	for category, n := range perIP {
		if n > 0 {
			categories = append(categories, category)
		}
	}
	p.counts.mu.Unlock()
	sort.Strings(categories)
	return categories
}
