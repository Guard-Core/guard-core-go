package guardcore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Event enrichment layer, ported from the reference
// guard_core/core/events/enricher.py and the enrichment-key constants of
// guard_core/core/events/event_types.py: every event and metric riding the
// agent stream gains the guard.* metadata keys the Guard Agent and the
// OTel/Logfire sinks consume.
//
// Parity behaviors:
//   - identity keys (project id when configured, service name always,
//     deployment environment when the resource attribute is set) ride both
//     events and metrics
//   - events additionally gain the deterministic threat score, the matched
//     dynamic rule (id + version) and the per-IP behavioral correlation pair
//   - enrichment order is identity, threat score, rule correlation, behavior
//     correlation (the reference enrich_event strategy chain)
//   - an event without a metadata map ships unenriched, exactly like the
//     reference's `metadata is None` early return (and likewise a metric
//     without a tags map)
//
// The redaction interaction is unchanged: the bus redacts endpoints and
// user agents when the event is BUILT (events.go), enrichment happens later
// on the dispatch path and only adds derived, non-sensitive guard.* keys.
// The otel/logfire handlers forward exactly those guard.* keys onward.

// Enrichment metadata keys (event_types.py ENRICHMENT_KEY_*). The dotted
// strings are the cross-language wire contract of the telemetry pipeline.
const (
	EnrichmentKeyProjectID        = "guard.project_id"
	EnrichmentKeyServiceName      = "guard.service.name"
	EnrichmentKeyDeploymentEnv    = "guard.deployment.environment"
	EnrichmentKeyThreatScore      = "guard.threat_score"
	EnrichmentKeyRuleID           = "guard.rule.id"
	EnrichmentKeyRuleVersion      = "guard.rule.version"
	EnrichmentKeyBehaviorKey      = "guard.behavior.correlation_key"
	EnrichmentKeyRecentEventCount = "guard.behavior.recent_event_count"
)

// DefaultThreatScore mirrors _DEFAULT_THREAT_SCORE: the score every event
// type outside _THREAT_SCORE_MAP receives.
const DefaultThreatScore = 20

// behaviorCorrelationWindowSeconds mirrors
// _BEHAVIOR_CORRELATION_WINDOW_SECONDS (the 300s sliding window behind both
// the recent-event count and the correlation-key time bucket).
const behaviorCorrelationWindowSeconds = 300

// DefaultOtelServiceName mirrors the reference otel_service_name default.
const DefaultOtelServiceName = "guard-core"

// threatScores mirrors _THREAT_SCORE_MAP: one deterministic score per event
// type; unknown types score DefaultThreatScore (ThreatScorer.score_for).
var threatScores = map[string]int{
	EventPenetrationAttempt:               90,
	EventIPBanned:                         70,
	EventEmergencyMode:                    60,
	EventIPBlocked:                        50,
	EventBehaviorViolation:                50,
	EventCloudBlocked:                     50,
	EventCountryBlocked:                   50,
	EventDecoratorViolation:               50,
	EventAuthenticationFailed:             50,
	EventEmergencyModeBlock:               50,
	EventDynamicRuleViolation:             50,
	EventPatternDetected:                  50,
	EventSuspiciousRequest:                50,
	EventDynamicRuleApplied:               40,
	EventCSPViolation:                     40,
	EventContentFiltered:                  40,
	EventCustomRequestCheck:               40,
	EventDecodingError:                    40,
	EventRedisError:                       40,
	EventIPBanFailed:                      40,
	EventDetectionEngineCallbackError:     40,
	EventPatternAnomalyTimeout:            40,
	EventPatternAnomalySlowExecution:      40,
	EventPatternAnomalyStatisticalAnomaly: 40,
	EventAccessDenied:                     30,
	EventUserAgentBlocked:                 30,
	EventSecurityBypass:                   30,
	EventRateLimited:                      20,
	EventGeoLookupFailed:                  20,
	EventRedisConnection:                  20,
	EventRouteUnresolved:                  20,
	EventIPUnbanned:                       10,
	EventHTTPSEnforced:                    10,
	EventDynamicRuleUpdated:               10,
	EventPathExcluded:                     10,
	EventPatternAdded:                     10,
	EventPatternRemoved:                   10,
	EventRateLimitScriptReloaded:          10,
	EventSecurityHeadersApplied:           10,
}

// ThreatScoreFor mirrors ThreatScorer.score_for: the mapped score for the
// event type, or DefaultThreatScore (20) for anything unmapped.
func ThreatScoreFor(eventType string) int {
	if score, ok := threatScores[eventType]; ok {
		return score
	}
	return DefaultThreatScore
}

// DynamicRuleMatcher is the rule-correlation seam (the reference duck-typed
// dynamic_rule_handler.match_event). *DynamicRuleManager implements it.
type DynamicRuleMatcher interface {
	MatchEvent(event SecurityEvent) (ruleID string, version int, ok bool)
}

// BehaviorCounter is the behavior-correlation seam (the reference duck-typed
// behavior_tracker.get_recent_event_count). *BehaviorTracker implements it.
type BehaviorCounter interface {
	GetRecentEventCount(ip string, windowSeconds int) int
}

// EnrichmentContext carries the enrichment dependencies (the reference
// EnrichmentContext dataclass): the identity source and the optional
// correlation handles. A nil handle skips its strategy.
type EnrichmentContext struct {
	Config             *SecurityConfig
	AgentHandler       AgentHandler
	DynamicRuleHandler DynamicRuleMatcher
	BehaviorTracker    BehaviorCounter
}

// EventEnricher populates the guard.* keys on events and metrics (the
// reference EventEnricher).
type EventEnricher struct {
	ctx EnrichmentContext
	// now is injectable so tests can pin the correlation time bucket.
	now func() time.Time
}

// NewEventEnricher wires the enricher over its context.
func NewEventEnricher(ctx EnrichmentContext) *EventEnricher {
	return &EventEnricher{ctx: ctx, now: time.Now}
}

// EnrichEvent applies the full strategy chain to the event (the reference
// enrich_event): identity, threat score, rule correlation, behavior
// correlation. A nil event or a nil metadata map ships untouched.
func (e *EventEnricher) EnrichEvent(event *SecurityEvent) {
	if e == nil || event == nil || event.Metadata == nil {
		return
	}
	e.applyIdentityMetadata(event.Metadata)
	e.applyThreatScore(event)
	e.applyRuleCorrelation(event.Metadata, event)
	e.applyBehaviorCorrelation(event.Metadata, event.IPAddress)
}

// EnrichMetric applies the identity strategy to the metric tags (the
// reference enrich_metric - metrics carry identity only). A nil metric or a
// nil tags map ships untouched.
func (e *EventEnricher) EnrichMetric(metric *SecurityMetric) {
	if e == nil || metric == nil || metric.Tags == nil {
		return
	}
	e.applyIdentityTags(metric.Tags)
}

// identityValues resolves the config identity triple (the reference
// _apply_identity): project id only when set, service name always,
// deployment environment only when the resource attribute is present.
func (e *EventEnricher) identityValues() (projectID, serviceName, deploymentEnv string) {
	cfg := e.ctx.Config
	if cfg == nil {
		return "", "", ""
	}
	return cfg.AgentProjectID, cfg.OtelServiceName, cfg.OtelResourceAttributes["deployment.environment"]
}

func (e *EventEnricher) applyIdentityMetadata(bag map[string]any) {
	projectID, serviceName, deploymentEnv := e.identityValues()
	if projectID != "" {
		bag[EnrichmentKeyProjectID] = projectID
	}
	bag[EnrichmentKeyServiceName] = serviceName
	if deploymentEnv != "" {
		bag[EnrichmentKeyDeploymentEnv] = deploymentEnv
	}
}

func (e *EventEnricher) applyIdentityTags(bag map[string]string) {
	projectID, serviceName, deploymentEnv := e.identityValues()
	if projectID != "" {
		bag[EnrichmentKeyProjectID] = projectID
	}
	bag[EnrichmentKeyServiceName] = serviceName
	if deploymentEnv != "" {
		bag[EnrichmentKeyDeploymentEnv] = deploymentEnv
	}
}

// applyThreatScore mirrors _apply_threat_score: the score rides only when
// the event carries a type.
func (e *EventEnricher) applyThreatScore(event *SecurityEvent) {
	if event.EventType == "" {
		return
	}
	event.Metadata[EnrichmentKeyThreatScore] = ThreatScoreFor(event.EventType)
}

// applyRuleCorrelation mirrors _apply_rule_correlation: with a rule handler
// whose MatchEvent answers, the rule id and version ride the event.
func (e *EventEnricher) applyRuleCorrelation(bag map[string]any, event *SecurityEvent) {
	handler := e.ctx.DynamicRuleHandler
	if handler == nil {
		return
	}
	ruleID, version, ok := handler.MatchEvent(*event)
	if !ok {
		return
	}
	bag[EnrichmentKeyRuleID] = ruleID
	bag[EnrichmentKeyRuleVersion] = version
}

// applyBehaviorCorrelation mirrors _apply_behavior_correlation: with a
// tracker and a non-empty ip, the recent event count over the 300s window
// rides, plus the deterministic correlation key
// sha256(f"{ip}|{service}|{bucket}")[:16] with bucket = unix // 300.
func (e *EventEnricher) applyBehaviorCorrelation(bag map[string]any, ip string) {
	tracker := e.ctx.BehaviorTracker
	if tracker == nil || ip == "" {
		return
	}
	bag[EnrichmentKeyRecentEventCount] = tracker.GetRecentEventCount(ip, behaviorCorrelationWindowSeconds)
	bag[EnrichmentKeyBehaviorKey] = e.behaviorKey(ip)
}

func (e *EventEnricher) behaviorKey(ip string) string {
	bucket := e.now().Unix() / behaviorCorrelationWindowSeconds
	service := ""
	if e.ctx.Config != nil {
		service = e.ctx.Config.OtelServiceName
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", ip, service, bucket)))
	return hex.EncodeToString(sum[:])[:16]
}
