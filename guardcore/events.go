package guardcore

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// Security event bus and metrics collector, ported from the reference
// event layer (guard_core/core/events/event_types.py, middleware_events.py,
// metrics.py): the observable event stream the Guard Agent consumes. The
// event names and payload shapes are the cross-language contract of spec
// 12; the vocabulary test pins every string.

// Event-type vocabulary (event_types.py). The two string/constant
// asymmetries the spec calls out are reproduced verbatim:
// EventBehaviorViolation is behavioral_violation (not behavior_violation)
// and EventEmergencyMode is emergency_mode_activated.
const (
	EventPenetrationAttempt      = "penetration_attempt"
	EventIPBlocked               = "ip_blocked"
	EventIPBanned                = "ip_banned"
	EventIPBanFailed             = "ip_ban_failed"
	EventIPUnbanned              = "ip_unbanned"
	EventCloudBlocked            = "cloud_blocked"
	EventHTTPSEnforced           = "https_enforced"
	EventDecoratorViolation      = "decorator_violation"
	EventBehaviorViolation       = "behavioral_violation"
	EventPatternDetected         = "pattern_detected"
	EventDynamicRuleUpdated      = "dynamic_rule_updated"
	EventDynamicRuleApplied      = "dynamic_rule_applied"
	EventDynamicRuleViolation    = "dynamic_rule_violation"
	EventEmergencyMode           = "emergency_mode_activated"
	EventAccessDenied            = "access_denied"
	EventAuthenticationFailed    = "authentication_failed"
	EventContentFiltered         = "content_filtered"
	EventCountryBlocked          = "country_blocked"
	EventCSPViolation            = "csp_violation"
	EventCustomRequestCheck      = "custom_request_check"
	EventDecodingError           = "decoding_error"
	EventEmergencyModeBlock      = "emergency_mode_block"
	EventGeoLookupFailed         = "geo_lookup_failed"
	EventPathExcluded            = "path_excluded"
	EventPatternAdded            = "pattern_added"
	EventPatternRemoved          = "pattern_removed"
	EventRateLimited             = "rate_limited"
	EventRateLimitScriptReloaded = "rate_limit_script_reloaded"
	EventRedisConnection         = "redis_connection"
	EventRedisError              = "redis_error"
	EventRouteUnresolved         = "route_unresolved"
	EventSecurityBypass          = "security_bypass"
	EventSecurityHeadersApplied  = "security_headers_applied"
	EventUserAgentBlocked        = "user_agent_blocked"
	EventSuspiciousRequest       = "suspicious_request"

	// The four detection-engine anomaly and callback-error names
	// (detection_engine_callback_error, pattern_anomaly_timeout,
	// pattern_anomaly_slow_execution,
	// pattern_anomaly_statistical_anomaly) are declared by the
	// performance monitor port (performance_monitor.go, PR 41), which
	// merges ahead of this branch; EventVocabulary reuses them from
	// there so the package never redeclares an event name.
)

// EventVocabulary returns every event-type string in EVENT_TYPE_VALUES.
func EventVocabulary() []string {
	return []string{
		EventPenetrationAttempt, EventIPBlocked, EventIPBanned, EventIPBanFailed,
		EventIPUnbanned, EventCloudBlocked, EventHTTPSEnforced,
		EventDecoratorViolation, EventBehaviorViolation, EventPatternDetected,
		EventDynamicRuleUpdated, EventDynamicRuleApplied, EventDynamicRuleViolation,
		EventEmergencyMode, EventAccessDenied, EventAuthenticationFailed,
		EventContentFiltered, EventCountryBlocked, EventCSPViolation,
		EventCustomRequestCheck, EventDecodingError, EventEmergencyModeBlock,
		EventGeoLookupFailed, EventPathExcluded, EventPatternAdded,
		EventPatternRemoved, EventRateLimited, EventRateLimitScriptReloaded,
		EventRedisConnection, EventRedisError, EventRouteUnresolved,
		EventSecurityBypass, EventSecurityHeadersApplied, EventUserAgentBlocked,
		EventSuspiciousRequest, EventDetectionEngineCallbackError,
		EventPatternAnomalyTimeout, EventPatternAnomalySlowExecution,
		EventPatternAnomalyStatisticalAnomaly,
	}

}

// Metric-type identifiers (event_types.py).
const (
	MetricResponseTime = "response_time"
	MetricRequestCount = "request_count"
	MetricErrorRate    = "error_rate"
)

// MetricVocabulary returns every metric-type string in METRIC_TYPE_VALUES.
func MetricVocabulary() []string {
	return []string{MetricResponseTime, MetricRequestCount, MetricErrorRate}
}

// Handler names the reference pins per emitter family.
const (
	MiddlewareHandlerName   = "middleware"
	IPBanHandlerName        = "ip_ban"
	RateLimitHandlerName    = "rate_limit"
	BehaviorHandlerName     = "behavior"
	DynamicRulesHandlerName = "dynamic_rules"
	CloudHandlerName        = "cloud"
	IPInfoHandlerName       = "ipinfo"
)

// EventFilter suppresses by exact type string (event_types.EventFilter).
type EventFilter struct {
	MutedEventTypes  map[string]bool
	MutedMetricTypes map[string]bool
}

// IsEventAllowed answers the event mute gate.
func (f EventFilter) IsEventAllowed(eventType string) bool {
	return !f.MutedEventTypes[eventType]
}

// IsMetricAllowed answers the metric mute gate.
func (f EventFilter) IsMetricAllowed(metricType string) bool {
	return !f.MutedMetricTypes[metricType]
}

// SecurityEvent is the reference SecurityEvent envelope
// (middleware_events._build_event). Field names match the reference's
// payload keys.
type SecurityEvent struct {
	Timestamp      time.Time      `json:"timestamp"`
	EventType      string         `json:"event_type"`
	IPAddress      string         `json:"ip_address"`
	Country        string         `json:"country,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
	ActionTaken    string         `json:"action_taken"`
	Reason         string         `json:"reason"`
	Endpoint       string         `json:"endpoint,omitempty"`
	Method         string         `json:"method,omitempty"`
	ResponseTime   float64        `json:"response_time,omitempty"`
	DecoratorType  string         `json:"decorator_type,omitempty"`
	RuleType       string         `json:"rule_type,omitempty"`
	HandlerName    string         `json:"handler_name"`
	PatternMatched string         `json:"pattern_matched,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// SecurityMetric is the reference SecurityMetric envelope (metrics.py).
type SecurityMetric struct {
	Timestamp  time.Time         `json:"timestamp"`
	MetricType string            `json:"metric_type"`
	Value      float64           `json:"value"`
	Tags       map[string]string `json:"tags"`
}

// AgentHandler is the guard-agent telemetry surface the bus forwards to
// (the reference agent_handler.send_event / send_metric). Implementations
// must be safe for concurrent use; the engine treats delivery as
// fire-and-forget and never propagates send errors to the request path.
type AgentHandler interface {
	SendEvent(event SecurityEvent) error
	SendMetric(metric SecurityMetric) error
}

// agentPipeline is the per-config agent stream the engine installs at
// construction: the bus, the metrics collector, and the handler-direct
// emitters all ride it. A nil pipeline (no AgentHandler configured) makes
// every emission a no-op, exactly like the reference's agentless mode.
type agentPipeline struct {
	handler  AgentHandler
	geo      CountryResolver
	cfg      *SecurityConfig
	filter   EventFilter
	enricher *EventEnricher
	bus      *SecurityEventBus
	metrics  *MetricsCollector
}

// newAgentPipeline wires the stream; the geo resolver is attached later
// by the Engine once the config's GeoIPHandler is resolved.
func newAgentPipeline(handler AgentHandler, cfg *SecurityConfig, filter EventFilter) *agentPipeline {
	pipeline := &agentPipeline{handler: handler, cfg: cfg, filter: filter}
	pipeline.bus = &SecurityEventBus{handler: handler, cfg: cfg, geo: cfg.GeoIPHandler, filter: filter}
	pipeline.metrics = &MetricsCollector{handler: handler, cfg: cfg, filter: filter}
	return pipeline
}

// attachGeoResolver points the bus's country column at the config's
// resolved GeoIP handler (the Engine calls this once the Validate pass
// has built the built-in manager).
func (p *agentPipeline) attachGeoResolver(resolver CountryResolver) {
	p.geo = resolver
	p.bus.geo = resolver
}

// attachDynamicRuleMatcher hands the enricher the live DynamicRuleManager
// once the Engine builds it (the reference build_enricher constructing the
// rule handle when enable_dynamic_rules is on). A nil matcher or an
// enrichment-less pipeline is a no-op; rule correlation keys then never ride.
func (p *agentPipeline) attachDynamicRuleMatcher(matcher DynamicRuleMatcher) {
	if p == nil || p.enricher == nil || matcher == nil {
		return
	}
	p.enricher.ctx.DynamicRuleHandler = matcher
}

// agentPipelineFor returns the config's installed pipeline, or nil.
func agentPipelineFor(cfg *SecurityConfig) *agentPipeline {
	if cfg == nil {
		return nil
	}
	return cfg.agent
}

// SecurityEventBus builds SecurityEvent records and forwards them to the
// agent handler (middleware_events.SecurityEventBus). Bus-routed events
// respect the agent_enable_events gate; handler-direct emitters do not
// (spec 12, Discrepancies).
type SecurityEventBus struct {
	handler AgentHandler
	cfg     *SecurityConfig
	geo     CountryResolver
	filter  EventFilter
}

// NewSecurityEventBus wires the bus.
func NewSecurityEventBus(handler AgentHandler, cfg *SecurityConfig, geo CountryResolver, filter EventFilter) *SecurityEventBus {
	return &SecurityEventBus{handler: handler, cfg: cfg, geo: geo, filter: filter}
}

// lookupCountry mirrors _lookup_country: a resolver failure logs and
// yields an empty country; the event is still sent.
func (b *SecurityEventBus) lookupCountry(clientIP string) string {
	if b.geo == nil {
		return ""
	}
	country, _ := b.geo.GetCountry(clientIP)
	return country
}

// forwardTraceHeaders mirrors _forward_trace_headers: traceparent and
// tracestate ride the metadata when present and not already set. The
// caller guarantees a non-nil map (cloneMetadata).
func forwardTraceHeaders(req Request, metadata map[string]any) map[string]any {
	headers := req.Headers()
	for _, header := range []string{"traceparent", "tracestate"} {
		if value, ok := headers.Get(header); ok && value != "" {
			if _, exists := metadata[header]; !exists {
				metadata[header] = value
			}
		}
	}
	return metadata
}

// SendMiddlewareEvent mirrors send_middleware_event: gated by the agent
// presence and the agent_enable_events flag, muted by the filter, and
// delivering the full envelope with handler_name "middleware".
func (b *SecurityEventBus) SendMiddlewareEvent(eventType string, req Request, actionTaken, reason string, kwargs map[string]any) {
	if b == nil || b.handler == nil || b.cfg == nil || !b.cfg.AgentEnableEvents {
		return
	}
	if !b.filter.IsEventAllowed(eventType) {
		return
	}
	clientIP := resolveClientIP(req)
	if clientIP == "" {
		clientIP = UnknownClientIdentity
	}
	decoratorType, _ := kwargs["decorator_type"].(string)
	ruleType, _ := kwargs["rule_type"].(string)
	metadata := forwardTraceHeaders(req, cloneMetadata(kwargs))
	var userAgent string
	if raw, ok := req.Headers().Get("User-Agent"); ok && raw != "" {
		userAgent = RedactHeaderValueForDisplay(raw, b.cfg.LogSensitiveParams, b.cfg.LogSensitiveBodyFields, b.cfg.LogSensitiveHeaders)
	}
	event := SecurityEvent{
		Timestamp:     time.Now().UTC(),
		EventType:     eventType,
		IPAddress:     clientIP,
		Country:       b.lookupCountry(clientIP),
		UserAgent:     userAgent,
		ActionTaken:   actionTaken,
		Reason:        reason,
		Endpoint:      redactEndpointForDisplay(req.URLPath(), b.cfg),
		Method:        req.Method(),
		ResponseTime:  pipelineResponseTime(req),
		DecoratorType: decoratorType,
		RuleType:      ruleType,
		HandlerName:   MiddlewareHandlerName,
		Metadata:      metadata,
	}
	if err := b.handler.SendEvent(event); err != nil {
		log.Printf("Failed to send security event to agent: %v", err)
	}
}

// SendHTTPSViolationEvent mirrors send_https_violation_event: a
// route-level require_https reports decorator_violation with the
// authentication decorator type, global enforcement reports
// https_enforced; both carry the original scheme and the redacted
// https-swapped redirect URL.
func (b *SecurityEventBus) SendHTTPSViolationEvent(req Request, route *RouteConfig) {
	redirectURL := redactEndpointForDisplay(req.URLReplaceScheme("https"), b.cfg)
	kwargs := map[string]any{
		"original_scheme": req.URLScheme(),
		"redirect_url":    redirectURL,
	}
	if route != nil && route.RequireHTTPS {
		kwargs["decorator_type"] = "authentication"
		kwargs["violation_type"] = "require_https"
		b.SendMiddlewareEvent(EventDecoratorViolation, req, "https_redirect",
			"Route requires HTTPS but request was HTTP", kwargs)
		return
	}
	b.SendMiddlewareEvent(EventHTTPSEnforced, req, "https_redirect",
		"HTTP request redirected to HTTPS for security", kwargs)
}

// SendHandlerEvent is the handler-direct emitter the spec carves out of
// the bus gate ("the bus's agent_enable_events gate does not apply to
// handler-direct emitters"): ip_ban, rate_limit, behavior, dynamic_rules,
// cloud and ipinfo deliver their own envelopes with their handler_name
// and only the bus's envelope hygiene (timestamp, logged send failures).
// Like the reference handlers (_ipban_events.py, ratelimit_handler.py,
// _dynamic_rule_events.py, cloud_handler.py, ipinfo_handler.py), these
// emitters never consult the event filter: the mute lists gate the
// middleware stream and the metrics, not the handler families.
func (b *SecurityEventBus) SendHandlerEvent(eventType string, handlerName string, ipAddress, actionTaken, reason string, metadata map[string]any) {
	b.SendHandlerEventFull(eventType, handlerName, ipAddress, actionTaken, reason, "", metadata)
}

// SendHandlerEventFull is SendHandlerEvent with the optional envelope
// columns the reference sets on some handler-family events (rule_type on
// the behavioral violation and the geo country_blocked hop): kwargs stay
// in metadata and the promoted columns mirror _send_behavior_event /
// check_country_access.
func (b *SecurityEventBus) SendHandlerEventFull(eventType string, handlerName string, ipAddress, actionTaken, reason, ruleType string, metadata map[string]any) {
	if b == nil || b.handler == nil {
		return
	}
	if metadata == nil {
		// The reference SecurityEvent model defaults metadata to an empty
		// dict, so every emission is enrichment-eligible; a nil map here
		// would ship the event unenriched (enricher.py's `metadata is
		// None` early return).
		metadata = map[string]any{}
	}
	event := SecurityEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   eventType,
		IPAddress:   ipAddress,
		ActionTaken: actionTaken,
		Reason:      reason,
		RuleType:    ruleType,
		HandlerName: handlerName,
		Metadata:    metadata,
	}
	if err := b.handler.SendEvent(event); err != nil {
		log.Printf("Failed to send %s event to agent: %v", handlerName, err)
	}
}

// SendHandlerEventRequest is the handler-direct emitter with the full
// middleware envelope columns (the reference _send_rate_limit_event shape:
// the manager quotes endpoint, method and the pipeline response_time over
// its own handler name). Like the other handler-direct emitters it never
// consults the agent_enable_events gate or the mute filter.
func (b *SecurityEventBus) SendHandlerEventRequest(eventType string, handlerName string, req Request, actionTaken, reason, ruleType string, kwargs map[string]any) {
	if b == nil || b.handler == nil {
		return
	}
	metadata := forwardTraceHeaders(req, cloneMetadata(kwargs))
	var userAgent string
	if raw, ok := req.Headers().Get("User-Agent"); ok && raw != "" {
		userAgent = RedactHeaderValueForDisplay(raw, b.logSensitiveParams(), b.logSensitiveBodyFields(), b.logSensitiveHeaders())
	}
	decoratorType, _ := kwargs["decorator_type"].(string)
	event := SecurityEvent{
		Timestamp:     time.Now().UTC(),
		EventType:     eventType,
		IPAddress:     resolveClientIP(req),
		Country:       b.lookupCountry(resolveClientIP(req)),
		UserAgent:     userAgent,
		ActionTaken:   actionTaken,
		Reason:        reason,
		Endpoint:      redactEndpointForDisplay(req.URLPath(), b.cfg),
		Method:        req.Method(),
		ResponseTime:  pipelineResponseTime(req),
		DecoratorType: decoratorType,
		RuleType:      ruleType,
		HandlerName:   handlerName,
		Metadata:      metadata,
	}
	if err := b.handler.SendEvent(event); err != nil {
		log.Printf("Failed to send %s event to agent: %v", handlerName, err)
	}
}

// log-sensitive accessors tolerate a nil config (handler-direct emitters
// can run on a bus built without one).
func (b *SecurityEventBus) logSensitiveParams() map[string]bool {
	if b.cfg == nil {
		return nil
	}
	return b.cfg.LogSensitiveParams
}

func (b *SecurityEventBus) logSensitiveBodyFields() map[string]bool {
	if b.cfg == nil {
		return nil
	}
	return b.cfg.LogSensitiveBodyFields
}

func (b *SecurityEventBus) logSensitiveHeaders() map[string]bool {
	if b.cfg == nil {
		return nil
	}
	return b.cfg.LogSensitiveHeaders
}

// MetricsCollector mirrors metrics.MetricsCollector: gated by the agent
// handler and the agent_enable_metrics flag, muted by the filter.
type MetricsCollector struct {
	handler AgentHandler
	cfg     *SecurityConfig
	filter  EventFilter
}

// NewMetricsCollector wires the collector.
func NewMetricsCollector(handler AgentHandler, cfg *SecurityConfig, filter EventFilter) *MetricsCollector {
	return &MetricsCollector{handler: handler, cfg: cfg, filter: filter}
}

// SendMetric mirrors send_metric.
func (c *MetricsCollector) SendMetric(metricType string, value float64, tags map[string]string) {
	if c == nil || c.handler == nil || c.cfg == nil || !c.cfg.AgentEnableMetrics {
		return
	}
	if !c.filter.IsMetricAllowed(metricType) {
		return
	}
	if tags == nil {
		tags = map[string]string{}
	}
	metric := SecurityMetric{
		Timestamp:  time.Now().UTC(),
		MetricType: metricType,
		Value:      value,
		Tags:       tags,
	}
	if err := c.handler.SendMetric(metric); err != nil {
		log.Printf("Failed to send metric to agent: %v", err)
	}
}

// CollectRequestMetrics mirrors collect_request_metrics: response_time,
// request_count, and error_rate (only for status >= 400), all tagged with
// the redacted endpoint and method, error_rate and response_time with the
// string status.
func (c *MetricsCollector) CollectRequestMetrics(req Request, responseTime float64, statusCode int) {
	if c == nil || c.handler == nil || c.cfg == nil || !c.cfg.AgentEnableMetrics {
		return
	}
	endpoint := redactEndpointForDisplay(req.URLPath(), c.cfg)
	method := req.Method()
	status := fmt.Sprintf("%d", statusCode)
	c.SendMetric(MetricResponseTime, responseTime, map[string]string{
		"endpoint": endpoint, "method": method, "status": status,
	})
	c.SendMetric(MetricRequestCount, 1.0, map[string]string{
		"endpoint": endpoint, "method": method,
	})
	if statusCode >= 400 {
		c.SendMetric(MetricErrorRate, 1.0, map[string]string{
			"endpoint": endpoint, "method": method, "status": status,
		})
	}
}

func cloneMetadata(kwargs map[string]any) map[string]any {
	metadata := make(map[string]any, len(kwargs))
	for k, v := range kwargs {
		metadata[k] = v
	}
	return metadata
}

// redactEndpointForDisplay applies the reference redact_endpoint_for_display
// over the path with the config's sensitive log sets.
func redactEndpointForDisplay(path string, cfg *SecurityConfig) string {
	query := map[string]string{}
	if parsed, ok := splitURLQuery(path); ok {
		path, query = parsed.path, parsed.query
	}
	var sensitiveParams map[string]bool
	if cfg != nil {
		sensitiveParams = cfg.LogSensitiveParams
	}
	return redactURLForDisplay(path, query, sensitiveParams)
}

type urlParts struct {
	path  string
	query map[string]string
}

func splitURLQuery(rawURL string) (urlParts, bool) {
	idx := strings.IndexByte(rawURL, '?')
	if idx < 0 {
		return urlParts{}, false
	}
	query := map[string]string{}
	for _, pair := range strings.Split(rawURL[idx+1:], "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		query[urlQueryUnescape(key)] = value
	}
	return urlParts{path: rawURL[:idx], query: query}, true
}

func urlQueryUnescape(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '%' && i+2 < len(value) {
			hi, ok1 := queryHexVal(value[i+1])
			lo, ok2 := queryHexVal(value[i+2])
			if ok1 && ok2 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func queryHexVal(ch byte) (int, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0'), true
	case ch >= 'a' && ch <= 'f':
		return int(ch-'a') + 10, true
	case ch >= 'A' && ch <= 'F':
		return int(ch-'A') + 10, true
	}
	return 0, false
}

// pipelineResponseTime reads the request's pipeline start stamp the
// Engine sets at dispatch; an unstamped request reports 0.
func pipelineResponseTime(req Request) float64 {
	state := req.State()
	if state == nil || state.PipelineStartedAt.IsZero() {
		return 0
	}
	return time.Since(state.PipelineStartedAt).Seconds()
}
