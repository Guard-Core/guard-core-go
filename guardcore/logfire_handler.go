package guardcore

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// LogfireHandler ports the reference Logfire export handler
// (guard_core/core/events/logfire_handler.py): security events become
// spans named guard.event.<event_type> with the guard.* columns and the
// enrichment metadata, metrics become structured log records named
// guard.metric.<metric_type> (the reference logfire.info hop) carrying
// value, endpoint and the tags minus the duplicated columns.
//
// Divergence from the reference, by design: the Python handler calls the
// logfire SDK (whose DEFAULT_LOGFIRE_INSTANCE owns process-global
// configuration and can detect an existing configuration); the Go engine
// cannot host the SDK, so the handler speaks OTLP/HTTP JSON directly -
// the Logfire API is an OTLP endpoint - and reproduces the
// already-configured guard as a per-process claim: the first Start wins,
// a second handler's Start warns and skips its configuration exactly like
// the reference yields to a host-configured logfire.

// LogfireConfig configures LogfireHandler.
type LogfireConfig struct {
	// ServiceName is the configured service (the reference
	// logfire_service_name; the reference warns and skips configuration
	// when logfire is already configured for the process).
	ServiceName string
	// Endpoint is the OTLP/HTTP base URL. Empty defaults to the Logfire
	// API endpoint.
	Endpoint string
	// Token is the Logfire write token sent as a bearer token.
	Token string
	// ResourceAttributes are extra resource attributes.
	ResourceAttributes map[string]string
	// Timeout bounds each export POST (default 10s).
	Timeout time.Duration
	// BatchSize flushes the buffer once it holds this many records
	// (default 64).
	BatchSize int
	// Client overrides the export HTTP client.
	Client *http.Client
}

// DefaultLogfireEndpoint is the Logfire OTLP API base.
const DefaultLogfireEndpoint = "https://logfire-api.pydantic.dev"

// DefaultLogfireConfig fills the SDK-equivalent defaults.
func DefaultLogfireConfig() LogfireConfig {
	return LogfireConfig{
		ServiceName: "guard-core",
		Endpoint:    DefaultLogfireEndpoint,
		Timeout:     10 * time.Second,
		BatchSize:   64,
	}
}

// The process-wide configuration claim mirrors the reference's
// logfire.DEFAULT_LOGFIRE_INSTANCE.config._initialized check: one
// LogfireHandler per process gets to configure (its service name is
// remembered), later handlers yield with the reference's warning text.
var (
	logfireConfiguredByGuard atomic.Bool
	logfireConfiguredService atomic.Value // string
	logfireConfigureLock     sync.Mutex
)

// LogfireHandler implements AgentHandler with OTLP export toward the
// Logfire API. It satisfies the composite lifecycle surfaces
// (Start/Stop/Flush/Healthy).
type LogfireHandler struct {
	cfg    LogfireConfig
	client *http.Client

	mu    sync.Mutex
	spans []otlpSpan
	logs  []otlpRecord

	started        bool
	configuredByUs bool
	startWarned    bool
}

// NewLogfireHandler wires the handler.
func NewLogfireHandler(cfg LogfireConfig) *LogfireHandler {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "guard-core"
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultLogfireEndpoint
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 64
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &LogfireHandler{cfg: cfg, client: client}
}

// Start claims the process-wide configuration (the reference start():
// when logfire is already configured for the process, the handler warns,
// marks itself started and does not reconfigure).
func (h *LogfireHandler) Start() error {
	logfireConfigureLock.Lock()
	defer logfireConfigureLock.Unlock()
	if logfireConfiguredByGuard.Load() {
		if !h.startWarned {
			h.startWarned = true
			log.Printf(
				"logfire is already configured for this process (by a host "+
					"application or an earlier guard_core instance); guard_core "+
					"will not apply its logfire_service_name %s",
				h.cfg.ServiceName,
			)
		}
		h.mu.Lock()
		h.started = true
		h.mu.Unlock()
		return nil
	}
	logfireConfiguredByGuard.Store(true)
	logfireConfiguredService.Store(h.cfg.ServiceName)
	h.mu.Lock()
	h.started = true
	h.configuredByUs = true
	h.mu.Unlock()
	return nil
}

// Stop releases the claim when this handler configured it (the reference
// stop(): only the configuring owner calls logfire.shutdown).
func (h *LogfireHandler) Stop() error {
	logfireConfigureLock.Lock()
	if h.configuredByUs {
		logfireConfiguredByGuard.Store(false)
		logfireConfiguredService.Store("")
		h.configuredByUs = false
	}
	logfireConfigureLock.Unlock()
	if err := h.Flush(); err != nil {
		log.Printf("handler.flush_buffer failed: %v", err)
	}
	return nil
}

// Flush exports every buffered span and log record.
func (h *LogfireHandler) Flush() error {
	h.mu.Lock()
	spans := h.spans
	logs := h.logs
	h.spans = nil
	h.logs = nil
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), h.cfg.Timeout)
	defer cancel()

	var flushErr error
	if len(spans) > 0 {
		if err := postOTLP(ctx, h.client, h.cfg.Endpoint, "/v1/traces", h.cfg.Token, otlpTraceRequest{
			ResourceSpans: []otlpResourceSpans{{
				Resource: otlpResource{Attributes: otlpResourceAttributes(h.cfg.ServiceName, h.cfg.ResourceAttributes)},
				ScopeSpans: []otlpScopeSpan{{
					Scope: otlpScope{Name: "guardcore.logfire"},
					Spans: spans,
				}},
			}},
		}); err != nil {
			log.Printf("logfire span export failed: %v", err)
			flushErr = err
		}
	}
	if len(logs) > 0 {
		if err := postOTLP(ctx, h.client, h.cfg.Endpoint, "/v1/logs", h.cfg.Token, otlpLogRequest{
			ResourceLogs: []otlpResourceLogs{{
				Resource: otlpResource{Attributes: otlpResourceAttributes(h.cfg.ServiceName, h.cfg.ResourceAttributes)},
				ScopeLogs: []otlpScopeLogs{{
					Scope:      otlpScope{Name: "guardcore.logfire"},
					LogRecords: logs,
				}},
			}},
		}); err != nil {
			log.Printf("logfire log export failed: %v", err)
			flushErr = err
		}
	}
	return flushErr
}

// Healthy answers whether an export endpoint is configured (the
// reference health_check answers SDK availability).
func (h *LogfireHandler) Healthy() bool {
	return h.cfg.Endpoint != ""
}

// SendEvent buffers one security event as a span named
// guard.event.<event_type> with the reference's attribute columns and
// the guard.-prefixed enrichment metadata (traceparent/tracestate are
// dropped, exactly like the reference's enrichment dict).
func (h *LogfireHandler) SendEvent(event SecurityEvent) error {
	now := time.Now()
	start := event.Timestamp
	if start.IsZero() {
		start = now
	}
	attrs := []otlpAttribute{
		otlpStringAttr("event_type", event.EventType),
		otlpStringAttr("ip_address", event.IPAddress),
		otlpStringAttr("action_taken", event.ActionTaken),
		otlpStringAttr("reason", event.Reason),
		otlpStringAttr("endpoint", event.Endpoint),
		otlpStringAttr("method", event.Method),
	}
	if statusCode, ok := event.Metadata["status_code"]; ok {
		if code, ok := toInt64(statusCode); ok {
			attrs = append(attrs, otlpIntAttr("status_code", code))
		}
	}
	for key, value := range event.Metadata {
		if key == "traceparent" || key == "tracestate" {
			continue
		}
		if text, ok := value.(string); ok && len(key) > 6 && key[:6] == "guard." {
			attrs = append(attrs, otlpStringAttr(key, text))
		}
	}
	span := otlpSpan{
		TraceID:           randomTraceID(),
		SpanID:            randomSpanID(),
		Name:              "guard.event." + event.EventType,
		Kind:              1,
		StartTimeUnixNano: strconv.FormatInt(start.UnixNano(), 10),
		EndTimeUnixNano:   strconv.FormatInt(now.UnixNano(), 10),
		Attributes:        attrs,
	}
	h.mu.Lock()
	h.spans = append(h.spans, span)
	pending := len(h.spans)
	h.mu.Unlock()
	return h.flushIfFull(pending)
}

// SendMetric buffers one metric as a structured log record named
// guard.metric.<metric_type> carrying value, endpoint and the tags
// minus the value/endpoint columns (the reference safe_tags).
func (h *LogfireHandler) SendMetric(metric SecurityMetric) error {
	stamp := metric.Timestamp
	if stamp.IsZero() {
		stamp = time.Now()
	}
	attrs := []otlpAttribute{
		otlpDoubleAttr("value", metric.Value),
	}
	endpoint := ""
	if metric.Tags != nil {
		endpoint = metric.Tags["endpoint"]
	}
	if endpoint != "" {
		attrs = append(attrs, otlpStringAttr("endpoint", endpoint))
	}
	keys := make([]string, 0, len(metric.Tags))
	for key := range metric.Tags {
		if key == "value" || key == "endpoint" {
			continue
		}
		keys = append(keys, key)
	}
	sortStrings(keys)
	for _, key := range keys {
		attrs = append(attrs, otlpStringAttr(key, metric.Tags[key]))
	}
	record := otlpRecord{
		TimeUnixNano:         strconv.FormatInt(stamp.UnixNano(), 10),
		ObservedTimeUnixNano: strconv.FormatInt(time.Now().UnixNano(), 10),
		SeverityNumber:       9,
		SeverityText:         "INFO",
		Body:                 otlpAttributeValue{StringValue: "guard.metric." + metric.MetricType},
		Attributes:           attrs,
	}
	h.mu.Lock()
	h.logs = append(h.logs, record)
	pending := len(h.logs)
	h.mu.Unlock()
	return h.flushIfFull(pending)
}

func (h *LogfireHandler) flushIfFull(pending int) error {
	if h.cfg.BatchSize > 0 && pending >= h.cfg.BatchSize {
		return h.Flush()
	}
	return nil
}

// toInt64 widens the numeric metadata values the block hooks and checks
// stash.
func toInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		return int64(typed), true
	}
	return 0, false
}
