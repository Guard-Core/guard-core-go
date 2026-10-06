package guardcore

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// OtelHandler ports the reference OTel export handler
// (guard_core/core/events/otel_handler.py) onto a dependency-free OTLP/
// HTTP JSON exporter: security events become spans named
// guard.event.<event_type> carrying the guard.* attribute set, metrics
// become the guard.request.duration histogram and the
// guard.request.count / guard.error.count counters, and a traceparent in
// the event metadata links the span to the caller's trace (the reference
// TraceContextTextMapPropagator extraction).
//
// Divergence from the reference, by design: the Python handler glues the
// OpenTelemetry SDK into the process (global tracer/meter providers with
// claim-and-yield semantics); the Go engine cannot host the SDK (the
// dependency rules keep guardcore to three direct modules), so the
// handler exports OTLP itself and owns no global state. Start is
// therefore always successful on a valid endpoint, and repeated handlers
// never fight over process-global providers.

// OtelConfig configures OtelHandler.
type OtelConfig struct {
	// ServiceName lands in the resource service.name attribute.
	ServiceName string
	// ResourceAttributes are extra resource attributes.
	ResourceAttributes map[string]string
	// ExporterEndpoint is the OTLP/HTTP base URL, e.g.
	// http://localhost:4318. A base already ending in /v1/traces or
	// /v1/metrics is trimmed before the signal path is joined.
	ExporterEndpoint string
	// Token is the optional bearer token on every export.
	Token string
	// Timeout bounds each export POST (default 10s).
	Timeout time.Duration
	// BatchSize flushes the buffer once it holds this many records
	// (default 64).
	BatchSize int
	// FlushInterval drives the background flusher Start installs
	// (default 5s).
	FlushInterval time.Duration
	// Client overrides the export HTTP client.
	Client *http.Client
}

// DefaultOtelConfig fills the SDK-equivalent defaults.
func DefaultOtelConfig() OtelConfig {
	return OtelConfig{
		ServiceName:   "guard-core",
		Timeout:       10 * time.Second,
		BatchSize:     64,
		FlushInterval: 5 * time.Second,
	}
}

// OtelHandler implements AgentHandler with OTLP export. It satisfies the
// composite lifecycle surfaces (Start/Stop/Flush/Healthy).
type OtelHandler struct {
	cfg    OtelConfig
	client *http.Client

	mu      sync.Mutex
	spans   []otlpSpan
	points  map[string][]otlpMetricPoint
	started bool
	stopped bool

	stopOnce sync.Once
	doneCh   chan struct{}
}

type otlpMetricPoint struct {
	kind       string // "histogram" | "counter"
	timestamp  time.Time
	value      float64
	attributes []otlpAttribute
}

// NewOtelHandler wires the handler; exports stay buffered until Flush or
// the configured batch size/interval fires.
func NewOtelHandler(cfg OtelConfig) *OtelHandler {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "guard-core"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 64
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &OtelHandler{
		cfg:    cfg,
		client: client,
		points: map[string][]otlpMetricPoint{},
		doneCh: make(chan struct{}),
	}
}

// Start installs the background flusher (the reference start(): with the
// SDK it builds the providers; here it starts the periodic export loop).
func (h *OtelHandler) Start() error {
	h.mu.Lock()
	if h.started {
		h.mu.Unlock()
		return nil
	}
	h.started = true
	h.stopped = false
	h.mu.Unlock()
	go h.flushLoop()
	return nil
}

// Stop drains the buffer and stops the flusher (the reference stop()).
func (h *OtelHandler) Stop() error {
	h.stopOnce.Do(func() {
		h.mu.Lock()
		h.stopped = true
		h.mu.Unlock()
		close(h.doneCh)
	})
	return h.Flush()
}

// Flush exports every buffered span and metric point.
func (h *OtelHandler) Flush() error {
	h.mu.Lock()
	spans := h.spans
	h.spans = nil
	points := h.points
	h.points = map[string][]otlpMetricPoint{}
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), h.cfg.Timeout)
	defer cancel()

	var flushErr error
	if len(spans) > 0 {
		if err := h.exportSpans(ctx, spans); err != nil {
			log.Printf("otel span export failed: %v", err)
			flushErr = err
		}
	}
	if len(points) > 0 {
		if err := h.exportMetrics(ctx, points); err != nil {
			log.Printf("otel metric export failed: %v", err)
			flushErr = err
		}
	}
	return flushErr
}

// Healthy answers whether an export endpoint is configured (the
// reference health_check answers SDK availability).
func (h *OtelHandler) Healthy() bool {
	return h.cfg.ExporterEndpoint != ""
}

// SendEvent buffers one security event as an OTLP span: named
// guard.event.<event_type>, carrying the reference's guard.* attributes
// and parented by the metadata traceparent when present. The buffer
// auto-flushes at the batch size.
func (h *OtelHandler) SendEvent(event SecurityEvent) error {
	span := buildEventSpan(event)
	h.mu.Lock()
	h.spans = append(h.spans, span)
	full := len(h.spans) >= h.cfg.BatchSize && h.cfg.BatchSize > 0
	h.mu.Unlock()
	if full {
		return h.Flush()
	}
	return nil
}

// SendMetric buffers one metric sample on the instrument the reference
// pins per type: response_time -> guard.request.duration histogram,
// request_count -> guard.request.count counter, error_rate ->
// guard.error.count counter. Unknown types log the reference's warning
// and record nothing.
func (h *OtelHandler) SendMetric(metric SecurityMetric) error {
	var kind string
	switch metric.MetricType {
	case MetricResponseTime:
		kind = "histogram"
	case MetricRequestCount, MetricErrorRate:
		kind = "counter"
	default:
		log.Printf("Unknown OTEL metric type %s - no instrument recorded", metric.MetricType)
		return nil
	}
	point := otlpMetricPoint{
		kind:      kind,
		timestamp: metric.Timestamp,
		value:     metric.Value,
	}
	keys := make([]string, 0, len(metric.Tags))
	for key := range metric.Tags {
		keys = append(keys, key)
	}
	sortStrings(keys)
	for _, key := range keys {
		point.attributes = append(point.attributes, otlpStringAttr(key, metric.Tags[key]))
	}
	h.mu.Lock()
	h.points[metric.MetricType] = append(h.points[metric.MetricType], point)
	full := len(h.points[metric.MetricType]) >= h.cfg.BatchSize && h.cfg.BatchSize > 0
	h.mu.Unlock()
	if full {
		return h.Flush()
	}
	return nil
}

// buildEventSpan mirrors the reference span shape: guard.* columns,
// enrichment metadata forwarded (guard.-prefixed keys except the W3C
// trace carriers), traceparent linkage.
func buildEventSpan(event SecurityEvent) otlpSpan {
	now := time.Now()
	start := event.Timestamp
	if start.IsZero() {
		start = now
	}
	linked, linkedOK := traceContext{}, false
	attrs := []otlpAttribute{
		otlpStringAttr("guard.event_type", event.EventType),
		otlpStringAttr("guard.ip_address", event.IPAddress),
		otlpStringAttr("guard.action_taken", event.ActionTaken),
		otlpStringAttr("guard.reason", event.Reason),
		otlpStringAttr("guard.endpoint", event.Endpoint),
		otlpStringAttr("guard.method", event.Method),
	}
	for key, value := range event.Metadata {
		switch key {
		case "traceparent":
			if text, ok := value.(string); ok {
				if parsed, ok := parseTraceparent(text); ok {
					linked, linkedOK = parsed, true
				}
			}
			continue
		case "tracestate":
			continue
		}
		// Enrichment keys start with "guard." (the reference forwards
		// only those).
		text, ok := value.(string)
		if !ok {
			continue
		}
		if len(key) > 6 && key[:6] == "guard." {
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
	if linkedOK {
		span.TraceID = linked.TraceID
		span.SpanID = linked.SpanID
		span.ParentSpanID = linked.ParentID
	}
	return span
}

func (h *OtelHandler) exportSpans(ctx context.Context, spans []otlpSpan) error {
	return postOTLP(ctx, h.client, h.cfg.ExporterEndpoint, "/v1/traces", h.cfg.Token, otlpTraceRequest{
		ResourceSpans: []otlpResourceSpans{{
			Resource: otlpResource{Attributes: otlpResourceAttributes(h.cfg.ServiceName, h.cfg.ResourceAttributes)},
			ScopeSpans: []otlpScopeSpan{{
				Scope: otlpScope{Name: "guardcore.otel"},
				Spans: spans,
			}},
		}},
	})
}

func (h *OtelHandler) exportMetrics(ctx context.Context, points map[string][]otlpMetricPoint) error {
	now := time.Now()
	var metrics []otlpWire
	if histPoints, ok := points[MetricResponseTime]; ok && len(histPoints) > 0 {
		dataPoints := make([]otlpHistogramPoint, 0, len(histPoints))
		sum, min, max := 0.0, 0.0, 0.0
		for i, point := range histPoints {
			if i == 0 || point.value < min {
				min = point.value
			}
			if i == 0 || point.value > max {
				max = point.value
			}
			sum += point.value
			dataPoints = append(dataPoints, otlpHistogramPoint{
				StartTimeUnixNano: strconv.FormatInt(point.timestamp.UnixNano(), 10),
				TimeUnixNano:      strconv.FormatInt(point.timestamp.UnixNano(), 10),
				Count:             "1",
				Sum:               point.value,
				Min:               min,
				Max:               max,
				Attributes:        point.attributes,
			})
		}
		hist, err := json.Marshal(otlpHistogram{DataPoints: dataPoints, AggregationTemporality: 2})
		if err != nil {
			return err
		}
		metrics = append(metrics, otlpWire{
			Name:      "guard.request.duration",
			Unit:      "s",
			Histogram: hist,
		})
	}
	for _, metricType := range []string{MetricRequestCount, MetricErrorRate} {
		counterPoints, ok := points[metricType]
		if !ok || len(counterPoints) == 0 {
			continue
		}
		dataPoints := make([]otlpSumPoint, 0, len(counterPoints))
		for _, point := range counterPoints {
			stamp := point.timestamp
			if stamp.IsZero() {
				stamp = now
			}
			dataPoints = append(dataPoints, otlpSumPoint{
				StartTimeUnixNano: strconv.FormatInt(stamp.UnixNano(), 10),
				TimeUnixNano:      strconv.FormatInt(stamp.UnixNano(), 10),
				AsDouble:          point.value,
				Attributes:        point.attributes,
			})
		}
		sum, err := json.Marshal(otlpSum{DataPoints: dataPoints, AggregationTemporality: 2, IsMonotonic: metricType == MetricRequestCount})
		if err != nil {
			return err
		}
		metrics = append(metrics, otlpWire{Name: metricOtelName(metricType), Sum: sum})
	}
	if len(metrics) == 0 {
		return nil
	}
	return postOTLP(ctx, h.client, h.cfg.ExporterEndpoint, "/v1/metrics", h.cfg.Token, otlpMetricRequest{
		ResourceMetrics: []otlpResourceMetrics{{
			Resource: otlpResource{Attributes: otlpResourceAttributes(h.cfg.ServiceName, h.cfg.ResourceAttributes)},
			ScopeMetrics: []otlpScopeMetric{{
				Scope:   otlpScope{Name: "guardcore.otel"},
				Metrics: metrics,
			}},
		}},
	})
}

// metricOtelName maps the metric vocabulary onto the reference instrument
// names.
func metricOtelName(metricType string) string {
	switch metricType {
	case MetricRequestCount:
		return "guard.request.count"
	case MetricErrorRate:
		return "guard.error.count"
	}
	return metricType
}

func (h *OtelHandler) flushLoop() {
	ticker := time.NewTicker(h.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.doneCh:
			return
		case <-ticker.C:
			_ = h.Flush()
		}
	}
}
