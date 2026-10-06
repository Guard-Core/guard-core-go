package guardcore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Shared OTLP/HTTP JSON wire encoding for the export handlers. The
// engine carries no OpenTelemetry SDK dependency (the dependency rules
// keep guardcore to three direct modules), so the exporters speak the
// OTLP/HTTP JSON protocol directly: every collector, vendor endpoint and
// the Logfire API accepts it.

type otlpAttributeValue struct {
	StringValue string   `json:"stringValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
	IntValue    string   `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
}

type otlpAttribute struct {
	Key   string             `json:"key"`
	Value otlpAttributeValue `json:"value"`
}

func otlpStringAttr(key, value string) otlpAttribute {
	return otlpAttribute{Key: key, Value: otlpAttributeValue{StringValue: value}}
}

func otlpIntAttr(key string, value int64) otlpAttribute {
	return otlpAttribute{Key: key, Value: otlpAttributeValue{IntValue: strconv.FormatInt(value, 10)}}
}

func otlpDoubleAttr(key string, value float64) otlpAttribute {
	double := value
	return otlpAttribute{Key: key, Value: otlpAttributeValue{DoubleValue: &double}}
}

func otlpBoolAttr(key string, value bool) otlpAttribute {
	return otlpAttribute{Key: key, Value: otlpAttributeValue{BoolValue: &value}}
}

// otlpResourceAttributes builds the resource column: service.name plus
// the configured extras, service.name first.
func otlpResourceAttributes(serviceName string, extra map[string]string) []otlpAttribute {
	attrs := []otlpAttribute{otlpStringAttr("service.name", serviceName)}
	keys := make([]string, 0, len(extra))
	for key := range extra {
		keys = append(keys, key)
	}
	sortStrings(keys)
	for _, key := range keys {
		attrs = append(attrs, otlpStringAttr(key, extra[key]))
	}
	return attrs
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// traceContext is the parsed W3C traceparent linkage an event metadata
// can carry (the reference _extract_parent_context).
type traceContext struct {
	TraceID  string
	SpanID   string
	ParentID string
}

// parseTraceparent parses the version-00 traceparent header:
// 00-<32 hex trace id>-<16 hex span id>-<2 hex flags>.
func parseTraceparent(value string) (traceContext, bool) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != 4 || parts[0] != "00" {
		return traceContext{}, false
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return traceContext{}, false
	}
	if !isHex(parts[1]) || !isHex(parts[2]) || !isHex(parts[3]) {
		return traceContext{}, false
	}
	if parts[1] == "00000000000000000000000000000000" || parts[2] == "0000000000000000" {
		return traceContext{}, false
	}
	return traceContext{TraceID: parts[1], SpanID: randomSpanID(), ParentID: parts[2]}, true
}

func isHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func randomTraceID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		for i := range buf {
			buf[i] = byte(i)
		}
	}
	return hex.EncodeToString(buf[:])
}

func randomSpanID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		for i := range buf {
			buf[i] = byte(i + 16)
		}
	}
	return hex.EncodeToString(buf[:])
}

// otlpSpan is the ExportTraceServiceRequest span record.
type otlpSpan struct {
	TraceID           string          `json:"traceId"`
	SpanID            string          `json:"spanId"`
	ParentSpanID      string          `json:"parentSpanId,omitempty"`
	Name              string          `json:"name"`
	Kind              int             `json:"kind"`
	StartTimeUnixNano string          `json:"startTimeUnixNano"`
	EndTimeUnixNano   string          `json:"endTimeUnixNano"`
	Attributes        []otlpAttribute `json:"attributes,omitempty"`
}

// otlpTraceRequest is the ExportTraceServiceRequest envelope.
type otlpTraceRequest struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	Resource   otlpResource    `json:"resource"`
	ScopeSpans []otlpScopeSpan `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpAttribute `json:"attributes"`
}

type otlpScopeSpan struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpScope struct {
	Name string `json:"name"`
}

// otlpMetricRequest is the ExportMetricsServiceRequest envelope.
type otlpMetricRequest struct {
	ResourceMetrics []otlpResourceMetrics `json:"resourceMetrics"`
}

type otlpResourceMetrics struct {
	Resource     otlpResource      `json:"resource"`
	ScopeMetrics []otlpScopeMetric `json:"scopeMetrics"`
}

type otlpScopeMetric struct {
	Scope   otlpScope  `json:"scope"`
	Metrics []otlpWire `json:"metrics"`
}

// otlpWire carries either a histogram or a sum payload; json is built by
// hand for the union so omitempty keeps the shape legal.
type otlpWire struct {
	Name      string          `json:"name"`
	Unit      string          `json:"unit,omitempty"`
	Histogram json.RawMessage `json:"histogram,omitempty"`
	Sum       json.RawMessage `json:"sum,omitempty"`
}

type otlpHistogram struct {
	DataPoints             []otlpHistogramPoint `json:"dataPoints"`
	AggregationTemporality int                  `json:"aggregationTemporality"`
}

type otlpHistogramPoint struct {
	StartTimeUnixNano string          `json:"startTimeUnixNano"`
	TimeUnixNano      string          `json:"timeUnixNano"`
	Count             string          `json:"count"`
	Sum               float64         `json:"sum"`
	Min               float64         `json:"min"`
	Max               float64         `json:"max"`
	Attributes        []otlpAttribute `json:"attributes,omitempty"`
}

type otlpSum struct {
	DataPoints             []otlpSumPoint `json:"dataPoints"`
	AggregationTemporality int            `json:"aggregationTemporality"`
	IsMonotonic            bool           `json:"isMonotonic"`
}

type otlpSumPoint struct {
	StartTimeUnixNano string          `json:"startTimeUnixNano"`
	TimeUnixNano      string          `json:"timeUnixNano"`
	AsDouble          float64         `json:"asDouble"`
	Attributes        []otlpAttribute `json:"attributes,omitempty"`
}

// otlpLogRequest is the ExportLogsServiceRequest envelope (the Logfire
// metric hop: metrics surface as structured log records).
type otlpLogRequest struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpScopeLogs struct {
	Scope      otlpScope    `json:"scope"`
	LogRecords []otlpRecord `json:"logRecords"`
}

type otlpRecord struct {
	TimeUnixNano         string             `json:"timeUnixNano"`
	ObservedTimeUnixNano string             `json:"observedTimeUnixNano"`
	SeverityNumber       int                `json:"severityNumber"`
	SeverityText         string             `json:"severityText"`
	Body                 otlpAttributeValue `json:"body"`
	Attributes           []otlpAttribute    `json:"attributes,omitempty"`
}

// postOTLP delivers one envelope to the signal endpoint. The path is
// joined onto the configured base with the reference's signal-aware
// trimming (otel_handler._otlp_signal_endpoint): a base already ending in
// a known signal path loses it first.
func postOTLP(ctx context.Context, client *http.Client, base, signalPath string, token string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("otlp encode: %w", err)
	}
	endpoint := otlpSignalEndpoint(base, signalPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("otlp export to %s: %w", endpoint, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp export to %s: status %d", endpoint, resp.StatusCode)
	}
	return nil
}

// otlpSignalEndpoint mirrors _otlp_signal_endpoint: strip a known signal
// suffix from the configured base, then append the wanted one.
func otlpSignalEndpoint(endpoint, signalPath string) string {
	base := strings.TrimRight(endpoint, "/")
	for _, known := range []string{"/v1/traces", "/v1/metrics", "/v1/logs"} {
		if strings.HasSuffix(base, known) {
			base = base[:len(base)-len(known)]
			break
		}
	}
	return base + signalPath
}
