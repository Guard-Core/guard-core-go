package guardcore

import "strings"

// Event-stream wiring: the helper seams every check, manager, and the
// pipeline use to emit through the installed agent pipeline. All helpers
// are inert no-ops on an agentless config, mirroring the reference where
// the middleware owns the event_bus and the managers own agent handlers.

// busFor returns the config's installed bus, or nil.
func busFor(cfg *SecurityConfig) *SecurityEventBus {
	if pipeline := agentPipelineFor(cfg); pipeline != nil {
		return pipeline.bus
	}
	return nil
}

// metricsFor returns the config's installed metrics collector, or nil.
func metricsFor(cfg *SecurityConfig) *MetricsCollector {
	if pipeline := agentPipelineFor(cfg); pipeline != nil {
		return pipeline.metrics
	}
	return nil
}

// emitBusEvent routes one middleware event through the installed bus
// (send_middleware_event): gated by agent_enable_events, muted by the
// event filter, handler_name "middleware".
func emitBusEvent(cfg *SecurityConfig, eventType string, req Request, actionTaken, reason string, kwargs map[string]any) {
	if bus := busFor(cfg); bus != nil {
		bus.SendMiddlewareEvent(eventType, req, actionTaken, reason, kwargs)
	}
}

// blockedOrLoggedAction mirrors the reference's action_taken selection on
// the check sites: request_blocked in active mode, logged_only in
// passive mode.
func blockedOrLoggedAction(passiveMode bool) string {
	if passiveMode {
		return "logged_only"
	}
	return "request_blocked"
}

// emitAccessDeniedEvent mirrors emit_access_denied_event (checks/helpers.py):
// a decorator_violation with the decorator classification and metadata.
func emitAccessDeniedEvent(cfg *SecurityConfig, req Request, reason, decoratorType string, passiveMode bool, metadata map[string]any) {
	kwargs := map[string]any{"decorator_type": decoratorType}
	for k, v := range metadata {
		kwargs[k] = v
	}
	emitBusEvent(cfg, EventDecoratorViolation, req, blockedOrLoggedAction(passiveMode), reason, kwargs)
}

// classifyHeaderViolation mirrors _classify_header_violation
// (required_headers.py).
func classifyHeaderViolation(headerName string) (string, string) {
	switch strings.ToLower(headerName) {
	case "x-api-key":
		return "authentication", "api_key_required"
	case "authorization":
		return "authentication", "required_header"
	}
	return "advanced", "required_header"
}

// emitGeoEventToBus forwards a GeoEvent (the country_blocked /
// geo_lookup_failed / decorator_violation family the geo surface already
// produces) through the bus as a handler-direct event, bypassing the
// agent gate exactly like the reference's ipinfo/cloud emitters.
func emitGeoEventToBus(cfg *SecurityConfig, ev GeoEvent) {
	bus := busFor(cfg)
	if bus == nil {
		return
	}
	metadata := map[string]any{}
	for k, v := range ev.Metadata {
		metadata[k] = v
	}
	if ev.Country != "" {
		metadata["country"] = ev.Country
	}
	if ev.RuleType != "" {
		metadata["rule_type"] = ev.RuleType
	}
	handlerName := ev.HandlerName
	if handlerName == "" {
		handlerName = IPInfoHandlerName
	}
	bus.SendHandlerEventFull(ev.EventType, handlerName, ev.IPAddress, ev.ActionTaken, ev.Reason, ev.RuleType, metadata)
}

// pythonListRepr renders a string list the way the reference embeds it in
// event reasons (python list repr: ['a', 'b']).
func pythonListRepr(values []string) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range values {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteByte('\'')
		b.WriteString(v)
		b.WriteByte('\'')
	}
	b.WriteByte(']')
	return b.String()
}
