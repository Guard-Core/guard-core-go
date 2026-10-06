package guardcore

import (
	"log"
	"reflect"
	"sync"
)

// Agent-handler adapters, ported from the reference handler surface
// (guard_core/core/events/composite_handler.py and the adaptation seam the
// engine's AgentHandler interface implies).

// AgentHandlerFunc adapts plain functions to the AgentHandler interface.
// It is the bridge for implementations whose native API cannot satisfy
// the interface directly - for example guard-agent-go, whose SendEvent
// carries a context.Context first argument and whose SecurityEvent model
// is its own wire type. A wrapper such as
//
//	&guardcore.AgentHandlerFunc{
//	    EventFunc: func(ev guardcore.SecurityEvent) error {
//	        return agent.SendEvent(ctx, toAgentEvent(ev))
//	    },
//	    MetricFunc: func(m guardcore.SecurityMetric) error {
//	        return agent.SendMetric(ctx, toAgentMetric(m))
//	    },
//	}
//
// restores pluggability without changing either side's public signature:
// the engine interface stays context-free (the pipeline treats delivery
// as fire-and-forget and has no per-request context to pass), while the
// agent keeps its context-carrying API its own adapters already use. A
// nil func answers nil.
type AgentHandlerFunc struct {
	EventFunc  func(SecurityEvent) error
	MetricFunc func(SecurityMetric) error
}

// SendEvent forwards to EventFunc.
func (f *AgentHandlerFunc) SendEvent(event SecurityEvent) error {
	if f == nil || f.EventFunc == nil {
		return nil
	}
	return f.EventFunc(event)
}

// SendMetric forwards to MetricFunc.
func (f *AgentHandlerFunc) SendMetric(metric SecurityMetric) error {
	if f == nil || f.MetricFunc == nil {
		return nil
	}
	return f.MetricFunc(metric)
}

// The optional per-child surfaces the composite drives when present. The
// OTel and Logfire handlers implement them so a composite can own their
// lifecycle; nested composites work because the composite itself
// implements the same shapes.
type (
	// AgentStarter starts a child handler.
	AgentStarter interface{ Start() error }
	// AgentStopper stops a child handler.
	AgentStopper interface{ Stop() error }
	// AgentFlusher drains a child handler's pending buffer.
	AgentFlusher interface{ Flush() error }
	// AgentReporter reports a child handler's health.
	AgentReporter interface{ Healthy() bool }
	// AgentDynamicRules fetches agent-synced dynamic rules (the
	// DynamicRulesProvider capability) from a child handler.
	AgentDynamicRules interface {
		GetDynamicRules() (*DynamicRules, error)
	}
)

// CompositeAgentHandler fans one event/metric stream out to N sinks,
// ported from composite_handler.py: the filter gates by type string, the
// optional enricher stamps the guard.* keys before fan-out, a failing
// child never fails the stream (the error is logged), start failures
// degrade the composite without stopping the fan-out, and dynamic rules
// resolve from the first child that provides them.
type CompositeAgentHandler struct {
	mu       sync.Mutex
	handlers []AgentHandler
	filter   EventFilter
	enricher *EventEnricher
	started  bool
	failed   []string
}

// NewCompositeAgentHandler wires the fan-out. A nil filter lets every
// type through (the reference EventFilter() default).
func NewCompositeAgentHandler(handlers []AgentHandler, filter *EventFilter) *CompositeAgentHandler {
	children := make([]AgentHandler, len(handlers))
	copy(children, handlers)
	composite := &CompositeAgentHandler{handlers: children}
	if filter != nil {
		composite.filter = *filter
	}
	return composite
}

// NewCompositeAgentHandlerWithEnricher wires the fan-out with the enricher
// the reference CompositeAgentHandler accepts: every allowed event/metric
// is enriched before the children see it (composite_handler.py
// send_event/send_metric: filter, enrich, fan out).
func NewCompositeAgentHandlerWithEnricher(handlers []AgentHandler, filter *EventFilter, enricher *EventEnricher) *CompositeAgentHandler {
	composite := NewCompositeAgentHandler(handlers, filter)
	composite.enricher = enricher
	return composite
}

// Started answers whether Start ran (the reference .started property).
func (c *CompositeAgentHandler) Started() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

// Degraded answers whether Start ran and any child failed to start (the
// reference .degraded property).
func (c *CompositeAgentHandler) Degraded() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started && len(c.failed) > 0
}

// FailedHandlers lists the child types that failed to start (the
// reference .failed_handlers property).
func (c *CompositeAgentHandler) FailedHandlers() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.failed...)
}

// SendEvent filters by event type, enriches and fans out; child failures
// are logged and never propagated (the reference send_event).
func (c *CompositeAgentHandler) SendEvent(event SecurityEvent) error {
	if c == nil {
		return nil
	}
	if event.EventType != "" && !c.filter.IsEventAllowed(event.EventType) {
		return nil
	}
	if c.enricher != nil {
		c.enricher.EnrichEvent(&event)
	}
	for _, handler := range c.children() {
		if err := handler.SendEvent(event); err != nil {
			log.Printf("handler.send_event failed: %v", err)
		}
	}
	return nil
}

// SendMetric filters by metric type, enriches and fans out; child failures
// are logged and never propagated (the reference send_metric).
func (c *CompositeAgentHandler) SendMetric(metric SecurityMetric) error {
	if c == nil {
		return nil
	}
	if metric.MetricType != "" && !c.filter.IsMetricAllowed(metric.MetricType) {
		return nil
	}
	if c.enricher != nil {
		c.enricher.EnrichMetric(&metric)
	}
	for _, handler := range c.children() {
		if err := handler.SendMetric(metric); err != nil {
			log.Printf("handler.send_metric failed: %v", err)
		}
	}
	return nil
}

// Start starts every child implementing AgentStarter; a failing child is
// recorded and logged, and the composite still reports started (the
// reference start()).
func (c *CompositeAgentHandler) Start() error {
	c.mu.Lock()
	c.failed = nil
	children := append([]AgentHandler(nil), c.handlers...)
	c.mu.Unlock()
	for _, handler := range children {
		starter, ok := handler.(AgentStarter)
		if !ok {
			continue
		}
		if err := starter.Start(); err != nil {
			name := concreteHandlerName(handler)
			log.Printf("Handler %s failed to start: %v", name, err)
			c.mu.Lock()
			c.failed = append(c.failed, name)
			c.mu.Unlock()
		}
	}
	c.mu.Lock()
	c.started = true
	c.mu.Unlock()
	return nil
}

// Stop stops every child implementing AgentStopper; failures are logged,
// never propagated (the reference stop()).
func (c *CompositeAgentHandler) Stop() error {
	for _, handler := range c.children() {
		stopper, ok := handler.(AgentStopper)
		if !ok {
			continue
		}
		if err := stopper.Stop(); err != nil {
			log.Printf("handler.stop failed: %v", err)
		}
	}
	return nil
}

// Flush drains every child implementing AgentFlusher; failures are
// logged, never propagated (the reference flush_buffer()).
func (c *CompositeAgentHandler) Flush() error {
	for _, handler := range c.children() {
		flusher, ok := handler.(AgentFlusher)
		if !ok {
			continue
		}
		if err := flusher.Flush(); err != nil {
			log.Printf("handler.flush_buffer failed: %v", err)
		}
	}
	return nil
}

// GetDynamicRules returns the first child-provided rules snapshot (the
// reference get_dynamic_rules). Like the reference composite - which
// always carries the method - the composite always satisfies
// DynamicRulesProvider, so an agentless child set simply keeps the rule
// loop idle on nil results.
func (c *CompositeAgentHandler) GetDynamicRules() (*DynamicRules, error) {
	for _, handler := range c.children() {
		provider, ok := handler.(AgentDynamicRules)
		if !ok {
			continue
		}
		rules, err := provider.GetDynamicRules()
		if err != nil {
			log.Printf("handler.get_dynamic_rules failed: %v", err)
			continue
		}
		if rules != nil {
			return rules, nil
		}
	}
	return nil, nil
}

// Healthy reports every child's health (the reference health_check). A
// child without the AgentReporter surface counts as healthy; no children
// is healthy (the reference all([]) is True).
func (c *CompositeAgentHandler) Healthy() bool {
	children := c.children()
	if len(children) == 0 {
		return true
	}
	for _, handler := range children {
		reporter, ok := handler.(AgentReporter)
		if !ok {
			continue
		}
		if !reporter.Healthy() {
			return false
		}
	}
	return true
}

func (c *CompositeAgentHandler) children() []AgentHandler {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]AgentHandler(nil), c.handlers...)
}

// concreteHandlerName names a child for the degradation log (the
// reference type(handler).__name__).
func concreteHandlerName(handler AgentHandler) string {
	typ := reflect.TypeOf(handler)
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == nil {
		return "AgentHandler"
	}
	return typ.Name()
}
