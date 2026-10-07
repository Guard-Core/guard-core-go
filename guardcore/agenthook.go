package guardcore

import (
	"log"
)

// The on_error hook surface, mirrored from the reference
// invoke_error_hook (guard_core/_utils/agent_events.py): a best-effort
// callback invoked when a middleware/agent step fails, carrying the stage
// name, the error and a context map. A panicking hook is contained with
// the reference log line.

// invokeErrorHook dispatches the config's OnError with containment: a
// panicking hook logs "on_error hook raised while handling '<stage>'" and
// never propagates.
func invokeErrorHook(cfg *SecurityConfig, stage string, err error, context map[string]any) {
	if cfg == nil || cfg.OnError == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("on_error hook raised while handling '%s': %v", stage, r)
		}
	}()
	cfg.OnError(stage, err, context)
}

// agentInitFailure handles the reference _on_agent_init_failed semantics
// (fastapi-guard guard/middleware.py): the stream is marked degraded, the
// on_error hook fires with the "agent_init" stage, and agent_strict
// decides between raising and degrading to agent-off with the reference
// log lines.
func agentInitFailure(cfg *SecurityConfig, err error) error {
	invokeErrorHook(cfg, "agent_init", err, map[string]any{})
	if cfg != nil && cfg.AgentStrict {
		return err
	}
	log.Printf("%v", err)
	log.Printf("Continuing without agent functionality")
	return nil
}

// agentHandlerAnomalySender adapts the config's AgentHandler onto the
// performance monitor's AnomalyEventSender seam (the reference passes the
// agent handler into record_metric per call).
type agentHandlerAnomalySender struct {
	handler AgentHandler
	ip      string
}

func (a agentHandlerAnomalySender) SendAnomalyEvent(event AnomalyEvent) error {
	if a.handler == nil {
		return nil
	}
	ip := a.ip
	if ip == "" {
		ip = UnknownClientIdentity
	}
	return a.handler.SendEvent(SecurityEvent{
		Timestamp:   event.Timestamp,
		EventType:   event.EventType,
		IPAddress:   ip,
		ActionTaken: event.ActionTaken,
		Reason:      event.Reason,
		HandlerName: "middleware",
		Metadata:    event.Metadata,
	})
}
