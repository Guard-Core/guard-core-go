# Agent wiring

guard-core-go ships the agent telemetry pipeline: set `EnableAgent` and inject an `AgentHandler` (for example the one from [guard-agent-go](https://github.com/Guard-Core/guard-agent-go)) and the engine streams security events and metrics through it, and `EnableDynamicRules` pulls agent-synced rules. Without an `AgentHandler` the event bus and metrics collector are inert. On top of that the engine exposes two lower-level seams.

## The OnBlock hook

`SecurityConfig.OnBlock` is the block-event seam. The pipeline calls it for
every block or passive-detection verdict, right before an error response is
returned:

```go
cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
    c.OnBlock = func(req guardcore.Request, payload map[string]any) {
        // Forward to guard-agent-go, write to a queue, sample, ...
    }
})
```

The payload is a flat map with these keys:

| Key | Meaning |
|---|---|
| `check_name` | The check that produced the verdict (e.g. `ip_security`, `rate_limit`, `required_headers`) |
| `reason` | Human-readable reason string |
| `trigger_info` | The matched pattern, header, or field that triggered the verdict |
| `passive_mode` | `true` when the engine only observed (config `PassiveMode` or a passive check); no response was written |
| `client_ip` | Resolved client IP, canonicalized; `unknown` when it cannot be resolved |
| `path` | Request path |
| `method` | HTTP method |
| `status_code` | Status the engine will return; `0` for passive detections |

Behavioral guarantees:

- The hook is panic-guarded: a panicking hook is recovered and logged
  (`on_block hook raised: ...`); it never takes down the server or alters the
  verdict.
- It never runs for `custom_request`, `custom_validators`, or
  `https_enforcement` verdicts (these fire through a forced path instead, so
  custom-validator blocks still reach the hook with the validator's status).
- It runs synchronously on the request path: keep it fast, non-blocking, and
  never return an error into the pipeline. For production, hand the payload to
  a buffered channel and forward from a worker goroutine.

## The rate-limit script-reload hook

`RateLimitManager.SetAgentHandlerHook` wires a callback that fires whenever the
rate-limit Lua script is reloaded after a Redis `NOSCRIPT`:

```go
engine.RateLimit.SetAgentHandlerHook(func() {
    // Notify guard-agent-go that the rate-limit backend re-primed itself.
})
```

## Forwarding to guard-agent-go

Inject the agent client as `SecurityConfig.AgentHandler` (with `EnableAgent`, `AgentEnableEvents` and `AgentEnableMetrics`) to forward the engine's event and metric stream. `OnBlock` stays available for your own block-event sinks, and its payload keys match the Python engine's block event fields.
