# Agent wiring

guard-core-go does not ship agent telemetry yet: setting `EnableAgent` fails
config validation (`enable_agent: Guard Agent telemetry is not implemented in
this port yet`). Until [guard-agent-go](https://github.com/Guard-Core/guard-agent-go)
integration lands, the engine exposes two deliberate seams you can wire today.

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

The Go agent mirrors the Python guard-agent's API. Once its engine-event
pipeline accepts these payloads, forward `OnBlock` events with the payload map
as-is: the keys match the Python engine's block event fields, so the agent's
existing consumers keep working. Until then, both example apps
([simple](https://github.com/Guard-Core/guard-core-go/tree/master/examples/simple_app)
and
[advanced](https://github.com/Guard-Core/guard-core-go/tree/master/examples/advanced_app))
log the payload from `OnBlock` as the placeholder integration.

## What the Python engine has that this port does not (yet)

- `EnableAgent` / agent startup initialization and heartbeat events
- `ip_banned`, `ip_unbanned`, `rate_limited`, `cloud_blocked` security events
- Middleware lifecycle events (`request_processed`, `https_violation`, ...)

Track these in the [roadmap](roadmap.md).
