# guard-core-go simple app

A minimal guarded `net/http` server built directly on the guard-core-go
engine, in a single `main.go`. It shows the canonical engine wiring and the
complete `net/http` request shim, so it doubles as a reference for writing
your own adapter.

For a production-style layout (multi-stage Docker, nginx, admin routes, route
registry), see [`../advanced_app`](../advanced_app).

## Run it

With Docker Compose (recommended, includes Redis):

```bash
cd examples/simple_app
docker compose up --build
```

Or with the Go toolchain (in-process state, no Redis needed):

```bash
go run ./examples/simple_app
```

## Endpoints

| Endpoint | What it demonstrates |
|---|---|
| `GET /` | API info; passes the guard |
| `GET /health` | Liveness probe; excluded from the pipeline via `ExcludePaths` |
| `POST /echo` | Body-bearing request through detection |
| `GET /rate/strict` | Per-endpoint rate limit: 1 request per 10 seconds (`EndpointRateLimits`) |
| `GET /search?q=...` | Query parameter scanning; XSS payloads are blocked as suspicious activity |

## Try the security behavior

```bash
# Allowed
curl -i http://localhost:8080/

# Blocked by penetration detection (400, suspicious activity)
curl -i -G http://localhost:8080/search --data-urlencode 'q=<script>alert(1)</script>'

# Rate limited: the second request within 10 seconds returns 429
curl -i http://localhost:8080/rate/strict
curl -i http://localhost:8080/rate/strict

# Auto-banned: after AutoBanThreshold (5) violations the IP is banned and
# every verdict carries the custom 403 body
curl -i http://localhost:8080/
```

## A note on address headers

The Python engine skips ssrf scanning for address headers (`host`,
`x-forwarded-for`, `x-real-ip`, ...) automatically. This Go port does not
apply that built-in exclusion yet, so `main.go` mirrors it through
`ExcludedDetectionHeaders`; without it, a plain `Host: localhost` request is
flagged as an ssrf attempt.

## Configuration knobs demonstrated

`main.py`-style inline comments in `main.go` walk through every knob used:

- Global rate limiting (`RateLimit`, `RateLimitWindow`) and per-endpoint
  overrides (`EndpointRateLimits`)
- Auto-banning (`AutoBanThreshold`, `AutoBanDuration`)
- Penetration detection with all categories enabled
- Blocked user agents (regex patterns)
- `CustomErrorResponses` for consistent block bodies
- `ExcludePaths` for health and docs routes
- Redis via `REDIS_URL` / `REDIS_PREFIX` (compose wires Redis in; without it
  the managers fall back to in-process state)
- The `OnBlock` hook: the telemetry seam for wiring
  [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) (comment-level
  guidance in `main.go`; agent integration is not implemented in the engine
  port yet, and `EnableAgent` fails config validation)

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REDIS_URL` | (unset; Redis disabled) | When set, bans and rate limits are shared through Redis |
| `REDIS_PREFIX` | `guard_core:` | Redis key prefix |
