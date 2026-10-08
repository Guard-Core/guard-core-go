# guard-core-go advanced example

A production-style deployment of the guard-core-go engine: multi-stage Docker
build, non-root runtime, nginx reverse proxy, Redis for shared bans and rate
limits, route-registry guards, and admin routes that drive the ban manager.

For the minimal single-file version, see [`../simple_app`](../simple_app).

## Architecture

```text
Client -> nginx (port 80) -> guard middleware -> net/http handlers
                                    |
                              guardcore.Engine
                                    |
                            Redis (bans, rate limits)
```

- `cmd/server` - assembly: config, engine lifecycle, route registry, server
  with timeouts and graceful shutdown
- `internal/config` - environment-driven `SecurityConfig` tuning
- `internal/guardmw` - the net/http adapter (request translation, route IDs,
  verdict writing)
- `internal/routes` - handlers, including `/admin/*` operational routes

## Quick start

```bash
cd examples/advanced_app
docker compose up --build
```

## Endpoints

| Endpoint | Notes |
|---|---|
| `GET /` | API info |
| `GET /health`, `GET /ready` | Probes, excluded from the pipeline |
| `POST /echo` | Body-bearing request through detection |
| `GET /rate/burst` | `EndpointRateLimits`: 5 requests per 60 seconds |
| `GET /admin/banned` | Ban counts (requires `X-Admin-Token`) |
| `POST /admin/ban` | Body `{"ip": "...", "seconds": 300, "reason": "..."}` (requires `X-Admin-Token`) |
| `POST /admin/unban` | Body `{"ip": "..."}` (requires `X-Admin-Token`) |
| `GET /test/xss`, `GET /test/sqli`, `GET /test/traversal` | Hostile query-param payloads; the guard blocks them before the handler runs |

## Try the security behavior

```bash
# Allowed
curl -i http://localhost/

# Penetration detection blocks the payload as suspicious activity (400;
# the tuned 403 body appears once the IP crosses an auto-ban threshold)
curl -i "http://localhost/test/xss?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# Rate limiting: the sixth request in 60 seconds returns 429
for i in $(seq 1 6); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost/rate/burst; done

# Route registry guard: missing admin token -> 400 from the engine
curl -i http://localhost/admin/banned

# With the token (see ADMIN_TOKEN)
curl -i -H 'X-Admin-Token: admin-token-change-me' http://localhost/admin/banned

# Manual ban, then observe the banned IP verdict, then unban
curl -s -X POST http://localhost/admin/ban -H 'X-Admin-Token: admin-token-change-me' \
  -H 'Content-Type: application/json' -d '{"ip": "203.0.113.9", "seconds": 120}'
curl -s -H 'X-Admin-Token: admin-token-change-me' http://localhost/admin/banned
curl -s -X POST http://localhost/admin/unban -H 'X-Admin-Token: admin-token-change-me' \
  -H 'Content-Type: application/json' -d '{"ip": "203.0.113.9"}'
```

## Module layout note

Both example apps live inside the root module
(`github.com/rennf93/guard-core-go/v4/examples/...`) rather than in separate Go
modules or a `go.work` workspace. Rationale: the examples pin the exact engine
they document (same module, same commit), so `go vet ./...` and
`go build ./...` gate them together with the engine in CI and the Dockerfiles
`COPY go.mod go.sum` only once. Splitting them out would let an example drift
against a published engine version while still compiling. The tradeoff: the
examples' imports resolve only inside this module, which is fine for
copy-paste-driven reference code.

## Configuration knobs demonstrated

- Proxy trust: `TrustedProxies` + `TrustedProxyDepth` (one hop: nginx)
- Global rate limiting plus per-endpoint overrides (`EndpointRateLimits`)
- Auto-banning (`AutoBanThreshold`, `AutoBanDuration`) and per-threat bans
  (`ThreatBanConfig` for `sqli` and `xss`)
- Penetration detection with all categories
- `CustomErrorResponses` for consistent block bodies (403 and 429)
- `ExcludePaths` so probes never touch the pipeline
- `LogRequestLevel` / `LogSuspiciousLevel`
- Route-scoped guards through `RouteRegistry` (`RequiredHeaders` on
  `/admin/*`)
- `OnBlock` hook: the telemetry seam for
  [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) wiring
  (comment-level guidance in `internal/config/config.go`; `EnableAgent` is
  fail-closed in this port, so the hook is the integration point)

## Intentional simplifications

- The admin gate uses `RequiredHeaders` (a real engine-enforced route guard).
  Route-level `IPWhitelist` is not consumed by the pipeline in this port yet;
  use the global `Whitelist` or edge ACLs for IP gating.
- Per-route rate limits are not read by the pipeline yet; endpoint limits are
  expressed with `EndpointRateLimits` instead.
- The `/test/*` payloads ride in query parameters because the pipeline does
  not scan request bodies in this port (see [`../../docs/roadmap.md`](../../docs/roadmap.md)).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTED_PROXIES` | empty | CIDRs whose forwarded headers are trusted |
| `TRUSTED_PROXY_DEPTH` | `1` | Forwarding hops to trust |
| `REDIS_URL` | (unset; Redis disabled) | Shared ban/rate-limit state |
| `REDIS_PREFIX` | `guard_core:` | Redis key prefix |
| `ADMIN_TOKEN` | `admin-token-change-me` | `X-Admin-Token` value for `/admin/*` |
| `RATE_LIMIT` / `RATE_LIMIT_WINDOW` | `30` / `60` | Global rate limit |
| `AUTO_BAN_THRESHOLD` / `AUTO_BAN_DURATION` | `5` / `300` | Auto-ban policy |
| `BLOCK_CLOUD_PROVIDERS` | empty | Comma-separated providers (e.g. `AWS,GCP`) |
| `LOG_REQUEST_LEVEL` / `LOG_SUSPICIOUS_LEVEL` | `INFO` / `WARNING` | Log levels |

## Key differences from simple_app

| Feature | simple_app | advanced_app |
|---|---|---|
| Reverse proxy | none | nginx with edge rate limiting |
| Layout | single `main.go` | `cmd/` + `internal/` packages |
| Docker build | single stage | multi-stage build, non-root user |
| Route registry | not used | `admin` route with `RequiredHeaders` |
| Admin/ops routes | none | ban, unban, ban counts |
| Health checks | compose probe only | compose probes + nginx + graceful shutdown |
| Resource limits | none | CPU and memory limits per service |
