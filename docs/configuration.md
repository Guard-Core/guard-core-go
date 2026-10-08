# Configuration

`SecurityConfig` is one flat struct built through
`guardcore.DefaultSecurityConfig()` or
`guardcore.NewSecurityConfig(mutate func(*SecurityConfig))`. The latter applies
your mutation and then runs `Validate()`, returning any validation error.

## Client identity and proxy trust

| Field | Type | Default | Notes |
|---|---|---|---|
| `TrustedProxies` | `[]string` | empty | IPs or CIDRs whose forwarding headers are trusted |
| `TrustedProxyDepth` | `int` | `1` | Must be >= 1 |
| `TrustXForwardedProto` | `bool` | `false` | Honor `X-Forwarded-Proto` for HTTPS detection |

## Access lists

| Field | Type | Notes |
|---|---|---|
| `Whitelist` | `[]string` | IPs or CIDRs, validated at config time |
| `ExemptIPs` | `[]string` | IPs or CIDRs, validated at config time; skip-list for trusted automation, see below |
| `Blacklist` | `[]string` | IPs or CIDRs, validated at config time |
| `ExcludePaths` | `[]string` | Absolute paths skipped by the pipeline (defaults: `/docs`, `/redoc`, `/openapi.json`, `/openapi.yaml`, `/favicon.ico`, `/static`) |
| `EmergencyMode` | `bool` | Blocks everything except `EmergencyWhitelist` |
| `EmergencyWhitelist` | `[]string` | Allowed during emergency mode |

### Exempt IPs vs the whitelist

`Whitelist` doubles as an allowlist: when it is non-empty, every IP not on it
is denied. `ExemptIPs` is noise reduction for known-friendly automation, not
immunity: an exempt request skips rate limiting, the user-agent check, and
per-route cloud-provider blocks, while the blacklist, dynamic IP bans,
penetration detection, HTTPS enforcement, and the global `BlockCloudProviders`
block still apply. Exemption never opens the whitelist gate and never adds a
deny path of its own; an IP on both lists is simply a whitelist match.

## Redis

| Field | Type | Default | Notes |
|---|---|---|---|
| `EnableRedis` | `bool` | `true` | Required for distributed bans and rate limits |
| `RedisURL` | `string` | `redis://localhost:6379` | |
| `RedisPrefix` | `string` | `guard_core:` | Key prefix |
| `RedisFailOpen` | `bool` | `false` | On Redis failure, allow traffic instead of blocking |

## IP banning

| Field | Type | Default | Notes |
|---|---|---|---|
| `EnableIPBanning` | `bool` | `true` | |
| `AutoBanThreshold` | `int` | `10` | Violations before an auto-ban; must be >= 1 |
| `AutoBanDuration` | `int` | `3600` | Auto-ban length in seconds |
| `ThreatBanConfig` | `map[string]ThreatBanEntry` | empty | Per-category `{Threshold, Duration}` overrides |
| `EnableRateLimitAutoBan` | `bool` | `false` | Count rate-limit violations toward auto-ban |

## Rate limiting

| Field | Type | Default | Notes |
|---|---|---|---|
| `EnableRateLimiting` | `bool` | `true` | |
| `RateLimit` | `int` | `10` | Requests per window |
| `RateLimitWindow` | `int` | `60` | Window length in seconds |
| `EndpointRateLimits` | `map[string]RateLimitEntry` | empty | Exact-path overrides, key is the request path |

## Penetration detection

| Field | Type | Default | Notes |
|---|---|---|---|
| `EnablePenetrationDetection` | `bool` | `true` | |
| `EnabledDetectionCategories` | `[]string` | all categories | See [Detection](detection.md) |
| `ExcludedDetectionHeaders` | `map[string]bool` | empty | Header names merged into the excluded-header scan: excluded headers skip the `ssrf` category only when the header is address-carrying or its value parses as an address chain; every other category still scans them |
| `ExcludedDetectionParams` | `map[string]bool` | empty | Query parameter names skipped |
| `ExcludedDetectionBodyFields` | `map[string]bool` | empty | JSON body fields skipped |
| `Detection` | `Config` | `DefaultConfig()` | Detector tuning (see below) |

## Cloud provider blocking

| Field | Type | Default | Notes |
|---|---|---|---|
| `BlockCloudProviders` | `[]string` | empty | e.g. `AWS`, or `AWS:!us-east-1` to carve out a region |
| `CloudIPRefreshInterval` | `int` | `3600` | Seconds, clamped to `[60, 86400]` |

## Geo country rules

| Field | Type | Default | Notes |
|---|---|---|---|
| `WhitelistCountries` | `[]string` | empty | ISO 3166-1 alpha-2 codes, uppercased at config time. Non-empty is restrictive: only listed countries pass, and an unresolved country is denied |
| `BlockedCountries` | `[]string` | empty | ISO 3166-1 alpha-2 codes that are always denied. Ignored while `WhitelistCountries` is non-empty |
| `GeoIPDBPath` | `string` | empty | Path to a local MMDB database with top-level `country` records (the ipinfo `country_asn.mmdb` layout). Required when country rules are set and no handler is injected |
| `GeoIPHandler` | `CountryResolver` | nil | Injected resolver (`GetCountry(ip) (string, bool)`); replaces the built-in MMDB reader |

Country rules run inside the `ip_security` check: after the global IP lists,
before the cloud-provider check, exactly like the reference
`check_ip_access`. A global `Whitelist` match and a route
`RouteConfig.WhitelistCountries` match skip the country stage. Loopback IPs
are exempt from the global country stage. An unresolvable country fails
closed in allowlist mode and open in blocklist mode. Route-level
`RouteConfig.BlockedCountries` / `WhitelistCountries` combine with the route
IP list verdicts; the route stage has no loopback exemption. The engine does
not download databases: provision the MMDB file yourself or inject a
resolver. Exempt IPs are not exempt from country rules.

## User agents, headers, auth

| Field | Type | Notes |
|---|---|---|
| `BlockedUserAgents` | `[]string` | Regex patterns, validated with `regexp.Compile` |
| `AuthVerifier` | `AuthVerifier` | `func(req, credential) (any, error)` used by `AuthRequired` routes |

## Logging

| Field | Type | Default | Notes |
|---|---|---|---|
| `LogRequestLevel` | `string` | `INFO` | One of `INFO`, `DEBUG`, `WARNING`, `ERROR`, `CRITICAL` |
| `LogSuspiciousLevel` | `string` | `WARNING` | |
| `MutedCheckLogs` | `map[string]bool` | empty | Check names whose logs are suppressed |
| `LogSensitiveHeaders` | `map[string]bool` | empty | Headers whose values are redacted |
| `LogSensitiveParams` | `map[string]bool` | empty | Params whose values are redacted |
| `LogSensitiveBodyFields` | `map[string]bool` | empty | Body fields whose values are redacted |

## Custom behavior

| Field | Type | Notes |
|---|---|---|
| `CustomErrorResponses` | `map[int]string` | Status code to body message, used for every block verdict |
| `OnBlock` | `func(req Request, payload map[string]any)` | Telemetry hook, see below |
| `CustomRequestCheck` | `func(req Request) *Response` | Final user-defined gate; non-nil response blocks |
| `PassiveMode` | `bool` | Log violations without blocking |
| `FailSecure` | `bool` | Default `true`; fail-closed on internal errors |
| `RouteResolutionStrict` | `bool` | Reject requests whose route cannot be resolved |

### The OnBlock hook

`OnBlock` is the single telemetry seam in this port. It fires for every block
verdict with a payload containing `check_name`, `reason`, `trigger_info`,
`passive_mode`, `client_ip`, `path`, `method`, and `status_code`.

```go
cfg.OnBlock = func(req guardcore.Request, payload map[string]any) {
    log.Printf("blocked %s %s by %s: %s",
        payload["method"], payload["path"], payload["check_name"], payload["reason"])
}
```

Hook panics are recovered and logged; they never affect the verdict.

!!! note "Agent wiring"
    Guard Agent telemetry is not implemented in this port yet
    (`EnableAgent` is fail-closed and returns an unsupported-feature error).
    Until the agent event pipeline lands, forward `OnBlock` payloads to
    [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) from your own
    hook implementation. See `examples/advanced_app` for a worked example.

## Detector tuning

```go
cfg.Detection = guardcore.Config{
    CompilerTimeout:        2 * time.Second,
    MaxContentLength:       10000,
    PreserveAttackPatterns: true,
    MaxBodyInspectBytes:    262144,
    SemanticThreshold:      0.7,
    ThreatScoreThreshold:   1.0,
}
```

## Unsupported (fail-closed) options

Validation rejects configurations this port does not implement yet, rather
than silently ignoring them:

- `EnableDynamicRules`
- `EnableAgent`

`GlobalBehaviorRules` is implemented: rules are validated at config time
(`validateBehaviorRules`) and drive the in-memory behavior ban through the
pipeline's behavioral processor.

Each returns an `*UnsupportedFeatureError` from `Validate()`. See
[Roadmap](roadmap.md) for the full divergence list.

## CORS

| Field | Type | Default | Notes |
|---|---|---|---|
| `EnableCORS` | `bool` | `false` | Enables the CORS handler over the engine |
| `CORSAllowOrigins` | `[]string` | `["*"]` | Exact origins; `*` allows every origin |
| `CORSAllowMethods` | `[]string` | `GET, POST, PUT, PATCH, DELETE, OPTIONS` | Uppercased at config time; an empty list falls back to `GET` |
| `CORSAllowHeaders` | `[]string` | `["*"]` | Lowercased at config time; `*` echoes the requested headers verbatim |
| `CORSAllowCredentials` | `bool` | `false` | Accepted together with the `*` origin, but downgraded at policy resolution: the wildcard policy answers without the allow-credentials header, like the reference `_compute_cors_config` |
| `CORSExposeHeaders` | `[]string` | empty | Joined into `Access-Control-Expose-Headers` on responses |
| `CORSMaxAge` | `int` | `600` | A configured `0` falls back to `600` |

Behavior mirrors the reference `CorsHandler` (guard_core
`handlers/cors_handler.py`) and the adapter dispatch: a preflight (OPTIONS
carrying `Access-Control-Request-Method`) executes the security pipeline and
is then short-circuited with `200 OK` (or `400 Disallowed CORS: origin,
method, headers`), blocked responses compose the CORS headers on top of the
security-header set, and disallowed origins simply get no CORS headers (the
browser enforces). For pass-through responses the adapter merges
`Engine.ResponseHeaders()` with `Engine.CORSResponseHeaders(req)`.
