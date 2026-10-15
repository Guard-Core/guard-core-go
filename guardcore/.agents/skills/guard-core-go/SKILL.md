---
name: guard-core-go
description: Use when working in the guard-core-go repository or consuming the guardcore Go package, the core API security engine of the guard-core ecosystem. Load this skill when editing guardcore/, wiring the Engine facade (NewEngine) with SecurityConfig, adding SecurityCheck implementations to the 17-check pipeline, using Detect for threat detection, working with IP banning, Redis-backed rate limiting, or cloud provider IP blocking, running the integration tests (build tag integration, REDIS_HOST), the conformance fixture suite, or the cross-implementation Redis interop harness (build tag interop), or writing a framework adapter that must keep all security logic in the core.
---

# guard-core-go skill

## Quick Reference

- Module: `github.com/rennf93/guard-core-go/v4` (go.mod `go 1.25.0`); package import path: `github.com/rennf93/guard-core-go/v4/guardcore`.
- Library only: no `package main`, no binary, no Makefile. Shipped tag: `v4.0.4` (versioned to track the Python guard-core engine).
- Entry points: `NewSecurityConfig(mutate)` for config, `NewEngine(cfg)` for the facade, `guardcore.Detect(content, ip, context)` for raw content detection.
- Test layers: `go test ./...` (unit + conformance), `REDIS_HOST=127.0.0.1 go test -tags integration ./...` (Redis integration), `go test -tags interop ./guardcore -run TestInteropRunner` (Python cross-implementation harness).
- CI gates: `gofmt -l .` must print nothing, `go vet ./...`, `govulncheck ./...`, unit and Redis integration tests on Go 1.25.x and 1.26.x (`.github/workflows/ci.yml`).

## Installation

```
go get github.com/rennf93/guard-core-go/v4@v4.0.4
```

Direct dependencies pulled in (go.mod): `github.com/dlclark/regexp2` (timeout-guarded regex engine), `github.com/redis/go-redis/v9` (optional Redis state), `golang.org/x/text` (unicode normalization). Redis is a runtime dependency only when `EnableRedis` is true; without Redis the engine still detects threats, enforces whitelist/blacklist, and fails cloud caches open.

## Setup

```
cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
    c.EnablePenetrationDetection = true
    c.EnableRateLimiting = true
})
eng, err := guardcore.NewEngine(cfg)   // validates config, builds pipeline and managers
if err := eng.Initialize(); err != nil { ... }  // wire Redis, ban, rate limit, cloud ranges
resp := eng.Check(req)                  // nil means allowed; non-nil means blocked
defer eng.Close()
```

- `DefaultSecurityConfig()` is secure by default: `FailSecure: true`, Redis enabled at `redis://localhost:6379` with prefix `guard_core:`, IP banning and rate limiting on, all 19 detection categories on, standard `ExcludePaths` (`/docs`, `/redoc`, `/openapi.json`, `/openapi.yaml`, `/favicon.ico`, `/static`).
- Build requests with `guardcore.NewRequestFactory().CreateRequest(guardcore.RequestOptions{...})`; `RequestOptions` carries `Path`, `Scheme`, `Method`, `ClientHost`, `Header`, `QueryParams`, `Body`/`BodyFunc`, and an optional `State`.
- Startup (`Engine.Initialize`) is `sync.Once` guarded and idempotent. With `EnableRedis` false it only refreshes cloud ranges in the background; with Redis down it fails unless `RedisFailOpen` is true (then it logs and continues without Redis state).

## Engine and NewEngine

`NewEngine(cfg *SecurityConfig) (*Engine, error)` is the composition root. It rejects a nil or invalid config, then wires `Routes *RouteRegistry`, `Redis *RedisManager`, `Ban *IPBanManager`, `RateLimit *RateLimitManager`, `Cloud *CloudManager` (the package-level `DefaultCloudManager`), and the built pipeline. Methods: `Initialize()`, `Check(req Request) *Response`, `CreateErrorResponse(statusCode, defaultMessage)` (honors `CustomErrorResponses`), `Close()`. `Check` applies path exclusions and route-level `all` bypass before executing the pipeline; `nil` return means allowed.

## SecurityConfig

`SecurityConfig` is the single config surface; `Validate()` fills defaults, clamps values (`CloudIPRefreshInterval` to [60, 86400], default 3600), uppercases log levels, and rejects unknown names for `muted_check_logs`, detection categories, threat-ban categories, and cloud providers. Key groups: Redis (`EnableRedis`, `RedisURL`, `RedisPrefix`, `RedisFailOpen`), banning (`EnableIPBanning`, `AutoBanThreshold`, `AutoBanDuration`, `ThreatBanConfig`, `EnableRateLimitAutoBan`), rate limiting (`RateLimit`, `RateLimitWindow`, `EndpointRateLimits`), detection (`EnablePenetrationDetection`, `EnabledDetectionCategories`, per-scope exclusions, `Detection Config` with `CompilerTimeout`), behavior (`PassiveMode`, `FailSecure`, `ExcludePaths`, `CustomErrorResponses`, `OnBlock` hook), route-agnostic guards (`EnforceHTTPS`, `EmergencyMode`, `BlockCloudProviders` with `Provider:!region` carve-outs, `BlockedUserAgents`, `CustomRequestCheck`). Dynamic rules, agent telemetry (through an injected `AgentHandler`), CORS, geo country lists and global behavior rules are all implemented; `Validate()` rejects inconsistent combinations of them (for example `EnableEnrichment` without `EnableAgent`). `Revision()`/`BumpRevision()` drive pipeline rebuilds.

## Request, Response, and the Checks Pipeline

`Request` is an interface (framework adapters implement it or build one via `RequestFactory`): `URLPath`, `URLScheme`, `URLFull`, `URLReplaceScheme`, `Method`, `ClientHost`, `Headers`, `QueryParams`, `Body`, `State`. `Response` is `{StatusCode, Headers, Body}` built via `ResponseFactory`. A check implements `SecurityCheck`: `CheckName`, `AppliesTo(cfg)`, `EnforcedOnExcludedPaths`, `Check(req) *Response`. `BuildDefaultPipeline(cfg, ban, rateLimit, routes)` assembles 17 checks in a fixed slot order (`CheckNameValues` in `guardcore/config.go`, `buildChecks` in `guardcore/pipeline.go`): `route_config`, `emergency_mode`, `https_enforcement`, `request_logging`, `request_size_content`, `required_headers`, `authentication`, `referrer`, `custom_validators`, `time_window`, `cloud_ip_refresh`, `ip_security`, `cloud_provider`, `user_agent`, `rate_limit`, `suspicious_activity`, `custom_request`. Per-route overrides come from `RouteRegistry.Register(routeID, mutate)` returning a `*RouteConfig` (auth, required headers, size/content types, referrer, time windows, route rate limits, bypassed checks); registrations bump the revision so the pipeline rebuilds. `RequestState` carries bypass flags (`HasBypass`), the block stash, and route resolution; blocked responses are logged unless the check is in `MutedCheckLogs`, and `on_block` is suppressed for `custom_request`, `custom_validators`, and `https_enforcement`.

## Managers: IPBanManager, RateLimitManager, CloudManager, RedisManager

- `IPBanManager` (`NewIPBanManager(redisHandler, trustedProxies)`): `Ban(ip, duration, reason)`, `IsIPBanned(ip)`, `Unban`, `Reset`, `InitializeRedis`, `BannedIPCount`/`BannedNetworkCount`. Supports single IPs and CIDR network bans; IP canonicalization handles `::ffff:` mapped spellings.
- `RateLimitManager` (`NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), redisHandler, banManager)`): sliding-window counters via a loaded Lua script (`ScriptLoad`/`EvalSha`), global plus per-endpoint buckets (`CheckRateLimit`, `CheckRateLimitByIP`), autoban integration, `RateLimitOutcome.RetryAfter()`.
- `CloudManager`: package singleton `DefaultCloudManager`. `InitializeRedis(redis, providers, ttl)`, `IsCloudIP(ip, selectors)`, `GetCloudProviderDetails`, `RefreshAsync`, `ScheduleRefresh` (single-flight), `Status()`. Providers: AWS, GCP, Azure, DigitalOcean, Linode, Vultr (`AllCloudProviders`). Stores implement `CloudIPStore` (`InMemoryCloudIPStore`, `RedisCloudIPStore`, `RedisCloudRangesStore`) using the `cloud_ip_v2:<provider>` payload format; a selector `AWS:!us-east-1` blocks AWS except us-east-1.
- `RedisManager` (`NewRedisManager(RedisConfig{URL, Prefix, EnableRedis})`): implements `RedisHandler` (`GetKey`, `SetKey`, `Delete`, `Keys`, `DeletePattern`, `Initialize`, `Close`, `Prefix`, `Enabled`) plus `RedisAdmin` extras (`ScanMatch`, `PTTL`, `SetPX`, `DeleteKeys`). All keys are namespaced under the configured prefix.

## Detect and the Conformance Suite

`Detect(content, ip, context string) DetectResult` preprocesses the content (URL decoding, base64 candidate decoding with a gzip budget, unicode normalization, truncation) and runs the compiled pattern table plus semantic analysis. `DetectResult` fields: `IsThreat`, `ThreatScore`, `Threats []map[string]any`, `OriginalLength`, `ProcessedLength`, `DetectionMethod`. Categories are the 19 entries of `AllDetectionCategories` (`xss`, `sqli`, `cmd_injection`, `path_traversal`, `proto_pollution`, `deserialization`, and others). Behavior is pinned by `conformance/conformance_test.go`: it replays `conformance/guard-core-spec-4.0.2/cases/*.json` against `Detect` and compares every field (threat score rounded to 6 decimals, threats compared as a multiset). Expected values in the corpus were generated from the Python reference engine and must never be hand-edited (see `CORPUS.md`); if your change breaks conformance, revert or regenerate fixtures from the reference engine.

## Footguns

- Go 1.25+ is required (go.mod `go 1.25.0`); with older toolchains the module refuses to build.
- Integration tests skip silently when `REDIS_HOST` is unset: a green `go test ./...` says nothing about Redis paths. The `interop` test is the opposite: it fails hard without `REDIS_HOST` and needs `INTEROP_PHASE` set.
- `NewEngine` does not connect to Redis; until `Initialize()` succeeds, bans and rate limits have no shared state. `Initialize` runs once per engine; calling it again returns the first result.
- `DefaultCloudManager` is process-global: two engines in one process share cloud stores and refresh stamps by design.
- `SecurityConfig.Validate()` mutates the config (fills defaults, clamps the cloud refresh interval, normalizes log levels); constructing `SecurityConfig{}` literally without validation leaves zero values that checks read directly.
- `PassiveMode` returns `nil` (allowed) from checks but still stashes block reasons and fires hooks; do not use response-nil as "nothing happened".
- Detection patterns are `regexp2`, not stdlib `regexp` (different syntax; `\Z` is translated to `\z`). Every pattern must keep its `MatchTimeout`; removing the timeout reintroduces ReDoS.
- CORS, geo lists, dynamic rules and agent telemetry are implemented. Inconsistent combinations (enrichment without the agent, a dynamic-rule interval under 60) return an error at config time by design; do not "fix" this by relaxing config validation.
- The root `adapters/` directory is empty and untracked by git; it is a placeholder, not a package.
- `KNOWN_GAPS.md` at the repo root is the maintainer's local working notes and is gitignored; never commit or reference it in code.

## Related Projects

- guard-core (Python): the reference engine; source of the conformance corpus expected values and the other participant in the Redis interop harness.
- nethttp-guard: the Go `net/http` adapter that translates framework requests into `guardcore.Request` and `guardcore.Response` back into HTTP responses; it contains no security logic.
