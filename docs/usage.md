# Usage

## Engine lifecycle

The `Engine` facade composes config, route registry, Redis, ban manager, rate
limit manager, and the check pipeline.

```go
cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
    c.EnableRateLimiting = true
    c.RateLimit = 30
    c.RateLimitWindow = 60
})
if err != nil {
    log.Fatal(err) // config validation failure
}

engine, err := guardcore.NewEngine(cfg)
if err != nil {
    log.Fatal(err)
}

// Idempotent (sync.Once-guarded): connects Redis, primes cloud IP ranges,
// initializes ban/rate-limit state. Call once before the first Check.
if err := engine.Initialize(); err != nil {
    log.Fatal(err)
}
defer engine.Close()
```

Exposed fields: `engine.Config`, `engine.Routes`, `engine.Redis`,
`engine.Ban`, `engine.RateLimit`, `engine.Cloud`.

## The request contract

Adapters (or your own middleware) translate native requests into
`guardcore.Request` via the `RequestFactory`:

```go
type Request interface {
    URLPath() string
    URLScheme() string
    URLFull() string
    URLReplaceScheme(scheme string) string
    Method() string
    ClientHost() string
    Headers() Headers
    QueryParams() map[string]string
    Body() ([]byte, error)
    State() *RequestState
}
```

`RequestState` carries per-request resolution results (`ClientIP`,
`GuardRouteID`, `BypassChecks`, `AuthPrincipal`, ...). Set
`RequestOptions.State` if you need to seed a route ID or client IP directly.

## Checking requests

```go
resp := engine.Check(req)
if resp != nil {
    // Blocked. Write resp.StatusCode, resp.Headers, resp.Body.
}
```

Well-known block verdicts:

| Situation | Status | Body |
|---|---|---|
| Banned IP | 403 | `IP address banned` |
| Suspicious content | 403 | `Suspicious activity detected` |
| Rate limit exceeded | 429 | `Too many requests` |

All of these can be overridden through `SecurityConfig.CustomErrorResponses`.

## Standalone content detection

You can use the detector directly without the pipeline:

```go
result := guardcore.Detect(content, ip, context)
if result.IsThreat {
    log.Printf("threat score %.2f via %s", result.ThreatScore, result.DetectionMethod)
}
```

See [Detection](detection.md) for the full API.

## Managers

The managers are usable on their own for admin tooling:

```go
// IP bans
banned, err := engine.Ban.Ban("192.0.2.10", 3600, "manual")
if engine.Ban.IsIPBanned("192.0.2.10") {
    _ = engine.Ban.Unban("192.0.2.10")
}

// Rate limits
allowed, err := engine.RateLimit.CheckRateLimitByIP("192.0.2.10", "/api")
```

## Route-scoped configuration

Register route configs on the engine's registry and attach the route ID to
requests (adapters expose a `WithRouteID` context helper):

```go
engine.Routes.Register("strict", func(rc *guardcore.RouteConfig) {
    rc.RateLimit = 1
    rc.RateLimitWindow = 10
    rc.APIKeyRequired = true
})
```

## Net/http wiring

The engine has no HTTP dependency. For `net/http` services either use the
[`nethttp-guard`](https://github.com/Guard-Core/nethttp-guard) adapter or build
your own shim:

```go
factory := guardcore.NewRequestFactory()

func guardMiddleware(engine *guardcore.Engine, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
        header := map[string]string{}
        for k, v := range r.Header {
            header[k] = strings.Join(v, ",")
        }
        req := factory.CreateRequest(guardcore.RequestOptions{
            Path:       r.URL.Path,
            Scheme:     "http",
            Host:       r.Host,
            RawQuery:   r.URL.RawQuery,
            Method:     r.Method,
            ClientHost: r.RemoteAddr,
            Header:     header,
            QueryParams: func() map[string]string {
                qp := map[string]string{}
                for k, v := range r.URL.Query() {
                    qp[k] = v[0]
                }
                return qp
            }(),
            Body: body,
        })
        if resp := engine.Check(req); resp != nil {
            for k, v := range resp.Headers {
                w.Header().Set(k, v)
            }
            w.WriteHeader(resp.StatusCode)
            _, _ = w.Write(resp.Body)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

!!! note
    For production wiring prefer the `nethttp-guard` adapter: it handles
    trusted proxy resolution, replayable bodies, and fail-closed error
    handling. The [`examples/`](https://github.com/Guard-Core/guard-core-go/tree/master/examples)
    directory shows both a minimal and a production-style layout.
