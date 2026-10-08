# guard-core-go

Guard Core Go: the API security core engine for Go. A framework-agnostic port of the [guard-core](https://github.com/Guard-Core/guard-core) detection engine that powers the Go adapters: [nethttp-guard](https://github.com/Guard-Core/nethttp-guard), [gin-guard](https://github.com/Guard-Core/gin-guard), [echo-guard](https://github.com/Guard-Core/echo-guard), and [fiber-guard](https://github.com/Guard-Core/fiber-guard).

Docs: <https://guard-core.github.io/guard-core-go/>

## Install

```sh
go get github.com/rennf93/guard-core-go/v4@v4.0.4
```

The module is `github.com/rennf93/guard-core-go/v4`; the primary package is `guardcore`.

## Usage

```go
package main

import (
	"log"

	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
)

func main() {
	cfg := guardcore.DefaultSecurityConfig()
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := engine.Initialize(); err != nil {
		log.Fatal(err)
	}
}
```

The engine provides IP control and rate limiting, signature-based penetration detection, security headers, behavioral tracking, and cloud-provider range checks. Framework adapters translate native request types into the guardcore request surface and verdicts back into exact HTTP responses; build your own integration against the engine directly when an adapter is not available.

## License

MIT. See [LICENSE](LICENSE).
