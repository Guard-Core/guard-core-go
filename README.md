<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Guard Core Go: the API security core engine for Go. A framework-agnostic port of the [guard-core](https://github.com/Guard-Core/guard-core) detection engine that powers the Go adapters: [nethttp-guard](https://github.com/Guard-Core/nethttp-guard), [gin-guard](https://github.com/Guard-Core/gin-guard), [echo-guard](https://github.com/Guard-Core/echo-guard), and [fiber-guard](https://github.com/Guard-Core/fiber-guard).</strong>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-core-go/releases">
        <img src="https://img.shields.io/github/v/tag/Guard-Core/guard-core-go?label=release&color=0080ff" alt="Release tag">
    </a>
    <a href="https://guard-core.github.io/guard-core-go/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-go/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/guard-core-go/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-go/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-core-go/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-go/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/guard-core-go/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-core-go/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/guard-core-go/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-go/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/guard-core-go/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/guard-core-go?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Go-00ADD8.svg?style=flat&logo=go&logoColor=white" alt="Go"> <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&logo=redis&logoColor=white" alt="Redis">
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/guard-core-go/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---

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
