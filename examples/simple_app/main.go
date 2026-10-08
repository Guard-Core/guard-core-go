// Command simple_app is a minimal guarded net/http server built directly on
// the guard-core-go engine. It demonstrates the canonical engine wiring:
//
//	SecurityConfig -> NewEngine -> Initialize -> per-request Check
//
// guard-core-go is framework-agnostic, so this app also contains a tiny
// net/http shim (about 40 lines) that mirrors what the official adapters
// (nethttp-guard, gin-guard, echo-guard, fiber-guard) do internally. For real
// services prefer an adapter; this shim exists to show the full contract.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
)

func main() {
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		// Rate limiting: global 30 req/60s per client, with a strict
		// per-endpoint override used by the demo and the live smoke test.
		c.EnableRateLimiting = true
		c.RateLimit = 30
		c.RateLimitWindow = 60
		c.EndpointRateLimits = map[string]guardcore.RateLimitEntry{
			"/rate/strict": {Requests: 1, Window: 10},
		}

		// IP banning: 5 violations in the window earns a 5 minute ban.
		c.EnableIPBanning = true
		c.AutoBanThreshold = 5
		c.AutoBanDuration = 300

		// Penetration detection: all categories, default thresholds.
		c.EnablePenetrationDetection = true

		// The Python engine automatically skips ssrf scanning for address
		// headers (host, x-forwarded-for, x-real-ip, ...). This port does
		// not apply that built-in exclusion yet, so mirror it here;
		// otherwise a plain "Host: localhost" request is flagged as ssrf.
		// Excluding these headers only narrows detection scanning, it does
		// not affect trusted-proxy client IP resolution.
		c.ExcludedDetectionHeaders = map[string]bool{
			"host": true, "origin": true, "via": true,
			"x-forwarded-for": true, "x-forwarded-host": true,
			"x-real-ip": true, "x-client-ip": true,
			"x-cluster-client-ip": true, "cf-connecting-ip": true,
			"true-client-ip": true, "fly-client-ip": true,
			"x-envoy-external-address": true,
		}

		// Blocked user agents (regex patterns).
		c.BlockedUserAgents = []string{"badbot", "evil-crawler", "sqlmap"}

		// Custom block bodies, keyed by status code.
		c.CustomErrorResponses = map[int]string{
			403: "Blocked by guard-core-go",
		}

		// Paths the pipeline never sees.
		c.ExcludePaths = []string{
			"/docs", "/redoc", "/openapi.json", "/favicon.ico", "/static", "/health",
		}

		// OnBlock is the telemetry seam of this port. Guard Agent
		// integration is not implemented in guard-core-go yet (setting
		// EnableAgent fails config validation), so wire the agent from
		// here: forward these payloads to guard-agent-go
		// (https://github.com/Guard-Core/guard-agent-go) once its event
		// pipeline accepts engine events. The payload carries check_name,
		// reason, trigger_info, passive_mode, client_ip, path, method, and
		// status_code.
		c.OnBlock = func(req guardcore.Request, payload map[string]any) {
			log.Printf("guard blocked %s %s from %s via %s: %s",
				payload["method"], payload["path"], payload["client_ip"],
				payload["check_name"], payload["reason"])
		}

		// Redis: enabled when REDIS_URL is set (docker compose sets it to
		// redis://redis:6379). Without Redis the managers fall back to
		// in-process state, which is fine for a demo but not for replicas.
		if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
			c.EnableRedis = true
			c.RedisURL = redisURL
		} else {
			c.EnableRedis = false
		}
		if prefix := os.Getenv("REDIS_PREFIX"); prefix != "" {
			c.RedisPrefix = prefix
		}
	})
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	// Idempotent; connects Redis when enabled and primes cloud IP ranges.
	if err := engine.Initialize(); err != nil {
		log.Fatalf("initialize: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			log.Printf("engine close: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", info)
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/echo", echo)
	mux.HandleFunc("/rate/strict", strict)
	mux.HandleFunc("/search", search)

	log.Println("simple_app listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", guard(engine, mux)))
}

// guard is the minimal net/http adapter. It mirrors the official
// nethttp-guard shim: strip the port from RemoteAddr, keep the first header
// value per key, keep the first query value per key, and hand a replayable
// body prefix to the engine.
func guard(engine *guardcore.Engine, next http.Handler) http.Handler {
	factory := guardcore.NewRequestFactory()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
			// The engine consumes the byte slice; hand the handler a
			// replayable body so it can decode the payload itself.
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		header := make(map[string]string, len(r.Header))
		for k, v := range r.Header {
			if len(v) > 0 {
				header[k] = v[0]
			}
		}
		if r.Host != "" {
			header["Host"] = r.Host
		}

		query := make(map[string]string, len(r.URL.Query()))
		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				query[k] = v[0]
			}
		}

		req := factory.CreateRequest(guardcore.RequestOptions{
			Path:        r.URL.Path,
			Scheme:      "http",
			Host:        r.Host,
			RawQuery:    r.URL.RawQuery,
			Method:      r.Method,
			ClientHost:  clientHost(r),
			Header:      header,
			QueryParams: query,
			Body:        body,
		})

		resp := engine.Check(req)
		if resp == nil {
			next.ServeHTTP(w, r)
			return
		}
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(resp.Body)
	})
}

func clientHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func info(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"app":"guard-core-go simple_app","endpoints":` +
		`["/health","/echo (POST)","/rate/strict","/search?q="]}` + "\n"))
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

func echo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"echo":true}` + "\n"))
}

func strict(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"endpoint":"/rate/strict","limit":"1 request per 10 seconds"}` + "\n"))
}

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if strings.ContainsRune(q, '<') || strings.ContainsRune(q, '\'') {
		// The engine should have blocked requests that reach this handler
		// with hostile input; treat this as defense in depth.
		http.Error(w, "Blocked by guard-core-go", http.StatusForbidden)
		return
	}
	encoded, err := json.Marshal(map[string]any{"query": q, "results": []string{}})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(encoded, '\n'))
}
