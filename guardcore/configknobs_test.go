package guardcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func captureLogForKnobs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestDetectionKnobValidation(t *testing.T) {
	_, err := NewSecurityConfig(func(c *SecurityConfig) { c.Detection.MaxScanValues = 1 })
	if err == nil || !strings.Contains(err.Error(), "detection_max_scan_values") {
		t.Fatalf("scan values below 2 must be rejected, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.Detection.MaxScanChars = 1 })
	if err == nil || !strings.Contains(err.Error(), "detection_max_scan_chars") {
		t.Fatalf("scan chars below 1024 must be rejected, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.Detection.MaxJSONDepth = 0 })
	if err != nil {
		t.Fatalf("zero depth means the default and must validate, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.Detection.MaxJSONDepth = 1001 })
	if err == nil || !strings.Contains(err.Error(), "detection_max_json_depth") {
		t.Fatalf("depth above 1000 must be rejected, got %v", err)
	}
	ok, err := NewSecurityConfig(nil)
	if err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if ok.Detection.MaxScanValues != 512 || ok.Detection.MaxScanChars != 65536 || ok.Detection.MaxJSONDepth != 32 {
		t.Fatalf("reference defaults must apply, got %+v", ok.Detection)
	}
	if ok.BodyReadTimeout != 3*time.Second || ok.SyncBodyReadMaxConcurrent != 64 || ok.LogCountryCheckLevel != "INFO" || ok.RedisRetries != 1 {
		t.Fatalf("the knob defaults must apply, got %+v", ok)
	}
}

func TestBodyReadKnobValidation(t *testing.T) {
	_, err := NewSecurityConfig(func(c *SecurityConfig) { c.BodyReadTimeout = -time.Second })
	if err == nil || !strings.Contains(err.Error(), "body_read_timeout") {
		t.Fatalf("negative timeout must be rejected, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.BodyReadTimeout = 31 * time.Second })
	if err == nil || !strings.Contains(err.Error(), "body_read_timeout") {
		t.Fatalf("timeout over 30s must be rejected, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.SyncBodyReadMaxConcurrent = 10001 })
	if err == nil || !strings.Contains(err.Error(), "sync_body_read_max_concurrent") {
		t.Fatalf("slot budget over 10000 must be rejected, got %v", err)
	}
}

func TestRedisKnobValidation(t *testing.T) {
	zero := 0 * time.Second
	_, err := NewSecurityConfig(func(c *SecurityConfig) { c.RedisSocketConnectTimeout = &zero })
	if err == nil || !strings.Contains(err.Error(), "redis_socket_connect_timeout") {
		t.Fatalf("a zero connect timeout must be rejected, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.RedisSocketTimeout = &zero })
	if err == nil || !strings.Contains(err.Error(), "redis_socket_timeout") {
		t.Fatalf("a zero socket timeout must be rejected, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.RedisRetries = -1 })
	if err == nil || !strings.Contains(err.Error(), "redis_retries") {
		t.Fatalf("negative retries must be rejected, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.RedisMaxConnections = -1 })
	if err == nil || !strings.Contains(err.Error(), "redis_max_connections") {
		t.Fatalf("negative pool size must be rejected, got %v", err)
	}
	_, err = NewSecurityConfig(func(c *SecurityConfig) { c.RedisHealthCheckInterval = -time.Second })
	if err == nil || !strings.Contains(err.Error(), "redis_health_check_interval") {
		t.Fatalf("negative health interval must be rejected, got %v", err)
	}
}

func TestRedisKnobsPlumbIntoInitialize(t *testing.T) {
	cfg := testConfig(t)
	connect := 250 * time.Millisecond
	socket := 250 * time.Millisecond
	cfg.EnableRedis = true
	cfg.RedisURL = "redis://127.0.0.1:1" // dead port: the dial fails fast
	cfg.RedisSocketConnectTimeout = &connect
	cfg.RedisSocketTimeout = &socket
	cfg.RedisHealthCheckInterval = time.Minute
	cfg.RedisMaxConnections = 3
	cfg.RedisRetries = 0
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()
	// The overrides apply inside Initialize: the dead port fails under the
	// tightened budget (the default budget would take seconds).
	start := time.Now()
	err = engine.Redis.Initialize()
	if err == nil {
		t.Fatal("the dead redis must fail Initialize")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the configured timeouts must bound the failed dial, took %v", elapsed)
	}
}

func TestBoundBodyReadFastPath(t *testing.T) {
	cfg := testConfig(t)
	body, err := BoundBodyRead(cfg, func() ([]byte, error) { return []byte("ok"), nil })
	if err != nil || string(body) != "ok" {
		t.Fatalf("a fast read must pass through, got (%q, %v)", body, err)
	}
	nilCfgBody, err := BoundBodyRead(nil, func() ([]byte, error) { return []byte("raw"), nil })
	if err != nil || string(nilCfgBody) != "raw" {
		t.Fatalf("a nil config must read directly, got (%q, %v)", nilCfgBody, err)
	}
}

func TestBoundBodyReadTimesOut(t *testing.T) {
	buf := captureLogForKnobs(t)
	cfg := testConfig(t)
	cfg.BodyReadTimeout = 50 * time.Millisecond
	body, err := BoundBodyRead(cfg, func() ([]byte, error) {
		time.Sleep(300 * time.Millisecond)
		return []byte("late"), nil
	})
	if !errors.Is(err, errBodyReadTimeout) || body != nil {
		t.Fatalf("a stalled read must report the body unavailable, got (%q, %v)", body, err)
	}
	if !strings.Contains(err.Error(), "body_read_timeout") {
		t.Fatalf("the timeout error must name the knob, got %v", err)
	}
	// The abandoned read goroutine keeps running; give it a moment to
	// release the slot before the suite moves on.
	time.Sleep(350 * time.Millisecond)
	if strings.Contains(buf.String(), "sync_body_read_max_concurrent") {
		t.Fatal("a plain timeout must not log the budget exhaustion")
	}
}

func TestBoundBodyReadBudgetExhausted(t *testing.T) {
	buf := captureLogForKnobs(t)
	cfg := testConfig(t)
	cfg.BodyReadTimeout = 80 * time.Millisecond
	cfg.SyncBodyReadMaxConcurrent = 1
	setBodyReadSlotsCapacityForTest(1)
	// Park the single slot with a stalled read, then the next read gives
	// up with the exhaustion log and the budget error.
	parked := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_, _ = BoundBodyRead(cfg, func() ([]byte, error) {
			close(parked)
			<-release
			return nil, nil
		})
	}()
	<-parked
	body, err := BoundBodyRead(cfg, func() ([]byte, error) { return []byte("nope"), nil })
	close(release)
	if !errors.Is(err, errBodyReadBudget) || body != nil {
		t.Fatalf("an exhausted budget must give up without reading, got (%q, %v)", body, err)
	}
	if !strings.Contains(buf.String(), "sync_body_read_max_concurrent (1) exhausted") {
		t.Fatalf("the exhaustion must be logged, got %q", buf.String())
	}
	if !strings.Contains(err.Error(), "sync_body_read_max_concurrent") {
		t.Fatalf("the budget error must name the knob, got %v", err)
	}
	time.Sleep(120 * time.Millisecond)
}

func setBodyReadSlotsCapacityForTest(n int) {
	bodyReadSlotsOnce.Do(func() {})
	bodyReadSlots = make(chan struct{}, n)
}

func TestScanBudgetExhaustionWarnsOnce(t *testing.T) {
	buf := captureLogForKnobs(t)
	cfg := testConfig(t)
	cfg.Detection.MaxScanValues = 2
	cfg.Detection.MaxScanChars = 10
	budget := newDetectionScanBudget(cfg, "203.0.113.9")
	if budget.exhausted("aaaa") {
		t.Fatal("the first value must scan")
	}
	if budget.exhausted("bbbb") {
		t.Fatal("the second value must scan")
	}
	if !budget.exhausted("cccc") {
		t.Fatal("the value cap must bite on the third value")
	}
	if !strings.Contains(buf.String(), "detection_max_scan_values (2) reached for client 203.0.113.9") {
		t.Fatalf("the value-cap warning must name the client, got %q", buf.String())
	}
	// A fresh budget exercises the char cap (the first value consumes the
	// cap exactly, the second is skipped with the warning).
	buf2 := captureLogForKnobs(t)
	charBudget := newDetectionScanBudget(cfg, "203.0.113.8")
	if charBudget.exhausted("0123456789") {
		t.Fatal("the first value scans and consumes the char cap exactly")
	}
	if !charBudget.exhausted("x") {
		t.Fatal("the char cap must bite once consumed")
	}
	if !strings.Contains(buf2.String(), "detection_max_scan_chars (10) reached for client 203.0.113.8") {
		t.Fatalf("the char-cap warning must name the client, got %q", buf2.String())
	}
	if budget.exhausted("more") != true {
		t.Fatal("beyond the value cap every value is skipped")
	}
	_ = buf
}

func TestScanBudgetDepthCap(t *testing.T) {
	budget := newDetectionScanBudget(nil, "x")
	if budget.depthCap() != 32 {
		t.Fatalf("a nil config must fall back to the reference depth default, got %d", budget.depthCap())
	}
	if budgetDepthCap(nil) != 32 {
		t.Fatal("a nil budget must fall back to the reference depth default")
	}
	buf := captureLogForKnobs(t)
	cfg := testConfig(t)
	cfg.Detection.MaxJSONDepth = 3
	deep := newDetectionScanBudget(cfg, "203.0.113.7")
	deep.warnJSONDepthOnce()
	deep.warnJSONDepthOnce()
	logged := buf.String()
	if strings.Count(logged, "detection_max_json_depth (3) reached") != 1 {
		t.Fatalf("the depth warning must fire exactly once, got %q", logged)
	}
	if !strings.Contains(logged, "nested content below that depth is scanned as text") {
		t.Fatalf("the depth warning must carry the reference text, got %q", logged)
	}
}

func TestDetectThreatStopsAtScanValueCap(t *testing.T) {
	buf := captureLogForKnobs(t)
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.Detection.MaxScanValues = 2
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	// All values are benign, so the verdict is deterministic regardless of
	// the param map's random iteration order: the two scanned values pass,
	// the rest hit the cap and never scan.
	req := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/clean"
		opts.RawQuery = "a=clean1&b=clean2&c=clean3&d=clean4"
		opts.QueryParams = map[string]string{
			"a": "clean1",
			"b": "clean2",
			"c": "clean3",
			"d": "clean4",
		}
	})
	categories, _ := detectThreat(req, cfg, resolveDetectionExclusions(cfg, nil))
	if categories != nil {
		t.Fatalf("clean values must not detect, got %v", categories)
	}
	if !strings.Contains(buf.String(), "detection_max_scan_values (2) reached") {
		t.Fatalf("the cap warning must fire, got %q", buf.String())
	}
}

func TestJSONDepthCapSerializesAsText(t *testing.T) {
	buf := captureLogForKnobs(t)
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.Detection.MaxJSONDepth = 2
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	body := `{"a": {"b": {"c": {"d": "deep"}}}}`
	values := extractBodyScanValues(body, "application/json", cfg, nil, newDetectionScanBudget(cfg, "203.0.113.9"))
	joined := ""
	for _, v := range values {
		joined += v.content + "|"
	}
	if !strings.Contains(joined, `"c"`) || strings.Contains(joined, "deep\", \"e") {
		t.Fatalf("the walk must serialize below-cap containers as text, got %q", joined)
	}
	if !strings.Contains(buf.String(), "detection_max_json_depth (2) reached") {
		t.Fatalf("the depth warning must fire, got %q", buf.String())
	}
}

func TestCountryVerdictLogging(t *testing.T) {
	cfg := testConfig(t)
	cfg.GeoIPHandler = fakeCountryResolver{"203.0.113.9": "BR", "198.51.100.7": "US"}
	cfg.LogCountryCheckLevel = "INFO"
	buf := captureLogForKnobs(t)

	cfg.BlockedCountries = []string{"BR"}
	if _, blocked := globalCountryVerdict(cfg, "203.0.113.9"); !blocked {
		t.Fatal("a blocked country must block")
	}
	if !strings.Contains(buf.String(), "IP from blocked country 203.0.113.9 - BR - IP from blocked country") {
		t.Fatalf("the blocked verdict must log, got %q", buf.String())
	}

	cfg.BlockedCountries = []string{"DE"}
	if _, blocked := globalCountryVerdict(cfg, "198.51.100.7"); blocked {
		t.Fatal("a non-blocked country must pass")
	}
	if !strings.Contains(buf.String(), "IP not from blocked or whitelisted country 198.51.100.7 - US") {
		t.Fatalf("the not-affected verdict must log at the country level, got %q", buf.String())
	}
	before := buf.Len()
	cfg.LogCountryCheckLevel = ""
	_, _ = globalCountryVerdict(cfg, "198.51.100.7")
	if buf.Len() != before {
		t.Fatalf("an empty log_country_check_level must silence the non-block verdicts")
	}
}

func TestAgentStrictFailsNewEngine(t *testing.T) {
	_, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableAgent = true
		c.AgentHandler = nil
		c.AgentStrict = true
	})
	if err != nil {
		t.Fatalf("config must validate (strictness bites at engine construction): %v", err)
	}
	_, engineErr := NewEngine(func() *SecurityConfig {
		c, _ := NewSecurityConfig(func(c *SecurityConfig) {
			c.EnableAgent = true
			c.AgentStrict = true
		})
		return c
	}())
	if engineErr == nil || !strings.Contains(engineErr.Error(), "agent cannot initialize") {
		t.Fatalf("strict mode must fail the engine construction, got %v", engineErr)
	}

	// Non-strict degrades with the reference log lines.
	buf := captureLogForKnobs(t)
	hookStages := []string{}
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableAgent = true
		c.OnError = func(stage string, err error, ctx map[string]any) { hookStages = append(hookStages, stage) }
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, engineErr := NewEngine(cfg)
	if engineErr != nil {
		t.Fatalf("non-strict mode must degrade, got %v", engineErr)
	}
	defer engine.Close()
	if !strings.Contains(buf.String(), "Continuing without agent functionality") {
		t.Fatalf("the degrade must log the reference line, got %q", buf.String())
	}
	if len(hookStages) != 1 || hookStages[0] != "agent_init" {
		t.Fatalf("the on_error hook must fire at the agent_init stage, got %v", hookStages)
	}
}

func TestInvokeErrorHookContainment(t *testing.T) {
	buf := captureLogForKnobs(t)
	cfg := testConfig(t)
	cfg.OnError = func(stage string, err error, ctx map[string]any) { panic("hook blew up") }
	invokeErrorHook(cfg, "geoip", errors.New("lookup failed"), map[string]any{"client_ip": "1.2.3.4"})
	if !strings.Contains(buf.String(), "on_error hook raised while handling 'geoip'") {
		t.Fatalf("a panicking hook must be contained with the reference log, got %q", buf.String())
	}
	invokeErrorHook(nil, "geoip", errors.New("x"), nil)
	invokeErrorHook(testConfig(t), "geoip", errors.New("x"), nil)
}

func TestLookupCountryHookOnPanickingResolver(t *testing.T) {
	hookCalled := false
	cfg := testConfig(t)
	cfg.OnError = func(stage string, err error, ctx map[string]any) {
		hookCalled = stage == "geoip" && ctx["client_ip"] == "203.0.113.9"
	}
	cfg.GeoIPHandler = panickingResolver{}
	bus := NewSecurityEventBus(nil, cfg, cfg.GeoIPHandler, EventFilter{})
	if country := bus.lookupCountry("203.0.113.9"); country != "" {
		t.Fatalf("a panicking resolver must yield an empty country, got %q", country)
	}
	if !hookCalled {
		t.Fatal("the on_error hook must fire at the geoip stage")
	}
}

type panickingResolver struct{}

func (panickingResolver) GetCountry(ip string) (string, bool) {
	panic("resolver exploded")
}

func TestPatternValidationCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	cache := NewPatternValidationCache(path)
	calls := 0
	probe := func() (bool, string) { calls++; return true, "safe" }
	allowed, reason := cache.cachedEmpiricalVerdict("a?", 1, probe)
	if !allowed || reason != "safe" || calls != 1 {
		t.Fatalf("the first verdict must come from the probe, got (%v, %q, %d calls)", allowed, reason, calls)
	}
	if allowed, _ := cache.cachedEmpiricalVerdict("a?", 1, probe); !allowed {
		t.Fatal("the second verdict must come from the cache")
	}
	if calls != 1 {
		t.Fatalf("the probe must run exactly once, got %d", calls)
	}
	if _, _ = cache.cachedEmpiricalVerdict("b+", 1, probe); calls != 2 {
		t.Fatalf("a different pattern must re-probe, got %d calls", calls)
	}

	// A different engine version's file is dropped on load.
	stale := patternValidationFile{
		SchemaVersion: patternValidationCacheVersion,
		EngineVersion: "0-stale",
		Entries:       map[string]patternValidationEntry{"1|a?": {Allowed: false, Reason: "stale"}},
	}
	data, err := json.Marshal(stale)
	if err != nil {
		t.Fatalf("marshal stale cache: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write stale cache: %v", err)
	}
	reloaded := NewPatternValidationCache(path)
	calls = 0
	allowed, _ = reloaded.cachedEmpiricalVerdict("a?", 1, probe)
	if !allowed || calls != 1 {
		t.Fatalf("a stale entry must be ignored, got (%v, %d calls)", allowed, calls)
	}

	// A corrupt file starts empty.
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt cache: %v", err)
	}
	buf := captureLogForKnobs(t)
	corrupt := NewPatternValidationCache(path)
	if corrupt == nil || len(corrupt.entries) != 0 {
		t.Fatal("a corrupt cache must start empty")
	}
	if !strings.Contains(buf.String(), "pattern validation cache") {
		t.Fatalf("the corrupt cache must be reported, got %q", buf.String())
	}

	// A missing file starts empty and silent.
	missing := NewPatternValidationCache(filepath.Join(dir, "absent.json"))
	if len(missing.entries) != 0 {
		t.Fatal("a missing cache file must start empty")
	}
}

func TestAddPatternUsesCachedValidation(t *testing.T) {
	dir := t.TempDir()
	installPatternValidationCache(NewPatternValidationCache(filepath.Join(dir, "cache.json")))
	defer installPatternValidationCache(nil)
	manager := NewSusPatternsManager(nil)
	if !manager.AddPattern("safe-pattern-"+time.Now().Format("150405.000000000"), true) {
		t.Fatal("a safe pattern must register through the cached chain")
	}
	// An unsafe pattern still rejects through the deterministic gates.
	if manager.AddPattern("(a+)+$", true) {
		t.Fatal("a catastrophically backtracking pattern must reject")
	}
}

func TestPerformanceMonitorWiringRecordsOverallDetection(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.Detection.AnomalyThreshold = 4
		c.Detection.SlowPatternThreshold = 0.5
		c.Detection.MonitorHistorySize = 120
		c.Detection.MaxTrackedPatterns = 200
		c.Detection.AnomalyEmissionCooldown = 30
		c.Detection.MinSamplesForAnomaly = 12
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()
	DefaultSusPatternsManager.Detect("clean content here", "203.0.113.9", "test", "corr-1")
	stats := DefaultSusPatternsManager.perfMonitor.GetSummaryStats()
	if stats.TotalExecutions == 0 {
		t.Fatalf("the overall_detection metric must be recorded, got %+v", stats)
	}
}

func TestNormalizeBodyReadSlots(t *testing.T) {
	if got := normalizeBodyReadSlots(0); got != 64 {
		t.Fatalf("a non-positive budget keeps the default, got %d", got)
	}
	if got := normalizeBodyReadSlots(5); got != 5 {
		t.Fatalf("a set budget applies verbatim, got %d", got)
	}
}

func TestNewEngineInstallsValidationCache(t *testing.T) {
	dir := t.TempDir()
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.Detection.PatternValidationCachePath = filepath.Join(dir, "cache.json")
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()
	if activePatternValidationCache() == nil {
		t.Fatal("the engine must install the configured validation cache")
	}
	installPatternValidationCache(nil)
}

func TestLogCountryCheckResultBranches(t *testing.T) {
	cfg := testConfig(t)
	buf := captureLogForKnobs(t)
	// A blocked hit with an empty suspicious level is silent.
	cfg.LogSuspiciousLevel = ""
	logCountryCheckResult(cfg, "blocked", "203.0.113.9", "BR")
	// An empty country renders the blocked line without the country.
	cfg.LogSuspiciousLevel = "WARNING"
	logCountryCheckResult(cfg, "blocked", "203.0.113.9", "")
	// An unknown country log level silences the whitelisted verdict.
	cfg.LogCountryCheckLevel = "TRACE"
	logCountryCheckResult(cfg, "whitelisted", "203.0.113.9", "BR")
	logCountryCheckResult(cfg, "not_affected", "203.0.113.9", "US")
	logCountryCheckResult(nil, "blocked", "203.0.113.9", "BR")
	logged := buf.String()
	if strings.Contains(logged, "IP from blocked country 203.0.113.9 - BR") {
		t.Fatalf("an empty suspicious level must silence blocked verdicts, got %q", logged)
	}
	if !strings.Contains(logged, "IP from blocked country 203.0.113.9 - IP from blocked country") {
		t.Fatalf("an empty country renders the short blocked line, got %q", logged)
	}
	if strings.Contains(logged, "IP from whitelisted country") || strings.Contains(logged, "IP not from blocked or whitelisted country") {
		t.Fatalf("an unknown country log level must silence non-block verdicts, got %q", logged)
	}
}

func TestClientIPForBudgetSentinel(t *testing.T) {
	req := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) { opts.ClientHost = "" })
	if got := clientIPForBudget(req); got != UnknownClientIdentity {
		t.Fatalf("an unknown identity must render the sentinel, got %q", got)
	}
}

func TestScanBudgetCapFallbacks(t *testing.T) {
	budget := newDetectionScanBudget(nil, "x")
	if budget.valuesCap() != 512 || budget.charsCap() != 65536 {
		t.Fatalf("a nil config must fall back to the reference caps, got (%d, %d)", budget.valuesCap(), budget.charsCap())
	}
	zero := testConfig(t)
	zero.Detection.MaxScanValues = 0
	zero.Detection.MaxScanChars = 0
	zero.Detection.MaxJSONDepth = 0
	fallback := newDetectionScanBudget(zero, "x")
	if fallback.valuesCap() != 512 || fallback.charsCap() != 65536 || fallback.depthCap() != 32 {
		t.Fatalf("zero caps must fall back to the reference defaults, got (%d, %d, %d)", fallback.valuesCap(), fallback.charsCap(), fallback.depthCap())
	}
}

func TestInitializeRedisSkipsUnrestorablePattern(t *testing.T) {
	buf := captureLogForKnobs(t)
	manager := NewSusPatternsManager(nil)
	manager.InitializeRedis(stubRedisHandler{value: "(a+)+$"})
	if !strings.Contains(buf.String(), "Skipped restoring persisted pattern") {
		t.Fatalf("an unrestorable persisted pattern must be skipped with the reference log, got %q", buf.String())
	}
}

type stubRedisHandler struct {
	value string
}

func (s stubRedisHandler) Prefix() string { return "test:" }
func (s stubRedisHandler) Enabled() bool  { return true }
func (s stubRedisHandler) Initialize() error {
	return nil
}
func (s stubRedisHandler) Close() error { return nil }
func (s stubRedisHandler) GetKey(namespace, key string) (string, error) {
	if namespace == "patterns" && key == "custom" {
		return s.value, nil
	}
	return "", nil
}
func (s stubRedisHandler) SetKey(namespace, key, value string, ttlSeconds *int) error {
	return nil
}
func (s stubRedisHandler) Delete(namespace, key string) (int64, error) {
	return 0, nil
}
func (s stubRedisHandler) Keys(pattern string) ([]string, error) {
	return nil, nil
}
func (s stubRedisHandler) DeletePattern(pattern string) (int64, error) {
	return 0, nil
}

func TestAgentHandlerAnomalySender(t *testing.T) {
	var sent SecurityEvent
	sender := agentHandlerAnomalySender{handler: &AgentHandlerFunc{EventFunc: func(event SecurityEvent) error {
		sent = event
		return nil
	}}}
	if err := sender.SendAnomalyEvent(AnomalyEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   EventPatternAnomalyTimeout,
		ActionTaken: "anomaly",
		Reason:      "timeout",
		Metadata:    map[string]any{"pattern": "x"},
	}); err != nil {
		t.Fatalf("the sender must deliver through the handler, got %v", err)
	}
	if sent.EventType != EventPatternAnomalyTimeout || sent.IPAddress != UnknownClientIdentity || sent.HandlerName != "middleware" {
		t.Fatalf("the anomaly must map onto the security event envelope, got %+v", sent)
	}
	if err := (agentHandlerAnomalySender{}).SendAnomalyEvent(AnomalyEvent{}); err != nil {
		t.Fatalf("a nil handler must no-op, got %v", err)
	}
}

func TestDetectThreatValueCapContinues(t *testing.T) {
	buf := captureLogForKnobs(t)
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.EnableRedis = false
		c.Detection.MaxScanValues = 2
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	req := newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/clean"
		opts.RawQuery = "a=clean1&b=clean2&c=clean3&d=clean4"
		opts.QueryParams = map[string]string{"a": "clean1", "b": "clean2", "c": "clean3", "d": "clean4"}
	})
	// All values are benign, so the verdict is deterministic regardless of
	// the param map's random iteration order: the two scanned values pass,
	// the rest hit the cap and never scan.
	if categories, _ := detectThreat(req, cfg, resolveDetectionExclusions(cfg, nil)); categories != nil {
		t.Fatalf("clean values must not detect, got %v", categories)
	}
	if !strings.Contains(buf.String(), "detection_max_scan_values (2) reached") {
		t.Fatalf("the cap warning must fire, got %q", buf.String())
	}
}

func TestScanBudgetZeroCapFallbackHandBuiltConfig(t *testing.T) {
	budget := newDetectionScanBudget(&SecurityConfig{}, "x")
	if budget.valuesCap() != 512 || budget.charsCap() != 65536 || budget.depthCap() != 32 {
		t.Fatalf("a hand-built zero config must fall back to the reference caps, got (%d, %d, %d)",
			budget.valuesCap(), budget.charsCap(), budget.depthCap())
	}
}

func TestPatternValidationCacheSaveFailures(t *testing.T) {
	dir := t.TempDir()
	// A directory in place of the cache's parent: MkdirAll and the write
	// fail; the verdict still returns from the live probe.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	buf := captureLogForKnobs(t)
	cache := NewPatternValidationCache(filepath.Join(blocker, "cache.json"))
	allowed, _ := cache.cachedEmpiricalVerdict("ok?", 1, func() (bool, string) { return true, "safe" })
	if !allowed {
		t.Fatal("a failing cache write must not change the verdict")
	}
	if !strings.Contains(buf.String(), "pattern validation cache") {
		t.Fatalf("the write failure must be reported, got %q", buf.String())
	}

	// A rename over a non-empty directory fails and is logged.
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(target, "inner"), 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	buf2 := captureLogForKnobs(t)
	renameCache := NewPatternValidationCache(target)
	renameCache.cachedEmpiricalVerdict("ok2?", 1, func() (bool, string) { return true, "safe" })
	if !strings.Contains(buf2.String(), "pattern validation cache rename failed") {
		t.Fatalf("the rename failure must be reported, got %q", buf2.String())
	}
}

func TestPatternValidationCacheReloadsValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	cache := NewPatternValidationCache(path)
	calls := 0
	probe := func() (bool, string) { calls++; return false, "unsafe: timed out" }
	cache.cachedEmpiricalVerdict("x?", 1, probe)
	reloaded := NewPatternValidationCache(path)
	allowed, reason := reloaded.cachedEmpiricalVerdict("x?", 1, probe)
	if allowed || reason != "unsafe: timed out" || calls != 1 {
		t.Fatalf("a valid file must restore the verdict without re-probing, got (%v, %q, %d calls)", allowed, reason, calls)
	}
}

func TestNilBudgetExhaustedIsNeverTrue(t *testing.T) {
	var budget *detectionScanBudget
	if budget.exhausted("anything") {
		t.Fatal("a nil budget never exhausts (the walk falls back to the reference defaults)")
	}
}
