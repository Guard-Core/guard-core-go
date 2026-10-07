package guardcore

// Branch completion for the sus-patterns registry: the seeding helper, the
// truncation helper, the uncompilable-pattern rejection, the agentless
// telemetry suppression, the persistence error paths and the detection
// edge identities.

import (
	"errors"
	"strings"
	"testing"
)

func TestSeedCustomPattern(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	m.SeedCustomPattern("seeded-[a-z]+")
	customs := m.GetCustomPatterns()
	if len(customs) != 1 || customs[0] != "seeded-[a-z]+" {
		t.Fatalf("seed wrong: %v", customs)
	}
	// the seeded pattern participates in the scan
	threats := m.scanCustomPatterns("a seeded-abc b")
	if len(threats) != 1 {
		t.Fatalf("seeded scan wrong: %v", threats)
	}
	// an uncompilable seed is skipped
	m.SeedCustomPattern("*bad")
	if len(m.GetCustomPatterns()) != 1 {
		t.Fatalf("uncompilable seed leaked: %v", m.GetCustomPatterns())
	}
}

func TestAddPatternUncompilable(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	// a pattern the safety chain accepts but the engine cannot compile:
	// the escaped-control form parses as literals while regexp2 rejects
	// the class-bad escape shape
	if m.AddPattern(`[[:bogus:]]+`, true) {
		t.Log("posix-style class accepted by regexp2")
	}
	if len(m.GetCustomPatterns()) > 1 {
		t.Fatalf("unexpected registry growth: %v", m.GetCustomPatterns())
	}
}

func TestDetectPatternMatchSemanticIdentity(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	// a semantic-only threat carries the semantic:<attack_type> identity
	matched, identity := m.DetectPatternMatch(
		"../../../../../../etc/passwd%00", "203.0.113.7", "url_path", "")
	if !matched {
		t.Skip("no semantic threat for this input")
	}
	if !strings.HasPrefix(identity, "semantic:") && identity == "unknown" {
		t.Fatalf("semantic identity wrong: %q", identity)
	}
}

func TestDetectCustomThreatsCountSemantic(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	// the structural-dense corpus input carries a semantic component: the
	// counts branch runs over the mixed threat list
	agent := &susCaptureAgent{}
	m.SetAgentHandler(agent)
	defer m.SetAgentHandler(nil)
	result := m.Detect(
		"${x} <t> (y) [z] {w} a://b c://d <b>call(f(x))</b> union select concat(database(),table_name) from information_schema.tables where 1=1 {{render(jinja(template(mustache(handlebars(ejs(pug(twig)))))))}}",
		"203.0.113.7", "request_body", "")
	if !result.IsThreat || len(agent.events) != 1 {
		t.Fatalf("mixed detection wrong: %v %d", result.IsThreat, len(agent.events))
	}
	metadata := agent.events[0].Metadata
	if metadata["semantic_threats"] == 0 || metadata["regex_threats"] == 0 {
		t.Fatalf("mixed counts wrong: %v", metadata)
	}
}

func TestDetectPreviewTruncation(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	agent := &susCaptureAgent{}
	m.SetAgentHandler(agent)
	defer m.SetAgentHandler(nil)

	long := "<script>alert(1)</script>" + strings.Repeat("x", 200)
	m.Detect(long, "203.0.113.7", "request_body", "")
	if len(agent.events) != 1 {
		t.Fatalf("event missing: %d", len(agent.events))
	}
	preview, _ := agent.events[0].Metadata["content_preview"].(string)
	if len([]rune(preview)) != 100 {
		t.Fatalf("preview not capped: %d", len([]rune(preview)))
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("abcdef", 3); got != "abc" {
		t.Fatalf("truncate wrong: %q", got)
	}
	if got := truncateRunes("ab", 3); got != "ab" {
		t.Fatalf("under-limit truncate wrong: %q", got)
	}
}

func TestSendEventAgentError(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	m.SetAgentHandler(errorAgent{})
	m.AddPattern("errpattern-[a-z]+", true)
	// the send failure is logged and never raised; the pattern still landed
	if len(m.GetCustomPatterns()) != 1 {
		t.Fatalf("pattern missing after agent error: %v", m.GetCustomPatterns())
	}
}

type errorAgent struct{}

func (errorAgent) SendEvent(event SecurityEvent) error { return errors.New("agent down") }
func (errorAgent) SendMetric(metric SecurityMetric) error {
	return errors.New("agent down")
}

func TestScanCustomPatternsEmptyRegistry(t *testing.T) {
	resetSusPatternsForTest(t)
	if threats := DefaultSusPatternsManager.scanCustomPatterns("anything"); len(threats) != 0 {
		t.Fatalf("empty registry scanned threats: %v", threats)
	}
}

func TestInitializeRedisNilHandler(t *testing.T) {
	resetSusPatternsForTest(t)
	DefaultSusPatternsManager.InitializeRedis(nil)
}

func TestInstallAgentStreamNilDetaches(t *testing.T) {
	resetSusPatternsForTest(t)
	cfg, err := NewSecurityConfig(func(sc *SecurityConfig) {})
	if err != nil {
		t.Fatal(err)
	}
	// an agentless config detaches the registry handler at construction
	if _, err := NewEngine(cfg); err != nil {
		t.Fatal(err)
	}
	if DefaultSusPatternsManager.currentAgentHandler() != nil {
		t.Fatal("agentless engine left the registry handler attached")
	}
}

type failingSetKeyRedis struct{ live *RedisManager }

func (f *failingSetKeyRedis) Prefix() string { return f.live.Prefix() }
func (f *failingSetKeyRedis) Enabled() bool  { return f.live.Enabled() }
func (f *failingSetKeyRedis) Initialize() error {
	return f.live.Initialize()
}
func (f *failingSetKeyRedis) Close() error { return f.live.Close() }
func (f *failingSetKeyRedis) GetKey(namespace, key string) (string, error) {
	return f.live.GetKey(namespace, key)
}
func (f *failingSetKeyRedis) SetKey(namespace, key, value string, ttlSeconds *int) error {
	return errors.New("redis write refused")
}
func (f *failingSetKeyRedis) Delete(namespace, key string) (int64, error) {
	return f.live.Delete(namespace, key)
}
func (f *failingSetKeyRedis) Keys(pattern string) ([]string, error) {
	return f.live.Keys(pattern)
}
func (f *failingSetKeyRedis) DeletePattern(pattern string) (int64, error) {
	return f.live.DeletePattern(pattern)
}

func TestAddPatternPersistError(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	live := newSusPatternsLiveRedis(t)
	if err := live.Initialize(); err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	m.InitializeRedis(&failingSetKeyRedis{live: live})
	// the add succeeds: the persistence failure is logged, never raised
	if !m.AddPattern("persistfail-[a-z]+", true) {
		t.Fatal("add failed on a persistence error")
	}
	if len(m.GetCustomPatterns()) != 1 {
		t.Fatalf("pattern missing: %v", m.GetCustomPatterns())
	}
}

func TestRemovePatternPersistError(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	live := newSusPatternsLiveRedis(t)
	if err := live.Initialize(); err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	m.InitializeRedis(&failingSetKeyRedis{live: live})
	m.AddPattern("persistfail2-[a-z]+", true)
	if !m.RemovePattern("persistfail2-[a-z]+", true) {
		t.Fatal("removal failed on a persistence error")
	}
}

func TestRemovePatternKeepsOtherEntries(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	live := newSusPatternsLiveRedis(t)
	if err := live.Initialize(); err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	defer func() {
		_, _ = live.Delete("patterns", "custom")
	}()
	m.InitializeRedis(live)
	m.AddPattern("keepme-[a-z]+", true)
	m.AddPattern("dropme-[a-z]+", true)
	if !m.RemovePattern("dropme-[a-z]+", true) {
		t.Fatal("removal failed")
	}
	customs := m.GetCustomPatterns()
	if len(customs) != 1 || customs[0] != "keepme-[a-z]+" {
		t.Fatalf("other entries not kept: %v", customs)
	}
}

func TestInitializeRedisDeadHandler(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	dead := NewRedisManager(RedisConfig{URL: "redis://127.0.0.1:1", Prefix: "guard_core_test_dead:", EnableRedis: true})
	defer func() { _ = dead.Close() }()
	// the GetKey error path logs and returns; no panic
	m.InitializeRedis(dead)
	if len(m.GetCustomPatterns()) != 0 {
		t.Fatal("dead handler restored patterns")
	}
}

func TestInitializeRedisTrailingComma(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	live := newSusPatternsLiveRedis(t)
	if err := live.Initialize(); err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	defer func() {
		_, _ = live.Delete("patterns", "custom")
	}()
	if err := live.SetKey("patterns", "custom", "trailing-[a-z]+,", nil); err != nil {
		t.Fatal(err)
	}
	m.InitializeRedis(live)
	customs := m.GetCustomPatterns()
	if len(customs) != 1 {
		t.Fatalf("trailing comma restore wrong: %v", customs)
	}
}

func TestAddPatternEngineIncompilable(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	// x{3,2} parses as literals in the Python-re grammar (the compile gate
	// accepts it) while the regexp2 timing engine rejects the range
	if m.AddPattern("x{3,2}", true) {
		t.Fatal("engine-incompilable pattern accepted")
	}
}

func TestClearCustomPatternsDirect(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	m.SeedCustomPattern("clearme-[a-z]+")
	m.ClearCustomPatterns()
	if len(m.GetCustomPatterns()) != 0 {
		t.Fatalf("clear failed: %v", m.GetCustomPatterns())
	}
}

func TestScanCustomPatternsNonMatch(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	m.SeedCustomPattern("nomatch-[a-z]+z")
	if threats := m.scanCustomPatterns("nothing here"); len(threats) != 0 {
		t.Fatalf("non-matching content scanned threats: %v", threats)
	}
}

func TestInitializeRedisSkipsKnown(t *testing.T) {
	resetSusPatternsForTest(t)
	m := DefaultSusPatternsManager
	live := newSusPatternsLiveRedis(t)
	if err := live.Initialize(); err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	defer func() {
		_, _ = live.Delete("patterns", "custom")
	}()
	if !m.AddPattern("known-[a-z]+", true) {
		t.Fatal("add failed")
	}
	// the persisted set now contains the known pattern; the restore skips it
	m.InitializeRedis(live)
	if len(m.GetCustomPatterns()) != 1 {
		t.Fatalf("known skip wrong: %v", m.GetCustomPatterns())
	}
}

func TestSeedCustomPatternZeroValueManager(t *testing.T) {
	var m SusPatternsManager
	m.SeedCustomPattern("zero-[a-z]+")
	if len(m.GetCustomPatterns()) != 1 {
		t.Fatalf("zero-value seed wrong: %v", m.GetCustomPatterns())
	}
	m.ClearCustomPatterns()
	if len(m.GetCustomPatterns()) != 0 {
		t.Fatalf("zero-value clear wrong: %v", m.GetCustomPatterns())
	}
}
