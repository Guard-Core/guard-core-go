package conformance

// redis_interop-kind conformance suite (spec 4.1.0, redis_interop.json):
// byte-level pins of the engine's on-the-wire Redis surface per
// specs/08-redis-schema.md. Each case performs one operation through the
// REAL Go handlers pointed at the live Redis under the suite prefix, then
// probes every key the prefix scan observes: the exact key string, the
// Redis type, the TTL semantics (whether one is set and its configured
// value, never the remaining seconds), and the value bytes, member shapes
// and scores per the comparison contract (index.json > comparison >
// redis_interop): engine-generated values (ban expiry floats, epoch zset
// members, uuid4 members) are pinned by SHAPE regex, static string and
// JSON values by byte equality.
//
// Divergences are recorded per case in go_redis_interop_xfail.json
// (fail-closed: unbaselined failures are red, baselined cases that pass
// are red, baselined cases that never ran are red).
//
// The suite needs the live Redis; like the guardcore integration suite it
// skips loudly when REDIS_HOST is unset, and the CI conformance job always
// provides it.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const redisInteropXfailFile = "guard-core-spec-4.1.0/go_redis_interop_xfail.json"

type redisInteropSuite struct {
	Suite string             `json:"suite"`
	Kind  string             `json:"kind"`
	Doc   string             `json:"doc"`
	Cases []redisInteropCase `json:"cases"`
}

type redisInteropCase struct {
	ID        string `json:"id"`
	Prefix    string `json:"prefix"`
	Operation struct {
		Op   string         `json:"op"`
		Args map[string]any `json:"args"`
	} `json:"operation"`
	Expected []redisKeyRecord `json:"expected"`
}

type redisTTLRecord struct {
	Set     bool `json:"set"`
	Seconds int  `json:"seconds,omitempty"`
}

type redisKeyRecord struct {
	Key  string         `json:"key"`
	Type string         `json:"type"`
	TTL  redisTTLRecord `json:"ttl"`
	Card int            `json:"card,omitempty"`
	// Exactly one of the value pins rides per record.
	Value            *string           `json:"value,omitempty"`
	ValueShape       string            `json:"value_shape,omitempty"`
	MemberShape      string            `json:"member_shape,omitempty"`
	ScoreShape       string            `json:"score_shape,omitempty"`
	ScoreEqualsMembr bool              `json:"score_equals_member,omitempty"`
	Members          []redisMemberPin  `json:"members,omitempty"`
	Extra            map[string]any    `json:"-"`
	RawMembers       []redisZSetMember `json:"-"`
}

type redisMemberPin struct {
	Member string  `json:"member"`
	Score  float64 `json:"score"`
}

type redisZSetMember struct {
	Member string
	Score  float64
}

// latin1Decode maps raw Redis bytes onto the runner's comparison domain:
// the reference corpus stored the ipinfo database fixture bytes through a
// latin-1 mapping (byte value == code point), so each byte maps to the
// rune of the same value.
func latin1Decode(raw []byte) string {
	runes := make([]rune, 0, len(raw))
	for _, b := range raw {
		runes = append(runes, rune(b))
	}
	return string(runes)
}

func redisHost() string {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	return host
}

func redisURLForSuite() string {
	return "redis://" + redisHost() + ":6379/0"
}

func probePrefix(t *testing.T, client *redis.Client, prefix string) map[string]redisKeyRecord {
	t.Helper()
	keys, err := client.Keys(t.Context(), prefix+"*").Result()
	if err != nil {
		t.Fatalf("prefix scan: %v", err)
	}
	sort.Strings(keys)
	out := map[string]redisKeyRecord{}
	for _, key := range keys {
		record := redisKeyRecord{Key: key}
		record.Type, err = client.Type(t.Context(), key).Result()
		if err != nil {
			t.Fatalf("type %s: %v", key, err)
		}
		pttl, err := client.PTTL(t.Context(), key).Result()
		if err != nil {
			t.Fatalf("pttl %s: %v", key, err)
		}
		switch {
		case pttl > 0:
			record.TTL = redisTTLRecord{Set: true, Seconds: int(math.Ceil(pttl.Seconds()))}
		default:
			record.TTL = redisTTLRecord{Set: false}
		}
		switch record.Type {
		case "string":
			raw, err := client.Get(t.Context(), key).Bytes()
			if err != nil {
				t.Fatalf("get %s: %v", key, err)
			}
			value := latin1Decode(raw)
			record.Value = &value
		case "zset":
			members, err := client.ZRangeWithScores(t.Context(), key, 0, -1).Result()
			if err != nil {
				t.Fatalf("zrange %s: %v", key, err)
			}
			for _, m := range members {
				member, ok := m.Member.(string)
				if !ok {
					t.Fatalf("zset %s: non-string member %v", key, m.Member)
				}
				record.RawMembers = append(record.RawMembers, redisZSetMember{Member: member, Score: m.Score})
			}
			record.Card = len(members)
		}
		out[key] = record
	}
	return out
}

// recordDiffs compares one expected record against the probed key record.
func recordDiffs(want redisKeyRecord, got redisKeyRecord) []string {
	var diffs []string
	if want.Type == "json" {
		if got.Type != "string" {
			diffs = append(diffs, fmt.Sprintf("type: got %s want json (string with JSON bytes)", got.Type))
		}
	} else if got.Type != want.Type {
		diffs = append(diffs, fmt.Sprintf("type: got %s want %s", got.Type, want.Type))
	}
	if got.TTL.Set != want.TTL.Set {
		diffs = append(diffs, fmt.Sprintf("ttl set: got %v want %v", got.TTL.Set, want.TTL.Set))
	} else if want.TTL.Set {
		// The configured value, never the remaining seconds: the probe
		// completed within seconds of the write, so the remaining TTL
		// rounds up into [configured-slack, configured].
		const slack = 30
		if got.TTL.Seconds > want.TTL.Seconds || got.TTL.Seconds < want.TTL.Seconds-slack {
			diffs = append(diffs, fmt.Sprintf("ttl seconds: got %d want configured %d (within %ds)", got.TTL.Seconds, want.TTL.Seconds, slack))
		}
	}
	if want.Value != nil {
		if got.Value == nil {
			diffs = append(diffs, "value: key holds no string value")
		} else if *got.Value != *want.Value {
			diffs = append(diffs, fmt.Sprintf("value: got %q want %q", *got.Value, *want.Value))
		}
	}
	if want.ValueShape != "" {
		if got.Value == nil {
			diffs = append(diffs, "value_shape: key holds no string value")
		} else if !regexp.MustCompile(want.ValueShape).MatchString(*got.Value) {
			diffs = append(diffs, fmt.Sprintf("value_shape: got %q want shape %s", *got.Value, want.ValueShape))
		}
	}
	if want.MemberShape != "" {
		if len(got.RawMembers) != want.Card {
			diffs = append(diffs, fmt.Sprintf("card: got %d want %d", len(got.RawMembers), want.Card))
		}
		for _, m := range got.RawMembers {
			if !regexp.MustCompile(want.MemberShape).MatchString(m.Member) {
				diffs = append(diffs, fmt.Sprintf("member_shape: got %q want shape %s", m.Member, want.MemberShape))
				break
			}
			if want.ScoreShape != "" && !regexp.MustCompile(want.ScoreShape).MatchString(strconv.FormatFloat(m.Score, 'f', -1, 64)) {
				diffs = append(diffs, fmt.Sprintf("score_shape: got %v want shape %s", m.Score, want.ScoreShape))
				break
			}
			if want.ScoreEqualsMembr {
				parsed, err := strconv.ParseFloat(m.Member, 64)
				if err != nil || round6(parsed) != round6(m.Score) {
					diffs = append(diffs, fmt.Sprintf("score_equals_member: member %q score %v", m.Member, m.Score))
					break
				}
			}
		}
	}
	if len(want.Members) > 0 {
		if len(got.RawMembers) != len(want.Members) {
			diffs = append(diffs, fmt.Sprintf("card: got %d want %d", len(got.RawMembers), len(want.Members)))
		} else {
			for i, pin := range want.Members {
				if got.RawMembers[i].Member != pin.Member || round6(got.RawMembers[i].Score) != round6(pin.Score) {
					diffs = append(diffs, fmt.Sprintf("members[%d]: got %q@%v want %q@%v", i, got.RawMembers[i].Member, got.RawMembers[i].Score, pin.Member, pin.Score))
				}
			}
		}
	}
	return diffs
}

func flushPrefix(t *testing.T, client *redis.Client, prefix string) {
	t.Helper()
	keys, err := client.Keys(t.Context(), prefix+"*").Result()
	if err != nil {
		t.Fatalf("flush scan: %v", err)
	}
	if len(keys) > 0 {
		if err := client.Del(t.Context(), keys...).Err(); err != nil {
			t.Fatalf("flush del: %v", err)
		}
	}
}

func argsString(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func argsInt(args map[string]any, key string) (int, bool) {
	if v, ok := args[key].(float64); ok {
		return int(v), true
	}
	return 0, false
}

// runRedisInteropOp performs the case's operation through the real Go
// handlers against the live Redis.
func runRedisInteropOp(t *testing.T, c redisInteropCase) error {
	t.Helper()
	url := redisURLForSuite()
	prefix := c.Prefix
	args := c.Operation.Args
	rioConfig := func(mutate func(*guardcore.SecurityConfig)) *guardcore.SecurityConfig {
		cfg, err := guardcore.NewSecurityConfig(func(sc *guardcore.SecurityConfig) {
			sc.EnableRedis = true
			sc.RedisURL = url
			sc.RedisPrefix = prefix
			if mutate != nil {
				mutate(sc)
			}
		})
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		return cfg
	}
	newRedis := func() *guardcore.RedisManager {
		manager := guardcore.NewRedisManager(guardcore.RedisConfig{URL: url, Prefix: prefix, EnableRedis: true})
		if err := manager.Initialize(); err != nil {
			t.Fatalf("redis initialize: %v", err)
		}
		return manager
	}

	switch c.Operation.Op {
	case "rate_limit":
		// The reference drives the manager primitive single-tier: one call,
		// one bucket (the tiered pipeline check always appends the global
		// tier). CheckRateLimitByIP is the same primitive in the Go port;
		// the observable bytes match the Lua path (member = epoch float,
		// score equal, TTL = 2x window).
		limit, _ := argsInt(args, "rate_limit")
		window, _ := argsInt(args, "rate_limit_window")
		redisMgr := newRedis()
		defer func() { _ = redisMgr.Close() }()
		cfg := rioConfig(func(sc *guardcore.SecurityConfig) {
			sc.EnableRateLimiting = true
			sc.RateLimit = limit
			sc.RateLimitWindow = window
		})
		manager := guardcore.NewRateLimitManager(guardcore.RateLimitConfigFromSecurityConfig(cfg), redisMgr, nil)
		manager.InitializeRedis(redisMgr)
		endpointPath := argsString(args, "endpoint_path")
		if _, err := manager.CheckRateLimitByIP(argsString(args, "client_ip"), endpointPath); err != nil {
			return err
		}
		return nil
	case "ban_ip":
		redisMgr := newRedis()
		defer func() { _ = redisMgr.Close() }()
		ban := guardcore.NewIPBanManager(redisMgr, nil)
		duration, _ := argsInt(args, "duration")
		reason := argsString(args, "reason")
		if reason == "" {
			reason = "rio_ban"
		}
		_, err := ban.Ban(argsString(args, "ip"), duration, reason)
		return err
	case "behavior_usage", "behavior_return":
		redisMgr := newRedis()
		defer func() { _ = redisMgr.Close() }()
		tracker := guardcore.NewBehaviorTracker(rioConfig(nil), redisMgr, nil, discardLogger())
		ruleRaw, _ := args["rule"].(map[string]any)
		rule := guardcore.BehaviorRuleConfig{RuleType: argsString(ruleRaw, "rule_type")}
		if v, ok := argsInt(ruleRaw, "threshold"); ok {
			rule.Threshold = v
		}
		if v, ok := argsInt(ruleRaw, "window"); ok {
			rule.Window = v
		}
		if c.Operation.Op == "behavior_usage" {
			tracker.TrackEndpointUsage(argsString(args, "endpoint_id"), argsString(args, "client_ip"), rule, nowFloat())
			return nil
		}
		rule.Pattern = argsString(ruleRaw, "pattern")
		status, _ := argsInt(args, "response_status")
		resp := guardcore.NewResponseFactory().CreateResponse("not found", status)
		tracker.TrackReturnPattern(argsString(args, "endpoint_id"), argsString(args, "client_ip"), resp, rule, nowFloat(), 0)
		return nil
	case "security_headers":
		redisMgr := newRedis()
		defer func() { _ = redisMgr.Close() }()
		// A clean header state: only the case's block is non-empty, so
		// CacheConfiguration writes only that block's key (the reference
		// manager's other blocks are None).
		state := guardcore.DefaultSecurityHeaders()
		state.CSP = nil
		state.HSTS = nil
		state.Custom = nil
		if csp, ok := args["csp_config"].(map[string]any); ok {
			directives := make([]guardcore.CSPDirective, 0, len(csp))
			names := make([]string, 0, len(csp))
			for name := range csp {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				directives = append(directives, guardcore.CSPDirective{Name: name, Sources: strList(csp[name])})
			}
			state.CSP = directives
		}
		if hsts, ok := args["hsts_config"].(map[string]any); ok {
			hstsConfig := &guardcore.HSTSConfig{IncludeSubdomains: true}
			if v, ok := argsInt(hsts, "max_age"); ok {
				hstsConfig.MaxAge = v
			}
			if v, ok := hsts["include_subdomains"].(bool); ok {
				hstsConfig.IncludeSubdomains = v
			}
			state.HSTS = hstsConfig
		}
		if custom, ok := args["custom_headers"].(map[string]any); ok {
			headers := map[string]string{}
			for name, value := range custom {
				headers[name] = fmt.Sprint(value)
			}
			state.Custom = headers
		}
		manager := guardcore.NewSecurityHeadersManager(state)
		manager.InitializeRedis(redisMgr)
		return nil
	case "add_pattern":
		// The Go detection corpus is a compile-time table (KNOWN_GAPS): no
		// sus-patterns registry or its patterns:custom Redis write exists.
		return fmt.Errorf("no custom pattern registry in the Go engine")
	case "ipinfo_database":
		// The reference drives IPInfoManager.initialize with a pinned
		// download; the Go lifecycle equivalent downloads from a local
		// server serving the fixture bytes and caches them in Redis with
		// the max-age TTL.
		redisMgr := newRedis()
		defer func() { _ = redisMgr.Close() }()
		maxAge, _ := argsInt(args, "max_age")
		if maxAge == 0 {
			maxAge = guardcore.DefaultIPInfoMaxAge
		}
		dbPath := t.TempDir() + "/corpus.mmdb"
		manager := guardcore.NewIPInfoManager("corpus-token", dbPath, maxAge, nil)
		manager.Redis = redisMgr
		manager.SetDownloadEndpoint(serveFixtureBytes(t), nil)
		manager.Initialize()
		return nil
	case "cloud_ranges":
		redisMgr := newRedis()
		defer func() { _ = redisMgr.Close() }()
		provider := argsString(args, "provider")
		ranges := strList(args["ranges"])
		regionsRaw, _ := args["regions"].(map[string]any)
		regions := map[string]string{}
		for cidr, region := range regionsRaw {
			regions[cidr] = fmt.Sprint(region)
		}
		ttl, _ := argsInt(args, "ttl")
		manager := guardcore.NewCloudManager()
		manager.SetRedisHandler(redisMgr)
		manager.SetRangeFetcher(func(string) ([]string, map[string]string, error) {
			return ranges, regions, nil
		})
		return manager.RefreshAsync([]string{provider}, ttl)
	case "cloud_ip_store":
		redisMgr := newRedis()
		defer func() { _ = redisMgr.Close() }()
		store := guardcore.NewRedisCloudIPStore(redisMgr)
		ttl := 0
		if v, ok := args["ttl"].(float64); ok {
			ttl = int(v)
		}
		return store.Set(argsString(args, "provider"), strList(args["ranges"]), ttl)
	case "dynamic_rules":
		redisMgr := newRedis()
		defer func() { _ = redisMgr.Close() }()
		cfg := rioConfig(func(sc *guardcore.SecurityConfig) {
			sc.EnableDynamicRules = true
		})
		rulesRaw, _ := args["rules"].(map[string]any)
		raw, err := json.Marshal(rulesRaw)
		if err != nil {
			return err
		}
		rules := &guardcore.DynamicRules{}
		if err := json.Unmarshal(raw, rules); err != nil {
			return err
		}
		manager := guardcore.NewDynamicRuleManager(cfg, redisMgr, nil, nil)
		return manager.UpdateRules(func() (*guardcore.DynamicRules, error) {
			return rules, nil
		})
	default:
		return fmt.Errorf("unknown redis interop op %q", c.Operation.Op)
	}
}

func nowFloat() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// fixtureMMDBBytes is the corpus fixture download payload
// (redis_interop_cases.py FAKE_MMDB_BYTES).
var fixtureMMDBBytes = []byte("corpus-mmdb-fixture:\xe9\xff\x00\x80:end")

// serveFixtureBytes starts a local server answering the fixture bytes, the
// runner's stand-in for the pinned ipinfo download.
func serveFixtureBytes(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixtureMMDBBytes)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func loadRedisInteropXfail(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(redisInteropXfailFile)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}
		}
		t.Fatal(err)
	}
	var baseline struct {
		SpecVersion string            `json:"spec_version"`
		Cases       map[string]string `json:"cases"`
	}
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.SpecVersion != corpusSpecVersion {
		t.Fatalf("xfail baseline spec pin %s does not match %s", baseline.SpecVersion, corpusSpecVersion)
	}
	return baseline.Cases
}

func TestRedisInteropConformance(t *testing.T) {
	if os.Getenv("REDIS_HOST") == "" {
		t.Skip("REDIS_HOST not set: the redis_interop corpus drives the live Redis; the CI conformance job and the local gate always provide it")
	}
	path := filepath.Join(corpusCasesDir, "redis_interop.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var suite redisInteropSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	if suite.Kind != "redis_interop" {
		t.Fatalf("suite kind drifted: %q", suite.Kind)
	}
	if len(suite.Cases) == 0 {
		t.Fatal("redis_interop corpus matched zero cases: a vacuous pass is a failure")
	}

	client := redis.NewClient(&redis.Options{Addr: redisHost() + ":6379"})
	defer func() { _ = client.Close() }()
	if err := client.Ping(t.Context()).Err(); err != nil {
		t.Fatalf("REDIS_HOST is set but Redis is unreachable: %v", err)
	}

	xfail := loadRedisInteropXfail(t)
	baselinedSeen := map[string]bool{}
	total, passed, xfailed, stale := 0, 0, 0, 0
	var failures, xfailNotes []string
	for _, c := range suite.Cases {
		total++
		key := suite.Suite + "/" + c.ID
		prefix := c.Prefix
		flushPrefix(t, client, prefix)
		runErr := runRedisInteropOp(t, c)
		var diffs []string
		if runErr != nil {
			diffs = []string{"driver: " + runErr.Error()}
		} else {
			got := probePrefix(t, client, prefix)
			seen := map[string]bool{}
			for _, want := range c.Expected {
				gotRecord, ok := got[want.Key]
				if !ok {
					diffs = append(diffs, fmt.Sprintf("key %s: not written", want.Key))
					continue
				}
				seen[want.Key] = true
				diffs = append(diffs, recordDiffs(want, gotRecord)...)
			}
			var extras []string
			for key := range got {
				if !seen[key] {
					extras = append(extras, key)
				}
			}
			if len(extras) > 0 {
				sort.Strings(extras)
				diffs = append(diffs, fmt.Sprintf("unexpected extra keys under the prefix: %s", strings.Join(extras, ", ")))
			}
		}
		if len(diffs) == 0 {
			passed++
			if reason, ok := xfail[key]; ok {
				stale++
				baselinedSeen[key] = true
				failures = append(failures, fmt.Sprintf("stale xfail baseline entry %s [%s]: case now produces byte-identical keys; remove the entry", key, reason))
			}
			continue
		}
		reason, ok := xfail[key]
		if !ok {
			failures = append(failures, fmt.Sprintf("%s:\n  %s\n  record the divergence in %s", key, strings.Join(prefixAll(diffs, "  "), "\n  "), redisInteropXfailFile))
			continue
		}
		baselinedSeen[key] = true
		xfailed++
		xfailNotes = append(xfailNotes, fmt.Sprintf("xfail %s [%s]: %s", key, reason, strings.Join(diffs, "; ")))
	}
	for id := range xfail {
		if !baselinedSeen[id] {
			failures = append(failures, fmt.Sprintf("xfail baseline entry %s never ran; corpus changed?", id))
		}
	}
	sort.Strings(xfailNotes)
	for _, x := range xfailNotes {
		t.Logf("%s", x)
	}
	if len(failures) > 0 {
		t.Fatalf("redis_interop conformance drift: %d failures over %d cases\n%s", len(failures), total, strings.Join(failures, "\n"))
	}
	t.Logf("redis_interop conformance gate: %d passed, %d xfail, %d stale, %d cases (spec %s)", passed, xfailed, stale, total, corpusSpecVersion)
}
