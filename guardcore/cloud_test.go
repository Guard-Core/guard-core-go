package guardcore

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRedisHandler struct {
	mu   sync.Mutex
	data map[string]string
	ttls map[string]*int
}

func newFakeRedisHandler() *fakeRedisHandler {
	return &fakeRedisHandler{data: map[string]string{}, ttls: map[string]*int{}}
}

func (f *fakeRedisHandler) key(namespace, key string) string { return namespace + ":" + key }

func (f *fakeRedisHandler) Prefix() string    { return "guard_core:" }
func (f *fakeRedisHandler) Enabled() bool     { return true }
func (f *fakeRedisHandler) Initialize() error { return nil }
func (f *fakeRedisHandler) Close() error      { return nil }

func (f *fakeRedisHandler) GetKey(namespace, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data[f.key(namespace, key)], nil
}

func (f *fakeRedisHandler) SetKey(namespace, key, value string, ttlSeconds *int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[f.key(namespace, key)] = value
	f.ttls[f.key(namespace, key)] = ttlSeconds
	return nil
}

func (f *fakeRedisHandler) Delete(namespace, key string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.key(namespace, key)
	if _, ok := f.data[k]; !ok {
		return 0, nil
	}
	delete(f.data, k)
	return 1, nil
}

func (f *fakeRedisHandler) Keys(pattern string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := strings.TrimSuffix(pattern, "*")
	var out []string
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeRedisHandler) DeletePattern(pattern string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := strings.TrimSuffix(pattern, "*")
	var removed int64
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			delete(f.data, k)
			removed++
		}
	}
	return removed, nil
}

func cloudTestRangeSet(t *testing.T, regions map[string]string, cidrs ...string) cloudRangeSet {
	t.Helper()
	set := newCloudRangeSet()
	for _, cidr := range cidrs {
		masked, key, err := parseCloudNetwork(cidr)
		if err != nil {
			t.Fatalf("bad test cidr %q: %v", cidr, err)
		}
		set.networks[key] = masked
		if region := regions[cidr]; region != "" {
			set.regions[key] = region
		}
	}
	return set
}

func cloudTestConfig(t *testing.T, mutate func(*SecurityConfig)) *SecurityConfig {
	t.Helper()
	cfg, err := NewSecurityConfig(mutate)
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	return cfg
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(message)
}

func TestCloudProviderRegistryIsExact(t *testing.T) {
	if len(AllCloudProviders) != 6 {
		t.Fatalf("expected exactly six providers, got %v", AllCloudProviders)
	}
	for _, name := range []string{"AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"} {
		if !ValidCloudProviders[name] {
			t.Fatalf("%s must be a valid provider", name)
		}
	}
	for _, name := range []string{"aws", "Google", "OVH", ""} {
		if ValidCloudProviders[name] {
			t.Fatalf("%q must not be a valid provider", name)
		}
	}
}

func TestParseCloudSelectors(t *testing.T) {
	blocked, carveouts := parseCloudSelectors([]string{"AWS"})
	if !blocked["AWS"] || len(carveouts) != 0 {
		t.Fatalf("bare selector must block without carve-out: %v %v", blocked, carveouts)
	}

	blocked, carveouts = parseCloudSelectors([]string{"GCP:!us-central1"})
	if !blocked["GCP"] {
		t.Fatalf("carve-out selector must still block the provider: %v", blocked)
	}
	if !carveouts["GCP"]["us-central1"] || len(carveouts["GCP"]) != 1 {
		t.Fatalf("carve-out region not registered: %v", carveouts)
	}

	blocked, carveouts = parseCloudSelectors([]string{"AWS:!"})
	if !blocked["AWS"] || len(carveouts) != 0 {
		t.Fatalf("bare '!' must be a plain block: %v %v", blocked, carveouts)
	}

	blocked, carveouts = parseCloudSelectors([]string{":!region"})
	if len(blocked) != 0 || len(carveouts) != 0 {
		t.Fatalf("empty provider part must be skipped: %v %v", blocked, carveouts)
	}

	blocked, carveouts = parseCloudSelectors([]string{"AWS", "GCP:!us-central1", "GCP:!europe-west1"})
	if !blocked["AWS"] || !blocked["GCP"] || len(blocked) != 2 {
		t.Fatalf("unexpected blocked set: %v", blocked)
	}
	if !carveouts["GCP"]["us-central1"] || !carveouts["GCP"]["europe-west1"] || len(carveouts["GCP"]) != 2 {
		t.Fatalf("carve-outs for one provider must union: %v", carveouts)
	}

	blocked, carveouts = parseCloudSelectors([]string{"GCP:!"})
	if len(carveouts) != 0 {
		t.Fatalf("empty region must not register a carve-out: %v", carveouts)
	}
}

func TestBareProviderNamesDeduplicates(t *testing.T) {
	names := bareProviderNames([]string{"GCP:!us-central1", "AWS", "GCP", "AWS:!europe-west1"})
	if strings.Join(names, ",") != "AWS,GCP" {
		t.Fatalf("unexpected bare provider names: %v", names)
	}
}

func TestCloudConfigValidation(t *testing.T) {
	cfg := cloudTestConfig(t, func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS", "GCP:!us-central1", "Azure:!"}
	})
	if len(cfg.BlockCloudProviders) != 3 {
		t.Fatalf("valid selectors must be accepted: %v", cfg.BlockCloudProviders)
	}
	for _, invalid := range []string{"OVH", "aws", ":!us-central1", "AW"} {
		if _, err := NewSecurityConfig(func(c *SecurityConfig) {
			c.BlockCloudProviders = []string{invalid}
		}); err == nil {
			t.Fatalf("selector %q must be rejected", invalid)
		}
	}
	_, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS", "NotACloud"}
	})
	if err == nil || !strings.Contains(err.Error(), "NotACloud") {
		t.Fatalf("error must name the unknown provider: %v", err)
	}
}

func TestCloudIPRefreshIntervalDefaultAndClamp(t *testing.T) {
	def := testConfig(t)
	if def.CloudIPRefreshInterval != DefaultCloudIPRefreshInterval {
		t.Fatalf("default interval must be %d, got %d", DefaultCloudIPRefreshInterval, def.CloudIPRefreshInterval)
	}
	if def.CloudIPRefreshInterval != 3600 {
		t.Fatalf("spec default must be 3600, got %d", def.CloudIPRefreshInterval)
	}
	cases := []struct {
		in   int
		want int
	}{
		{0, 3600},
		{1, 60},
		{59, 60},
		{60, 60},
		{7200, 7200},
		{86400, 86400},
		{86401, 86400},
		{1000000, 86400},
	}
	for _, tc := range cases {
		cfg, err := NewSecurityConfig(func(c *SecurityConfig) { c.CloudIPRefreshInterval = tc.in })
		if err != nil {
			t.Fatalf("interval %d: %v", tc.in, err)
		}
		if cfg.CloudIPRefreshInterval != tc.want {
			t.Fatalf("interval %d must clamp to %d, got %d", tc.in, tc.want, cfg.CloudIPRefreshInterval)
		}
	}
}

func TestCloudProvidersToCheckPrecedence(t *testing.T) {
	if got := cloudProvidersToCheck(nil, []string{"AWS"}); strings.Join(got, ",") != "AWS" {
		t.Fatalf("global providers must apply without a route config: %v", got)
	}
	route := &RouteConfig{BlockCloudProviders: []string{"GCP"}}
	if got := cloudProvidersToCheck(route, []string{"AWS"}); strings.Join(got, ",") != "GCP" {
		t.Fatalf("route providers must shadow global providers: %v", got)
	}
	if got := cloudProvidersToCheck(&RouteConfig{}, []string{"AWS"}); strings.Join(got, ",") != "AWS" {
		t.Fatalf("route without providers must fall back to global: %v", got)
	}
	if got := cloudProvidersToCheck(nil, nil); got != nil {
		t.Fatalf("no providers must yield nil, got %v", got)
	}
	if got := cloudProvidersToCheck(&RouteConfig{BlockCloudProviders: []string{"GCP"}}, nil); strings.Join(got, ",") != "GCP" {
		t.Fatalf("route providers must apply without global providers: %v", got)
	}
}

func TestIsCloudIPMatchesRanges(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8", "192.0.2.0/24"), false)

	if !m.IsCloudIP("10.1.2.3", []string{"AWS"}) {
		t.Fatalf("ip inside AWS range must match")
	}
	if !m.IsCloudIP("192.0.2.55", []string{"AWS"}) {
		t.Fatalf("ip inside second AWS range must match")
	}
	if m.IsCloudIP("203.0.113.1", []string{"AWS"}) {
		t.Fatalf("ip outside AWS ranges must not match")
	}
	if m.IsCloudIP("10.1.2.3", []string{"GCP"}) {
		t.Fatalf("provider absent from the registry must be skipped")
	}
	if m.IsCloudIP("not-an-ip", []string{"AWS"}) {
		t.Fatalf("unparseable ip must not match")
	}
	if m.IsCloudIP("10.1.2.3", nil) {
		t.Fatalf("empty selector list must not match")
	}
}

func TestIsCloudIPUnparseableLogsAndFailsOpen(t *testing.T) {
	m := NewCloudManager()
	var buf bytes.Buffer
	m.SetLogger(log.New(&buf, "", 0))
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8"), false)
	if m.IsCloudIP("definitely-not-an-ip", []string{"AWS"}) {
		t.Fatalf("unparseable ip must not be blocked")
	}
	if !strings.Contains(buf.String(), "Invalid IP address: definitely-not-an-ip") {
		t.Fatalf("unparseable ip must log the invalid address: %q", buf.String())
	}
}

func TestIsCloudIPCarveOutsArePerNetwork(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("AWS", cloudTestRangeSet(t, map[string]string{
		"10.1.0.0/16": "us-central1",
		"10.2.0.0/16": "us-east-1",
	}, "10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"), false)

	selectors := []string{"AWS:!us-central1"}
	if m.IsCloudIP("10.1.0.5", selectors) {
		t.Fatalf("network whose region is carved out must be allowed")
	}
	if !m.IsCloudIP("10.2.0.5", selectors) {
		t.Fatalf("network with a different region must stay blocked")
	}
	if !m.IsCloudIP("10.3.0.5", selectors) {
		t.Fatalf("network with no registered region must never be carved out")
	}
	if !m.IsCloudIP("10.1.0.5", []string{"AWS"}) {
		t.Fatalf("without a carve-out the whole provider is blocked")
	}
}

func TestIsCloudIPEmptyRangesWarnCooldown(t *testing.T) {
	m := NewCloudManager()
	var buf bytes.Buffer
	m.SetLogger(log.New(&buf, "", 0))
	base := time.Unix(1_700_000_000, 0)
	m.nowFunc = func() time.Time { return base }
	m.installRanges("AWS", newCloudRangeSet(), false)

	countWarnings := func() int { return strings.Count(buf.String(), "not populated yet") }

	if m.IsCloudIP("10.0.0.1", []string{"AWS"}) {
		t.Fatalf("empty range set must fail open")
	}
	if countWarnings() != 1 {
		t.Fatalf("first empty-range hit must warn once, got %d", countWarnings())
	}
	m.nowFunc = func() time.Time { return base.Add(100 * time.Second) }
	m.IsCloudIP("10.0.0.1", []string{"AWS"})
	if countWarnings() != 1 {
		t.Fatalf("warning inside the 300s cooldown must be suppressed, got %d", countWarnings())
	}
	m.nowFunc = func() time.Time { return base.Add(301 * time.Second) }
	m.IsCloudIP("10.0.0.1", []string{"AWS"})
	if countWarnings() != 2 {
		t.Fatalf("warning after the 300s cooldown must fire again, got %d", countWarnings())
	}
}

func TestCloudStoreMissVersusEmptyHit(t *testing.T) {
	store := NewInMemoryCloudIPStore()
	entries, found, err := store.Get("AWS")
	if err != nil || found || entries != nil {
		t.Fatalf("miss must report (nil, false): %v %v %v", entries, found, err)
	}
	if err := store.Set("AWS", []string{}, 300); err != nil {
		t.Fatalf("set empty: %v", err)
	}
	entries, found, err = store.Get("AWS")
	if err != nil || !found || len(entries) != 0 {
		t.Fatalf("empty hit must report (empty, true): %v %v %v", entries, found, err)
	}
	if err := store.Set("GCP", []string{"10.0.0.0/8|us-central1"}, 300); err != nil {
		t.Fatalf("set: %v", err)
	}
	entries, found, err = store.Get("GCP")
	if err != nil || !found || len(entries) != 1 || entries[0] != "10.0.0.0/8|us-central1" {
		t.Fatalf("unexpected cached entries: %v %v %v", entries, found, err)
	}
}

func TestCloudStoreExpiryReportsMiss(t *testing.T) {
	store := NewInMemoryCloudIPStore()
	base := time.Unix(1_700_000_000, 0)
	store.nowFunc = func() time.Time { return base }
	if err := store.Set("AWS", []string{"10.0.0.0/8"}, 60); err != nil {
		t.Fatalf("set: %v", err)
	}
	store.nowFunc = func() time.Time { return base.Add(61 * time.Second) }
	entries, found, err := store.Get("AWS")
	if err != nil || found || entries != nil {
		t.Fatalf("expired entry must report a miss: %v %v %v", entries, found, err)
	}
}

func TestRedisCloudIPStoreRoundTrip(t *testing.T) {
	redis := newFakeRedisHandler()
	store := NewRedisCloudIPStore(redis)
	entries, found, err := store.Get("AWS")
	if err != nil || found {
		t.Fatalf("missing key must report a miss: %v %v", found, err)
	}
	if err := store.Set("AWS", []string{"10.0.0.0/8|us-east-1", "192.0.2.0/24"}, 300); err != nil {
		t.Fatalf("set: %v", err)
	}
	raw, err := redis.GetKey("cloud_ip_v2", "AWS")
	if err != nil || raw != `["10.0.0.0/8|us-east-1", "192.0.2.0/24"]` {
		t.Fatalf("unexpected cloud_ip_v2 payload: %q %v", raw, err)
	}
	entries, found, err = store.Get("AWS")
	if err != nil || !found || len(entries) != 2 {
		t.Fatalf("cached entries must round-trip: %v %v %v", entries, found, err)
	}
	if err := store.Set("GCP", []string{}, 300); err != nil {
		t.Fatalf("set empty: %v", err)
	}
	entries, found, err = store.Get("GCP")
	if err != nil || !found || len(entries) != 0 {
		t.Fatalf("cached empty set must be a hit with zero entries: %v %v %v", entries, found, err)
	}
}

func TestDecodeCachedEntriesRejectsCorruptPayload(t *testing.T) {
	if _, err := decodeCachedEntries([]string{"not-a-network"}); err == nil {
		t.Fatalf("corrupt cache entry must error")
	}
	set, err := decodeCachedEntries([]string{"10.0.0.0/8"})
	if err != nil || len(set.networks) != 1 || set.regions["10.0.0.0/8"] != "" {
		t.Fatalf("entry without region must decode: %v %v", set, err)
	}
	set, err = decodeCachedEntries([]string{"10.0.0.0/8|us-east-1"})
	if err != nil || set.regions["10.0.0.0/8"] != "us-east-1" {
		t.Fatalf("entry with region must decode: %v %v", set, err)
	}
}

func TestGetCloudProviderDetailsRendersMaskedNetwork(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8", "2001:db8::/32"), false)

	provider, network, ok := m.GetCloudProviderDetails("10.1.2.3", []string{"AWS"})
	if !ok || provider != "AWS" || network != "10.0.0.0/8" {
		t.Fatalf("unexpected details: %q %q %v", provider, network, ok)
	}
	provider, network, ok = m.GetCloudProviderDetails("2001:db8::1", []string{"AWS"})
	if !ok || provider != "AWS" || network != "2001:db8::/32" {
		t.Fatalf("ipv6 details must use the canonical masked rendering: %q %q %v", provider, network, ok)
	}
	if _, _, ok := m.GetCloudProviderDetails("203.0.113.9", []string{"AWS"}); ok {
		t.Fatalf("non-matching ip must report not found")
	}
	if _, _, ok := m.GetCloudProviderDetails("10.1.2.3", nil); ok {
		t.Fatalf("empty selector list must report not found")
	}
}

func TestRefreshAsyncCacheMissFetchesAndCaches(t *testing.T) {
	redis := newFakeRedisHandler()
	m := NewCloudManager()
	m.SetStore(NewRedisCloudIPStore(redis))
	m.testFetcher = func(provider string) (cloudRangeSet, error) {
		return cloudTestRangeSet(t, nil, "203.0.114.0/24"), nil
	}
	if err := m.RefreshAsync([]string{"AWS"}, 300); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !m.hasRanges("AWS") || !m.IsCloudIP("203.0.114.5", []string{"AWS"}) {
		t.Fatalf("fetched ranges must be installed in memory")
	}
	raw, _ := redis.GetKey("cloud_ip_v2", "AWS")
	if raw != `["203.0.114.0/24"]` {
		t.Fatalf("fetched ranges must be cached: %q", raw)
	}
	if ttl := redis.ttls["cloud_ip_v2:AWS"]; ttl == nil || *ttl != 300 {
		t.Fatalf("cache entry must carry the refresh ttl: %v", ttl)
	}
	if m.lastUpdated["AWS"].IsZero() {
		t.Fatalf("successful fetch must stamp last_updated")
	}
}

func TestRefreshAsyncCacheHitSkipsFetch(t *testing.T) {
	redis := newFakeRedisHandler()
	store := NewRedisCloudIPStore(redis)
	if err := store.Set("AWS", []string{"198.51.100.0/24"}, 300); err != nil {
		t.Fatalf("seed: %v", err)
	}
	m := NewCloudManager()
	m.SetStore(store)
	m.testFetcher = func(string) (cloudRangeSet, error) {
		panic("cache hit must not fetch")
	}
	if err := m.RefreshAsync([]string{"AWS"}, 300); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !m.IsCloudIP("198.51.100.7", []string{"AWS"}) {
		t.Fatalf("cached ranges must be installed in memory")
	}
}

func TestRefreshAsyncEmptySetIsNotCached(t *testing.T) {
	redis := newFakeRedisHandler()
	m := NewCloudManager()
	m.SetStore(NewRedisCloudIPStore(redis))
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "198.51.100.0/24"), true)
	previousStamp := m.lastUpdated["AWS"]
	m.testFetcher = func(string) (cloudRangeSet, error) {
		return newCloudRangeSet(), nil
	}
	if err := m.RefreshAsync([]string{"AWS"}, 300); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if raw, _ := redis.GetKey("cloud_ip_v2", "AWS"); raw != "" {
		t.Fatalf("empty fetch must not be cached: %q", raw)
	}
	if !m.lastUpdated["AWS"].Equal(previousStamp) {
		t.Fatalf("empty fetch must not move last_updated")
	}
	if !m.IsCloudIP("198.51.100.7", []string{"AWS"}) {
		t.Fatalf("previously cached ranges must stay installed after an empty fetch")
	}
}

func TestRefreshAsyncFailureEnsuresEmptyEntry(t *testing.T) {
	m := NewCloudManager()
	var buf bytes.Buffer
	m.SetLogger(log.New(&buf, "", 0))
	m.testFetcher = func(string) (cloudRangeSet, error) {
		return cloudRangeSet{}, errors.New("network down")
	}
	if err := m.RefreshAsync([]string{"AWS"}, 300); err != nil {
		t.Fatalf("refresh must swallow fetch failures: %v", err)
	}
	if !m.hasRanges("AWS") {
		t.Fatalf("failed first fetch must leave an empty entry")
	}
	if m.IsCloudIP("10.0.0.1", []string{"AWS"}) {
		t.Fatalf("empty entry must fail open")
	}
	if !strings.Contains(buf.String(), "Failed to refresh AWS IP ranges: network down") {
		t.Fatalf("fetch failure must be logged: %q", buf.String())
	}
}

func TestRefreshAsyncStoreErrorFailsOpen(t *testing.T) {
	m := NewCloudManager()
	m.SetStore(&erroringCloudStore{})
	var buf bytes.Buffer
	m.SetLogger(log.New(&buf, "", 0))
	if err := m.RefreshAsync([]string{"AWS"}, 300); err != nil {
		t.Fatalf("refresh must swallow store failures: %v", err)
	}
	if !m.hasRanges("AWS") {
		t.Fatalf("store failure must leave an empty entry")
	}
	if !strings.Contains(buf.String(), "Failed to refresh AWS IP ranges") {
		t.Fatalf("store failure must be logged: %q", buf.String())
	}
}

type erroringCloudStore struct{}

func (s *erroringCloudStore) Get(provider string) ([]string, bool, error) {
	return nil, false, errors.New("store read failed")
}

func (s *erroringCloudStore) Set(provider string, entries []string, ttlSeconds int) error {
	return errors.New("store write failed")
}

func TestScheduleRefreshIsSingleFlight(t *testing.T) {
	m := NewCloudManager()
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	if !m.ScheduleRefresh([]string{"AWS"}, 60, func() error {
		mu.Lock()
		calls++
		mu.Unlock()
		close(started)
		<-release
		return nil
	}) {
		t.Fatalf("first schedule must report true")
	}
	<-started
	if m.ScheduleRefresh([]string{"AWS"}, 60, func() error { return nil }) {
		t.Fatalf("schedule while a refresh is in flight must report false")
	}
	if m.ScheduleRefresh([]string{"AWS"}, 60, nil) {
		t.Fatalf("default-refresh schedule while in flight must also be a no-op")
	}
	close(release)
	waitForCondition(t, time.Second, func() bool { return !m.Refreshing() }, "refresh must clear the in-flight flag")
	if !m.ScheduleRefresh([]string{"AWS"}, 60, func() error { return nil }) {
		t.Fatalf("schedule after completion must report true")
	}
	waitForCondition(t, time.Second, func() bool { return !m.Refreshing() }, "second refresh must complete")
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("only the first schedule may run the refresh, got %d calls", calls)
	}
}

func TestCloudIPRefreshCheckSkipsWithoutProviders(t *testing.T) {
	m := NewCloudManager()
	cfg := testConfig(t)
	check := &cloudIPRefreshCheck{cfg: cfg, manager: m}
	req := newTestRequest(t, nil)
	if resp := check.Check(req); resp != nil {
		t.Fatalf("refresh check must never block, got %+v", resp)
	}
	if m.LastRefreshStamp() != 0 || m.Refreshing() {
		t.Fatalf("no providers must be a no-op")
	}
}

func TestCloudIPRefreshCheckRespectsInterval(t *testing.T) {
	m := NewCloudManager()
	base := time.Unix(1_700_000_000, 0)
	m.nowFunc = func() time.Time { return base }
	cfg := cloudTestConfig(t, func(c *SecurityConfig) { c.BlockCloudProviders = []string{"AWS"} })
	check := &cloudIPRefreshCheck{cfg: cfg, manager: m}
	m.SetLastRefreshStamp(base.Unix() - 60)
	if resp := check.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("refresh check must never block, got %+v", resp)
	}
	if m.Refreshing() {
		t.Fatalf("a fresh stamp must not schedule a refresh")
	}
	if m.LastRefreshStamp() != base.Unix()-60 {
		t.Fatalf("a fresh stamp must not be rewritten")
	}
}

func TestCloudIPRefreshCheckAdvancesStampAndSchedules(t *testing.T) {
	m := NewCloudManager()
	base := time.Unix(1_700_000_000, 0)
	m.nowFunc = func() time.Time { return base }
	m.testFetcher = func(string) (cloudRangeSet, error) {
		return cloudTestRangeSet(t, nil, "203.0.114.0/24"), nil
	}
	cfg := cloudTestConfig(t, func(c *SecurityConfig) { c.BlockCloudProviders = []string{"AWS"} })
	check := &cloudIPRefreshCheck{cfg: cfg, manager: m}
	m.SetLastRefreshStamp(base.Unix() - 3601)
	if resp := check.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("refresh check must never block, got %+v", resp)
	}
	if got := m.LastRefreshStamp(); got != base.Unix() {
		t.Fatalf("stamp must advance to int(now)=%d, got %d", base.Unix(), got)
	}
	waitForCondition(t, time.Second, func() bool { return m.hasRanges("AWS") }, "scheduled refresh must run in the background")
	if !m.IsCloudIP("203.0.114.5", []string{"AWS"}) {
		t.Fatalf("background refresh must install fetched ranges")
	}
}

func TestCloudIPRefreshCheckRollsBackStampWhenSchedulingFails(t *testing.T) {
	m := NewCloudManager()
	base := time.Unix(1_700_000_000, 0)
	m.nowFunc = func() time.Time { return base }
	m.mu.Lock()
	m.refreshInFlight = true
	m.mu.Unlock()
	cfg := cloudTestConfig(t, func(c *SecurityConfig) { c.BlockCloudProviders = []string{"AWS"} })
	check := &cloudIPRefreshCheck{cfg: cfg, manager: m}
	previous := base.Unix() - 7200
	m.SetLastRefreshStamp(previous)
	if resp := check.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("refresh check must never block, got %+v", resp)
	}
	if got := m.LastRefreshStamp(); got != previous {
		t.Fatalf("failed scheduling must roll the stamp back to %d, got %d", previous, got)
	}
	m.mu.Lock()
	m.refreshInFlight = false
	m.mu.Unlock()
}

func TestCloudIPRefreshCheckUsesRouteProviders(t *testing.T) {
	m := NewCloudManager()
	base := time.Unix(1_700_000_000, 0)
	m.nowFunc = func() time.Time { return base }
	var mu sync.Mutex
	fetched := map[string]bool{}
	m.testFetcher = func(provider string) (cloudRangeSet, error) {
		mu.Lock()
		fetched[provider] = true
		mu.Unlock()
		return cloudTestRangeSet(t, nil, "203.0.114.0/24"), nil
	}
	cfg := testConfig(t)
	check := &cloudIPRefreshCheck{cfg: cfg, manager: m}
	m.SetLastRefreshStamp(base.Unix() - 3601)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		state.RouteConfig = &RouteConfig{BlockCloudProviders: []string{"GCP"}}
	})
	check.Check(req)
	waitForCondition(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return fetched["GCP"]
	}, "route-level providers must drive the refresh")
	mu.Lock()
	defer mu.Unlock()
	if fetched["AWS"] {
		t.Fatalf("global providers must not be refreshed when the route overrides them")
	}
}

func TestCloudProviderCheckSkips(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8"), false)
	cfg := cloudTestConfig(t, func(c *SecurityConfig) { c.BlockCloudProviders = []string{"AWS"} })
	check := &cloudProviderCheck{cfg: cfg, manager: m}

	whitelisted := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.1.2.3"
		state.IsWhitelisted = true
	})
	if resp := check.Check(whitelisted); resp != nil {
		t.Fatalf("whitelisted request must skip: %+v", resp)
	}

	noIP := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = ""
	})
	if resp := check.Check(noIP); resp != nil {
		t.Fatalf("request without client ip must skip: %+v", resp)
	}

	bypassed := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.1.2.3"
		state.RouteConfig = &RouteConfig{BypassedChecks: []string{"clouds"}}
	})
	if resp := check.Check(bypassed); resp != nil {
		t.Fatalf("route bypassing 'clouds' must skip: %+v", resp)
	}

	noMatch := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.113.9"
	})
	if resp := check.Check(noMatch); resp != nil {
		t.Fatalf("non-cloud ip must pass: %+v", resp)
	}

	emptyProviders := &cloudProviderCheck{cfg: testConfig(t), manager: m}
	blockedIP := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.1.2.3"
	})
	if resp := emptyProviders.Check(blockedIP); resp != nil {
		t.Fatalf("empty provider list must skip: %+v", resp)
	}
}

func TestCloudProviderCheckBlocksWith403(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8"), false)
	cfg := cloudTestConfig(t, func(c *SecurityConfig) { c.BlockCloudProviders = []string{"AWS"} })
	check := &cloudProviderCheck{cfg: cfg, manager: m}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.1.2.3"
	})
	resp := check.Check(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != CloudBlockedMsg {
		t.Fatalf("cloud ip must be blocked with 403 %q, got %+v", CloudBlockedMsg, resp)
	}
	if resp.Headers == nil {
		t.Fatalf("error response must carry a headers map")
	}
	stash := req.State().BlockStash
	if stash == nil || stash.Reason != "Blocked cloud provider IP: 10.1.2.3" {
		t.Fatalf("block reason must be stashed for the pipeline hook: %+v", stash)
	}
}

func TestCloudProviderCheckUsesCustomErrorResponse(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8"), false)
	cfg := cloudTestConfig(t, func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS"}
		c.CustomErrorResponses = map[int]string{403: "no cloud access"}
	})
	check := &cloudProviderCheck{cfg: cfg, manager: m}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.1.2.3"
	})
	resp := check.Check(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != "no cloud access" {
		t.Fatalf("configured 403 message must win, got %+v", resp)
	}
}

func TestCloudProviderCheckPassiveModeLogsOnly(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8"), false)
	var mu sync.Mutex
	var payload map[string]any
	cfg := cloudTestConfig(t, func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS"}
		c.PassiveMode = true
		c.OnBlock = func(req Request, p map[string]any) {
			mu.Lock()
			payload = p
			mu.Unlock()
		}
	})
	check := &cloudProviderCheck{cfg: cfg, manager: m}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.1.2.3"
	})
	if resp := check.Check(req); resp != nil {
		t.Fatalf("passive mode must not block, got %+v", resp)
	}
	mu.Lock()
	defer mu.Unlock()
	if payload == nil {
		t.Fatalf("passive mode must fire the on_block hook inline")
	}
	if payload["check_name"] != "cloud_provider" || payload["passive_mode"] != true {
		t.Fatalf("unexpected passive payload: %+v", payload)
	}
	if payload["reason"] != "Blocked cloud provider IP: 10.1.2.3" {
		t.Fatalf("passive payload must carry the cloud reason: %+v", payload)
	}
	if req.State().BlockStash != nil {
		t.Fatalf("passive mode must not stash a block")
	}
}

func TestCloudProviderCheckNonPassiveDefersHookToPipeline(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8"), false)
	hookCalls := 0
	cfg := cloudTestConfig(t, func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS"}
		c.OnBlock = func(req Request, p map[string]any) { hookCalls++ }
	})
	check := &cloudProviderCheck{cfg: cfg, manager: m}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.1.2.3"
	})
	if resp := check.Check(req); resp == nil {
		t.Fatalf("non-passive cloud ip must be blocked")
	}
	if hookCalls != 0 {
		t.Fatalf("non-passive check must stash, not fire the hook (pipeline fires it): %d", hookCalls)
	}
}

func TestCloudProviderCheckRouteLevelSelectors(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("GCP", cloudTestRangeSet(t, map[string]string{
		"10.1.0.0/16": "us-central1",
		"10.2.0.0/16": "us-east1",
	}, "10.1.0.0/16", "10.2.0.0/16"), false)
	cfg := testConfig(t)
	check := &cloudProviderCheck{cfg: cfg, manager: m}

	carvedOut := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.1.0.5"
		state.RouteConfig = &RouteConfig{BlockCloudProviders: []string{"GCP:!us-central1"}}
	})
	if resp := check.Check(carvedOut); resp != nil {
		t.Fatalf("route carve-out region must pass: %+v", resp)
	}

	routeBlocked := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.2.0.5"
		state.RouteConfig = &RouteConfig{BlockCloudProviders: []string{"GCP:!us-central1"}}
	})
	resp := check.Check(routeBlocked)
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("route-level provider list must block non-carved-out ranges: %+v", resp)
	}
}

func TestCloudManagerInitializeRedisInstallsStoreAndRefreshes(t *testing.T) {
	redis := newFakeRedisHandler()
	store := NewRedisCloudIPStore(redis)
	if err := store.Set("AWS", []string{"198.51.100.0/24"}, 300); err != nil {
		t.Fatalf("seed: %v", err)
	}
	m := NewCloudManager()
	m.testFetcher = func(string) (cloudRangeSet, error) {
		panic("initialization must read the redis cache, not fetch")
	}
	if err := m.InitializeRedis(redis, []string{"AWS"}, 300); err != nil {
		t.Fatalf("InitializeRedis: %v", err)
	}
	if !m.IsCloudIP("198.51.100.7", []string{"AWS"}) {
		t.Fatalf("startup refresh must install the cached ranges")
	}
	if err := m.InitializeRedis(nil, []string{"AWS"}, 300); err == nil {
		t.Fatalf("nil redis handler must be rejected")
	}
}

func TestBuildDefaultPipelineCloudSlots(t *testing.T) {
	cfg := cloudTestConfig(t, func(c *SecurityConfig) { c.BlockCloudProviders = []string{"AWS"} })
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	p, _ := BuildDefaultPipeline(cfg, ban, rl, nil)
	want := []string{"route_config", "cloud_ip_refresh", "ip_security", "cloud_provider", "rate_limit", "suspicious_activity"}
	if got := p.CheckNames(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("cloud checks must land at the spec-03 slots, want %v got %v", want, got)
	}
}

func TestBuildDefaultPipelineCloudSlotsFromRouteOnly(t *testing.T) {
	cfg := testConfig(t)
	registry := NewRouteRegistry()
	registry.Register("/api", func(rc *RouteConfig) { rc.BlockCloudProviders = []string{"AWS"} })
	ban := NewIPBanManager(nil, nil)
	rl := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), nil, ban)
	p, _ := BuildDefaultPipeline(cfg, ban, rl, registry)
	names := strings.Join(p.CheckNames(), ",")
	if !strings.Contains(names, "cloud_ip_refresh") || !strings.Contains(names, "cloud_provider") {
		t.Fatalf("a route-level provider list must enable both cloud checks: %v", names)
	}
}

func TestPipelineCloudChecksSkipOnExcludedPaths(t *testing.T) {
	m := NewCloudManager()
	m.installRanges("AWS", cloudTestRangeSet(t, nil, "10.0.0.0/8"), false)
	cfg := cloudTestConfig(t, func(c *SecurityConfig) { c.BlockCloudProviders = []string{"AWS"} })
	p := NewSecurityCheckPipeline([]SecurityCheck{
		&cloudIPRefreshCheck{cfg: cfg, manager: m},
		&cloudProviderCheck{cfg: cfg, manager: m},
	}, cfg, nil)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "10.1.2.3"
		state.ExclusionScoped = true
	})
	if resp := p.Execute(req); resp != nil {
		t.Fatalf("cloud checks must not run on exclusion-scoped paths: %+v", resp)
	}
}
