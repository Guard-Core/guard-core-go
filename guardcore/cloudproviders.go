package guardcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var AllCloudProviders = []string{"AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"}

var ValidCloudProviders = func() map[string]bool {
	m := make(map[string]bool, len(AllCloudProviders))
	for _, p := range AllCloudProviders {
		m[p] = true
	}
	return m
}()

const DefaultCloudIPRefreshInterval = 3600

const MinCloudIPRefreshInterval = 60

const MaxCloudIPRefreshInterval = 86400

const emptyRangesWarningCooldown = 300 * time.Second

type cloudRangeSet struct {
	networks map[string]netip.Prefix
	regions  map[string]string
}

func newCloudRangeSet() cloudRangeSet {
	return cloudRangeSet{networks: map[string]netip.Prefix{}, regions: map[string]string{}}
}

func ttlIntPtr(n int) *int { return &n }

func parseCloudNetwork(prefix string) (netip.Prefix, string, error) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return netip.Prefix{}, "", err
	}
	masked := p.Masked()
	return masked, masked.String(), nil
}

func parseCloudSelectors(selectors []string) (map[string]bool, map[string]map[string]bool) {
	blocked := map[string]bool{}
	carveouts := map[string]map[string]bool{}
	for _, selector := range selectors {
		provider, region, hasMarker := strings.Cut(selector, ":!")
		if provider == "" {
			continue
		}
		blocked[provider] = true
		if hasMarker && region != "" {
			if carveouts[provider] == nil {
				carveouts[provider] = map[string]bool{}
			}
			carveouts[provider][region] = true
		}
	}
	return blocked, carveouts
}

func bareProviderNames(selectors []string) []string {
	seen := map[string]bool{}
	names := []string{}
	for _, selector := range selectors {
		provider, _, _ := strings.Cut(selector, ":!")
		if provider == "" || seen[provider] {
			continue
		}
		seen[provider] = true
		names = append(names, provider)
	}
	sort.Strings(names)
	return names
}

func encodeCachedEntry(network, region string) string {
	if region != "" {
		return network + "|" + region
	}
	return network
}

func encodeCachedRanges(set cloudRangeSet) []string {
	entries := make([]string, 0, len(set.networks))
	for key := range set.networks {
		entries = append(entries, encodeCachedEntry(key, set.regions[key]))
	}
	sort.Strings(entries)
	return entries
}

func decodeCachedEntries(entries []string) (cloudRangeSet, error) {
	set := newCloudRangeSet()
	for _, entry := range entries {
		prefix, region, _ := strings.Cut(entry, "|")
		masked, key, err := parseCloudNetwork(prefix)
		if err != nil {
			return cloudRangeSet{}, fmt.Errorf("corrupt cloud cache entry %q: %w", entry, err)
		}
		set.networks[key] = masked
		if region != "" {
			set.regions[key] = region
		}
	}
	return set, nil
}

func decodeCachedRangesPayload(payload string) (cloudRangeSet, error) {
	entries := strings.Split(payload, ",")
	return decodeCachedEntries(entries)
}

func encodeCloudIPv2Payload(entries []string) string {
	sorted := append([]string(nil), entries...)
	sort.Strings(sorted)
	quoted := make([]string, 0, len(sorted))
	for _, entry := range sorted {
		// json.Marshal of a string value cannot fail.
		b, _ := json.Marshal(entry)
		quoted = append(quoted, string(b))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

type decodedCloudIPv2Payload struct {
	entries []string
	found   bool
}

func decodeCloudIPv2Payload(raw string) decodedCloudIPv2Payload {
	if raw == "" {
		return decodedCloudIPv2Payload{}
	}
	var items []any
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return decodedCloudIPv2Payload{}
	}
	entries := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return decodedCloudIPv2Payload{}
		}
		entries = append(entries, s)
	}
	return decodedCloudIPv2Payload{entries: entries, found: true}
}

type CloudIPStore interface {
	Get(provider string) ([]string, bool, error)
	Set(provider string, entries []string, ttlSeconds int) error
}

type InMemoryCloudIPStore struct {
	mu        sync.Mutex
	data      map[string][]string
	expiresAt map[string]time.Time
	nowFunc   func() time.Time
}

func NewInMemoryCloudIPStore() *InMemoryCloudIPStore {
	return &InMemoryCloudIPStore{data: map[string][]string{}, expiresAt: map[string]time.Time{}, nowFunc: time.Now}
}

func (s *InMemoryCloudIPStore) Get(provider string) ([]string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFunc()
	if expiresAt, ok := s.expiresAt[provider]; ok && !now.Before(expiresAt) {
		delete(s.data, provider)
		delete(s.expiresAt, provider)
		return nil, false, nil
	}
	entries, ok := s.data[provider]
	if !ok {
		return nil, false, nil
	}
	return append([]string(nil), entries...), true, nil
}

func (s *InMemoryCloudIPStore) Set(provider string, entries []string, ttlSeconds int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[provider] = append([]string(nil), entries...)
	if ttlSeconds > 0 {
		s.expiresAt[provider] = s.nowFunc().Add(time.Duration(ttlSeconds) * time.Second)
	} else {
		delete(s.expiresAt, provider)
	}
	return nil
}

type RedisCloudIPStore struct {
	redis  RedisHandler
	prefix string
}

func NewRedisCloudIPStore(redis RedisHandler) *RedisCloudIPStore {
	return &RedisCloudIPStore{redis: redis, prefix: "cloud_ip_v2"}
}

func (s *RedisCloudIPStore) Get(provider string) ([]string, bool, error) {
	raw, err := s.redis.GetKey(s.prefix, provider)
	if err != nil {
		return nil, false, err
	}
	decoded := decodeCloudIPv2Payload(raw)
	if !decoded.found {
		return nil, false, nil
	}
	return decoded.entries, true, nil
}

func (s *RedisCloudIPStore) Set(provider string, entries []string, ttlSeconds int) error {
	// encodeCloudIPv2Payload cannot fail for string entries.
	return s.redis.SetKey(s.prefix, provider, encodeCloudIPv2Payload(entries), ttlIntPtr(ttlSeconds))
}

type RedisCloudRangesStore struct {
	redis RedisHandler
}

func NewRedisCloudRangesStore(redis RedisHandler) *RedisCloudRangesStore {
	return &RedisCloudRangesStore{redis: redis}
}

func (s *RedisCloudRangesStore) Get(provider string) ([]string, bool, error) {
	raw, err := s.redis.GetKey("cloud_ranges_v2", provider)
	if err != nil {
		return nil, false, err
	}
	if raw == "" {
		return nil, false, nil
	}
	return strings.Split(raw, ","), true, nil
}

func (s *RedisCloudRangesStore) Set(provider string, entries []string, ttlSeconds int) error {
	sorted := append([]string(nil), entries...)
	sort.Strings(sorted)
	return s.redis.SetKey("cloud_ranges_v2", provider, strings.Join(sorted, ","), ttlIntPtr(ttlSeconds))
}

const (
	awsIPRangesURL      = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	gcpIPRangesURL      = "https://www.gstatic.com/ipranges/cloud.json"
	azurePageURL        = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
	digitalOceanCSVURL  = "https://www.digitalocean.com/geo/google.csv"
	linodeCSVURL        = "https://geoip.linode.com/"
	vultrJSONURL        = "https://geofeed.constant.com/?json"
	cloudFetchTimeout   = 10 * time.Second
	azureUserAgentValue = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
)

const (
	azureDownloadMaxAttempts    = 3
	azureDownloadRetryDelay     = 2 * time.Second
	azureDownloadMaxElapsed     = 20 * time.Second
	azureDownloadAttemptTimeout = 10 * time.Second
	azurePageFetchTimeout       = 10 * time.Second
	azureTrustedDownloadHost    = "download.microsoft.com"
	azureStaleWarningDays       = 90
	azureCloudServiceTagName    = "AzureCloud"
	azureServiceTagsDateLayout  = "20060102"
	azureTrustedDownloadHTTPS   = "https"
)

var azureServiceTagsURLPattern = regexp.MustCompile(`https://download\.microsoft\.com/[^"'\s<>]+ServiceTags[^"'\s<>]*\.json(?:\?[^"'\s<>]*)?`)

var azureServiceTagsDatePattern = regexp.MustCompile(`ServiceTags_Public_(\d{8})`)

var azureFailoverLinkPattern = regexp.MustCompile(`<a\b[^>]*\bid=["']failoverLink["'][^>]*>`)

var azureHrefPattern = regexp.MustCompile(`href=["']([^"']+)["']`)

var azureGenericJSONHrefPattern = regexp.MustCompile(`href=["'](https://download\.microsoft\.com/[^"']+\.json(?:\?[^"']*)?)["']`)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newCloudHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func cloudHTTPGet(client *http.Client, url string, headers map[string]string, timeout time.Duration, refuseRedirects bool) ([]byte, int, error) {
	if client == nil {
		client = newCloudHTTPClient(timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if refuseRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, resp.StatusCode, fmt.Errorf("azure IP ranges download redirected (status %d); refusing to follow redirects", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("HTTP request to %s failed with status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func fetchAWSIPRanges(client *http.Client) (cloudRangeSet, error) {
	body, _, err := cloudHTTPGet(client, awsIPRangesURL, nil, cloudFetchTimeout, false)
	if err != nil {
		return cloudRangeSet{}, err
	}
	var data struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
			Region   string `json:"region"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return cloudRangeSet{}, err
	}
	set := newCloudRangeSet()
	for _, entry := range data.Prefixes {
		if entry.Service != "AMAZON" {
			continue
		}
		masked, key, err := parseCloudNetwork(entry.IPPrefix)
		if err != nil {
			return cloudRangeSet{}, err
		}
		set.networks[key] = masked
		if entry.Region != "" {
			set.regions[key] = entry.Region
		}
	}
	return set, nil
}

func fetchGCPIPRanges(client *http.Client) (cloudRangeSet, error) {
	body, _, err := cloudHTTPGet(client, gcpIPRangesURL, nil, cloudFetchTimeout, false)
	if err != nil {
		return cloudRangeSet{}, err
	}
	var data struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
			Scope      string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return cloudRangeSet{}, err
	}
	set := newCloudRangeSet()
	for _, entry := range data.Prefixes {
		prefix := entry.IPv4Prefix
		if prefix == "" {
			prefix = entry.IPv6Prefix
		}
		if prefix == "" {
			continue
		}
		masked, key, err := parseCloudNetwork(prefix)
		if err != nil {
			return cloudRangeSet{}, err
		}
		set.networks[key] = masked
		if entry.Scope != "" {
			set.regions[key] = entry.Scope
		}
	}
	return set, nil
}

func fetchCSVPrefixNetworks(client *http.Client, url string) (cloudRangeSet, error) {
	body, _, err := cloudHTTPGet(client, url, nil, cloudFetchTimeout, false)
	if err != nil {
		return cloudRangeSet{}, err
	}
	set := newCloudRangeSet()
	for _, rawLine := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix := strings.TrimSpace(strings.SplitN(line, ",", 2)[0])
		if prefix == "" {
			continue
		}
		masked, key, err := parseCloudNetwork(prefix)
		if err != nil {
			continue
		}
		set.networks[key] = masked
	}
	return set, nil
}

func fetchDigitalOceanIPRanges(client *http.Client) (cloudRangeSet, error) {
	return fetchCSVPrefixNetworks(client, digitalOceanCSVURL)
}

func fetchLinodeIPRanges(client *http.Client) (cloudRangeSet, error) {
	return fetchCSVPrefixNetworks(client, linodeCSVURL)
}

func fetchVultrIPRanges(client *http.Client) (cloudRangeSet, error) {
	body, _, err := cloudHTTPGet(client, vultrJSONURL, nil, cloudFetchTimeout, false)
	if err != nil {
		return cloudRangeSet{}, err
	}
	var data struct {
		Subnets []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"subnets"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return cloudRangeSet{}, err
	}
	set := newCloudRangeSet()
	for _, entry := range data.Subnets {
		if entry.IPPrefix == "" {
			continue
		}
		masked, key, err := parseCloudNetwork(entry.IPPrefix)
		if err != nil {
			continue
		}
		set.networks[key] = masked
	}
	return set, nil
}

func isTrustedAzureDownloadURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return parsed.Scheme == azureTrustedDownloadHTTPS && parsed.Hostname() == azureTrustedDownloadHost
}

func parseServiceTagsDate(rawURL string, now time.Time) (time.Time, bool) {
	match := azureServiceTagsDatePattern.FindStringSubmatch(rawURL)
	if match == nil {
		return time.Time{}, false
	}
	parsed, err := time.ParseInLocation(azureServiceTagsDateLayout, match[1], time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	if parsed.After(today) {
		return time.Time{}, false
	}
	return parsed, true
}

func serviceTagsSortKey(rawURL string, now time.Time) (bool, time.Time, string) {
	parsed, ok := parseServiceTagsDate(rawURL, now)
	if !ok {
		return false, time.Time{}, rawURL
	}
	return true, parsed, rawURL
}

func compareServiceTagsKeys(a, b string, now time.Time) bool {
	aHasDate, aDate, aURL := serviceTagsSortKey(a, now)
	bHasDate, bDate, bURL := serviceTagsSortKey(b, now)
	if aHasDate != bHasDate {
		return bHasDate
	}
	if aHasDate && !aDate.Equal(bDate) {
		return aDate.Before(bDate)
	}
	return aURL < bURL
}

func warnIfServiceTagsURLIsStale(rawURL string, now time.Time, logger *log.Logger) {
	parsed, ok := parseServiceTagsDate(rawURL, now)
	if !ok {
		logger.Printf("Selected Azure ServiceTags URL has no parseable date, cannot confirm it is current: %s", rawURL)
		return
	}
	ageDays := int(now.UTC().Sub(parsed).Hours() / 24)
	if ageDays > azureStaleWarningDays {
		logger.Printf("Selected Azure ServiceTags URL is %d days old, possibly stale: %s", ageDays, rawURL)
	}
}

func extractFailoverLinkURL(decodedHTML string) string {
	anchor := azureFailoverLinkPattern.FindString(decodedHTML)
	if anchor == "" {
		return ""
	}
	href := azureHrefPattern.FindStringSubmatch(anchor)
	if href == nil {
		return ""
	}
	if !isTrustedAzureDownloadURL(href[1]) {
		return ""
	}
	return href[1]
}

func extractNewestServiceTagsURL(decodedHTML string, now time.Time, logger *log.Logger) string {
	var candidates []string
	for _, url := range azureServiceTagsURLPattern.FindAllString(decodedHTML, -1) {
		if isTrustedAzureDownloadURL(url) {
			candidates = append(candidates, url)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	winner := candidates[0]
	for _, candidate := range candidates[1:] {
		if compareServiceTagsKeys(winner, candidate, now) {
			winner = candidate
		}
	}
	warnIfServiceTagsURLIsStale(winner, now, logger)
	return winner
}

func extractGenericJSONURL(decodedHTML string) string {
	match := azureGenericJSONHrefPattern.FindStringSubmatch(decodedHTML)
	if match == nil {
		return ""
	}
	// The href pattern only matches https://download.microsoft.com URLs,
	// so the match is trusted by construction.
	return match[1]
}

func extractAzureDownloadURL(decodedHTML string, now time.Time, logger *log.Logger) string {
	if url := extractFailoverLinkURL(decodedHTML); url != "" {
		return url
	}
	if url := extractNewestServiceTagsURL(decodedHTML, now, logger); url != "" {
		return url
	}
	return extractGenericJSONURL(decodedHTML)
}

func downloadAzureServiceTags(client *http.Client, downloadURL string, deadline time.Time, nowFunc func() time.Time) ([]byte, error) {
	for attempt := 1; ; attempt++ {
		remaining := deadline.Sub(nowFunc())
		if remaining <= 0 {
			return nil, errors.New("azure IP ranges download exceeded max elapsed time")
		}
		attemptTimeout := azureDownloadAttemptTimeout
		if remaining < attemptTimeout {
			attemptTimeout = remaining
		}
		body, status, err := cloudHTTPGet(client, downloadURL, nil, attemptTimeout, true)
		if err == nil {
			return body, nil
		}
		if status >= 300 && status < 400 {
			return nil, err
		}
		remaining = deadline.Sub(nowFunc())
		if attempt >= azureDownloadMaxAttempts || remaining <= 0 {
			return nil, err
		}
		delay := azureDownloadRetryDelay
		if remaining < delay {
			delay = remaining
		}
		time.Sleep(delay)
	}
}

func selectAzureCloudPrefixes(body []byte) ([]string, error) {
	var data struct {
		Values []struct {
			Name       string `json:"name"`
			Properties struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	for _, entry := range data.Values {
		if entry.Name == azureCloudServiceTagName {
			return entry.Properties.AddressPrefixes, nil
		}
	}
	return nil, fmt.Errorf("azure ServiceTags document has no %q tag", azureCloudServiceTagName)
}

func fetchAzureIPRanges(client *http.Client, nowFunc func() time.Time, logger *log.Logger) (cloudRangeSet, error) {
	now := nowFunc()
	deadline := now.Add(azureDownloadMaxElapsed)
	pageTimeout := azurePageFetchTimeout
	if remaining := deadline.Sub(nowFunc()); remaining < pageTimeout {
		pageTimeout = remaining
	}
	if pageTimeout <= 0 {
		return cloudRangeSet{}, errors.New("azure IP ranges download exceeded max elapsed time")
	}
	pageBody, _, err := cloudHTTPGet(client, azurePageURL, map[string]string{"User-Agent": azureUserAgentValue}, pageTimeout, false)
	if err != nil {
		return cloudRangeSet{}, err
	}
	decodedHTML := html.UnescapeString(string(pageBody))
	downloadURL := extractAzureDownloadURL(decodedHTML, nowFunc(), logger)
	if downloadURL == "" {
		return cloudRangeSet{}, errors.New("could not find Azure IP ranges download URL")
	}
	body, err := downloadAzureServiceTags(client, downloadURL, deadline, nowFunc)
	if err != nil {
		return cloudRangeSet{}, err
	}
	prefixes, err := selectAzureCloudPrefixes(body)
	if err != nil {
		return cloudRangeSet{}, err
	}
	set := newCloudRangeSet()
	for _, prefix := range prefixes {
		masked, key, err := parseCloudNetwork(prefix)
		if err != nil {
			return cloudRangeSet{}, err
		}
		set.networks[key] = masked
	}
	return set, nil
}

type cloudFetcher func(client *http.Client, nowFunc func() time.Time, logger *log.Logger) (cloudRangeSet, error)

var cloudFetchers = map[string]cloudFetcher{
	"AWS": func(c *http.Client, _ func() time.Time, _ *log.Logger) (cloudRangeSet, error) {
		return fetchAWSIPRanges(c)
	},
	"GCP": func(c *http.Client, _ func() time.Time, _ *log.Logger) (cloudRangeSet, error) {
		return fetchGCPIPRanges(c)
	},
	"Azure": fetchAzureIPRanges,
	"DigitalOcean": func(c *http.Client, _ func() time.Time, _ *log.Logger) (cloudRangeSet, error) {
		return fetchDigitalOceanIPRanges(c)
	},
	"Linode": func(c *http.Client, _ func() time.Time, _ *log.Logger) (cloudRangeSet, error) {
		return fetchLinodeIPRanges(c)
	},
	"Vultr": func(c *http.Client, _ func() time.Time, _ *log.Logger) (cloudRangeSet, error) {
		return fetchVultrIPRanges(c)
	},
}

type CloudProviderStatus struct {
	Ready         bool
	LastRefreshed time.Time
	Entries       int
}

type CloudManager struct {
	mu                  sync.RWMutex
	logger              *log.Logger
	HTTPClient          *http.Client
	nowFunc             func() time.Time
	store               CloudIPStore
	redisHandler        RedisHandler
	ipRanges            map[string]cloudRangeSet
	lastUpdated         map[string]time.Time
	refreshInFlight     bool
	lastRefreshStamp    int64
	emptyRangesWarnedAt map[string]time.Time
	testFetcher         func(provider string) (cloudRangeSet, error)
}

func NewCloudManager() *CloudManager {
	m := &CloudManager{
		logger:              log.Default(),
		HTTPClient:          newCloudHTTPClient(cloudFetchTimeout),
		nowFunc:             time.Now,
		ipRanges:            map[string]cloudRangeSet{},
		lastUpdated:         map[string]time.Time{},
		emptyRangesWarnedAt: map[string]time.Time{},
	}
	return m
}

func (m *CloudManager) SetLogger(logger *log.Logger) { m.logger = logger }

func (m *CloudManager) SetStore(store CloudIPStore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store = store
}

func (m *CloudManager) SetRedisHandler(redis RedisHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.redisHandler = redis
}

func (m *CloudManager) effectiveStore() CloudIPStore {
	if m.store != nil {
		return m.store
	}
	if m.redisHandler != nil {
		return NewRedisCloudRangesStore(m.redisHandler)
	}
	return nil
}

func (m *CloudManager) LastRefreshStamp() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastRefreshStamp
}

func (m *CloudManager) SetLastRefreshStamp(stamp int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastRefreshStamp = stamp
}

func (m *CloudManager) fetchProviderRanges(provider string) (cloudRangeSet, error) {
	if m.testFetcher != nil {
		return m.testFetcher(provider)
	}
	fetcher, ok := cloudFetchers[provider]
	if !ok {
		return cloudRangeSet{}, fmt.Errorf("no fetcher for cloud provider %q", provider)
	}
	return fetcher(m.HTTPClient, m.nowFunc, m.logger)
}

func (m *CloudManager) installRanges(provider string, set cloudRangeSet, updateStamp bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipRanges[provider] = set
	if updateStamp {
		m.lastUpdated[provider] = m.nowFunc()
	}
}

func (m *CloudManager) hasRanges(provider string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.ipRanges[provider]
	return ok
}

func (m *CloudManager) RefreshAsync(providers []string, ttl int) error {
	store := m.effectiveStore()
	for _, provider := range bareProviderNames(providers) {
		if store != nil {
			entries, found, err := store.Get(provider)
			if err != nil {
				m.logRefreshFailure(provider, err)
				m.ensureProviderEntry(provider)
				continue
			}
			if found {
				set, err := decodeCachedEntries(entries)
				if err != nil {
					m.logRefreshFailure(provider, err)
					m.ensureProviderEntry(provider)
					continue
				}
				m.installRanges(provider, set, false)
				continue
			}
		}
		set, err := m.fetchProviderRanges(provider)
		if err != nil {
			m.logRefreshFailure(provider, err)
			m.ensureProviderEntry(provider)
			continue
		}
		if len(set.networks) > 0 {
			if store != nil {
				if err := store.Set(provider, encodeCachedRanges(set), ttl); err != nil {
					m.logRefreshFailure(provider, err)
				}
			}
			m.installRanges(provider, set, true)
		}
	}
	return nil
}

func (m *CloudManager) logRefreshFailure(provider string, err error) {
	m.logger.Printf("Failed to refresh %s IP ranges: %s", provider, err.Error())
}

func (m *CloudManager) ensureProviderEntry(provider string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ipRanges[provider]; !ok {
		m.ipRanges[provider] = newCloudRangeSet()
	}
}

func (m *CloudManager) ScheduleRefresh(providers []string, ttl int, refresh func() error) bool {
	m.mu.Lock()
	if m.refreshInFlight {
		m.mu.Unlock()
		return false
	}
	m.refreshInFlight = true
	m.mu.Unlock()
	go func() {
		defer func() {
			m.mu.Lock()
			m.refreshInFlight = false
			m.mu.Unlock()
		}()
		run := refresh
		if run == nil {
			run = func() error { return m.RefreshAsync(providers, ttl) }
		}
		if err := run(); err != nil {
			m.logger.Printf("Background cloud IP refresh failed: %s", err.Error())
		}
	}()
	return true
}

func (m *CloudManager) Refreshing() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.refreshInFlight
}

func (m *CloudManager) warnEmptyRanges(provider string) {
	m.mu.Lock()
	now := m.nowFunc()
	if warnedAt, ok := m.emptyRangesWarnedAt[provider]; ok && now.Sub(warnedAt) < emptyRangesWarningCooldown {
		m.mu.Unlock()
		return
	}
	m.emptyRangesWarnedAt[provider] = now
	m.mu.Unlock()
	m.logger.Printf("Cloud IP ranges for %s are not populated yet; is_cloud_ip is returning not-blocked for every %s IP until the initial fetch completes.", provider, provider)
}

func (m *CloudManager) IsCloudIP(ip string, selectors []string) bool {
	addr, err := netip.ParseAddr(stripIPBrackets(ip))
	if err != nil {
		m.logger.Printf("Invalid IP address: %s", ip)
		return false
	}
	blocked, carveouts := parseCloudSelectors(selectors)
	m.mu.RLock()
	matched := false
	var emptyProviders []string
	for provider := range blocked {
		set, ok := m.ipRanges[provider]
		if !ok {
			continue
		}
		if len(set.networks) == 0 {
			emptyProviders = append(emptyProviders, provider)
			continue
		}
		allowedRegions := carveouts[provider]
		for key, network := range set.networks {
			if !network.Contains(addr.Unmap()) && !network.Contains(addr) {
				continue
			}
			if len(allowedRegions) > 0 && allowedRegions[set.regions[key]] {
				continue
			}
			matched = true
			break
		}
		if matched {
			break
		}
	}
	m.mu.RUnlock()
	for _, provider := range emptyProviders {
		m.warnEmptyRanges(provider)
	}
	return matched
}

func (m *CloudManager) GetCloudProviderDetails(ip string, selectors []string) (string, string, bool) {
	addr, err := netip.ParseAddr(stripIPBrackets(ip))
	if err != nil {
		m.logger.Printf("Invalid IP address: %s", ip)
		return "", "", false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, provider := range bareProviderNames(selectors) {
		set, ok := m.ipRanges[provider]
		if !ok {
			continue
		}
		for key, network := range set.networks {
			if network.Contains(addr.Unmap()) || network.Contains(addr) {
				return provider, key, true
			}
		}
	}
	return "", "", false
}

func (m *CloudManager) Status() map[string]CloudProviderStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := make(map[string]CloudProviderStatus, len(AllCloudProviders))
	for _, provider := range AllCloudProviders {
		set := m.ipRanges[provider]
		status[provider] = CloudProviderStatus{
			Ready:         len(set.networks) > 0,
			LastRefreshed: m.lastUpdated[provider],
			Entries:       len(set.networks),
		}
	}
	return status
}

var DefaultCloudManager = NewCloudManager()
