package guardcore

// Coverage tests for the cloud provider surface: cache codecs, stores,
// the offline fetchers (driven through injected transports), the Azure
// ServiceTags scrape helpers, and the CloudManager lifecycle.

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// cloudServe maps request URLs to fixture responses.
type cloudServe struct {
	responses map[string]cloudResponse
	failFirst int
	failErr   error
	seen      []string
}

type cloudResponse struct {
	status  int
	body    string
	headers map[string]string
}

func (s *cloudServe) roundTrip() roundTripperFunc {
	return func(req *http.Request) (*http.Response, error) {
		s.seen = append(s.seen, req.URL.String())
		for name, values := range req.Header {
			if name == "User-Agent" && len(values) > 0 && values[0] == azureUserAgentValue {
				s.seen = append(s.seen, "azure-ua")
			}
		}
		if s.failFirst > 0 {
			s.failFirst--
			return nil, s.failErr
		}
		resp, ok := s.responses[req.URL.String()]
		if !ok {
			return nil, fmt.Errorf("unexpected cloud request %s", req.URL.String())
		}
		status := resp.status
		if status == 0 {
			status = http.StatusOK
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(resp.body)),
			Header:     http.Header{},
		}, nil
	}
}

func cloudClient(s *cloudServe) *http.Client {
	return &http.Client{Transport: s.roundTrip()}
}

func TestCloudCacheCodecs(t *testing.T) {
	if got := encodeCachedEntry("10.0.0.0/8", "us-east"); got != "10.0.0.0/8|us-east" {
		t.Fatalf("region encoding mismatch: %q", got)
	}
	if got := encodeCachedEntry("10.0.0.0/8", ""); got != "10.0.0.0/8" {
		t.Fatalf("regionless encoding mismatch: %q", got)
	}
	payload := encodeCloudIPv2Payload([]string{"b", "a"})
	if payload != `["a", "b"]` {
		t.Fatalf("payload must be sorted json, got %q", payload)
	}
	if empty := encodeCloudIPv2Payload(nil); empty != "[]" {
		t.Fatalf("empty payloads must encode to an empty list, got %q", empty)
	}
	set, err := decodeCachedRangesPayload("10.0.0.0/8|us,192.168.1.0/24")
	if err != nil {
		t.Fatalf("decodeCachedRangesPayload: %v", err)
	}
	if len(set.networks) != 2 || set.regions["10.0.0.0/8"] != "us" {
		t.Fatalf("decoded set mismatch: %+v", set)
	}
	if _, err := decodeCachedRangesPayload("not-a-prefix"); err == nil || !strings.Contains(err.Error(), "corrupt cloud cache entry") {
		t.Fatalf("corrupt entries must surface, got %v", err)
	}
}

func TestDecodeCloudIPv2PayloadShapes(t *testing.T) {
	if got := decodeCloudIPv2Payload(""); got.found {
		t.Fatal("empty payloads must not be found")
	}
	if got := decodeCloudIPv2Payload("{not json"); got.found {
		t.Fatal("malformed payloads must not be found")
	}
	if got := decodeCloudIPv2Payload(`[1,2]`); got.found {
		t.Fatal("non-string items must not be found")
	}
	got := decodeCloudIPv2Payload(`["10.0.0.0/8","192.168.0.0/16"]`)
	if !got.found || len(got.entries) != 2 || got.entries[0] != "10.0.0.0/8" {
		t.Fatalf("valid payloads must decode, got %+v", got)
	}
}

func TestInMemoryCloudIPStoreTTLAndOverrides(t *testing.T) {
	store := NewInMemoryCloudIPStore()
	now := time.Unix(1_000_000, 0)
	store.nowFunc = func() time.Time { return now }
	if _, found, _ := store.Get("AWS"); found {
		t.Fatal("an empty store must miss")
	}
	if err := store.Set("AWS", []string{"10.0.0.0/8"}, 60); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entries, found, err := store.Get("AWS")
	if err != nil || !found || len(entries) != 1 {
		t.Fatalf("live entries must be returned, got %v %v %v", entries, found, err)
	}
	// Advance past the TTL: the entry expires and is evicted.
	now = now.Add(2 * time.Minute)
	if _, found, _ := store.Get("AWS"); found {
		t.Fatal("expired entries must miss")
	}
	// An entry stored without a TTL never expires.
	if err := store.Set("GCP", []string{"192.168.0.0/16"}, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	now = now.Add(time.Hour)
	if _, found, _ := store.Get("GCP"); !found {
		t.Fatal("entries without a TTL must not expire")
	}
}

func TestCoverageCloudRedisCloudIPStoreRoundTrip(t *testing.T) {
	redisHandler := newFakeRedisHandler()
	store := NewRedisCloudIPStore(redisHandler)
	if _, found, err := store.Get("AWS"); err != nil || found {
		t.Fatalf("an empty redis must miss, got %v %v", found, err)
	}
	if err := store.Set("AWS", []string{"10.0.0.0/8"}, 120); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entries, found, err := store.Get("AWS")
	if err != nil || !found || len(entries) != 1 || entries[0] != "10.0.0.0/8" {
		t.Fatalf("round trip mismatch: %v %v %v", entries, found, err)
	}
}

func TestRedisCloudRangesStore(t *testing.T) {
	redisHandler := newFakeRedisHandler()
	store := NewRedisCloudRangesStore(redisHandler)
	if _, found, err := store.Get("AWS"); err != nil || found {
		t.Fatalf("an empty redis must miss, got %v %v", found, err)
	}
	if err := store.Set("AWS", []string{"b", "a"}, 60); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entries, found, err := store.Get("AWS")
	if err != nil || !found || len(entries) != 2 || entries[0] != "a" {
		t.Fatalf("ranges must sort on set, got %v %v %v", entries, found, err)
	}
}

// erroringRedisHandler fails every read.
type erroringRedisHandler struct{ fakeRedisHandler }

func (f *erroringRedisHandler) GetKey(string, string) (string, error) {
	return "", errors.New("redis read exploded")
}

func TestRedisCloudStoresSurfaceReadErrors(t *testing.T) {
	redisHandler := &erroringRedisHandler{fakeRedisHandler{data: map[string]string{}, ttls: map[string]*int{}}}
	if _, _, err := NewRedisCloudIPStore(redisHandler).Get("AWS"); err == nil {
		t.Fatal("redis read errors must surface from the v2 store")
	}
	if _, _, err := NewRedisCloudRangesStore(redisHandler).Get("AWS"); err == nil {
		t.Fatal("redis read errors must surface from the ranges store")
	}
}

func TestCloudHTTPGetBadURLAndBody(t *testing.T) {
	if _, _, err := cloudHTTPGet(cloudClient(&cloudServe{}), "://bad", nil, time.Second, false); err == nil {
		t.Fatal("unparseable urls must fail the request build")
	}
	exploding := &cloudServe{responses: map[string]cloudResponse{
		"https://body.test/x": {body: "x", headers: map[string]string{}},
	}}
	client := &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(errReader{})}, nil
	})}
	if _, _, err := cloudHTTPGet(client, "https://body.test/x", nil, time.Second, false); err == nil {
		t.Fatal("body read errors must surface")
	}
	_ = exploding
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read exploded") }

func TestFetchTransportErrorsSurface(t *testing.T) {
	down := &cloudServe{failFirst: 1, failErr: errors.New("dial exploded")}
	if _, err := fetchGCPIPRanges(cloudClient(down)); err == nil {
		t.Fatal("gcp transport errors must surface")
	}
	if _, err := fetchVultrIPRanges(cloudClient(down)); err == nil {
		t.Fatal("vultr transport errors must surface")
	}
	csv := &cloudServe{responses: map[string]cloudResponse{
		digitalOceanCSVURL: {body: ",x\n10.0.0.0/8\n"},
	}}
	set, err := fetchDigitalOceanIPRanges(cloudClient(csv))
	if err != nil || len(set.networks) != 1 {
		t.Fatalf("empty csv prefixes must be skipped, got %+v %v", set.networks, err)
	}
}

func TestCloudManagerFetchViaRealFetchers(t *testing.T) {
	m := NewCloudManager()
	m.SetLogger(log.New(io.Discard, "", 0))
	// No network in tests: every real fetcher fails fast against the
	// closed-port client, which covers the fetcher dispatch.
	m.HTTPClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial exploded")
	})}
	for _, provider := range AllCloudProviders {
		if _, err := m.fetchProviderRanges(provider); err == nil {
			t.Fatalf("provider %s must fail against a dead transport", provider)
		}
	}
}

func TestCloudManagerRefreshAsyncStoreSetFailure(t *testing.T) {
	m := NewCloudManager()
	m.SetLogger(log.New(io.Discard, "", 0))
	m.SetStore(&writeFailingCloudStore{})
	m.testFetcher = func(provider string) (cloudRangeSet, error) {
		set := newCloudRangeSet()
		masked, key, _ := parseCloudNetwork("10.0.0.0/8")
		set.networks[key] = masked
		return set, nil
	}
	if err := m.RefreshAsync([]string{"AWS"}, 60); err != nil {
		t.Fatalf("RefreshAsync: %v", err)
	}
	if !m.hasRanges("AWS") {
		t.Fatal("a store write failure must not block installation")
	}
}

func TestCloudManagerScheduleDefaultRefresh(t *testing.T) {
	m := NewCloudManager()
	m.SetLogger(log.New(io.Discard, "", 0))
	m.testFetcher = func(provider string) (cloudRangeSet, error) {
		return newCloudRangeSet(), nil
	}
	if !m.ScheduleRefresh([]string{"AWS"}, 60, nil) {
		t.Fatal("a nil refresh must schedule the default")
	}
	waitUntilShort(t, func() bool { return !m.Refreshing() })
}

func TestFetchAzureDownloadAndPrefixFailures(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	logger := log.New(io.Discard, "", 0)
	page := `<html><a id="failoverLink" href="https://download.microsoft.com/d/ServiceTags_Public_20260901.json">x</a></html>`

	// The download step returns a server error: the retry budget exhausts.
	failing := &cloudServe{responses: map[string]cloudResponse{
		azurePageURL: {body: page},
		"https://download.microsoft.com/d/ServiceTags_Public_20260901.json": {status: 500},
	}}
	if _, err := fetchAzureIPRanges(cloudClient(failing), func() time.Time { return now }, logger); err == nil {
		t.Fatal("a failing download must surface")
	}

	// The downloaded document carries an unparseable prefix.
	badPrefix := &cloudServe{responses: map[string]cloudResponse{
		azurePageURL: {body: page},
		"https://download.microsoft.com/d/ServiceTags_Public_20260901.json": {body: `{"values":[{"name":"AzureCloud","properties":{"addressPrefixes":["nope"]}}]}`},
	}}
	if _, err := fetchAzureIPRanges(cloudClient(badPrefix), func() time.Time { return now }, logger); err == nil {
		t.Fatal("unparseable azure prefixes must surface")
	}
}

func TestCloudHTTPGetPaths(t *testing.T) {
	ok := &cloudServe{responses: map[string]cloudResponse{
		"https://ok.test/data": {status: 200, body: "payload"},
	}}
	body, status, err := cloudHTTPGet(cloudClient(ok), "https://ok.test/data", map[string]string{"X-Test": "1"}, time.Second, false)
	if err != nil || status != 200 || string(body) != "payload" {
		t.Fatalf("successful gets must read the body, got %q %d %v", body, status, err)
	}

	serverError := &cloudServe{responses: map[string]cloudResponse{
		"https://bad.test/x": {status: 500},
	}}
	if _, status, err := cloudHTTPGet(cloudClient(serverError), "https://bad.test/x", nil, time.Second, false); err == nil || status != 500 {
		t.Fatalf("non-2xx must surface with the status, got %d %v", status, err)
	}

	redirect := &cloudServe{responses: map[string]cloudResponse{
		"https://redirect.test/x": {status: 302},
	}}
	_, status, err = cloudHTTPGet(cloudClient(redirect), "https://redirect.test/x", nil, time.Second, true)
	if err == nil || status != 302 || !strings.Contains(err.Error(), "refusing to follow redirects") {
		t.Fatalf("refused redirects must surface, got %d %v", status, err)
	}

	transportError := &cloudServe{failFirst: 1, failErr: errors.New("dial exploded")}
	if _, _, err := cloudHTTPGet(cloudClient(transportError), "https://any.test/x", nil, time.Second, false); err == nil {
		t.Fatal("transport errors must surface")
	}

	// A nil client falls back to the default timeout client; the request
	// fails against a closed local port without touching the network.
	if _, _, err := cloudHTTPGet(nil, "http://127.0.0.1:1/x", nil, time.Second, false); err == nil {
		t.Fatal("unreachable endpoints must error")
	}
}

func TestFetchAWSIPRanges(t *testing.T) {
	serve := &cloudServe{responses: map[string]cloudResponse{
		awsIPRangesURL: {body: `{"prefixes":[
			{"ip_prefix":"10.0.0.0/8","service":"AMAZON","region":"us-east-1"},
			{"ip_prefix":"192.168.0.0/16","service":"S3","region":"us-west-2"},
			{"ip_prefix":"172.16.0.0/12","service":"AMAZON","region":""}
		]}`},
	}}
	set, err := fetchAWSIPRanges(cloudClient(serve))
	if err != nil {
		t.Fatalf("fetchAWSIPRanges: %v", err)
	}
	if len(set.networks) != 2 {
		t.Fatalf("only AMAZON entries are kept, got %d", len(set.networks))
	}
	if set.regions["10.0.0.0/8"] != "us-east-1" {
		t.Fatalf("regions must be kept, got %+v", set.regions)
	}
	if _, ok := set.networks["192.168.0.0/16"]; ok {
		t.Fatal("non-AMAZON services must be skipped")
	}

	broken := &cloudServe{responses: map[string]cloudResponse{
		awsIPRangesURL: {body: "{not json"},
	}}
	if _, err := fetchAWSIPRanges(cloudClient(broken)); err == nil {
		t.Fatal("malformed documents must surface")
	}
	badPrefix := &cloudServe{responses: map[string]cloudResponse{
		awsIPRangesURL: {body: `{"prefixes":[{"ip_prefix":"nope","service":"AMAZON"}]}`},
	}}
	if _, err := fetchAWSIPRanges(cloudClient(badPrefix)); err == nil {
		t.Fatal("unparseable prefixes must surface")
	}
	unreachable := &cloudServe{failFirst: 1, failErr: errors.New("dial exploded")}
	if _, err := fetchAWSIPRanges(cloudClient(unreachable)); err == nil {
		t.Fatal("transport errors must surface")
	}
}

func TestFetchGCPIPRanges(t *testing.T) {
	serve := &cloudServe{responses: map[string]cloudResponse{
		gcpIPRangesURL: {body: `{"prefixes":[
			{"ipv4Prefix":"10.0.0.0/8","scope":"us-east1"},
			{"ipv6Prefix":"2001:db8::/32","scope":"europe-west1"},
			{"scope":"no-prefix"}
		]}`},
	}}
	set, err := fetchGCPIPRanges(cloudClient(serve))
	if err != nil {
		t.Fatalf("fetchGCPIPRanges: %v", err)
	}
	if len(set.networks) != 2 {
		t.Fatalf("entries without prefixes must be skipped, got %d", len(set.networks))
	}
	if set.regions["10.0.0.0/8"] != "us-east1" || set.regions["2001:db8::/32"] != "europe-west1" {
		t.Fatalf("scopes must map to regions, got %+v", set.regions)
	}
	badPrefix := &cloudServe{responses: map[string]cloudResponse{
		gcpIPRangesURL: {body: `{"prefixes":[{"ipv4Prefix":"999.0.0.0/8"}]}`},
	}}
	if _, err := fetchGCPIPRanges(cloudClient(badPrefix)); err == nil {
		t.Fatal("unparseable prefixes must surface")
	}
	if _, err := fetchGCPIPRanges(cloudClient(&cloudServe{responses: map[string]cloudResponse{
		gcpIPRangesURL: {body: "{bad"},
	}})); err == nil {
		t.Fatal("malformed documents must surface")
	}
}

func TestFetchCSVPrefixNetworks(t *testing.T) {
	serve := &cloudServe{responses: map[string]cloudResponse{
		digitalOceanCSVURL: {body: "# comment\n\n 10.0.0.0/8 ,extra\nnot-a-prefix\n192.168.0.0/16\n"},
	}}
	set, err := fetchDigitalOceanIPRanges(cloudClient(serve))
	if err != nil {
		t.Fatalf("fetchDigitalOceanIPRanges: %v", err)
	}
	if len(set.networks) != 2 {
		t.Fatalf("comments, blanks and bad rows must be skipped, got %d", len(set.networks))
	}
	if _, ok := set.networks["192.168.0.0/16"]; !ok {
		t.Fatalf("csv prefixes must be kept, got %+v", set.networks)
	}
	linode := &cloudServe{responses: map[string]cloudResponse{
		linodeCSVURL: {body: "172.16.0.0/12,x\n"},
	}}
	linodeSet, err := fetchLinodeIPRanges(cloudClient(linode))
	if err != nil || len(linodeSet.networks) != 1 {
		t.Fatalf("linode csv fetch mismatch: %v %+v", err, linodeSet.networks)
	}
	if _, err := fetchLinodeIPRanges(cloudClient(&cloudServe{failFirst: 1, failErr: errors.New("down")})); err == nil {
		t.Fatal("transport errors must surface")
	}
}

func TestFetchVultrIPRanges(t *testing.T) {
	serve := &cloudServe{responses: map[string]cloudResponse{
		vultrJSONURL: {body: `{"subnets":[{"ip_prefix":"10.0.0.0/8"},{"ip_prefix":""},{"ip_prefix":"bad"}]}`},
	}}
	set, err := fetchVultrIPRanges(cloudClient(serve))
	if err != nil {
		t.Fatalf("fetchVultrIPRanges: %v", err)
	}
	if len(set.networks) != 1 {
		t.Fatalf("empty and bad prefixes must be skipped, got %d", len(set.networks))
	}
	if _, err := fetchVultrIPRanges(cloudClient(&cloudServe{responses: map[string]cloudResponse{
		vultrJSONURL: {body: "{bad"},
	}})); err == nil {
		t.Fatal("malformed documents must surface")
	}
}

func TestIsTrustedAzureDownloadURL(t *testing.T) {
	if !isTrustedAzureDownloadURL("https://download.microsoft.com/x/ServiceTags.json") {
		t.Fatal("the trusted host must pass")
	}
	if isTrustedAzureDownloadURL("http://download.microsoft.com/x.json") {
		t.Fatal("plain http must be refused")
	}
	if isTrustedAzureDownloadURL("https://evil.test/x.json") {
		t.Fatal("other hosts must be refused")
	}
	if isTrustedAzureDownloadURL("://bad") {
		t.Fatal("unparseable urls must be refused")
	}
}

func TestParseServiceTagsDate(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	if _, ok := parseServiceTagsDate("https://download.microsoft.com/x.json", now); ok {
		t.Fatal("urls without a date must fail")
	}
	if _, ok := parseServiceTagsDate("https://download.microsoft.com/ServiceTags_Public_99999999.json", now); ok {
		t.Fatal("unparseable dates must fail")
	}
	if _, ok := parseServiceTagsDate("https://download.microsoft.com/ServiceTags_Public_20991231.json", now); ok {
		t.Fatal("future dates must fail")
	}
	parsed, ok := parseServiceTagsDate("https://download.microsoft.com/ServiceTags_Public_20260901.json", now)
	if !ok || parsed != time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("current dates must parse, got %v %v", parsed, ok)
	}
}

func TestCompareServiceTagsKeys(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	dated := func(d string) string {
		return "https://download.microsoft.com/ServiceTags_Public_" + d + ".json"
	}
	if !compareServiceTagsKeys(dated("20260901"), dated("20260915"), now) {
		t.Fatal("older dates sort first")
	}
	if compareServiceTagsKeys(dated("20260915"), dated("20260901"), now) {
		t.Fatal("newer dates must win")
	}
	// Dated entries beat undated ones; undated fall back to URL order.
	if !compareServiceTagsKeys("https://download.microsoft.com/a.json", dated("20260901"), now) {
		t.Fatal("undated entries must lose to dated ones")
	}
	if compareServiceTagsKeys(dated("20260901"), "https://download.microsoft.com/a.json", now) {
		t.Fatal("dated entries must beat undated ones")
	}
	if !compareServiceTagsKeys("https://download.microsoft.com/a.json", "https://download.microsoft.com/b.json", now) {
		t.Fatal("undated entries compare by url")
	}
	hasDate, _, _ := serviceTagsSortKey(dated("20260901"), now)
	if !hasDate {
		t.Fatal("dated keys must report a date")
	}
	noDate, _, _ := serviceTagsSortKey("https://download.microsoft.com/a.json", now)
	if noDate {
		t.Fatal("undated keys must report no date")
	}
}

func TestWarnIfServiceTagsURLIsStale(t *testing.T) {
	var buf strings.Builder
	logger := log.New(&buf, "", 0)
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	warnIfServiceTagsURLIsStale("https://download.microsoft.com/x.json", now, logger)
	if !strings.Contains(buf.String(), "no parseable date") {
		t.Fatalf("undated urls must warn, got %q", buf.String())
	}
	buf.Reset()
	warnIfServiceTagsURLIsStale("https://download.microsoft.com/ServiceTags_Public_20260901.json", now, logger)
	if buf.String() != "" {
		t.Fatalf("current urls must not warn, got %q", buf.String())
	}
	warnIfServiceTagsURLIsStale("https://download.microsoft.com/ServiceTags_Public_20200101.json", now, logger)
	if !strings.Contains(buf.String(), "days old, possibly stale") {
		t.Fatalf("stale urls must warn, got %q", buf.String())
	}
}

func TestExtractFailoverLinkURL(t *testing.T) {
	html := `<a id="failoverLink" href="https://download.microsoft.com/download/1/ServiceTags.json">x</a>`
	if got := extractFailoverLinkURL(html); got != "https://download.microsoft.com/download/1/ServiceTags.json" {
		t.Fatalf("trusted failover links must be extracted, got %q", got)
	}
	if got := extractFailoverLinkURL(`<a id="failoverLink" href="https://evil.test/x.json">x</a>`); got != "" {
		t.Fatalf("untrusted failover links must be refused, got %q", got)
	}
	if got := extractFailoverLinkURL(`<a id="failoverLink">no href</a>`); got != "" {
		t.Fatalf("anchors without hrefs must be refused, got %q", got)
	}
	if got := extractFailoverLinkURL(`<p>nothing here</p>`); got != "" {
		t.Fatalf("pages without anchors must return empty, got %q", got)
	}
}

func TestExtractNewestServiceTagsURL(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	page := `<a href="https://evil.test/ServiceTags_Public_20260910.json">e</a>
		https://download.microsoft.com/x/ServiceTags_Public_20260910.json?x=1
		https://download.microsoft.com/y/ServiceTags_Public_20260920.json`
	if got := extractNewestServiceTagsURL(page, now, logger); got != "https://download.microsoft.com/y/ServiceTags_Public_20260920.json" {
		t.Fatalf("the newest trusted candidate must win, got %q", got)
	}
	if got := extractNewestServiceTagsURL("https://evil.test/ServiceTags_Public_20260910.json", now, logger); got != "" {
		t.Fatalf("untrusted-only pages must return empty, got %q", got)
	}
	if got := extractNewestServiceTagsURL("<p>none</p>", now, logger); got != "" {
		t.Fatalf("pages without candidates must return empty, got %q", got)
	}
}

func TestExtractGenericJSONURL(t *testing.T) {
	if got := extractGenericJSONURL(`<a href="https://download.microsoft.com/download/x/latest.json">x</a>`); got != "https://download.microsoft.com/download/x/latest.json" {
		t.Fatalf("trusted generic json hrefs must be extracted, got %q", got)
	}
	if got := extractGenericJSONURL(`<a href="https://evil.test/latest.json">x</a>`); got != "" {
		t.Fatalf("untrusted hrefs must be refused, got %q", got)
	}
	if got := extractGenericJSONURL("<p>none</p>"); got != "" {
		t.Fatalf("pages without generic hrefs must return empty, got %q", got)
	}
}

func TestExtractAzureDownloadURLPriority(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	failover := `<a id="failoverLink" href="https://download.microsoft.com/f/ServiceTags.json">x</a>`
	if got := extractAzureDownloadURL(failover, now, logger); got != "https://download.microsoft.com/f/ServiceTags.json" {
		t.Fatalf("the failover link must win, got %q", got)
	}
	serviceTags := `https://download.microsoft.com/s/ServiceTags_Public_20260901.json`
	if got := extractAzureDownloadURL(serviceTags, now, logger); got != serviceTags {
		t.Fatalf("service tags candidates come next, got %q", got)
	}
	if got := extractAzureDownloadURL(`<a href="https://download.microsoft.com/g/latest.json">x</a>`, now, logger); got != "https://download.microsoft.com/g/latest.json" {
		t.Fatalf("generic json hrefs are the fallback, got %q", got)
	}
}

func TestDownloadAzureServiceTags(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	frozen := func() time.Time { return now }

	// Immediate success.
	serve := &cloudServe{responses: map[string]cloudResponse{
		"https://download.microsoft.com/ok/ServiceTags.json": {body: "{}"},
	}}
	body, err := downloadAzureServiceTags(cloudClient(serve), "https://download.microsoft.com/ok/ServiceTags.json", now.Add(time.Minute), frozen)
	if err != nil || string(body) != "{}" {
		t.Fatalf("immediate downloads must succeed, got %q %v", body, err)
	}

	// Redirect refusals return without retrying.
	redirect := &cloudServe{responses: map[string]cloudResponse{
		"https://download.microsoft.com/redir/ServiceTags.json": {status: 302},
	}}
	if _, err := downloadAzureServiceTags(cloudClient(redirect), "https://download.microsoft.com/redir/ServiceTags.json", now.Add(time.Minute), frozen); err == nil {
		t.Fatal("redirects must abort the download")
	}

	// Transient failures retry until the attempt budget runs out.
	flaky := &cloudServe{failFirst: 10, failErr: errors.New("down")}
	deadline := now.Add(10 * time.Millisecond)
	if _, err := downloadAzureServiceTags(cloudClient(flaky), "https://download.microsoft.com/flaky/ServiceTags.json", deadline, frozen); err == nil {
		t.Fatal("exhausted attempts must surface the error")
	}

	// An exhausted deadline aborts before the first attempt.
	past := now.Add(-time.Minute)
	if _, err := downloadAzureServiceTags(cloudClient(serve), "https://download.microsoft.com/ok/ServiceTags.json", past, frozen); err == nil || !strings.Contains(err.Error(), "max elapsed time") {
		t.Fatalf("an expired deadline must abort, got %v", err)
	}
}

func TestSelectAzureCloudPrefixes(t *testing.T) {
	body := []byte(`{"values":[
		{"name":"AzureKubernetes","properties":{"addressPrefixes":["10.1.0.0/16"]}},
		{"name":"AzureCloud","properties":{"addressPrefixes":["10.0.0.0/8","2001:db8::/32"]}}
	]}`)
	prefixes, err := selectAzureCloudPrefixes(body)
	if err != nil {
		t.Fatalf("selectAzureCloudPrefixes: %v", err)
	}
	if len(prefixes) != 2 || prefixes[0] != "10.0.0.0/8" {
		t.Fatalf("the AzureCloud tag must be selected, got %v", prefixes)
	}
	if _, err := selectAzureCloudPrefixes([]byte(`{"values":[{"name":"Other"}]}`)); err == nil {
		t.Fatal("documents without the AzureCloud tag must fail")
	}
	if _, err := selectAzureCloudPrefixes([]byte("{bad")); err == nil {
		t.Fatal("malformed documents must fail")
	}
}

func TestFetchAzureIPRangesEndToEnd(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	page := `<html><a id="failoverLink" href="https://download.microsoft.com/d/ServiceTags_Public_20260901.json">x</a></html>`
	serve := &cloudServe{responses: map[string]cloudResponse{
		azurePageURL: {body: page},
		"https://download.microsoft.com/d/ServiceTags_Public_20260901.json": {body: `{"values":[{"name":"AzureCloud","properties":{"addressPrefixes":["10.0.0.0/8"]}}]}`},
	}}
	logger := log.New(io.Discard, "", 0)
	set, err := fetchAzureIPRanges(cloudClient(serve), func() time.Time { return now }, logger)
	if err != nil {
		t.Fatalf("fetchAzureIPRanges: %v", err)
	}
	if _, ok := set.networks["10.0.0.0/8"]; !ok {
		t.Fatalf("AzureCloud prefixes must be installed, got %+v", set.networks)
	}
	seenUA := false
	for _, seen := range serve.seen {
		if seen == "azure-ua" {
			seenUA = true
		}
	}
	if !seenUA {
		t.Fatal("the azure page fetch must send the browser user agent")
	}

	// A page without any usable link fails cleanly.
	empty := &cloudServe{responses: map[string]cloudResponse{
		azurePageURL: {body: "<html><p>no links</p></html>"},
	}}
	if _, err := fetchAzureIPRanges(cloudClient(empty), func() time.Time { return now }, logger); err == nil || !strings.Contains(err.Error(), "could not find Azure IP ranges download URL") {
		t.Fatalf("link-less pages must fail, got %v", err)
	}

	// A page fetch failure propagates.
	down := &cloudServe{failFirst: 1, failErr: errors.New("page down")}
	if _, err := fetchAzureIPRanges(cloudClient(down), func() time.Time { return now }, logger); err == nil {
		t.Fatal("page fetch failures must surface")
	}

	// A downloaded document without the AzureCloud tag fails.
	otherTag := &cloudServe{responses: map[string]cloudResponse{
		azurePageURL: {body: page},
		"https://download.microsoft.com/d/ServiceTags_Public_20260901.json": {body: `{"values":[{"name":"Other","properties":{"addressPrefixes":["10.0.0.0/8"]}}]}`},
	}}
	if _, err := fetchAzureIPRanges(cloudClient(otherTag), func() time.Time { return now }, logger); err == nil {
		t.Fatal("documents without AzureCloud must fail")
	}

	// A clock that jumps past the download deadline aborts the page fetch.
	steps := 0
	jumpy := func() time.Time {
		steps++
		if steps <= 1 {
			return now
		}
		return now.Add(time.Hour)
	}
	if _, err := fetchAzureIPRanges(cloudClient(serve), jumpy, logger); err == nil || !strings.Contains(err.Error(), "max elapsed time") {
		t.Fatalf("an expired deadline must abort, got %v", err)
	}
}

func TestCloudManagerFetchProviderRanges(t *testing.T) {
	m := NewCloudManager()
	m.SetLogger(log.New(io.Discard, "", 0))
	if _, err := m.fetchProviderRanges("NoSuchProvider"); err == nil {
		t.Fatal("unknown providers must fail")
	}
	m.testFetcher = func(provider string) (cloudRangeSet, error) {
		set := newCloudRangeSet()
		masked, key, _ := parseCloudNetwork("10.0.0.0/8")
		set.networks[key] = masked
		return set, nil
	}
	set, err := m.fetchProviderRanges("AWS")
	if err != nil || len(set.networks) != 1 {
		t.Fatalf("the test fetcher must take precedence, got %+v %v", set.networks, err)
	}
}

func TestCloudManagerRefreshAsyncWithStore(t *testing.T) {
	m := NewCloudManager()
	m.SetLogger(log.New(io.Discard, "", 0))
	store := NewInMemoryCloudIPStore()
	m.SetStore(store)
	if m.effectiveStore() == nil {
		t.Fatal("an explicit store must be used")
	}
	if err := store.Set("AWS", []string{"10.0.0.0/8|us", "bad-entry"}, 60); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var fetches int
	m.testFetcher = func(provider string) (cloudRangeSet, error) {
		fetches++
		if provider == "FAIL" {
			return cloudRangeSet{}, errors.New("fetch exploded")
		}
		return newCloudRangeSet(), nil // empty: nothing installed
	}
	// Cached AWS entry decodes the valid prefix and skips the fetch; the
	// corrupt entry inside it is logged and re-ensured; FAIL logs and
	// ensures; the empty set installs nothing.
	if err := m.RefreshAsync([]string{"AWS", "FAIL"}, 60); err != nil {
		t.Fatalf("RefreshAsync: %v", err)
	}
	if fetches != 1 {
		t.Fatalf("only the failed provider must fetch, got %d fetches", fetches)
	}
	if !m.hasRanges("AWS") || !m.hasRanges("FAIL") {
		t.Fatal("failed providers must still get an empty entry")
	}

	// A redis-backed store (no explicit store) is used when set.
	redisManager := &fakeRedisHandler{data: map[string]string{}, ttls: map[string]*int{}}
	m2 := NewCloudManager()
	m2.SetLogger(log.New(io.Discard, "", 0))
	m2.SetRedisHandler(redisManager)
	if m2.effectiveStore() == nil {
		t.Fatal("a redis handler must provide a store")
	}
	m2.testFetcher = func(provider string) (cloudRangeSet, error) {
		set := newCloudRangeSet()
		masked, key, err := parseCloudNetwork("10.0.0.0/8")
		if err != nil {
			return cloudRangeSet{}, err
		}
		set.networks[key] = masked
		return set, nil
	}
	if err := m2.RefreshAsync([]string{"GCP"}, 60); err != nil {
		t.Fatalf("RefreshAsync: %v", err)
	}
	if !m2.hasRanges("GCP") {
		t.Fatal("fetched ranges must install")
	}
	if stored, _ := redisManager.data["cloud_ranges_v2:GCP"]; !strings.Contains(stored, "10.0.0.0/8") {
		t.Fatalf("fetched ranges must persist, got %q", stored)
	}
	// A nil effective store (no store, no redis) skips persistence.
	m3 := NewCloudManager()
	m3.SetLogger(log.New(io.Discard, "", 0))
	m3.testFetcher = m2.testFetcher
	if m3.effectiveStore() != nil {
		t.Fatal("without store or redis there is no store")
	}
	if err := m3.RefreshAsync([]string{"Azure"}, 60); err != nil {
		t.Fatalf("RefreshAsync: %v", err)
	}
	if !m3.hasRanges("Azure") {
		t.Fatal("ranges must install without a store")
	}
	// A store read error is logged and the provider entry is ensured.
	failing := &failingCloudStore{}
	m4 := NewCloudManager()
	m4.SetLogger(log.New(io.Discard, "", 0))
	m4.SetStore(failing)
	m4.testFetcher = func(provider string) (cloudRangeSet, error) {
		return cloudRangeSet{}, errors.New("fetch exploded")
	}
	if err := m4.RefreshAsync([]string{"AWS"}, 60); err != nil {
		t.Fatalf("RefreshAsync: %v", err)
	}
	if !m4.hasRanges("AWS") {
		t.Fatal("store errors must still ensure the provider entry")
	}
}

type failingCloudStore struct{}

func (f *failingCloudStore) Get(string) ([]string, bool, error) {
	return nil, false, errors.New("store exploded")
}

func (f *failingCloudStore) Set(string, []string, int) error { return errors.New("store exploded") }

// writeFailingCloudStore reads as a miss but fails every write.
type writeFailingCloudStore struct{}

func (w *writeFailingCloudStore) Get(string) ([]string, bool, error) {
	return nil, false, nil
}

func (w *writeFailingCloudStore) Set(string, []string, int) error {
	return errors.New("store write exploded")
}

func TestCloudManagerScheduleRefresh(t *testing.T) {
	m := NewCloudManager()
	m.SetLogger(log.New(io.Discard, "", 0))
	var calls int
	done := make(chan struct{})
	ok := m.ScheduleRefresh([]string{"AWS"}, 60, func() error {
		calls++
		close(done)
		return nil
	})
	if !ok {
		t.Fatal("the first scheduled refresh must start")
	}
	<-done
	waitUntilShort(t, func() bool { return !m.Refreshing() })
	// While a refresh is in flight, further schedules are refused.
	blocking := make(chan struct{})
	m2 := NewCloudManager()
	m2.SetLogger(log.New(io.Discard, "", 0))
	m2.ScheduleRefresh([]string{"AWS"}, 60, func() error {
		<-blocking
		return nil
	})
	if m2.ScheduleRefresh([]string{"AWS"}, 60, nil) {
		t.Fatal("a second refresh must be refused while one is in flight")
	}
	close(blocking)
	waitUntilShort(t, func() bool { return !m2.Refreshing() })
	// A failing refresh is logged, not surfaced.
	m3 := NewCloudManager()
	m3.SetLogger(log.New(io.Discard, "", 0))
	m3.ScheduleRefresh([]string{"AWS"}, 60, func() error { return errors.New("refresh exploded") })
	waitUntilShort(t, func() bool { return !m3.Refreshing() })
}

func waitUntilShort(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestCloudManagerIsCloudIP(t *testing.T) {
	var buf strings.Builder
	m := NewCloudManager()
	m.SetLogger(log.New(&buf, "", 0))
	now := time.Unix(1, 0)
	m.nowFunc = func() time.Time { return now }
	set := newCloudRangeSet()
	masked, key, _ := parseCloudNetwork("10.0.0.0/8")
	set.networks[key] = masked
	set.regions[key] = "us-east-1"
	m.installRanges("AWS", set, true)

	if !m.IsCloudIP("10.1.2.3", []string{"AWS"}) {
		t.Fatal("an AWS ip must match")
	}
	if m.IsCloudIP("203.0.113.9", []string{"AWS"}) {
		t.Fatal("a non-cloud ip must not match")
	}
	// A regional carveout allows the region's addresses.
	if m.IsCloudIP("10.1.2.3", []string{"AWS:!us-east-1"}) {
		t.Fatal("carved-out regions must not match")
	}
	if !m.IsCloudIP("10.1.2.3", []string{"AWS:!eu-west-1"}) {
		t.Fatal("other regions must still match")
	}
	if m.IsCloudIP("not-an-ip", []string{"AWS"}) {
		t.Fatal("invalid ips must not match")
	}
	if !strings.Contains(buf.String(), "Invalid IP address") {
		t.Fatal("invalid ips must be logged")
	}
	// An unknown provider has no ranges: not blocked, no warning.
	buf.Reset()
	if m.IsCloudIP("10.1.2.3", []string{"GCP"}) {
		t.Fatal("unknown providers must not match")
	}
	if strings.Contains(buf.String(), "not populated yet") {
		t.Fatal("missing providers are silently skipped")
	}
	// An empty installed set warns, with a cooldown.
	empty := NewCloudManager()
	empty.SetLogger(log.New(&buf, "", 0))
	empty.nowFunc = func() time.Time { return now }
	empty.installRanges("GCP", newCloudRangeSet(), false)
	if empty.IsCloudIP("10.1.2.3", []string{"GCP"}) {
		t.Fatal("empty ranges must not match")
	}
	if !strings.Contains(buf.String(), "not populated yet") {
		t.Fatal("empty ranges must warn")
	}
	buf.Reset()
	empty.IsCloudIP("10.1.2.3", []string{"GCP"})
	if strings.Contains(buf.String(), "not populated yet") {
		t.Fatal("the warning must respect the cooldown")
	}
	now = now.Add(emptyRangesWarningCooldown + time.Second)
	empty.IsCloudIP("10.1.2.3", []string{"GCP"})
	if !strings.Contains(buf.String(), "not populated yet") {
		t.Fatal("the warning must re-fire after the cooldown")
	}
	// IPv6 addresses match too.
	v6 := newCloudRangeSet()
	_, v6key, _ := parseCloudNetwork("2001:db8::/32")
	maskedV6, _ := netip.ParsePrefix("2001:db8::/32")
	v6.networks[v6key] = maskedV6.Masked()
	m.installRanges("Azure", v6, false)
	if !m.IsCloudIP("2001:db8::1", []string{"Azure"}) {
		t.Fatal("ipv6 addresses must match")
	}
}

func TestCloudManagerGetCloudProviderDetails(t *testing.T) {
	var buf strings.Builder
	m := NewCloudManager()
	m.SetLogger(log.New(&buf, "", 0))
	set := newCloudRangeSet()
	masked, key, _ := parseCloudNetwork("10.0.0.0/8")
	set.networks[key] = masked
	m.installRanges("AWS", set, true)
	provider, network, ok := m.GetCloudProviderDetails("10.1.2.3", []string{"AWS"})
	if !ok || provider != "AWS" || network != "10.0.0.0/8" {
		t.Fatalf("details mismatch: %q %q %v", provider, network, ok)
	}
	if _, _, ok := m.GetCloudProviderDetails("203.0.113.9", []string{"AWS"}); ok {
		t.Fatal("unmatched ips must report nothing")
	}
	if _, _, ok := m.GetCloudProviderDetails("nope", []string{"AWS"}); ok {
		t.Fatal("invalid ips must report nothing")
	}
	if _, _, ok := m.GetCloudProviderDetails("10.1.2.3", []string{"GCP"}); ok {
		t.Fatal("unknown providers must report nothing")
	}
}

func TestCloudManagerStatus(t *testing.T) {
	m := NewCloudManager()
	now := time.Unix(100, 0)
	m.nowFunc = func() time.Time { return now }
	status := m.Status()
	if len(status) != len(AllCloudProviders) {
		t.Fatalf("status must cover every provider, got %d", len(status))
	}
	if status["AWS"].Ready {
		t.Fatal("an unpopulated provider is not ready")
	}
	set := newCloudRangeSet()
	masked, key, _ := parseCloudNetwork("10.0.0.0/8")
	set.networks[key] = masked
	m.installRanges("AWS", set, true)
	status = m.Status()
	if !status["AWS"].Ready || status["AWS"].Entries != 1 || !status["AWS"].LastRefreshed.Equal(now) {
		t.Fatalf("populated providers must report readiness, got %+v", status["AWS"])
	}
	if m.LastRefreshStamp() != 0 {
		t.Fatal("the stamp defaults to zero")
	}
	m.SetLastRefreshStamp(42)
	if m.LastRefreshStamp() != 42 {
		t.Fatal("the stamp must be settable")
	}
}
