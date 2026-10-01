package guardcore

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The exported lifecycle seams (SetDownloadEndpoint, SetRangeFetcher) are
// the injection points the conformance runners drive; these tests pin them
// from outside the internals the in-package lifecycle tests use.

func TestSetDownloadEndpointDrivesTheLifecycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(mmdbBytesForTest(t, map[string]string{"203.0.113.0/24": "US"}))
	}))
	defer srv.Close()

	dbPath := t.TempDir() + "/country_asn.mmdb"
	manager := NewIPInfoManager("seam-token", dbPath, DefaultIPInfoMaxAge, nil)
	manager.SetDownloadEndpoint(srv.URL, srv.Client())
	manager.Initialize()
	country, ok := manager.GetCountry("203.0.113.9")
	if !ok || country != "US" {
		t.Fatalf("download via the pinned endpoint must serve countries, got %q ok=%v", country, ok)
	}
}

func TestSetDownloadEndpointNilClientKeepsDefault(t *testing.T) {
	dbPath := t.TempDir() + "/country_asn.mmdb"
	manager := NewIPInfoManager("seam-token", dbPath, DefaultIPInfoMaxAge, nil)
	// A closed port keeps the download deterministic; the failure path must
	// keep the manager soft (no panic, lookups miss).
	manager.SetDownloadEndpoint("http://127.0.0.1:1/db", nil)
	manager.Initialize()
	if _, ok := manager.GetCountry("203.0.113.9"); ok {
		t.Fatal("a failed download must leave lookups missing")
	}
}

func TestSetRangeFetcherPinsRangesAndRegions(t *testing.T) {
	manager := NewCloudManager()
	manager.SetRangeFetcher(func(provider string) ([]string, map[string]string, error) {
		if provider != "CORPUS" {
			return nil, nil, errors.New("unexpected provider " + provider)
		}
		return []string{"203.0.113.0/24"}, map[string]string{"203.0.113.0/24": "us-east"}, nil
	})
	if err := manager.RefreshAsync([]string{"CORPUS"}, 0); err != nil {
		t.Fatalf("RefreshAsync: %v", err)
	}
	if !manager.IsCloudIP("203.0.113.9", []string{"CORPUS"}) {
		t.Fatal("the pinned range must answer as cloud IP")
	}
	provider, network, ok := manager.GetCloudProviderDetails("203.0.113.9", []string{"CORPUS"})
	if !ok || provider != "CORPUS" || network != "203.0.113.0/24" {
		t.Fatalf("provider details drifted: %q %q %v", provider, network, ok)
	}

	// A fresh manager (no cache) with the seam cleared falls back to the
	// built-in registry, which has no fetcher for the corpus provider.
	cleared := NewCloudManager()
	cleared.SetRangeFetcher(nil)
	if err := cleared.RefreshAsync([]string{"CORPUS"}, 0); err != nil {
		t.Fatalf("RefreshAsync after clearing: %v", err)
	}
	if cleared.IsCloudIP("203.0.113.9", []string{"CORPUS"}) {
		t.Fatal("clearing the seam must restore the built-in registry (no fetcher for CORPUS)")
	}
}

func TestSetRangeFetcherRejectsCorruptRanges(t *testing.T) {
	manager := NewCloudManager()
	manager.SetRangeFetcher(func(string) ([]string, map[string]string, error) {
		return []string{"not-a-prefix"}, nil, nil
	})
	if err := manager.RefreshAsync([]string{"CORPUS"}, 0); err != nil {
		t.Fatalf("RefreshAsync must swallow fetch failures like the reference: %v", err)
	}
	if manager.IsCloudIP("203.0.113.9", []string{"CORPUS"}) {
		t.Fatal("a corrupt pinned range must fail the fetch, not install ranges")
	}
}

func TestSetRangeFetcherFetchFailureFailsSoft(t *testing.T) {
	manager := NewCloudManager()
	manager.SetRangeFetcher(func(string) ([]string, map[string]string, error) {
		return nil, nil, errors.New("corpus injected fetch failure")
	})
	// The reference refresh fails soft: a fetch error is logged and the
	// provider stays empty, never a panic or a partial install.
	if err := manager.RefreshAsync([]string{"CORPUS"}, 0); err != nil {
		t.Fatalf("RefreshAsync must swallow fetch errors: %v", err)
	}
	if manager.IsCloudIP("203.0.113.9", []string{"CORPUS"}) {
		t.Fatal("a failed fetch must not install ranges")
	}
}
