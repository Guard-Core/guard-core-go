package guardcore

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// The disk-backed pattern-validation cache, mirroring the reference
// PatternValidationCache (guard_core/detection_engine/_validation_cache.py)
// wired from detection_pattern_validation_cache_path: the empirical
// cost-verdict outcome of pattern validation (probe synthesis plus the
// timed probes) is cached keyed by pattern and flags, so a process boot
// reuses prior certifications instead of re-timing every custom pattern.
// The cheap deterministic layers (dangerous constructs, compile check,
// structural detectors) always re-run outside this cache. Cache entries
// from a different engine version are ignored and overwritten.

// patternValidationCacheVersion pins the cache schema; entries written by
// a different engine version are dropped on load and never reused.
const patternValidationCacheVersion = 1

type patternValidationEntry struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type patternValidationFile struct {
	SchemaVersion int                               `json:"schema_version"`
	EngineVersion string                            `json:"engine_version"`
	Entries       map[string]patternValidationEntry `json:"entries"`
}

type patternValidationCache struct {
	path    string
	version string
	mu      sync.Mutex
	entries map[string]patternValidationEntry
	loaded  bool
}

var activeValidationCache *patternValidationCache

var validationCacheMu sync.Mutex

// NewPatternValidationCache builds the cache over path and loads any
// existing file: entries whose engine version differs from this build's
// are dropped (they are overwritten on the next save). A missing or
// corrupt file leaves an empty in-memory cache (validation stays fully
// empirical, the reference's unset-path behavior).
func NewPatternValidationCache(path string) *patternValidationCache {
	cache := &patternValidationCache{
		path:    path,
		version: patternValidationEngineVersion,
		entries: map[string]patternValidationEntry{},
	}
	cache.load()
	return cache
}

// patternValidationEngineVersion versions the empirical verdicts: bump it
// whenever the validation chain's outcomes can change (the reference keys
// its cache on the engine version for the same reason).
const patternValidationEngineVersion = "1"

func (c *patternValidationCache) load() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loaded = true
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var file patternValidationFile
	if err := json.Unmarshal(data, &file); err != nil {
		log.Printf("pattern validation cache at %s is corrupt; starting empty: %v", c.path, err)
		return
	}
	if file.SchemaVersion != patternValidationCacheVersion || file.EngineVersion != c.version {
		return
	}
	if file.Entries != nil {
		c.entries = file.Entries
	}
}

func (c *patternValidationCache) save() {
	_ = os.MkdirAll(filepath.Dir(c.path), 0o755)
	file := patternValidationFile{
		SchemaVersion: patternValidationCacheVersion,
		EngineVersion: c.version,
		Entries:       c.entries,
	}
	data, err := json.Marshal(file)
	if err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("pattern validation cache write failed at %s: %v", c.path, err)
		return
	}
	if err := os.Rename(tmp, c.path); err != nil {
		log.Printf("pattern validation cache rename failed at %s: %v", c.path, err)
	}
}

// cachedEmpiricalVerdict looks the key up and falls back to the probe,
// storing its outcome: the cache is an optimization over the empirical
// arm, never a behavior change (a load or write failure degrades to full
// re-validation).
func (c *patternValidationCache) cachedEmpiricalVerdict(pattern string, flags uint32, probe func() (bool, string)) (bool, string) {
	key := fmt.Sprintf("%d|%s", flags, pattern)
	c.mu.Lock()
	entry, ok := c.entries[key]
	c.mu.Unlock()
	if ok {
		return entry.Allowed, entry.Reason
	}
	allowed, reason := probe()
	c.mu.Lock()
	c.entries[key] = patternValidationEntry{Allowed: allowed, Reason: reason}
	c.save()
	c.mu.Unlock()
	return allowed, reason
}

// installPatternValidationCache makes cache the active validation cache
// for the default sus-patterns registry (the engine composition calls it
// when detection_pattern_validation_cache_path is set).
func installPatternValidationCache(cache *patternValidationCache) {
	validationCacheMu.Lock()
	defer validationCacheMu.Unlock()
	activeValidationCache = cache
}

func activePatternValidationCache() *patternValidationCache {
	validationCacheMu.Lock()
	defer validationCacheMu.Unlock()
	return activeValidationCache
}

// validatePatternSafetyCostCached runs the deterministic gates of
// ValidatePatternSafety's cost mode (dangerous constructs, compile check)
// and routes the empirical cost probe through the active validation cache
// when one is installed.
func validatePatternSafetyCostCached(pattern string, maxContentLength int) (bool, string) {
	if violation, found := dangerousConstructViolation(pattern); found {
		return false, violation
	}
	if _, err := parseRedosPattern(pattern, defaultPatternFlags); err != nil {
		return false, "Pattern validation failed: " + err.Error()
	}
	if cache := activePatternValidationCache(); cache != nil {
		return cache.cachedEmpiricalVerdict(pattern, uint32(defaultPatternFlags), func() (bool, string) {
			return reachProbeCostVerdict(pattern, maxContentLength, 0)
		})
	}
	return reachProbeCostVerdict(pattern, maxContentLength, 0)
}
