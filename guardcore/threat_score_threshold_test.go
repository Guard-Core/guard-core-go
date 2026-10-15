package guardcore

import (
	"math"
	"strings"
	"testing"
)

func thresholdRequest(t *testing.T, value string) Request {
	t.Helper()
	return newTestRequest(t, func(opts *RequestOptions, _ *RequestState) {
		opts.Path = "/x"
		opts.RawQuery = "a=" + value
		opts.QueryParams = map[string]string{"a": value}
	})
}

func TestThreatScoreThresholdDefaultAndRange(t *testing.T) {
	cfg, err := NewSecurityConfig(nil)
	if err != nil || cfg.Detection.ThreatScoreThreshold != 1.0 {
		t.Fatalf("default must be 1.0 and valid, got %v, %v", cfg.Detection.ThreatScoreThreshold, err)
	}
	cfg, err = NewSecurityConfig(func(c *SecurityConfig) { c.Detection.ThreatScoreThreshold = 0 })
	if err != nil || cfg.Detection.ThreatScoreThreshold != 1.0 {
		t.Fatalf("zero means the default, got %v, %v", cfg.Detection.ThreatScoreThreshold, err)
	}
	for _, ok := range []float64{0.5, 1, 5, 10} {
		if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.Detection.ThreatScoreThreshold = ok }); err != nil {
			t.Fatalf("%v must validate, got %v", ok, err)
		}
	}
	for _, bad := range []float64{-0.1, 10.5, math.NaN(), math.Inf(1)} {
		_, err := NewSecurityConfig(func(c *SecurityConfig) { c.Detection.ThreatScoreThreshold = bad })
		if err == nil || !strings.Contains(err.Error(), "detection_threat_score_threshold") {
			t.Fatalf("%v must be rejected naming the knob, got %v", bad, err)
		}
	}
}

func TestThreatScoreThresholdGatesRegexAnomaly(t *testing.T) {
	// "../../etc/passwd" accumulates a regex anomaly of 2.0 and no semantic hit.
	req := thresholdRequest(t, "../../etc/passwd")
	for _, tc := range []struct {
		threshold float64
		blocks    bool
	}{{1.0, true}, {2.0, true}, {3.0, false}, {10.0, false}} {
		cfg := testConfig(t)
		cfg.Detection.ThreatScoreThreshold = tc.threshold
		categories, _ := detectThreat(req, cfg, resolveDetectionExclusions(cfg, nil))
		if (len(categories) > 0) != tc.blocks {
			t.Fatalf("threshold %v: blocked=%v, want %v (%v)", tc.threshold, len(categories) > 0, tc.blocks, categories)
		}
	}
}

func TestThreatScoreThresholdGatesScanTimeBudget(t *testing.T) {
	jumpClock(t, 1000)
	req := thresholdRequest(t, "hello")
	for _, tc := range []struct {
		threshold float64
		blocks    bool
	}{{1.0, true}, {5.0, false}} {
		cfg := testConfig(t)
		cfg.Detection.MaxScanSeconds = 0.1
		cfg.Detection.ThreatScoreThreshold = tc.threshold
		categories, _ := detectThreat(req, cfg, resolveDetectionExclusions(cfg, nil))
		if (len(categories) > 0) != tc.blocks {
			t.Fatalf("threshold %v: blocked=%v, want %v (%v)", tc.threshold, len(categories) > 0, tc.blocks, categories)
		}
	}
}
