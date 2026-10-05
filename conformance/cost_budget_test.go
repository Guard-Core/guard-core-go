package conformance

// Cost-budget conformance for the cost_bodies suite: verdict parity for
// large inputs is enforced by the main corpus runner (they are plain detect
// cases); this file enforces the OTHER half, scan-cost ceilings, so gross
// cost divergence from the reference can never pass silently again.
//
// Ceilings are self-relative (see index.json cost_budgets.method): each run
// measures its own best-of-3 at the 8 KiB workload and every other workload
// must satisfy
//
//	best_ms <= K * best8_ms * (size_bytes / 8192) + floor_ms
//
// which tolerates host speed and fixed overhead while catching
// superlinear scans. A workload over ceiling fails unless it is listed in
// go_cost_xfail.json with a reason; a listed workload that comes back UNDER
// ceiling also fails, so an xfail entry must be removed when the engine
// fixes the curve (fail-closed drift, same policy as the detect xfails).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

type costBudgets struct {
	Method  string              `json:"method"`
	K       float64             `json:"k"`
	FloorMS float64             `json:"floor_ms"`
	Budgets map[string]costMeta `json:"budgets"`
}

type costMeta struct {
	ReferenceMS      float64 `json:"reference_ms"`
	ExpectedIsThreat bool    `json:"expected_is_threat"`
}

type costXfail struct {
	Workloads map[string]struct {
		Reason string `json:"reason"`
	} `json:"workloads"`
}

func TestCostBudgets(t *testing.T) {
	indexPath := "guard-core-spec-4.1.0/cases/index.json"
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("cost budgets: cannot read %s: %v", indexPath, err)
	}
	var index struct {
		CostBudgets *costBudgets `json:"cost_budgets"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatalf("cost budgets: index.json malformed: %v", err)
	}
	if index.CostBudgets == nil || len(index.CostBudgets.Budgets) == 0 {
		t.Fatal("cost budgets: index.json has no cost_budgets block; regenerate the corpus (generate_cost_cases.py) so cost stays enforced")
	}
	budgets := index.CostBudgets

	suiteRaw, err := os.ReadFile("guard-core-spec-4.1.0/cases/cost_bodies.json")
	if err != nil {
		t.Fatalf("cost budgets: cannot read cost_bodies.json: %v", err)
	}
	var suite struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				Content string `json:"content"`
				Context string `json:"context"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(suiteRaw, &suite); err != nil {
		t.Fatalf("cost budgets: cost_bodies.json malformed: %v", err)
	}
	if len(suite.Cases) == 0 {
		t.Fatal("cost budgets: cost_bodies.json matched zero cases; a vacuous pass is a failure")
	}

	xfail := loadCostXfail(t)

	best8MS, baselineThreat := bestOf3Cost(t, suite.Cases, "cost_prose_8kib")
	if baselineThreat != budgets.Budgets["cost_prose_8kib"].ExpectedIsThreat {
		t.Errorf("cost budgets/cost_prose_8kib: verdict drifted from the recorded expectation")
	}
	t.Logf("cost budgets: baseline best8=%.1f ms", best8MS)

	type over struct {
		id      string
		best    float64
		ceiling float64
	}
	var overs []over
	for _, c := range suite.Cases {
		best, threat := bestOf3Cost(t, suite.Cases, c.ID)
		sizeBytes := len(c.Input.Content)
		ceiling := budgets.K*best8MS*(float64(sizeBytes)/8192.0) + budgets.FloorMS
		if threat != budgets.Budgets[c.ID].ExpectedIsThreat {
			t.Errorf("cost budgets/%s: verdict drifted from the recorded expectation", c.ID)
		}
		line := fmt.Sprintf("cost budgets/%s: best=%.1f ms ceiling=%.1f ms (size %d bytes)",
			c.ID, best, ceiling, sizeBytes)
		if entry, ok := xfail.Workloads[c.ID]; ok {
			if best <= ceiling {
				t.Errorf("%s: listed in go_cost_xfail.json but now UNDER ceiling; remove the xfail entry (%s)", line, entry.Reason)
			} else {
				t.Logf("%s: xfail (still over ceiling): %s", line, entry.Reason)
			}
			continue
		}
		t.Logf("%s", line)
		if best > ceiling {
			overs = append(overs, over{c.ID, best, ceiling})
		}
	}
	if len(overs) > 0 {
		sort.Slice(overs, func(i, j int) bool { return overs[i].best > overs[j].best })
		for _, o := range overs {
			t.Errorf("cost budgets/%s: best %.1f ms exceeds ceiling %.1f ms; scan cost diverged superlinearly from the reference (register in go_cost_xfail.json with a reason and a tracked fix, or fix the engine)", o.id, o.best, o.ceiling)
		}
	}
}

func loadCostXfail(t *testing.T) costXfail {
	t.Helper()
	path := filepath.Join("guard-core-spec-4.1.0", "go_cost_xfail.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return costXfail{Workloads: map[string]struct {
				Reason string `json:"reason"`
			}{}}
		}
		t.Fatalf("cost budgets: cannot read %s: %v", path, err)
	}
	var xf costXfail
	if err := json.Unmarshal(data, &xf); err != nil {
		t.Fatalf("cost budgets: %s malformed: %v", path, err)
	}
	return xf
}

func bestOf3Cost(t *testing.T, cases []struct {
	ID    string `json:"id"`
	Input struct {
		Content string `json:"content"`
		Context string `json:"context"`
	} `json:"input"`
}, id string) (best float64, threat bool) {
	t.Helper()
	for _, c := range cases {
		if c.ID != id {
			continue
		}
		// Adaptive sampling: small workloads are cheap enough to take the
		// min of 3; at 256 KiB and beyond one timed run each keeps the
		// whole suite CI-viable, and the 5x-linear ceilings absorb the
		// lost precision.
		runs := 3
		switch size := len(c.Input.Content); {
		case size >= 256*1024:
			runs = 1
		case size >= 64*1024:
			runs = 2
		}
		best = float64(^uint64(0) >> 1)
		for i := 0; i < runs; i++ {
			start := time.Now()
			verdict := guardcore.Detect(c.Input.Content, "203.0.113.7", c.Input.Context)
			threat = verdict.IsThreat
			elapsed := float64(time.Since(start).Microseconds()) / 1000.0
			if elapsed < best {
				best = elapsed
			}
		}
		return best, threat
	}
	t.Fatalf("cost budgets: workload %s not found in cost_bodies.json", id)
	return 0, false
}
