package conformance

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

type caseFile struct {
	Suite string            `json:"suite"`
	Kind  string            `json:"kind"`
	Cases []conformanceCase `json:"cases"`
}

type conformanceCase struct {
	ID    string `json:"id"`
	Input struct {
		Content string `json:"content"`
		Context string `json:"context"`
	} `json:"input"`
	Expected struct {
		IsThreat        bool    `json:"is_threat"`
		ThreatScore     float64 `json:"threat_score"`
		Threats         []any   `json:"threats"`
		OriginalLength  int     `json:"original_length"`
		ProcessedLength int     `json:"processed_length"`
		DetectionMethod string  `json:"detection_method"`
	} `json:"expected"`
}

func canonicalize(v any) any {
	switch x := v.(type) {
	case float64:
		return round6(x)
	case map[string]any:
		out := map[string]any{}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		for _, k := range keys {
			if k == "execution_time" {
				continue
			}
			out[k] = canonicalize(x[k])
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, canonicalize(item))
		}
		return out
	}
	return v
}

func round6(f float64) float64 {
	return math.Round(f*1e6) / 1e6
}

func threatKey(v map[string]any) string {
	var b strings.Builder
	for _, k := range []string{"category", "pattern", "position", "type", "match", "weight", "attack_type", "probability", "threat_score", "analysis"} {
		if val, ok := v[k]; ok {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(fmt.Sprint(canonicalize(val)))
			b.WriteByte('|')
		}
	}
	return b.String()
}

func multisetEqual(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	am := map[string]int{}
	bm := map[string]int{}
	for _, item := range a {
		m, ok := item.(map[string]any)
		if !ok {
			return false
		}
		am[threatKey(m)]++
	}
	for _, item := range b {
		m, ok := item.(map[string]any)
		if !ok {
			return false
		}
		bm[threatKey(m)]++
	}
	for k, v := range am {
		if bm[k] != v {
			return false
		}
	}
	return true
}

func resultToAny(r guardcore.DetectResult) map[string]any {
	threats := make([]any, 0, len(r.Threats))
	for _, t := range r.Threats {
		threats = append(threats, canonicalize(t))
	}
	return map[string]any{
		"is_threat":        r.IsThreat,
		"threat_score":     round6(r.ThreatScore),
		"threats":          threats,
		"original_length":  r.OriginalLength,
		"processed_length": r.ProcessedLength,
		"detection_method": r.DetectionMethod,
	}
}

func diffs(got, want map[string]any) []string {
	var out []string
	if got["is_threat"] != want["is_threat"] {
		out = append(out, fmt.Sprintf("is_threat: got %v want %v", got["is_threat"], want["is_threat"]))
	}
	if got["threat_score"] != want["threat_score"] {
		out = append(out, fmt.Sprintf("threat_score: got %v want %v", got["threat_score"], want["threat_score"]))
	}
	if got["original_length"] != want["original_length"] {
		out = append(out, fmt.Sprintf("original_length: got %v want %v", got["original_length"], want["original_length"]))
	}
	if got["processed_length"] != want["processed_length"] {
		out = append(out, fmt.Sprintf("processed_length: got %v want %v", got["processed_length"], want["processed_length"]))
	}
	if got["detection_method"] != want["detection_method"] {
		out = append(out, fmt.Sprintf("detection_method: got %v want %v", got["detection_method"], want["detection_method"]))
	}
	gt := got["threats"].([]any)
	wt := want["threats"].([]any)
	if !multisetEqual(gt, wt) {
		out = append(out, fmt.Sprintf("threats: got %s want %s", summarize(gt), summarize(wt)))
	}
	return out
}

func summarize(list []any) string {
	var parts []string
	for _, item := range list {
		m := item.(map[string]any)
		parts = append(parts, fmt.Sprintf("%v|%v@%v", m["category"], shortPattern(m["pattern"]), m["position"]))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

func shortPattern(p any) string {
	s := fmt.Sprint(p)
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

func TestConformance(t *testing.T) {
	files, err := filepath.Glob("guard-core-spec-4.1.0/cases/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("conformance corpus glob matched zero files: expected guard-core-spec-4.1.0/cases/*.json; a vacuous pass is a failure")
	}
	sort.Strings(files)
	t.Logf("conformance corpus: %d files matched in guard-core-spec-4.1.0/cases", len(files))
	total, failed, skipped := 0, 0, 0
	caseFiles := 0
	var failures []string
	for _, f := range files {
		if strings.HasSuffix(f, "index.json") {
			continue
		}
		if strings.HasPrefix(filepath.Base(f), "pipeline_") {
			// Pipeline-kind suites have a different schema and are
			// replayed by pipeline_test.go.
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var cf caseFile
		if err := json.Unmarshal(data, &cf); err != nil {
			t.Fatal(err)
		}
		if cf.Kind != "detect" {
			// Pipeline-kind suites are replayed by pipeline_test.go.
			continue
		}
		caseFiles++
		for _, c := range cf.Cases {
			total++
			c := c
			result := guardcore.Detect(c.Input.Content, "203.0.113.7", c.Input.Context)
			got := resultToAny(result)
			want := map[string]any{
				"is_threat":        c.Expected.IsThreat,
				"threat_score":     round6(c.Expected.ThreatScore),
				"threats":          canonicalize(c.Expected.Threats),
				"original_length":  c.Expected.OriginalLength,
				"processed_length": c.Expected.ProcessedLength,
				"detection_method": c.Expected.DetectionMethod,
			}
			if d := diffs(got, want); len(d) > 0 {
				failed++
				failures = append(failures, fmt.Sprintf("%s/%s:\n  %s", cf.Suite, c.ID, strings.Join(prefixAll(d, "  "), "\n  ")))
			}
		}
	}
	for _, f := range failures {
		t.Errorf("%s", f)
	}
	t.Logf("conformance corpus: %d detect case files loaded, %d cases from guard-core-spec-4.1.0", caseFiles, total)
	t.Logf("conformance: %d/%d passed, %d failed, %d skipped", total-failed-skipped, total, failed, skipped)
}

func prefixAll(list []string, p string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, p+s)
	}
	return out
}
