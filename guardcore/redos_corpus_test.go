package guardcore

// Corpus-driven coverage for the validator: the pattern_safety corpus
// exercises the timed arbiter branches (verdict paths, retries, timeout
// trips, structural overrides) that unit tests cannot reach without the
// hostile patterns. This is the same suite the conformance package runs;
// duplicating it inside guardcore keeps the fail-closed coverage gate
// meaningful for the safety layer.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePatternSafetyCorpus(t *testing.T) {
	path := filepath.Join("..", "conformance", "guard-core-spec-4.1.0", "cases", "safety_gates.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("safety corpus not present outside the repository checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Cases []struct {
			Input struct {
				Pattern          string   `json:"pattern"`
				Mode             string   `json:"mode"`
				TestStrings      []string `json:"test_strings"`
				MaxContentLength int      `json:"max_content_length"`
			} `json:"input"`
			Expected struct {
				Safe        bool   `json:"safe"`
				ReasonClass string `json:"reason_class"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	if len(suite.Cases) == 0 {
		t.Skip("corpus matched zero cases")
	}
	for _, c := range suite.Cases {
		var (
			safe   bool
			reason string
		)
		if c.Input.Mode == "test_strings" {
			safe, reason = ValidatePatternSafetyStrings(c.Input.Pattern, c.Input.TestStrings)
		} else {
			safe, reason = ValidatePatternSafetyCost(c.Input.Pattern, c.Input.MaxContentLength)
		}
		if class := structuralViolationClass(reason); safe != c.Expected.Safe || class != c.Expected.ReasonClass {
			t.Errorf("%s %s: got safe=%v class=%s (%q), want safe=%v class=%s",
				c.Input.Mode, c.Input.Pattern, safe, class, reason, c.Expected.Safe, c.Expected.ReasonClass)
		}
	}
}
