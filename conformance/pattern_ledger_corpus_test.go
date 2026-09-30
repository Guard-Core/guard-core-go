package conformance

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestDedupSorted unit-tests the evidence-case dedup used at generation.
func TestDedupSorted(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, []string{}},
		{"already unique", []string{"b", "a"}, []string{"a", "b"}},
		{"duplicates", []string{"sqli::a", "sqli::a", "sqli::b", "sqli::a"}, []string{"sqli::a", "sqli::b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupSorted(append([]string(nil), tt.in...))
			if len(got) != len(tt.want) {
				t.Fatalf("dedupSorted(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("dedupSorted(%v) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}

// writeSyntheticCorpus lays out a minimal detect-suite corpus in a temp
// dir so the loader and generator error paths are exercised without
// touching the vendored 4.1.0 corpus.
func writeSyntheticCorpus(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The synthetic suite fires one \Z-anchored pattern whose RE2 status is
// translated and whose single sighting verifies on the raw input.
const syntheticSuiteJSON = `{
  "suite": "synthetic",
  "kind": "detect",
  "cases": [
    {
      "id": "anchor_case",
      "input": {"content": "evil.py", "context": "url_path"},
      "expected": {
        "is_threat": true,
        "threats": [
          {"type": "regex", "pattern": "evil\\.py\\Z", "match": "evil.py", "position": 0, "category": "sensitive_file", "weight": 1.0}
        ]
      }
    }
  ]
}`

// TestCollectCorpusPatternEvidenceErrors pins the loader's failure modes:
// an empty corpus dir and a corrupt suite file are hard errors, while
// non-detect suites and malformed threats are skipped, not fatal.
func TestCollectCorpusPatternEvidenceErrors(t *testing.T) {
	t.Run("empty dir", func(t *testing.T) {
		dir := writeSyntheticCorpus(t, map[string]string{})
		if _, _, err := collectCorpusPatternEvidence(dir); err == nil {
			t.Fatal("empty corpus dir must error: a vacuous ledger is a failure")
		}
	})
	t.Run("corrupt file", func(t *testing.T) {
		dir := writeSyntheticCorpus(t, map[string]string{"broken.json": "{not json"})
		if _, _, err := collectCorpusPatternEvidence(dir); err == nil {
			t.Fatal("corrupt suite file must error")
		}
	})
	t.Run("non-detect and malformed sightings are skipped", func(t *testing.T) {
		dir := writeSyntheticCorpus(t, map[string]string{
			"index.json":      `{"spec_version": "4.1.0"}`,
			"pipeline_x.json": `{"suite": "pipeline_x", "kind": "pipeline", "cases": []}`,
			"synthetic.json":  syntheticSuiteJSON,
			"odd.json": `{
				"suite": "odd", "kind": "detect",
				"cases": [
					{"id": "no_threats", "input": {"content": "x"}, "expected": {"is_threat": false, "threats": []}},
					{"id": "bad_threat", "input": {"content": "x"}, "expected": {"threats": ["not-an-object"]}},
					{"id": "empty_pattern", "input": {"content": "x"}, "expected": {"threats": [{"pattern": "", "category": "xss"}]}}
				]
			}`,
		})
		observed, sightings, err := collectCorpusPatternEvidence(dir)
		if err != nil {
			t.Fatalf("synthetic corpus must load: %v", err)
		}
		if len(observed) != 1 || sightings != 1 {
			t.Fatalf("expected exactly the synthetic anchor pattern sighted once, got %d patterns / %d sightings", len(observed), sightings)
		}
	})
}

// TestBuildPatternLedgerSynthetic drives the generator over the synthetic
// corpus end to end: the \Z-anchored pattern lands in the translated group
// with corpus-verified evidence, and a corpus with no detect threats
// refuses to produce a vacuous ledger.
func TestBuildPatternLedgerSynthetic(t *testing.T) {
	t.Run("translated entry verifies", func(t *testing.T) {
		dir := writeSyntheticCorpus(t, map[string]string{"synthetic.json": syntheticSuiteJSON})
		ledger, err := buildPatternLedger(dir)
		if err != nil {
			t.Fatalf("build ledger: %v", err)
		}
		if len(ledger.Entries) != 1 || ledger.Entries[0].Status != StatusTranslated {
			t.Fatalf("expected one translated entry, got %+v", ledger.Entries)
		}
		entry := ledger.Entries[0]
		if entry.Translation == "" || entry.Construct == "" {
			t.Fatalf("translated entry must record the translation and construct: %+v", entry)
		}
		if len(entry.VerifiedOn) != 1 || entry.VerifiedOn[0] != "synthetic::anchor_case" {
			t.Fatalf("entry must cite the synthetic evidence case as verified: %+v", entry.VerifiedOn)
		}
		if ledger.Counts["total"] != 1 || ledger.Counts["translated"] != 1 {
			t.Fatalf("counts block must reflect the entries: %+v", ledger.Counts)
		}
	})
	t.Run("vacuous corpus refuses", func(t *testing.T) {
		dir := writeSyntheticCorpus(t, map[string]string{
			"index.json":         `{"spec_version": "4.1.0"}`,
			"only_pipeline.json": `{"suite": "only_pipeline", "kind": "pipeline", "cases": []}`,
		})
		if _, err := buildPatternLedger(dir); err == nil {
			t.Fatal("a corpus with zero detect threats must refuse to generate a ledger")
		}
	})
}

// TestVerifyTranslationEvidenceEdges pins the matcher's boundary behavior:
// negative and out-of-range positions never verify.
func TestVerifyTranslationEvidenceEdges(t *testing.T) {
	re := regexp.MustCompile(`evil\.py\z`)
	if !verifyTranslationEvidence(re, "evil.py", "evil.py", 0) {
		t.Fatal("exact reproduction must verify")
	}
	if verifyTranslationEvidence(re, "evil.py", "evil.py", -1) {
		t.Fatal("negative position must not verify")
	}
	if verifyTranslationEvidence(re, "evil.py", "evil.py", 99) {
		t.Fatal("out-of-range position must not verify")
	}
	if verifyTranslationEvidence(re, "no match here", "evil.py", 0) {
		t.Fatal("absent match must not verify")
	}
}

// TestCollectCorpusGlobError pins the malformed-glob failure mode.
func TestCollectCorpusGlobError(t *testing.T) {
	if _, _, err := collectCorpusPatternEvidence("["); err == nil {
		t.Fatal("a malformed glob path must error, not return an empty ledger")
	}
}

// TestCollectCorpusUnreadableFile pins the read-failure path via a
// dangling symlink that matches the suite glob.
func TestCollectCorpusUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "missing-target.json"), filepath.Join(dir, "dangling.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := collectCorpusPatternEvidence(dir); err == nil {
		t.Fatal("an unreadable suite file must error")
	}
}

// TestBuildPatternLedgerPropagatesLoaderErrors pins that the generator
// surfaces corpus loader failures instead of emitting an empty ledger.
func TestBuildPatternLedgerPropagatesLoaderErrors(t *testing.T) {
	if _, err := buildPatternLedger("["); err == nil {
		t.Fatal("buildPatternLedger must propagate the corpus loader error")
	}
}

// TestBuildPatternLedgerRejectsUnverifiedTranslation pins the referee
// contract at generation time: a translated pattern whose recorded
// evidence never reproduces on the raw inputs is refused, not recorded.
func TestBuildPatternLedgerRejectsUnverifiedTranslation(t *testing.T) {
	dir := writeSyntheticCorpus(t, map[string]string{
		"unverifiable.json": `{
			"suite": "unverifiable", "kind": "detect",
			"cases": [{
				"id": "phantom",
				"input": {"content": "totally different", "context": "url_path"},
				"expected": {"is_threat": true, "threats": [
					{"type": "regex", "pattern": "missing\\.py\\Z", "match": "missing.py", "position": 0, "category": "sensitive_file", "weight": 1.0}
				]}
			}]
		}`,
	})
	_, err := buildPatternLedger(dir)
	if err == nil {
		t.Fatal("an unverified translation must be refused")
	}
	if !regexp.MustCompile(`no corpus evidence reproduced`).MatchString(err.Error()) {
		t.Fatalf("unexpected refusal reason: %v", err)
	}
}
