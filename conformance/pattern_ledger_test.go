package conformance

import (
	"encoding/json"
	"flag"
	"os"
	"regexp"
	"strings"
	"testing"
)

// updateLedger is set by `go test ./conformance -run TestPatternLedger
// -update`: regenerate pattern_ledger.json from the live corpus instead of
// checking it. Deliberate maintenance action, never a CI path.
var updateLedger = flag.Bool("update", false, "regenerate conformance/pattern_ledger.json from the live corpus")

func loadLedger(t *testing.T) *PatternLedger {
	t.Helper()
	data, err := os.ReadFile(patternLedgerFile)
	if err != nil {
		t.Fatalf("read %s: %v (generate it with %s)", patternLedgerFile, err, ledgerRegenerateHint)
	}
	var ledger PatternLedger
	if err := json.Unmarshal(data, &ledger); err != nil {
		t.Fatalf("decode %s: %v", patternLedgerFile, err)
	}
	return &ledger
}

// corpusEvidenceIndex maps pattern -> "suite::case" -> the recorded raw
// input sighting of that pattern in that case. A case can fire several
// patterns, so the index is keyed per pattern, not per case alone.
func corpusEvidenceIndex(t *testing.T) map[string]map[string]ledgerObservation {
	t.Helper()
	observed, _, err := collectCorpusPatternEvidence(corpusCasesDir)
	if err != nil {
		t.Fatalf("collect corpus evidence: %v", err)
	}
	index := map[string]map[string]ledgerObservation{}
	for pattern, acc := range observed {
		perPattern := map[string]ledgerObservation{}
		for _, obs := range acc.firstSeen {
			if _, seen := perPattern[obs.caseID]; !seen {
				perPattern[obs.caseID] = obs
			}
		}
		index[pattern] = perPattern
	}
	return index
}

// TestPatternLedger is the referee required by specs/impl/go.md option 1:
// the ledger must enumerate every distinct corpus pattern exactly once
// with the RE2 status the live stdlib engine computes, and every
// translated entry must still reproduce its corpus evidence.
func TestPatternLedger(t *testing.T) {
	generated, err := buildPatternLedger(corpusCasesDir)
	if err != nil {
		t.Fatalf("regenerate ledger from corpus: %v", err)
	}
	if *updateLedger {
		out, err := json.MarshalIndent(generated, "", "  ")
		if err != nil {
			t.Fatalf("encode ledger: %v", err)
		}
		if err := os.WriteFile(patternLedgerFile, append(out, '\n'), 0o644); err != nil {
			t.Fatalf("write %s: %v", patternLedgerFile, err)
		}
		t.Logf("regenerated %s: %d entries", patternLedgerFile, len(generated.Entries))
		return
	}
	ledger := loadLedger(t)
	if ledger.SpecVersion != corpusSpecVersion {
		t.Fatalf("ledger spec_version %q, corpus is %s", ledger.SpecVersion, corpusSpecVersion)
	}

	observed, totalSightings, err := collectCorpusPatternEvidence(corpusCasesDir)
	if err != nil {
		t.Fatalf("collect corpus pattern evidence: %v", err)
	}
	if len(observed) == 0 || totalSightings == 0 {
		t.Fatal("corpus evidence collection is empty: a vacuous ledger pass is a failure")
	}

	recorded := map[string]*PatternLedgerEntry{}
	for i := range ledger.Entries {
		entry := &ledger.Entries[i]
		if prev, dup := recorded[entry.Pattern]; dup {
			t.Errorf("pattern appears in more than one ledger entry (statuses %s and %s): every corpus pattern appears in exactly one state", prev.Status, entry.Status)
			continue
		}
		recorded[entry.Pattern] = entry
	}

	if len(generated.Entries) != len(ledger.Entries) {
		t.Errorf("ledger entry count %d, live corpus implies %d: regenerate with %s", len(ledger.Entries), len(generated.Entries), ledgerRegenerateHint)
	}
	generatedMap := map[string]PatternLedgerEntry{}
	for _, entry := range generated.Entries {
		generatedMap[entry.Pattern] = entry
	}

	for pattern, acc := range observed {
		entry, ok := recorded[pattern]
		if !ok {
			t.Errorf("corpus pattern missing from the ledger: %.80s (category %s): regenerate with %s", pattern, acc.category, ledgerRegenerateHint)
			continue
		}
		want, ok := generatedMap[pattern]
		if !ok {
			t.Errorf("pattern %.80s is recorded in the ledger but the live corpus classification failed to derive it", pattern)
			continue
		}
		if entry.Status != want.Status {
			t.Errorf("pattern %.80s: ledger status %q but live RE2 classification is %q: a pattern's status changed: regenerate with %s", pattern, entry.Status, want.Status, ledgerRegenerateHint)
			continue
		}
		if entry.Translation != want.Translation || entry.Construct != want.Construct {
			t.Errorf("pattern %.80s: recorded translation/construct drifted from the live derivation: regenerate with %s", pattern, ledgerRegenerateHint)
		}
		if got, wantCount := len(entry.EvidenceCases), len(acc.evidence); got != wantCount {
			t.Errorf("pattern %.80s: ledger lists %d evidence cases, corpus has %d: regenerate with %s", pattern, got, wantCount, ledgerRegenerateHint)
		}
		if want.Status == StatusUnmatchable && entry.DetectionLimit == "" {
			t.Errorf("pattern %.80s: unmatchable entries must carry a documented detection limit, not silence", pattern)
		}
	}

	for _, entry := range ledger.Entries {
		if _, ok := observed[entry.Pattern]; !ok {
			t.Errorf("ledger entry for pattern %.80s matches no corpus threat: a stale entry (status %s): regenerate with %s", entry.Pattern, entry.Status, ledgerRegenerateHint)
		}
	}

	// Counts block must agree with the entries.
	counts := map[string]int{}
	for _, entry := range ledger.Entries {
		counts[string(entry.Status)]++
	}
	counts["total"] = len(ledger.Entries)
	for key, want := range counts {
		if ledger.Counts[key] != want {
			t.Errorf("ledger counts[%q]=%d, entries imply %d", key, ledger.Counts[key], want)
		}
	}

	// The 4.1.0 corpus must keep its full status spread (46 as_is, 3
	// translated, 22 unmatchable, 71 distinct). A change here is a
	// spec-level event and must fail the build until the ledger is
	// regenerated deliberately.
	wantCounts := map[string]int{"as_is": 46, "translated": 3, "unmatchable": 22}
	for status, want := range wantCounts {
		if got := ledger.Counts[status]; got != want {
			t.Errorf("ledger counts[%q]=%d, spec %s corpus implies %d: a pattern's RE2 status changed: regenerate with %s", status, got, corpusSpecVersion, want, ledgerRegenerateHint)
		}
	}
	if len(ledger.Entries) != 71 {
		t.Errorf("ledger holds %d entries, spec %s corpus fires 71 distinct patterns", len(ledger.Entries), corpusSpecVersion)
	}

	// Every as_is entry compiles unchanged right now; every translated
	// entry's translation compiles, the raw pattern no longer does, and the
	// recorded verified_on cases reproduce on the raw case inputs (the
	// corpus is the referee).
	evidence := corpusEvidenceIndex(t)
	for i := range ledger.Entries {
		entry := &ledger.Entries[i]
		switch entry.Status {
		case StatusAsIs:
			if _, err := regexp.Compile(entry.Pattern); err != nil {
				t.Errorf("as_is entry %.60s no longer compiles with stdlib RE2: %v (status changed: regenerate with %s)", entry.Pattern, err, ledgerRegenerateHint)
			}
		case StatusTranslated:
			re, err := regexp.Compile(entry.Translation)
			if err != nil {
				t.Errorf("translated entry %.60s: recorded translation does not compile with stdlib RE2: %v", entry.Pattern, err)
				continue
			}
			if _, rawErr := regexp.Compile(entry.Pattern); rawErr == nil {
				t.Errorf("translated entry %.60s now compiles unchanged: status changed, regenerate with %s", entry.Pattern, ledgerRegenerateHint)
			}
			if len(entry.VerifiedOn) == 0 {
				t.Errorf("translated entry %.60s carries no verified_on cases: an unverified translation must not ship", entry.Pattern)
				continue
			}
			for _, caseID := range entry.VerifiedOn {
				obs, ok := evidence[entry.Pattern][caseID]
				if !ok {
					t.Errorf("translated entry %.60s cites unknown corpus case %s", entry.Pattern, caseID)
					continue
				}
				if !verifyTranslationEvidence(re, obs.content, obs.match, obs.position) {
					t.Errorf("translated entry %.60s fails corpus verification on %s: recorded (match, position) no longer reproduces", entry.Pattern, caseID)
				}
			}
		case StatusUnmatchable:
			if _, err := regexp.Compile(entry.Pattern); err == nil {
				t.Errorf("unmatchable entry %.60s now compiles with stdlib RE2: status changed, regenerate with %s", entry.Pattern, ledgerRegenerateHint)
			}
			if len(entry.Constructs) == 0 {
				t.Errorf("unmatchable entry %.60s records no blocking constructs", entry.Pattern)
			}
			if entry.VerifiedOn != nil {
				t.Errorf("unmatchable entry %.60s must not carry verified_on cases", entry.Pattern)
			}
		}
	}
}

// TestPatternLedgerTranslatedEvidenceIsNonVacuous pins that the ledger's
// verification actually runs against real corpus cases: a refactoring that
// empties the evidence index or the translated group must fail, not pass
// silently.
func TestPatternLedgerTranslatedEvidenceIsNonVacuous(t *testing.T) {
	ledger := loadLedger(t)
	evidence := corpusEvidenceIndex(t)
	translated, cited := 0, 0
	for _, entry := range ledger.Entries {
		if entry.Status == StatusTranslated {
			translated++
			cited += len(entry.VerifiedOn)
			if evidence[entry.Pattern] == nil {
				t.Errorf("translated entry %.60s has no per-pattern evidence index", entry.Pattern)
			}
		}
	}
	if translated == 0 || cited == 0 {
		t.Fatalf("translated group holds %d entries citing %d verified cases: a vacuous ledger pass is a failure", translated, cited)
	}
	if len(evidence) == 0 {
		t.Fatal("corpus evidence index is empty: the ledger referee cannot verify anything")
	}
}

// TestClassifyRE2 unit-tests the classifier's decision boundaries with
// synthetic patterns so the corpus referee does not stand in for the
// classification logic itself.
func TestClassifyRE2(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		wantStatus PatternLedgerStatus
	}{
		{"plain literal", `abc`, StatusAsIs},
		{"anchors and classes", `\A(?:foo|bar)+[\s\S]*?baz\b`, StatusAsIs},
		{"absolute end anchor", `foo\s*\Z`, StatusTranslated},
		{"negative lookahead", `foo(?!bar)`, StatusUnmatchable},
		{"positive lookahead", `foo(?=bar)`, StatusUnmatchable},
		{"negative lookbehind", `(?<!x)foo`, StatusUnmatchable},
		{"positive lookbehind", `(?<=x)foo`, StatusUnmatchable},
		{"backreference", `(foo)\1`, StatusUnmatchable},
		{"lookahead with anchor", `\A(?:(?!\n).)*\s*\Z`, StatusUnmatchable},
		{"nested repeat overflow", `(?:[a-z]{0,100}){0,20}`, StatusUnmatchable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _, _, constructs, re := classifyRE2(tt.pattern)
			if status != tt.wantStatus {
				t.Fatalf("classifyRE2(%q) = %s, want %s", tt.pattern, status, tt.wantStatus)
			}
			if status == StatusUnmatchable && len(constructs) == 0 {
				t.Fatalf("unmatchable classification of %q carries no constructs", tt.pattern)
			}
			if status != StatusUnmatchable && re == nil {
				t.Fatalf("classification %s of %q must return the compiled RE2 form", status, tt.pattern)
			}
		})
	}
}

// TestTranslatePatternZ mirrors guardcore.translatePattern's contract: the
// unescaped \Z anchor is rewritten, escaped spellings are left alone.
func TestTranslatePatternZ(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		changed bool
	}{
		{`abc`, `abc`, false},
		{`foo\Z`, `foo\z`, true},
		{`\Zfoo`, `\zfoo`, true},
		{`foo\\Z`, `foo\\Z`, false},
		{`\Z\Z`, `\z\z`, true},
		{`a\Zb\Zc`, `a\zb\zc`, true},
	}
	for _, tt := range tests {
		got, changed := translatePatternZ(tt.in)
		if got != tt.want || changed != tt.changed {
			t.Errorf("translatePatternZ(%q) = (%q, %v), want (%q, %v)", tt.in, got, changed, tt.want, tt.changed)
		}
	}
}

// TestDetectionLimitDocumentsConstructs pins the honesty contract: every
// generated detection limit names its blocking constructs.
func TestDetectionLimitDocumentsConstructs(t *testing.T) {
	got := detectionLimitFor([]string{"negative lookahead (?!...)", "backreference (\\1)"})
	for _, want := range []string{"negative lookahead (?!...)", "backreference (\\1)", "RE2"} {
		if !strings.Contains(got, want) {
			t.Errorf("detection limit %.120s does not mention %q", got, want)
		}
	}
}
