// Pattern translation ledger for spec 4.1.0 (specs/impl/go.md, "Regex
// engine" option 1): every distinct regex pattern firing in the vendored
// corpus (guard-core-spec-4.1.0/cases/, detect suites) appears in exactly
// one RE2 status.
//
// Statuses mirror the Rust sibling (Rust/guard-core-rs/conformance/
// pattern_ledger.toml):
//
//	as_is        compiles unchanged with the stdlib RE2 engine
//	             (regexp.Compile).
//	translated   recorded corpus-verified translation; evidence_cases list
//	             the corpus cases whose recorded (match, position) the
//	             translation reproduces on the raw case input.
//	unmatchable  constructs the RE2 engine rejects; no translation
//	             attempted. Each entry carries the blocking constructs and
//	             a documented detection limit instead of silence.
//
// The shipped engine is the backtracking regexp2 build behind
// guardcore.compileRE (translatePattern already performs the \Z -> \z
// anchor rewrite) with the spec's MatchTimeout, so every corpus pattern
// compiles and matches at runtime. This ledger records the RE2 posture the
// spec's default direction requires: what a pure stdlib-regexp engine
// could compile, what it needs rewritten, and what it would silently
// miss. pattern_ledger_test.go is the referee: it recomputes every status
// from the live corpus and fails when a pattern's status changes
// unexpectedly.
package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// PatternLedgerStatus is the RE2 status of one corpus pattern.
type PatternLedgerStatus string

const (
	// StatusAsIs: the pattern compiles unchanged with stdlib RE2.
	StatusAsIs PatternLedgerStatus = "as_is"
	// StatusTranslated: a recorded translation makes the pattern RE2
	// compilable; verified against the corpus evidence.
	StatusTranslated PatternLedgerStatus = "translated"
	// StatusUnmatchable: RE2 rejects the pattern's constructs; documented
	// detection limits apply.
	StatusUnmatchable PatternLedgerStatus = "unmatchable"
)

// patternStatusOrder pins the ledger's entry ordering (Rust-precedent
// grouping by status, patterns sorted within each group).
var patternStatusOrder = []PatternLedgerStatus{StatusAsIs, StatusTranslated, StatusUnmatchable}

// PatternLedgerEntry is one corpus pattern's RE2 record.
type PatternLedgerEntry struct {
	Pattern  string              `json:"pattern"`
	Category string              `json:"category"`
	Status   PatternLedgerStatus `json:"status"`
	// Translation is the recorded RE2-compilable rewrite (translated only).
	Translation string `json:"translation,omitempty"`
	// Construct names the rewrite performed (translated entries).
	Construct string `json:"construct,omitempty"`
	// Constructs lists the RE2-blocking constructs (unmatchable entries).
	Constructs []string `json:"constructs,omitempty"`
	// EvidenceCases lists corpus case ids ("suite::case") where the
	// pattern fires, sorted.
	EvidenceCases []string `json:"evidence_cases"`
	// VerifiedOn lists the evidence cases whose recorded (match, position)
	// the RE2 form reproduces on the raw case input (translated entries;
	// the corpus is the referee per specs/impl/go.md).
	VerifiedOn []string `json:"verified_on,omitempty"`
	// DetectionLimit documents what an RE2-only engine would silently miss
	// (unmatchable entries).
	DetectionLimit string `json:"detection_limit,omitempty"`
}

// PatternLedger is the generated ledger document (pattern_ledger.json).
type PatternLedger struct {
	SpecVersion     string               `json:"spec_version"`
	Engine          string               `json:"engine"`
	HowToRegenerate string               `json:"how_to_regenerate"`
	Counts          map[string]int       `json:"counts"`
	Entries         []PatternLedgerEntry `json:"entries"`
}

// ledgerObservation is one corpus threat sighting of a pattern.
type ledgerObservation struct {
	suite    string
	caseID   string
	content  string
	match    string
	position int
}

// ledgerPatternAccumulator folds the observations of one distinct pattern.
type ledgerPatternAccumulator struct {
	category string
	evidence map[string]bool
	// firstSeen holds one observation per sighting, in corpus order.
	firstSeen []ledgerObservation
}

// corpusCasesDir is the vendored corpus mounted next to this package.
const corpusCasesDir = "guard-core-spec-4.1.0/cases"

// patternLedgerFile is the checked-in generated ledger.
const patternLedgerFile = "pattern_ledger.json"

// ledgerCaseFile mirrors the detect-suite JSON schema (the package's
// conformance_test.go loader types live behind the test build tag, so this
// file carries its own shapes).
type ledgerCaseFile struct {
	Suite string       `json:"suite"`
	Kind  string       `json:"kind"`
	Cases []ledgerCase `json:"cases"`
}

type ledgerCase struct {
	ID    string `json:"id"`
	Input struct {
		Content string `json:"content"`
		Context string `json:"context"`
	} `json:"input"`
	Expected struct {
		Threats []json.RawMessage `json:"threats"`
	} `json:"expected"`
}

// collectCorpusPatternEvidence walks the detect suites of the vendored
// corpus and folds every threat sighting by pattern source. The pipeline_*
// suites have a different schema and do not carry detect threats.
func collectCorpusPatternEvidence(casesDir string) (map[string]*ledgerPatternAccumulator, int, error) {
	files, err := filepath.Glob(filepath.Join(casesDir, "*.json"))
	if err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("corpus glob matched zero files in %s: a vacuous ledger is a failure", casesDir)
	}
	sort.Strings(files)
	seen := map[string]*ledgerPatternAccumulator{}
	total := 0
	for _, f := range files {
		if strings.HasSuffix(f, "index.json") {
			continue
		}
		if strings.HasPrefix(filepath.Base(f), "pipeline_") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, 0, err
		}
		var cf ledgerCaseFile
		if err := json.Unmarshal(data, &cf); err != nil {
			return nil, 0, fmt.Errorf("%s: %w", f, err)
		}
		if cf.Kind != "detect" {
			continue
		}
		for _, c := range cf.Cases {
			for _, raw := range c.Expected.Threats {
				var threat struct {
					Pattern  string  `json:"pattern"`
					Category string  `json:"category"`
					Match    string  `json:"match"`
					Position float64 `json:"position"`
				}
				if err := json.Unmarshal(raw, &threat); err != nil || threat.Pattern == "" {
					continue
				}
				pattern := threat.Pattern
				category := threat.Category
				match := threat.Match
				position := threat.Position
				acc := seen[pattern]
				if acc == nil {
					acc = &ledgerPatternAccumulator{evidence: map[string]bool{}}
					seen[pattern] = acc
				}
				if acc.category == "" {
					acc.category = category
				}
				caseID := cf.Suite + "::" + c.ID
				acc.evidence[caseID] = true
				acc.firstSeen = append(acc.firstSeen, ledgerObservation{
					suite:    cf.Suite,
					caseID:   caseID,
					content:  c.Input.Content,
					match:    match,
					position: int(position),
				})
				total++
			}
		}
	}
	return seen, total, nil
}

// translatePatternZ is the one mechanical RE2 rewrite the corpus needs:
// Python's absolute end-of-string anchor \Z does not exist in RE2; \z is
// the RE2 spelling with identical semantics (end of text, not end of
// line). guardcore.translatePattern applies the same rewrite for the
// runtime engine. The escape is only rewritten when not itself escaped
// (the preceding byte is not a backslash), mirroring translatePattern.
func translatePatternZ(src string) (string, bool) {
	if !strings.Contains(src, `\Z`) {
		return src, false
	}
	var b strings.Builder
	changed := false
	for i := 0; i < len(src); i++ {
		if i+1 < len(src) && src[i] == '\\' && src[i+1] == 'Z' && (i == 0 || src[i-1] != '\\') {
			b.WriteString(`\z`)
			i++
			changed = true
			continue
		}
		b.WriteByte(src[i])
	}
	return b.String(), changed
}

// re2BlockingConstructs reports the PCRE constructs the pattern uses that
// the RE2 engine rejects, in first-appearance order. Backreference and
// lookaround probes share one scanner pass; the nested-repeat case has no
// syntactic marker and is attributed from the compile error.
func re2BlockingConstructs(pattern string) []string {
	var constructs []string
	probes := []struct {
		marker string
		name   string
	}{
		{"(?=", "positive lookahead (?=...)"},
		{"(?!", "negative lookahead (?!...)"},
		{"(?<=", "positive lookbehind (?<=...)"},
		{"(?<!", "negative lookbehind (?<!...)"},
	}
	// Longest markers first so (?<= is not shadowed by (?!.
	sort.Slice(probes, func(i, j int) bool { return len(probes[i].marker) > len(probes[j].marker) })
	found := map[string]bool{}
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '\\' {
			// Escaped constructs (\(? \) \1 literals) and backreferences
			// both start here; a backslash-digit pair is a backreference.
			if i+1 < len(pattern) && pattern[i+1] >= '1' && pattern[i+1] <= '9' {
				name := fmt.Sprintf("backreference (\\%c)", pattern[i+1])
				if !found[name] {
					found[name] = true
					constructs = append(constructs, name)
				}
			}
			i++
			continue
		}
		if pattern[i] != '(' || i+1 >= len(pattern) || pattern[i+1] != '?' {
			continue
		}
		for _, probe := range probes {
			if strings.HasPrefix(pattern[i:], probe.marker) && !found[probe.name] {
				found[probe.name] = true
				constructs = append(constructs, probe.name)
			}
		}
	}
	return constructs
}

// classifyRE2 computes a corpus pattern's RE2 status: as_is when stdlib
// regexp compiles it unchanged, translated when the recorded \Z rewrite
// alone makes it compile, unmatchable otherwise (with the blocking
// constructs and the compile error category). The returned regexp is the
// compiled RE2 form for as_is/translated entries (nil for unmatchable).
func classifyRE2(pattern string) (PatternLedgerStatus, string, string, []string, *regexp.Regexp) {
	if re, err := regexp.Compile(pattern); err == nil {
		return StatusAsIs, "", "", nil, re
	}
	if translated, changed := translatePatternZ(pattern); changed {
		if re, err := regexp.Compile(translated); err == nil {
			return StatusTranslated, translated, `\Z (Python absolute end anchor) -> \z`, nil, re
		}
	}
	constructs := re2BlockingConstructs(pattern)
	if len(constructs) == 0 {
		// No syntactic lookaround/backreference marker: attribute the
		// failure from the compile error (nested-repeat size limits are
		// the observed case in the 4.1.0 corpus).
		_, err := regexp.Compile(pattern)
		constructs = []string{fmt.Sprintf("repeat-size limit (RE2 rejects: %v)", err)}
	}
	return StatusUnmatchable, "", "", constructs, nil
}

// detectionLimitFor documents what an RE2-only engine would silently miss
// for an unmatchable pattern. The shipped engine compiles every corpus
// pattern (regexp2 behind guardcore.compileRE); the limit records the
// RE2-only posture, not a shipped gap.
func detectionLimitFor(constructs []string) string {
	return fmt.Sprintf(
		"RE2 cannot compile this pattern (%s): an RE2-only engine would not run it and matches depending on those constructs (the listed evidence cases) would go undetected there. The shipped engine compiles it via regexp2 with the spec MatchTimeout; this entry documents the RE2 posture of specs/impl/go.md option 1, not a shipped detection gap.",
		strings.Join(constructs, ", "),
	)
}

// verifyTranslationEvidence answers whether the compiled RE2 form of a
// translated pattern reproduces one corpus-recorded sighting on the raw
// case input: the scan must surface exactly the recorded match text at the
// recorded code-point position.
func verifyTranslationEvidence(re *regexp.Regexp, content, wantMatch string, wantPosition int) bool {
	if wantPosition < 0 || wantPosition > len([]rune(content)) {
		return false
	}
	for _, pair := range re.FindAllStringIndex(content, -1) {
		// FindAllStringIndex reports byte offsets; the corpus records
		// code-point positions, so convert the start offset.
		if utf8.RuneCountInString(content[:pair[0]]) == wantPosition && content[pair[0]:pair[1]] == wantMatch {
			return true
		}
	}
	return false
}

// buildPatternLedger generates the ledger document from the live corpus.
func buildPatternLedger(casesDir string) (*PatternLedger, error) {
	seen, _, err := collectCorpusPatternEvidence(casesDir)
	if err != nil {
		return nil, err
	}
	patterns := make([]string, 0, len(seen))
	for pattern := range seen {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	ledger := &PatternLedger{
		SpecVersion:     corpusSpecVersion,
		Engine:          ledgerEngineNote,
		HowToRegenerate: ledgerRegenerateHint,
		Counts:          map[string]int{},
		Entries:         []PatternLedgerEntry{},
	}
	byStatus := map[PatternLedgerStatus][]PatternLedgerEntry{}
	for _, pattern := range patterns {
		acc := seen[pattern]
		status, translation, construct, constructs, re := classifyRE2(pattern)
		entry := PatternLedgerEntry{
			Pattern:       pattern,
			Category:      acc.category,
			Status:        status,
			Translation:   translation,
			Construct:     construct,
			Constructs:    constructs,
			EvidenceCases: sortedKeys(acc.evidence),
		}
		if status == StatusUnmatchable {
			entry.DetectionLimit = detectionLimitFor(constructs)
		}
		if status == StatusTranslated {
			// The corpus is the referee: the recorded translation must
			// reproduce the recorded (match, position) on at least the raw
			// inputs of the firing cases; sightings on preprocessed
			// surfaces stay in evidence_cases unverified. classifyRE2
			// guarantees re is the compiled translation here.
			for _, obs := range acc.firstSeen {
				if verifyTranslationEvidence(re, obs.content, obs.match, obs.position) {
					entry.VerifiedOn = append(entry.VerifiedOn, obs.caseID)
				}
			}
			if len(entry.VerifiedOn) == 0 {
				return nil, fmt.Errorf("translated pattern %.60s: no corpus evidence reproduced on raw inputs: refusing to record an unverified translation", pattern)
			}
			entry.VerifiedOn = dedupSorted(entry.VerifiedOn)
		}
		byStatus[status] = append(byStatus[status], entry)
		ledger.Counts[string(status)]++
	}
	ledger.Counts["total"] = len(patterns)
	for _, status := range patternStatusOrder {
		ledger.Entries = append(ledger.Entries, byStatus[status]...)
	}
	if len(ledger.Entries) == 0 {
		return nil, errors.New("pattern ledger generated zero entries from a non-empty corpus: refusing to write a vacuous ledger")
	}
	return ledger, nil
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func dedupSorted(values []string) []string {
	sort.Strings(values)
	out := make([]string, 0, len(values))
	for i, v := range values {
		if i == 0 || v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

const (
	corpusSpecVersion    = "4.1.0"
	ledgerEngineNote     = "shipped engine: regexp2 v1.12.0 behind guardcore.compileRE (translatePattern rewrites \\Z to \\z) with the spec MatchTimeout; this ledger records the stdlib RE2 (regexp.Compile) posture of specs/impl/go.md option 1"
	ledgerRegenerateHint = "go test ./conformance -run TestPatternLedger -update"
)
