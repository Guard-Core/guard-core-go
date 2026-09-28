package guardcore

import "sort"

type DetectResult struct {
	IsThreat        bool
	ThreatScore     float64
	Threats         []map[string]any
	OriginalLength  int
	ProcessedLength int
	DetectionMethod string
}

var decodeBudgetExhaustedPattern = "decode_budget_exhausted"

func decodeBudgetExhaustedThreat() map[string]any {
	return map[string]any{
		"type":     "regex",
		"pattern":  decodeBudgetExhaustedPattern,
		"match":    decodeBudgetExhaustedPattern,
		"position": 0,
		"category": "custom",
		"weight":   1.0,
	}
}

var pathTraversalDecodedShapeCompiled = mustCompile(pathTraversalDecodedShapeSource, 0, windowTimeout)

func regexAnomaly(threats []map[string]any) float64 {
	sum := 0.0
	for _, t := range threats {
		if w, ok := t["weight"].(float64); ok {
			sum += w
		}
	}
	return sum
}

// dropViewDuplicateThreats mirrors _drop_view_duplicate_threats from
// guard_core/handlers/suspatterns_handler.py: keep only the scan results
// whose (pattern, match_text) pair the earlier views have not already
// recorded, so a raw-view sighting of a row over text the processed views
// already matched counts once instead of doubling the threat score.
func dropViewDuplicateThreats(seenThreats, newThreats []map[string]any) []map[string]any {
	if len(newThreats) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(seenThreats)+len(newThreats))
	threatKey := func(t map[string]any) string {
		pattern, _ := t["pattern"].(string)
		match, _ := t["match"].(string)
		return pattern + "\x00" + match
	}
	for _, t := range seenThreats {
		seen[threatKey(t)] = struct{}{}
	}
	var kept []map[string]any
	for _, t := range newThreats {
		key := threatKey(t)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		kept = append(kept, t)
	}
	return kept
}

func checkDecodedViewPathTraversal(pre *preprocessor, processedContent, content, rawViewContent string, enabledCategories map[string]bool) map[string]any {
	if enabledCategories != nil && !enabledCategories["path_traversal"] {
		return nil
	}
	decodedT := newScanText(processedContent)
	rawT := newScanText(rawViewContent)
	decodedMatches := findAllMatches(pathTraversalDecodedShapeCompiled, decodedT)
	rawCount := len(findAllMatches(pathTraversalDecodedShapeCompiled, rawT))
	if len(decodedMatches) <= rawCount {
		return nil
	}
	m := decodedMatches[0]
	return map[string]any{
		"type":     "regex",
		"pattern":  pathTraversalDecodedShapeSource,
		"match":    sanitizeForReporting(m.text()),
		"position": m.start(),
		"category": "path_traversal",
		"weight":   resolvePatternWeight(pathTraversalDecodedShapeSource, "path_traversal"),
	}
}

func checkSemanticThreats(processedContent, originalContent string) ([]map[string]any, float64, map[string]any) {
	if looksLikeBinaryContent(originalContent) {
		return nil, 0.0, nil
	}
	rs := []rune(processedContent)
	if len(rs) > defaultMaxSemanticLength {
		rs = rs[:defaultMaxSemanticLength]
	}
	content := string(rs)
	analysis := semanticAnalyze(content)
	score := semanticThreatScore(analysis)
	var threats []map[string]any
	if score > semanticThreshold {
		probsAny, _ := analysis["attack_probabilities"].(map[string]any)
		for _, attackType := range attackKeywordOrder {
			prob, _ := probsAny[attackType].(float64)
			if prob >= semanticThreshold {
				threats = append(threats, map[string]any{
					"type":        "semantic",
					"attack_type": attackType,
					"probability": prob,
					"analysis":    analysis,
				})
			}
		}
		if len(threats) == 0 && score >= semanticThreshold {
			threats = append(threats, map[string]any{
				"type":         "semantic",
				"attack_type":  "suspicious",
				"threat_score": score,
				"analysis":     analysis,
			})
		}
	}
	return threats, score, analysis
}

const defaultMaxSemanticLength = 10000
const semanticThreshold = 0.7

func calculateThreatScore(regexThreats, semanticThreats []map[string]any) float64 {
	if len(regexThreats) == 0 && len(semanticThreats) == 0 {
		return 0.0
	}
	anomaly := regexAnomaly(regexThreats)
	semanticMax := 0.0
	for _, t := range semanticThreats {
		v := 0.0
		if p, ok := t["probability"].(float64); ok {
			v = p
		} else if p, ok := t["threat_score"].(float64); ok {
			v = p
		}
		if v > semanticMax {
			semanticMax = v
		}
	}
	score := anomaly
	if semanticMax > score {
		score = semanticMax
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func Detect(content string, ip string, context string) DetectResult {
	originalLength := len([]rune(content))

	cfg := DefaultConfig()
	pre := newPreprocessor(cfg)
	pp := pre.preprocessWithDecoded(content)
	processedContent := pp.processed
	decodeBudgetExhausted := pp.budgetExhausted
	precomputedDecoded := pp.decoded

	var regexThreats []map[string]any

	mainThreats, _, _ := checkRegexPatterns(newScanText(processedContent), context, nil, viewMain)
	regexThreats = append(regexThreats, mainThreats...)

	rawViewContent := pre.preprocessSignalPreserving(content)
	rawThreats, _, _ := checkRegexPatterns(newScanText(rawViewContent), context, nil, viewRaw)
	// A raw-view sighting of a pattern over text the processed views already
	// matched is the same evidence and must not inflate the threat score
	// (guard-core _drop_view_duplicate_threats, applied to the raw pass
	// only; merge order stays processed-then-raw). This port folds pattern
	// timeouts into the threats list, so one dedup covers both.
	rawThreats = dropViewDuplicateThreats(regexThreats, rawThreats)
	regexThreats = append(regexThreats, rawThreats...)

	if dv := checkDecodedViewPathTraversal(pre, processedContent, content, rawViewContent, nil); dv != nil {
		regexThreats = append(regexThreats, dv)
	}

	var urlDecodedViewContent string
	var urlDecodedBudgetExhausted bool
	if precomputedDecoded != "" {
		urlDecodedViewContent = pre.truncateSafely(precomputedDecoded)
		urlDecodedBudgetExhausted = decodeBudgetExhausted
	} else {
		urlDecodedViewContent, urlDecodedBudgetExhausted = pre.preprocessURLDecodedNewlinePreserving(content)
	}
	urlThreats, _, _ := checkRegexPatterns(newScanText(urlDecodedViewContent), context, nil, viewURLDecoded)
	regexThreats = append(regexThreats, urlThreats...)

	if decodeBudgetExhausted || urlDecodedBudgetExhausted {
		regexThreats = append(regexThreats, decodeBudgetExhaustedThreat())
	}

	shortBase64View := buildShortBase64AdditiveView(normalizeUnicode, pre.truncateSafely, content)
	if shortBase64View != "" {
		sbThreats, _, _ := checkRegexPatterns(newScanText(shortBase64View), context, nil, viewPlain)
		regexThreats = append(regexThreats, sbThreats...)
	}

	semanticThreats, _, _ := checkSemanticThreats(processedContent, content)

	threats := append(append([]map[string]any{}, regexThreats...), semanticThreats...)
	isThreat := regexAnomaly(regexThreats) >= 1.0 || len(semanticThreats) > 0
	threatScore := calculateThreatScore(regexThreats, semanticThreats)

	sort.SliceStable(threats, func(i, j int) bool { return false })

	return DetectResult{
		IsThreat:        isThreat,
		ThreatScore:     threatScore,
		Threats:         threats,
		OriginalLength:  originalLength,
		ProcessedLength: len([]rune(processedContent)),
		DetectionMethod: "enhanced",
	}
}
