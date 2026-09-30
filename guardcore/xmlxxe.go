package guardcore

import (
	"sort"

	"github.com/dlclark/regexp2"
)

var xmlDoctypeRE = mustCompileI(`<!DOCTYPE`)
var xmlPublicRE = mustCompileI(`PUBLIC`)
var xmlSchemeRE = mustCompile(`https?://`, regexp2.IgnoreCase, windowTimeout)
var xmlW3OrgRE = mustCompile(`(?:www\.)?w3\.org/`, regexp2.IgnoreCase, windowTimeout)
var xmlClass12RE = mustCompile(`[>\[]`, 0, windowTimeout)
var xmlClass3RE = mustCompile(`["'>]`, 0, windowTimeout)
var xmlEntityPrefixRE = mustCompile(`<!ENTITY`, regexp2.IgnoreCase, windowTimeout)

func firstAtOrAfter(sorted []int, floor int) (int, bool) {
	idx := sort.SearchInts(sorted, floor)
	if idx >= len(sorted) {
		return 0, false
	}
	return sorted[idx], true
}

func xmlInternalEntityFinditer(t scanText) []rmatch {
	var boundaries []int
	for _, m := range findAllMatches(xmlClass12RE, t) {
		boundaries = append(boundaries, m.start())
	}
	var entities []int
	for _, m := range findAllMatches(xmlEntityPrefixRE, t) {
		entities = append(entities, m.start())
	}
	var out []rmatch
	lastEnd := 0
	for _, prefix := range findAllMatches(xmlDoctypeRE, t) {
		if prefix.start() < lastEnd {
			continue
		}
		boundary, ok := firstAtOrAfter(boundaries, prefix.end())
		if !ok {
			return out
		}
		lastEnd = boundary + 1
		if t.rs[boundary] != '[' {
			continue
		}
		entity, ok := firstAtOrAfter(entities, boundary+1)
		if !ok {
			return out
		}
		lastEnd = entity + len("<!ENTITY")
		out = append(out, matchFromIndices(t, prefix.start(), lastEnd, ""))
	}
	return out
}

func xmlSchemeCompletionEnd(t scanText, schemeStart int, class12, class3 []int) (int, bool) {
	if schemeStart == 0 || !containsRune("\"'", t.rs[schemeStart-1]) {
		return 0, false
	}
	m, err := xmlSchemeRE.FindStringMatchStartingAt(t.s, schemeStart)
	if err != nil || m == nil || m.Index != schemeStart {
		return 0, false
	}
	schemeEnd := m.Index + m.Length
	if w, _ := xmlW3OrgRE.FindStringMatchStartingAt(t.s, schemeEnd); err == nil && w != nil && w.Index == schemeEnd {
		return 0, false
	}
	return xmlQuotedURLEnd(t, schemeEnd, class12, class3)
}

func xmlQuotedURLEnd(t scanText, schemeEnd int, class12, class3 []int) (int, bool) {
	idx := sort.SearchInts(class3, schemeEnd)
	if idx >= len(class3) {
		return 0, false
	}
	quote2 := class3[idx]
	if quote2 == schemeEnd || t.rs[quote2] == '>' {
		return 0, false
	}
	idx2 := sort.SearchInts(class12, quote2+1)
	if idx2 >= len(class12) {
		return 0, false
	}
	final := class12[idx2]
	if t.rs[final] != '>' {
		return 0, false
	}
	return final, true
}

func xmlPublicExternalDTDFinditer(t scanText) []rmatch {
	var doctypePositions []int
	for _, m := range findAllMatches(xmlDoctypeRE, t) {
		doctypePositions = append(doctypePositions, m.start())
	}
	var publicPositions []int
	for _, m := range findAllMatches(xmlPublicRE, t) {
		publicPositions = append(publicPositions, m.start())
	}
	if len(doctypePositions) == 0 || len(publicPositions) == 0 {
		return nil
	}
	var class12 []int
	for _, m := range findAllMatches(xmlClass12RE, t) {
		class12 = append(class12, m.start())
	}
	var class3 []int
	for _, m := range findAllMatches(xmlClass3RE, t) {
		class3 = append(class3, m.start())
	}
	quoteToFinalGT := map[int]int{}
	var quotePositions []int
	for _, sm := range findAllMatches(xmlSchemeRE, t) {
		final, ok := xmlSchemeCompletionEnd(t, sm.start(), class12, class3)
		if !ok {
			continue
		}
		quotePos := sm.start() - 1
		quotePositions = append(quotePositions, quotePos)
		quoteToFinalGT[quotePos] = final
	}
	if len(quotePositions) == 0 {
		return nil
	}
	sort.Ints(quotePositions)

	var out []rmatch
	lastEnd := 0
	for _, publicPos := range publicPositions {
		if publicPos < lastEnd {
			continue
		}
		runIdx := sort.SearchInts(class12, publicPos)
		runStart := 0
		if runIdx > 0 {
			runStart = class12[runIdx-1] + 1
		}
		runEnd := t.n
		if runIdx < len(class12) {
			runEnd = class12[runIdx]
		}
		doctypeBefore, ok := firstAtOrAfter(doctypePositions, runStart)
		if !ok || doctypeBefore >= publicPos-9 {
			continue
		}
		quote1, ok := firstAtOrAfter(quotePositions, publicPos+7)
		if !ok || quote1 >= runEnd {
			continue
		}
		finalGT := quoteToFinalGT[quote1]
		out = append(out, matchFromIndices(t, doctypeBefore, finalGT+1, ""))
		lastEnd = finalGT + 1
	}
	return out
}
