package guardcore

// Port of guard_core.detection_engine._redos_unreachable_terminator: the
// broad-scan walk that flags a quantified broad scan whose terminator
// cannot be reached by repeating its own prefix.

import "strings"

var prefixResetChars = "()|^$"
var terminatorNonLiteralLeaders = "()|^$.*+?{"

// skipSymbolQuantifierAt mirrors _skip_symbol_quantifier_at.
func skipSymbolQuantifierAt(text string, k int) int {
	end := k + 1
	if end < len(text) && text[end] == '?' {
		end++
	}
	return end - k
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// skipBraceQuantifierAt mirrors _skip_brace_quantifier_at.
func skipBraceQuantifierAt(text string, k int) int {
	endBrace := strings.IndexByte(text[k:], '}')
	if endBrace == -1 {
		return 0
	}
	endBrace += k
	parts := strings.Split(text[k+1:endBrace], ",")
	for _, part := range parts {
		if part != "" && !allDigits(part) {
			return 0
		}
	}
	allEmpty := true
	for _, part := range parts {
		if part != "" {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return 0
	}
	end := endBrace + 1
	if end < len(text) && text[end] == '?' {
		end++
	}
	return end - k
}

// skipQuantifierAt mirrors _skip_quantifier_at.
func skipQuantifierAt(text string, k int) int {
	if k >= len(text) {
		return 0
	}
	switch c := text[k]; c {
	case '*', '+', '?':
		return skipSymbolQuantifierAt(text, k)
	case '{':
		return skipBraceQuantifierAt(text, k)
	}
	return 0
}

// quantifierAtAllowsZero mirrors _quantifier_at_allows_zero.
func quantifierAtAllowsZero(text string, k int) bool {
	if skipQuantifierAt(text, k) == 0 {
		return false
	}
	c := text[k]
	if c == '*' || c == '?' {
		return true
	}
	if c != '{' {
		return false
	}
	endBrace := strings.IndexByte(text[k:], '}')
	if endBrace == -1 {
		return false
	}
	endBrace += k
	low := strings.Split(text[k+1:endBrace], ",")[0]
	return low == "" || low == "0"
}

// terminatorCharsAt mirrors _terminator_chars_at; ok is false for the
// un-decidable cases the reference returns None for.
func terminatorCharsAt(text string, j int) (map[rune]bool, bool) {
	if j >= len(text) {
		return nil, false
	}
	c := text[j]
	switch {
	case c == '[':
		end := skipCharClass(text, j)
		if end-1 <= j+1 {
			return nil, false
		}
		inner := text[j+1 : end-1]
		if strings.HasPrefix(inner, "^") || inner == "" {
			return nil, false
		}
		// The reference builds a raw char set of the class body (escapes
		// are NOT decoded here).
		set := make(map[rune]bool, len(inner))
		for _, r := range inner {
			set[r] = true
		}
		return set, true
	case c == '\\' && j+1 < len(text):
		next := rune(text[j+1])
		if isAlnumRune(next) {
			return nil, false
		}
		return map[rune]bool{next: true}, true
	case strings.ContainsRune(terminatorNonLiteralLeaders, rune(c)):
		return nil, false
	}
	return map[rune]bool{rune(c): true}, true
}

func isAlnumRune(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r > 127
}

// broadScanExcludedChars mirrors _broad_scan_excluded_chars; ok is false
// for the non-negated-class case (excluded == None in the reference).
func broadScanExcludedChars(pattern string, i int) (int, map[rune]bool, bool) {
	c := pattern[i]
	if c == '.' {
		return i + 1, map[rune]bool{}, true
	}
	j := skipCharClass(pattern, i)
	if j-1 <= i+1 {
		return j, nil, false
	}
	inner := pattern[i+1 : j-1]
	if !strings.HasPrefix(inner, "^") {
		return j, nil, false
	}
	excluded := make(map[rune]bool, len(inner))
	// The reference builds a raw char set of the negated body (escapes are
	// NOT decoded here).
	for _, r := range inner[1:] {
		excluded[r] = true
	}
	return j, excluded, true
}

// classTerminatorFinding mirrors _class_terminator_finding.
func classTerminatorFinding(pattern string, i, scanEnd int, prefixChars, excluded map[rune]bool) (string, bool) {
	if outerQuantifierLen(pattern, scanEnd) == 0 {
		return "", false
	}
	termPos := scanEnd + skipQuantifierAt(pattern, scanEnd)
	terminatorChars, ok := terminatorCharsAt(pattern, termPos)
	if !ok || len(prefixChars) == 0 {
		return "", false
	}
	for ch := range prefixChars {
		if excluded[ch] || terminatorChars[ch] {
			return "", false
		}
	}
	return pattern[i:scanEnd] + " preceded by " + sortedRunes(prefixChars), true
}

func sortedRunes(set map[rune]bool) string {
	runes := make([]rune, 0, len(set))
	for r := range set {
		runes = append(runes, r)
	}
	for i := 1; i < len(runes); i++ {
		for j := i; j > 0 && runes[j] < runes[j-1]; j-- {
			runes[j], runes[j-1] = runes[j-1], runes[j]
		}
	}
	return string(runes)
}

// unreachableTerminatorStep mirrors _unreachable_terminator_step.
func unreachableTerminatorStep(pattern string, i int, prefixChars map[rune]bool) (int, map[rune]bool, string, bool) {
	c := pattern[i]
	switch {
	case c == '(':
		if strings.HasPrefix(pattern[i+1:], "?:") {
			return i + 3, prefixChars, "", false
		}
		if i+1 < len(pattern) && pattern[i+1] == '?' {
			endParen := strings.IndexByte(pattern[i:], ')')
			next := i + 1
			if endParen != -1 {
				next = i + endParen + 1
			}
			return next, map[rune]bool{}, "", false
		}
		return i + 1, prefixChars, "", false
	case strings.ContainsRune(prefixResetChars, rune(c)):
		return i + 1, map[rune]bool{}, "", false
	case c == '[' || c == '.':
		scanEnd, excluded, ok := broadScanExcludedChars(pattern, i)
		if !ok {
			next := scanEnd + skipQuantifierAt(pattern, scanEnd)
			return next, map[rune]bool{}, "", false
		}
		if finding, found := classTerminatorFinding(pattern, i, scanEnd, prefixChars, excluded); found {
			return scanEnd, prefixChars, finding, true
		}
		next := scanEnd + skipQuantifierAt(pattern, scanEnd)
		return next, map[rune]bool{}, "", false
	case c == '\\' && i+1 < len(pattern):
		nxt := rune(pattern[i+1])
		tokenEnd := i + 2
		var nextPrefix map[rune]bool
		if !isAlnumRune(nxt) {
			nextPrefix = copyRuneSet(prefixChars)
			nextPrefix[nxt] = true
		} else if quantifierAtAllowsZero(pattern, tokenEnd) {
			nextPrefix = copyRuneSet(prefixChars)
		} else {
			nextPrefix = map[rune]bool{}
		}
		return tokenEnd + skipQuantifierAt(pattern, tokenEnd), nextPrefix, "", false
	default:
		nextPrefix := copyRuneSet(prefixChars)
		nextPrefix[rune(c)] = true
		return i + 1 + skipQuantifierAt(pattern, i+1), nextPrefix, "", false
	}
}

func copyRuneSet(src map[rune]bool) map[rune]bool {
	dst := make(map[rune]bool, len(src)+1)
	for k := range src {
		dst[k] = true
	}
	return dst
}

// detectUnreachableTerminatorScan mirrors _detect_unreachable_terminator_scan.
func detectUnreachableTerminatorScan(pattern string) (string, bool) {
	finding, found := unreachableTerminatorWalk(pattern)
	return finding, found
}

// unreachableTerminatorExcludedScan reports whether the flagged broad scan
// is a negated character class whose exclusion set already contains the
// terminator characters. Such a scan provably cannot absorb its terminator:
// the reference's reach-probe arbiter measured every corpus case of this
// shape under budget and overrode the structural flag (the "structural rule
// flagged ... but the timed reach-probe measured it under budget" branch);
// this port reproduces that override without the wall-clock dependence on
// the reference engine's per-construct backtrack constants.
func unreachableTerminatorExcludedScan(pattern string) bool {
	prefixChars := map[rune]bool{}
	i := 0
	for i < len(pattern) {
		c := pattern[i]
		switch {
		case c == '(':
			if strings.HasPrefix(pattern[i+1:], "?:") {
				i += 3
				continue
			}
			if i+1 < len(pattern) && pattern[i+1] == '?' {
				endParen := strings.IndexByte(pattern[i:], ')')
				if endParen == -1 {
					i++
				} else {
					i += endParen + 1
				}
				prefixChars = map[rune]bool{}
				continue
			}
			i++
		case strings.ContainsRune(prefixResetChars, rune(c)):
			i++
			prefixChars = map[rune]bool{}
		case c == '[' || c == '.':
			scanEnd, excluded, ok := broadScanExcludedChars(pattern, i)
			if !ok {
				i = scanEnd + skipQuantifierAt(pattern, scanEnd)
				prefixChars = map[rune]bool{}
				continue
			}
			if finding, found := classTerminatorFinding(pattern, i, scanEnd, prefixChars, excluded); found {
				_ = finding
				// The scan is exclusive of its terminator when the
				// exclusion set is non-empty and covers every terminator
				// character.
				termPos := scanEnd + skipQuantifierAt(pattern, scanEnd)
				terminatorChars, termOK := terminatorCharsAt(pattern, termPos)
				if ok && len(excluded) > 0 && termOK {
					covered := true
					for ch := range terminatorChars {
						if !excluded[ch] {
							covered = false
							break
						}
					}
					if covered {
						return true
					}
				}
				return false
			}
			i = scanEnd + skipQuantifierAt(pattern, scanEnd)
			prefixChars = map[rune]bool{}
		case c == '\\' && i+1 < len(pattern):
			nxt := rune(pattern[i+1])
			tokenEnd := i + 2
			if !isAlnumRune(nxt) {
				prefixChars[nxt] = true
			} else if !quantifierAtAllowsZero(pattern, tokenEnd) {
				prefixChars = map[rune]bool{}
			}
			i = tokenEnd + skipQuantifierAt(pattern, tokenEnd)
		default:
			prefixChars[rune(c)] = true
			i = i + 1 + skipQuantifierAt(pattern, i+1)
		}
		if i <= 0 {
			break
		}
	}
	return false
}

func unreachableTerminatorWalk(pattern string) (string, bool) {
	prefixChars := map[rune]bool{}
	i := 0
	for i < len(pattern) {
		next, nextPrefix, finding, found := unreachableTerminatorStep(pattern, i, prefixChars)
		i = next
		prefixChars = nextPrefix
		if found {
			return finding, true
		}
		if i <= 0 {
			// defensive: never loop
			break
		}
	}
	return "", false
}
