package guardcore

// Ports of guard_core.detection_engine._redos_exact_state,
// _redos_literal_runs and _redos_class_intersection: the pairing-chain
// machinery that extracts class-intersection (fill, stray) probe units.

import "strings"

const maxGroupCrossingDepth = 16

// narrowExactStateRaw mirrors _narrow_exact_state_raw.
func narrowExactStateRaw(state, right *intervalSet) *intervalSet {
	if state == nil || right == nil {
		return nil
	}
	return state.intersection(right)
}

// exactOverlapFillRaw mirrors _exact_overlap_fill_raw.
func exactOverlapFillRaw(state, right *intervalSet) (rune, bool) {
	if state == nil || right == nil {
		return 0, false
	}
	member, ok := state.intersection(right).firstMember()
	if !ok {
		return 0, false
	}
	return rune(member), true
}

// isolatedAlternativeExactState mirrors _isolated_alternative_exact_state.
func isolatedAlternativeExactState(altSlots []reSlot, depth int) *intervalSet {
	state := fullIntervals()
	for _, slot := range altSlots {
		if atom, ok := slot.(pairingAtom); ok {
			if atom.allowsZero {
				continue
			}
			state = narrowExactStateRaw(state, atom.intervals)
		} else if np, isNp := slot.(nonPairingSlot); isNp && np.isBoundary {
			if np.inner == nil {
				return nil
			}
			groupState := isolatedGroupExactState(np.inner, depth+1)
			state = narrowExactStateRaw(state, groupState)
		}
		if state == nil {
			return nil
		}
	}
	return state
}

// isolatedGroupExactState mirrors _isolated_group_exact_state.
func isolatedGroupExactState(alternatives [][]reSlot, depth int) *intervalSet {
	if depth > maxGroupCrossingDepth {
		return nil
	}
	var combined *intervalSet
	for _, alt := range alternatives {
		altState := isolatedAlternativeExactState(alt, depth)
		if altState == nil {
			continue
		}
		if combined == nil {
			combined = altState
		} else {
			combined = combined.union(altState)
		}
	}
	return combined
}

// adversarialLiteralRuns mirrors _adversarial_literal_runs.
func adversarialLiteralRuns(pattern string) []string {
	var runs []string
	var current []rune
	var stack []bool
	flush := func() {
		if len(current) > 0 {
			runs = append(runs, string(current))
			current = current[:0]
		}
	}
	hardReset := "|^$."
	i := 0
	n := len(pattern)
	for i < n {
		c := pattern[i]
		switch {
		case c == '[':
			end := skipCharClass(pattern, i)
			chars := atomCharSet(pattern[i:end])
			if len(chars) > 0 && len(chars) <= 10 {
				best := rune(-1)
				for r := range chars {
					if best == -1 || r < best {
						best = r
					}
				}
				current = append(current, best)
			} else {
				flush()
			}
			i = end
		case c == '(':
			if strings.HasPrefix(pattern[i+1:], "?:") {
				stack = append(stack, true)
				i += 3
				continue
			}
			if i+1 < n && pattern[i+1] == '?' {
				flush()
				endParen := findGroupEnd(pattern, i)
				if endParen == -1 {
					i++
				} else {
					i = endParen
				}
				continue
			}
			stack = append(stack, false)
			flush()
			i++
		case c == ')':
			transparent := false
			if len(stack) > 0 {
				transparent = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			if !transparent {
				flush()
			}
			i++
		case strings.ContainsRune(hardReset, rune(c)):
			flush()
			i++
		case c == '*' || c == '+' || c == '?':
			i++
		case c == '{':
			endBrace := strings.IndexByte(pattern[i:], '}')
			if endBrace == -1 {
				i++
			} else {
				i += endBrace + 1
			}
		case c == '\\' && i+1 < n:
			nxt := rune(pattern[i+1])
			tokenEnd := i + 2
			if isAlnumRune(nxt) {
				qend, allowsZero := quantifierSpanAllowsZero(pattern, tokenEnd)
				if allowsZero {
					i = qend
					continue
				}
				flush()
				if qend > tokenEnd {
					i = qend
				} else {
					i = tokenEnd
				}
				continue
			}
			current = append(current, nxt)
			i = tokenEnd
		default:
			current = append(current, rune(c))
			i++
		}
	}
	flush()
	return runs
}

// quantifierSpanAllowsZero mirrors _quantifier_span_allows_zero.
func quantifierSpanAllowsZero(text string, k int) (int, bool) {
	if k >= len(text) {
		return k, false
	}
	c := text[k]
	switch c {
	case '*', '?':
		return k + 1 + lazyMarkerLen(text, k+1), true
	case '+':
		return k + 1 + lazyMarkerLen(text, k+1), false
	case '{':
		endBrace := strings.IndexByte(text[k:], '}')
		if endBrace == -1 {
			return k, false
		}
		endBrace += k
		low := strings.Split(text[k+1:endBrace], ",")[0]
		if low != "" && !allDigits(low) {
			return k, false
		}
		end := endBrace + 1 + lazyMarkerLen(text, endBrace+1)
		return end, low == "" || low == "0"
	}
	return k, false
}

func lazyMarkerLen(text string, k int) int {
	if k < len(text) && text[k] == '?' {
		return 1
	}
	return 0
}
