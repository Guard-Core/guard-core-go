package guardcore

// Port of guard_core.detection_engine._redos_reach_probe: synthesis of a
// probe string that reaches every quantified region of a pattern.

import (
	"errors"
	"fmt"
	"strings"
)

const (
	probeReachStressLen        = 4000
	probeReachBoundedCap       = 4000
	probeReachTotalBudget      = 12000
	probeReachMaxLength        = 2 * probeReachTotalBudget
	probeReachGroupRepeatCap   = 3
	probeReachBreakCharCands   = "\x01\x02\x03\x04\x05\x06\x07\x08"
	probeReachStrayByte        = '\x00'
	errProbeConstructionBudget = "mandatory repeat exceeds the probe construction budget"
)

var errProbeOverflow = errors.New(errProbeConstructionBudget)

// reachBudgetClampedCount mirrors _reach_budget_clamped_count (which only
// computes; the call sites subtract from the budget).
func reachBudgetClampedCount(budget *int, unitLen, low, high int) (int, error) {
	if unitLen <= 0 {
		return high, nil
	}
	if low > probeReachMaxLength/unitLen {
		return 0, errProbeOverflow
	}
	affordable := 0
	if budget != nil {
		affordable = *budget / unitLen
	}
	if affordable < 0 {
		affordable = 0
	}
	count := high
	if affordable < count {
		count = affordable
	}
	if low > count {
		count = low
	}
	return count, nil
}

// reachQuantifierRepeatRange mirrors _reach_quantifier_repeat_range.
func reachQuantifierRepeatRange(text string, k int) (int, int, int) {
	if k >= len(text) {
		return 1, 1, k
	}
	switch c := text[k]; c {
	case '*':
		end := k + 1
		if end < len(text) && text[end] == '?' {
			end++
		}
		return 0, probeReachStressLen, end
	case '+':
		end := k + 1
		if end < len(text) && text[end] == '?' {
			end++
		}
		return 1, probeReachStressLen, end
	case '?':
		end := k + 1
		if end < len(text) && text[end] == '?' {
			end++
		}
		return 0, 1, end
	case '{':
		endBrace := strings.IndexByte(text[k:], '}')
		if endBrace == -1 {
			return 1, 1, k
		}
		endBrace += k
		parts := strings.Split(text[k+1:endBrace], ",")
		if !allDigits(parts[0]) || parts[0] == "" {
			return 1, 1, k
		}
		low := 0
		for _, ch := range parts[0] {
			low = low*10 + int(ch-'0')
		}
		high := 0
		switch {
		case len(parts) == 1:
			high = low
		case parts[1] == "":
			high = probeReachStressLen
		case allDigits(parts[1]):
			high = 0
			for _, ch := range parts[1] {
				high = high*10 + int(ch-'0')
			}
		default:
			return 1, 1, k
		}
		end := endBrace + 1
		if end < len(text) && text[end] == '?' {
			end++
		}
		if high > probeReachBoundedCap {
			high = probeReachBoundedCap
		}
		if high < low {
			high = low
		}
		return low, high, end
	}
	return 1, 1, k
}

var probeReachLookaroundPrefixes = []string{"?=", "?!", "?<=", "?<!"}

// reachGroupWalkTarget mirrors _reach_group_walk_target; skip true means
// the group contributes nothing; ok false means synthesis fails.
func reachGroupWalkTarget(rawInner string) (string, bool, bool) {
	if !strings.HasPrefix(rawInner, "?") {
		return rawInner, false, true
	}
	if strings.HasPrefix(rawInner, "?:") {
		return rawInner[2:], false, true
	}
	if strings.HasPrefix(rawInner, "?P<") {
		close := strings.IndexByte(rawInner, '>')
		if close == -1 {
			return "", false, false
		}
		return rawInner[close+1:], false, true
	}
	for _, prefix := range probeReachLookaroundPrefixes {
		if strings.HasPrefix(rawInner, prefix) {
			return "", true, true
		}
	}
	if strings.HasPrefix(rawInner, "?#") {
		return "", true, true
	}
	if matchInlineFlagScoped(rawInner) {
		return rawInner[inlineFlagScopedLen(rawInner):], false, true
	}
	if matchInlineFlagOnly(rawInner) {
		return "", true, true
	}
	return "", false, false
}

// matchInlineFlagScoped mirrors _PROBE_REACH_INLINE_FLAG_SCOPED_RE:
// (?flags: at the head.
func matchInlineFlagScoped(rawInner string) bool {
	if !strings.HasPrefix(rawInner, "?") {
		return false
	}
	i := 1
	i += spanFlagLetters(rawInner[i:])
	if i < len(rawInner) && rawInner[i] == '-' {
		i++
		i += spanFlagLetters(rawInner[i:])
	}
	return i < len(rawInner) && rawInner[i] == ':'
}

func inlineFlagScopedLen(rawInner string) int {
	i := 1
	i += spanFlagLetters(rawInner[i:])
	if i < len(rawInner) && rawInner[i] == '-' {
		i++
		i += spanFlagLetters(rawInner[i:])
	}
	return i + 1
}

func spanFlagLetters(s string) int {
	i := 0
	for i < len(s) && strings.ContainsRune("aiLmsux", rune(s[i])) {
		i++
	}
	return i
}

// matchInlineFlagOnly mirrors _PROBE_REACH_INLINE_FLAG_ONLY_RE.
func matchInlineFlagOnly(rawInner string) bool {
	if !strings.HasPrefix(rawInner, "?") {
		return false
	}
	i := 1
	i += spanFlagLetters(rawInner[i:])
	if i < len(rawInner) && rawInner[i] == '-' {
		i++
		i += spanFlagLetters(rawInner[i:])
	}
	return i == len(rawInner)
}

// reachStressFill mirrors _reach_stress_fill.
func reachStressFill(text string, tokenEnd int, rep string, charsSeen map[rune]bool, budget *int) (string, int, error) {
	low, high, next := reachQuantifierRepeatRange(text, tokenEnd)
	count, err := reachBudgetClampedCount(budget, len(rep), low, high)
	if err != nil {
		return "", 0, err
	}
	*budget -= len(rep) * count
	if rep != "" {
		charsSeen[rune(rep[0])] = true
	}
	return strings.Repeat(rep, count), next, nil
}

// reachHexEscapeSpan mirrors _reach_hex_escape_span.
func reachHexEscapeSpan(text string, i int) bool {
	n := len(text)
	return text[i+1] == 'x' && i+3 < n && isHexDigit(text[i+2]) && isHexDigit(text[i+3])
}

type probeSynthState struct {
	charsSeen    map[rune]bool
	budget       int
	groupTexts   map[int]string
	groupCounter int
}

// synthNextAtom mirrors _synth_next_atom.
func synthNextAtom(text string, i int, st *probeSynthState, depth int) (string, int, error) {
	switch c := text[i]; c {
	case '\\':
		return synthEscapeAtom(text, i, st)
	case '[':
		end := skipCharClass(text, i)
		rep, ok := representativeCharForAtom(text[i:end])
		if !ok {
			return "", 0, errSynthFail
		}
		return reachStressFill(text, end, string(rep), st.charsSeen, &st.budget)
	case '.':
		return reachStressFill(text, i+1, "a", st.charsSeen, &st.budget)
	case '(':
		return synthGroupAtom(text, i, st, depth)
	default:
		return reachStressFill(text, i+1, string(c), st.charsSeen, &st.budget)
	}
}

var errSynthFail = errors.New("probe synthesis failed for this pattern")

// synthEscapeAtom mirrors _synth_escape_atom.
func synthEscapeAtom(text string, i int, st *probeSynthState) (string, int, error) {
	if i+1 >= len(text) {
		return "", 0, errSynthFail
	}
	letter := text[i+1]
	isHex := reachHexEscapeSpan(text, i)
	tokenEnd := i + 4
	if !isHex {
		tokenEnd = i + 2
	}
	switch {
	case strings.ContainsRune("AZbB", rune(letter)):
		return "", tokenEnd, nil
	case letter >= '0' && letter <= '9':
		backref, ok := st.groupTexts[int(letter-'0')]
		if !ok {
			return "", 0, errSynthFail
		}
		return reachStressFill(text, tokenEnd, backref, st.charsSeen, &st.budget)
	}
	var rep rune
	if isHex {
		hi, hiOK := hexVal(text[i+2])
		lo, loOK := hexVal(text[i+3])
		if !hiOK || !loOK {
			return "", 0, errSynthFail
		}
		rep = rune(int(hi)<<4 | int(lo))
	} else {
		r, ok := representativeCharForAtom(text[i:tokenEnd])
		if !ok {
			return "", 0, errSynthFail
		}
		rep = r
	}
	return reachStressFill(text, tokenEnd, string(rep), st.charsSeen, &st.budget)
}

// synthGroupAtom mirrors _synth_group_atom.
func synthGroupAtom(text string, i int, st *probeSynthState, depth int) (string, int, error) {
	groupEnd := findGroupEnd(text, i)
	if groupEnd == -1 {
		return "", 0, errSynthFail
	}
	rawInner := text[i+1 : groupEnd-1]
	reservedNumber := 0
	hasReserved := false
	if !strings.HasPrefix(rawInner, "?") || strings.HasPrefix(rawInner, "?P<") {
		st.groupCounter++
		reservedNumber = st.groupCounter
		hasReserved = true
	}
	walkInner, skip, ok := reachGroupWalkTarget(rawInner)
	if !ok {
		return "", 0, errSynthFail
	}
	if skip {
		return "", groupEnd, nil
	}
	firstBranch := splitTopLevelAlternations(walkInner)[0]
	subText, subErr := synthesizeReachingProbeSegment(firstBranch, st, depth+1)
	if subErr != nil {
		return "", 0, subErr
	}
	if hasReserved {
		st.groupTexts[reservedNumber] = subText
	}
	low, high, next := reachQuantifierRepeatRange(text, groupEnd)
	if high > probeReachGroupRepeatCap {
		high = probeReachGroupRepeatCap
	}
	if high < low {
		high = low
	}
	count, err := reachBudgetClampedCount(&st.budget, len(subText), low, high)
	if err != nil {
		return "", 0, err
	}
	st.budget -= len(subText) * count
	return strings.Repeat(subText, count), next, nil
}

// synthesizeReachingProbeSegment mirrors _synthesize_reaching_probe_segment.
func synthesizeReachingProbeSegment(text string, st *probeSynthState, depth int) (string, error) {
	if depth > maxGroupNestingDepth {
		return "", errSynthFail
	}
	var out []string
	length := 0
	i := 0
	for i < len(text) {
		if text[i] == '^' || text[i] == '$' {
			i++
			continue
		}
		piece, next, err := synthNextAtom(text, i, st, depth)
		if err != nil {
			return "", err
		}
		length += len(piece)
		if length > probeReachMaxLength {
			return "", errSynthFail
		}
		out = append(out, piece)
		i = next
	}
	return strings.Join(out, ""), nil
}

// synthesizeReachingProbe mirrors _synthesize_reaching_probe.
func synthesizeReachingProbe(pattern string) (string, bool) {
	st := &probeSynthState{
		charsSeen:  map[rune]bool{},
		budget:     probeReachTotalBudget,
		groupTexts: map[int]string{},
	}
	body, err := synthesizeReachingProbeSegment(pattern, st, 0)
	if err != nil {
		return "", false
	}
	for _, ch := range probeReachBreakCharCands {
		if !st.charsSeen[ch] {
			return body + string(ch), true
		}
	}
	return "", false
}

var _ = fmt.Sprintf
