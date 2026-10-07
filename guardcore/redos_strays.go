package guardcore

// Port of guard_core.detection_engine._redos_stray_chooser. The reference
// verifies stray candidates in a killable subprocess because untrusted
// regexes cannot run inline; this port verifies against a regexp2 compile
// carrying a MatchTimeout, which is the same fail-closed contract without a
// subprocess (the timeout is the kill switch).

import (
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

const reachProbeStrayByte = "\x00"

var leadingPrefixMetachars = ".^$*+?{}[]()|\\"

// strayFallbackCandidates mirrors _STRAY_FALLBACK_CANDIDATES.
var strayFallbackCandidates = []string{
	"\x00", "z", "\n", " ", "-", "\t", "\r", "9", "!", "~", "_", ".", "A", "\x1f", "\x7f", "/",
}

const strayCandidateCap = 16

var strayVerifyFillCounts = [3]int{1, 2, 8}

const strayVerifyTimeout = 500 * time.Millisecond

type strayContext struct {
	pattern      string
	flags        reFlags
	prefix       string
	patternUnion *intervalSet
	compiled     *regexp2.Regexp
}

// unwrapLeadingTransparentGroup mirrors _unwrap_leading_transparent_group.
func unwrapLeadingTransparentGroup(pattern string) string {
	text := pattern
	for strings.HasPrefix(text, "(?:") {
		end := findGroupEnd(text, 0)
		if end == -1 || end != len(text) {
			break
		}
		text = text[3 : end-1]
	}
	return text
}

// leadingLiteralPrefix mirrors _leading_literal_prefix.
func leadingLiteralPrefix(pattern string) string {
	text := unwrapLeadingTransparentGroup(pattern)
	var prefix []rune
	i := 0
	n := len(text)
	for i < n {
		c := text[i]
		if c == '\\' && i+1 < n && !isAlnumRune(rune(text[i+1])) {
			prefix = append(prefix, rune(text[i+1]))
			i += 2
			continue
		}
		if strings.ContainsRune(leadingPrefixMetachars, rune(c)) {
			break
		}
		prefix = append(prefix, rune(c))
		i++
	}
	return string(prefix)
}

// fillToLength mirrors _fill_to_length.
func fillToLength(prefix, fillChar, stray string, length int) string {
	if length <= len(prefix) {
		return prefix[:length]
	}
	bodyLength := length - len(prefix)
	if bodyLength > 1 {
		return prefix + strings.Repeat(fillChar, bodyLength-1) + stray
	}
	return prefix + strings.Repeat(fillChar, bodyLength)
}

// repeatProbeToLength mirrors _repeat_probe_to_length.
func repeatProbeToLength(unit string, length int, stray string) string {
	if unit == "" {
		return unit
	}
	reps := length/len(unit) + 1
	result := strings.Repeat(unit, reps)[:length]
	homogeneous := true
	seen := map[rune]bool{}
	for _, r := range unit {
		seen[r] = true
	}
	if len(seen) > 1 {
		homogeneous = false
	}
	if homogeneous || length%len(unit) == 0 {
		result = result[:len(result)-1] + stray
	}
	return result
}

// prefixedRepeatProbe mirrors _prefixed_repeat_probe.
func prefixedRepeatProbe(prefix, unit, stray string, flood bool, length int) string {
	if length <= len(prefix) {
		return prefix[:length]
	}
	remaining := length - len(prefix)
	tailLength := 1
	if flood {
		tailLength = remaining / 2
		if tailLength < 1 {
			tailLength = 1
		}
	}
	bodyLength := remaining - tailLength
	body := strings.Repeat(unit, bodyLength/len(unit)+1)[:bodyLength]
	return prefix + body + strings.Repeat(stray, tailLength)
}

// buildStrayContext mirrors _build_stray_context.
func buildStrayContext(pattern string, flags reFlags) (*strayContext, error) {
	compiled, err := compileRE(pattern, regexp2OptionsForFlags(flags), strayVerifyTimeout)
	if err != nil {
		// The stray chooser only runs after a successful compile gate; a
		// compile failure here is the same fail-closed contract.
		return nil, err
	}
	return &strayContext{
		pattern:      pattern,
		flags:        flags,
		prefix:       leadingLiteralPrefix(pattern),
		patternUnion: patternClassUnion(pattern, flags),
		compiled:     compiled,
	}, nil
}

// regexp2OptionsForFlags maps the safety-layer flags onto regexp2 options.
func regexp2OptionsForFlags(flags reFlags) regexp2.RegexOptions {
	opts := regexp2.None
	if flags&flagIgnoreCase != 0 {
		opts |= regexp2.IgnoreCase
	}
	if flags&flagMultiline != 0 {
		opts |= regexp2.Multiline
	}
	if flags&flagDotAll != 0 {
		opts |= regexp2.Singleline
	}
	return opts
}

// searchMatches reports whether the compiled pattern finds any match in
// probe; a MatchTimeout trip counts as a match (the stray is rejected
// fail-closed).
func (ctx *strayContext) searchMatches(probe string) bool {
	m, err := ctx.compiled.FindStringMatch(probe)
	if err != nil {
		return true
	}
	return m != nil
}

// firstComplementChar mirrors _first_complement_char.
func firstComplementChar(iv *intervalSet) (string, bool) {
	member, ok := iv.complement().firstMember()
	if !ok {
		return "", false
	}
	return string(rune(member)), true
}

// dedupCappedCandidates mirrors _dedup_capped_candidates.
func dedupCappedCandidates(candidates []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
		if len(out) >= strayCandidateCap {
			break
		}
	}
	return out
}

// strayForPair mirrors _stray_for_pair.
func strayForPair(left, right *intervalSet) string {
	member, ok := left.union(right).complement().firstMember()
	if !ok {
		return reachProbeStrayByte
	}
	return string(rune(member))
}

// classIntersectionStrayCandidates mirrors
// _class_intersection_stray_candidates.
func classIntersectionStrayCandidates(tail []*intervalSet, left, right, patternUnion *intervalSet) []string {
	var ordered []string
	for _, intervals := range tail {
		if c, ok := firstComplementChar(intervals); ok {
			ordered = append(ordered, c)
		}
	}
	if c, ok := firstComplementChar(right); ok {
		ordered = append(ordered, c)
	}
	if c, ok := firstComplementChar(left.union(right)); ok {
		ordered = append(ordered, c)
	}
	if c, ok := firstComplementChar(patternUnion); ok {
		ordered = append(ordered, c)
	}
	ordered = append(ordered, strayFallbackCandidates...)
	return dedupCappedCandidates(ordered)
}

// chooseClassIntersectionStray mirrors choose_class_intersection_stray.
func chooseClassIntersectionStray(ctx *strayContext, fill rune, left, right *intervalSet, tail []*intervalSet) (string, error) {
	if ctx == nil {
		return strayForPair(left, right), nil
	}
	candidates := classIntersectionStrayCandidates(tail, left, right, ctx.patternUnion)
	for _, candidate := range candidates {
		allReject := true
		for _, count := range strayVerifyFillCounts {
			probe := fillToLength(ctx.prefix, string(fill), candidate, len(ctx.prefix)+count+1)
			if ctx.searchMatches(probe) {
				allReject = false
				break
			}
		}
		if allReject {
			return candidate, nil
		}
	}
	return strayForPair(left, right), nil
}

// chooseRepeatUnitStray mirrors choose_repeat_unit_stray. A nil context
// (builder construction without a compiled pattern) falls back to the
// reference's default stray byte.
func chooseRepeatUnitStray(ctx *strayContext, unit string) (string, error) {
	if unit == "" || ctx == nil {
		return reachProbeStrayByte, nil
	}
	var candidates []string
	if c, ok := firstComplementChar(ctx.patternUnion); ok {
		candidates = append(candidates, c)
	}
	candidates = append(candidates, strayFallbackCandidates...)
	candidates = dedupCappedCandidates(candidates)
	for _, candidate := range candidates {
		allReject := true
		for _, count := range strayVerifyFillCounts {
			probe := repeatProbeToLength(unit, len(unit)*count, candidate)
			if ctx.searchMatches(probe) {
				allReject = false
				break
			}
		}
		if allReject {
			return candidate, nil
		}
	}
	return reachProbeStrayByte, nil
}
