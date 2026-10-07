package guardcore

// Port of guard_core.detection_engine._redos_structure_primitives and
// _redos_structure_rules: the string-level structural analysis used by the
// ReDoS safety prefilters. Every helper mirrors the reference function of
// the same name; the rules are pure pattern-text walks, no engine input.

import (
	"errors"
	"regexp"
	"strings"
)

// skipCharClass mirrors _skip_char_class: index just past a [...] run.
func skipCharClass(text string, i int) int {
	j := i + 1
	for j < len(text) && text[j] != ']' {
		if text[j] == '\\' && j+1 < len(text) {
			j += 2
			continue
		}
		j++
	}
	if j < len(text) {
		j++
	}
	return j
}

// stripEscapesAndCharClasses mirrors _strip_escapes_and_char_classes.
func stripEscapesAndCharClasses(pattern string) string {
	var b strings.Builder
	i := 0
	for i < len(pattern) {
		c := pattern[i]
		if c == '\\' && i+1 < len(pattern) {
			b.WriteByte('X')
			i += 2
			continue
		}
		if c == '[' {
			i = skipCharClass(pattern, i)
			b.WriteByte('X')
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

var branchUnboundedSingleRE = regexp.MustCompile(`^.[*+]$`)
var branchUnboundedBraceRE = regexp.MustCompile(`^.\{[0-9]+,\}$`)

// branchIsUnboundedSingle mirrors _branch_is_unbounded_single.
func branchIsUnboundedSingle(branch string) bool {
	if branchUnboundedSingleRE.MatchString(branch) {
		return true
	}
	return branchUnboundedBraceRE.MatchString(branch)
}

// advancePastEscapeOrCharClass mirrors _advance_past_escape_or_char_class;
// -1 when the index is a plain character.
func advancePastEscapeOrCharClass(text string, i int) int {
	if text[i] == '\\' && i+1 < len(text) {
		return i + 2
	}
	if text[i] == '[' {
		return skipCharClass(text, i)
	}
	return -1
}

// findGroupEnd mirrors _find_group_end; -1 when unbalanced.
func findGroupEnd(text string, start int) int {
	depth := 1
	j := start + 1
	for j < len(text) && depth > 0 {
		if skip := advancePastEscapeOrCharClass(text, j); skip != -1 {
			j = skip
			continue
		}
		switch text[j] {
		case '(':
			depth++
		case ')':
			depth--
		}
		j++
	}
	if depth != 0 {
		return -1
	}
	return j
}

// normalizeGroupInner mirrors _normalize_group_inner; ok is false for
// (?P=...) backreference groups (they have no body to analyze).
func normalizeGroupInner(inner string) (string, bool) {
	if strings.HasPrefix(inner, "?:") {
		return inner[2:], true
	}
	if strings.HasPrefix(inner, "?P=") {
		return "", false
	}
	if strings.HasPrefix(inner, "?P<") {
		end := strings.IndexByte(inner, '>')
		if end == -1 {
			return "", false
		}
		return inner[end+1:], true
	}
	return inner, true
}

// unwrapTransparentWrapper mirrors _unwrap_transparent_wrapper.
func unwrapTransparentWrapper(text string) string {
	for strings.HasPrefix(text, "(") {
		end := findGroupEnd(text, 0)
		if end == -1 || end != len(text) {
			break
		}
		candidate, ok := normalizeGroupInner(text[1 : end-1])
		if !ok {
			break
		}
		text = candidate
	}
	return text
}

// outerQuantifierLen mirrors _outer_quantifier_len.
func outerQuantifierLen(text string, k int) int {
	if k < len(text) && (text[k] == '*' || text[k] == '+') {
		return 1
	}
	if k < len(text) && text[k] == '{' {
		endBrace := strings.IndexByte(text[k:], '}')
		if endBrace != -1 {
			braceInner := text[k+1 : k+endBrace]
			if strings.ContainsRune(braceInner, ',') && strings.Split(braceInner, ",")[1] == "" {
				return endBrace + 1
			}
		}
	}
	return 0
}

// branchesOverlap mirrors _branches_overlap.
func branchesOverlap(branches []string) bool {
	for a := 0; a < len(branches); a++ {
		for b := a + 1; b < len(branches); b++ {
			x, y := branches[a], branches[b]
			if x == y || strings.HasPrefix(x, y) || strings.HasPrefix(y, x) {
				return true
			}
		}
	}
	return false
}

const metaBranchChars = "()[]{}.*+?^$|\\"

// isPureLiteralBranch mirrors _is_pure_literal_branch.
func isPureLiteralBranch(branch string) bool {
	if branch == "" {
		return false
	}
	for _, c := range branch {
		if strings.ContainsRune(metaBranchChars, c) {
			return false
		}
	}
	return true
}

// splitTopLevelAlternations mirrors _split_top_level_alternations.
func splitTopLevelAlternations(inner string) []string {
	var branches []string
	depth := 0
	start := 0
	k := 0
	for k < len(inner) {
		if skip := advancePastEscapeOrCharClass(inner, k); skip != -1 {
			k = skip
			continue
		}
		switch inner[k] {
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				branches = append(branches, inner[start:k])
				start = k + 1
			}
		}
		k++
	}
	return append(branches, inner[start:])
}

// overlappingLiteralBranches mirrors _overlapping_literal_branches.
func overlappingLiteralBranches(inner string) bool {
	var literalBranches []string
	for _, b := range splitTopLevelAlternations(inner) {
		if isPureLiteralBranch(b) {
			literalBranches = append(literalBranches, b)
		}
	}
	return len(literalBranches) >= 2 && branchesOverlap(literalBranches)
}

// quantifiedGroupBody mirrors one yield of _iter_quantified_group_bodies.
type quantifiedGroupBody struct {
	start int
	end   int
	inner string
}

// iterQuantifiedGroupBodies mirrors _iter_quantified_group_bodies_at; deep
// nesting returns the reference's nesting-depth rejection.
func iterQuantifiedGroupBodies(pattern string, base int, depth int) ([]quantifiedGroupBody, error) {
	if depth > maxGroupNestingDepth {
		return nil, errGroupNestingTooDeep
	}
	var out []quantifiedGroupBody
	i := 0
	for i < len(pattern) {
		if pattern[i] != '(' {
			i++
			continue
		}
		j := findGroupEnd(pattern, i)
		if j == -1 {
			i++
			continue
		}
		rawInner := pattern[i+1 : j-1]
		sub, err := iterQuantifiedGroupBodies(rawInner, base+i+1, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
		if inner, ok := normalizeGroupInner(rawInner); ok {
			inner = unwrapTransparentWrapper(inner)
			qlen := outerQuantifierLen(pattern, j)
			if qlen > 0 {
				out = append(out, quantifiedGroupBody{start: base + i, end: base + j + qlen, inner: inner})
			}
		}
		i = j
	}
	return out, nil
}

var errGroupNestingTooDeep = errors.New(nestingDepthRejectionReason)

// nestedBodyIsUnbounded mirrors _nested_body_is_unbounded.
func nestedBodyIsUnbounded(inner string) bool {
	stripped := stripEscapesAndCharClasses(inner)
	for _, b := range strings.Split(stripped, "|") {
		if branchIsUnboundedSingle(b) {
			return true
		}
	}
	return overlappingLiteralBranches(inner)
}

// detectNestedUnboundedQuantifier mirrors _detect_nested_unbounded_quantifier.
func detectNestedUnboundedQuantifier(pattern string) (string, bool, error) {
	bodies, err := iterQuantifiedGroupBodies(pattern, 0, 0)
	if err != nil {
		// GroupNestingTooDeep is the reference's rejection finding.
		return nestingDepthRejectionReason, true, nil
	}
	for _, body := range bodies {
		if nestedBodyIsUnbounded(body.inner) {
			return pattern[body.start:body.end], true, nil
		}
	}
	return "", false, nil
}

const broadShorthandEscapeLetters = "SWD"

var alreadyBroadShorthandRE = regexp.MustCompile(`\\[SWD]`)

// isBroadCharClassInner mirrors _is_broad_char_class_inner.
func isBroadCharClassInner(inner string) bool {
	if strings.HasPrefix(inner, "^") {
		excluded := inner[1:]
		return !alreadyBroadShorthandRE.MatchString(excluded)
	}
	return inner == `\s\S` || inner == `\S\s`
}

// broadAtomSpan mirrors _broad_atom_span.
func broadAtomSpan(pattern string, i int) (int, bool) {
	c := pattern[i]
	n := len(pattern)
	switch {
	case c == '\\' && i+1 < n:
		return i + 2, strings.ContainsRune(broadShorthandEscapeLetters, rune(pattern[i+1]))
	case c == '[':
		j := skipCharClass(pattern, i)
		inner := pattern[i+1 : j-1]
		return j, isBroadCharClassInner(inner)
	case c == '.':
		return i + 1, true
	}
	return i + 1, false
}

// broadUnboundedRunAt mirrors _broad_unbounded_run_at.
func broadUnboundedRunAt(pattern string, depth int) (int, []string, error) {
	if depth > maxGroupNestingDepth {
		return 0, nil, errGroupNestingTooDeep
	}
	count := 0
	var spans []string
	i := 0
	n := len(pattern)
	for i < n {
		if pattern[i] == '(' {
			j := findGroupEnd(pattern, i)
			if j == -1 {
				i++
				continue
			}
			if inner, ok := normalizeGroupInner(pattern[i+1 : j-1]); ok {
				bestCount := -1
				var bestSpans []string
				for _, branch := range splitTopLevelAlternations(inner) {
					c2, s2, err := broadUnboundedRunAt(branch, depth+1)
					if err != nil {
						return 0, nil, err
					}
					if c2 > bestCount {
						bestCount = c2
						bestSpans = s2
					}
				}
				count += bestCount
				spans = append(spans, bestSpans...)
			}
			i = j
			continue
		}
		atomEnd, isBroad := broadAtomSpan(pattern, i)
		if isBroad && outerQuantifierLen(pattern, atomEnd) > 0 {
			count++
			spans = append(spans, pattern[i:atomEnd])
		}
		i = atomEnd
	}
	return count, spans, nil
}

// detectAdjacentBroadUnboundedQuantifiers mirrors
// _detect_adjacent_broad_unbounded_quantifiers.
func detectAdjacentBroadUnboundedQuantifiers(pattern string) (string, bool, error) {
	count, spans, err := broadUnboundedRunAt(pattern, 0)
	if err != nil {
		// GroupNestingTooDeep is the reference's rejection finding.
		return nestingDepthRejectionReason, true, nil
	}
	if count >= 2 {
		limit := len(spans)
		if limit > 2 {
			limit = 2
		}
		return strings.Join(spans[:limit], " and "), true, nil
	}
	return "", false, nil
}
