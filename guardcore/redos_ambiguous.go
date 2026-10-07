package guardcore

// Ports of guard_core.detection_engine._redos_literal_in_wildcard and
// _redos_ambiguous_tail: the literal-absorption and ambiguous-optional-tail
// structural detectors plus the flat quantified-atom parser they share.

import "strings"

// literalRunAt mirrors _literal_run_at (literal_in_wildcard).
func literalRunAt(pattern string, i int) (string, int) {
	j := i
	n := len(pattern)
	for j < n && (isAlnumRune(rune(pattern[j])) || pattern[j] == '-') {
		j++
	}
	return pattern[i:j], j
}

// wildcardAbsorbsLiteral mirrors _wildcard_absorbs_literal.
func wildcardAbsorbsLiteral(pattern string, i, end int) (string, bool) {
	qlen := outerQuantifierLen(pattern, end)
	if qlen == 0 {
		return "", false
	}
	classChars := atomCharSet(pattern[i:end])
	if len(classChars) == 0 {
		return "", false
	}
	literal, _ := literalRunAt(pattern, end+qlen)
	if len(literal) < 2 {
		return "", false
	}
	for _, ch := range literal {
		if !classChars[ch] {
			return "", false
		}
	}
	return pattern[i:end+qlen] + " then literal '" + literal + "'", true
}

// detectAmbiguousLiteralBoundary mirrors _detect_ambiguous_literal_boundary.
func detectAmbiguousLiteralBoundary(pattern string) (string, bool) {
	i := 0
	n := len(pattern)
	for i < n {
		if pattern[i] != '[' {
			i++
			continue
		}
		end := skipCharClass(pattern, i)
		if finding, found := wildcardAbsorbsLiteral(pattern, i, end); found {
			return finding, true
		}
		i = end
	}
	return "", false
}

// flatAtomText mirrors one entry of
// _parse_flat_quantified_atoms_with_text.
type flatAtomText struct {
	text      string
	optional  bool
	unbounded bool
	variable  bool
}

// parseSymbolQuantifier mirrors _parse_symbol_quantifier.
func parseSymbolQuantifier(inner string, i int) (optional, unbounded bool, next int) {
	symbol := inner[i]
	optional = symbol == '*' || symbol == '?'
	unbounded = symbol == '*' || symbol == '+'
	i++
	if i < len(inner) && inner[i] == '?' {
		i++
	}
	return optional, unbounded, i
}

type braceQuantifier struct {
	optional  bool
	unbounded bool
	variable  bool
	next      int
}

// parseBraceQuantifierWithVariability mirrors
// _parse_brace_quantifier_with_variability.
func parseBraceQuantifierWithVariability(inner string, i int) (braceQuantifier, bool) {
	endBrace := strings.IndexByte(inner[i:], '}')
	if endBrace == -1 {
		return braceQuantifier{}, false
	}
	endBrace += i
	parts := strings.Split(inner[i+1:endBrace], ",")
	if len(parts) == 0 || !allDigits(parts[0]) || parts[0] == "" {
		return braceQuantifier{}, false
	}
	low := 0
	for _, c := range parts[0] {
		low = low*10 + int(c-'0')
	}
	optional := low == 0
	unbounded := len(parts) > 1 && parts[1] == ""
	variable := unbounded || (len(parts) > 1 && parts[1] != parts[0])
	j := endBrace + 1
	if j < len(inner) && inner[j] == '?' {
		j++
	}
	return braceQuantifier{optional: optional, unbounded: unbounded, variable: variable, next: j}, true
}

// rawAtomSpan mirrors _raw_atom_span.
func rawAtomSpan(inner string, i int) int {
	if inner[i] == '\\' && i+1 < len(inner) {
		return i + 2
	}
	if inner[i] == '[' {
		return skipCharClass(inner, i)
	}
	return i + 1
}

// parseFlatQuantifiedAtomsWithText mirrors
// _parse_flat_quantified_atoms_with_text; nil when the inner text is not a
// flat atom sequence.
func parseFlatQuantifiedAtomsWithText(inner string) []flatAtomText {
	var atoms []flatAtomText
	i := 0
	n := len(inner)
	for i < n {
		if inner[i] == '(' || inner[i] == '|' {
			return nil
		}
		atomEnd := rawAtomSpan(inner, i)
		atomText := inner[i:atomEnd]
		i = atomEnd
		optional, unbounded, variable := false, false, false
		if i < n && (inner[i] == '*' || inner[i] == '+' || inner[i] == '?') {
			optional, unbounded, i = parseSymbolQuantifier(inner, i)
			variable = true
		} else if i < n && inner[i] == '{' {
			parsed, ok := parseBraceQuantifierWithVariability(inner, i)
			if !ok {
				return nil
			}
			optional, unbounded, variable, i = parsed.optional, parsed.unbounded, parsed.variable, parsed.next
		}
		atoms = append(atoms, flatAtomText{text: atomText, optional: optional, unbounded: unbounded, variable: variable})
	}
	return atoms
}

// atomsHaveAmbiguousPair mirrors _atoms_have_ambiguous_pair.
func atomsHaveAmbiguousPair(atoms []flatAtomText) bool {
	for a := range atoms {
		for b := range atoms {
			if atoms[a].unbounded && atoms[b].optional && a != b {
				return true
			}
		}
	}
	return false
}

// hasOverlappingCyclicNeighbor mirrors _has_overlapping_cyclic_neighbor.
func hasOverlappingCyclicNeighbor(atoms []flatAtomText) bool {
	n := len(atoms)
	for k := range atoms {
		if !atoms[k].variable {
			continue
		}
		nextText := atoms[(k+1)%n].text
		if atomsOverlap(atoms[k].text, nextText) {
			return true
		}
	}
	return false
}

// groupInnerIsAmbiguous mirrors _group_inner_is_ambiguous.
func groupInnerIsAmbiguous(inner string) bool {
	rawAtoms := parseFlatQuantifiedAtomsWithText(inner)
	if rawAtoms == nil {
		return false
	}
	if len(rawAtoms) == 1 {
		return rawAtoms[0].variable && !rawAtoms[0].unbounded
	}
	shaped := make([]flatAtomText, len(rawAtoms))
	copy(shaped, rawAtoms)
	if atomsHaveAmbiguousPair(shaped) {
		return true
	}
	return hasOverlappingCyclicNeighbor(rawAtoms)
}

// detectAmbiguousOptionalTail mirrors
// _detect_ambiguous_optional_tail_in_quantified_group.
func detectAmbiguousOptionalTail(pattern string) (string, bool, error) {
	bodies, err := iterQuantifiedGroupBodies(pattern, 0, 0)
	if err != nil {
		// GroupNestingTooDeep is the reference's rejection finding.
		return nestingDepthRejectionReason, true, nil
	}
	for _, body := range bodies {
		if groupInnerIsAmbiguous(body.inner) {
			return pattern[body.start:body.end], true, nil
		}
	}
	return "", false, nil
}
