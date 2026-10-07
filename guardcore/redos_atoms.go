package guardcore

// Atom character-set helpers replacing the reference's compile-and-probe
// strategy (_atom_char_set / _representative_char_for_atom /
// _candidate_chars_for_atom_text in _redos_ambiguous_tail.py and
// _redos_parse_slots.py): the printable-probe result is computed from the
// parsed atom's member intervals instead of re.compiled fullmatch probing.

import "strings"

// printableRunes mirrors string.printable's iteration order (digits,
// lowercase, uppercase, punctuation, whitespace).
var printableRunes = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\v\f")

// nodeIntervals computes the member intervals of a parsed node the way
// _node_intervals does for single ops, recursing into containers the way a
// compiled fullmatch single-character probe would.
func nodeIntervals(node *reNode, flags reFlags) *intervalSet {
	switch node.op {
	case opLiteral:
		iv := singleInterval(int(node.ch))
		return expandIgnoreCase(iv, flags)
	case opNotLiteral:
		iv := singleInterval(int(node.ch))
		return expandIgnoreCase(iv, flags).complement()
	case opAny:
		return anyIntervals(flags)
	case opIn:
		return node.interval
	case opRepeat:
		return bodyIntervals(node.body, flags)
	case opBranch:
		iv := emptyIntervals()
		for _, branch := range node.branches {
			iv = iv.union(bodyIntervals(branch, flags))
		}
		return iv
	case opSubPattern:
		return bodyIntervals(node.body, flags)
	case opAssert:
		// lookarounds do not consume
		return emptyIntervals()
	}
	return emptyIntervals()
}

func bodyIntervals(body []reNode, flags reFlags) *intervalSet {
	if len(body) == 0 {
		return emptyIntervals()
	}
	iv := fullIntervals()
	for i := range body {
		iv = iv.intersection(nodeIntervals(&body[i], flags))
	}
	return iv
}

// atomParseSingle parses an atom text and requires the reference's
// `len(parsed.data) == 1` shape.
func atomParseSingle(atomText string) (*reNode, bool) {
	parsed, err := parseRedosPattern(atomText, flagDotAll)
	if err != nil || len(parsed.nodes) != 1 {
		return nil, false
	}
	return &parsed.nodes[0], true
}

// atomCharSet mirrors _atom_char_set: the printable characters the atom
// can match in a fullmatch of one character.
func atomCharSet(atomText string) map[rune]bool {
	node, ok := atomParseSingle(atomText)
	if !ok {
		return map[rune]bool{}
	}
	iv := nodeIntervals(node, flagDotAll)
	out := map[rune]bool{}
	for _, r := range printableRunes {
		if iv.contains(int(r)) {
			out[r] = true
		}
	}
	return out
}

// representativeCharForAtom mirrors _representative_char_for_atom: the
// first printable character the atom fullmatches, else the first accepted
// candidate from the atom's component first members, else no representative.
func representativeCharForAtom(atomText string) (rune, bool) {
	node, ok := atomParseSingle(atomText)
	if !ok {
		return 0, false
	}
	iv := nodeIntervals(node, flagDotAll)
	if iv.isEmpty() {
		return 0, false
	}
	for _, r := range printableRunes {
		if iv.contains(int(r)) {
			return r, true
		}
	}
	// Reference fallback: the first accepted candidate from the atom's
	// component first members.
	for _, candidate := range candidateCharsForAtomText(atomText) {
		if iv.contains(int(candidate)) {
			return candidate, true
		}
	}
	return 0, false
}

// candidateCharsForAtomText mirrors _candidate_chars_for_atom_text.
func candidateCharsForAtomText(atomText string) []rune {
	node, ok := atomParseSingle(atomText)
	if !ok {
		return nil
	}
	members := nodeIntervals(node, flagDotAll).componentFirstMembers()
	out := make([]rune, 0, len(members))
	for _, m := range members {
		out = append(out, rune(m))
	}
	return out
}

// atomsOverlap mirrors _atoms_overlap.
func atomsOverlap(textA, textB string) bool {
	setA := atomCharSet(textA)
	if len(setA) == 0 {
		return false
	}
	for r := range atomCharSet(textB) {
		if setA[r] {
			return true
		}
	}
	return false
}

var _ = strings.Contains
