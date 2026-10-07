package guardcore

// Port of guard_core.detection_engine._redos_parse_slots and
// _redos_repeat_alphabet: typed pairing slots over the parsed AST (the
// replacement for re._parser opcodes) plus the repeated-alphabet fills and
// the large-bounded-repeat risk flag.

// pairingAtom mirrors _PairingAtom.
type pairingAtom struct {
	intervals       *intervalSet
	allowsZero      bool
	unbounded       bool
	maxRepeat       int
	variableBounded bool
}

// nonPairingSlot mirrors _NonPairingSlot.
type nonPairingSlot struct {
	isBoundary      bool
	inner           [][]reSlot
	unbounded       bool
	maxRepeat       int
	variableBounded bool
}

type reSlot interface{ isSlot() }

func (pairingAtom) isSlot()    {}
func (nonPairingSlot) isSlot() {}

const noMaxRepeat = -1

// slotForNode mirrors _slot_for_flat_item.
func slotForNode(node *reNode, flags reFlags) reSlot {
	if node.op == opRepeat {
		return repeatSlot(node, flags)
	}
	return unrepeatedSlot(node, flags)
}

func unrepeatedSlot(node *reNode, flags reFlags) reSlot {
	return pairingOrNonPairing(node, flags, false, false, noMaxRepeat, false)
}

func repeatSlot(node *reNode, flags reFlags) reSlot {
	low, high := node.min, node.max
	allowsZero := low == 0
	unbounded := high >= maxRepeat
	variableBounded := !unbounded && low < high
	maxRepeatVal := noMaxRepeat
	if !unbounded {
		maxRepeatVal = high
	}
	if len(node.body) == 1 {
		return pairingOrNonPairing(&node.body[0], flags, allowsZero, unbounded, maxRepeatVal, variableBounded)
	}
	return nonPairingSlot{
		isBoundary:      !allowsZero,
		inner:           sequenceToAlternatives(node.body, flags),
		unbounded:       unbounded,
		maxRepeat:       maxRepeatVal,
		variableBounded: variableBounded,
	}
}

func pairingOrNonPairing(node *reNode, flags reFlags, allowsZero, unbounded bool, maxRepeatVal int, variableBounded bool) reSlot {
	switch node.op {
	case opLiteral, opNotLiteral, opAny, opIn:
		iv := nodeIntervals(node, flags)
		return pairingAtom{
			intervals:       iv,
			allowsZero:      allowsZero,
			unbounded:       unbounded,
			maxRepeat:       maxRepeatVal,
			variableBounded: variableBounded,
		}
	case opRepeat:
		// The reference's _nonpairing_slot fallback: a repeated repeat is
		// an opaque boundary slot.
		return nonPairingSlot{isBoundary: true}
	case opBranch:
		alts := make([][]reSlot, 0, len(node.branches))
		for _, branch := range node.branches {
			alts = append(alts, walkSequence(branch, flags))
		}
		return nonPairingSlot{isBoundary: !allowsZero, inner: alts, unbounded: unbounded, maxRepeat: maxRepeatVal, variableBounded: variableBounded}
	case opSubPattern:
		return nonPairingSlot{
			isBoundary:      !allowsZero,
			inner:           sequenceToAlternatives(node.body, flags),
			unbounded:       unbounded,
			maxRepeat:       maxRepeatVal,
			variableBounded: variableBounded,
		}
	case opAssert:
		return nonPairingSlot{isBoundary: false, inner: sequenceToAlternatives(node.body, flags), unbounded: false, maxRepeat: noMaxRepeat}
	case opAt:
		return nonPairingSlot{isBoundary: false, unbounded: false, maxRepeat: noMaxRepeat}
	case opGroupRef:
		return nonPairingSlot{isBoundary: true, unbounded: unbounded, maxRepeat: maxRepeatVal, variableBounded: variableBounded}
	}
	return nonPairingSlot{isBoundary: true}
}

// walkSequence mirrors _walk_sequence.
func walkSequence(nodes []reNode, flags reFlags) []reSlot {
	out := make([]reSlot, 0, len(nodes))
	for i := range nodes {
		out = append(out, slotForNode(&nodes[i], flags))
	}
	return out
}

// sequenceToAlternatives mirrors _sequence_to_alternatives.
func sequenceToAlternatives(nodes []reNode, flags reFlags) [][]reSlot {
	if len(nodes) == 1 && nodes[0].op == opBranch {
		alts := make([][]reSlot, 0, len(nodes[0].branches))
		for _, branch := range nodes[0].branches {
			alts = append(alts, walkSequence(branch, flags))
		}
		return alts
	}
	return [][]reSlot{walkSequence(nodes, flags)}
}

// patternSlots mirrors _pattern_slots.
func patternSlots(pattern string, flags reFlags) []reSlot {
	parsed, err := parseRedosPattern(pattern, flags)
	if err != nil {
		return nil
	}
	return walkSequence(parsed.nodes, parsed.flags)
}

// collectPairingIntervals mirrors _collect_pairing_intervals.
func collectPairingIntervals(slots []reSlot) []*intervalSet {
	var out []*intervalSet
	for _, slot := range slots {
		switch s := slot.(type) {
		case pairingAtom:
			out = append(out, s.intervals)
		case nonPairingSlot:
			if s.inner != nil {
				for _, alt := range s.inner {
					out = append(out, collectPairingIntervals(alt)...)
				}
			}
		}
	}
	return out
}

// patternClassUnion mirrors _pattern_class_union.
func patternClassUnion(pattern string, flags reFlags) *intervalSet {
	slots := patternSlots(pattern, flags)
	if slots == nil {
		return emptyIntervals()
	}
	union := emptyIntervals()
	for _, iv := range collectPairingIntervals(slots) {
		union = union.union(iv)
	}
	return union
}

// patternComplementChars mirrors _pattern_complement_chars.
func patternComplementChars(pattern string, flags reFlags) []rune {
	slots := patternSlots(pattern, flags)
	if slots == nil {
		return nil
	}
	var out []rune
	seen := map[rune]bool{}
	for _, iv := range collectPairingIntervals(slots) {
		member, ok := iv.complement().firstMember()
		if !ok {
			continue
		}
		r := rune(member)
		if seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// collectAlphabetAtoms mirrors _collect_alphabet_atoms.
func collectAlphabetAtoms(slots []reSlot, repeated bool) []struct {
	intervals *intervalSet
	repeated  bool
} {
	var atoms []struct {
		intervals *intervalSet
		repeated  bool
	}
	for _, slot := range slots {
		isRepeated := repeated || canRepeat(slot)
		switch s := slot.(type) {
		case pairingAtom:
			atoms = append(atoms, struct {
				intervals *intervalSet
				repeated  bool
			}{s.intervals, isRepeated})
		case nonPairingSlot:
			if s.inner != nil {
				for _, alt := range s.inner {
					atoms = append(atoms, collectAlphabetAtoms(alt, isRepeated)...)
				}
			}
		}
	}
	return atoms
}

func canRepeat(slot reSlot) bool {
	switch s := slot.(type) {
	case pairingAtom:
		return s.unbounded || (s.maxRepeat != noMaxRepeat && s.maxRepeat > 1)
	case nonPairingSlot:
		return s.unbounded || (s.maxRepeat != noMaxRepeat && s.maxRepeat > 1)
	}
	return false
}

func slotVariableBounded(slot reSlot) bool {
	switch s := slot.(type) {
	case pairingAtom:
		return s.variableBounded && s.maxRepeat != noMaxRepeat && s.maxRepeat >= largeBoundedRepeatLimit
	case nonPairingSlot:
		return s.variableBounded && s.maxRepeat != noMaxRepeat && s.maxRepeat >= largeBoundedRepeatLimit
	}
	return false
}

const largeBoundedRepeatLimit = 4096

// repeatAlphabetFills mirrors _repeat_alphabet_fills.
func repeatAlphabetFills(pattern string, flags reFlags) []rune {
	slots := patternSlots(pattern, flags)
	if slots == nil {
		return nil
	}
	atoms := collectAlphabetAtoms(slots, false)
	repeated := emptyIntervals()
	for _, atom := range atoms {
		if atom.repeated {
			repeated = repeated.union(atom.intervals)
		}
	}
	if repeated.isEmpty() {
		return nil
	}
	regions := []*intervalSet{repeated}
	seen := map[*intervalSet]bool{}
	for _, atom := range atoms {
		if seen[atom.intervals] {
			continue
		}
		seen[atom.intervals] = true
		regions = splitAlphabet(regions, []*intervalSet{atom.intervals})
	}
	var fills []rune
	for _, region := range regions {
		if member, ok := region.firstMember(); ok {
			fills = append(fills, rune(member))
		}
	}
	return fills
}

func splitAlphabet(regions []*intervalSet, constraints []*intervalSet) []*intervalSet {
	var result []*intervalSet
	for _, region := range regions {
		var parts []*intervalSet
		for _, constraint := range constraints {
			parts = append(parts, region.intersection(constraint), region.difference(constraint))
		}
		for _, part := range parts {
			if !part.isEmpty() {
				result = append(result, part)
			}
		}
	}
	return result
}

// hasLargeBoundedRepeat mirrors _has_large_bounded_repeat.
func hasLargeBoundedRepeat(pattern string, flags reFlags) bool {
	slots := patternSlots(pattern, flags)
	if slots == nil {
		return false
	}
	return slotsHaveLargeBoundedRepeat(slots)
}

func slotsHaveLargeBoundedRepeat(slots []reSlot) bool {
	for _, slot := range slots {
		if slotVariableBounded(slot) {
			return true
		}
		if s, ok := slot.(nonPairingSlot); ok && s.inner != nil {
			for _, alt := range s.inner {
				if slotsHaveLargeBoundedRepeat(alt) {
					return true
				}
			}
		}
	}
	return false
}
