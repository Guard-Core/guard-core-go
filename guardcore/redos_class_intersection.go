package guardcore

// Port of guard_core.detection_engine._redos_class_intersection: the
// pairing-chain walk that extracts (fill, stray) probe units for
// quantified class regions.

type fillStray struct {
	fill  rune
	stray string
}

// crossNonPairingSlot mirrors _cross_non_pairing_slot. The boolean result
// reports failure (None in the reference).
func crossNonPairingSlot(slot nonPairingSlot, shared *intervalSet, exactState *intervalSet) (*intervalSet, rune, bool, *intervalSet, bool) {
	if slot.inner == nil {
		if slot.isBoundary {
			return nil, 0, false, nil, false
		}
		return shared, 0, false, nil, true
	}
	crossing := groupCrossingResult(slot.inner, shared, 0)
	groupState := isolatedGroupExactState(slot.inner, 0)
	if crossing == nil {
		var fill rune
		var hasFill bool
		if slot.unbounded {
			fill, hasFill = exactOverlapFillRaw(exactState, groupState)
		}
		if slot.isBoundary {
			if !hasFill {
				return nil, 0, false, nil, false
			}
			return emptyIntervals(), fill, true, groupState, true
		}
		return shared, fill, hasFill, groupState, true
	}
	member, hasMember := crossing.firstMember()
	var fill rune
	hasFill := false
	if slot.unbounded && hasMember {
		fill = rune(member)
		hasFill = true
	}
	resultShared := shared
	if slot.isBoundary {
		resultShared = crossing
	}
	return resultShared, fill, hasFill, groupState, true
}

// groupCrossingResult mirrors _group_crossing_result.
func groupCrossingResult(alternatives [][]reSlot, shared *intervalSet, depth int) *intervalSet {
	if depth > maxGroupCrossingDepth {
		return nil
	}
	var combined *intervalSet
	for _, alt := range alternatives {
		result := alternativeCrossing(alt, shared, depth)
		if result == nil {
			continue
		}
		if combined == nil {
			combined = result
		} else {
			combined = combined.union(result)
		}
	}
	return combined
}

// alternativeCrossing mirrors _alternative_crossing.
func alternativeCrossing(altSlots []reSlot, shared *intervalSet, depth int) *intervalSet {
	local := shared
	for _, slot := range altSlots {
		switch s := slot.(type) {
		case pairingAtom:
			if s.allowsZero {
				continue
			}
			overlap := local.intersection(s.intervals)
			if overlap.isEmpty() {
				return nil
			}
			local = overlap
		case nonPairingSlot:
			if !s.isBoundary {
				continue
			}
			if s.inner == nil {
				return nil
			}
			crossing := groupCrossingResult(s.inner, local, depth+1)
			if crossing == nil {
				return nil
			}
			local = crossing
		}
	}
	return local
}

// tailPairingIntervals mirrors _tail_pairing_intervals.
func tailPairingIntervals(slots []reSlot, start int) []*intervalSet {
	var out []*intervalSet
	for i := start; i < len(slots); i++ {
		if atom, ok := slots[i].(pairingAtom); ok {
			out = append(out, atom.intervals)
		}
	}
	return out
}

// fillConfirmed mirrors _fill_confirmed: the Go slots carry no compiled
// predicate, so the interval membership check decides.
func fillConfirmed(left, right pairingAtom, fill rune) bool {
	return left.intervals.contains(int(fill)) && right.intervals.contains(int(fill))
}

func leftConfirmsFill(left pairingAtom, fill rune) bool {
	return left.intervals.contains(int(fill))
}

// appendPairingUnit mirrors _append_pairing_unit.
func appendPairingUnit(units *[]fillStray, left, right pairingAtom, fill rune, tail []*intervalSet, ctx *strayContext) error {
	if fillConfirmed(left, right, fill) {
		stray, err := chooseClassIntersectionStray(ctx, fill, left.intervals, right.intervals, tail)
		if err != nil {
			return err
		}
		*units = append(*units, fillStray{fill: fill, stray: stray})
	}
	return nil
}

// advancePairingChain mirrors _advance_pairing_chain; stop reports the
// should_stop verdict.
func advancePairingChain(units *[]fillStray, left pairingAtom, shared *intervalSet, slot pairingAtom, exactState *intervalSet, tail []*intervalSet, ctx *strayContext) (*intervalSet, *intervalSet, bool, error) {
	overlap := shared.intersection(slot.intervals)
	if !overlap.isEmpty() {
		if slot.unbounded {
			member, _ := overlap.firstMember()
			if err := appendPairingUnit(units, left, slot, rune(member), tail, ctx); err != nil {
				return nil, nil, false, err
			}
		}
		if !slot.allowsZero {
			shared = overlap
			exactState = narrowExactStateRaw(exactState, slot.intervals)
		}
		return shared, exactState, false, nil
	}
	exactFill, hasExactFill := exactOverlapFillRaw(exactState, slot.intervals)
	if !hasExactFill {
		return shared, exactState, !slot.allowsZero, nil
	}
	if slot.unbounded {
		if err := appendPairingUnit(units, left, slot, exactFill, tail, ctx); err != nil {
			return nil, nil, false, err
		}
	}
	if !slot.allowsZero {
		shared = overlap
		exactState = nil
	}
	return shared, exactState, false, nil
}

// pairingUnitsFrom mirrors _pairing_units_from.
func pairingUnitsFrom(slots []reSlot, start int, ctx *strayContext) ([]fillStray, error) {
	left, ok := slots[start].(pairingAtom)
	if !ok {
		return nil, nil
	}
	shared := left.intervals
	exactState := left.intervals
	var units []fillStray
	for index := start + 1; index < len(slots); index++ {
		slot := slots[index]
		tail := tailPairingIntervals(slots, index+1)
		if np, isNp := slot.(nonPairingSlot); isNp {
			crossed, fill, hasFill, groupState, ok2 := crossNonPairingSlot(np, shared, exactState)
			if !ok2 {
				break
			}
			shared = crossed
			if np.isBoundary {
				exactState = narrowExactStateRaw(exactState, groupState)
			}
			if hasFill && leftConfirmsFill(left, fill) {
				stray, err := chooseClassIntersectionStray(ctx, fill, left.intervals, shared, tail)
				if err != nil {
					return nil, err
				}
				units = append(units, fillStray{fill: fill, stray: stray})
			}
			continue
		}
		atom := slot.(pairingAtom)
		var err error
		var stop bool
		shared, exactState, stop, err = advancePairingChain(&units, left, shared, atom, exactState, tail, ctx)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
	}
	return units, nil
}

// flattenAlternatives mirrors _flatten_alternatives.
func flattenAlternatives(alternatives [][]reSlot) []reSlot {
	if len(alternatives) == 1 {
		return alternatives[0]
	}
	var flat []reSlot
	for index, alt := range alternatives {
		if index > 0 {
			flat = append(flat, nonPairingSlot{isBoundary: true})
		}
		flat = append(flat, alt...)
	}
	return flat
}

// unitsInSlots mirrors _units_in_slots.
func unitsInSlots(slots []reSlot, ctx *strayContext) ([]fillStray, error) {
	var units []fillStray
	for index, slot := range slots {
		if np, ok := slot.(nonPairingSlot); ok {
			if np.inner != nil {
				groupUnits, err := unitsInSlots(flattenAlternatives(np.inner), ctx)
				if err != nil {
					return nil, err
				}
				units = append(units, groupUnits...)
			}
			continue
		}
		if atom, isAtom := slot.(pairingAtom); isAtom && atom.unbounded {
			more, err := pairingUnitsFrom(slots, index, ctx)
			if err != nil {
				return nil, err
			}
			units = append(units, more...)
		}
	}
	return units, nil
}

// includeBoundedRepeats mirrors _include_bounded_repeats.
func includeBoundedRepeats(slots []reSlot) []reSlot {
	result := make([]reSlot, 0, len(slots))
	for _, slot := range slots {
		repeating := false
		switch s := slot.(type) {
		case pairingAtom:
			repeating = s.unbounded || (s.maxRepeat != noMaxRepeat && s.maxRepeat > 1)
		case nonPairingSlot:
			repeating = s.unbounded || (s.maxRepeat != noMaxRepeat && s.maxRepeat > 1)
		}
		if np, ok := slot.(nonPairingSlot); ok && np.inner != nil {
			inner := make([][]reSlot, 0, len(np.inner))
			for _, alt := range np.inner {
				inner = append(inner, includeBoundedRepeats(alt))
			}
			np.inner = inner
			slot = np
		}
		switch s := slot.(type) {
		case pairingAtom:
			s.unbounded = repeating
			result = append(result, s)
		case nonPairingSlot:
			s.unbounded = repeating
			result = append(result, s)
		}
	}
	return result
}

// classIntersectionProbeUnits mirrors _class_intersection_probe_units.
func classIntersectionProbeUnits(pattern string, flags reFlags, ctx *strayContext, includeBounded bool) ([]fillStray, error) {
	slots := patternSlots(pattern, flags)
	if slots == nil {
		return nil, nil
	}
	if ctx == nil {
		var err error
		ctx, err = buildStrayContext(pattern, flags)
		if err != nil {
			return nil, err
		}
	}
	if includeBounded {
		slots = includeBoundedRepeats(slots)
	}
	return unitsInSlots(slots, ctx)
}
