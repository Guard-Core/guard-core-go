package guardcore

// Port of guard_core.detection_engine._redos_probe_fill and the probe
// builders it composes: the adversarial probe families the reach-probe
// cost arbiter times (repeat-alphabet fills, class-intersection units,
// prefixed repeat probes, literal runs, reaching-probe prefixes and
// ambiguous group fill units).

import (
	"sort"
	"strings"
)

const (
	reachProbeMaxRunVariants    = 12
	reachProbeMaxTimedProbeSets = 512
)

// reachProbePrefixCutLengths mirrors _REACH_PROBE_PREFIX_CUT_LENGTHS.
var reachProbePrefixCutLengths = [3]int{20, 30, 50}

// probeBuilder maps a probe length to the adversarial probe string.
type probeBuilder func(length int) string

// repeatUnitBuilder mirrors _repeat_unit_builder.
func repeatUnitBuilder(ctx *strayContext, unit string) probeBuilder {
	stray, err := chooseRepeatUnitStray(ctx, unit)
	if err != nil {
		stray = reachProbeStrayByte
	}
	return func(length int) string {
		return repeatProbeToLength(unit, length, stray)
	}
}

// literalRunBuilders mirrors _literal_run_builders.
func literalRunBuilders(pattern string, ctx *strayContext) []probeBuilder {
	runs := adversarialLiteralRuns(pattern)
	if len(runs) > reachProbeMaxRunVariants {
		runs = runs[:reachProbeMaxRunVariants]
	}
	builders := make([]probeBuilder, 0, len(runs))
	for _, run := range runs {
		builders = append(builders, repeatUnitBuilder(ctx, run))
	}
	return builders
}

// reachProbePrefixBuilders mirrors _reach_probe_prefix_builders.
func reachProbePrefixBuilders(pattern string, ctx *strayContext) []probeBuilder {
	fullProbe, ok := synthesizeReachingProbe(pattern)
	if !ok || fullProbe == "" {
		return nil
	}
	bodyOnly := strings.ReplaceAll(fullProbe[:len(fullProbe)-1], "?", "")
	var builders []probeBuilder
	for _, cut := range reachProbePrefixCutLengths {
		end := cut
		if end > len(bodyOnly) {
			end = len(bodyOnly)
		}
		prefix := bodyOnly[:end]
		if len(prefix) >= 2 {
			builders = append(builders, repeatUnitBuilder(ctx, prefix))
		}
	}
	return builders
}

// classIntersectionBuilders mirrors _class_intersection_builders.
func classIntersectionBuilders(pattern string, flags reFlags, ctx *strayContext) ([]probeBuilder, error) {
	prefix := leadingLiteralPrefix(pattern)
	units, err := classIntersectionProbeUnits(pattern, flags, ctx, true)
	if err != nil {
		return nil, err
	}
	builders := make([]probeBuilder, 0, len(units))
	for _, unit := range units {
		fill, stray := string(unit.fill), string(unit.stray)
		builders = append(builders, func(length int) string {
			return fillToLength(prefix, fill, stray, length)
		})
	}
	return builders, nil
}

// ambiguousGroupFillUnit mirrors _ambiguous_group_fill_unit.
func ambiguousGroupFillUnit(inner string) (string, bool) {
	atoms := parseFlatQuantifiedAtomsWithText(inner)
	if atoms == nil {
		return "", false
	}
	var unit strings.Builder
	for _, atom := range atoms {
		ch, ok := representativeCharForAtom(atom.text)
		if !ok {
			return "", false
		}
		unit.WriteRune(ch)
	}
	if unit.Len() == 0 {
		return "", false
	}
	return unit.String(), true
}

// ambiguousGroupFillBuilders mirrors _ambiguous_group_fill_builders.
func ambiguousGroupFillBuilders(pattern string, ctx *strayContext) ([]probeBuilder, error) {
	var builders []probeBuilder
	bodies, err := iterQuantifiedGroupBodies(pattern, 0, 0)
	if err != nil {
		return nil, nil
	}
	for _, body := range bodies {
		if !groupInnerIsAmbiguous(body.inner) {
			continue
		}
		unit, ok := ambiguousGroupFillUnit(body.inner)
		if ok {
			builders = append(builders, repeatUnitBuilder(ctx, unit))
		}
	}
	return builders, nil
}

// repeatGroupUnits mirrors _repeat_group_units: (prefix, unit) pairs for
// repeated group bodies. The reference derives these through the full
// prefix-state walk; this port walks the quantified group bodies directly
// and derives the same unit texts from the body's representative chars.
func repeatGroupUnits(pattern string, flags reFlags) ([][2]string, error) {
	parsed, err := parseRedosPattern(pattern, flags)
	if err != nil {
		return nil, nil
	}
	type groupPair struct {
		prefix string
		unit   string
	}
	var pairs []groupPair
	seen := map[[2]string]bool{}
	pairTextSize := 0
	var walk func(nodes []reNode, prefix string) error
	addPair := func(prefix, unit string) {
		if unit == "" {
			return
		}
		pair := [2]string{prefix, unit}
		if seen[pair] {
			return
		}
		seen[pair] = true
		pairs = append(pairs, groupPair{prefix: prefix, unit: unit})
		pairTextSize += len(prefix) + len(unit)
	}
	walk = func(nodes []reNode, prefix string) error {
		for i := range nodes {
			node := &nodes[i]
			if node.op == opRepeat && node.max >= maxRepeat {
				// a repeated body: derive the fill unit of its flat atom
				// sequence (the reference's repeated-body units)
				body := node.body
				inner := body
				if len(body) == 1 && body[0].op == opSubPattern {
					inner = body[0].body
				}
				flat := true
				for j := range inner {
					switch inner[j].op {
					case opBranch, opSubPattern, opAssert, opGroupRef:
						flat = false
					case opRepeat:
						// single-atom repeats contribute their atom; nested
						// multi-atom repeats are not flat
						if len(inner[j].body) != 1 {
							flat = false
						}
					}
				}
				if flat {
					var unit strings.Builder
					ok := true
					for j := range inner {
						atom := &inner[j]
						if atom.op == opRepeat {
							atom = &atom.body[0]
						}
						ch, hasRep := representativeCharForNode(atom, defaultPatternFlags)
						if !hasRep {
							ok = false
							break
						}
						unit.WriteRune(ch)
					}
					if ok {
						addPair(prefix, unit.String())
					}
				} else {
					// nested structure: recurse for deeper repeat pairs
					if err := walk(inner, prefix); err != nil {
						return err
					}
				}
			}
			if len(node.body) > 0 {
				if err := walk(node.body, prefix); err != nil {
					return err
				}
			}
			for _, branch := range node.branches {
				if err := walk(branch, prefix); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(parsed.nodes, ""); err != nil {
		return nil, err
	}
	out := make([][2]string, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, [2]string{pair.prefix, pair.unit})
	}
	return out, nil
}

// representativeCharForNode picks the representative printable character
// for a parsed atom node (the prefix walk's per-atom fill character).
func representativeCharForNode(node *reNode, flags reFlags) (rune, bool) {
	iv := nodeIntervals(node, flags)
	if iv.isEmpty() {
		return 0, false
	}
	for _, r := range printableRunes {
		if iv.contains(int(r)) {
			return r, true
		}
	}
	if first, ok := iv.firstMember(); ok {
		return rune(first), true
	}
	return 0, false
}

// repeatReachingPrefixes mirrors _repeat_reaching_prefixes: the reaching
// prefixes of the pattern (leading literal text plus the synthesized
// probe's leading cuts).
func repeatReachingPrefixes(pattern string, flags reFlags) []string {
	var prefixes []string
	prefix := leadingLiteralPrefix(pattern)
	if len(prefix) >= 2 {
		prefixes = append(prefixes, prefix)
	}
	fullProbe, ok := synthesizeReachingProbe(pattern)
	if ok && fullProbe != "" {
		bodyOnly := strings.ReplaceAll(fullProbe[:len(fullProbe)-1], "?", "")
		for _, cut := range reachProbePrefixCutLengths {
			end := cut
			if end > len(bodyOnly) {
				end = len(bodyOnly)
			}
			if end >= 2 {
				prefixes = append(prefixes, bodyOnly[:end])
			}
		}
	}
	return dedupStrings(prefixes)
}

func dedupStrings(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

// reachProbeCandidateBuilders mirrors _reach_probe_candidate_builders.
func reachProbeCandidateBuilders(pattern string, flags reFlags) ([]probeBuilder, error) {
	ctx, err := buildStrayContext(pattern, flags)
	if err != nil {
		return nil, err
	}
	repeatFills := repeatAlphabetFills(pattern, flags)
	classUnits, err := classIntersectionProbeUnits(pattern, flags, ctx, true)
	if err != nil {
		return nil, err
	}
	groupPairs, err := repeatGroupUnits(pattern, flags)
	if err != nil {
		return nil, err
	}
	groupStrays := patternComplementChars(pattern, flags)

	// prefixed unit builders over (prefixes x units x flood)
	classPrefixUnits := make([]fillStray, 0, len(classUnits)*2)
	classPrefixUnits = append(classPrefixUnits, classUnits...)
	for _, unit := range classUnits {
		for _, stray := range groupStrays {
			classPrefixUnits = append(classPrefixUnits, fillStray{fill: unit.fill, stray: string(stray)})
		}
	}
	var classPrefixes []string
	if len(classUnits) > 0 {
		classPrefixes = append([]string{""}, repeatReachingPrefixes(pattern, flags)...)
	}

	builders := make([]probeBuilder, 0, 64)
	for _, fill := range repeatFills {
		fillStr := string(fill)
		prefix := ctx.prefix
		builders = append(builders, func(length int) string {
			return fillToLength(prefix, fillStr, fillStr, length)
		})
	}
	ciBuilders, err := classIntersectionBuilders(pattern, flags, ctx)
	if err != nil {
		return nil, err
	}
	builders = append(builders, ciBuilders...)
	for _, prefix := range classPrefixes {
		for _, unit := range dedupFillStrays(classPrefixUnits) {
			fill, stray := string(unit.fill), string(unit.stray)
			for _, flood := range []bool{false, true} {
				builders = append(builders, func(length int) string {
					return prefixedRepeatProbe(prefix, fill, stray, flood, length)
				})
			}
		}
	}
	for _, pair := range groupPairs {
		prefix, unitText := pair[0], pair[1]
		primaryStray, _ := chooseRepeatUnitStray(ctx, unitText)
		strays := dedupStrings(append([]string{primaryStray}, runesToStrings(groupStrays)...))
		for _, stray := range strays {
			for _, pfx := range dedupStrings([]string{prefix, ""}) {
				for _, flood := range []bool{false, true} {
					builders = append(builders, func(length int) string {
						return prefixedRepeatProbe(pfx, unitText, stray, flood, length)
					})
				}
			}
		}
	}
	builders = append(builders, literalRunBuilders(pattern, ctx)...)
	builders = append(builders, reachProbePrefixBuilders(pattern, ctx)...)
	for _, unit := range classUnits {
		fill, stray := string(unit.fill), string(unit.stray)
		builders = append(builders, func(length int) string {
			return prefixedRepeatProbe(ctx.prefix, fill, stray, false, length)
		})
	}
	agfBuilders, err := ambiguousGroupFillBuilders(pattern, ctx)
	if err != nil {
		return nil, err
	}
	builders = append(builders, agfBuilders...)
	return builders, nil
}

func dedupFillStrays(units []fillStray) []fillStray {
	seen := map[fillStray]bool{}
	out := make([]fillStray, 0, len(units))
	for _, unit := range units {
		if seen[unit] {
			continue
		}
		seen[unit] = true
		out = append(out, unit)
	}
	return out
}

func runesToStrings(runes []rune) []string {
	out := make([]string, 0, len(runes))
	for _, r := range runes {
		out = append(out, string(r))
	}
	return out
}

// uniqueProbeSets mirrors _unique_probe_sets: dedupe builder output tuples
// per size combination.
func uniqueProbeSets(builders []probeBuilder, sizes []int) [][]string {
	seen := map[string]bool{}
	var sets [][]string
	for _, builder := range builders {
		probes := make([]string, 0, len(sizes))
		for _, size := range sizes {
			probes = append(probes, builder(size))
		}
		digest := strings.Join(probes, "\x00")
		if seen[digest] {
			continue
		}
		seen[digest] = true
		sets = append(sets, probes)
	}
	return sets
}

// strideSampledProbeSets mirrors _stride_sampled_probe_sets.
func strideSampledProbeSets(sets [][]string, cap int) [][]string {
	total := len(sets)
	if total <= cap {
		return sets
	}
	stride := (total + cap - 1) / cap
	var sampled [][]string
	for i := 0; i < total; i += stride {
		sampled = append(sampled, sets[i])
	}
	return sampled
}

var _ = sort.Ints
