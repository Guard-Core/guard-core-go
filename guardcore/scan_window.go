package guardcore

import (
	"sort"
	"time"

	"github.com/dlclark/regexp2"
)

const windowTimeout = 2000 * time.Millisecond

type regexp2P = regexp2.Regexp

func terminatorEnds(re *regexp2P, t scanText) []int {
	var out []int
	for _, m := range findAllMatches(re, t) {
		out = append(out, m.end())
	}
	return out
}

type scanBound struct {
	prefix *regexp2P
	term   *regexp2P
}

func boundedFinditer(re *regexp2P, t scanText, bound scanBound) []rmatch {
	ends := terminatorEnds(bound.term, t)
	if len(ends) == 0 {
		return nil
	}
	ceiling := ends[len(ends)-1]

	var starts []int
	for _, m := range findAllMatches(bound.prefix, t) {
		starts = append(starts, m.start())
	}
	if len(starts) == 0 {
		return nil
	}

	var out []rmatch
	searchFrom := 0
	for {
		idx := sort.SearchInts(starts, searchFrom)
		var found *rmatch
		for i := idx; i < len(starts); i++ {
			if starts[i] >= ceiling {
				break
			}
			if m, ok := findFirstAt(re, t, starts[i], ceiling); ok {
				found = &m
				break
			}
		}
		if found == nil {
			return out
		}
		out = append(out, *found)
		if found.end() > found.start() {
			searchFrom = found.end()
		} else {
			searchFrom = found.start() + 1
		}
	}
}
