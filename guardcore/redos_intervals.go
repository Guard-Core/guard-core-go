package guardcore

// Port of guard_core.detection_engine._redos_intervals: a sorted,
// non-overlapping set of inclusive Unicode code-point intervals with the
// union / intersection / complement / difference algebra the ReDoS static
// safety layer needs. Inclusive [low, high] bounds mirror the Python
// implementation exactly.

const (
	minCodePoint = 0
	maxCodePoint = 0x10FFFF
)

type redosInterval struct {
	low  int
	high int
}

type intervalSet struct {
	intervals []redosInterval
}

func normalizeIntervals(pairs []redosInterval) []redosInterval {
	if len(pairs) == 0 {
		return nil
	}
	sorted := make([]redosInterval, len(pairs))
	copy(sorted, pairs)
	sortRedosIntervals(sorted)
	merged := make([]redosInterval, 0, len(sorted))
	merged = append(merged, sorted[0])
	for _, pair := range sorted[1:] {
		last := &merged[len(merged)-1]
		if pair.low <= last.high+1 {
			if pair.high > last.high {
				last.high = pair.high
			}
			continue
		}
		merged = append(merged, pair)
	}
	return merged
}

func sortRedosIntervals(items []redosInterval) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].low < items[j-1].low; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func emptyIntervals() *intervalSet {
	return &intervalSet{}
}

func fullIntervals() *intervalSet {
	return &intervalSet{intervals: []redosInterval{{low: minCodePoint, high: maxCodePoint}}}
}

func singleInterval(codePoint int) *intervalSet {
	return &intervalSet{intervals: []redosInterval{{low: codePoint, high: codePoint}}}
}

func rangeIntervals(low, high int) *intervalSet {
	if low < minCodePoint {
		low = minCodePoint
	}
	if high > maxCodePoint {
		high = maxCodePoint
	}
	if low > high {
		return emptyIntervals()
	}
	return &intervalSet{intervals: []redosInterval{{low: low, high: high}}}
}

func newIntervalSet(pairs []redosInterval) *intervalSet {
	return &intervalSet{intervals: normalizeIntervals(pairs)}
}

func (s *intervalSet) isEmpty() bool {
	return len(s.intervals) == 0
}

func (s *intervalSet) contains(codePoint int) bool {
	lo, hi := 0, len(s.intervals)
	for lo < hi {
		mid := (lo + hi) / 2
		iv := s.intervals[mid]
		switch {
		case codePoint < iv.low:
			hi = mid
		case codePoint > iv.high:
			lo = mid + 1
		default:
			return true
		}
	}
	return false
}

func (s *intervalSet) firstMember() (int, bool) {
	if len(s.intervals) == 0 {
		return 0, false
	}
	return s.intervals[0].low, true
}

func (s *intervalSet) componentFirstMembers() []int {
	out := make([]int, 0, len(s.intervals))
	for _, iv := range s.intervals {
		out = append(out, iv.low)
	}
	return out
}

func (s *intervalSet) union(other *intervalSet) *intervalSet {
	merged := make([]redosInterval, 0, len(s.intervals)+len(other.intervals))
	merged = append(merged, s.intervals...)
	merged = append(merged, other.intervals...)
	return newIntervalSet(merged)
}

func (s *intervalSet) intersection(other *intervalSet) *intervalSet {
	var result []redosInterval
	i, j := 0, 0
	left, right := s.intervals, other.intervals
	for i < len(left) && j < len(right) {
		a, b := left[i], right[j]
		low := maxInt(a.low, b.low)
		high := minInt(a.high, b.high)
		if low <= high {
			result = append(result, redosInterval{low: low, high: high})
		}
		if a.high < b.high {
			i++
		} else {
			j++
		}
	}
	return &intervalSet{intervals: normalizeIntervals(result)}
}

func (s *intervalSet) complement() *intervalSet {
	var result []redosInterval
	cursor := minCodePoint
	for _, iv := range s.intervals {
		if iv.low > cursor {
			result = append(result, redosInterval{low: cursor, high: iv.low - 1})
		}
		cursor = iv.high + 1
	}
	if cursor <= maxCodePoint {
		result = append(result, redosInterval{low: cursor, high: maxCodePoint})
	}
	return &intervalSet{intervals: normalizeIntervals(result)}
}

func (s *intervalSet) difference(other *intervalSet) *intervalSet {
	return s.intersection(other.complement())
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
