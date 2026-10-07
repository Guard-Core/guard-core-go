package guardcore

// Escape sequences, character classes and character-member intervals for
// the Python-re-compatible safety parser (companion to redos_parser.go).
// Member intervals feed the parse-slots layer that replaces re._parser's
// typed opcodes.

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// category intervals computed once per (category, ascii) pair; mirrors
// _redos_intervals.cached_category_intervals.
var categoryIntervalCache syncMapIntervalCache

type syncMapIntervalCache struct {
	entries map[categoryCacheKey]*intervalSet
}

type categoryCacheKey struct {
	category int
	ascii    bool
}

func cachedCategoryIntervals(category int, ascii bool) *intervalSet {
	key := categoryCacheKey{category: category, ascii: ascii}
	if iv, ok := categoryIntervalCache.lookup(key); ok {
		return iv
	}
	iv := computeCategoryIntervals(category, ascii)
	categoryIntervalCache.store(key, iv)
	return iv
}

func (c *syncMapIntervalCache) lookup(key categoryCacheKey) (*intervalSet, bool) {
	if c.entries == nil {
		return nil, false
	}
	iv, ok := c.entries[key]
	return iv, ok
}

func (c *syncMapIntervalCache) store(key categoryCacheKey, iv *intervalSet) {
	if c.entries == nil {
		c.entries = map[categoryCacheKey]*intervalSet{}
	}
	c.entries[key] = iv
}

func categoryPredicate(category int, ascii bool) func(rune) bool {
	switch category {
	case catDigit:
		if ascii {
			return func(r rune) bool { return r >= '0' && r <= '9' }
		}
		return unicode.IsDigit
	case catNotDigit:
		if ascii {
			return func(r rune) bool { return !(r >= '0' && r <= '9') }
		}
		return func(r rune) bool { return !unicode.IsDigit(r) }
	case catSpace:
		if ascii {
			return func(r rune) bool {
				switch r {
				case ' ', '\t', '\n', '\r', '\f', '\v':
					return true
				}
				return false
			}
		}
		return unicode.IsSpace
	case catNotSpace:
		if ascii {
			return func(r rune) bool {
				switch r {
				case ' ', '\t', '\n', '\r', '\f', '\v':
					return false
				}
				return true
			}
		}
		return func(r rune) bool { return !unicode.IsSpace(r) }
	case catWord:
		if ascii {
			return func(r rune) bool {
				return r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			}
		}
		return func(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) }
	case catNotWord:
		if ascii {
			return func(r rune) bool {
				return !(r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'))
			}
		}
		return func(r rune) bool { return !(r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)) }
	}
	return func(rune) bool { return true }
}

func computeCategoryIntervals(category int, ascii bool) *intervalSet {
	pred := categoryPredicate(category, ascii)
	var pairs []redosInterval
	start := -1
	for cp := 0; cp <= maxCodePoint; cp++ {
		if pred(rune(cp)) {
			if start < 0 {
				start = cp
			}
			continue
		}
		if start >= 0 {
			pairs = append(pairs, redosInterval{low: start, high: cp - 1})
			start = -1
		}
	}
	if start >= 0 {
		pairs = append(pairs, redosInterval{low: start, high: maxCodePoint})
	}
	return newIntervalSet(pairs)
}

// anyIntervals mirrors _any_intervals: full range, minus newline unless
// DOTALL.
func anyIntervals(flags reFlags) *intervalSet {
	if flags&flagDotAll != 0 {
		return fullIntervals()
	}
	return fullIntervals().difference(singleInterval('\n'))
}

// expandIgnoreCase mirrors _apply_ignorecase: case closure over the set's
// members (bounded scan like the reference's member-scan ceiling).
func expandIgnoreCase(iv *intervalSet, flags reFlags) *intervalSet {
	if flags&flagIgnoreCase == 0 {
		return iv
	}
	var pairs []redosInterval
	for _, interval := range iv.intervals {
		ceiling := interval.low + 4096
		if ceiling > interval.high+1 {
			ceiling = interval.high + 1
		}
		for cp := interval.low; cp < ceiling; cp++ {
			r := rune(cp)
			pairs = append(pairs, redosInterval{low: cp, high: cp})
			if lo := unicode.ToLower(r); lo != r {
				pairs = append(pairs, redosInterval{low: int(lo), high: int(lo)})
			}
			if up := unicode.ToUpper(r); up != r {
				pairs = append(pairs, redosInterval{low: int(up), high: int(up)})
			}
		}
		if interval.high >= ceiling {
			pairs = append(pairs, redosInterval{low: ceiling, high: interval.high})
		}
	}
	return newIntervalSet(pairs)
}

// parseEscapeAtom parses a backslash escape outside a character class.
func (p *reParser) parseEscapeAtom() (*reNode, error) {
	start := p.pos
	p.pos++ // consume '\'
	if p.pos >= len(p.src) {
		return nil, parseErrorAt("bad escape (end of pattern)", start)
	}
	c := p.src[p.pos]
	switch c {
	case 'd', 'D', 'w', 'W', 's', 'S':
		p.pos++
		cat := escapeCategory(c)
		return &reNode{op: opIn, interval: categoryIntervalsFor(cat, p.flags), category: cat, flags: p.flags}, nil
	case 'b':
		p.pos++
		return &reNode{op: opAt, anchor: atBoundary, flags: p.flags}, nil
	case 'B':
		p.pos++
		return &reNode{op: opAt, anchor: atNonBoundary, flags: p.flags}, nil
	case 'A':
		p.pos++
		return &reNode{op: opAt, anchor: atBeginString, flags: p.flags}, nil
	case 'Z':
		p.pos++
		return &reNode{op: opAt, anchor: atEndString, flags: p.flags}, nil
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return p.parseDecimalEscape(start)
	case 'x':
		p.pos++
		ch, err := p.parseHexEscape(start, 2)
		if err != nil {
			return nil, err
		}
		return p.literalNode(ch), nil
	case 'u':
		p.pos++
		ch, err := p.parseHexEscape(start, 4)
		if err != nil {
			return nil, err
		}
		return p.literalNode(ch), nil
	case 'U':
		p.pos++
		ch, err := p.parseHexEscape(start, 8)
		if err != nil {
			return nil, err
		}
		return p.literalNode(ch), nil
	case 'N':
		// named unicode character: the safety parser rejects the full name
		// database fail-closed (a valid-Python pattern rejected here is a
		// documented, safe divergence).
		return nil, parseErrorAt("unknown extension \\N", start)
	default:
		if isASCIILetter(rune(c)) {
			ch, ok := simpleEscapeChar(c)
			if !ok {
				return nil, parseErrorAt(fmt.Sprintf("bad escape \\%s", string(c)), start)
			}
			p.pos++
			return p.literalNode(ch), nil
		}
		// punctuation and non-ASCII escapes are literal
		p.pos++
		return p.literalNode(rune(c)), nil
	}
}

func escapeCategory(c byte) int {
	switch c {
	case 'd':
		return catDigit
	case 'D':
		return catNotDigit
	case 'w':
		return catWord
	case 'W':
		return catNotWord
	case 's':
		return catSpace
	case 'S':
		return catNotSpace
	}
	return catDigit
}

func categoryIntervalsFor(category int, flags reFlags) *intervalSet {
	ascii := flags&flagASCII != 0
	iv := cachedCategoryIntervals(category, ascii)
	if flags&flagIgnoreCase != 0 && !ascii {
		iv = expandIgnoreCase(iv, flags)
	}
	return iv
}

func simpleEscapeChar(c byte) (rune, bool) {
	switch c {
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	case 'f':
		return '\f', true
	case 'v':
		return '\v', true
	case 'a':
		return 7, true
	}
	return 0, false
}

// parseDecimalEscape mirrors sre_parse's digit-escape rule: a leading zero
// is octal; leading 1-9 followed by two more octal digits is octal; the
// remaining digit runs are group references (valid only below the
// groups-opened counter and for closed groups).
func (p *reParser) parseDecimalEscape(start int) (*reNode, error) {
	c := p.src[p.pos]
	if c == '0' {
		digits := "0"
		p.pos++
		for i := 0; i < 2 && p.pos < len(p.src) && isOctalDigit(p.src[p.pos]); i++ {
			digits += string(p.src[p.pos])
			p.pos++
		}
		ch, err := parseOctalDigits(digits, start)
		if err != nil {
			return nil, err
		}
		return p.literalNode(ch), nil
	}
	digits := string(c)
	p.pos++
	if p.pos < len(p.src) && isDecimalDigit(p.src[p.pos]) {
		digits += string(p.src[p.pos])
		p.pos++
		if isOctalDigit(digits[0]) && isOctalDigit(digits[1]) &&
			p.pos < len(p.src) && isOctalDigit(p.src[p.pos]) {
			digits += string(p.src[p.pos])
			p.pos++
			ch, err := parseOctalDigits(digits, start)
			if err != nil {
				return nil, err
			}
			return p.literalNode(ch), nil
		}
	}
	return p.parseGroupReference(start, digits)
}

func parseOctalDigits(digits string, start int) (rune, error) {
	val, err := strconv.ParseInt(digits, 8, 32)
	if err != nil || val > 0o377 {
		return 0, parseErrorAt(fmt.Sprintf("octal escape value \\%s outside of range 0-0o377", digits), start)
	}
	return rune(val), nil
}

func isOctalDigit(c byte) bool {
	return c >= '0' && c <= '7'
}

func isDecimalDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func (p *reParser) parseGroupReference(start int, digits string) (*reNode, error) {
	group, _ := strconv.Atoi(digits)
	if group < p.groups {
		if p.openGroups[group] {
			return nil, parseErrorAt("cannot refer to an open group", start)
		}
		return &reNode{op: opGroupRef, refIdx: group, flags: p.flags}, nil
	}
	return nil, parseErrorAt(fmt.Sprintf("invalid group reference %d", group), start)
}

func (p *reParser) parseHexEscape(start int, width int) (rune, error) {
	if p.pos+width > len(p.src) {
		return 0, parseErrorAt(fmt.Sprintf("incomplete escape \\%s", mapWidth(width)), start)
	}
	text := p.src[p.pos : p.pos+width]
	val, err := strconv.ParseUint(text, 16, 32)
	if err != nil {
		return 0, parseErrorAt("incomplete escape", start)
	}
	p.pos += width
	return rune(val), nil
}

func mapWidth(width int) string {
	switch width {
	case 2:
		return "x"
	case 4:
		return "u"
	default:
		return "U"
	}
}

// parseCharClass parses a [...] character class into a member-interval
// node (re._parser IN op equivalent).
func (p *reParser) parseCharClass() (*reNode, error) {
	start := p.pos
	p.pos++ // consume '['
	negated := false
	if p.pos < len(p.src) && p.src[p.pos] == '^' {
		negated = true
		p.pos++
	}
	members := emptyIntervals()
	first := true
	for {
		if p.pos >= len(p.src) {
			return nil, parseErrorAt("unterminated character set", start)
		}
		c := p.src[p.pos]
		if c == ']' && !first {
			p.pos++
			break
		}
		first = false
		low, isClass, classIv, err := p.parseClassAtom()
		if err != nil {
			return nil, err
		}
		if isClass {
			members = members.union(classIv)
			continue
		}
		// range?
		if p.pos+1 < len(p.src) && p.src[p.pos] == '-' && p.src[p.pos+1] != ']' {
			p.pos++ // consume '-'
			high, isClass2, classIv2, err := p.parseClassAtom()
			if err != nil {
				return nil, err
			}
			if isClass2 {
				// Python: bad character range if either side is a class
				return nil, parseErrorAt("bad character range", start)
			}
			_ = classIv2
			if int(high) < int(low) {
				return nil, parseErrorAt("bad character range", start)
			}
			iv := rangeIntervals(int(low), int(high))
			if p.flags&flagIgnoreCase != 0 {
				iv = expandIgnoreCase(iv, p.flags)
			}
			members = members.union(iv)
			continue
		}
		members = members.union(p.classLiteralIntervals(low))
	}
	if negated {
		members = members.complement()
	}
	return &reNode{op: opIn, interval: members, flags: p.flags}, nil
}

func (p *reParser) classLiteralIntervals(ch rune) *intervalSet {
	iv := singleInterval(int(ch))
	if p.flags&flagIgnoreCase != 0 {
		iv = expandIgnoreCase(iv, p.flags)
	}
	return iv
}

// parseClassAtom parses one class member; isClass reports a category/class
// escape whose intervals are returned directly.
func (p *reParser) parseClassAtom() (rune, bool, *intervalSet, error) {
	c := p.src[p.pos]
	if c != '\\' {
		p.pos++
		return rune(c), false, nil, nil
	}
	start := p.pos
	p.pos++
	if p.pos >= len(p.src) {
		return 0, false, nil, parseErrorAt("bad escape (end of pattern)", start)
	}
	e := p.src[p.pos]
	switch e {
	case 'd', 'D', 'w', 'W', 's', 'S':
		p.pos++
		cat := escapeCategory(e)
		return 0, true, categoryIntervalsFor(cat, p.flags), nil
	case 'b':
		// backspace inside a class
		p.pos++
		return 8, false, nil, nil
	case 'x':
		p.pos++
		ch, err := p.parseHexEscape(start, 2)
		if err != nil {
			return 0, false, nil, err
		}
		return ch, false, nil, nil
	case 'u':
		p.pos++
		ch, err := p.parseHexEscape(start, 4)
		if err != nil {
			return 0, false, nil, err
		}
		return ch, false, nil, nil
	case 'U':
		p.pos++
		ch, err := p.parseHexEscape(start, 8)
		if err != nil {
			return 0, false, nil, err
		}
		return ch, false, nil, nil
	case '0', '1', '2', '3', '4', '5', '6', '7':
		// octal escape inside a class (no group references there)
		digits := string(p.src[p.pos])
		p.pos++
		for i := 0; i < 2 && p.pos < len(p.src) && isOctalDigit(p.src[p.pos]); i++ {
			digits += string(p.src[p.pos])
			p.pos++
		}
		val, err := strconv.ParseInt(digits, 8, 32)
		if err != nil || val > 0o377 {
			return 0, false, nil, parseErrorAt(fmt.Sprintf("octal escape value %s outside of range 0-0o377", digits), start)
		}
		return rune(val), false, nil, nil
	case 'N':
		return 0, false, nil, parseErrorAt("unknown extension \\N", start)
	default:
		if isASCIILetter(rune(e)) {
			ch, ok := simpleEscapeChar(e)
			if !ok {
				return 0, false, nil, parseErrorAt(fmt.Sprintf("bad escape \\%s", string(e)), start)
			}
			p.pos++
			return ch, false, nil, nil
		}
		p.pos++
		return rune(e), false, nil, nil
	}
}

// validateGroupName enforces Python's group-name identifier grammar and
// returns the Python-style error for bad names.
func validateGroupNameError(name string, pos int) error {
	if name == "" {
		return parseErrorAt("missing group name", pos)
	}
	for i, ch := range name {
		valid := ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(i > 0 && ch >= '0' && ch <= '9')
		if !valid {
			return parseErrorAt(fmt.Sprintf("bad character in group name '%s'", name), pos)
		}
	}
	return nil
}

var _ = strings.TrimSpace
