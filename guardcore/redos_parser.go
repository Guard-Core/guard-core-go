package guardcore

// A Python-re-compatible regular-expression parser for the ReDoS static
// safety layer. The reference safety chain
// (guard_core.detection_engine.compiler.PatternCompiler) validates patterns
// against CPython's sre grammar: a pattern the reference oracle rejects at
// compile time must be rejected here with the same verdict class, including
// constructs regexp2 accepts but Python re does not (atomic groups,
// possessive quantifiers, group references to undefined groups, ...).
//
// The parser is intentionally narrow: it models the sre grammar the
// reference engine accepts (Python 3.10 grammar is the corpus oracle), and
// rejects everything else fail-closed. It produces the AST shape the
// probe-synthesis machinery needs (member intervals per pairing atom,
// repeat bounds, group tables) in place of Python's re._parser module.

import (
	"fmt"
	"strings"
)

const (
	// maxRepeat mirrors re._parser.MAXREPEAT: the sentinel for an
	// unbounded quantifier upper bound.
	maxRepeat = 1 << 32
	// maxGroupNestingDepth mirrors _MAX_GROUP_NESTING_DEPTH.
	maxGroupNestingDepth = 20
	// nesting depth rejection reason text pins the reference message.
	nestingDepthRejectionReason = "pattern exceeds the maximum group nesting depth of 20 the ReDoS structural analyzer supports"
)

type reFlags int

const (
	flagIgnoreCase reFlags = 1 << iota
	flagMultiline
	flagDotAll
	flagASCII
	flagLocale
	flagVerbose
)

// reOp enumerates the AST operations the safety layer models.
type reOp int

const (
	opLiteral reOp = iota
	opNotLiteral
	opAny
	opIn
	opRepeat
	opBranch
	opSubPattern
	opAssert
	opAt
	opGroupRef
)

// anchor kinds for opAt.
const (
	atBeginning   = iota // ^
	atEnd                // $
	atBoundary           // \b
	atNonBoundary        // \B
	atBeginString        // \A
	atEndString          // \Z
)

// category kinds for category nodes.
const (
	catDigit = iota
	catNotDigit
	catSpace
	catNotSpace
	catWord
	catNotWord
)

type reNode struct {
	op        reOp
	ch        rune
	interval  *intervalSet
	min, max  int
	lazy      bool
	body      []reNode
	branches  [][]reNode
	groupIdx  int
	groupName string
	refIdx    int
	refName   string
	negative  bool
	behind    bool
	anchor    int
	category  int
	flags     reFlags
}

type redosParseError struct {
	msg string
	pos int
}

func (e *redosParseError) Error() string {
	return fmt.Sprintf("%s at position %d", e.msg, e.pos)
}

func parseErrorAt(msg string, pos int) *redosParseError {
	return &redosParseError{msg: msg, pos: pos}
}

type parsedPattern struct {
	nodes      []reNode
	groups     int
	groupNames map[string]int
	flags      reFlags
}

type reParser struct {
	src        string
	pos        int
	groups     int // groups opened so far (sre state.groups semantics)
	openGroups map[int]bool
	groupNames map[string]int
	flags      reFlags
	nesting    int
	overflow   bool // a repetition number exceeded the engine limit
}

// parseRedosPattern parses a pattern under Python re semantics with the
// given initial flags. Flags are the numeric equivalent of the reference's
// re.IGNORECASE | re.MULTILINE defaults.
func parseRedosPattern(pattern string, flags reFlags) (*parsedPattern, error) {
	p := &reParser{
		src: pattern,
		// sre_parse.State starts the group counter at 1; the first
		// opening parenthesis becomes group 1.
		groups:     1,
		openGroups: map[int]bool{},
		groupNames: map[string]int{},
		flags:      flags,
	}
	nodes, err := p.parseAlternations(true)
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.src) {
		// A ')' stopped the parse: unbalanced at top level.
		return nil, parseErrorAt("unbalanced parenthesis", p.pos)
	}
	return &parsedPattern{
		nodes:      nodes,
		groups:     p.groups,
		groupNames: p.groupNames,
		flags:      p.flags,
	}, nil
}

func (p *reParser) parseAlternations(top bool) ([]reNode, error) {
	var branches [][]reNode
	for {
		nodes, err := p.parseSequence()
		if err != nil {
			return nil, err
		}
		branches = append(branches, nodes)
		if p.pos >= len(p.src) || p.src[p.pos] != '|' {
			break
		}
		p.pos++
	}
	if len(branches) == 1 {
		return branches[0], nil
	}
	return []reNode{{op: opBranch, branches: branches, flags: p.flags}}, nil
}

func (p *reParser) parseSequence() ([]reNode, error) {
	var nodes []reNode
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '|' || c == ')' {
			return nodes, nil
		}
		item, err := p.parseItem()
		if err != nil {
			return nil, err
		}
		if item != nil {
			nodes = append(nodes, *item)
		}
	}
	return nodes, nil
}

func (p *reParser) parseItem() (*reNode, error) {
	if err := p.skipVerbose(); err != nil {
		return nil, err
	}
	if p.pos >= len(p.src) {
		return nil, nil
	}
	atom, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	if atom == nil {
		return nil, nil
	}
	// At most one quantifier per atom: stacking quantifiers is the
	// reference's "multiple repeat" error.
	if err := p.skipVerbose(); err != nil {
		return nil, err
	}
	if p.pos >= len(p.src) {
		return atom, nil
	}
	if c := p.src[p.pos]; c != '*' && c != '+' && c != '?' && c != '{' {
		return atom, nil
	}
	qmin, qmax, qlen, lazy, ok := p.parseQuantifier()
	if !ok {
		if p.overflow {
			return nil, parseErrorAt("the repetition number is too large", startOfAtom(p, atom))
		}
		// A malformed '{' is a literal (Python behavior): the atom stands
		// and the '{' is handled by the next parseAtom call.
		return atom, nil
	}
	if atom.op == opAt {
		return nil, parseErrorAt("nothing to repeat", p.pos-qlen)
	}
	if atom.op == opRepeat {
		return nil, parseErrorAt("multiple repeat", p.pos-qlen)
	}
	wrapped := &reNode{op: opRepeat, min: qmin, max: qmax, lazy: lazy, body: []reNode{*atom}, flags: p.flags}
	if p.pos < len(p.src) && p.src[p.pos] == '?' {
		wrapped.lazy = true
		p.pos++
	}
	if p.pos < len(p.src) {
		switch p.src[p.pos] {
		case '*', '+', '?':
			return nil, parseErrorAt("multiple repeat", p.pos)
		case '{':
			if _, _, _, _, ok := p.probeQuantifier(); ok {
				return nil, parseErrorAt("multiple repeat", p.pos)
			}
		}
	}
	return wrapped, nil
}

// parseQuantifier parses a quantifier at the current position. ok is false
// when the text is not a quantifier (a malformed '{' is a literal).
func (p *reParser) parseQuantifier() (int, int, int, bool, bool) {
	c := p.src[p.pos]
	start := p.pos
	switch c {
	case '*':
		p.pos++
		return 0, maxRepeatUnbounded(), 1, false, true
	case '+':
		p.pos++
		return 1, maxRepeatUnbounded(), 1, false, true
	case '?':
		p.pos++
		return 0, 1, 1, false, true
	case '{':
		end := strings.IndexByte(p.src[p.pos:], '}')
		if end < 0 {
			return 0, 0, 0, false, false
		}
		body := p.src[p.pos+1 : p.pos+end]
		parts := strings.Split(body, ",")
		var lowStr, highStr string
		switch len(parts) {
		case 1:
			lowStr, highStr = parts[0], parts[0]
		case 2:
			lowStr, highStr = parts[0], parts[1]
		default:
			return 0, 0, 0, false, false
		}
		if lowStr == "" && highStr == "" {
			return 0, 0, 0, false, false
		}
		low, lowOK := parseDecimal(lowStr)
		high, highOK := parseDecimal(highStr)
		if !lowOK || !highOK {
			// an all-digit run that overflowed the sentinel is the
			// reference's "repetition number too large"; junk is a literal
			if (!lowOK && allDigits(lowStr)) || (!highOK && allDigits(highStr)) {
				p.overflow = true
			}
			return 0, 0, 0, false, false
		}
		hmax := high
		if highStr == "" {
			hmax = maxRepeatUnbounded()
			high = hmax
		}
		if low > high {
			return 0, 0, 0, false, false
		}
		p.pos += end + 1
		return low, hmax, p.pos - start, false, true
	}
	return 0, 0, 0, false, false
}

func maxRepeatUnbounded() int { return maxRepeat }

// startOfAtom recovers the atom's start offset for error positions: the
// wrapped body's own position, else the quantifier start.
func startOfAtom(p *reParser, atom *reNode) int {
	if atom.op == opLiteral || atom.op == opIn || atom.op == opAny || atom.op == opAt {
		return p.pos
	}
	return p.pos
}

func parseDecimal(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
		if n > maxRepeat {
			return 0, false
		}
	}
	return n, true
}

// parseAtom parses one atom; nil with nil error means nothing parsed
// (end or alternation boundary consumed by the caller).
func (p *reParser) parseAtom() (*reNode, error) {
	c := p.src[p.pos]
	switch c {
	case '*':
		return nil, parseErrorAt("nothing to repeat", p.pos)
	case '+':
		return nil, parseErrorAt("nothing to repeat", p.pos)
	case '?':
		return nil, parseErrorAt("nothing to repeat", p.pos)
	case '{':
		// A '{' that is not a well-formed quantifier is a literal; a
		// well-formed quantifier here has nothing to repeat.
		if _, _, _, _, ok := p.probeQuantifier(); ok {
			return nil, parseErrorAt("nothing to repeat", p.pos)
		}
		p.pos++
		return p.literalNode('{'), nil
	case '^':
		p.pos++
		return &reNode{op: opAt, anchor: atBeginning, flags: p.flags}, nil
	case '$':
		p.pos++
		return &reNode{op: opAt, anchor: atEnd, flags: p.flags}, nil
	case '[':
		return p.parseCharClass()
	case '(':
		return p.parseGroup()
	case ')':
		// handled by parseSequence
		return nil, nil
	case '\\':
		return p.parseEscapeAtom()
	case '.':
		p.pos++
		return &reNode{op: opAny, interval: anyIntervals(p.flags), flags: p.flags}, nil
	default:
		p.pos++
		node := p.literalNode(rune(c))
		return node, nil
	}
}

func (p *reParser) literalNode(ch rune) *reNode {
	iv := singleInterval(int(ch))
	if p.flags&flagIgnoreCase != 0 {
		iv = expandIgnoreCase(iv, p.flags)
	}
	return &reNode{op: opLiteral, ch: ch, interval: iv, flags: p.flags}
}

func (p *reParser) probeQuantifier() (int, int, int, bool, bool) {
	saved := p.pos
	qmin, qmax, qlen, lazy, ok := p.parseQuantifier()
	p.pos = saved
	return qmin, qmax, qlen, lazy, ok
}

func (p *reParser) parseGroup() (*reNode, error) {
	open := p.pos
	p.pos++ // consume '('
	if p.pos >= len(p.src) {
		return nil, parseErrorAt("missing ), unterminated subpattern", open)
	}
	if p.src[p.pos] != '?' {
		// plain capturing group (sre_parse.opengroup assigns the current
		// counter then increments)
		idx := p.groups
		p.groups++
		p.openGroups[idx] = true
		body, err := p.parseGroupBody(open)
		if err != nil {
			return nil, err
		}
		delete(p.openGroups, idx)
		return &reNode{op: opSubPattern, groupIdx: idx, body: body, flags: p.flags}, nil
	}
	p.pos++ // consume '?'
	if p.pos >= len(p.src) {
		return nil, parseErrorAt("unknown extension", open)
	}
	switch p.src[p.pos] {
	case 'P':
		p.pos++
		if p.pos >= len(p.src) {
			return nil, parseErrorAt("unknown extension ?P", open)
		}
		switch p.src[p.pos] {
		case '<':
			return p.parseNamedGroup(open)
		case '=':
			p.pos++
			name, err := p.parseGroupNameToken(')')
			if err != nil {
				return nil, err
			}
			if err := validateGroupNameError(name, p.pos-len(name)); err != nil {
				return nil, err
			}
			if p.pos >= len(p.src) || p.src[p.pos] != ')' {
				return nil, parseErrorAt("missing ), unterminated name", open)
			}
			p.pos++
			idx, ok := p.groupNames[name]
			if !ok {
				return nil, parseErrorAt(fmt.Sprintf("unknown group name '%s'", name), open+3)
			}
			return &reNode{op: opGroupRef, refIdx: idx, refName: name, flags: p.flags}, nil
		default:
			return nil, parseErrorAt("unknown extension ?P"+string(p.src[p.pos]), open)
		}
	case '<':
		p.pos++
		if p.pos < len(p.src) && (p.src[p.pos] == '=' || p.src[p.pos] == '!') {
			negative := p.src[p.pos] == '!'
			p.pos++
			body, err := p.parseLookaroundBody(open, negative, true)
			if err != nil {
				return nil, err
			}
			return &reNode{op: opAssert, behind: true, negative: negative, body: body, flags: p.flags}, nil
		}
		// (?<name>...) is Python 3.11+ syntax; the corpus oracle grammar
		// (Python 3.10) rejects it fail-closed.
		return nil, parseErrorAt("unknown extension ?<", open)
	case '=':
		p.pos++
		return p.parseLookaround(open, false, false)
	case '!':
		p.pos++
		return p.parseLookaround(open, true, false)
	case ':':
		p.pos++
		body, err := p.parseGroupBody(open)
		if err != nil {
			return nil, err
		}
		return &reNode{op: opSubPattern, body: body, flags: p.flags}, nil
	case '#':
		// comment group: scan to the closing ')'
		end := strings.IndexByte(p.src[p.pos:], ')')
		if end < 0 {
			return nil, parseErrorAt("missing ), unterminated comment", open)
		}
		p.pos += end + 1
		return nil, nil
	case '>':
		// atomic group: valid regexp2/Python 3.11+ syntax, rejected by the
		// corpus oracle grammar (Python 3.10) fail-closed.
		return nil, parseErrorAt("unknown extension ?>", open)
	case '(':
		return nil, parseErrorAt("unknown extension ?(", open)
	default:
		return p.parseInlineFlags(open)
	}
}

func (p *reParser) parseNamedGroup(open int) (*reNode, error) {
	p.pos++ // consume '<'
	nameStart := p.pos
	name, err := p.parseGroupNameToken('>')
	if err != nil {
		return nil, err
	}
	if err := validateGroupNameError(name, nameStart); err != nil {
		return nil, err
	}
	if p.pos >= len(p.src) || p.src[p.pos] != '>' {
		return nil, parseErrorAt("missing >, unterminated name", open)
	}
	p.pos++
	if _, dup := p.groupNames[name]; dup {
		return nil, parseErrorAt(fmt.Sprintf("redefinition of group name '%s'", name), nameStart)
	}
	idx := p.groups
	p.groups++
	p.groupNames[name] = idx
	p.openGroups[idx] = true
	body, err := p.parseGroupBody(open)
	if err != nil {
		return nil, err
	}
	delete(p.openGroups, idx)
	return &reNode{op: opSubPattern, groupIdx: idx, groupName: name, body: body, flags: p.flags}, nil
}

func (p *reParser) parseLookaround(open int, negative, behind bool) (*reNode, error) {
	body, err := p.parseLookaroundBody(open, negative, behind)
	if err != nil {
		return nil, err
	}
	return &reNode{op: opAssert, behind: behind, negative: negative, body: body, flags: p.flags}, nil
}

func (p *reParser) parseLookaroundBody(open int, negative, behind bool) ([]reNode, error) {
	return p.parseGroupBody(open)
}

func (p *reParser) parseGroupBody(open int) ([]reNode, error) {
	p.nesting++
	if p.nesting > maxGroupNestingDepth {
		return nil, parseErrorAt("sorry, but this version only supports 20 nested parentheses", open)
	}
	defer func() { p.nesting-- }()
	body, err := p.parseAlternations(false)
	if err != nil {
		return nil, err
	}
	if p.pos >= len(p.src) || p.src[p.pos] != ')' {
		return nil, parseErrorAt("missing ), unterminated subpattern", open)
	}
	p.pos++
	return body, nil
}

// parseInlineFlags handles (?flags) and (?flags:...).
func (p *reParser) parseInlineFlags(open int) (*reNode, error) {
	add, remove := reFlags(0), reFlags(0)
	negative := false
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch c {
		case 'i':
			if negative {
				remove |= flagIgnoreCase
			} else {
				add |= flagIgnoreCase
			}
		case 'm':
			if negative {
				remove |= flagMultiline
			} else {
				add |= flagMultiline
			}
		case 's':
			if negative {
				remove |= flagDotAll
			} else {
				add |= flagDotAll
			}
		case 'a':
			if negative {
				remove |= flagASCII
			} else {
				add |= flagASCII
			}
		case 'L':
			if negative {
				remove |= flagLocale
			} else {
				add |= flagLocale
			}
		case 'x':
			if negative {
				remove |= flagVerbose
			} else {
				add |= flagVerbose
			}
		case 'u':
			// Python 3.11+ accepts (?u) as a no-op flag.
		case '-':
			if negative {
				return nil, parseErrorAt("global flags not at the start of the expression", open)
			}
			negative = true
		case ':':
			p.pos++
			saved := p.flags
			p.flags = (p.flags | add) &^ remove
			body, err := p.parseGroupBody(open)
			p.flags = saved
			if err != nil {
				return nil, err
			}
			return &reNode{op: opSubPattern, body: body, flags: saved}, nil
		case ')':
			// global flags: only legal when the opening parenthesis is at
			// the very start of the pattern
			if open != 0 {
				return nil, parseErrorAt("global flags not at the start of the expression", open)
			}
			p.pos++
			p.flags = (p.flags | add) &^ remove
			return nil, nil
		default:
			return nil, parseErrorAt("unknown flag", p.pos)
		}
		p.pos++
	}
	return nil, parseErrorAt("unknown flag", open)
}

func (p *reParser) parseGroupNameToken(end byte) (string, error) {
	start := p.pos
	for p.pos < len(p.src) && p.src[p.pos] != end {
		p.pos++
	}
	return p.src[start:p.pos], nil
}

func (p *reParser) skipVerbose() error {
	if p.flags&flagVerbose == 0 {
		return nil
	}
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			p.pos++
			continue
		}
		if c == '#' {
			end := strings.IndexByte(p.src[p.pos:], '\n')
			if end < 0 {
				p.pos = len(p.src)
				return nil
			}
			p.pos += end + 1
			continue
		}
		return nil
	}
	return nil
}
