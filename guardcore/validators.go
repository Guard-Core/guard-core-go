package guardcore

import (
	"net"
	"strings"
)

var ambiguousBacktickContexts = map[string]bool{"query_param": true, "url_path": true}
var globValueStartContexts = map[string]bool{"request_body": true}

func countShellOperators(token string) int {
	count := 0
	rs := []rune(token)
	i := 0
	for i < len(rs) {
		if rs[i] == ';' {
			count++
			i++
			continue
		}
		if rs[i] == '|' || rs[i] == '&' {
			if i+1 < len(rs) && rs[i+1] == rs[i] {
				count++
				i += 2
			} else {
				count++
				i++
			}
			continue
		}
		i++
	}
	return count
}

var shellMetacharWindowCompiled = mustCompile(`(?:;|\|\||\||&&)\s*(?:`+"`"+`|[A-Za-z_][\w-]*|[~./][\w./-]*|-[\w-]*)|\$\(|\$\{`, 0, windowTimeout)
var strongSQLGluedPrefixCompiled = mustCompile(`(?i)\b(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|GROUP\s+BY)\z`, 0, windowTimeout)
var strongSQLGluedSuffixCompiled = mustCompile(`(?i)\A(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|GROUP\s+BY)\b`, 0, windowTimeout)
var implausibleSQLIdentCharsCompiled = regexpCompileASCII(`[\s/.;|&$()]`)
var bareShellParamNameCompiled = mustCompile(`\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\z`, 0, windowTimeout)
var shellPrintableASCIICompiled = mustCompile(`\A[\t\x20-\x7e]*\z`, 0, windowTimeout)
var globBoundaryPrefixCompiled = mustCompile(`(?:;|\|\||\||&&|\$\(|`+"`"+`)\s*\z`, 0, windowTimeout)
var ldapWildcardClauseEndCompiled = mustCompile(`=[^()]+\*\s*\z`, 0, windowTimeout)
var ldapAttackTokenCompiled = mustCompile(`\*|\(\s*[&|!]|\x00|\(\s*\(|~=|>=|<=`, 0, windowTimeout)
var ldapParenFollowupSymbolCompiled = mustCompile(`\A\s*(?:[!(]|\*)`, 0, windowTimeout)
var ldapAttrDescSource = `(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*`
var ldapParenFollowupAttrCompiled = mustCompile(`\A\s*`+ldapAttrDescSource+`:?=`, 0, windowTimeout)

func regexpCompileASCII(src string) *regexp2P {
	return mustCompile(src, 0, windowTimeout)
}

func backtickWindowStart(t scanText, position int) int {
	index := position
	for index > 0 && !containsRune("\"'`"+"\n\r", t.rs[index-1]) {
		index--
	}
	return index
}

func backtickWindowEnd(t scanText, position int) int {
	index := position
	for index < t.n && !containsRune("\"'`"+"\n\r", t.rs[index]) {
		index++
	}
	return index
}

func strongSQLKeywordGluedToPair(t scanText, start, end int) bool {
	ws := backtickWindowStart(t, start)
	we := backtickWindowEnd(t, end)
	prefix := scanText{s: t.str(ws, start), rs: t.rs[ws:start], n: start - ws}
	suffix := scanText{s: t.str(end, we), rs: t.rs[end:we], n: we - end}
	for _, m := range findAllMatches(strongSQLGluedPrefixCompiled, prefix) {
		_ = m
		return true
	}
	for _, m := range findAllMatches(strongSQLGluedSuffixCompiled, suffix) {
		_ = m
		return true
	}
	return false
}

func gluedBacktickPairIsInjection(m rmatch, context string) bool {
	t := scanText{s: m.full(), rs: m.runes(), n: len(m.runes())}
	start, end := m.start(), m.end()
	token := t.str(start+1, end-1)
	st := scanText{s: token, rs: t.rs[start+1 : end-1], n: end - 1 - (start + 1)}
	if len(findAllMatches(shellPrintableASCIICompiled, st)) == 0 {
		return false
	}
	if countShellOperators(token) >= 2 {
		return true
	}
	tailAnchored := strings.TrimSpace(t.str(end, t.n)) == ""
	clauseInitial := false
	if start > 0 && containsRune(" \t\r\n", t.rs[start-1]) {
		prefix := strings.TrimRight(t.str(0, start), " \t\r\n\v\f")
		if prefix != "" {
			last := []rune(prefix)[len([]rune(prefix))-1]
			clauseInitial = containsRune(".!?;&|", last)
		}
	}
	appendedClause := tailAnchored && clauseInitial
	prefixGlued := start > 0 && isWordRune(t.rs[start-1])
	suffixGlued := end < t.n && isWordRune(t.rs[end])
	if !prefixGlued && !suffixGlued && !appendedClause {
		return false
	}
	if ok, _ := implausibleSQLIdentCharsCompiled.MatchString(token); ok {
		return true
	}
	ws := backtickWindowStart(t, start)
	we := backtickWindowEnd(t, end)
	window := scanText{s: t.str(ws, we), rs: t.rs[ws:we], n: we - ws}
	if len(findAllMatches(shellMetacharWindowCompiled, window)) > 0 {
		return true
	}
	if strongSQLKeywordGluedToPair(t, start, end) {
		return false
	}
	normalized := strings.SplitN(context, ":", 2)[0]
	return ambiguousBacktickContexts[normalized] || appendedClause
}

func dollarSubstitutionPairIsInjection(m rmatch, context string) bool {
	t := scanText{s: m.full(), rs: m.runes(), n: len(m.runes())}
	start, end := m.start(), m.end()
	prefixQuoted := start > 0 && t.rs[start-1] == '`'
	suffixQuoted := end < t.n && t.rs[end] == '`'
	if prefixQuoted || suffixQuoted {
		return false
	}
	delimiter := t.rs[start+1]
	token := t.str(start+2, end-1)
	stripped := strings.ToLower(strings.TrimSpace(token))
	if stripped == "ifs" {
		return true
	}
	if delimiter == '{' {
		st := scanText{s: strings.TrimSpace(token), rs: []rune(strings.TrimSpace(token)), n: len([]rune(strings.TrimSpace(token)))}
		if len(findAllMatches(bareShellParamNameCompiled, st)) == 0 {
			return true
		}
	} else {
		for _, r := range token {
			if containsRune("/.;|&$()", r) {
				return true
			}
		}
	}
	if strongSQLKeywordGluedToPair(t, start, end) {
		return false
	}
	normalized := strings.SplitN(context, ":", 2)[0]
	return ambiguousBacktickContexts[normalized]
}

func quoteSpliceTokenIsDangerousCommand(m rmatch, context string) bool {
	run := 0
	for _, fragment := range splitOnQuoteRuns(m.text()) {
		if len([]rune(fragment)) == 1 {
			run++
		} else {
			run = 0
		}
		if run >= 3 {
			return true
		}
	}
	return false
}

func splitOnQuoteRuns(s string) []string {
	var out []string
	var cur []rune
	for _, r := range s {
		if r == '\'' || r == '"' {
			out = append(out, string(cur))
			cur = nil
			continue
		}
		cur = append(cur, r)
	}
	out = append(out, string(cur))
	return out
}

var braceWordItemRE = mustCompile(`\A[A-Za-z0-9_./~-]+\z`, 0, windowTimeout)

func braceExpansionIsDangerousCommand(m rmatch, context string) bool {
	text := m.text()
	rs := []rune(text)
	start := indexOfRune(rs, '{', 0)
	end := lastIndexOfRune(rs, '}')
	if start == -1 || end == -1 || end <= start {
		return false
	}
	for _, item := range strings.Split(string(rs[start+1:end]), ",") {
		irs := []rune(item)
		st := scanText{s: item, rs: irs, n: len(irs)}
		if len(findAllMatches(braceWordItemRE, st)) == 0 {
			continue
		}
		hasLetter := false
		for _, r := range irs {
			if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
				hasLetter = true
				break
			}
		}
		if hasLetter {
			return true
		}
	}
	return false
}

func globTokenIsWordShaped(token string) bool {
	rs := []rune(token)
	for i, r := range rs {
		if r != '?' && r != '*' {
			continue
		}
		left := 0
		p := i - 1
		for p >= 0 && isASCIILetter(rs[p]) {
			left++
			p--
		}
		right := 0
		p = i + 1
		for p < len(rs) && isASCIILetter(rs[p]) {
			right++
			p++
		}
		if left+right >= 2 {
			return true
		}
	}
	return false
}

func isASCIILetter(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
}

func globWildcardTokenIsDangerousCommand(m rmatch, context string) bool {
	if !globTokenIsWordShaped(m.text()) {
		return false
	}
	t := scanText{s: m.full(), rs: m.runes(), n: len(m.runes())}
	if m.end() < t.n {
		suffix := t.rs[m.end()]
		if !containsRune(" \t\r\n;|&", suffix) {
			return false
		}
	}
	prefix := t.str(0, m.start())
	ps := scanText{s: prefix, rs: t.rs[:m.start()], n: m.start()}
	if len(findAllMatches(globBoundaryPrefixCompiled, ps)) > 0 {
		return true
	}
	normalized := strings.SplitN(context, ":", 2)[0]
	if globValueStartContexts[context] {
		return strings.TrimSpace(prefix) == ""
	}
	_ = normalized
	return false
}

func ldapNextCandidateScanLimit(re *regexp2P, t scanText, after int) int {
	if m, ok := searchFrom(re, t, after); ok {
		return m.end()
	}
	return t.n
}

func ldapFilterExpressionForwardExtent(t scanText, start, scanLimit int) int {
	position := start
	depth := 0
	for position < scanLimit {
		r := t.rs[position]
		if containsRune("()\"'\n", r) {
			if containsRune("\"'\n", r) {
				return position
			}
			if r == '(' {
				depth++
			} else if depth == 0 {
				return position
			} else {
				depth--
			}
		}
		position++
	}
	return scanLimit
}

func ldapWildcardChainIsInjection(m rmatch) bool {
	t := scanText{s: m.full(), rs: m.runes(), n: len(m.runes())}
	gt := []rune(m.text())
	rel := indexOfRune(gt, ')', 0)
	if rel == -1 {
		return false
	}
	closeParenPos := m.start() + rel

	backwardStart := closeParenPos - 40
	if backwardStart < 0 {
		backwardStart = 0
	}
	depth := 0
	position := closeParenPos - 1
	for position >= backwardStart && !containsRune("\"'\n&", t.rs[position]) {
		if t.rs[position] == ')' {
			depth--
		} else if t.rs[position] == '(' {
			depth++
		}
		position--
	}
	backwardWindow := t.str(position+1, closeParenPos)
	depthUnresolved := backwardStart > 0 && position < backwardStart

	scanLimit := ldapNextCandidateScanLimit(m.re, t, m.end())
	extent := ldapFilterExpressionForwardExtent(t, closeParenPos+1, scanLimit)
	forwardWindow := t.str(closeParenPos, extent)

	wildcardAdjacent := len(gt) > 0 && gt[0] == '*'
	depthProves := depth <= 0 && (wildcardAdjacent || !depthUnresolved)
	bw := scanText{s: backwardWindow, rs: []rune(backwardWindow), n: len([]rune(backwardWindow))}
	depthOrClause := depthProves || len(findAllMatches(ldapWildcardClauseEndCompiled, bw)) > 0
	if !depthOrClause {
		return false
	}
	fw := scanText{s: forwardWindow, rs: []rune(forwardWindow), n: len([]rune(forwardWindow))}
	return len(findAllMatches(ldapAttackTokenCompiled, bw)) > 0 || len(findAllMatches(ldapAttackTokenCompiled, fw)) > 0
}

func ldapParenConjunctionIsInjection(m rmatch) bool {
	t := scanText{s: m.full(), rs: m.runes(), n: len(m.runes())}
	scanLimit := ldapNextCandidateScanLimit(m.re, t, m.end())
	tailEnd := ldapFilterExpressionForwardExtent(t, m.end(), scanLimit)
	tail := t.str(m.end(), tailEnd)
	trs := []rune(tail)
	ts := scanText{s: tail, rs: trs, n: len(trs)}
	if len(findAllMatches(ldapParenFollowupSymbolCompiled, ts)) > 0 {
		return true
	}
	hasEq := false
	for _, r := range tail {
		if r == '=' {
			hasEq = true
			break
		}
	}
	return hasEq && len(findAllMatches(ldapParenFollowupAttrCompiled, ts)) > 0
}

type ipRange struct{ lo, hi uint32 }

var legacyIPv4BlockedRanges = []ipRange{
	{0x00000000, 0x00FFFFFF},
	{0x7F000000, 0x7FFFFFFF},
	{0x0A000000, 0x0AFFFFFF},
	{0xAC100000, 0xAC1FFFFF},
	{0xC0A80000, 0xC0A8FFFF},
	{0xA9FE0000, 0xA9FEFFFF},
	{0x646464C8, 0x646464C8},
}

func decodeLegacyIPv4Part(part string) (uint32, bool) {
	lower := strings.ToLower(part)
	if strings.HasPrefix(lower, "0x") {
		digits := part[2:]
		if digits == "" {
			return 0, false
		}
		var v uint64
		for _, c := range digits {
			var d uint64
			switch {
			case c >= '0' && c <= '9':
				d = uint64(c - '0')
			case c >= 'a' && c <= 'f':
				d = uint64(c-'a') + 10
			default:
				return 0, false
			}
			v = v*16 + d
			if v > 0xFFFFFFFF {
				return 0, false
			}
		}
		return uint32(v), true
	}
	if len(part) > 1 && part[0] == '0' {
		digits := part[1:]
		var v uint64
		for _, c := range digits {
			if c < '0' || c > '7' {
				return 0, false
			}
			v = v*8 + uint64(c-'0')
			if v > 0xFFFFFFFF {
				return 0, false
			}
		}
		return uint32(v), true
	}
	var v uint64
	for _, c := range part {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
		if v > 0xFFFFFFFF {
			return 0, false
		}
	}
	return uint32(v), true
}

func decodeLegacyIPv4Host(host string) (uint32, bool) {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return 0, false
	}
	var decoded []uint32
	for _, part := range parts {
		v, ok := decodeLegacyIPv4Part(part)
		if !ok {
			return 0, false
		}
		decoded = append(decoded, v)
	}
	if len(decoded) == 1 && decoded[0] != 0 && decoded[0] < (1<<24) {
		bare := !(len(parts[0]) > 1 && parts[0][0] == '0') && !strings.HasPrefix(strings.ToLower(parts[0]), "0x")
		if bare {
			return 0, false
		}
	}
	for _, v := range decoded[:len(decoded)-1] {
		if v > 255 {
			return 0, false
		}
	}
	remainingBits := uint(8 * (5 - len(decoded)))
	if uint64(decoded[len(decoded)-1]) >= (1 << remainingBits) {
		return 0, false
	}
	var result uint64
	for _, v := range decoded[:len(decoded)-1] {
		result = (result << 8) | uint64(v)
	}
	result = (result << remainingBits) | uint64(decoded[len(decoded)-1])
	return uint32(result), true
}

func legacyIPv4MatchIsBlocked(m rmatch, context string) bool {
	host := m.group1()
	ip, ok := decodeLegacyIPv4Host(host)
	if !ok {
		return false
	}
	for _, r := range legacyIPv4BlockedRanges {
		if ip >= r.lo && ip <= r.hi {
			return true
		}
	}
	return false
}

var _ = net.ParseIP
