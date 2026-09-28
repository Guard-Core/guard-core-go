package guardcore

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

type Config struct {
	CompilerTimeout        time.Duration
	MaxContentLength       int
	PreserveAttackPatterns bool
	MaxBodyInspectBytes    int
	SemanticThreshold      float64
	ThreatScoreThreshold   float64
}

func DefaultConfig() Config {
	return Config{
		CompilerTimeout:        2000 * time.Millisecond,
		MaxContentLength:       10000,
		PreserveAttackPatterns: true,
		MaxBodyInspectBytes:    262144,
		SemanticThreshold:      0.7,
		ThreatScoreThreshold:   1.0,
	}
}

func translatePattern(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); i++ {
		if i+1 < len(src) && src[i] == '\\' && src[i+1] == 'Z' && (i == 0 || src[i-1] != '\\') {
			b.WriteString(`\z`)
			i++
			continue
		}
		b.WriteByte(src[i])
	}
	return b.String()
}

func compileRE(src string, opts regexp2.RegexOptions, timeout time.Duration) (*regexp2.Regexp, error) {
	re, err := regexp2.Compile(translatePattern(src), opts)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		re.MatchTimeout = timeout
	}
	return re, nil
}

func compileREIgnoreCase(src string, timeout time.Duration) (*regexp2.Regexp, error) {
	return compileRE(src, regexp2.IgnoreCase, timeout)
}

func mustCompile(src string, opts regexp2.RegexOptions, timeout time.Duration) *regexp2.Regexp {
	re, err := compileRE(src, opts, timeout)
	if err != nil {
		panic("guardcore: compile " + src + ": " + err.Error())
	}
	return re
}

func mustCompileI(src string) *regexp2.Regexp {
	return mustCompile(src, regexp2.IgnoreCase, 0)
}

type scanText struct {
	s   string
	rs  []rune
	b2r []int32
	n   int
}

func newScanText(s string) scanText {
	rs := []rune(s)
	b2r := make([]int32, len(s)+1)
	r := 0
	for i := 0; i < len(s); {
		b2r[i] = int32(r)
		_, sz := utf8.DecodeRuneInString(s[i:])
		i += sz
		r++
	}
	b2r[len(s)] = int32(r)
	return scanText{s: s, rs: rs, b2r: b2r, n: len(rs)}
}

func (t scanText) runeOff(b int) int {
	if b >= len(t.s) {
		return t.n
	}
	return int(t.b2r[b])
}

func (t scanText) str(start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > t.n {
		end = t.n
	}
	if start >= end {
		return ""
	}
	return string(t.rs[start:end])
}

type rmatch struct {
	t      scanText
	rStart int
	rEnd   int
	g1     string
	re     *regexp2P
}

func (m rmatch) text() string   { return m.t.str(m.rStart, m.rEnd) }
func (m rmatch) start() int     { return m.rStart }
func (m rmatch) end() int       { return m.rEnd }
func (m rmatch) full() string   { return m.t.s }
func (m rmatch) runes() []rune  { return m.t.rs }
func (m rmatch) group1() string { return m.g1 }

func matchFromIndices(t scanText, rStart, rEnd int, g1 string) rmatch {
	return rmatch{t: t, rStart: rStart, rEnd: rEnd, g1: g1}
}

func findAllMatches(re *regexp2.Regexp, t scanText) []rmatch {
	var out []rmatch
	pos := 0
	n := t.n
	for pos <= n {
		// Runes API: Match.Index is a rune index, so the scan position and
		// match spans share one coordinate system (Python parity: code
		// point indices) and the subject is not re-encoded per call.
		m, err := re.FindRunesMatchStartingAt(t.rs, pos)
		if err != nil || m == nil {
			break
		}
		if m.Index < pos {
			// Defensive: keep the scan monotonic even if the engine
			// reports a match behind the requested start.
			pos++
			continue
		}
		g1 := ""
		if g := m.GroupByNumber(1); g != nil && len(g.Captures) > 0 {
			g1 = g.String()
		}
		out = append(out, matchFromIndices(t, m.Index, m.Index+m.Length, g1))
		next := m.Index + m.Length
		if m.Length == 0 {
			next++
		}
		if next <= pos {
			next = pos + 1
		}
		pos = next
	}
	return out
}

func findFirstAt(re *regexp2.Regexp, t scanText, start, ceiling int) (rmatch, bool) {
	if start >= ceiling || start < 0 {
		return rmatch{}, false
	}
	if ceiling > len(t.rs) {
		ceiling = len(t.rs)
	}
	if start >= ceiling {
		return rmatch{}, false
	}
	m, err := re.FindRunesMatchStartingAt(t.rs[:ceiling], start)
	if err != nil || m == nil || m.Index != start {
		return rmatch{}, false
	}
	g1 := ""
	if g := m.GroupByNumber(1); g != nil && len(g.Captures) > 0 {
		g1 = g.String()
	}
	return matchFromIndices(t, m.Index, m.Index+m.Length, g1), true
}

func searchFrom(re *regexp2.Regexp, t scanText, start int) (rmatch, bool) {
	if start > t.n {
		return rmatch{}, false
	}
	m, err := re.FindRunesMatchStartingAt(t.rs, start)
	if err != nil || m == nil {
		return rmatch{}, false
	}
	g1 := ""
	if g := m.GroupByNumber(1); g != nil && len(g.Captures) > 0 {
		g1 = g.String()
	}
	return matchFromIndices(t, m.Index, m.Index+m.Length, g1), true
}

func lastIndexOfRune(rs []rune, target rune) int {
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i] == target {
			return i
		}
	}
	return -1
}

func runeStr(rs []rune) string { return string(rs) }

var _ = utf8.RuneLen
