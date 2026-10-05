package guardcore

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

const b64MinRunLength = 12
const gzipMagic0 = 0x1f
const gzipMagic1 = 0x8b
const maxGunzipAttemptsPerPass = 8
const b64PrintableRatioThreshold = 0.5
const b64FallbackPrintableRatioThreshold = 0.95
const maxReplacementCharRatio = 0.2

const dataAlphabetClass = `A-Za-z0-9+/_\-`
const b64SeparatorClass = `[\x00-\x7F-[A-Za-z0-9+/_\-]]`
const widenedSeparatorClass = `[\x00-\x7F-[A-Za-z0-9+/=\r\n]]`

var b64RunUnit = `[` + dataAlphabetClass + `]` + b64SeparatorClass + `*`

var b64BaseRE = regexp2.MustCompile(
	`(?<![`+dataAlphabetClass+`])(?:(?:`+b64RunUnit+`){12,}={0,2}|(?:`+b64RunUnit+`){11,}=|(?:`+b64RunUnit+`){10,}==)(?![`+dataAlphabetClass+`=])`, 0)
var b64RunRE = regexp2.MustCompile(
	`(?<![`+dataAlphabetClass+`])[`+dataAlphabetClass+`]{12,}={0,2}(?![`+dataAlphabetClass+`=])`, 0)
var b64SubFloorRE = regexp2.MustCompile(
	`(?<![`+dataAlphabetClass+`])[`+dataAlphabetClass+`]{1,11}(?![`+dataAlphabetClass+`])`, 0)
var b64HexLiteralRE = regexp2.MustCompile(`0[xX][0-9a-fA-F]+`, 0)
var b64WidenedMarkerRE = regexp2.MustCompile(widenedSeparatorClass, 0)

func isHexLiteral(token string) bool {
	m, err := b64HexLiteralRE.MatchString(token)
	return err == nil && m
}

func findAllStrings(re *regexp2.Regexp, s string) []string {
	// Convert to runes once: FindStringMatchStartingAt would re-convert the
	// remaining suffix to runes on every call, which is quadratic over the
	// scan and dominated large-body profiles.
	runes := []rune(s)
	var out []string
	pos := 0
	for pos <= len(runes) {
		m, err := re.FindRunesMatchStartingAt(runes, pos)
		if err != nil || m == nil {
			break
		}
		if m.Index < pos {
			// Defensive: skip stale matches behind the scan start so the
			// loop always progresses (see findAllMatches).
			pos++
			continue
		}
		out = append(out, m.String())
		next := m.Index + m.Length
		if next <= pos {
			next = pos + 1
		}
		pos = next
	}
	return out
}

func printableRatio(text string) float64 {
	if text == "" {
		return 0.0
	}
	count := 0
	total := 0
	for _, r := range text {
		total++
		if r == ' ' || unicode.IsPrint(r) {
			count++
		}
	}
	return float64(count) / float64(total)
}

func replacementCharRatio(text string) float64 {
	if text == "" {
		return 0.0
	}
	count := 0
	total := 0
	for _, r := range text {
		total++
		if r == 0xFFFD {
			count++
		}
	}
	return float64(count) / float64(total)
}

func boundedGunzip(raw []byte, maxOutputBytes int) []byte {
	if len(raw) < 2 || raw[0] != gzipMagic0 || raw[1] != gzipMagic1 {
		return nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	defer zr.Close()
	out := make([]byte, maxOutputBytes)
	n, err := io.ReadFull(zr, out)
	if n > 0 {
		return out[:n]
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return nil
	}
	return nil
}

type b64Decoder struct {
	gunzipAttemptsLeft int
	maxGunzipOutput    int
}

func decodeCleaned(d *b64Decoder, cleaned string, minPrintableRatio float64) (string, bool) {
	padding := (4 - len(cleaned)%4) % 4
	padded := cleaned + stringsRepeat("=", padding)
	raw, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		return "", false
	}
	if len(raw) >= 2 && raw[0] == gzipMagic0 && raw[1] == gzipMagic1 && d.gunzipAttemptsLeft > 0 {
		d.gunzipAttemptsLeft--
		if gunzipped := boundedGunzip(raw, d.maxGunzipOutput); gunzipped != nil {
			raw = gunzipped
		}
	}
	decoded := decodeUTF8Replace(raw)
	if replacementCharRatio(decoded) > maxReplacementCharRatio {
		return "", false
	}
	if printableRatio(decoded) >= minPrintableRatio {
		return decoded, true
	}
	return "", false
}

func decodeUTF8Replace(raw []byte) string {
	return string(bytes.Runes(raw))
}

func stringsRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func urlsafeTranslate(cleaned string) string {
	out := []rune(cleaned)
	for i, r := range out {
		if r == '-' {
			out[i] = '+'
		} else if r == '_' {
			out[i] = '/'
		}
	}
	return string(out)
}

func (d *b64Decoder) decodeToken(token string, minPrintableRatio float64) (string, bool) {
	if isHexLiteral(token) {
		return "", false
	}
	cleaned := removeAllSeparators(token)
	if decoded, ok := decodeCleaned(d, urlsafeTranslate(cleaned), minPrintableRatio); ok {
		return decoded, true
	}
	if containsAny(cleaned, "-_") {
		stripped := removeAll(cleaned, "-_")
		return decodeCleaned(d, stripped, minPrintableRatio)
	}
	return "", false
}

func containsAny(s, chars string) bool {
	for _, r := range s {
		for _, c := range chars {
			if r == c {
				return true
			}
		}
	}
	return false
}

func removeAll(s, chars string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if !containsAny(string(r), chars) {
			out = append(out, r)
		}
	}
	return string(out)
}

func removeAllSeparators(token string) string {
	var b strings.Builder
	for _, r := range token {
		if r < 0x80 && r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
			continue
		}
		if r < 0x80 && r >= 'a' && r <= 'z' {
			b.WriteRune(r)
			continue
		}
		if r < 0x80 && r >= '0' && r <= '9' {
			b.WriteRune(r)
			continue
		}
		if r == '+' || r == '/' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (d *b64Decoder) decodeRuns(token string) string {
	out, err := b64RunRE.ReplaceFunc(token, func(m regexp2.Match) string {
		decoded, ok := d.decodeToken(m.String(), b64FallbackPrintableRatioThreshold)
		if ok {
			return decoded
		}
		return m.String()
	}, -1, -1)
	if err != nil {
		return token
	}
	return out
}

func (d *b64Decoder) replaceCandidate(m regexp2.Match) string {
	token := m.String()
	primaryThreshold := b64PrintableRatioThreshold
	if wmatch, err := b64WidenedMarkerRE.MatchString(token); err == nil && wmatch {
		primaryThreshold = b64FallbackPrintableRatioThreshold
	}
	decoded, ok := d.decodeToken(token, primaryThreshold)
	base := token
	if ok {
		base = decoded
	} else {
		base = d.decodeRuns(token)
	}
	fm := findAllStrings(b64SubFloorRE, token)
	fragments := concatStrings(fm)
	if len(fragments) < b64MinRunLength {
		return base
	}
	reassembled, ok := d.decodeToken(fragments, b64FallbackPrintableRatioThreshold)
	if !ok || containsSubstring(base, reassembled) {
		return base
	}
	return base + " " + reassembled
}

func concatStrings(parts []string) string {
	out := ""
	for _, p := range parts {
		out += p
	}
	return out
}

func containsSubstring(s, sub string) bool {
	return len(sub) == 0 || indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func decodeBase64Candidates(content string, gunzipAttemptsLeft *int, maxGunzipOutput int) string {
	if gunzipAttemptsLeft == nil {
		n := maxGunzipAttemptsPerPass
		gunzipAttemptsLeft = &n
	}
	d := &b64Decoder{gunzipAttemptsLeft: *gunzipAttemptsLeft, maxGunzipOutput: maxGunzipOutput}
	out, err := b64BaseRE.ReplaceFunc(content, func(m regexp2.Match) string {
		return d.replaceCandidate(m)
	}, -1, -1)
	if err != nil {
		return content
	}
	*gunzipAttemptsLeft = d.gunzipAttemptsLeft
	return out
}

const shortBase64TokenMax = b64MinRunLength - 1
const shortBase64MaxCandidates = 20000
const shortBase64PrintableThreshold = 0.95

var shortBase64TokenRE = regexp2.MustCompile(`[A-Za-z0-9+/]{4,}`, 0)

func shortBase64DecodeToken(token string) (string, bool) {
	if len(token) > shortBase64TokenMax {
		return "", false
	}
	padding := (4 - len(token)%4) % 4
	padded := token
	for i := 0; i < padding; i++ {
		padded += "="
	}
	raw, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		return "", false
	}
	if !utf8.Valid(raw) {
		return "", false
	}
	return string(raw), true
}

func isQualifyingFragment(text string) bool {
	if printableRatio(text) < shortBase64PrintableThreshold {
		return false
	}
	return containsAny(text, "${}#")
}

func buildShortBase64AdditiveView(normalize func(string) string, truncate func(string) string, content string) string {
	if content == "" {
		return ""
	}
	content = truncate(normalize(content))
	// Runes once for the same reason as findAllStrings: the string API
	// re-converts the remaining suffix on every call.
	runes := []rune(content)
	var fragments []string
	attempts := 0
	pos := 0
	for pos <= len(runes) {
		m, err := shortBase64TokenRE.FindRunesMatchStartingAt(runes, pos)
		if err != nil || m == nil {
			break
		}
		if m.Index < pos {
			// Defensive: skip stale matches behind the scan start so the
			// loop always progresses (see findAllMatches).
			pos++
			continue
		}
		attempts++
		if attempts > shortBase64MaxCandidates {
			break
		}
		if decoded, ok := shortBase64DecodeToken(m.String()); ok && isQualifyingFragment(decoded) {
			fragments = append(fragments, decoded)
		}
		pos = m.Index + m.Length
		if pos <= m.Index || m.Length == 0 {
			pos = m.Index + 1
		}
	}
	out := ""
	for i, f := range fragments {
		if i > 0 {
			out += "\n"
		}
		out += f
	}
	return out
}
