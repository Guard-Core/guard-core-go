package guardcore

import (
	"sort"
	"unicode"

	"github.com/dlclark/regexp2"
)

func fileUploadMatchStart(t scanText, filenameStart int) (int, bool) {
	cursor := filenameStart - 1
	firstNewline := -1
	for cursor >= 0 && unicode.IsSpace(t.rs[cursor]) {
		if t.rs[cursor] == '\n' {
			firstNewline = cursor
		}
		cursor--
	}
	if cursor == -1 {
		return 0, true
	}
	switch t.rs[cursor] {
	case ';', ',', ':', '\n':
		return cursor, true
	}
	if firstNewline != -1 {
		return firstNewline, true
	}
	return 0, false
}

func fileUploadSkipWhitespace(t scanText, cursor int) int {
	for cursor < t.n && unicode.IsSpace(t.rs[cursor]) {
		cursor++
	}
	return cursor
}

func fileUploadQuotedCandidate(t scanText, filenameStart int) (start, bodyStart, end int, ok bool) {
	start, ok = fileUploadMatchStart(t, filenameStart)
	if !ok {
		return 0, 0, 0, false
	}
	cursor := fileUploadSkipWhitespace(t, filenameStart+len("filename"))
	if cursor >= t.n || t.rs[cursor] != '=' {
		return 0, 0, 0, false
	}
	cursor = fileUploadSkipWhitespace(t, cursor+1)
	if cursor >= t.n || (t.rs[cursor] != '"' && t.rs[cursor] != '\'') {
		return 0, 0, 0, false
	}
	bodyStart = cursor + 1
	quoteIdx := indexOfRune(t.rs, '"', bodyStart)
	alt := indexOfRune(t.rs, '\'', bodyStart)
	if alt != -1 && (quoteIdx == -1 || alt < quoteIdx) {
		quoteIdx = alt
	}
	if quoteIdx == -1 {
		return 0, 0, 0, false
	}
	return start, bodyStart, quoteIdx + 1, true
}

var fileUploadBenignTerminalRE = mustCompile(`\.(?:`+fileUploadBenignAlt+`)\z`, regexp2.IgnoreCase, windowTimeout)
var fileUploadDangerousTerminalRE = mustCompile(`\.(?:`+fileUploadDangerousAlt+`)\z`, regexp2.IgnoreCase, windowTimeout)
var fileUploadDangerousMarkerRE = mustCompile(`\.(?:`+fileUploadDoubleAlt+`)(?![A-Za-z0-9])`, regexp2.IgnoreCase, windowTimeout)
var fileUploadTruncationMarkerRE = mustCompile("(?:%00|\\\\u0000|\\\\x00|\\\\0|\x00|;|\\.\\z)", regexp2.IgnoreCase, windowTimeout)
var fileUploadDecodedTruncationMarkerRE = mustCompile("(?:\x00|;|\\.\\z)", 0, windowTimeout)
var fileUploadTokenRE = mustCompileI("filename")

func fileUploadIsDoubleExtension(body scanText) bool {
	if len(findAllMatches(fileUploadBenignTerminalRE, body)) == 0 {
		return false
	}
	finalDot := lastIndexOfRune(body.rs, '.')
	if finalDot == -1 {
		return false
	}
	for _, m := range findAllMatchesLimited(fileUploadDangerousMarkerRE, body, finalDot) {
		suffixStart := m.end()
		if suffixStart == finalDot {
			return true
		}
		if suffixStart < finalDot && !containsRune("\" '", body.rs[suffixStart]) {
			return true
		}
	}
	return false
}

func findAllMatchesLimited(re *regexp2P, t scanText, ceiling int) []rmatch {
	if ceiling <= 0 {
		return nil
	}
	sub := scanText{s: t.str(0, ceiling), rs: t.rs[:ceiling], n: ceiling}
	return findAllMatches(re, sub)
}

func fileUploadIsTruncation(body scanText, decoded bool) bool {
	marker := fileUploadTruncationMarkerRE
	if decoded {
		marker = fileUploadDecodedTruncationMarkerRE
	}
	for _, m := range findAllMatches(fileUploadDangerousMarkerRE, body) {
		if anchoredAnywhere(marker, body, m.end()) {
			return true
		}
	}
	return false
}

func anchoredAnywhere(re *regexp2P, t scanText, at int) bool {
	if at > t.n {
		return false
	}
	m, err := re.FindStringMatchStartingAt(t.s, at)
	return err == nil && m != nil && m.Index == at
}

func fileUploadKindMatches(body scanText, source string) bool {
	switch source {
	case fileUploadDangerousSource:
		return len(findAllMatches(fileUploadDangerousTerminalRE, body)) > 0
	case fileUploadDoubleSource:
		return fileUploadIsDoubleExtension(body)
	case fileUploadTruncationSource:
		return fileUploadIsTruncation(body, false)
	case fileUploadDecodedTruncationSource:
		return fileUploadIsTruncation(body, true)
	}
	return false
}

func containsRune(set string, r rune) bool {
	for _, c := range set {
		if c == r {
			return true
		}
	}
	return false
}

func fileUploadScanMatches(t scanText, source string) []rmatch {
	var matches []rmatch
	lastEnd := 0
	for _, m := range findAllMatches(fileUploadTokenRE, t) {
		start, bodyStart, end, ok := fileUploadQuotedCandidate(t, m.start())
		if !ok {
			continue
		}
		if start < lastEnd {
			continue
		}
		body := scanText{s: t.str(bodyStart, end-1), rs: t.rs[bodyStart : end-1], n: end - 1 - bodyStart}
		if !fileUploadKindMatches(body, source) {
			continue
		}
		matches = append(matches, matchFromIndices(t, start, end, ""))
		lastEnd = end
	}
	return matches
}

var _ = sort.SearchInts
