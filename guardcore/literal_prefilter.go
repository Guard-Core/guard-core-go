package guardcore

// Required-literal prefilter for tempered-loop anchored patterns.
//
// The recon families start with `\A` followed by a greedy tempered loop
// `(?:(?!\n).)*` (optionally inside a lookahead) and then a plain
// alternation of literals (`(?:scan(?:ner|...)?|attack(?:er|...)?|...)`).
// Their match cost is dominated by the position-0 attempt: the loop walks
// the whole value, then every backtrack position retries the alternation.
// When NONE of the alternation's leading literals occurs anywhere in the
// text, the pattern cannot match at any position, so the entire regex can
// be skipped. Presence of any literal runs the regex exactly as before:
// the skip is conservative and can never change a verdict.

import "strings"

// extractLeadingLiterals recognizes the two tempered-loop shapes and
// returns each top-level alternative's leading literal run (escapes
// resolved). It returns nil unless EVERY alternative yields a non-empty
// literal, the alternation is small, and nothing else in the pattern could
// break the "literal must occur in text" guarantee (case sensitivity is
// preserved: these rows carry no (?i)).
func extractLeadingLiterals(src string) []string {
	rest, ok := strings.CutPrefix(src, `\A`)
	if !ok {
		return nil
	}
	if after, ok := strings.CutPrefix(rest, `(?=`); ok {
		rest = after
	}
	if after, ok := strings.CutPrefix(rest, `(?:(?!\n).)*`); ok {
		rest = after
	} else {
		return nil
	}
	rest = strings.TrimPrefix(rest, `\b`)
	if after, ok := strings.CutPrefix(rest, `(?:`); !ok {
		return nil
	} else {
		rest = after
	}
	var lits []string
	var cur strings.Builder
	flush := func() bool {
		lit := cur.String()
		cur.Reset()
		if len(lit) < 2 || len(lits) >= 64 {
			return false
		}
		lits = append(lits, lit)
		return true
	}
	depth := 1
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch c {
		case '\\':
			if i+1 >= len(rest) {
				return nil
			}
			cur.WriteByte(rest[i+1])
			i++
		case '(':
			// Literal run ends; skip this alternative's remainder.
			if cur.Len() > 0 && !flush() {
				return nil
			}
			depth++
			i++ // the '(' was already counted; scan inside the group
			for i < len(rest) && depth > 1 {
				switch rest[i] {
				case '\\':
					i++
				case '(':
					depth++
				case ')':
					depth--
				}
				i++
			}
			if depth != 1 {
				return nil
			}
			i-- // reprocess the char after the group in the outer loop
		case '[':
			if !flush() {
				return nil
			}
			end := strings.IndexByte(rest[i+1:], ']')
			if end < 0 {
				return nil
			}
			i += end + 1
		case '|':
			if cur.Len() > 0 && !flush() {
				return nil
			}
		case ')':
			depth--
			if depth == 0 {
				if cur.Len() > 0 && !flush() {
					return nil
				}
				return lits
			}
			return nil
		case '?', '*', '+', '{':
			// A quantifier after a literal run fixes that run's minimum
			// requirement; after a skipped group it constrains the group.
			// Either way the run (if any) stays required, and any tail is
			// skipped up to the next top-level separator.
			if cur.Len() > 0 && !flush() {
				return nil
			}
			for i < len(rest) && rest[i] != '|' && rest[i] != ')' {
				if rest[i] == '\\' {
					i++
				}
				i++
			}
			i--
		case '.':
			// Unescaped dot: still a fixed character in the literal run,
			// kept verbatim as required text.
			cur.WriteByte(c)
		default:
			cur.WriteByte(c)
		}
	}
	return nil
}

// literalPrefilter reports whether any required literal occurs in text.
// Patterns compile with IgnoreCase, so both sides compare lowercased; the
// literals arrive pre-lowered from the compile hook.
func literalPrefilter(lits []string, text string) bool {
	lowered := strings.ToLower(text)
	for _, lit := range lits {
		if strings.Contains(lowered, lit) {
			return true
		}
	}
	return false
}
