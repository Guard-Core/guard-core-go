package guardcore

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var defaultSensitiveLogHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"x-api-key":           true,
}

var defaultSensitiveLogFields = map[string]bool{
	"access_token":  true,
	"refresh_token": true,
	"api_key":       true,
	"apikey":        true,
	"token":         true,
	"password":      true,
	"secret":        true,
	"client_secret": true,
	"signature":     true,
}

const RedactedPlaceholder = "[REDACTED]"

func mergeSensitiveNames(defaults, extra map[string]bool) map[string]bool {
	merged := make(map[string]bool, len(defaults)+len(extra))
	for name := range defaults {
		merged[name] = true
	}
	for name := range extra {
		merged[strings.ToLower(name)] = true
	}
	return merged
}

func mergeSensitiveLogHeaders(extra map[string]bool) map[string]bool {
	return mergeSensitiveNames(defaultSensitiveLogHeaders, extra)
}

func mergeSensitiveLogBodyFields(extra map[string]bool) map[string]bool {
	return mergeSensitiveNames(defaultSensitiveLogFields, extra)
}

func mergedSensitiveNames(sensitiveParams, sensitiveBodyFields, sensitiveHeaders map[string]bool) map[string]bool {
	merged := mergeSensitiveLogBodyFields(sensitiveBodyFields)
	for name := range mergeSensitiveNames(nil, sensitiveParams) {
		merged[name] = true
	}
	for name := range mergeSensitiveLogHeaders(sensitiveHeaders) {
		merged[name] = true
	}
	return merged
}

func RedactSensitiveHeaders(headers map[string]string, sensitiveHeaders, sensitiveBodyFields, sensitiveParams map[string]bool) map[string]string {
	sensitive := mergeSensitiveLogHeaders(sensitiveHeaders)
	bodyFields := mergeSensitiveLogBodyFields(sensitiveBodyFields)
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		if sensitive[strings.ToLower(strings.TrimSpace(key))] {
			out[key] = RedactedPlaceholder
			continue
		}
		out[key] = RedactBlobForDisplay(value, sensitiveParams, bodyFields, sensitiveHeaders)
	}
	return out
}

func formatSensitiveHeaders(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, headers[key]))
	}
	return strings.Join(parts, ", ")
}

var xmlElementRedactRe = regexp.MustCompile(`(?i)<([A-Za-z_][\w.:-]*)>([^<]*)</([A-Za-z_][\w.:-]*)>`)

func redactXMLElements(text string, sensitive map[string]bool) string {
	return xmlElementRedactRe.ReplaceAllStringFunc(text, func(match string) string {
		parts := xmlElementRedactRe.FindStringSubmatch(match)
		if len(parts) != 4 || !sensitive[strings.ToLower(parts[1])] || parts[1] != parts[3] {
			return match
		}
		return "<" + parts[1] + ">" + RedactedPlaceholder + "</" + parts[1] + ">"
	})
}

// The value grammar carries terminated and unterminated quoted forms
// alongside the bare token, so a value like "000000 that lost its
// closing quote still redacts (the reference scanner treats both quote
// characters as value starts; guard_core/_utils/pair_value_scan.py).
var pairRedactRe = regexp.MustCompile(`(?i)([A-Za-z_][\w.-]*)\s*([=:])\s*("[^"]*"|'[^']*'|"[^"]*|'[^']*|[^\s&;,'"\]]+)`)

// redactPairsInText redacts sensitive name/value pairs. A non-sensitive
// label's value can itself carry sensitive pairs ("reason: token=x" -
// the label consumes "reason:" and the value swallows the pair), so the
// value is rescanned recursively, bounded like the reference's value
// scan (guard_core/_utils/pair_redaction.py).
func redactPairsInText(text string, sensitive map[string]bool) string {
	return redactPairsDepth(text, sensitive, 0)
}

const pairRedactionMaxDepth = 6

func redactPairsDepth(text string, sensitive map[string]bool, depth int) string {
	if depth > pairRedactionMaxDepth {
		return text
	}
	return pairRedactRe.ReplaceAllStringFunc(text, func(match string) string {
		parts := pairRedactRe.FindStringSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		if sensitive[strings.ToLower(parts[1])] {
			return parts[1] + parts[2] + RedactedPlaceholder
		}
		scanned := redactPairsDepth(parts[3], sensitive, depth+1)
		if scanned == parts[3] {
			return match
		}
		return parts[1] + parts[2] + scanned
	})
}

// jsonRedactionMaxDepth is the display-redaction JSON depth cap, matching
// Python's _DEFAULT_MAX_JSON_DEPTH = 32 (guard_core/_utils/detection_config.py,
// applied to the display path through _resolve_json_depth_cap): container
// levels nested at or below the cap collapse to [REDACTED].
const jsonRedactionMaxDepth = 32

func redactSensitiveJSON(node any, sensitive map[string]bool, depth int) (any, bool, bool) {
	switch typed := node.(type) {
	case map[string]any:
		if depth >= jsonRedactionMaxDepth {
			// Depth cap: the container collapses and the display path
			// redacts the whole value (guard-core 8bae9459).
			return RedactedPlaceholder, true, true
		}
		changed := false
		capHit := false
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			if sensitive[strings.ToLower(key)] {
				out[key] = RedactedPlaceholder
				changed = true
				continue
			}
			redacted, sub, hit := redactSensitiveJSON(value, sensitive, depth+1)
			out[key] = redacted
			changed = changed || sub
			capHit = capHit || hit
		}
		return out, changed, capHit
	case []any:
		if depth >= jsonRedactionMaxDepth {
			return RedactedPlaceholder, true, true
		}
		changed := false
		capHit := false
		out := make([]any, len(typed))
		for i, value := range typed {
			redacted, sub, hit := redactSensitiveJSON(value, sensitive, depth+1)
			out[i] = redacted
			changed = changed || sub
			capHit = capHit || hit
		}
		return out, changed, capHit
	default:
		return node, false, false
	}
}

func marshalCompactJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func jsonRedactText(text string, sensitive map[string]bool) string {
	var parsed any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return ""
	}
	switch parsed.(type) {
	case map[string]any, []any:
	default:
		return ""
	}
	redacted, changed, depthCapHit := redactSensitiveJSON(parsed, sensitive, 1)
	// A depth-cap collapse on the display path redacts the whole value
	// instead of emitting a huge half-redacted structure (guard-core
	// 8bae9459). The cap-hit check precedes the unchanged check, matching
	// Python's _json_redact_text ordering.
	if depthCapHit {
		return RedactedPlaceholder
	}
	if !changed {
		return ""
	}
	return marshalCompactJSON(redacted)
}

func RedactBlobForDisplay(text string, sensitiveParams, sensitiveBodyFields, sensitiveHeaders map[string]bool) string {
	if text == "" {
		return text
	}
	sensitive := mergedSensitiveNames(sensitiveParams, mergeSensitiveLogBodyFields(sensitiveBodyFields), sensitiveHeaders)
	if redacted := jsonRedactText(text, sensitive); redacted != "" {
		return redacted
	}
	if decoded, err := url.QueryUnescape(text); err == nil && decoded != text {
		if redacted := jsonRedactText(decoded, sensitive); redacted != "" {
			return redacted
		}
	}
	return redactPairsInText(redactXMLElements(text, sensitive), sensitive)
}

func RedactHeaderValueForDisplay(value string, sensitiveParams, sensitiveBodyFields, sensitiveHeaders map[string]bool) string {
	if value == "" {
		return value
	}
	return RedactBlobForDisplay(value, sensitiveParams, sensitiveBodyFields, sensitiveHeaders)
}

func RedactURLForDisplay(rawURL string, sensitiveParams, sensitiveBodyFields, sensitiveHeaders map[string]bool) string {
	if rawURL == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		// A malformed URL must never skip redaction (the reference's
		// splitter tolerates malformed escapes): fall back to the blob
		// redactor over the raw text.
		return RedactBlobForDisplay(rawURL, sensitiveParams, sensitiveBodyFields, sensitiveHeaders)
	}
	sensitive := mergedSensitiveNames(sensitiveParams, mergeSensitiveLogBodyFields(sensitiveBodyFields), sensitiveHeaders)
	changed := false
	username := ""
	hasPassword := false
	if parsed.User != nil {
		username = parsed.User.Username()
		_, hasPassword = parsed.User.Password()
		if hasPassword {
			parsed.User = nil
			changed = true
		}
	}
	if parsed.RawQuery != "" {
		values, qerr := url.ParseQuery(parsed.RawQuery)
		if qerr != nil {
			// A malformed query string must not skip redaction either:
			// pair-scan the raw segment.
			if redacted := redactPairsInText(redactXMLElements(parsed.RawQuery, sensitive), sensitive); redacted != parsed.RawQuery {
				parsed.RawQuery = redacted
				changed = true
			}
		}
		if qerr == nil {
			queryChanged := false
			for key := range values {
				if sensitive[strings.ToLower(key)] {
					values[key] = []string{RedactedPlaceholder}
					queryChanged = true
				}
			}
			if queryChanged {
				parsed.RawQuery = values.Encode()
				changed = true
			}
		}
	}
	if parsed.Path != "" {
		if redacted := redactPairsInText(redactXMLElements(parsed.Path, sensitive), sensitive); redacted != parsed.Path {
			parsed.Path = redacted
			changed = true
		}
	}
	// The fragment redacts like the query (the reference
	// redact_url_for_display runs _redact_json_or_pairs_segment over both).
	if parsed.Fragment != "" {
		if redacted := redactPairsInText(redactXMLElements(parsed.Fragment, sensitive), sensitive); redacted != parsed.Fragment {
			parsed.Fragment = redacted
			changed = true
		}
	}
	if !changed {
		return rawURL
	}
	result := parsed.String()
	if hasPassword {
		marker := "://" + parsed.Host
		idx := strings.Index(result, marker)
		if idx >= 0 {
			result = result[:idx+3] + username + ":[REDACTED]@" + parsed.Host + result[idx+len(marker):]
		}
	}
	return result
}

type LogOptions struct {
	Logger              *log.Logger
	LogType             string
	Reason              string
	PassiveMode         bool
	TriggerInfo         string
	Level               string
	CheckName           string
	MutedCheckLogs      map[string]bool
	OnBlock             func(req Request, payload map[string]any)
	SensitiveHeaders    map[string]bool
	SensitiveParams     map[string]bool
	SensitiveBodyFields map[string]bool
}

type ActivityLogger interface {
	LogActivity(req Request, opts LogOptions)
}

var DefaultActivityLogger ActivityLogger = defaultActivityLogger{}

type defaultActivityLogger struct{}

func (defaultActivityLogger) LogActivity(req Request, opts LogOptions) {
	dispatchBlockHook(req, opts)
	if opts.Level == "" {
		return
	}
	if opts.CheckName != "" && opts.MutedCheckLogs[opts.CheckName] {
		return
	}
	if opts.Logger == nil {
		return
	}
	opts.Logger.Print(buildActivityMessage(req, opts)) // codeql[go/clear-text-logging]:ignore values masked by RedactSensitiveHeaders
}

func dispatchBlockHook(req Request, opts LogOptions) {
	if opts.LogType != "suspicious" {
		return
	}
	if !opts.PassiveMode {
		stashBlock(req.State(), opts.Reason, opts.TriggerInfo)
		return
	}
	fireBlockHook(&SecurityConfig{OnBlock: opts.OnBlock}, req, opts.CheckName, opts.Reason, opts.TriggerInfo, true, 0)
}

func extractRequestContext(req Request, opts LogOptions) map[string]string {
	ip := resolveClientIP(req)
	if ip == "" {
		ip = UnknownClientIdentity
	}
	return map[string]string{
		"client_ip": ip,
		"method":    req.Method(),
		"url":       RedactURLForDisplay(req.URLFull(), opts.SensitiveParams, opts.SensitiveBodyFields, opts.SensitiveHeaders),
		"headers":   formatSensitiveHeaders(RedactSensitiveHeaders(req.Headers().Map(), opts.SensitiveHeaders, opts.SensitiveBodyFields, opts.SensitiveParams)),
	}
}

// sanitizeForLog mirrors Python's _sanitize_for_log
// (guard_core/_utils/logging_utils.py): the result is pure ASCII so log
// lines can never break on legacy console encodings (Windows cp1252).
// Newlines, carriage returns, and tabs become literal escapes; raw invalid
// UTF-8 bytes, the Go counterpart of Python's surrogate-escaped bytes
// (U+DC80-DCFF), become \xNN escapes carrying the original byte value; and
// every other control or non-ASCII rune becomes a \uXXXX escape.
func sanitizeForLog(value string) string {
	if value == "" {
		return value
	}
	sanitized := strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(value)
	var out strings.Builder
	for i := 0; i < len(sanitized); {
		r, size := utf8.DecodeRuneInString(sanitized[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&out, `\x%02x`, sanitized[i])
		} else if r >= 32 && r <= 126 {
			out.WriteRune(r)
		} else {
			fmt.Fprintf(&out, `\u%04x`, r)
		}
		i += size
	}
	return out.String()
}

func buildActivityMessage(req Request, opts LogOptions) string {
	context := extractRequestContext(req, opts)
	var details, reasonMessage string
	// The headers/URL values in context are already masked: context is built
	// through RedactSensitiveHeaders and RedactURLForDisplay (sensitive
	// headers, params, and body fields are replaced with placeholders and the
	// result is covered by activity-logger tests). CodeQL cannot see that
	// sanitizer, so the header-derived flows below carry an explicit
	// suppression with that reason rather than a blind allow. The Reason and
	// TriggerInfo fields carry detection-derived text (matched pattern
	// previews, body excerpts) and are console-safe escaped for the same
	// reason (guard-core f5d53ca5).
	switch opts.LogType {
	case "request":
		details = fmt.Sprintf("Request from %s: %s %s", context["client_ip"], context["method"], context["url"])
		reasonMessage = fmt.Sprintf("Headers: %s", context["headers"]) // codeql[go/clear-text-logging]:ignore values masked by RedactSensitiveHeaders
	case "suspicious":
		if opts.PassiveMode {
			details = fmt.Sprintf("[PASSIVE MODE] Penetration attempt detected from %s: %s %s", context["client_ip"], context["method"], context["url"])
			reasonMessage = fmt.Sprintf("Headers: %s", context["headers"]) // codeql[go/clear-text-logging]:ignore values masked by RedactSensitiveHeaders
			if opts.TriggerInfo != "" {
				reasonMessage = fmt.Sprintf("Trigger: %s - %s", sanitizeForLog(opts.TriggerInfo), reasonMessage)
			}
		} else {
			details = fmt.Sprintf("Suspicious activity detected from %s: %s %s", context["client_ip"], context["method"], context["url"])
			reasonMessage = fmt.Sprintf("Reason: %s - Headers: %s", sanitizeForLog(opts.Reason), context["headers"]) // codeql[go/clear-text-logging]:ignore values masked by RedactSensitiveHeaders
		}
	default:
		details = fmt.Sprintf("%s from %s: %s %s", strings.ToUpper(opts.LogType[:1])+opts.LogType[1:], context["client_ip"], context["method"], context["url"])
		reasonMessage = fmt.Sprintf("Details: %s - Headers: %s", sanitizeForLog(opts.Reason), context["headers"]) // codeql[go/clear-text-logging]:ignore values masked by RedactSensitiveHeaders
	}
	return fmt.Sprintf("%s - %s", details, reasonMessage)
}

func LogActivity(req Request, opts LogOptions) {
	// CodeQL reports the header taint at this call site; the logger masks
	// sensitive values via RedactSensitiveHeaders before writing (see the
	// comment above buildActivityMessage and the activity-logger tests).
	DefaultActivityLogger.LogActivity(req, opts) // codeql[go/clear-text-logging]:ignore values masked by RedactSensitiveHeaders
}
