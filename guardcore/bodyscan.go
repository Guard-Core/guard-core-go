package guardcore

// Request body scanning (guard-core 4.0.4 parity).
//
// Ports the body-value extraction of the reference engine: urlencoded form
// bodies split into field values, multipart/form-data bodies split into parts
// (file-part payloads that are mostly binary are cut into printable islands),
// JSON bodies walked to their leaves, and plain or unknown bodies scanned as
// one whole value. Each extracted value carries the context label the Python
// engine scans it with (guard_core/_utils/body_form_scan.py,
// body_json_scan.py, embedded_json_scan.py):
//
//	form field name / value     request_body / request_body:form_field
//	multipart label / entry     request_body / request_body:multipart_field
//	JSON walk leaves            request_body (+ nested field walks gain
//	                            the ":embedded_json" leaf suffix)
//	blob fallback               request_body (whole body)
//
// Everything that only shapes Python logging (sensitive-field redaction,
// content previews) is intentionally absent: this port's detection surface is
// the category list, so only the extracted values, their contexts, their
// order, and the island reduction are mirrored.
//
// Deviations from Python (forced by the Go string model or stdlib gaps, all
// detection-neutral or noted):
//   - raw bytes become Go strings (invalid UTF-8 mapped to U+FFFD on rune
//     conversion), the engine-wide body representation; Python decodes with
//     surrogateescape, so one binary byte is one surrogate rune there and one
//     U+FFFD per maximal invalid run here. Ratios stay on the same side of
//     the binary-like threshold for real payloads.
//   - JSON number leaves scan the literal JSON text (json.Number) instead of
//     Python's float repr, and json.loads' NaN/Infinity extension is not
//     accepted (such bodies fall through to the blob scan, like any parse
//     failure in Python).
//   - the multipart scanner is a line-based port of the email feedparser
//     tolerances (raw header names and case, colonless lines joining the
//     payload, folded header values, preamble/epilogue, nested multipart
//     containers walked in place); header entry order inside one part is
//     wire order, so it matches Python exactly.

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	formFieldContext     = "request_body:form_field"
	multipartFieldCtx    = "request_body:multipart_field"
	requestBodyCtx       = "request_body"
	jsonWalkDepthCap     = 32
	defaultJSONLeafLabel = ""
	multipartFileLabel   = "file"
)

// bodyScanValue is one value handed to Detect with the context label Python
// scans it under. forcedCategory carries the JSON mongo-operator-key hit,
// which the reference engine reports directly from the JSON walk without a
// pattern scan (body_json_scan._mongo_operator_key_hit).
type bodyScanValue struct {
	content        string
	context        string
	forcedCategory string
}

// mongoOperatorKeyRE mirrors _MONGO_OPERATOR_KEY_RE from
// guard_core/_utils/body_json_scan.py.
var mongoOperatorKeyRE = regexp.MustCompile(`^\$(?:ne|gt|gte|lt|lte|eq|in|nin|nor|and|or|not|all|size|exists|type|mod|options|where|regex|expr|function|elemMatch)$`)

// extractBodyScanValues mirrors _scan_request_body routing on the lowered
// content type: form-urlencoded fields, multipart parts, JSON walks, and the
// whole-body blob fallback. Binary island reduction inside file parts uses
// cfg.DetectionBinaryMinRunLength; field exclusions use
// cfg.ExcludedDetectionBodyFields.
func extractBodyScanValues(rawBody, contentType string, cfg *SecurityConfig, excludedBodyFields map[string]bool) []bodyScanValue {
	lowered := strings.ToLower(contentType)
	excluded := excludedBodyFields
	switch {
	case strings.Contains(lowered, "application/x-www-form-urlencoded"):
		return appendFormBodyValues(nil, rawBody, excluded)
	case strings.Contains(lowered, "multipart/form-data"):
		return appendMultipartBodyValues(nil, rawBody, contentType, cfg, excluded)
	}
	if strings.Contains(lowered, "json") {
		if root, ok := parseOrderedJSON(rawBody); ok {
			return appendJSONWalkEntries(nil, root, requestBodyCtx, excluded)
		}
	}
	var blob []bodyScanValue
	return append(blob, bodyScanValue{content: rawBody, context: requestBodyCtx})
}

// appendFormBodyValues mirrors _scan_form_body: parse_qsl pairs with
// keep_blank_values, excluded names skipping the whole pair, the name scanned
// as a request_body value, then the value as a form_field value (with the
// embedded JSON walk taking precedence over the raw string, exactly like
// _check_value_enhanced's embedded-JSON-first order).
func appendFormBodyValues(values []bodyScanValue, rawBody string, excluded map[string]bool) []bodyScanValue {
	for _, pair := range parseFormPairs(rawBody) {
		if excluded[strings.ToLower(pair.name)] {
			continue
		}
		values = append(values, bodyScanValue{content: pair.name, context: requestBodyCtx})
		values = appendFieldBodyValue(values, pair.value, formFieldContext, excluded)
	}
	return values
}

// appendFieldBodyValue scans one form/multipart field value: a value that
// parses as a JSON object or array walks leaf-first (leaf context gains the
// ":embedded_json" suffix) and the raw value still scans afterwards with the
// field context, mirroring _check_value_enhanced: the embedded-JSON walk
// short-circuits the raw scan only when a leaf hits, and a clean walk that
// reports nothing falls through to the raw-value detect (payloads hidden in
// structural text or duplicate-key remnants still hit).
func appendFieldBodyValue(values []bodyScanValue, content, context string, excluded map[string]bool) []bodyScanValue {
	if root, ok := parseOrderedJSON(content); ok {
		values = appendJSONWalkEntries(values, root, context+embeddedJSONLeafContextSuffix, excluded)
	}
	return append(values, bodyScanValue{content: content, context: context})
}

// appendMultipartBodyValues mirrors _scan_multipart_body: when the body does
// not parse into at least one leaf part, the whole raw body is scanned as one
// request_body blob value (Python's _scan_blob_body fallback, including the
// no-parts-with-final-boundary case the email parser reports as
// is_multipart() == False).
func appendMultipartBodyValues(values []bodyScanValue, rawBody, contentType string, cfg *SecurityConfig, excludedBodyFields map[string]bool) []bodyScanValue {
	_, params := parseMediaTypeParams(contentType)
	boundary := params["boundary"]
	parts := parseMultipartParts(rawBody, boundary)
	if len(parts) == 0 {
		return append(values, bodyScanValue{content: rawBody, context: requestBodyCtx})
	}
	for _, part := range parts {
		values = appendMultipartPartValues(values, part, cfg, excludedBodyFields)
	}
	return values
}

// appendMultipartPartValues mirrors the per-part entry construction of
// _multipart_part_entries and the scan order of _scan_multipart_part: the
// filename entry, every part header entry, and the payload entries (islands
// when the part is a binary-like file part) are built first, then scanned
// with the label name scan in front of the first entry, exactly like the
// reference scanning the label once per entry (first-hit identical). A part
// that yields no entries is not scanned at all, like the reference.
func appendMultipartPartValues(values []bodyScanValue, part multipartPart, cfg *SecurityConfig, excludedBodyFields map[string]bool) []bodyScanValue {
	name, hasName := partDispositionParam(part, "name")
	filename, hasFilename := partDispositionParam(part, "filename")
	if !hasFilename {
		filename, hasFilename = partRFC2231Filename(part)
	}
	if hasName && excludedBodyFields[strings.ToLower(name)] {
		return values
	}
	label := name
	if !hasName {
		label = multipartFileLabel
	}
	ctx := multipartFieldCtx
	excluded := excludedBodyFields

	var entries []string
	if hasFilename {
		sanitized := strings.ReplaceAll(filename, "\"", "")
		sanitized = strings.ReplaceAll(sanitized, "'", "")
		entries = append(entries, "filename=\""+sanitized+"\"")
	}
	for _, header := range part.headers {
		entries = append(entries, header.name+": "+header.value)
	}
	payload := string(part.payload)
	if hasFilename && valueIsBinaryLike(payload) {
		entries = append(entries, extractBinaryIslands(payload, cfg.DetectionBinaryMinRunLength)...)
	} else if payload != "" {
		entries = append(entries, payload)
	}
	if len(entries) == 0 {
		return values
	}
	values = append(values, bodyScanValue{content: label, context: requestBodyCtx})
	for _, entry := range entries {
		values = appendFieldBodyValue(values, entry, ctx, excluded)
	}
	return values
}

// partDispositionParam extracts a content-disposition parameter the way the
// Python email parser does: tolerant semicolon splitting that respects
// quoted strings, outer quotes stripped only when they pair, escaped quotes
// unescaped.
func partDispositionParam(part multipartPart, param string) (string, bool) {
	value, ok := firstHeaderValue(part.headers, "content-disposition")
	if !ok {
		return "", false
	}
	_, params := parseHeaderParams(value)
	v, ok := params[param]
	return v, ok
}

// partRFC2231Filename mirrors get_filename's RFC 2231 fallback: when no
// plain filename parameter exists, the extended pieces filename*, or the
// segments filename*0*..filename*N*, are joined, the charset prefix stripped,
// and the value percent-decoded.
func partRFC2231Filename(part multipartPart) (string, bool) {
	value, ok := firstHeaderValue(part.headers, "content-disposition")
	if !ok {
		return "", false
	}
	_, params := parseHeaderParams(value)
	if v, ok := params["filename*"]; ok {
		return decodeRFC2231Value(v), true
	}
	merged, ok := mergeRFC2231Segments(params, "filename")
	if !ok {
		return "", false
	}
	return decodeRFC2231Value(merged), true
}

func mergeRFC2231Segments(params map[string]string, base string) (string, bool) {
	var pieces []string
	for i := 0; ; i++ {
		key := base + "*" + itoa(i) + "*"
		v, ok := params[key]
		if !ok {
			break
		}
		pieces = append(pieces, v)
	}
	if len(pieces) == 0 {
		return "", false
	}
	return strings.Join(pieces, ""), true
}

func decodeRFC2231Value(value string) string {
	// charset'lang'percent-encoded
	if idx := strings.IndexByte(value, '\''); idx >= 0 {
		rest := value[idx+1:]
		if idx2 := strings.IndexByte(rest, '\''); idx2 >= 0 {
			value = rest[idx2+1:]
		}
	}
	return percentDecodeTolerant(value)
}

func firstHeaderValue(headers []mimeHeaderEntry, lowerName string) (string, bool) {
	for _, h := range headers {
		if strings.EqualFold(h.name, lowerName) {
			return h.value, true
		}
	}
	return "", false
}

// parseFormPairs mirrors urllib.parse.parse_qsl with keep_blank_values=True
// and the "&" separator: empty chunks dropped, partition on the first "=",
// missing values kept as empty strings, plus/space folding and tolerant
// percent-decoding.
type formPair struct {
	name  string
	value string
}

func parseFormPairs(rawBody string) []formPair {
	var pairs []formPair
	for _, chunk := range strings.Split(rawBody, "&") {
		if chunk == "" {
			continue
		}
		name := chunk
		value := ""
		if idx := strings.IndexByte(chunk, '='); idx >= 0 {
			name = chunk[:idx]
			value = chunk[idx+1:]
		}
		pairs = append(pairs, formPair{
			name:  unquotePlus(name),
			value: unquotePlus(value),
		})
	}
	return pairs
}

// unquotePlus mirrors unquote_plus with errors="surrogateescape": "+" becomes
// a space and every valid %XX escape contributes its byte; invalid escape
// sequences stay literal.
func unquotePlus(s string) string {
	if !strings.Contains(s, "+") && !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s):
			h1, ok1 := hexVal(s[i+1])
			h2, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(h1<<4 | h2)
				i += 2
				continue
			}
			b.WriteByte('%')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func percentDecodeTolerant(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h1, ok1 := hexVal(s[i+1])
			h2, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(h1<<4 | h2)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func itoa(i int) string { return strconv.Itoa(i) }

// parseMediaTypeParams splits a Content-Type style header into its lowercased
// main type and parameters, using the same tolerant quoted-string splitting
// as the disposition parser.
func parseMediaTypeParams(value string) (string, map[string]string) {
	mainType := ""
	params := map[string]string{}
	first := true
	for _, piece := range splitHeaderParams(value) {
		if first {
			first = false
			mainType = strings.ToLower(strings.TrimSpace(piece))
			continue
		}
		name, param, ok := splitParamPiece(piece)
		if ok {
			params[name] = param
		}
	}
	return mainType, params
}

// parseHeaderParams parses a Content-Disposition style header value into its
// parameters (everything after the first ";" piece).
func parseHeaderParams(value string) (string, map[string]string) {
	params := map[string]string{}
	pieces := splitHeaderParams(value)
	for i, piece := range pieces {
		if i == 0 {
			continue
		}
		name, param, ok := splitParamPiece(piece)
		if ok {
			params[name] = param
		}
	}
	if len(pieces) == 0 {
		return "", params
	}
	return strings.TrimSpace(pieces[0]), params
}

func splitParamPiece(piece string) (string, string, bool) {
	idx := strings.IndexByte(piece, '=')
	if idx < 0 {
		return "", "", false
	}
	name := strings.ToLower(strings.TrimSpace(piece[:idx]))
	value := unquoteHeaderParam(strings.TrimSpace(piece[idx+1:]))
	return name, value, true
}

// unquoteHeaderParam mirrors the email parser's param unquoting: matching
// outer quotes are stripped and escaped quotes and backslashes are unescaped;
// asymmetric quotes are kept verbatim.
func unquoteHeaderParam(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	value = value[1 : len(value)-1]
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) && (value[i+1] == '"' || value[i+1] == '\\') {
			b.WriteByte(value[i+1])
			i++
			continue
		}
		b.WriteByte(value[i])
	}
	return b.String()
}

// splitHeaderParams splits on semicolons that are not inside a quoted string,
// mirroring email.utils._parseparam's quote-aware splitting.
func splitHeaderParams(value string) []string {
	var pieces []string
	start := 0
	inQuotes := false
	escaped := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if escaped {
			escaped = false
			continue
		}
		switch {
		case c == '\\' && inQuotes:
			escaped = true
		case c == '"':
			inQuotes = !inQuotes
		case c == ';' && !inQuotes:
			pieces = append(pieces, value[start:i])
			start = i + 1
		}
	}
	pieces = append(pieces, value[start:])
	return pieces
}
