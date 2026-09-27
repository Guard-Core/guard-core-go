package guardcore

// Ordered JSON body walk (guard-core parity with
// guard_core/_utils/body_json_scan.py and embedded_json_scan.py).
//
// The reference engine parses with json.loads (dict insertion order) and
// walks the tree depth-first in insertion order: for each object entry the
// key is checked against the excluded body fields (whole subtree skipped),
// the mongo-operator-key registry (direct nosql hit), and a name scan; then
// the entry value descends. Objects and arrays deeper than the JSON depth
// cap are serialized back to compact JSON and scanned as one text value.
// Scalar leaves scan str(value).
//
// Values parsed out of a form or multipart field string walk with the field
// context plus the ":embedded_json" suffix (embedded_json_scan.py), and such
// a leaf string that itself parses as a JSON object or array walks again
// with another suffix, exactly like _check_embedded_json short-circuiting
// the raw value scan. The top-level JSON body walk keeps the plain
// request_body context and never re-parses leaf strings (the reference skips
// the embedded check when the context is exactly request_body).

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// jsonNode is one node of the ordered parse tree. Scalars carry their
// Python str() rendering (json.Number literals for numbers, "True"/"False",
// "None").
type jsonNode struct {
	isObject bool
	isArray  bool
	keys     []string
	values   map[string]*jsonNode
	items    []*jsonNode
	scalar   string
}

// parseOrderedJSON parses s and returns the root when it is a JSON object or
// array (json.loads returns other types too, but _scan_json_content and
// _check_embedded_json only walk dict/list). Trailing data or any parse
// failure returns false, like the reference falling through to the blob or
// raw-value scan.
func parseOrderedJSON(s string) (*jsonNode, bool) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	root, err := decodeJSONNode(dec)
	if err != nil || root == nil || (!root.isObject && !root.isArray) {
		return nil, false
	}
	// json.loads rejects trailing content after the value.
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return root, true
}

func decodeJSONNode(dec *json.Decoder) (*jsonNode, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return decodeJSONValue(dec, tok)
}

func decodeJSONValue(dec *json.Decoder, tok json.Token) (*jsonNode, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			node := &jsonNode{isObject: true, values: map[string]*jsonNode{}}
			for {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				if d, ok := keyTok.(json.Delim); ok && d == '}' {
					return node, nil
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errUnexpectedJSONToken
				}
				value, err := decodeJSONNode(dec)
				if err != nil {
					return nil, err
				}
				if _, seen := node.values[key]; !seen {
					node.keys = append(node.keys, key)
				}
				// Python dicts keep the first insertion position and the
				// last value for duplicate keys.
				node.values[key] = value
			}
		case '[':
			node := &jsonNode{isArray: true}
			for {
				itemTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				if d, ok := itemTok.(json.Delim); ok && d == ']' {
					return node, nil
				}
				item, err := decodeJSONValue(dec, itemTok)
				if err != nil {
					return nil, err
				}
				node.items = append(node.items, item)
			}
		default:
			return nil, errUnexpectedJSONToken
		}
	case string:
		return &jsonNode{scalar: t}, nil
	case json.Number:
		return &jsonNode{scalar: t.String()}, nil
	case bool:
		// Python str(True) / str(False).
		if t {
			return &jsonNode{scalar: "True"}, nil
		}
		return &jsonNode{scalar: "False"}, nil
	case nil:
		return &jsonNode{scalar: "None"}, nil
	}
	return nil, errUnexpectedJSONToken
}

type jsonWalkError struct{}

func (jsonWalkError) Error() string { return "unexpected json token" }

var errUnexpectedJSONToken = jsonWalkError{}

// appendJSONWalkEntries emits the scan values of one JSON walk in the
// reference order. Entries carry the request_body context for keys; leaves
// carry the walk context (request_body, or a field context with the
// ":embedded_json" suffix).
func appendJSONWalkEntries(values []bodyScanValue, root *jsonNode, context string, excluded map[string]bool) []bodyScanValue {
	allowLeafReparse := context != requestBodyCtx
	// Frames are consumed in order; the reference uses a LIFO stack and
	// pushes children reversed, so children process in insertion order.
	type frame struct {
		isEntry bool
		key     string
		node    *jsonNode
		item    *jsonNode
		label   string
		depth   int
	}
	stack := []frame{{node: root, label: defaultJSONLeafLabel, depth: 1}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if f.isEntry {
			keyStr := f.key
			if excluded[strings.ToLower(keyStr)] {
				continue
			}
			if mongoOperatorKeyRE.MatchString(keyStr) {
				// body_json_scan._mongo_operator_key_hit: the reference
				// reports this hit straight from the walk, unfiltered.
				values = append(values, bodyScanValue{
					content:        keyStr,
					context:        requestBodyCtx,
					forcedCategory: "nosql",
				})
				continue
			}
			values = append(values, bodyScanValue{content: keyStr, context: requestBodyCtx, label: "JSON key '" + keyStr + "': "})
			stack = append(stack, frame{node: f.item, label: keyStr, depth: f.depth + 1})
			continue
		}
		node := f.node
		switch {
		case node.isObject:
			if f.depth >= jsonWalkDepthCap {
				values = append(values, bodyScanValue{content: serializeCompactJSON(node), context: context, label: bodyFieldLabel(f.label)})
				continue
			}
			for i := len(node.keys) - 1; i >= 0; i-- {
				stack = append(stack, frame{isEntry: true, key: node.keys[i], item: node.values[node.keys[i]], depth: f.depth})
			}
		case node.isArray:
			if f.depth >= jsonWalkDepthCap {
				values = append(values, bodyScanValue{content: serializeCompactJSON(node), context: context, label: bodyFieldLabel(f.label)})
				continue
			}
			for i := len(node.items) - 1; i >= 0; i-- {
				// List items inherit the container's label.
				stack = append(stack, frame{node: node.items[i], label: f.label, depth: f.depth + 1})
			}
		default:
			if allowLeafReparse {
				if inner, ok := parseOrderedJSON(node.scalar); ok {
					values = appendJSONWalkEntries(values, inner, context+embeddedJSONLeafContextSuffix, excluded)
					// Clean-parse fall-through (embedded_json_scan.py +
					// _check_value_enhanced): when the nested walk reports
					// nothing, the raw leaf string still scans with the walk
					// context, so payloads confined to the raw text
					// (duplicate-key remnants, structural text) still hit.
					values = append(values, bodyScanValue{content: node.scalar, context: context, label: bodyFieldLabel(f.label)})
					continue
				}
			}
			leafLabel := bodyFieldLabel(f.label)
			if f.label == "" {
				leafLabel = ""
			}
			values = append(values, bodyScanValue{content: node.scalar, context: context, label: leafLabel})
		}
	}
	return values
}

// serializeCompactJSON renders a subtree the way
// json.dumps(value, separators=(",", ":"), ensure_ascii=False) does for the
// depth-capped subtree scan.
func serializeCompactJSON(node *jsonNode) string {
	var b bytes.Buffer
	writeCompactJSON(&b, node)
	return b.String()
}

func writeCompactJSON(b *bytes.Buffer, node *jsonNode) {
	switch {
	case node.isObject:
		b.WriteByte('{')
		for i, key := range node.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('"')
			writeJSONStringBody(b, key)
			b.WriteString("\":")
			writeCompactJSON(b, node.values[key])
		}
		b.WriteByte('}')
	case node.isArray:
		b.WriteByte('[')
		for i, item := range node.items {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCompactJSON(b, item)
		}
		b.WriteByte(']')
	default:
		b.WriteString(jsonScalarLiteral(node.scalar))
	}
}

// jsonScalarLiteral renders a scalar back to JSON text: strings are quoted
// and escaped, numbers keep their literal, booleans and null render as in
// JSON (they were only stored as Python str() for scanning).
func jsonScalarLiteral(scalar string) string {
	switch scalar {
	case "True":
		return "true"
	case "False":
		return "false"
	case "None":
		return "null"
	}
	// Numbers keep the literal; anything else that is not a number is a
	// string that must be re-quoted.
	if isJSONNumberLiteral(scalar) {
		return scalar
	}
	var b bytes.Buffer
	b.WriteByte('"')
	writeJSONStringBody(&b, scalar)
	b.WriteByte('"')
	return b.String()
}

func isJSONNumberLiteral(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' {
		i = 1
		if i >= len(s) {
			return false
		}
	}
	digits := 0
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-':
		default:
			return false
		}
	}
	return digits > 0
}

// writeJSONStringBody escapes s the way json.dumps(ensure_ascii=False) does:
// quote, backslash, and the C0 controls; everything else stays literal UTF-8.
func writeJSONStringBody(b *bytes.Buffer, s string) {
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		default:
			if r < 0x20 {
				const hexDigits = "0123456789abcdef"
				b.WriteString("\\u00")
				b.WriteByte(hexDigits[(r>>4)&0xf])
				b.WriteByte(hexDigits[r&0xf])
				continue
			}
			b.WriteRune(r)
		}
	}
}
