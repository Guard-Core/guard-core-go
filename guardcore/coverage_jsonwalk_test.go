package guardcore

// Coverage tests for the ordered JSON body walk (jsonwalk.go).

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseOrderedJSON(t *testing.T) {
	if root, ok := parseOrderedJSON(`{"a": 1, "b": [true, false, null]}`); !ok || !root.isObject {
		t.Fatal("objects parse")
	}
	if root, ok := parseOrderedJSON(`[1, "x"]`); !ok || !root.isArray {
		t.Fatal("arrays parse")
	}
	// Scalars, malformed text, trailing data, and empty strings all refuse.
	for _, s := range []string{"42", `"text"`, `{"a":1} junk`, `{`, ``, `not json`} {
		if _, ok := parseOrderedJSON(s); ok {
			t.Fatalf("input %q must refuse to parse", s)
		}
	}
	// Duplicate keys keep the first position and the last value.
	root, ok := parseOrderedJSON(`{"a": 1, "a": 2}`)
	if !ok || len(root.keys) != 1 || root.values["a"].scalar != "2" {
		t.Fatalf("duplicate keys keep first position, got %v", root)
	}
}

func TestDecodeJSONValueUnexpectedToken(t *testing.T) {
	// Bare closing delimiters are never valid values.
	if _, err := decodeJSONValue(nil, ']'); err != errUnexpectedJSONToken {
		t.Fatalf("closing delimiters are unexpected tokens, got %v", err)
	}
	// Delimiter tokens reject as values too.
	if _, err := decodeJSONValue(nil, json.Delim('}')); err != errUnexpectedJSONToken {
		t.Fatalf("delimiter tokens are unexpected values, got %v", err)
	}
	if errUnexpectedJSONToken.Error() != "unexpected json token" {
		t.Fatal("the walk error explains itself")
	}
	// Malformed containers propagate their errors.
	for _, s := range []string{"{1: 2}", `{"a":`, "[1", `[{"a"`} {
		if _, ok := parseOrderedJSON(s); ok {
			t.Fatalf("malformed json %q must refuse", s)
		}
	}
	// Empty object keys keep empty leaf labels in embedded walks.
	root, ok := parseOrderedJSON(`{"": "v"}`)
	if !ok {
		t.Fatal("empty-key fixture must parse")
	}
	values := appendJSONWalkEntries(nil, root, "field"+embeddedJSONLeafContextSuffix, nil, nil)
	for _, v := range values {
		if v.content == "v" && v.label != "" {
			t.Fatalf("empty keys yield empty leaf labels, got %q", v.label)
		}
	}
}

func TestAppendJSONWalkEntriesOrder(t *testing.T) {
	root, ok := parseOrderedJSON(`{"b": {"$ne": 1}, "skip": "x", "a": "plain"}`)
	if !ok {
		t.Fatal("fixture must parse")
	}
	values := appendJSONWalkEntries(nil, root, requestBodyCtx, map[string]bool{"skip": true}, nil)
	// Entries: key b, mongo operator value walk..., key a, leaf plain.
	if len(values) == 0 {
		t.Fatal("walks produce values")
	}
	if values[0].content != "b" {
		t.Fatalf("walks keep insertion order, got %q", values[0].content)
	}
	for _, v := range values {
		if v.content == "skip" {
			t.Fatal("excluded keys drop their subtree")
		}
	}
	// A mongo operator key reports straight from the walk.
	root, _ = parseOrderedJSON(`{"$where": "1"}`)
	values = appendJSONWalkEntries(nil, root, requestBodyCtx, nil, nil)
	if len(values) == 0 || values[0].forcedCategory != "nosql" || values[0].content != "$where" {
		t.Fatalf("mongo operator keys force nosql, got %v", values)
	}
}

func TestAppendJSONWalkEntriesDepthCap(t *testing.T) {
	// Objects deeper than the cap serialize back to compact JSON.
	deep := strings.Repeat(`{"a":`, jsonWalkDepthCap+2) + "1" + strings.Repeat("}", jsonWalkDepthCap+2)
	root, ok := parseOrderedJSON(deep)
	if !ok {
		t.Fatal("deep fixture must parse")
	}
	values := appendJSONWalkEntries(nil, root, requestBodyCtx, nil, nil)
	found := false
	for _, v := range values {
		if strings.Contains(v.content, `{"a":`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("over-deep subtrees serialize, got %d values", len(values))
	}
	// Arrays over the cap serialize too.
	deepArray := strings.Repeat("[", jsonWalkDepthCap+2) + "1" + strings.Repeat("]", jsonWalkDepthCap+2)
	root, _ = parseOrderedJSON(deepArray)
	values = appendJSONWalkEntries(nil, root, requestBodyCtx, nil, nil)
	found = false
	for _, v := range values {
		if strings.HasPrefix(v.content, "[") {
			found = true
		}
	}
	if !found {
		t.Fatalf("over-deep arrays serialize, got %d values", len(values))
	}
}

func TestAppendJSONWalkEntriesLeafReparse(t *testing.T) {
	// Embedded walks re-parse leaf strings and still scan the raw text.
	root, ok := parseOrderedJSON(`{"f": "{\"g\": \"<script>\"}"}`)
	if !ok {
		t.Fatal("fixture must parse")
	}
	values := appendJSONWalkEntries(nil, root, "field"+embeddedJSONLeafContextSuffix, nil, nil)
	rawSeen, nestedSeen := false, false
	for _, v := range values {
		if strings.Contains(v.content, "<script>") {
			nestedSeen = true
		}
		if strings.Contains(v.content, `\u003c`) || strings.HasPrefix(v.content, "{\"") {
			rawSeen = true
		}
	}
	if !nestedSeen {
		t.Fatalf("embedded json leaves re-walk, got %v", values)
	}
	if !rawSeen {
		t.Fatalf("raw leaf strings still scan, got %v", values)
	}
	// The top-level request_body context never re-parses leaves.
	root, _ = parseOrderedJSON(`{"f": "{\"g\": 1}"}`)
	values = appendJSONWalkEntries(nil, root, requestBodyCtx, nil, nil)
	for _, v := range values {
		if strings.Contains(v.context, embeddedJSONLeafContextSuffix) {
			t.Fatal("request body leaves keep their context")
		}
	}
}

func TestSerializeCompactJSON(t *testing.T) {
	root, ok := parseOrderedJSON(`{"b": [1, "x\ny"], "a": {"c": null}}`)
	if !ok {
		t.Fatal("fixture must parse")
	}
	got := serializeCompactJSON(root)
	if got != `{"b":[1,"x\ny"],"a":{"c":null}}` {
		t.Fatalf("compact serialization keeps order and escapes, got %s", got)
	}
}

func TestJSONScalarLiteral(t *testing.T) {
	if got := jsonScalarLiteral("True"); got != "true" {
		t.Fatalf("booleans render as json, got %s", got)
	}
	if got := jsonScalarLiteral("False"); got != "false" {
		t.Fatalf("false renders as json, got %s", got)
	}
	if got := jsonScalarLiteral("None"); got != "null" {
		t.Fatalf("none renders as null, got %s", got)
	}
	if got := jsonScalarLiteral("-1.5E+3"); got != "-1.5E+3" {
		t.Fatalf("numbers keep literals, got %s", got)
	}
	if got := jsonScalarLiteral(`q"\\`); got != `"q\"\\\\"` {
		t.Fatalf("strings quote and escape, got %s", got)
	}
}

func TestIsJSONNumberLiteral(t *testing.T) {
	for _, s := range []string{"", "-", "abc", "1a", "."} {
		if isJSONNumberLiteral(s) {
			t.Fatalf("%q is not a number literal", s)
		}
	}
	for _, s := range []string{"0", "-12.5", "1e10", "2E-3", "1.5+2"} {
		if !isJSONNumberLiteral(s) {
			t.Fatalf("%q is a number literal", s)
		}
	}
}

func TestWriteJSONStringBody(t *testing.T) {
	buf := new(bytes.Buffer)
	writeJSONStringBody(buf, "a\"b\\c\nd\re\tf\bg\x01h\fé")
	got := buf.String()
	if got != `a\"b\\c\nd\re\tf\bg\u0001h\fé` {
		t.Fatalf("string bodies escape controls, got %q", got)
	}
}
