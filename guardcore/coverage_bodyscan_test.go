package guardcore

// Coverage tests for the body scan value extraction (bodyscan.go).

import (
	"strings"
	"testing"
)

func TestAppendMultipartPartValuesEmptyPart(t *testing.T) {
	// A part with only a name and no payload yields no entries and is not
	// scanned.
	cfg := &SecurityConfig{DetectionBinaryMinRunLength: 4}
	values := appendMultipartPartValues(nil, multipartPart{}, cfg, nil, nil)
	if len(values) != 0 {
		t.Fatalf("payload-less parts are not scanned, got %v", values)
	}
}

func TestPartRFC2231Filename(t *testing.T) {
	// The extended single-segment form decodes through the charset prefix.
	part := multipartPart{
		headers: []mimeHeaderEntry{
			{name: "Content-Disposition", value: `form-data; name="f"; filename*=utf-8''%61%62%63.txt`},
		},
	}
	if got, ok := partRFC2231Filename(part); !ok || got != "abc.txt" {
		t.Fatalf("extended filenames decode, got %q %v", got, ok)
	}
	// Segmented forms join and decode.
	part = multipartPart{
		headers: []mimeHeaderEntry{
			{name: "Content-Disposition", value: `form-data; filename*0*=utf-8''%61%62; filename*1*=cd.txt`},
		},
	}
	if got, ok := partRFC2231Filename(part); !ok || got != "abcd.txt" {
		t.Fatalf("segmented filenames join, got %q %v", got, ok)
	}
	// Parts without disposition params find nothing.
	if _, ok := partRFC2231Filename(multipartPart{}); ok {
		t.Fatal("header-less parts find nothing")
	}
}

func TestMergeRFC2231Segments(t *testing.T) {
	if got, ok := mergeRFC2231Segments(map[string]string{
		"filename*0*": "ab",
		"filename*1*": "cd",
	}, "filename"); !ok || got != "abcd" {
		t.Fatalf("segments join in order, got %q %v", got, ok)
	}
	if _, ok := mergeRFC2231Segments(map[string]string{"other*0*": "x"}, "filename"); ok {
		t.Fatal("missing segments find nothing")
	}
}

func TestParseHeaderParamsEmpty(t *testing.T) {
	main, params := parseHeaderParams("")
	if main != "" || len(params) != 0 {
		t.Fatalf("empty headers parse to defaults, got %q %v", main, params)
	}
	main, params = parseMediaTypeParams("")
	if main != "" || len(params) != 0 {
		t.Fatalf("empty media types parse to defaults, got %q %v", main, params)
	}
}

func TestPercentDecodeTolerant(t *testing.T) {
	// Content without percents passes through.
	if got := percentDecodeTolerant("plain"); got != "plain" {
		t.Fatalf("clean text passes through, got %q", got)
	}
	// Valid escapes decode in both cases.
	if got := percentDecodeTolerant("a%41b%4Ac"); got != "aAbJc" {
		t.Fatalf("escapes decode, got %q", got)
	}
	// Stray percents survive.
	if got := percentDecodeTolerant("100%"); got != "100%" {
		t.Fatalf("stray percents survive, got %q", got)
	}
}

func TestHexVal(t *testing.T) {
	if v, ok := hexVal('a'); !ok || v != 10 {
		t.Fatalf("lowercase hex decodes, got %d %v", v, ok)
	}
	if v, ok := hexVal('F'); !ok || v != 15 {
		t.Fatalf("uppercase hex decodes, got %d %v", v, ok)
	}
	if _, ok := hexVal('g'); ok {
		t.Fatal("letters past f fail")
	}
}

func TestAppendMultipartPartValuesBinaryIslands(t *testing.T) {
	cfg := &SecurityConfig{DetectionBinaryMinRunLength: 4}
	binaryPayload := "\x00\x01\x02" + strings.Repeat("attack payload ", 4) + "\x02\x03"
	values := appendMultipartPartValues(nil, multipartPart{
		headers: []mimeHeaderEntry{
			{name: "Content-Disposition", value: `form-data; name="file"; filename="blob.bin"`},
		},
		payload: []byte(binaryPayload),
	}, cfg, nil, nil)
	found := false
	for _, v := range values {
		if strings.Contains(v.content, "attack payload") {
			found = true
		}
	}
	if !found {
		t.Fatalf("binary parts carry islands, got %d values", len(values))
	}
}
