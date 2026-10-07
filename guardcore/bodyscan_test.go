package guardcore

// Port of tests/test_utils/test_body_form_scan.py and the detection cases of
// tests/test_detection/test_multipart_file_part_scanning.py (guard-core 4.0.4
// parity): urlencoded form fields, multipart parts with RFC 7578 filename
// detection, embedded JSON walk leaves, the whole-body blob fallback, the
// inspection budget, and the detection_binary_min_run_length knob.

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
)

func base64StdEncode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func extractValuePairs(rawBody, contentType string, cfg *SecurityConfig) [][2]string {
	values := extractBodyScanValues(rawBody, contentType, cfg, cfg.ExcludedDetectionBodyFields, nil)
	out := make([][2]string, 0, len(values))
	for _, v := range values {
		out = append(out, [2]string{v.context, v.content})
	}
	return out
}

func TestParseFormPairsMirrorsParseQSL(t *testing.T) {
	cases := []struct {
		body string
		want []formPair
	}{
		{"a=b&c", []formPair{{"a", "b"}, {"c", ""}}},
		{"a=b=c&d=&=v&+x=%2F%zz&a=b", []formPair{{"a", "b=c"}, {"d", ""}, {"", "v"}, {" x", "/%zz"}, {"a", "b"}}},
		{"a=1&&b=2&", []formPair{{"a", "1"}, {"b", "2"}}},
		{"", nil},
	}
	for _, tc := range cases {
		got := parseFormPairs(tc.body)
		if len(got) != len(tc.want) {
			t.Fatalf("parseFormPairs(%q) = %v, want %v", tc.body, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("parseFormPairs(%q)[%d] = %v, want %v", tc.body, i, got[i], tc.want[i])
			}
		}
	}
}

func TestFormBodyExtractionContextsAndOrder(t *testing.T) {
	values := extractValuePairs("system=<script>alert(1)</script>&note=hello", "application/x-www-form-urlencoded", testConfig(t))
	want := [][2]string{
		{"request_body", "system"},
		{"request_body:form_field", "<script>alert(1)</script>"},
		{"request_body", "note"},
		{"request_body:form_field", "hello"},
	}
	if len(values) != len(want) {
		t.Fatalf("got %v, want %v", values, want)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("value[%d] = %v, want %v", i, values[i], want[i])
		}
	}
}

func TestFormBodyExcludedFieldSkipsPair(t *testing.T) {
	cfg := testConfig(t)
	cfg.ExcludedDetectionBodyFields = map[string]bool{"user": true}
	values := extractValuePairs("user=<script>alert(1)</script>&ok=1", "application/x-www-form-urlencoded", cfg)
	if len(values) != 2 || values[0][1] != "ok" {
		t.Fatalf("excluded field must skip the whole pair, got %v", values)
	}
}

func TestFormFieldEmbeddedJSONWalkContexts(t *testing.T) {
	values := extractValuePairs(`data={"a":"<script>alert(1)</script>"}`, "application/x-www-form-urlencoded", testConfig(t))
	want := [][2]string{
		{"request_body", "data"},
		{"request_body", "a"},
		{"request_body:form_field:embedded_json", "<script>alert(1)</script>"},
		// Clean-parse fall-through: the raw value still scans after its
		// leaves (embedded_json_scan.py + _check_value_enhanced).
		{"request_body:form_field", `{"a":"<script>alert(1)</script>"}`},
	}
	if len(values) != len(want) {
		t.Fatalf("got %v, want %v", values, want)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("value[%d] = %v, want %v", i, values[i], want[i])
		}
	}
}

// Reference fall-through regression (guard-core embedded_json_scan.py +
// detection_scan._check_value_enhanced): a clean embedded-JSON parse walks
// the leaves first, and when no leaf hits, the RAW value still scans with
// the field context. A payload confined to the raw text (here a duplicate-key
// remnant the walk drops) must therefore still detect.
func TestFormFieldEmbeddedJSONCleanParseStillScansRawValue(t *testing.T) {
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Method = "POST"
		opts.Header = map[string]string{"content-type": "application/x-www-form-urlencoded"}
		opts.Body = []byte(`data={"comment":"<script>alert(1)</script>","comment":"safe"}`)
	})
	categories, _ := detectThreat(req, testConfig(t), resolveDetectionExclusions(testConfig(t), nil))
	assertCategoryPresent(t, categories, "xss")
}

func TestMultipartEmbeddedJSONCleanParseStillScansRawValue(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n" +
		`{"comment":"<script>alert(1)</script>","comment":"safe"}` +
		"\r\n--B0--\r\n"
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	assertCategoryPresent(t, categories, "xss")
}

// The same fall-through one level down: a leaf string that itself parses as
// JSON walks again with another suffix, and the raw leaf text still scans
// with the walk context when the nested walk reports nothing.
func TestEmbeddedJSONLeafReparseCleanParseStillScansRawLeaf(t *testing.T) {
	inner := strings.ReplaceAll(`{"a":"<script>alert(1)</script>","a":"safe"}`, `"`, `\"`)
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Method = "POST"
		opts.Header = map[string]string{"content-type": "application/x-www-form-urlencoded"}
		opts.Body = []byte(`data={"outer":"` + inner + `"}`)
	})
	categories, _ := detectThreat(req, testConfig(t), resolveDetectionExclusions(testConfig(t), nil))
	assertCategoryPresent(t, categories, "xss")
}

func TestMultipartTextPartEntries(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--B0--\r\n"
	values := extractValuePairs(body, multipartContentType, testConfig(t))
	want := [][2]string{
		{"request_body", "note"},
		{"request_body:multipart_field", `Content-Disposition: form-data; name="note"`},
		{"request_body:multipart_field", "hello"},
	}
	if len(values) != len(want) {
		t.Fatalf("got %v, want %v", values, want)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("value[%d] = %v, want %v", i, values[i], want[i])
		}
	}
}

func TestMultipartFilePartEntriesIncludeFilenameAndHeaders(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"report.pdf\"\r\n\r\nbinary-file-payload\r\n--B0--\r\n"
	values := extractValuePairs(body, multipartContentType, testConfig(t))
	want := [][2]string{
		{"request_body", "upload"},
		{"request_body:multipart_field", `filename="report.pdf"`},
		{"request_body:multipart_field", `Content-Disposition: form-data; name="upload"; filename="report.pdf"`},
		{"request_body:multipart_field", "binary-file-payload"},
	}
	if len(values) != len(want) {
		t.Fatalf("got %v, want %v", values, want)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("value[%d] = %v, want %v", i, values[i], want[i])
		}
	}
}

func TestMultipartJSONBodyWalkLeafContexts(t *testing.T) {
	values := extractValuePairs(`{"system":"1 OR 1=1","meta":{"deep":"x"}}`, "application/json", testConfig(t))
	want := [][2]string{
		{"request_body", "system"},
		{"request_body", "1 OR 1=1"},
		{"request_body", "meta"},
		{"request_body", "deep"},
		{"request_body", "x"},
	}
	if len(values) != len(want) {
		t.Fatalf("got %v, want %v", values, want)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("value[%d] = %v, want %v", i, values[i], want[i])
		}
	}
}

func TestJSONBodyExcludedKeySkipsSubtree(t *testing.T) {
	cfg := testConfig(t)
	cfg.ExcludedDetectionBodyFields = map[string]bool{"secret": true}
	values := extractValuePairs(`{"secret":{"a":"<script>alert(1)</script>"},"ok":1}`, "application/json", cfg)
	for _, v := range values {
		if strings.Contains(v[1], "script") {
			t.Fatalf("excluded key subtree must be skipped, got %v", values)
		}
	}
	if len(values) == 0 {
		t.Fatalf("expected the remaining entries to survive")
	}
}

func TestJSONBodyMongoOperatorKeyForcesNosqlHit(t *testing.T) {
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Method = "POST"
		opts.Header = map[string]string{"content-type": "application/json"}
		opts.Body = []byte(`{"$where": "1 OR 1=1"}`)
	})
	categories, _ := detectThreat(req, testConfig(t), resolveDetectionExclusions(testConfig(t), nil))
	assertCategoryPresent(t, categories, "nosql")
}

func TestNonJSONBodyWithJSONContentTypeFallsBackToBlob(t *testing.T) {
	values := extractValuePairs("1 OR 1=1", "application/json", testConfig(t))
	if len(values) != 1 || values[0][0] != "request_body" || values[0][1] != "1 OR 1=1" {
		t.Fatalf("non-JSON body with a JSON content type must scan as one blob, got %v", values)
	}
}

func TestFormBodySQLIDetected(t *testing.T) {
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Method = "POST"
		opts.Header = map[string]string{
			"content-type":   "application/x-www-form-urlencoded",
			"content-length": "17",
		}
		opts.Body = []byte("q=1+OR+1%3D1")
	})
	categories, _ := detectThreat(req, testConfig(t), resolveDetectionExclusions(testConfig(t), nil))
	assertCategoryPresent(t, categories, "sqli")
}

func TestEmptyFilePartContentNotDetected(t *testing.T) {
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("empty.bin", nil))
	assertNoCategories(t, categories)
}

func TestBenignUploadFilenameAndContentNotDetected(t *testing.T) {
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("note.txt", []byte("hello world")))
	assertNoCategories(t, categories)
}

func TestMaliciousUploadFilenameDetected(t *testing.T) {
	for _, filename := range []string{"shell.php.jpg", "evil.php%00.jpg"} {
		cfg := testConfig(t)
		categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody(filename, []byte("harmless-bytes")))
		if len(categories) != 1 || categories[0] != "file_upload" {
			t.Fatalf("filename %q: expected [file_upload], got %v", filename, categories)
		}
	}
}

func TestMaliciousUploadLongFilenamePrefixStillDetected(t *testing.T) {
	for _, padLen := range []int{254, 255, 256, 320} {
		filename := strings.Repeat("A", padLen) + ".php.jpg"
		cfg := testConfig(t)
		categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody(filename, []byte("harmless-bytes")))
		if len(categories) != 1 || categories[0] != "file_upload" {
			t.Fatalf("pad %d: expected [file_upload], got %v", padLen, categories)
		}
	}
}

func TestMaliciousUploadContentDetected(t *testing.T) {
	cases := []struct {
		content  string
		category string
	}{
		{"<script>alert(1)</script>", "xss"},
		{"1' OR '1'='1", "sqli"},
	}
	for _, tc := range cases {
		cfg := testConfig(t)
		categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("note.txt", []byte(tc.content)))
		if len(categories) != 1 || categories[0] != tc.category {
			t.Fatalf("content %q: expected [%s], got %v", tc.content, tc.category, categories)
		}
	}
}

func TestFilenameWithEscapedEmbeddedDoubleQuoteStillDetected(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell\\\".php%00.jpg\"\r\n\r\nharmless\r\n--B0--\r\n"
	values := extractValuePairs(body, multipartContentType, testConfig(t))
	if len(values) < 2 || values[1][1] != `filename="shell.php%00.jpg"` {
		t.Fatalf("escaped quote must be unescaped and stripped: got %v", values)
	}
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) != 1 || categories[0] != "file_upload" {
		t.Fatalf("expected [file_upload], got %v", categories)
	}
}

func TestFilenameWithEmbeddedSingleQuoteStillDetected(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell'.php.jpg\"\r\n\r\nharmless\r\n--B0--\r\n"
	values := extractValuePairs(body, multipartContentType, testConfig(t))
	if len(values) < 2 || values[1][1] != `filename="shell.php.jpg"` {
		t.Fatalf("single quote must be stripped from the filename entry: got %v", values)
	}
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) != 1 || categories[0] != "file_upload" {
		t.Fatalf("expected [file_upload], got %v", categories)
	}
}

func TestFilenameWithEmbeddedNewlineViaRFC2231StillDetected(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename*=UTF-8''shell.php%0A.jpg\r\n\r\nharmless\r\n--B0--\r\n"
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) != 1 || categories[0] != "file_upload" {
		t.Fatalf("expected [file_upload], got %v", categories)
	}
}

func TestFilenameWithSemicolonAndSingleQuoteStillDetected(t *testing.T) {
	filename := `filename="x=1;NOTE:'benign <script>alert(1)</script>';y=2"`
	body := "--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"" + filename + "\"\r\n\r\nbinary-file-payload\r\n--B0--\r\n"
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) == 0 {
		t.Fatalf("expected the smuggled payload in the filename to detect")
	}
}

func TestFilenameWithBareNewlineStillDetected(t *testing.T) {
	filename := "benign <script>alert(1)</script>\nx=1\ny=2"
	body := "--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"" + filename + "\"\r\n\r\nbinary-file-payload\r\n--B0--\r\n"
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) == 0 {
		t.Fatalf("expected the newline-split filename to still detect")
	}
}

func TestFilenameWithBareCRSmuggledHeaderPayloadStillDetected(t *testing.T) {
	filename := "x=1\rcustom-secret-field: '<script>alert(1)</script>'\ry=2"
	body := "--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"" + filename + "\"\r\n\r\nbinary-file-payload\r\n--B0--\r\n"
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) == 0 {
		t.Fatalf("expected the CR-smuggled filename payload to detect")
	}
}

func TestTextFieldWithoutFilenameStillDetectedViaPayload(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n"
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) == 0 {
		t.Fatalf("expected the text part payload to detect")
	}
}

func TestExcludedFieldNameSkipsMaliciousFilePart(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php.jpg\"\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n"
	cfg := testConfig(t)
	cfg.ExcludedDetectionBodyFields = map[string]bool{"file": true}
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	assertNoCategories(t, categories)
}

func TestNoNameFilePartStillDetectedWhenExcludedByFallbackLabel(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; filename=\"shell.php.jpg\"\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n"
	cfg := testConfig(t)
	cfg.ExcludedDetectionBodyFields = map[string]bool{"file": true}
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) == 0 {
		t.Fatalf("a part without a name param has no exclusion key and must stay detected")
	}
}

func TestNoContentDispositionPartMaliciousContentDetected(t *testing.T) {
	body := "--B0\r\nContent-Type: text/plain\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n"
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) == 0 {
		t.Fatalf("expected the disposition-less part payload to detect")
	}
}

func TestNestedMultipartMixedFilePartIsDetected(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"files\"\r\n" +
		"Content-Type: multipart/mixed; boundary=INNER\r\n\r\n" +
		"--INNER\r\nContent-Disposition: attachment; filename=\"shell.php.jpg\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\npayload-bytes" +
		"\r\n--INNER--\r\n--B0--\r\n"
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) != 1 || categories[0] != "file_upload" {
		t.Fatalf("nested multipart/mixed: expected [file_upload], got %v", categories)
	}
	values := extractValuePairs(body, multipartContentType, cfg)
	want := [][2]string{
		{"request_body", "file"},
		{"request_body:multipart_field", `filename="shell.php.jpg"`},
		{"request_body:multipart_field", `Content-Disposition: attachment; filename="shell.php.jpg"`},
		{"request_body:multipart_field", "Content-Type: application/octet-stream"},
		{"request_body:multipart_field", "payload-bytes"},
	}
	if len(values) != len(want) {
		t.Fatalf("nested entries: got %v, want %v", values, want)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("nested entry[%d] = %v, want %v", i, values[i], want[i])
		}
	}
}

func TestNestedMultipartExclusionDoesNotSuppressUnnamedLeaf(t *testing.T) {
	body := "--B0\r\nContent-Disposition: form-data; name=\"files\"\r\n" +
		"Content-Type: multipart/mixed; boundary=INNER\r\n\r\n" +
		"--INNER\r\nContent-Disposition: attachment; filename=\"shell.php.jpg\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\npayload-bytes" +
		"\r\n--INNER--\r\n--B0--\r\n"
	cfg := testConfig(t)
	cfg.ExcludedDetectionBodyFields = map[string]bool{"files": true}
	categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
	if len(categories) == 0 {
		t.Fatalf("the container name must not suppress the unnamed leaf part")
	}
}

func TestBase64TransferEncodedUploadContentDetected(t *testing.T) {
	cases := []struct {
		content  string
		category string
	}{
		{"<script>alert(document.cookie)</script>", "xss"},
		{"' OR '1'='1' -- comment for admin bypass", "sqli"},
	}
	for _, tc := range cases {
		encoded := base64StdEncode([]byte(tc.content))
		body := "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.b64\"\r\n" +
			"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
			encoded + "\r\n--B0--\r\n"
		cfg := testConfig(t)
		categories := multipartBodyRequest(t, cfg, multipartContentType, []byte(body))
		found := false
		for _, category := range categories {
			if category == tc.category {
				found = true
			}
		}
		if !found {
			t.Fatalf("base64 payload %q: expected %s in %v", tc.content, tc.category, categories)
		}
	}
}

func TestBoundaryMismatchFallsBackToWholeBodyBlobScan(t *testing.T) {
	encoded := base64StdEncode([]byte("<script>alert(document.cookie)</script>"))
	raw := "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.b64\"\r\n" +
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		encoded + "\r\n--B0--\r\n"
	values := extractValuePairs(raw, "multipart/form-data; boundary=DOES-NOT-MATCH", testConfig(t))
	if len(values) != 1 || values[0][0] != "request_body" {
		t.Fatalf("unparseable multipart must fall back to one blob value, got %v", values)
	}
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, "multipart/form-data; boundary=DOES-NOT-MATCH", []byte(raw))
	if len(categories) == 0 {
		t.Fatalf("the blob fallback must still detect the base64 payload")
	}
}

func TestMultipartBinaryContentReducedToPrintableIslands(t *testing.T) {
	var raw strings.Builder
	for i := 0; i < 100; i++ {
		for c := 0; c < 256; c++ {
			raw.WriteByte(byte(c))
		}
	}
	content := latin1Decoded([]byte(raw.String()))
	body := "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" + content + "\r\n--B0--\r\n"
	values := extractValuePairs(body, multipartContentType, testConfig(t))
	asciiRun := ""
	for c := 0x20; c <= 0x7e; c++ {
		asciiRun += string(rune(c))
	}
	latinRun := ""
	for c := 0xa1; c <= 0xff; c++ {
		latinRun += string(rune(c))
	}
	// label name scan, filename entry, two part headers, then the island
	// pair per cycle.
	if len(values) != 4+2*100 {
		t.Fatalf("expected 4 entries plus 2 islands per cycle, got %d", len(values))
	}
	if values[0][0] != "request_body" || values[0][1] != "file" {
		t.Fatalf("expected the label name scan first, got %v", values[0])
	}
	if values[1][1] != `filename="photo.jpg"` {
		t.Fatalf("expected the filename entry first, got %v", values[1])
	}
	if values[4][1] != asciiRun || values[5][1] != latinRun {
		t.Fatalf("island pair mismatch: got %q, %q", truncate(values[4][1]), truncate(values[5][1]))
	}
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func TestBenignBinaryCorpusProducesNoThreats(t *testing.T) {
	corpus := []struct {
		filename string
		raw      []byte
	}{
		{"photo.png", pngBytes(4000)},
		{"photo.jpg", jpegBytes(4000)},
		{"anim.gif", gifBytes(4000)},
		{"doc.pdf", pdfBytes(4000)},
		{"archive.zip", corpusZipBytes(4000)},
		{"random.bin", randomNoiseBytes(6, 4000)},
		{"blob.bin", fullByteRange(20)},
	}
	for _, tc := range corpus {
		cfg := testConfig(t)
		categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody(tc.filename, tc.raw))
		assertNoCategories(t, categories)
	}
}

func TestMaliciousFilenameStillDetectedWithBinaryContent(t *testing.T) {
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("shell.php.jpg", fullByteRange(100)))
	if len(categories) != 1 || categories[0] != "file_upload" {
		t.Fatalf("expected [file_upload] with binary content, got %v", categories)
	}
}

func TestPaddedWebshellDetectedDespiteBinaryPadding(t *testing.T) {
	payload := "<?php system($_GET['cmd']); ?>"
	padding := randomNoiseBytes(42, len(payload))
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("shell.jpg", []byte(payload+latin1Decoded(padding))))
	if len(categories) != 1 || categories[0] != "cmd_injection" {
		t.Fatalf("expected [cmd_injection], got %v", categories)
	}
}

func TestPaddedWebshellDetectedWithMajorityBinaryPadding(t *testing.T) {
	payload := "<?php system($_GET['cmd']); ?>"
	padding := randomNoiseBytes(43, len(payload)*4)
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("shell.jpg", []byte(payload+latin1Decoded(padding))))
	if len(categories) == 0 {
		t.Fatalf("expected the webshell island to detect under majority binary padding")
	}
}

func TestPDFFixtureStyleScriptIslandDetected(t *testing.T) {
	// The binary preview fixture style of the logging tests: a PDF header,
	// binary junk, and an embedded script island that must still scan.
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nstream\n")
	pdf.Write(randomNoiseBytes(4, 512))
	pdf.WriteString("\n<script>alert(1)</script>\nendstream\nendobj\n%%EOF")
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("doc.pdf", pdf.Bytes()))
	if len(categories) == 0 {
		t.Fatalf("expected the intact script island inside the PDF fixture to detect")
	}
}

func TestBudgetTruncatesBodyBeforeExtraction(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.Detection.MaxBodyInspectBytes = 16
	})
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	body := []byte(strings.Repeat("x", 16) + "&q=1 OR 1=1")
	if categories := multipartBodyRequest(t, cfg, "application/x-www-form-urlencoded", body); len(categories) != 0 {
		t.Fatalf("attack beyond the inspection budget must not detect, got %v", categories)
	}
	cfgFull, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.Detection.MaxBodyInspectBytes = 256
	})
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	if categories := multipartBodyRequest(t, cfgFull, "application/x-www-form-urlencoded", body); len(categories) == 0 {
		t.Fatalf("the same body within the budget must detect")
	}
}

func TestDetectionBinaryMinRunLengthValidation(t *testing.T) {
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.DetectionBinaryMinRunLength = 3 }); err == nil {
		t.Fatalf("detection_binary_min_run_length below 4 must be rejected")
	}
	if _, err := NewSecurityConfig(func(c *SecurityConfig) { c.DetectionBinaryMinRunLength = 1025 }); err == nil {
		t.Fatalf("detection_binary_min_run_length above 1024 must be rejected")
	}
	cfg := testConfig(t)
	if cfg.DetectionBinaryMinRunLength != 16 {
		t.Fatalf("default detection_binary_min_run_length must be 16, got %d", cfg.DetectionBinaryMinRunLength)
	}
}

func corpusRng(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }

func pngBytes(n int) []byte {
	rng := corpusRng(1)
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, 0x00, 0x00, 0x00, 0x0d)
	out = append(out, []byte("IHDR")...)
	for i := 0; i < 17; i++ {
		out = append(out, byte(rng.Intn(256)))
	}
	out = append(out, 0x00, 0x00, 0x0f, 0xa0)
	out = append(out, []byte("IDAT")...)
	for i := 0; i < n; i++ {
		out = append(out, byte(rng.Intn(256)))
	}
	out = append(out, 0x00, 0x00, 0x00, 0x00)
	out = append(out, []byte("IEND\xaeB`\x82")...)
	return out
}

func jpegBytes(n int) []byte {
	rng := corpusRng(2)
	out := []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
	for i := 0; i < n; i++ {
		out = append(out, byte(rng.Intn(256)))
	}
	return append(out, 0xff, 0xd9)
}

func gifBytes(n int) []byte {
	rng := corpusRng(3)
	out := []byte("GIF89a")
	for i := 0; i < n; i++ {
		out = append(out, byte(rng.Intn(256)))
	}
	return append(out, 0x00, 0x3b)
}

func pdfBytes(n int) []byte {
	rng := corpusRng(4)
	out := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nstream\n")
	for i := 0; i < n; i++ {
		out = append(out, byte(rng.Intn(256)))
	}
	return append(out, []byte("\nendstream\nendobj\n%%EOF")...)
}

func corpusZipBytes(n int) []byte {
	rng := corpusRng(5)
	out := []byte("PK\x03\x04\x14\x00\x00\x00\x08\x00")
	for i := 0; i < n; i++ {
		out = append(out, byte(rng.Intn(256)))
	}
	out = append(out, []byte("PK\x05\x06")...)
	for i := 0; i < 18; i++ {
		out = append(out, 0x00)
	}
	return out
}

func fullByteRange(cycles int) []byte {
	var out []byte
	for i := 0; i < cycles; i++ {
		for c := 0; c < 256; c++ {
			out = append(out, byte(c))
		}
	}
	return out
}
