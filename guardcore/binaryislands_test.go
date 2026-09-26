package guardcore

// Port of tests/test_utils/test_binary_islands.py (guard-core 4.0.4, upstream
// commit 5f399234) plus the multipart binary-corpus cases of
// tests/test_detection/test_multipart_file_part_scanning.py.
//
// Byte fixtures that Python decodes with latin-1 are rebuilt through the
// latin1Decoded helper (same package) so the scanned strings carry the same
// code points; noise-style fixtures use the engine's own representation
// (raw bytes as a Go string, invalid UTF-8 mapped to U+FFFD).

import (
	"bytes"
	"compress/zlib"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

const multipartContentType = "multipart/form-data; boundary=B0"

func islandsOf(content string, minRunLength int) []string {
	return extractBinaryIslands(content, minRunLength)
}

func TestExtractBinaryIslandsKeepsRunsAtOrAboveMinLength(t *testing.T) {
	islands := islandsOf("\x00abc\x00"+strings.Repeat("x", 16)+"\x00def\x00", 16)
	if len(islands) != 1 || islands[0] != strings.Repeat("x", 16) {
		t.Fatalf("expected [x*16], got %q", islands)
	}
}

func TestExtractBinaryIslandsReturnsRunsSeparately(t *testing.T) {
	islands := islandsOf("\x00"+strings.Repeat("a", 16)+"\x00"+strings.Repeat("b", 16)+"\x00", 16)
	if len(islands) != 2 || islands[0] != strings.Repeat("a", 16) || islands[1] != strings.Repeat("b", 16) {
		t.Fatalf("expected the two runs separately, got %q", islands)
	}
}

func TestExtractBinaryIslandsPreservesNonASCIITextRuns(t *testing.T) {
	text := "Café résumé naïve décor sélection"
	islands := extractBinaryIslands(text, 16)
	if len(islands) != 1 || islands[0] != text {
		t.Fatalf("expected the accented text to stay one run, got %q", islands)
	}
}

func TestExtractBinaryIslandsBelowMinRunLengthReturnsContent(t *testing.T) {
	content := "anything\x00at all"
	islands := extractBinaryIslands(content, 1)
	if len(islands) != 1 || islands[0] != content {
		t.Fatalf("expected [content] for min run 1, got %q", islands)
	}
}

func TestExtractBinaryIslandsKeepsTabNewlineCarriageReturnInsideRuns(t *testing.T) {
	islands := islandsOf("\x00select 1\nfrom t\r\nwhere x=1\x00", 16)
	if len(islands) != 1 || islands[0] != "select 1\nfrom t\r\nwhere x=1" {
		t.Fatalf("expected the whitespace run intact, got %q", islands)
	}
}

func TestValueIsBinaryLikeRejectsTextAndAcceptsNoise(t *testing.T) {
	if valueIsBinaryLike("") {
		t.Fatalf("empty content must not be binary-like")
	}
	if valueIsBinaryLike("plain text body with attack 1 OR 1=1") {
		t.Fatalf("plain text must not be binary-like")
	}
	if valueIsBinaryLike("one null\x00byte") {
		t.Fatalf("one null byte in text must not be binary-like")
	}
	if !valueIsBinaryLike(string(randomNoiseBytes(7, 4096))) {
		t.Fatalf("random noise must be binary-like")
	}
}

// multipartBodyRequest routes a raw body through detectThreat the way
// detect_penetration_attempt does for the Python fixtures.
func multipartBodyRequest(t *testing.T, cfg *SecurityConfig, contentType string, body []byte) []string {
	t.Helper()
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Method = "POST"
		opts.Header = map[string]string{
			"content-type":   contentType,
			"content-length": strconv.Itoa(len(body)),
		}
		opts.Body = body
	})
	categories, _ := detectThreat(req, cfg, resolveDetectionExclusions(cfg, nil))
	return categories
}

func assertNoCategories(t *testing.T, categories []string) {
	t.Helper()
	if len(categories) != 0 {
		t.Fatalf("expected no detection, got categories %v", categories)
	}
}

func assertCategoryPresent(t *testing.T, categories []string, want string) {
	t.Helper()
	for _, category := range categories {
		if category == want {
			return
		}
	}
	t.Fatalf("expected %s in categories, got %v", want, categories)
}

// randomNoiseBytes mirrors _noise_bytes: a seeded uniform byte stream.
func randomNoiseBytes(seed int64, size int) []byte {
	rng := rand.New(rand.NewSource(seed))
	raw := make([]byte, size)
	for i := range raw {
		raw[i] = byte(rng.Intn(256))
	}
	return raw
}

// compressedBytes mirrors _compressed_bytes: zlib at level 9 over random
// bytes, so the result decodes to binary-dense text under any engine's
// string model.
func compressedBytes(t *testing.T, seed int64, size int) []byte {
	t.Helper()
	raw := randomNoiseBytes(seed, size)
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		t.Fatalf("zlib writer: %v", err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func filePartBody(filename string, content []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"")
	buf.WriteString(filename)
	buf.WriteString("\"\r\n\r\n")
	buf.Write(content)
	buf.WriteString("\r\n--B0--\r\n")
	return buf.Bytes()
}

func TestPatternsCannotSpanSeparateIslands(t *testing.T) {
	runOne := "choose one: SELECT"
	runTwo := "* FROM x" + strings.Repeat("Y", 10)
	var payload bytes.Buffer
	payload.Write(compressedBytes(t, 17, 4096))
	payload.WriteByte('\x00')
	payload.WriteString(runOne)
	payload.WriteByte('\x00')
	payload.WriteString(runTwo)
	payload.WriteByte('\x00')
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("dump.bin", payload.Bytes()))
	assertNoCategories(t, categories)
}

func TestCompressedFilePartWithShortFragmentNotDetected(t *testing.T) {
	var payload bytes.Buffer
	payload.Write(compressedBytes(t, 11, 4096))
	payload.WriteByte('\x00')
	payload.WriteString("1 OR 1=1")
	payload.WriteByte('\x00')
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("installer.zip", payload.Bytes()))
	assertNoCategories(t, categories)
}

func TestCompressedFilePartWithEmbeddedScriptDetected(t *testing.T) {
	var payload bytes.Buffer
	payload.Write(compressedBytes(t, 12, 4096))
	payload.WriteByte('\x00')
	payload.WriteString("<script>alert(1)</script>")
	payload.WriteByte('\x00')
	payload.Write(compressedBytes(t, 13, 4096))
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("page.html.bin", payload.Bytes()))
	if len(categories) == 0 {
		t.Fatalf("expected the embedded script island to detect")
	}
}

func TestTextFilePartFullyScanned(t *testing.T) {
	payload := "-- benign --\r\nSELECT name FROM users; <script>alert(1)</script>\r\n"
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("notes.txt", []byte(payload)))
	if len(categories) == 0 {
		t.Fatalf("expected the text upload to be fully scanned and detect")
	}
}

func TestLowerMinRunLengthRestoresShortFragmentDetection(t *testing.T) {
	var payload bytes.Buffer
	payload.Write(compressedBytes(t, 14, 4096))
	payload.WriteByte('\x00')
	payload.WriteString("1 OR 1=1")
	payload.WriteByte('\x00')
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.DetectionBinaryMinRunLength = 4
	})
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	categories := multipartBodyRequest(t, cfg, multipartContentType, filePartBody("data.bin", payload.Bytes()))
	if len(categories) == 0 {
		t.Fatalf("expected detection with min run length 4")
	}
}

func TestOctetStreamBinaryBodyStillFullyScanned(t *testing.T) {
	var body bytes.Buffer
	body.Write(compressedBytes(t, 15, 4096))
	body.WriteByte('\x00')
	body.WriteString("1 OR 1=1")
	body.WriteByte('\x00')
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, "application/octet-stream", body.Bytes())
	assertCategoryPresent(t, categories, "sqli")
}

func TestOctetStreamBinaryBodyWithEmbeddedScriptDetected(t *testing.T) {
	var body bytes.Buffer
	body.Write(compressedBytes(t, 16, 4096))
	body.WriteByte('\x00')
	body.WriteString("<script>alert(1)</script>")
	body.WriteByte('\x00')
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, "application/octet-stream", body.Bytes())
	if len(categories) == 0 {
		t.Fatalf("expected the whole-body scan to detect the embedded script")
	}
}

func TestShortTextBodyKeepsFullScan(t *testing.T) {
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, "text/plain", []byte("1 OR 1=1"))
	assertCategoryPresent(t, categories, "sqli")
}

func TestMostlyTextBodyWithSingleNullKeepsFullScan(t *testing.T) {
	cfg := testConfig(t)
	categories := multipartBodyRequest(t, cfg, "text/plain", []byte("benign body with 1 OR 1=1\x00"))
	assertCategoryPresent(t, categories, "sqli")
}
