package guardcore

import (
	"strings"
	"testing"
)

// The four findings the redaction fuzz gate drove (M6): each fix here has
// a deterministic regression pin. The fuzz seed corpus alone only re-fires
// the malformed-query finding (the leak invariant skips pairs the shipped
// scanner grammar does not recognize, so a grammar regression silently
// disables its own check); these pins assert the fixed behaviors directly.
func TestRedactionFuzzFindingsRegressions(t *testing.T) {
	sensitive := map[string]bool{"token": true}

	t.Run("nonsensitive label swallow rescans the value", func(t *testing.T) {
		out := RedactBlobForDisplay("reason: token=SAMPLE-VALUE-01", sensitive, nil, nil)
		if strings.Contains(out, "SAMPLE-VALUE-01") {
			t.Fatalf("the sensitive pair behind the label leaked: %q", out)
		}
	})

	t.Run("unterminated quoted value still redacts", func(t *testing.T) {
		out := RedactBlobForDisplay(`token="000000`, sensitive, nil, nil)
		if strings.Contains(out, "000000") {
			t.Fatalf("the unterminated quoted value leaked: %q", out)
		}
		terminated := RedactBlobForDisplay(`token="000000"`, sensitive, nil, nil)
		if strings.Contains(terminated, "000000") {
			t.Fatalf("the terminated quoted value leaked: %q", terminated)
		}
	})

	t.Run("malformed urls and queries never skip redaction", func(t *testing.T) {
		// A query escape url.ParseQuery rejects must still pair-redact.
		out := RedactURLForDisplay("/?token=SAMPLE-VALUE-01%zz", sensitive, nil, nil)
		if strings.Contains(out, "SAMPLE-VALUE-01") {
			t.Fatalf("the malformed query leaked: %q", out)
		}
		// A URL url.Parse itself rejects falls back to the blob redactor.
		raw := "http://example.com/?token=SAMPLE-VALUE-01 and %zz"
		out = RedactURLForDisplay(raw, sensitive, nil, nil)
		if strings.Contains(out, "SAMPLE-VALUE-01") {
			t.Fatalf("the unparseable URL leaked: %q", out)
		}
	})

	t.Run("url fragments redact like queries", func(t *testing.T) {
		out := RedactURLForDisplay("/#token=SAMPLE-VALUE-01", sensitive, nil, nil)
		if strings.Contains(out, "SAMPLE-VALUE-01") {
			t.Fatalf("the fragment leaked: %q", out)
		}
	})
}
