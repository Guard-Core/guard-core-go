package guardcore

import (
	"strings"
	"testing"
)

func TestProbePickle(t *testing.T) {
	cases := []string{
		"Cz\nAz\nR",
		"c1\nAz\nR",
		"c a.b\ncc\nR",
		"c b.c\ncc\nR",
		"cabc\ndef\nR",
		"x\ncabc\ndef\nR",
		"c a.b.c\nzz\nR",
		"cc.b.a\nczz\nR",
		"cos\nsystem\nR",
		"c__builtin__\neval\nR",
		"cfoo.bar.baz\nqux\nR",
		"c b.a\ncc\nR",
	}
	for _, c := range cases {
		out := pickleGlobalGenericFinditer(newScanText(c))
		t.Logf("%q -> %d matches", c, len(out))
	}
	_ = strings.TrimSpace
}
