package guardcore

// Coverage tests for the pickle opcode VM used by the injection heuristics.

import (
	"strings"
	"testing"
)

func TestPickleWindowFromChars(t *testing.T) {
	window, ok := pickleWindowFromChars(string(rune('a')) + string(rune('b')) + string(rune(0x80)))
	if !ok || string(window) == "" {
		t.Fatalf("latin-1 windows pass through, got %q %v", window, ok)
	}
	// Anything above latin-1 (real multibyte text) is not a pickle window.
	if _, ok := pickleWindowFromChars("h\u4e2dlllo"); ok {
		t.Fatal("multibyte text must be rejected")
	}
	if _, ok := pickleWindowFromChars(string(rune(0x100))); ok {
		t.Fatal("the first code point above latin-1 must be rejected")
	}
}

func TestPickleReaderShortReads(t *testing.T) {
	r := &pickleReader{data: []byte("abc")}
	if _, err := r.read(4); err == nil {
		t.Fatal("a short read must fail")
	}
	if b, err := r.read(2); err != nil || string(b) != "ab" {
		t.Fatalf("in-bounds reads must succeed, got %q %v", b, err)
	}
	if _, err := r.readline(); err == nil {
		t.Fatal("a line without a newline must fail")
	}
	r2 := &pickleReader{data: []byte("one\ntwo\n")}
	if line, err := r2.readline(); err != nil || string(line) != "one\n" {
		t.Fatalf("readline must include the newline, got %q %v", line, err)
	}
	if line, err := r2.readline(); err != nil || string(line) != "two\n" {
		t.Fatalf("readline must advance, got %q %v", line, err)
	}
	if _, err := r2.readline(); err == nil {
		t.Fatal("exhausted readers must fail")
	}
	r3 := &pickleReader{data: []byte{1}}
	if _, err := r3.u1(); err != nil {
		t.Fatalf("u1: %v", err)
	}
	if _, err := r3.u1(); err == nil {
		t.Fatal("u1 must fail when exhausted")
	}
	r4 := &pickleReader{data: []byte{1, 2, 3}}
	if _, err := r4.u4(); err == nil {
		t.Fatal("u4 must fail on short data")
	}
	r5 := &pickleReader{data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	v, err := r5.u8()
	if err != nil || v != 0x0807060504030201 {
		t.Fatalf("u8 must decode little endian, got %#x %v", v, err)
	}
	r6 := &pickleReader{data: []byte{1, 2, 3}}
	if _, err := r6.u8(); err == nil {
		t.Fatal("u8 must fail on short data")
	}
	r7 := &pickleReader{data: []byte{0x34, 0x12}}
	if v, err := r7.u2(); err != nil || v != 0x1234 {
		t.Fatalf("u2 must decode little endian, got %#x %v", v, err)
	}
	if _, err := (&pickleReader{data: []byte{1}}).u2(); err == nil {
		t.Fatal("u2 must fail on short data")
	}
}

func TestStackPopToMark(t *testing.T) {
	stack := []any{"a", pickleMark, "b", "c"}
	items := stackPopToMark(&stack)
	if len(items) != 2 || items[0] != "b" || items[1] != "c" {
		t.Fatalf("items above the mark pop, got %v", items)
	}
	if len(stack) != 1 || stack[0] != "a" {
		t.Fatalf("the mark and items leave the stack, got %v", stack)
	}
	// Without a mark everything pops.
	stack = []any{"x", "y"}
	items = stackPopToMark(&stack)
	if len(items) != 2 || len(stack) != 0 {
		t.Fatalf("a markless stack empties, got %v / %v", items, stack)
	}
}

func stepAll(t *testing.T, data []byte) {
	t.Helper()
	vm := &pickleVM{memo: map[int]any{}}
	vm.r = pickleReader{data: data}
	for vm.r.pos < len(data) {
		_, done, err := vm.step()
		if err != nil {
			t.Fatalf("step failed at %d: %v", vm.r.pos, err)
		}
		if done {
			return
		}
	}
}

func TestPickleVMOpcodeCoverage(t *testing.T) {
	t.Run("protocol header and stack ops", func(t *testing.T) {
		stepAll(t, []byte{0x80, 0x04, '(', 't', ')', ']', '}', 'N', 'T', 'F', '.'})
		stepAll(t, []byte{0x95, 8, 0, 0, 0, 0, 0, 0, 0, '.'})
	})
	t.Run("strings", func(t *testing.T) {
		stepAll(t, []byte("S'hello\\n world'\n."))
		stepAll(t, []byte("V'quoted'\n."))
	})
	t.Run("binstring variants", func(t *testing.T) {
		stepAll(t, []byte{'X', 5, 0, 0, 0, 'h', 'e', 'l', 'l', 'o', '.'})
		stepAll(t, []byte{'U', 5, 'w', 'o', 'r', 'l', 'd', '.'})
		stepAll(t, []byte{'C', 3, 'a', 'b', 'c', '.'})
		stepAll(t, []byte{'B', 2, 0, 0, 0, 'x', 'y', '.'})
	})
	t.Run("short reads fail cleanly", func(t *testing.T) {
		if pickleWalkPrefix([]byte{'X', 9, 0, 0}, false) != true {
			t.Fatal("incomplete streams with short reads stay candidates")
		}
		if pickleWalkPrefix([]byte{'X', 9, 0, 0}, true) != false {
			t.Fatal("complete streams with short reads are rejected")
		}
	})
	t.Run("numbers", func(t *testing.T) {
		stepAll(t, []byte("I42\n."))
		stepAll(t, []byte("L-7\n."))
		stepAll(t, []byte{'i', 1, 0, 0, 0, '.'})
		stepAll(t, []byte{'K', 9, '.'})
		stepAll(t, []byte{'M', 0x34, 0x12, '.'})
		stepAll(t, []byte{'G', 1, 2, 3, 4, 5, 6, 7, 8, '.'})
	})
	t.Run("globals and reductions", func(t *testing.T) {
		stepAll(t, []byte("cos\nsystem\nR'."))
		stepAll(t, []byte("cos\nsystem\nb'."))
	})
	t.Run("append and setops", func(t *testing.T) {
		stepAll(t, []byte(")I1\nI2\na."))
		stepAll(t, []byte("(I1\nI2\ne."))
		stepAll(t, []byte("(I1\nu."))
		stepAll(t, []byte("(I1\ns."))
	})
	t.Run("memo opcodes", func(t *testing.T) {
		stepAll(t, []byte("p0\n."))
		stepAll(t, []byte("g0\n."))
		stepAll(t, []byte("h0\n."))
		stepAll(t, []byte{'q', 5, '.'})
		stepAll(t, []byte{'r', 1, 0, 0, 0, '.'})
	})
	t.Run("unsupported opcodes", func(t *testing.T) {
		for _, bad := range []struct {
			data []byte
			name string
		}{
			{[]byte{'w'}, "w"}, {[]byte{'x'}, "x"}, {[]byte{'z'}, "z"},
			{[]byte{'o'}, "o"}, {[]byte{'j'}, "j"}, {[]byte{'y'}, "y"},
			{[]byte{0x01}, "unknown"},
		} {
			if pickleWalkPrefix(bad.data, true) {
				t.Fatalf("opcode %q must reject complete streams", bad.name)
			}
		}
	})
	t.Run("proto-family setops", func(t *testing.T) {
		stepAll(t, []byte{0x85, '.'})
		stepAll(t, []byte{0x86, '.'})
		stepAll(t, []byte{0x87, '.'})
		stepAll(t, []byte{'N', 0x8c, '.'})
		stepAll(t, []byte{'N', 0x94, '.'})
	})
}

func TestPickleWalkSuffixReduction(t *testing.T) {
	// A reduction opcode reached mid-stream marks the suffix as injected.
	if !pickleWalkSuffix([]byte("cos\nsystem\nR"), false) {
		t.Fatal("a reachable reduce must mark the suffix")
	}
	// A clean complete suffix stays clean.
	if pickleWalkSuffix([]byte("I0\n."), true) {
		t.Fatal("a complete clean suffix must not be flagged")
	}
	if !pickleWalkSuffix([]byte("I0\n."), false) {
		t.Fatal("an incomplete clean suffix stays a candidate")
	}
	if pickleWalkSuffix([]byte{0x01}, true) {
		t.Fatal("unknown opcodes reject complete suffixes")
	}
}

func TestPickleUnquoteString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"'hello'\n", "hello"},
		{"\"world\"\r\n", "world"},
		{"'a\\nb'\n", "a\nb"},
		{"'a\\tb\\rc'\n", "a\tb\rc"},
		{"'a\\xb'\n", "axb"},
		{"plain\n", "plain"},
		{"unterminated'", "unterminated'"},
	}
	for _, tc := range cases {
		if got := pickleUnquoteString([]byte(tc.in)); got != tc.want {
			t.Fatalf("pickleUnquoteString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReplaceEscapesAndTrimRN(t *testing.T) {
	if got := replaceEscapes(`a\nb\tc\rd\\e`); got != "a\nb\tc\rd\\e" {
		t.Fatalf("escape decoding mismatch: %q", got)
	}
	if got := replaceEscapes(`trailing\`); got != `trailing\` {
		t.Fatalf("a trailing backslash stays, got %q", got)
	}
	if got := trimRN("x\r\n"); got != "x" {
		t.Fatalf("trailing newlines trim, got %q", got)
	}
	if got := trimRN(""); got != "" {
		t.Fatalf("empty strings stay empty, got %q", got)
	}
}

func TestPickleParseInt(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"42\n", 42},
		{"-7\r\n", -7},
		{"+5\n", 5},
		{"12abc\n", 12},
		{"\n", 0},
		{"999999", 999999},
	}
	for _, tc := range cases {
		if got := pickleParseInt(tc.in); got != tc.want {
			t.Fatalf("pickleParseInt(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestPickleGlobalCandidateIsInjection(t *testing.T) {
	// A real match from the detection registry: "cos\nsystem\nR" buried in a
	// stream whose prefix parses as clean pickle and whose suffix reduces.
	text := "S'ok'\ncos\nsystem\nR tail"
	scan := newScanText(text)
	start := strings.Index(text, "cos")
	full := newScanText("cos\nsystem\nR")
	m := matchFromIndices(scan, start, start+len("cos\nsystem\nR"), "")
	_ = full
	if !pickleGlobalCandidateIsInjection(m, "body") {
		t.Fatal("a reduction after a clean prefix must be flagged")
	}
	// A suffix that never reduces stays a candidate (incomplete walk).
	text2 := "S'ok'\ncos\nsystem\nR trailing text"
	scan2 := newScanText(text2)
	start2 := strings.Index(text2, "cos")
	m2 := matchFromIndices(scan2, start2, start2+len("cos\nsystem\nR"), "")
	if !pickleGlobalCandidateIsInjection(m2, "body") {
		t.Fatal("an unparseable suffix stays a candidate under the incomplete rule")
	}
	// A non-pickle prefix disqualifies the candidate.
	text3 := "hello world cos\nsystem\nR"
	scan3 := newScanText(text3)
	start3 := strings.Index(text3, "cos")
	m3 := matchFromIndices(scan3, start3, start3+len("cos\nsystem\nR"), "")
	if pickleGlobalCandidateIsInjection(m3, "body") {
		t.Fatal("a non-pickle prefix must disqualify the candidate")
	}
}

func TestBudgetSlice(t *testing.T) {
	long := strings.Repeat("a", pickleWorkBudgetBytes+10)
	if got := budgetSlice(long, pickleWorkBudgetBytes); len(got) != pickleWorkBudgetBytes {
		t.Fatalf("budgeted slices cap, got %d", len(got))
	}
	if got := budgetSlice("short", 10); got != "short" {
		t.Fatalf("short strings pass through, got %q", got)
	}
}

func TestPickleVMTruncatedOperands(t *testing.T) {
	// Every opcode whose operand read runs off the end of the stream must
	// fail the step without panicking; complete streams reject, incomplete
	// ones stay candidates.
	truncated := [][]byte{
		{0x80},         // proto without version
		{0x95, 1, 2},   // frame without a full length
		{'X', 9, 0, 0}, // binstring with a short payload
		{'U', 9},       // short binunicode
		{'C', 9},       // short binbytes
		{'B', 9, 0, 0}, // short binbytes4
		[]byte("S"),    // string without a line
		[]byte("V"),    // unicode without a line
		[]byte("I"),    // int without a line
		[]byte("L"),    // long without a line
		{'i', 1},       // binint without a full length
		{'K'},          // binuint1 without a byte
		{'M', 1},       // binuint2 without a full length
		{'G', 1, 2},    // binfloat without a full length
		[]byte("c"),    // global without lines
		[]byte("c\n"),  // global with one line
		{'q'},          // binput without a byte
		{'r', 1, 2},    // long binput without a length
		{'a'},          // append from an empty stack
		{0x8c},         // pop from an empty stack
		{0x94},         // pop from an empty stack
	}
	for _, data := range truncated {
		vm := &pickleVM{memo: map[int]any{}}
		vm.r = pickleReader{data: data}
		errored := false
		for vm.r.pos < len(data) {
			_, done, err := vm.step()
			if err != nil {
				errored = true
				break
			}
			if done {
				break
			}
		}
		if !errored {
			t.Fatalf("truncated payload %v must fail a step", data)
		}
		if !pickleWalkPrefix(data, true) == false {
			t.Fatalf("complete truncated payload %v must be rejected", data)
		}
		if !pickleWalkPrefix(data, false) {
			t.Fatalf("incomplete truncated payload %v stays a candidate", data)
		}
	}
	// The suffix walk reports errors on complete streams too.
	if pickleWalkSuffix([]byte{0x8c}, true) {
		t.Fatal("a complete stream with a stack error must be rejected")
	}
	if !pickleWalkSuffix([]byte{0x8c}, false) {
		t.Fatal("an incomplete stream with a stack error stays a candidate")
	}
	if !pickleWalkSuffix([]byte{0x8c, 0x8c}, false) {
		t.Fatal("a double pop on an incomplete stream stays a candidate")
	}
}

func TestPickleWalkTerminationAndNonPickleWindows(t *testing.T) {
	// A stream ending in STOP terminates the walk before exhaustion.
	if !pickleWalkPrefix([]byte("N."), false) {
		t.Fatal("a terminated walk succeeds")
	}
	if pickleWalkSuffix([]byte("N."), true) {
		t.Fatal("a terminated clean suffix stays clean")
	}
	// The step error on an exhausted reader surfaces directly.
	vm := &pickleVM{memo: map[int]any{}}
	vm.r = pickleReader{data: []byte{}}
	if _, _, err := vm.step(); err == nil {
		t.Fatal("an exhausted reader must fail the step")
	}
	// Operand reads that fail after a successful length read.
	for _, data := range [][]byte{
		{'X', 5, 0, 0, 0},
		{'U'},
		{'C'},
		{'B', 1},
		{'B', 5, 0, 0, 0},
	} {
		vm := &pickleVM{memo: map[int]any{}}
		vm.r = pickleReader{data: data}
		if _, _, err := vm.step(); err == nil {
			t.Fatalf("payload %v must fail its operand read", data)
		}
	}
	// Non-latin-1 windows disqualify the candidate outright.
	text := "h\u4e2dcos\nsystem\nR"
	scan := newScanText(text)
	start := strings.Index(text, "cos")
	m := matchFromIndices(scan, start, start+len("cos\nsystem\nR"), "")
	if pickleGlobalCandidateIsInjection(m, "body") {
		t.Fatal("a non-latin-1 prefix must disqualify the candidate")
	}
	text2 := "cos\nsystem\nR h\u4e2d"
	scan2 := newScanText(text2)
	m2 := matchFromIndices(scan2, 0, len("cos\nsystem\nR"), "")
	if pickleGlobalCandidateIsInjection(m2, "body") {
		t.Fatal("a non-latin-1 suffix must disqualify the candidate")
	}
}
