package guardcore

import "fmt"

const pickleWorkBudgetBytes = 4096

func pickleWindowFromChars(s string) ([]byte, bool) {
	// Note: the Python reference also maps surrogate escapes (U+DC80..U+DCFF,
	// Python's surrogateescape error handler) back to their high bytes. Go
	// strings cannot carry those code points: ranging over a string decodes
	// the escaped bytes as U+FFFD, so that branch of the reference mapping is
	// unrepresentable here and every rune must be latin-1 range.
	var window []byte
	for _, r := range s {
		if r > 0xFF {
			return nil, false
		}
		window = append(window, byte(r))
	}
	return window, true
}

type pickleReader struct {
	data []byte
	pos  int
}

func (p *pickleReader) read(n int) ([]byte, error) {
	if p.pos+n > len(p.data) {
		return nil, fmt.Errorf("short read")
	}
	out := p.data[p.pos : p.pos+n]
	p.pos += n
	return out, nil
}

func (p *pickleReader) readline() ([]byte, error) {
	start := p.pos
	for p.pos < len(p.data) {
		if p.data[p.pos] == '\n' {
			p.pos++
			return p.data[start:p.pos], nil
		}
		p.pos++
	}
	return nil, fmt.Errorf("short read line")
}

func (p *pickleReader) u1() (byte, error) {
	b, err := p.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (p *pickleReader) u4() (uint32, error) {
	b, err := p.read(4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, nil
}

func (p *pickleReader) u8() (uint64, error) {
	b, err := p.read(8)
	if err != nil {
		return 0, err
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v, nil
}

type pickleMarkType struct{}

var pickleMark = pickleMarkType{}

func stackPopToMark(stack *[]any) []any {
	s := *stack
	for i := len(s) - 1; i >= 0; i-- {
		if _, ok := s[i].(pickleMarkType); ok {
			items := append([]any{}, s[i+1:]...)
			*stack = s[:i]
			return items
		}
	}
	items := append([]any{}, s...)
	*stack = nil
	return items
}

type pickleVM struct {
	r     pickleReader
	stack []any
	memo  map[int]any
}

func (vm *pickleVM) push(v any) {
	vm.stack = append(vm.stack, v)
}

func (vm *pickleVM) pop() (any, error) {
	if len(vm.stack) == 0 {
		return nil, fmt.Errorf("empty stack")
	}
	v := vm.stack[len(vm.stack)-1]
	vm.stack = vm.stack[:len(vm.stack)-1]
	return v, nil
}

func (vm *pickleVM) step() (reachedReduceBuild bool, done bool, err error) {
	key, err := vm.r.u1()
	if err != nil {
		return false, true, err
	}
	switch key {
	case 0x80:
		if _, err := vm.r.u1(); err != nil {
			return false, true, err
		}
	case 0x95:
		if _, err := vm.r.u8(); err != nil {
			return false, true, err
		}
	case '(':
		vm.push(pickleMark)
	case 't':
		items := stackPopToMark(&vm.stack)
		vm.push(items)
	case ')':
		vm.push([]any{})
	case ']':
		vm.push([]any{})
	case '}':
		vm.push(map[string]any{})
	case 'N':
		vm.push(nil)
	case 'T':
		vm.push(true)
	case 'F':
		vm.push(false)
	case 'S', 'V':
		line, err := vm.r.readline()
		if err != nil {
			return false, true, err
		}
		vm.push(pickleUnquoteString(line))
	case 'X':
		n, err := vm.r.u4()
		if err != nil {
			return false, true, err
		}
		b, err := vm.r.read(int(n))
		if err != nil {
			return false, true, err
		}
		vm.push(string(b))
	case 'U':
		n, err := vm.r.u1()
		if err != nil {
			return false, true, err
		}
		b, err := vm.r.read(int(n))
		if err != nil {
			return false, true, err
		}
		vm.push(string(b))
	case 'C':
		n, err := vm.r.u1()
		if err != nil {
			return false, true, err
		}
		b, err := vm.r.read(int(n))
		if err != nil {
			return false, true, err
		}
		vm.push(b)
	case 'B':
		n, err := vm.r.u4()
		if err != nil {
			return false, true, err
		}
		b, err := vm.r.read(int(n))
		if err != nil {
			return false, true, err
		}
		vm.push(b)
	case 'I':
		line, err := vm.r.readline()
		if err != nil {
			return false, true, err
		}
		vm.push(pickleParseInt(string(line)))
	case 'L':
		line, err := vm.r.readline()
		if err != nil {
			return false, true, err
		}
		vm.push(pickleParseInt(string(line)))
	case 'i':
		n, err := vm.r.u4()
		if err != nil {
			return false, true, err
		}
		vm.push(int32(n))
	case 'K':
		n, err := vm.r.u1()
		if err != nil {
			return false, true, err
		}
		vm.push(int(n))
	case 'M':
		n, err := vm.r.u2()
		if err != nil {
			return false, true, err
		}
		vm.push(int(n))
	case 'G':
		if _, err := vm.r.u8(); err != nil {
			return false, true, err
		}
		vm.push(0.0)
	case 'c':
		if _, err := vm.r.readline(); err != nil {
			return false, true, err
		}
		if _, err := vm.r.readline(); err != nil {
			return false, true, err
		}
		vm.push("global")
	case 'R', 'b':
		return true, true, nil
	case 'a':
		if _, err := vm.pop(); err != nil {
			return false, true, err
		}
	case 'e', 'u', 's':
		stackPopToMark(&vm.stack)
	case 'p', 'g', 'h':
		line, err := vm.r.readline()
		if err != nil {
			return false, true, err
		}
		if key == 'g' || key == 'h' {
			vm.push(nil)
		} else {
			_ = line
		}
	case 'q':
		n, err := vm.r.u1()
		if err != nil {
			return false, true, err
		}
		if key == 'q' {
			vm.push(nil)
		}
		_ = n
	case 'r':
		if _, err := vm.r.u4(); err != nil {
			return false, true, err
		}
		vm.push(nil)
	case 'w', 'x', 'z':
		return false, true, fmt.Errorf("unsupported opcode")
	case '.':
		return false, true, nil
	case 0x85, 0x86, 0x87:
		stackPopToMark(&vm.stack)
		vm.push([]any{})
	case 0x8c, 0x94:
		if _, err := vm.pop(); err != nil {
			return false, true, err
		}
	case 'o', 'j', 'y':
		return false, true, fmt.Errorf("unsupported opcode")
	default:
		return false, true, fmt.Errorf("unknown opcode %d", key)
	}
	return false, false, nil
}

func (p *pickleReader) u2() (uint32, error) {
	b, err := p.read(2)
	if err != nil {
		return 0, err
	}
	return uint32(b[0]) | uint32(b[1])<<8, nil
}

func pickleUnquoteString(line []byte) string {
	s := string(line)
	s = trimRN(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		inner := s[1 : len(s)-1]
		inner = replaceEscapes(inner)
		return inner
	}
	return s
}

func replaceEscapes(s string) string {
	out := make([]rune, 0, len(s))
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		if rs[i] == '\\' && i+1 < len(rs) {
			i++
			switch rs[i] {
			case 'n':
				out = append(out, '\n')
			case 't':
				out = append(out, '\t')
			case 'r':
				out = append(out, '\r')
			default:
				out = append(out, rs[i])
			}
			continue
		}
		out = append(out, rs[i])
	}
	return string(out)
}

func trimRN(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func pickleParseInt(line string) int {
	s := trimRN(line)
	neg := false
	if len(s) > 0 && (s[0] == '-' || s[0] == '+') {
		neg = s[0] == '-'
		s = s[1:]
	}
	v := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + int(c-'0')
	}
	if neg {
		return -v
	}
	return v
}

func pickleWalkPrefix(window []byte, isComplete bool) bool {
	vm := &pickleVM{memo: map[int]any{}}
	vm.r = pickleReader{data: window}
	for vm.r.pos < len(window) {
		_, done, err := vm.step()
		if err != nil {
			return !isComplete
		}
		if done {
			break
		}
	}
	return true
}

func pickleWalkSuffix(window []byte, isComplete bool) bool {
	vm := &pickleVM{memo: map[int]any{}}
	vm.push(struct{}{})
	vm.r = pickleReader{data: window}
	for vm.r.pos < len(window) {
		reached, done, err := vm.step()
		if reached {
			return true
		}
		if err != nil {
			return !isComplete
		}
		if done {
			break
		}
	}
	return !isComplete
}

func pickleGlobalCandidateIsInjection(m rmatch, context string) bool {
	prefix := string(m.runes()[:m.start()])
	prefixRunes := []rune(prefix)
	if !(prefix == "" || prefixRunes[len(prefixRunes)-1] == '\n') {
		window, ok := pickleWindowFromChars(budgetSlice(prefix, pickleWorkBudgetBytes))
		if !ok {
			return false
		}
		if !pickleWalkPrefix(window, len(prefixRunes) <= pickleWorkBudgetBytes) {
			return false
		}
	}
	end1 := m.start() + len([]rune(m.group1()))
	suffixChars := string(m.runes()[end1:])
	window, ok := pickleWindowFromChars(budgetSlice(suffixChars, pickleWorkBudgetBytes))
	if !ok {
		return false
	}
	return pickleWalkSuffix(window, len([]rune(suffixChars)) <= pickleWorkBudgetBytes)
}

func budgetSlice(s string, budget int) string {
	rs := []rune(s)
	if len(rs) > budget {
		rs = rs[:budget]
	}
	return string(rs)
}
