package extract

// BIFF8 (.xls) XLM formula ptg-token folder — XLM-2.
//
// Legacy Excel-4.0 macrosheets store each FORMULA cell's expression not as text
// (as OOXML .xlsm does in <f> elements) but as a stream of parsed-expression
// tokens ("ptg"s) in reverse-Polish order. To make obfuscated string payloads
// (=CHAR(104)&CHAR(116)&"tp://evil"…, =EXEC("…")) visible to the keyword/URL/IOC
// YARA rules, we statically evaluate that token stream back into a formula
// string and feed the SAME shared sink (emitFoldedFormula / foldXLMFormulaDepth)
// the OOXML path uses, so the two container forms cannot drift on caps/markers.
//
// This is a STATIC string folder, not an interpreter: ptgConcat reassembles
// adjacent operands, ptgStr/ptgInt/ptgBool push literals, ptgFunc/ptgFuncVar
// wrap their arguments in a "=NAME(args)" shape (so dangerous-func detection
// fires), CHAR(n) folds to its byte, and every reference/name/array token pushes
// a neutral placeholder.
// No cell dereferencing, no control flow, no execution.
//
// ptg opcodes, operand sizes and the function-id table are reimplemented from
// the MS-XLS spec as cross-checked against ClamAV libclamav/xlm_extract.c and
// oletools plugin_biff.py (see oletools-reference.md §4). No code was copied.
//
// Fail-open + bounded: a malformed/truncated token stream returns whatever was
// folded so far; the token count, operand-stack depth and output length are all
// capped so a hostile blob cannot exhaust CPU or memory. Never panics.
//
// XLM-2 provides the parser only. Wiring it into the BIFF8 FORMULA (0x06) record
// walk in xlm.go is XLM-3.

import (
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

// BIFF8 ptg base opcodes (high class bits masked with &0x7f, matching the
// reference token dispatch). The value/ref/array class variants of the function
// and reference tokens (0x40/0x60 offsets) are normalised in parseBIFF8Formula.
const (
	ptgConcat  = 0x08 // binary: pop 2, push concatenation
	ptgStr     = 0x17 // operand: 1-byte cch + 1-byte fHighByte flag + chars
	ptgBool    = 0x1D // operand: 1 byte (0/1)
	ptgInt     = 0x1E // operand: uint16 LE
	ptgNum     = 0x1F // operand: 8-byte IEEE double (skipped, neutral push)
	ptgFunc    = 0x21 // function, fixed argc: uint16 func id
	ptgFuncVar = 0x22 // function, variable argc: 1-byte argc + uint16 func id
	ptgName    = 0x23 // defined-name reference (skip 4 bytes)
	ptgRef     = 0x24 // cell reference (skip 4 bytes)
	ptgArea    = 0x25 // area reference (skip 8 bytes)
	ptgMemArea = 0x26 // reference subexpression (skip 6 bytes)
	ptgExp     = 0x01 // shared-formula/array exp pointer (skip 4 bytes)
	ptgRef3d   = 0x3A // 3-D cell reference (skip 6 bytes)
	ptgArea3d  = 0x3B // 3-D area reference (skip 10 bytes)
	ptgNameX   = 0x39 // external name reference (skip 6 bytes)
	ptgAttr    = 0x19 // control attribute (variable size)

	// Single-byte arithmetic / comparison / reference operator ptgs (MS-XLS
	// §2.5.198). Each is exactly 1 byte — opcode only, no operand bytes. They
	// have no value/array class variants so normalizePtg passes them unchanged.

	// Binary operators: pop 2 operands, push "" (neutral string — this is a
	// static folder, not an evaluator; keeping stack arity correct is the goal).
	ptgAdd   = 0x03
	ptgSub   = 0x04
	ptgMul   = 0x05
	ptgDiv   = 0x06
	ptgPower = 0x07
	ptgLT    = 0x09
	ptgLE    = 0x0A
	ptgEQ    = 0x0B
	ptgGE    = 0x0C
	ptgGT    = 0x0D
	ptgNE    = 0x0E
	ptgIsect = 0x0F
	ptgUnion = 0x10
	ptgRange = 0x11

	// Unary operators: pop 1 operand, push it back unchanged (no payload).
	ptgUplus   = 0x12
	ptgUminus  = 0x13
	ptgPercent = 0x14

	// ptgParen (0x15): grouping marker — no stack change, advance 1 byte.
	ptgParen = 0x15

	// ptgMissArg (0x16): missing optional argument — push "" so downstream
	// ptgFuncVar still sees the right argument count.
	ptgMissArg = 0x16
)

// BIFF8 ptg fold caps.
const (
	// maxBIFFPtgTokens caps the number of ptg tokens parsed per formula — a
	// FORMULA cell with more tokens than this is anomalous; we stop and fold
	// what we have rather than spin on a hostile/garbage stream.
	maxBIFFPtgTokens = 8192
	// maxBIFFPtgStackDepth caps the operand stack — ptgConcat is the only op
	// that pops, so an all-operand stream of N tokens leaves N items on the
	// stack; cap it so memory stays bounded.
	maxBIFFPtgStackDepth = 4096
	// maxBIFFPtgOutputLen caps the byte length of any single operand string
	// (e.g. after repeated concat) so a fan-out of concatenations can't blow up
	// quadratically. Mirrors the per-formula sink cap downstream.
	maxBIFFPtgOutputLen = 64 * 1024
	// maxBIFFPtgFuncArgs caps how many operands a ptgFuncVar may pop for its
	// argument list (a hostile argc byte is up to 255; real XLM funcs are far
	// smaller, but we honour the byte up to this bound).
	maxBIFFPtgFuncArgs = 64
	// funcUserDefined is ptgFuncVar func id 0x806D (USERDEFINED): per MS-XLS it
	// carries an extra 9-byte trailer the reference parser skips.
	funcUserDefined = 0x806D
)

// biffFuncNames maps the BIFF8 ftab function ids we care about (dangerous XLM
// verbs + the common string-building functions) to their canonical names, so a
// folded ptgFunc/ptgFuncVar emits "=EXEC(...)" / "=CALL(...)" and the shared
// emitDangerousMarkers sink fires. Ids cross-checked against the ClamAV ftab
// (xlm_extract.c) — see oletools-reference.md §4. Unknown ids fold to a neutral
// FUNC_<hex> wrapper (no marker, but arguments are preserved for IOC scanning).
var biffFuncNames = map[uint16]string{
	31:    "MID",
	53:    "GOTO",
	54:    "HALT",
	108:   "SET.VALUE",
	110:   "EXEC",
	111:   "CHAR",
	132:   "FOPEN",
	137:   "FWRITELN",
	138:   "FWRITE",
	149:   "REGISTER",
	150:   "CALL",
	175:   "INITIATE",
	177:   "POKE",
	178:   "EXECUTE",
	179:   "TERMINATE",
	201:   "UNREGISTER",
	267:   "REGISTER.ID",
	336:   "CONCATENATE",
	32769: "OPEN", // opens a workbook/file (ftab 32769); used in dropper chains
	32774: "FILE.DELETE",
	32778: "QUIT", // terminates Excel (anti-analysis / cleanup)
	32785: "RUN",
	32864: "FORMULA",
	32893: "APP.ACTIVATE", // brings another application window to foreground (launcher assist)
	32899: "SEND.KEYS",    // sends keystrokes to another app (launcher / shellcode trampoline)
	33151: "WORKBOOK.HIDE",
}

// biffFuncArity gives the FIXED argument count for ptgFunc (0x21) function ids
// that take more than one MANDATORY operand. ptgFunc encodes only fixed-arity
// built-ins; the dangerous XLM verbs (EXEC/CALL/REGISTER/FOPEN/…) are variadic
// and arrive as ptgFuncVar (0x22) which already carries an explicit argc, so
// they are NOT listed here. This table exists purely to keep the operand stack
// balanced while folding: a fixed-arity multi-arg string builder like
// MID(s,n,m) or REPLACE(s,n,m,r) nested inside a dropper formula must pop ALL
// its operands, or the surrounding =EXEC(…)/concat under-pops and the fold
// garbles (the parent sees a leftover operand as its argument).
//
// Only functions whose mandatory arity is genuinely fixed and >1 belong here —
// any id absent from the map falls back to popping a single operand (the
// historical CHAR(n)/unary default), so an unknown or 1-arg function is never
// over-popped. Ftab ids cross-checked against MS-XLS §2.5.198.17 / the ClamAV
// ftab (oletools-reference.md §4).
var biffFuncArity = map[uint16]int{
	30:  2, // REPT(text, number_times)
	31:  3, // MID(text, start_num, num_chars)
	39:  2, // MOD(number, divisor)
	65:  3, // DATE(year, month, day)
	66:  3, // TIME(hour, minute, second)
	117: 2, // EXACT(text1, text2)
	119: 4, // REPLACE(old_text, start_num, num_chars, new_text)
}

// parseBIFF8Formula statically folds a BIFF8 XLM formula ptg token stream into a
// formula string. It evaluates the reverse-Polish token sequence on an operand
// stack: literal tokens push their value, ptgConcat folds the top two operands,
// and function tokens wrap their popped arguments in a named call. References,
// names and unhandled operands push an empty placeholder so concatenation
// structure is preserved without inventing content.
//
// Bounded and fail-open: on any truncation, unknown token or cap, it stops and
// returns the joined remaining operands (most-recent first is avoided — the
// stack is joined bottom-to-top so left-to-right formula order is preserved).
// Never panics.
func parseBIFF8Formula(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	stack := make([]string, 0, 16)
	push := func(s string) {
		if len(stack) >= maxBIFFPtgStackDepth {
			return
		}
		if len(s) > maxBIFFPtgOutputLen {
			s = s[:maxBIFFPtgOutputLen]
		}
		stack = append(stack, s)
	}

	pos := 0
	tokens := 0
	for pos < len(data) {
		if tokens >= maxBIFFPtgTokens {
			break
		}
		tokens++

		// ptg base opcode: clear the high bit (matches the reference dispatch),
		// then normalise the value/ref/array class variants of the function and
		// reference families down to their base opcode.
		ptg := normalizePtg(data[pos] & 0x7f)

		switch ptg {
		case ptgConcat:
			pos++
			// Pop two operands; concat in formula (left & right) order.
			b := popStack(&stack)
			a := popStack(&stack)
			push(a + b)

		case ptgStr:
			// data[pos+1] = cch, data[pos+2] = fHighByte (0 = 8-bit, 1 = UTF-16LE).
			if pos+2 >= len(data) {
				return joinStack(stack)
			}
			cch := int(data[pos+1])
			high := data[pos+2]
			body := data[pos+3:]
			if high == 1 {
				need := cch * 2
				if need > len(body) {
					return joinStack(stack)
				}
				push(decodeUTF16LE(body[:need]))
				pos += 3 + need
			} else {
				if cch > len(body) {
					return joinStack(stack)
				}
				push(string(body[:cch]))
				pos += 3 + cch
			}

		case ptgInt:
			if pos+2 >= len(data) {
				return joinStack(stack)
			}
			v := uint16(data[pos+1]) | uint16(data[pos+2])<<8
			push(strconv.Itoa(int(v)))
			pos += 3

		case ptgBool:
			if pos+1 >= len(data) {
				return joinStack(stack)
			}
			if data[pos+1] != 0 {
				push("TRUE")
			} else {
				push("FALSE")
			}
			pos += 2

		case ptgNum:
			// 8-byte double — not a string payload; push neutral, skip operand.
			if pos+8 >= len(data) {
				return joinStack(stack)
			}
			push("")
			pos += 9

		case ptgFunc:
			if pos+2 >= len(data) {
				return joinStack(stack)
			}
			funcID := uint16(data[pos+1]) | uint16(data[pos+2])<<8
			// Fixed-argc functions. Most fold the single top-of-stack operand
			// (the common CHAR(n)/unary case), but a multi-arg fixed-arity
			// builder (MID/REPLACE/DATE/…) listed in biffFuncArity must pop ALL
			// its operands or the surrounding =EXEC(…)/concat under-pops and the
			// fold garbles. Unknown ids fall back to a single pop (never
			// over-pops past a deeper, unrelated operand).
			push(wrapFunc(funcID, popBIFFFuncArgs(&stack, funcID)))
			pos += 3

		case ptgFuncVar:
			if pos+3 >= len(data) {
				return joinStack(stack)
			}
			argc := int(data[pos+1])
			funcID := uint16(data[pos+2]) | uint16(data[pos+3])<<8
			pos += 4
			if funcID == funcUserDefined {
				pos += 9 // USERDEFINED trailer (per MS-XLS / reference parser)
			}
			if argc > maxBIFFPtgFuncArgs {
				argc = maxBIFFPtgFuncArgs
			}
			args := make([]string, 0, argc)
			for i := 0; i < argc; i++ {
				args = append(args, popStack(&stack))
			}
			// Popped most-recent-first; reverse to source argument order.
			reverse(args)
			push(wrapFunc(funcID, strings.Join(args, ",")))

		case ptgName:
			pos += 5 // 1-byte token + 4-byte name index
			push("")

		case ptgRef:
			pos += 5 // 1-byte token + 4-byte cell ref
			push("")

		case ptgArea:
			pos += 9 // 1-byte token + 8-byte area ref
			push("")

		case ptgMemArea:
			pos += 7 // 1-byte token + 6-byte reference-subexpression header
			push("")

		case ptgExp:
			pos += 5 // 1-byte token + 4-byte row/col pointer
			push("")

		case ptgRef3d:
			pos += 7 // 1-byte token + 6-byte 3-D cell ref
			push("")

		case ptgArea3d:
			pos += 11 // 1-byte token + 10-byte 3-D area ref
			push("")

		case ptgNameX:
			pos += 7 // 1-byte token + 6-byte external name ref
			push("")

		case ptgAdd, ptgSub, ptgMul, ptgDiv, ptgPower,
			ptgLT, ptgLE, ptgEQ, ptgGE, ptgGT, ptgNE,
			ptgIsect, ptgUnion, ptgRange:
			// Binary operator (1 byte, no operand): pop 2, push "" so downstream
			// ptgFunc/ptgFuncVar tokens still find the right stack arity.
			pos++
			popStack(&stack)
			popStack(&stack)
			push("")

		case ptgUplus, ptgUminus, ptgPercent:
			// Unary operator (1 byte, no operand): pop 1, push it back unchanged.
			pos++
			v := popStack(&stack)
			push(v)

		case ptgParen:
			// Grouping marker — no stack change, advance 1 byte.
			pos++

		case ptgMissArg:
			// Missing optional argument — push "" so ptgFuncVar sees correct argc.
			pos++
			push("")

		case ptgAttr:
			next, ok := skipBIFFPtgAttr(data, pos)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			continue

		default:
			// Unknown/unhandled ptg: we cannot know its operand size, so blind
			// advancement would desync the stream. Stop and fold what we have.
			return joinStack(stack)
		}
	}

	return joinStack(stack)
}

func popBIFFFuncArgs(stack *[]string, funcID uint16) string {
	arity := 1
	if a, ok := biffFuncArity[funcID]; ok {
		arity = a
	}
	args := make([]string, 0, arity)
	for i := 0; i < arity; i++ {
		args = append(args, popStack(stack))
	}
	reverse(args) // popped most-recent-first; restore source order
	return strings.Join(args, ",")
}

func skipBIFFPtgAttr(data []byte, pos int) (int, bool) {
	// Control attribute (MS-XLS 2.5.198.3): 1-byte grbit + 2-byte param.
	// bitAttrChoose (0x04): the param is the count of CHOOSE cases minus one; it
	// is followed by (count+1)*2 bytes of branch offsets.
	if pos+4 > len(data) {
		return pos, false
	}
	skip := 4 // opcode(1) + grbit(1) + w(2)
	if data[pos+1]&0x04 != 0 {
		w := int(binary.LittleEndian.Uint16(data[pos+2:]))
		skip += (w + 1) * 2
	}
	if pos+skip > len(data) {
		return pos, false
	}
	return pos + skip, true
}

// normalizePtg maps the value-class (0x40) and array-class (0x60) variants of
// the function and reference token families down to their base opcode, so the
// dispatch in parseBIFF8Formula has a single case per logical token. Operand and
// binary tokens have no class variants and pass through unchanged.
func normalizePtg(ptg byte) byte {
	switch ptg {
	case 0x41, 0x61: // ptgFuncV / ptgFuncA
		return ptgFunc
	case 0x42, 0x62: // ptgFuncVarV / ptgFuncVarA
		return ptgFuncVar
	case 0x44, 0x64: // ptgRefV / ptgRefA
		return ptgRef
	case 0x45, 0x65: // ptgAreaV / ptgAreaA
		return ptgArea
	case 0x5A: // ptgRef3dV
		return ptgRef3d
	case 0x5B: // ptgArea3dV
		return ptgArea3d
	case 0x43, 0x63: // ptgNameV / ptgNameA
		return ptgName
	case 0x59: // ptgNameXV
		return ptgNameX
	}
	return ptg
}

// wrapFunc renders a folded function call as "=NAME(args)" (so the shared
// emitDangerousMarkers sink fires on dangerous verbs) for known ftab ids, or a
// neutral "FUNC_<hex>(args)" for unknown ids (arguments preserved for IOC scan,
// no marker).
func wrapFunc(funcID uint16, args string) string {
	if funcID == 111 {
		if s, ok := foldBIFFChar(args); ok {
			return s
		}
	}
	if name, ok := biffFuncNames[funcID]; ok {
		return "=" + name + "(" + args + ")"
	}
	return "FUNC_" + strconv.FormatUint(uint64(funcID), 16) + "(" + args + ")"
}

func foldBIFFChar(args string) (string, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(args))
	if err != nil || n < 0 || n > 127 {
		return "", false
	}
	if n < 32 && n != '\t' && n != '\n' && n != '\r' {
		return "", false
	}
	return string(rune(n)), true
}

// popStack removes and returns the top operand, or "" if the stack is empty.
func popStack(stack *[]string) string {
	s := *stack
	if len(s) == 0 {
		return ""
	}
	top := s[len(s)-1]
	*stack = s[:len(s)-1]
	return top
}

// joinStack concatenates the operand stack bottom-to-top so left-to-right
// formula order is preserved in the folded result.
func joinStack(stack []string) string {
	if len(stack) == 0 {
		return ""
	}
	if len(stack) == 1 {
		return stack[0]
	}
	var b strings.Builder
	for _, s := range stack {
		b.WriteString(s)
	}
	out := b.String()
	if len(out) > maxBIFFPtgOutputLen {
		out = out[:maxBIFFPtgOutputLen]
	}
	return out
}

// decodeUTF16LE decodes a UTF-16LE byte slice (even length already validated by
// the caller) to a Go string. Odd trailing bytes are dropped.
func decodeUTF16LE(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	return string(utf16.Decode(u))
}

// reverse reverses a string slice in place.
func reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
