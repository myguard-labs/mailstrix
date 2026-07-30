package extract

// Verbatim snapshots of the four pre-refactor ptg dispatch loops, kept as the
// oracle for TestBIFFPtgDifferential. Do not "clean these up" — their value is
// being byte-for-byte what shipped before the dedup refactor.

import (
	"strconv"
	"strings"
)

func parseBIFF8FormulaOld(data []byte) string {
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

func parseBIFF12FormulaOld(data []byte) string {
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

		ptg := normalizePtg(data[pos] & 0x7f)

		switch ptg {
		case ptgConcat:
			pos++
			b := popStack(&stack)
			a := popStack(&stack)
			push(a + b)

		case ptgStr:
			// BIFF12: uint16 charcount + UTF-16LE chars (no fHighByte flag).
			if pos+3 > len(data) {
				return joinStack(stack)
			}
			cch := int(uint16(data[pos+1]) | uint16(data[pos+2])<<8)
			body := data[pos+3:]
			need := cch * 2
			if need > len(body) {
				return joinStack(stack)
			}
			push(decodeUTF16LE(body[:need]))
			pos += 3 + need

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
				pos += 9
			}
			if argc > maxBIFFPtgFuncArgs {
				argc = maxBIFFPtgFuncArgs
			}
			args := make([]string, 0, argc)
			for i := 0; i < argc; i++ {
				args = append(args, popStack(&stack))
			}
			reverse(args)
			push(wrapFunc(funcID, strings.Join(args, ",")))

		case ptgName:
			pos += 5
			push("")

		case ptgRef:
			next, ok := skipBIFF12Ptg(data, pos, 7)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			push("")

		case ptgArea:
			next, ok := skipBIFF12Ptg(data, pos, 13)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			push("")

		case ptgMemArea:
			pos += 7
			push("")

		case ptgExp:
			next, ok := skipBIFF12Ptg(data, pos, 7)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			push("")

		case ptgRef3d:
			next, ok := skipBIFF12Ptg(data, pos, 9)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			push("")

		case ptgArea3d:
			next, ok := skipBIFF12Ptg(data, pos, 15)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			push("")

		case ptgNameX:
			pos += 7
			push("")

		case ptgAdd, ptgSub, ptgMul, ptgDiv, ptgPower,
			ptgLT, ptgLE, ptgEQ, ptgGE, ptgGT, ptgNE,
			ptgIsect, ptgUnion, ptgRange:
			// Binary operator (1 byte, no operand): pop 2, push "" neutral.
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
			return joinStack(stack)
		}
	}

	return joinStack(stack)
}

func parseBIFF8FormulaWithRefsOld(data []byte) string {
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

		ptg := normalizePtg(data[pos] & 0x7f)

		switch ptg {
		case ptgConcat:
			pos++
			b := popStack(&stack)
			a := popStack(&stack)
			push(a + b)

		case ptgStr:
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
				pos += 9
			}
			if argc > maxBIFFPtgFuncArgs {
				argc = maxBIFFPtgFuncArgs
			}
			args := make([]string, 0, argc)
			for i := 0; i < argc; i++ {
				args = append(args, popStack(&stack))
			}
			reverse(args)
			push(wrapFunc(funcID, strings.Join(args, ",")))

		case ptgName:
			pos += 5
			push("")

		case ptgRef:
			// D7: emit [[REF:A1]] placeholder instead of "".
			// Payload: 4 bytes after the token byte — row(uint16 LE) + col(uint16 LE).
			if pos+4 >= len(data) {
				return joinStack(stack)
			}
			row := uint16(data[pos+1]) | uint16(data[pos+2])<<8
			col := uint16(data[pos+3]) | uint16(data[pos+4])<<8
			a1 := biffCellToA1(row, col)
			if a1 == "" {
				push("")
			} else {
				push("[[REF:" + a1 + "]]")
			}
			pos += 5

		case ptgArea:
			pos += 9
			push("")

		case ptgMemArea:
			pos += 7
			push("")

		case ptgExp:
			pos += 5
			push("")

		case ptgRef3d:
			pos += 7
			push("")

		case ptgArea3d:
			pos += 11
			push("")

		case ptgNameX:
			pos += 7
			push("")

		case ptgAdd, ptgSub, ptgMul, ptgDiv, ptgPower,
			ptgLT, ptgLE, ptgEQ, ptgGE, ptgGT, ptgNE,
			ptgIsect, ptgUnion, ptgRange:
			pos++
			popStack(&stack)
			popStack(&stack)
			push("")

		case ptgUplus, ptgUminus, ptgPercent:
			pos++
			v := popStack(&stack)
			push(v)

		case ptgParen:
			pos++

		case ptgMissArg:
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
			return joinStack(stack)
		}
	}

	return joinStack(stack)
}

func parseBIFF12FormulaWithRefsOld(data []byte) string {
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

		ptg := normalizePtg(data[pos] & 0x7f)

		switch ptg {
		case ptgConcat:
			pos++
			b := popStack(&stack)
			a := popStack(&stack)
			push(a + b)

		case ptgStr:
			// BIFF12: uint16 charcount + UTF-16LE chars (no fHighByte flag).
			if pos+3 > len(data) {
				return joinStack(stack)
			}
			cch := int(uint16(data[pos+1]) | uint16(data[pos+2])<<8)
			body := data[pos+3:]
			need := cch * 2
			if need > len(body) {
				return joinStack(stack)
			}
			push(decodeUTF16LE(body[:need]))
			pos += 3 + need

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
				pos += 9
			}
			if argc > maxBIFFPtgFuncArgs {
				argc = maxBIFFPtgFuncArgs
			}
			args := make([]string, 0, argc)
			for i := 0; i < argc; i++ {
				args = append(args, popStack(&stack))
			}
			reverse(args)
			push(wrapFunc(funcID, strings.Join(args, ",")))

		case ptgName:
			pos += 5
			push("")

		case ptgRef:
			// D7: emit [[REF:A1]] placeholder instead of "".
			row, col, next, ok := readBIFF12PtgRef(data, pos)
			if !ok {
				return joinStack(stack)
			}
			a1 := biff12CellToA1(row, col)
			if a1 == "" {
				push("")
			} else {
				push("[[REF:" + a1 + "]]")
			}
			pos = next

		case ptgArea:
			next, ok := skipBIFF12Ptg(data, pos, 13)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			push("")

		case ptgMemArea:
			pos += 7
			push("")

		case ptgExp:
			next, ok := skipBIFF12Ptg(data, pos, 7)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			push("")

		case ptgRef3d:
			next, ok := skipBIFF12Ptg(data, pos, 9)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			push("")

		case ptgArea3d:
			next, ok := skipBIFF12Ptg(data, pos, 15)
			if !ok {
				return joinStack(stack)
			}
			pos = next
			push("")

		case ptgNameX:
			pos += 7
			push("")

		case ptgAdd, ptgSub, ptgMul, ptgDiv, ptgPower,
			ptgLT, ptgLE, ptgEQ, ptgGE, ptgGT, ptgNE,
			ptgIsect, ptgUnion, ptgRange:
			pos++
			popStack(&stack)
			popStack(&stack)
			push("")

		case ptgUplus, ptgUminus, ptgPercent:
			pos++
			v := popStack(&stack)
			push(v)

		case ptgParen:
			pos++

		case ptgMissArg:
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
			return joinStack(stack)
		}
	}

	return joinStack(stack)
}
