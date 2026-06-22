package extract

// xlm_emul_biff.go — BIFF8/BIFF12 two-pass XLM emulator helpers (Wave D, D7).
//
// Provides WithRefs variants of parseBIFF8Formula and parseBIFF12Formula that
// emit [[REF:A1]] placeholder tokens for ptgRef cells (instead of "") so the
// caller can later resolve them against the live emulator grid.
//
// Also provides:
//   - biffCellToA1:          convert 0-based (row, col) to A1 notation
//   - reRefPlaceholder:      regexp matching [[REF:A1]] tokens
//   - resolveRefPlaceholders: substitute [[REF:...]] against the xlmMachine grid
//   - stripRefPlaceholders:   remove any remaining [[REF:...]] tokens

import (
	"regexp"
	"strconv"
	"strings"
)

// biffCellToA1 converts a 0-based (row, col) pair from a BIFF ptgRef payload
// to A1 notation. Bits 14-15 of col are relative-reference flags and are
// masked before conversion. Both row and col are made 1-based.
func biffCellToA1(row, col uint16) string {
	// Mask relative-reference bits (14 and 15).
	c := int(col&0x3FFF) + 1
	r := int(row) + 1
	letters := colNumToLetters(c)
	if letters == "" {
		return ""
	}
	return letters + strconv.Itoa(r)
}

// parseBIFF8FormulaWithRefs is like parseBIFF8Formula but overrides the ptgRef
// case: instead of pushing "" it pushes a "[[REF:A1]]" placeholder that the
// caller can resolve against the live emulator grid. ptgRef3d still pushes "".
//
// This is a complete standalone copy of the parse loop so that the ptgRef case
// can be overridden without modifying the original function.
func parseBIFF8FormulaWithRefs(data []byte) string {
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
			arg := popStack(&stack)
			push(wrapFunc(funcID, arg))
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
			return joinStack(stack)

		default:
			return joinStack(stack)
		}
	}

	return joinStack(stack)
}

// parseBIFF12FormulaWithRefs is like parseBIFF12Formula but overrides the
// ptgRef case to emit "[[REF:A1]]" placeholders. ptgStr uses BIFF12 encoding
// (uint16 cch + UTF-16LE, no fHighByte). ptgRef3d still pushes "".
func parseBIFF12FormulaWithRefs(data []byte) string {
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
			arg := popStack(&stack)
			push(wrapFunc(funcID, arg))
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
			return joinStack(stack)

		default:
			return joinStack(stack)
		}
	}

	return joinStack(stack)
}

// reRefPlaceholder matches [[REF:A1]]-style tokens emitted by the WithRefs
// parsers. The inner part is the A1 coordinate (letters then digits).
var reRefPlaceholder = regexp.MustCompile(`\[\[REF:([A-Z]+[0-9]+)\]\]`)

// resolveRefPlaceholders replaces every [[REF:coord]] token in s with the
// live value of that cell in the named sheet (via m.getCellValue). Tokens
// whose cell has no value (empty or absent) are left unchanged.
func resolveRefPlaceholders(m *xlmMachine, sheetName, s string) string {
	return reRefPlaceholder.ReplaceAllStringFunc(s, func(match string) string {
		sub := reRefPlaceholder.FindStringSubmatch(match)
		if sub == nil {
			return match
		}
		coord := sub[1]
		if val, ok := m.getCellValue(sheetName, coord); ok {
			return val
		}
		return match
	})
}

// stripRefPlaceholders removes every [[REF:...]] token from s, leaving the
// surrounding text intact.
func stripRefPlaceholders(s string) string {
	return reRefPlaceholder.ReplaceAllString(s, "")
}
