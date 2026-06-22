package extract

// BIFF12 (.xlsb) XLM formula ptg-token folder — XLM-4.
//
// The binary OOXML spreadsheet format (.xlsb) stores macrosheet cells in
// xl/macrosheets/sheet*.bin parts as BIFF12 records rather than the XML <f>
// elements used by .xlsm. Each FMLA_* cell record carries the same kind of ptg
// reverse-Polish token stream as legacy BIFF8 (.xls), so an obfuscated payload
// (=EXEC(CHAR(104)&CHAR(116)&"tp://evil"…)) is invisible to the keyword/URL/IOC
// YARA rules unless we statically fold the token stream back into a formula
// string and feed the SAME shared sink (emitFoldedFormula) the OOXML/.xls paths
// use, so the three container forms cannot drift on caps/markers.
//
// BIFF12 vs BIFF8 (see oletools-reference.md §pyxlsb2):
//   - Record framing is varint: a 1–2 byte 7-bit-continuation record id, then a
//     1–4 byte 7-bit-continuation length (vs BIFF8's fixed uint16 type + uint16
//     length).
//   - ptgStr (0x17) is always uint16 charcount + UTF-16LE (vs BIFF8's 1-byte cch
//     + fHighByte flag).
//   - All other ptg opcodes and operand sizes match BIFF8, so the operand-stack
//     fold logic mirrors parseBIFF8Formula; only the string token differs.
//
// Macrosheet gate: only sheet parts under xl/macrosheets/ are folded — Excel
// writes Excel-4.0 macro content there exclusively, so an ordinary worksheet
// =SUM() in xl/worksheets/ can never fabricate a folded stream (same gating
// philosophy as the BIFF8 BOF dt 0x0040 gate in xlm.go).
//
// Fail-open + bounded: a malformed/truncated record stream or token stream
// returns whatever was folded so far; record count, token count, operand-stack
// depth and output length are all capped. Never panics. No code copied from
// pyxlsb2 — format/algorithm facts only.

import (
	"archive/zip"
	"io"
	"strconv"
	"strings"
	"time"
)

// BIFF12 formula-cell record ids (pyxlsb2 recordtypes.py 8–11). Each carries
// col(i32) style(i32) value flags(i16) sz(i32) formula_bytes[sz].
const (
	biff12FmlaString = 8
	biff12FmlaNum    = 9
	biff12FmlaBool   = 10
	biff12FmlaError  = 11
)

// BIFF12 fold caps (mirror the BIFF8/OOXML caps so the three paths stay aligned).
const (
	// maxBIFF12Records caps records walked per .bin sheet — a macrosheet is
	// dominated by FMLA records, so the formula cap alone doesn't bound the walk.
	maxBIFF12Records = 1 << 18
	// maxBIFF12Sheets caps macrosheet .bin parts scanned per workbook.
	maxBIFF12Sheets = maxXLMFoldSheets
	// maxBIFF12RecordLen caps a single record's declared length (varint guard) so
	// a hostile 4-byte length cannot ask us to allocate gigabytes.
	maxBIFF12RecordLen = maxBytesWorkbookXML
)

// fromXLSBXLMFold finds Excel-4.0 macrosheet parts (xl/macrosheets/sheet*.bin)
// in the already-opened OOXML zip, walks each as a BIFF12 record stream, folds
// the ptg token stream of every FMLA_* cell via parseBIFF12Formula, and feeds
// the results to the shared emitFoldedFormula sink (so .xlsb cannot drift from
// .xls/.xlsm on the minlen floor, output cap, or dangerous-func markers).
// Fail-open: any read/parse error silently returns. Bounded; respects deadline.
func fromXLSBXLMFold(zr *zip.Reader, out *[][]byte, deadline time.Time) {
	if expired(deadline) {
		return
	}

	var sheets []*zip.File
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "xl/macrosheets/") && strings.HasSuffix(strings.ToLower(f.Name), ".bin") {
			sheets = append(sheets, f)
			if len(sheets) >= maxBIFF12Sheets {
				break
			}
		}
	}
	if len(sheets) == 0 {
		return
	}

	totalOutput := 0
	for _, sf := range sheets {
		if expired(deadline) || len(*out) >= maxStreams {
			return
		}
		processXLSBSheet(sf, out, &totalOutput, deadline)
	}
}

// biff12FormulaCollected holds the decoded coordinate and raw ptg bytes of
// one FMLA_* record within a macrosheet, for the two-pass emulator batch.
type biff12FormulaCollected struct {
	coord string
	rgce  []byte
}

// processXLSBSheet walks one .bin macrosheet using a two-pass strategy (D7):
// pass 1 collects all FMLA_* cell ptg bytes with their A1 coordinates; pass 2
// feeds them to the emulator. If the emulator produces no output the original
// one-by-one fold path is used as fallback (defense-in-depth).
func processXLSBSheet(sf *zip.File, out *[][]byte, totalOutput *int, deadline time.Time) {
	if sf.UncompressedSize64 > maxBytesWorkbookXML {
		return
	}
	rc, err := sf.Open()
	if err != nil {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxBytesWorkbookXML))
	rc.Close() // #nosec G104 -- zip entry close
	if err != nil || len(raw) == 0 {
		return
	}

	// Pass 1: collect cells.
	// BrtRowHdr (record type 0) carries the current row number at payload[0:4].
	const biff12BrtRowHdr = 0
	pos := 0
	records := 0
	var currentRow uint32
	var collected []biff12FormulaCollected

	for pos < len(raw) {
		if expired(deadline) || len(*out) >= maxStreams {
			break
		}
		if records >= maxBIFF12Records || len(collected) >= maxXLMFoldFormulas {
			break
		}
		records++

		recID, n := readVarint(raw[pos:])
		if n == 0 {
			break // truncated record id
		}
		pos += n
		recLen, n := readVarint(raw[pos:])
		if n == 0 {
			break // truncated length
		}
		pos += n
		if recLen > maxBIFF12RecordLen || recLen > len(raw)-pos {
			break // declared length overruns the buffer — fail-open
		}
		payload := raw[pos : pos+recLen]
		pos += recLen

		switch recID {
		case biff12BrtRowHdr:
			// Row header: row index at bytes 0–3 (uint32 LE).
			if len(payload) >= 4 {
				currentRow = uint32(payload[0]) | uint32(payload[1])<<8 |
					uint32(payload[2])<<16 | uint32(payload[3])<<24
			}

		case biff12FmlaString, biff12FmlaNum, biff12FmlaBool, biff12FmlaError:
			rgce := biff12FormulaRgce(payload)
			if rgce == nil {
				continue
			}
			// Column is the first uint32 LE in the payload.
			var col uint32
			if len(payload) >= 4 {
				col = uint32(payload[0]) | uint32(payload[1])<<8 |
					uint32(payload[2])<<16 | uint32(payload[3])<<24
			}
			coord := biffCellToA1(uint16(currentRow), uint16(col))
			if coord == "" {
				coord = "A" + strconv.Itoa(int(currentRow)+1)
			}
			buf := make([]byte, len(rgce))
			copy(buf, rgce)
			collected = append(collected, biff12FormulaCollected{coord: coord, rgce: buf})
		}
	}

	if len(collected) == 0 {
		return
	}

	// Pass 2: build xlmCell slice and try the emulator.
	xlmCells := make([]xlmCell, 0, len(collected))
	for _, bc := range collected {
		formula := parseBIFF12FormulaWithRefs(bc.rgce)
		if formula == "" {
			continue
		}
		xlmCells = append(xlmCells, xlmCell{coord: bc.coord, formula: formula})
	}

	priorLen := len(*out)
	if len(xlmCells) > 0 {
		emulateXLMCells(xlmCells, out, totalOutput, deadline)
	}

	if len(*out) == priorLen {
		// Emulator produced no output — fall back to one-by-one fold.
		for _, bc := range collected {
			folded := parseBIFF12Formula(bc.rgce)
			if !emitFoldedFormula(folded, out, totalOutput, true) {
				return // per-document output cap reached
			}
		}
	}
}

// biff12FormulaRgce extracts the raw ptg byte stream from a FMLA_* record
// payload. Layout: col(i32) style(i32) <value> flags(i16) sz(i32) rgce[sz].
// The <value> field width varies by record type (FMLA_NUM = 8-byte double,
// FMLA_BOOL/ERROR = 1 byte, FMLA_STRING = a length-prefixed XLWideString of
// unknown width), so the prefix length is not fixed.
//
// We anchor on the END of the record instead: rgce runs to the record end, and
// the sz(i32) immediately precedes it. For each plausible value-field width we
// read the sz at the resulting offset and check off+4+sz == len(p) (i.e. sz
// exactly accounts for the trailing rgce bytes).
//
// biff12FormulaRgce is called for all four FMLA_* record types without knowing
// which produced the payload, so more than one candidate width could satisfy the
// end-anchor check by coincidence (a crafted/corrupt record). Picking one
// arbitrarily would silently hand the WRONG bytes to the ptg parser — a
// false-negative in a security scanner. So we require an UNAMBIGUOUS match:
// exactly one width must be self-consistent, otherwise return nil (fail-open).
func biff12FormulaRgce(p []byte) []byte {
	// Smallest real layout is col(4)+style(4)+value(1)+flags(2)+sz(4) = 15 bytes
	// (1-byte value field), before any rgce. Shorter payloads cannot carry a
	// FMLA_* formula.
	if len(p) < 15 {
		return nil
	}
	var match []byte
	matches := 0
	for _, valWidth := range []int{8, 1, 2, 4} {
		off := 8 + valWidth + 2 // col+style + value + flags
		if off+4 > len(p) {
			continue
		}
		szU := uint32(p[off]) | uint32(p[off+1])<<8 | uint32(p[off+2])<<16 | uint32(p[off+3])<<24
		if szU > maxBIFF12RecordLen {
			continue // implausible sz (also guards the int conversion on 32-bit)
		}
		sz := int(szU)
		rgceStart := off + 4
		if rgceStart+sz == len(p) {
			match = p[rgceStart : rgceStart+sz]
			matches++
		}
	}
	if matches != 1 {
		return nil // none or ambiguous — fail-open rather than guess
	}
	return match
}

// readVarint reads a pyxlsb2-style varint (7 bits per byte, high bit = more,
// little-endian) from the front of b. Returns the value and the number of bytes
// consumed, or (0, 0) on truncation. Bounded to 4 bytes (the format's max for
// both record id and length).
func readVarint(b []byte) (int, int) {
	v := 0
	for i := 0; i < 4; i++ {
		if i >= len(b) {
			return 0, 0 // truncated
		}
		c := b[i]
		v |= int(c&0x7f) << (7 * i)
		if c&0x80 == 0 {
			return v, i + 1
		}
	}
	// 4 bytes consumed with continuation still set — malformed.
	return 0, 0
}

// parseBIFF12Formula statically folds a BIFF12 ptg token stream into a formula
// string, identical in structure to parseBIFF8Formula (same operand stack, same
// ptgConcat/ptgFunc/ptgFuncVar/reference handling, same caps and fail-open
// contract) — the ONLY divergence is ptgStr, which in BIFF12 is a uint16
// charcount followed by UTF-16LE chars (no fHighByte flag). Never panics.
func parseBIFF12Formula(data []byte) string {
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
			pos += 5
			push("")

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
			return joinStack(stack)

		default:
			return joinStack(stack)
		}
	}

	return joinStack(stack)
}
