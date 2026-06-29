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
//   - Cell references carry wider row fields than BIFF8 (uint32 row + uint16
//     column flags), so the BIFF12 token walker has its own reference skips.
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
	"bytes"
	"io"
	"strconv"
	"strings"
	"time"
)

// BIFF12 cell/formula record ids. FMLA_* carries:
// col(i32) style(i32) value grbit(i16) cce(i32) formula_bytes[cce] rgcb.
// The trailing rgcb bytes are optional parsed-formula metadata and are not part
// of the ptg token stream.
const (
	biff12CellIsst   = 7
	biff12FmlaString = 8
	biff12FmlaNum    = 9
	biff12FmlaBool   = 10
	biff12FmlaError  = 11

	biff12BrtSSTBegin = 159
	biff12BrtSSTItem  = 19
)

// BIFF12 fold caps (mirror the BIFF8/OOXML caps so the three paths stay aligned).
const (
	// maxBIFF12Records caps records walked per .bin sheet — a macrosheet is
	// dominated by FMLA records, so the formula cap alone doesn't bound the walk.
	maxBIFF12Records = 1 << 18
	// maxBIFF12RecordLen caps a single record's declared length (varint guard) so
	// a hostile 4-byte length cannot ask us to allocate gigabytes.
	maxBIFF12RecordLen = maxBytesWorkbookXML
	// maxBIFF12SSTStrings caps shared-string entries retained for macrosheet
	// value-cell resolution. The enclosing sharedStrings.bin read is already
	// byte-capped; this limits entry fan-out.
	maxBIFF12SSTStrings = 1 << 16
)

// fromXLSBXLMFold finds Excel-4.0 macrosheet parts (xl/macrosheets/sheet*.bin)
// in the already-opened OOXML zip, walks each as a BIFF12 record stream, folds
// the ptg token stream of every FMLA_* cell via parseBIFF12Formula, and feeds
// the results to the shared emitFoldedFormula sink (so .xlsb cannot drift from
// .xls/.xlsm on the minlen floor, output cap, or dangerous-func markers).
// Fail-open: any read/parse error silently returns. Bounded; respects deadline.
// opts carries the per-request sheet/formula caps; nil uses package defaults.
func fromXLSBXLMFold(zr *zip.Reader, out *[][]byte, deadline time.Time, opts *Options) {
	if expired(deadline) {
		return
	}

	sheetCap := opts.xlmFoldSheets()
	formulaCap := opts.xlmFoldFormulas()

	var sheets []*zip.File
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "xl/macrosheets/") && strings.HasSuffix(strings.ToLower(f.Name), ".bin") {
			sheets = append(sheets, f)
			if len(sheets) >= sheetCap {
				break
			}
		}
	}
	if len(sheets) == 0 {
		return
	}

	sst := loadXLSBSharedStrings(zr, deadline)
	totalOutput := 0
	for _, sf := range sheets {
		if expired(deadline) || len(*out) >= maxStreams {
			return
		}
		processXLSBSheet(sf, sst, out, &totalOutput, deadline, formulaCap)
	}
}

// CSV-DDE-XLSB: a DDE-bearing supporting book in an .xlsb lives as a BrtBeginSupBook
// (record id 0x0163) inside xl/externalLinks/externalLink*.bin whose sbt field = 1
// (DDE). It carries a DDE server + topic (e.g. cmd | "/c calc") that runs a command
// on external-link refresh (MITRE T1559.002) — the xlsb-binary analogue of the
// CSV-DDE / OOXML-DDE command form. The server/topic are UTF-16LE inside a binary
// record, so a plain-text scan never sees them.
const (
	biff12BrtBeginSupBook = 0x0163 // [MS-XLSB] 2.4.297
	maxXLSBExternalBins   = 16
	maxXLSBSupBookDDE     = 32
)

// fromXLSBExternalDDE walks the xl/externalLinks/externalLink*.bin parts for a
// DDE supporting book (BrtBeginSupBook, sbt=1) and emits an "XLSB-DDE
// <server>|<topic>" marker for each. Bounded + fail-open: a malformed record
// stream yields whatever was found so far and never panics.
func fromXLSBExternalDDE(zr *zip.Reader, out *[][]byte, deadline time.Time) {
	if expired(deadline) {
		return
	}
	bins := 0
	for _, f := range zr.File {
		if expired(deadline) || bins >= maxXLSBExternalBins {
			return
		}
		lname := strings.ToLower(f.Name)
		if !strings.HasPrefix(lname, "xl/externallinks/") || !strings.HasSuffix(lname, ".bin") {
			continue
		}
		bins++
		if f.UncompressedSize64 > maxBytesWorkbookXML {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, maxBytesWorkbookXML))
		rc.Close() // #nosec G104 -- zip entry close
		if err != nil || len(raw) == 0 {
			continue
		}
		scanXLSBSupBookDDE(raw, out)
	}
}

// scanXLSBSupBookDDE walks one externalLink .bin BIFF12 record stream and emits
// a DDE marker for every BrtBeginSupBook with sbt=1.
func scanXLSBSupBookDDE(raw []byte, out *[][]byte) {
	records := 0
	pos := 0
	ddeCount := countXLSBDDE(*out)
	for pos < len(raw) {
		if records >= maxBIFF12Records || ddeCount >= maxXLSBSupBookDDE {
			return
		}
		records++

		recID, n := readVarint(raw[pos:])
		if n == 0 {
			return
		}
		pos += n
		recLen, n := readVarint(raw[pos:])
		if n == 0 || recLen < 0 || recLen > maxBIFF12RecordLen {
			return
		}
		pos += n
		if pos+recLen > len(raw) {
			return
		}
		body := raw[pos : pos+recLen]
		pos += recLen

		if recID != biff12BrtBeginSupBook || len(body) < 2 {
			continue
		}
		// sbt (2 bytes): 0=workbook, 1=DDE, 2=OLE.
		if uint16(body[0])|uint16(body[1])<<8 != 1 {
			continue
		}
		server, off := readXLNullableWideString(body, 2)
		topic, _ := readXLNullableWideString(body, off)
		if server == "" && topic == "" {
			continue
		}
		marker := "XLSB-DDE " + server + "|" + topic
		if len(marker) > maxBIFF12RecordLen {
			marker = marker[:maxBIFF12RecordLen]
		}
		*out = append(*out, []byte(marker))
		ddeCount++
	}
}

// readXLNullableWideString reads an [MS-XLSB] XLNullableWideString at off: a
// 4-byte character count (0xFFFFFFFF = null → empty string) followed by cch
// UTF-16LE characters. Returns the decoded string and the offset past it.
// Bounds-checked; on truncation returns "" and an offset at end-of-buffer.
func readXLNullableWideString(p []byte, off int) (string, int) {
	if off < 0 || off+4 > len(p) {
		return "", len(p)
	}
	cch := uint32(p[off]) | uint32(p[off+1])<<8 | uint32(p[off+2])<<16 | uint32(p[off+3])<<24
	off += 4
	if cch == 0xFFFFFFFF || cch == 0 { // null or empty
		return "", off
	}
	need := int(cch) * 2
	if need < 0 || off+need > len(p) {
		return "", len(p)
	}
	s := decodeUTF16LE(p[off : off+need])
	return s, off + need
}

func readXLWideString(p []byte, off int) (string, int, bool) {
	if off < 0 || off+4 > len(p) {
		return "", len(p), false
	}
	cch := uint32(p[off]) | uint32(p[off+1])<<8 | uint32(p[off+2])<<16 | uint32(p[off+3])<<24
	off += 4
	if cch > maxBIFF12RecordLen/2 {
		return "", len(p), false
	}
	need := int(cch) * 2 // #nosec G115 -- cch is bounded by maxBIFF12RecordLen/2 above.
	if need > len(p)-off {
		return "", len(p), false
	}
	s := decodeUTF16LE(p[off : off+need])
	return s, off + need, true
}

func loadXLSBSharedStrings(zr *zip.Reader, deadline time.Time) []string {
	for _, f := range zr.File {
		if expired(deadline) {
			return nil
		}
		if strings.ToLower(f.Name) != "xl/sharedstrings.bin" {
			continue
		}
		if f.UncompressedSize64 > maxBytesWorkbookXML {
			return nil
		}
		rc, err := f.Open()
		if err != nil {
			return nil
		}
		raw, err := io.ReadAll(io.LimitReader(rc, maxBytesWorkbookXML))
		rc.Close() // #nosec G104 -- zip entry close
		if err != nil {
			return nil
		}
		return parseXLSBSharedStrings(raw)
	}
	return nil
}

func parseXLSBSharedStrings(raw []byte) []string {
	var out []string
	pos := 0
	records := 0
	for pos < len(raw) {
		if records >= maxBIFF12Records || len(out) >= maxBIFF12SSTStrings {
			return out
		}
		records++

		recID, n := readVarint(raw[pos:])
		if n == 0 {
			return out
		}
		pos += n
		recLen, n := readVarint(raw[pos:])
		if n == 0 || recLen < 0 || recLen > maxBIFF12RecordLen {
			return out
		}
		pos += n
		if pos+recLen > len(raw) {
			return out
		}
		body := raw[pos : pos+recLen]
		pos += recLen

		switch recID {
		case biff12BrtSSTBegin:
			continue
		case biff12BrtSSTItem:
			s, ok := parseXLSBSharedStringItem(body)
			if !ok {
				s = ""
			}
			out = append(out, s)
		}
	}
	return out
}

func parseXLSBSharedStringItem(p []byte) (string, bool) {
	if len(p) < 5 {
		return "", false
	}
	// BrtSSTItem starts with one flags byte, followed by an XLWideString. Rich
	// text / extension payloads after the string are not needed for extraction.
	s, _, ok := readXLWideString(p, 1)
	return s, ok
}

// countXLSBDDE counts XLSB-DDE markers already emitted (bounds the per-file fan-out).
func countXLSBDDE(out [][]byte) int {
	c := 0
	for _, s := range out {
		if bytes.HasPrefix(s, []byte("XLSB-DDE ")) {
			c++
		}
	}
	return c
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
// formulaCap limits how many formula records are collected (effort-scaled).
func processXLSBSheet(sf *zip.File, sst []string, out *[][]byte, totalOutput *int, deadline time.Time, formulaCap int) {
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
	var valueCells []xlmCell

	for pos < len(raw) {
		if expired(deadline) || len(*out) >= maxStreams {
			break
		}
		if records >= maxBIFF12Records || len(collected) >= formulaCap {
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

		case biff12CellIsst:
			if len(valueCells) >= maxEmulCells {
				continue
			}
			coord, value, ok := biff12CellIsstValue(currentRow, payload, sst)
			if !ok {
				continue
			}
			valueCells = append(valueCells, xlmCell{coord: coord, value: value})

		case biff12FmlaString, biff12FmlaNum, biff12FmlaBool, biff12FmlaError:
			rgce := biff12FormulaRgce(recID, payload)
			if rgce == nil {
				continue
			}
			coord := biff12CellCoord(currentRow, payload)
			if coord == "" {
				coord = "A" + strconv.Itoa(int(currentRow)+1)
			}
			buf := make([]byte, len(rgce))
			copy(buf, rgce)
			collected = append(collected, biff12FormulaCollected{coord: coord, rgce: buf})
		}
	}

	if len(collected) == 0 && len(valueCells) == 0 {
		return
	}

	// Pass 2: build xlmCell slice and try the emulator.
	xlmCells := make([]xlmCell, 0, len(valueCells)+len(collected))
	xlmCells = append(xlmCells, valueCells...)
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

	if !xlmEmulatorProducedPayload(*out, priorLen) {
		// Emulator produced no output — fall back to one-by-one fold.
		for _, bc := range collected {
			folded := parseBIFF12Formula(bc.rgce)
			if !emitFoldedFormula(folded, out, totalOutput, true) {
				return // per-document output cap reached
			}
		}
	}
}

func biff12CellCoord(row uint32, p []byte) string {
	if len(p) < 4 {
		return ""
	}
	col := uint32(p[0]) | uint32(p[1])<<8 | uint32(p[2])<<16 | uint32(p[3])<<24
	return biff12CellToA1(row, col)
}

func biff12CellIsstValue(row uint32, p []byte, sst []string) (coord, value string, ok bool) {
	if len(p) < 12 {
		return "", "", false
	}
	idx := uint32(p[8]) | uint32(p[9])<<8 | uint32(p[10])<<16 | uint32(p[11])<<24
	if idx >= maxBIFF12SSTStrings {
		return "", "", false
	}
	i := int(idx) // #nosec G115 -- idx < maxBIFF12SSTStrings (65,536) above.
	if i >= len(sst) {
		return "", "", false
	}
	coord = biff12CellCoord(row, p)
	if coord == "" {
		return "", "", false
	}
	return coord, sst[i], true
}

func biff12CellToA1(row uint32, col uint32) string {
	if row > 1_048_575 {
		return ""
	}
	c := int(col&0x3FFF) + 1
	letters := colNumToLetters(c)
	if letters == "" {
		return ""
	}
	return letters + strconv.Itoa(int(row)+1) // #nosec G115 -- row <= 1,048,575 above.
}

// biff12FormulaRgce extracts the raw ptg byte stream from a FMLA_* record
// payload. Layout:
//
//	col(i32) style(i32) <value> grbit(i16) cce(i32) rgce[cce] rgcb
//
// The value field width is record-id specific; rgcb is a trailer after rgce.
// Older code anchored rgce at the record end, which lost real .xlsb formulas
// because non-empty trailers are normal.
func biff12FormulaRgce(recID int, p []byte) []byte {
	if len(p) < 15 {
		return nil
	}
	off := 8 // col + style
	switch recID {
	case biff12FmlaString:
		if off+4 > len(p) {
			return nil
		}
		cch := uint32(p[off]) | uint32(p[off+1])<<8 | uint32(p[off+2])<<16 | uint32(p[off+3])<<24
		off += 4
		charBytes := uint64(cch) * 2
		if charBytes > uint64(len(p)-off) {
			return nil
		}
		off += int(charBytes) // #nosec G115 -- charBytes is bounded by len(p)-off above.
	case biff12FmlaNum:
		off += 8
	case biff12FmlaBool, biff12FmlaError:
		off++
	default:
		return nil
	}
	if off+2+4 > len(p) {
		return nil
	}
	off += 2 // grbit
	cceU := uint32(p[off]) | uint32(p[off+1])<<8 | uint32(p[off+2])<<16 | uint32(p[off+3])<<24
	off += 4
	if cceU > maxBIFF12RecordLen {
		return nil
	}
	cce := int(cceU)
	if cce < 0 || off+cce > len(p) {
		return nil
	}
	return p[off : off+cce]
}

func readBIFF12PtgRef(data []byte, pos int) (row uint32, col uint32, next int, ok bool) {
	if pos < 0 || pos+7 > len(data) {
		return 0, 0, pos, false
	}
	row = uint32(data[pos+1]) | uint32(data[pos+2])<<8 | uint32(data[pos+3])<<16 | uint32(data[pos+4])<<24
	col = uint32(data[pos+5]) | uint32(data[pos+6])<<8
	return row, col, pos + 7, true
}

func skipBIFF12Ptg(data []byte, pos, size int) (int, bool) {
	if pos < 0 || size < 0 || pos+size > len(data) {
		return pos, false
	}
	return pos + size, true
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
