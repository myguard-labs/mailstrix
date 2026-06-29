package extract

// XLM hidden-macrosheet detection. Structural analysis only — zero macro
// execution. Two container forms are handled:
//
//   - OOXML (xlsm/xlsb/xlam): fromOOXMLXLM reads xl/workbook.xml from the
//     already-opened zip, checks whether any <sheet> element declares
//     state="veryHidden" or state="hidden" AND the workbook zip contains a
//     xl/macrosheets/ part (confirming Excel-4.0 macro content), and emits a
//     synthetic "XLM-HIDDEN-MACROSHEET <state> <name>" stream for each match.
//
//   - Legacy xls (BIFF8, OLE2): fromBIFFXLM reads the Workbook (or Book) stream
//     from the already-parsed OLE2, scans BOUNDSHEET8 records (type 0x0085), and
//     emits the same marker when the record's dt field (sheet type) is 0x01
//     (Excel-4.0 macro) AND the hidden-state bits indicate hidden or veryHidden.
//
// Both helpers follow the fail-open contract: any parse error silently returns
// with no streams emitted (the raw-bytes scan still happens). Neither panics.

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"io"
	"strconv"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// XLM extraction caps — intentionally modest; an xlsm with thousands of
// hidden macrosheets is anomalous and we don't want to flood Streams.
const (
	// maxXLMSheets caps BOUNDSHEET records scanned per BIFF stream.
	maxXLMSheets = 1024
	// maxBytesWorkbookXML caps the xl/workbook.xml read (zip-bomb guard).
	maxBytesWorkbookXML = 2 << 20
	// maxXLMMarkers caps synthetic XLM-HIDDEN-MACROSHEET streams per document.
	maxXLMMarkers = 64
	// maxBIFFRecords caps total BIFF records walked per Workbook stream (XLM-3).
	// A macrosheet substream is dominated by FORMULA records, so the per-sheet
	// cap (maxXLMSheets) does not bound the walk; this does.
	maxBIFFRecords = 1 << 18

	// biff-continue caps: a FORMULA ptg array split across CONTINUE (0x003C)
	// records is reassembled up to maxFormulaReassembled bytes across at most
	// maxContinueRecs records, so a hostile chain can't drive unbounded reads.
	maxContinueRecs       = 64
	maxFormulaReassembled = 1 << 16 // 64 KiB

	// SHRFMLA (0x00BC) resolution caps.
	// maxSHRFMLAEntries caps the per-macrosheet shared-formula table so a
	// hostile file cannot drive unbounded map growth.
	maxSHRFMLAEntries = 4096
	// maxSHRFMLACce caps the rgce byte length accepted from a SHRFMLA record.
	// Real shared formulas are tiny (a few dozen bytes); a huge cce is anomalous.
	maxSHRFMLACce = 1 << 14 // 16 KiB
)

// xlmHiddenStateLabel maps BIFF hidden-state bit values (grbit byte 0, bits 0–1)
// to the label used in the marker stream.
var xlmHiddenStateLabel = [4]string{
	0: "", // visible — no marker
	1: "hidden",
	2: "veryHidden",
	3: "hidden", // reserved, treat as hidden
}

// fromOOXMLXLM reads xl/workbook.xml from the already-opened OOXML zip and
// appends "XLM-HIDDEN-MACROSHEET <state> <name>" synthetic streams to *out for
// each sheet whose state is "hidden" or "veryHidden" AND for which the workbook
// zip contains an xl/macrosheets/ part (confirming Excel-4.0 macro content).
// Fail-open: any read/parse error silently returns with no streams added.
// Bounded by maxBytesWorkbookXML + maxXLMMarkers; respects expired(deadline).
//
// idx is the shared name→entry map built by fromOOXML; hasMacrosheet is
// precomputed by the same map-building pass (avoids re-scanning zr.File).
func fromOOXMLXLM(idx map[string]*zip.File, hasMacrosheet bool, out *[][]byte, deadline time.Time) {
	if expired(deadline) {
		return
	}

	// hasMacrosheet and the xl/workbook.xml lookup are provided by the caller
	// (fromOOXML) which already walked zr.File to build idx — no re-scan needed.
	if !hasMacrosheet {
		return
	}
	wbFile := idx["xl/workbook.xml"]
	if wbFile == nil {
		return
	}
	if wbFile.UncompressedSize64 > maxBytesWorkbookXML {
		return // anomalously large — skip
	}

	rc, err := wbFile.Open()
	if err != nil {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxBytesWorkbookXML))
	rc.Close() // #nosec G104 -- zip entry close; error is unrecoverable here
	if err != nil || len(raw) == 0 {
		return
	}

	// Stream-parse xl/workbook.xml looking for <sheet> elements.
	// Relevant attributes: name="…" state="hidden|veryHidden".
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	markers := countXLMMarkers(*out)
	for {
		if expired(deadline) {
			break
		}
		if markers >= maxXLMMarkers || len(*out) >= maxStreams {
			break
		}
		tok, err := dec.Token()
		if err != nil {
			break // EOF or malformed — fail-open
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "sheet" {
			continue
		}
		var sheetName, state string
		for _, attr := range se.Attr {
			switch attr.Name.Local {
			case "name":
				sheetName = attr.Value
			case "state":
				state = attr.Value
			}
		}
		if state != "hidden" && state != "veryHidden" {
			continue
		}
		// Emit marker — we already confirmed xl/macrosheets/ exists.
		*out = append(*out, []byte("XLM-HIDDEN-MACROSHEET "+state+" "+sheetName))
		markers++
	}
}

func xlmEmulatorProducedPayload(out [][]byte, priorLen int) bool {
	for _, s := range out[priorLen:] {
		if !bytes.HasPrefix(s, []byte("XLM-EMUL-DEPTH ")) {
			return true
		}
	}
	return false
}

// fromBIFFXLM reads the Workbook and/or Book streams from an already-parsed OLE2
// compound file and calls scanBIFFXLMStream for each present stream.
//
// A Double Stream File (DSF) legitimately contains BOTH a BIFF8 "Workbook" stream
// (for modern Excel) AND a BIFF5/7 "Book" stream (for Excel 95). Malware hides a
// malicious XLM macrosheet in the legacy "Book" stream, which modern tools ignore.
// Both streams are scanned when both are present.
//
// Fail-open: any parse error silently returns. Bounded by maxXLMSheets +
// maxXLMMarkers across both streams; respects expired(deadline).
func fromBIFFXLM(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if expired(deadline) {
		return
	}

	// Scan each stream that is present; do NOT break after the first.
	// The shared caps inside scanBIFFXLMStream (countXLMMarkers / len(res.Streams))
	// bound the total work across both streams.
	found := false
	for _, streamName := range []string{"Workbook", "Book"} {
		s := ole.FindStreamByName(streamName)
		if s == nil {
			continue
		}
		data := ole.GetStreamView(s.Index)
		if len(data) == 0 {
			continue
		}
		found = true
		scanBIFFXLMStream(data, res, deadline)
	}
	_ = found
}

// shrfmlaKey is the map key for the shared-formula table: anchor row/col (both
// 0-based, as decoded from the SHRFMLA rwFirst/colFirst fields).
type shrfmlaKey [2]uint16

// parseSHRFMLARecord parses a SHRFMLA (0x00BC) record payload and returns the
// anchor key and the rgce bytes of the shared formula body.
//
// SHRFMLA payload layout (MS-XLS §2.4.271):
//
//	rwFirst  uint16 LE  — first row of the shared range (0-based)
//	rwLast   uint16 LE  — last row (0-based); >= rwFirst
//	colFirst uint8      — first column (0-based)
//	colLast  uint8      — last column; >= colFirst
//	reserved uint8
//	cce      uint16 LE  — byte length of rgce
//	rgce     [cce]byte  — ptg token stream (the shared formula body)
//
// The extra rgcb (referenced-cell array) that follows rgce is not parsed; it
// carries run-length cell ranges for the shared cells and carries no formula
// content.
//
// Returns (key, nil) on any malformed input (fail-open). Enforces maxSHRFMLACce
// so a hostile cce cannot drive an oversized allocation.
func parseSHRFMLARecord(payload []byte) (key shrfmlaKey, rgce []byte, ok bool) {
	// Minimum: rwFirst(2)+rwLast(2)+colFirst(1)+colLast(1)+reserved(1)+cce(2) = 9 bytes.
	if len(payload) < 9 {
		return key, nil, false
	}
	rwFirst := binary.LittleEndian.Uint16(payload[0:])
	rwLast := binary.LittleEndian.Uint16(payload[2:])
	colFirst := payload[4]
	colLast := payload[5]
	// payload[6] = reserved — ignored.
	cce := int(binary.LittleEndian.Uint16(payload[7:]))

	// Sanity: colLast must be >= colFirst; rwLast >= rwFirst.
	if colLast < colFirst || rwLast < rwFirst {
		return key, nil, false
	}
	if cce == 0 {
		return key, nil, false
	}
	if cce > maxSHRFMLACce {
		cce = maxSHRFMLACce
	}
	body := payload[9:]
	if cce > len(body) {
		cce = len(body)
	}
	if cce == 0 {
		return key, nil, false
	}
	buf := make([]byte, cce)
	copy(buf, body[:cce])
	// Anchor is the top-left cell of the shared range: (rwFirst, colFirst).
	key = shrfmlaKey{rwFirst, uint16(colFirst)}
	return key, buf, true
}

// hasPtgExp reports whether rgce begins with a ptgExp token (0x01) followed by
// 4 bytes of row/col pointer. Returns the referenced anchor row/col when true.
// A FORMULA cell whose entire expression is a single ptgExp points at a shared
// formula defined by a SHRFMLA record anchored at that row/col.
func hasPtgExp(rgce []byte) (row, col uint16, ok bool) {
	// ptgExp is 1 byte (0x01) + 2-byte row + 2-byte col = 5 bytes total.
	if len(rgce) < 5 {
		return 0, 0, false
	}
	if (rgce[0] & 0x7f) != ptgExp {
		return 0, 0, false
	}
	row = binary.LittleEndian.Uint16(rgce[1:])
	col = binary.LittleEndian.Uint16(rgce[3:])
	return row, col, true
}

// resolveSharedFormulas replaces any biffFormulaCell whose rgce starts with
// ptgExp with the shared formula body from the shrfmla table. Cells whose
// pointer does not match any table entry are left unchanged (fail-open).
//
// Self-reference guard: the replacement body is not recursively resolved. A
// shared body that itself contains ptgExp is NOT expanded again — it is used
// as-is (the ptg walker treats ptgExp as opaque, pushing ""). This caps
// recursion depth at 1 (no unbounded chain is possible).
//
// The function modifies the slice in place (updates the rgce field of elements
// whose ptgExp pointer resolved). The slice header itself is not modified.
func resolveSharedFormulas(cells []biffFormulaCell, table map[shrfmlaKey][]byte) {
	if len(table) == 0 {
		return
	}
	for i := range cells {
		row, col, ok := hasPtgExp(cells[i].rgce)
		if !ok {
			continue
		}
		key := shrfmlaKey{row, col}
		body, found := table[key]
		if !found {
			continue // no matching SHRFMLA — leave as opaque ptgExp (current behaviour)
		}
		// Replace the ptgExp rgce with the shared formula body.
		// Shallow copy so the table entry is not aliased to the cell.
		buf := make([]byte, len(body))
		copy(buf, body)
		cells[i].rgce = buf
	}
}

// scanBIFFXLMStream parses one BIFF Workbook/Book stream and appends XLM
// markers and folded-formula streams to res.
//
// BOUNDSHEET record layout (payload):
//
//	lbPlyPos  uint32 LE — stream position of BOF record
//	grbit     uint16 LE — byte 0: hidden state (bits 0–1); byte 1: dt (sheet type)
//	cch       uint8      — length of sheet name (characters)
//	fHighByte uint8      — 0 = latin1, 1 = UTF-16 LE
//	name      []byte     — cch bytes (latin1) or cch*2 bytes (UTF-16 LE)
//
// Per-call locals (scanned, records, xlmOutput) reset for each stream, so each
// stream gets its own folded-output and record-walk budget (≤2× total). The
// shared global caps (countXLMMarkers / len(res.Streams)) still bound the union.
//
// D7: FORMULA records are now collected per macrosheet substream and fed to the
// XLM emulator as a batch (two-pass). If the emulator produces no output the
// original one-by-one fold path is used as fallback (defense-in-depth).
// biffFormulaCell holds the decoded coordinate and raw ptg bytes of one
// FORMULA record within a macrosheet substream, for two-pass emulation.
type biffFormulaCell struct {
	coord string
	rgce  []byte
}

func scanBIFFXLMStream(workbookData []byte, res *Result, deadline time.Time) {
	r := bytes.NewReader(workbookData)
	scanned := 0
	records := 0
	xlmMarkers := countXLMMarkers(res.Streams)
	inMacroSheet := false // set by BOF; gates FORMULA folding to macro substreams
	xlmOutput := 0        // folded-formula byte budget, separate from markers
	sheetIndex := 0       // monotonic counter for synthetic sheet names

	var macroSheetCells []biffFormulaCell  // accumulator for current macrosheet
	var shrfmlaTable map[shrfmlaKey][]byte // shared-formula table for current substream, allocated lazily

	// flushMacroSheet emits output for the cells collected from the current
	// macrosheet substream. It tries the emulator first; if that produces no
	// output it falls back to the original one-by-one fold path.
	flushMacroSheet := func() {
		if len(macroSheetCells) == 0 {
			return
		}
		cells := macroSheetCells
		macroSheetCells = nil

		// SHRFMLA resolution: replace ptgExp rgce with the shared formula body
		// so the emulator and fold path see the actual formula content. Cells
		// whose pointer is not in the table are left unchanged (fail-open).
		resolveSharedFormulas(cells, shrfmlaTable)

		// Build xlmCell slice using WithRefs parser so the emulator can
		// resolve intra-sheet cell references.
		xlmCells := make([]xlmCell, 0, len(cells))
		for _, bc := range cells {
			formula := parseBIFF8FormulaWithRefs(bc.rgce)
			if formula == "" {
				continue
			}
			xlmCells = append(xlmCells, xlmCell{coord: bc.coord, formula: formula})
		}

		priorLen := len(res.Streams)
		if len(xlmCells) > 0 {
			emulateXLMCells(xlmCells, &res.Streams, &xlmOutput, deadline)
		}

		if !xlmEmulatorProducedPayload(res.Streams, priorLen) {
			// Emulator produced no output — fall back to one-by-one fold.
			for _, bc := range cells {
				folded := parseBIFF8Formula(bc.rgce)
				emitFoldedFormula(folded, &res.Streams, &xlmOutput, true)
			}
		}
	}

	for {
		if expired(deadline) {
			break
		}
		if scanned >= maxXLMSheets {
			break
		}
		// A workbook stream is overwhelmingly FORMULA records, not BOUNDSHEETs,
		// so the per-sheet cap above does not bound the loop on a hostile file —
		// cap the total record count too.
		if records >= maxBIFFRecords {
			break
		}
		records++
		if xlmMarkers >= maxXLMMarkers || len(res.Streams) >= maxStreams {
			break
		}

		// BIFF record header: uint16 type + uint16 length.
		var recType, recLen uint16
		if err := binary.Read(r, binary.LittleEndian, &recType); err != nil {
			break // EOF or malformed
		}
		if err := binary.Read(r, binary.LittleEndian, &recLen); err != nil {
			break
		}

		// BOF (0x0809): substream boundary. Its dt field (offset 2) tells us
		// whether the following records belong to an Excel-4.0 MACROSHEET
		// substream (dt 0x0040) — only then do we fold its FORMULA cells, so
		// ordinary worksheet formulas (=SUM(...)) can't fabricate folded streams.
		//
		// D7: flush the previous macrosheet's accumulated cells before switching.
		if recType == 0x0809 {
			flushMacroSheet() // emit/fallback for the substream we just left
			inMacroSheet = false
			// Reset the shared-formula table for the new substream; SHRFMLA
			// entries from one macrosheet are not valid in another.
			shrfmlaTable = nil
			if recLen >= 4 {
				payload, ok := readBIFFRecordPrefix(r, recLen, 4)
				if !ok {
					break
				}
				dt := binary.LittleEndian.Uint16(payload[2:])
				if dt == 0x0040 {
					inMacroSheet = true
					sheetIndex++
				}
			} else {
				if _, err := r.Seek(int64(recLen), io.SeekCurrent); err != nil {
					break
				}
			}
			continue
		}

		// SHRFMLA (0x00BC): shared formula definition record. Per MS-XLS §2.4.271
		// a SHRFMLA immediately follows the first FORMULA record for its anchor
		// cell. Its payload defines the formula body shared by all cells in the
		// range [rwFirst..rwLast, colFirst..colLast]. Store it in shrfmlaTable
		// keyed by (rwFirst, colFirst) so a ptgExp pointer in a later FORMULA
		// cell can resolve it.
		//
		// Only accepted inside a macrosheet substream — a SHRFMLA in a plain
		// worksheet cannot carry XLM macro verbs and we don't want to store it.
		if recType == 0x00BC {
			if inMacroSheet && recLen >= 9 && len(shrfmlaTable) < maxSHRFMLAEntries {
				payload, ok := readBIFFRecordPrefix(r, recLen, 9+maxSHRFMLACce)
				if !ok {
					break // malformed — fail-open
				}
				if key, body, ok := parseSHRFMLARecord(payload); ok {
					if shrfmlaTable == nil {
						shrfmlaTable = make(map[shrfmlaKey][]byte, 4)
					}
					shrfmlaTable[key] = body
				}
			} else {
				if _, err := r.Seek(int64(recLen), io.SeekCurrent); err != nil {
					break
				}
			}
			continue
		}

		// FORMULA (0x0006): when inside a macrosheet substream, collect its ptg
		// bytes for the two-pass emulator batch (D7). Payload layout:
		//   row(2) col(2) ixfe(2) result(8) grbit(2) chn(4) cce(2) rgce[cce]
		// ptg bytes start at offset 22, length cce (uint16 at offset 20).
		if recType == 0x0006 {
			if !inMacroSheet || recLen < 22 {
				if _, err := r.Seek(int64(recLen), io.SeekCurrent); err != nil {
					break
				}
				continue
			}
			payload := make([]byte, recLen)
			if _, err := io.ReadFull(r, payload); err != nil {
				break
			}
			if len(macroSheetCells) < maxXLMFoldFormulas {
				row := binary.LittleEndian.Uint16(payload[0:])
				col := binary.LittleEndian.Uint16(payload[2:])
				coord := biffCellToA1(row, col)
				if coord == "" {
					coord = "A" + strconv.Itoa(int(row)+1) // fallback
				}
				cce := int(binary.LittleEndian.Uint16(payload[20:]))
				rgce := payload[22:]
				// biff-continue: a FORMULA whose ptg array (cce bytes) exceeds the
				// ~8 KB BIFF record cap spills its tail into the immediately
				// following CONTINUE (0x003C) records. Reassemble before parsing,
				// or the folded formula is truncated mid-ptg and a dangerous
				// trailing verb (=…EXEC/CALL) is silently lost.
				if cce > len(rgce) {
					rgce = readBiffFormulaContinue(r, rgce, cce)
				}
				if cce > len(rgce) {
					cce = len(rgce)
				}
				buf := make([]byte, cce)
				copy(buf, rgce[:cce])
				macroSheetCells = append(macroSheetCells, biffFormulaCell{coord: coord, rgce: buf})
			}
			continue
		}

		// NAME (0x0018): workbook-level defined name. Built-in names (fBuiltin set
		// in grbit) include Auto_Open (code 0x01) and Auto_Close (code 0x02) — the
		// autorun triggers for XLM dropper workbooks. Emit a synthetic marker so a
		// stacking YARA rule can detect the combination of autorun + hidden macrosheet
		// or dangerous function. MS-XLS NAME record layout:
		//   [0..1]  grbit  uint16 LE — bit 0x0020 = fBuiltin
		//   [3]     cch    uint8  — name length (1 for a builtin)
		//   [14]    rgch   first byte = builtin name code (0x01=Auto_Open, 0x02=Auto_Close)
		if recType == 0x0018 {
			if recLen >= 15 {
				payload, ok := readBIFFRecordPrefix(r, recLen, 15)
				if !ok {
					break // malformed — fail-open
				}
				grbit := binary.LittleEndian.Uint16(payload[0:])
				if grbit&0x0020 != 0 && payload[3] == 1 { // fBuiltin + single-byte name
					switch payload[14] {
					case 0x01:
						res.Streams = append(res.Streams, []byte("XLM-AUTO-OPEN"))
					case 0x02:
						res.Streams = append(res.Streams, []byte("XLM-AUTO-CLOSE"))
					}
				}
			} else {
				if _, err := r.Seek(int64(recLen), io.SeekCurrent); err != nil {
					break
				}
			}
			continue
		}

		if recType != 0x0085 {
			// Not a record we handle — skip the payload.
			if _, err := r.Seek(int64(recLen), io.SeekCurrent); err != nil {
				break
			}
			continue
		}
		scanned++

		// Read the BOUNDSHEET8 payload.
		if recLen < 6 {
			// Minimum: lbPlyPos(4) + grbit(2). Too short — malformed, skip.
			if _, err := r.Seek(int64(recLen), io.SeekCurrent); err != nil {
				break
			}
			continue
		}
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			break // malformed — fail-open
		}

		// grbit: byte 0 = hidden state (bits 0-1), byte 1 = dt (sheet type).
		grbit0 := payload[4]
		grbitDt := payload[5]
		hiddenBits := grbit0 & 0x03
		dt := grbitDt

		// dt 0x01 = Excel-4.0 macro sheet; others are worksheet/chart/VB.
		if dt != 0x01 {
			continue
		}
		stateLabel := xlmHiddenStateLabel[hiddenBits]
		if stateLabel == "" {
			continue // visible macro sheet — no marker
		}

		// Decode the sheet name.
		name := biffSheetName(payload[6:])
		res.Streams = append(res.Streams, []byte("XLM-HIDDEN-MACROSHEET "+stateLabel+" "+name))
		xlmMarkers++
	}

	// Flush any cells accumulated from the final macrosheet substream.
	flushMacroSheet()

	_ = sheetIndex // used only for disambiguation; suppress unused warning
}

func readBIFFRecordPrefix(r *bytes.Reader, recLen uint16, max int) ([]byte, bool) {
	n := int(recLen)
	if n > max {
		n = max
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, false
	}
	if skip := int(recLen) - n; skip > 0 {
		if skip > r.Len() {
			return nil, false
		}
		if _, err := r.Seek(int64(skip), io.SeekCurrent); err != nil {
			return nil, false
		}
	}
	return payload, true
}

// readBiffFormulaContinue reassembles a FORMULA ptg array that was split across
// the BIFF ~8 KB record boundary into one or more following CONTINUE (0x003C)
// records. rgce holds the bytes already read from the FORMULA record; need is
// the declared cce. It appends each immediately-following CONTINUE payload until
// need bytes are available, a non-CONTINUE record is reached (the reader is
// rewound to that record's header so the main walk re-reads it), or a safety cap
// is hit. Bounded and fail-open — never reads unbounded and never panics.
func readBiffFormulaContinue(r *bytes.Reader, rgce []byte, need int) []byte {
	// Copy out of the FORMULA payload's backing array before growing, so a later
	// append can't alias it.
	out := make([]byte, len(rgce), need)
	copy(out, rgce)

	for i := 0; i < maxContinueRecs && len(out) < need; i++ {
		pos, _ := r.Seek(0, io.SeekCurrent)
		var typ, length uint16
		if err := binary.Read(r, binary.LittleEndian, &typ); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			_, _ = r.Seek(pos, io.SeekStart)
			break
		}
		if typ != 0x003C { // not a CONTINUE — rewind so the main loop handles it
			_, _ = r.Seek(pos, io.SeekStart)
			break
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			break
		}
		out = append(out, body...)
		if len(out) > maxFormulaReassembled {
			out = out[:maxFormulaReassembled]
			break
		}
	}
	return out
}

// biffSheetName decodes the name field from a BOUNDSHEET8 payload slice starting
// at offset 0 (i.e. after lbPlyPos + grbit have been consumed). Layout:
//
//	[0] cch       uint8  — character count
//	[1] fHighByte uint8  — 0 = latin1, 1 = UTF-16 LE
//	[2…] name     bytes  — cch bytes (latin1) or cch*2 bytes (UTF-16 LE)
//
// Returns an empty string on any malformed input (fail-open).
func biffSheetName(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	cch := int(b[0])
	fHigh := b[1]
	if fHigh == 1 {
		// UTF-16 LE
		need := 2 + cch*2
		if len(b) < need {
			return ""
		}
		runes := make([]rune, cch)
		for i := range runes {
			runes[i] = rune(binary.LittleEndian.Uint16(b[2+i*2:]))
		}
		return string(runes)
	}
	// Latin-1
	need := 2 + cch
	if len(b) < need {
		return ""
	}
	return string(b[2 : 2+cch])
}

// countXLMMarkers counts how many streams already carry the XLM-HIDDEN-MACROSHEET
// prefix (used to enforce maxXLMMarkers).
func countXLMMarkers(streams [][]byte) int {
	n := 0
	for _, s := range streams {
		if bytes.HasPrefix(s, []byte("XLM-HIDDEN-MACROSHEET ")) {
			n++
		}
	}
	return n
}
