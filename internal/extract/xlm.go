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
	"strings"
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
func fromOOXMLXLM(zr *zip.Reader, out *[][]byte, deadline time.Time) {
	if expired(deadline) {
		return
	}

	// Build a name-set of all zip entries for fast membership tests.
	names := make(map[string]struct{}, len(zr.File))
	for _, f := range zr.File {
		names[f.Name] = struct{}{}
	}

	// Check whether any xl/macrosheets/ part exists — required to avoid FPs on
	// ordinary hidden sheets in workbooks that have no macro content at all.
	hasMacrosheet := false
	for name := range names {
		if strings.HasPrefix(name, "xl/macrosheets/") {
			hasMacrosheet = true
			break
		}
	}
	if !hasMacrosheet {
		return
	}

	// Locate xl/workbook.xml.
	var wbFile *zip.File
	for _, f := range zr.File {
		if f.Name == "xl/workbook.xml" {
			wbFile = f
			break
		}
	}
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
	for {
		if expired(deadline) {
			break
		}
		if countXLMMarkers(*out) >= maxXLMMarkers || len(*out) >= maxStreams {
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
	}
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
		data := ole.GetStream(s.Index)
		if len(data) == 0 {
			continue
		}
		found = true
		scanBIFFXLMStream(data, res, deadline)
	}
	_ = found
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
func scanBIFFXLMStream(workbookData []byte, res *Result, deadline time.Time) {
	// biffFormulaCell holds the decoded coordinate and raw ptg bytes of one
	// FORMULA record within a macrosheet substream, for two-pass emulation.
	type biffFormulaCell struct {
		coord string
		rgce  []byte
	}

	r := bytes.NewReader(workbookData)
	scanned := 0
	records := 0
	inMacroSheet := false // set by BOF; gates FORMULA folding to macro substreams
	xlmOutput := 0        // folded-formula byte budget, separate from markers
	sheetIndex := 0       // monotonic counter for synthetic sheet names

	var macroSheetCells []biffFormulaCell // accumulator for current macrosheet

	// flushMacroSheet emits output for the cells collected from the current
	// macrosheet substream. It tries the emulator first; if that produces no
	// output it falls back to the original one-by-one fold path.
	flushMacroSheet := func() {
		if len(macroSheetCells) == 0 {
			return
		}
		cells := macroSheetCells
		macroSheetCells = nil

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

		if len(res.Streams) == priorLen {
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
		if countXLMMarkers(res.Streams) >= maxXLMMarkers || len(res.Streams) >= maxStreams {
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
			if recLen >= 4 {
				payload := make([]byte, recLen)
				if _, err := io.ReadFull(r, payload); err != nil {
					break
				}
				dt := binary.LittleEndian.Uint16(payload[2:])
				if dt == 0x0040 {
					inMacroSheet = true
					sheetIndex++
				}
			} else if _, err := r.Seek(int64(recLen), io.SeekCurrent); err != nil {
				break
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
				payload := make([]byte, recLen)
				if _, err := io.ReadFull(r, payload); err != nil {
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
	}

	// Flush any cells accumulated from the final macrosheet substream.
	flushMacroSheet()

	_ = sheetIndex // used only for disambiguation; suppress unused warning
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
