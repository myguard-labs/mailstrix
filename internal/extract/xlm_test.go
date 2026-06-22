package extract

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// makeOOXMLWithXLM builds a minimal in-memory OOXML zip that looks like an
// xlsm with a hidden/veryHidden macrosheet. It includes:
//   - xl/workbook.xml — declares one sheet with the given state
//   - xl/macrosheets/sheet1.xml — signals Excel-4.0 macro content
//
// Reuses addZipEntry from ooxml_rels_test.go (same package).
func makeOOXMLWithXLM(t *testing.T, sheetName, state string) []byte {
	t.Helper()
	workbookXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
		`<sheets>` +
		`<sheet name="` + sheetName + `" sheetId="1" state="` + state + `" r:id="rId1"` +
		` xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>` +
		`</sheets>` +
		`</workbook>`

	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	addZipEntry(t, zw, "xl/workbook.xml", workbookXML)
	addZipEntry(t, zw, "xl/macrosheets/sheet1.xml", `<?xml version="1.0"?><macrosheet/>`)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// buildBIFFWorkbook constructs a minimal BIFF8-shaped byte slice containing a
// single BOUNDSHEET8 record (type 0x0085) with the given sheet type (dt),
// hidden-state bits, and name. Wrapped in a CFB via buildCFB under a
// "Workbook" stream name — reuses buildCFB from msg_test.go (same package).
func buildBIFFWorkbook(t *testing.T, sheetName string, dt byte, hidden byte) []byte {
	t.Helper()

	// Build the BOUNDSHEET8 payload:
	//   lbPlyPos  uint32 LE (4 bytes) — arbitrary
	//   grbit     uint16 LE — byte 0: hidden bits, byte 1: dt
	//   cch       uint8   — name length
	//   fHighByte uint8   — 0 = latin1
	//   name      [cch]byte
	cch := byte(len(sheetName))
	payload := make([]byte, 0, 6+2+int(cch))
	lbPlyPos := make([]byte, 4)
	binary.LittleEndian.PutUint32(lbPlyPos, 0)
	payload = append(payload, lbPlyPos...) // lbPlyPos
	payload = append(payload, hidden, dt)  // grbit: byte0=hidden, byte1=dt
	payload = append(payload, cch)         // cch
	payload = append(payload, 0)           // fHighByte = latin1
	payload = append(payload, []byte(sheetName)...)

	// Encode as a BIFF record: type=0x0085, len=uint16.
	recLen := uint16(len(payload))
	var record bytes.Buffer
	b2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(b2, 0x0085)
	record.Write(b2)
	binary.LittleEndian.PutUint16(b2, recLen)
	record.Write(b2)
	record.Write(payload)

	return buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "Workbook", mse: 2, data: record.Bytes()},
	})
}

// TestXLMOOXML_VeryHidden checks that an OOXML workbook declaring a
// state="veryHidden" sheet alongside an xl/macrosheets/ part emits a
// XLM-HIDDEN-MACROSHEET stream with "veryHidden".
func TestXLMOOXML_VeryHidden(t *testing.T) {
	buf := makeOOXMLWithXLM(t, "Macro1", "veryHidden")
	res := Extract(buf, time.Time{})

	if !res.IsDoc {
		t.Fatal("OOXML xlsm not flagged IsDoc")
	}
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("XLM-HIDDEN-MACROSHEET veryHidden Macro1")) {
		t.Fatalf("expected XLM-HIDDEN-MACROSHEET veryHidden Macro1; streams=%d joined=%q",
			len(res.Streams), joined)
	}
}

// TestXLMOOXML_Hidden checks that state="hidden" also emits the marker.
func TestXLMOOXML_Hidden(t *testing.T) {
	buf := makeOOXMLWithXLM(t, "HidSheet", "hidden")
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("XLM-HIDDEN-MACROSHEET hidden HidSheet")) {
		t.Fatalf("expected XLM-HIDDEN-MACROSHEET hidden HidSheet; got %q", joined)
	}
}

// TestXLMOOXML_VisibleNoMarker checks that a visible sheet in a workbook
// with an xl/macrosheets/ part does NOT emit a hidden-macrosheet marker.
func TestXLMOOXML_VisibleNoMarker(t *testing.T) {
	// Build workbook with visible sheet (no state attribute = visible).
	workbookXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
		`<sheets>` +
		`<sheet name="Sheet1" sheetId="1" r:id="rId1"` +
		` xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>` +
		`</sheets>` +
		`</workbook>`

	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	addZipEntry(t, zw, "xl/workbook.xml", workbookXML)
	addZipEntry(t, zw, "xl/macrosheets/sheet1.xml", `<?xml version="1.0"?><macrosheet/>`)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	res := Extract(b.Bytes(), time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("XLM-HIDDEN-MACROSHEET")) {
		t.Fatalf("visible sheet wrongly emitted XLM marker; got %q", joined)
	}
}

// TestXLMOOXML_NoMacrosheetsNoMarker checks that a hidden sheet in a workbook
// WITHOUT xl/macrosheets/ does NOT emit a marker (avoids FP on ordinary OOXML).
func TestXLMOOXML_NoMacrosheetsNoMarker(t *testing.T) {
	workbookXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
		`<sheets>` +
		`<sheet name="HiddenSheet" sheetId="1" state="veryHidden" r:id="rId1"` +
		` xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>` +
		`</sheets>` +
		`</workbook>`

	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	addZipEntry(t, zw, "xl/workbook.xml", workbookXML)
	// No xl/macrosheets/ entry
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	res := Extract(b.Bytes(), time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("XLM-HIDDEN-MACROSHEET")) {
		t.Fatalf("hidden sheet without macrosheets dir wrongly emitted marker; got %q", joined)
	}
}

// TestXLMBIFF_VeryHidden checks that a legacy xls OLE2 with a BOUNDSHEET8
// record declaring dt=0x01 (XLM macro) and state=veryHidden emits the marker.
func TestXLMBIFF_VeryHidden(t *testing.T) {
	// hidden bits: 2 = veryHidden; dt = 0x01 = Excel-4.0 macro
	buf := buildBIFFWorkbook(t, "Macro1", 0x01, 0x02)
	res := Extract(buf, time.Time{})

	if !res.IsDoc {
		t.Fatal("BIFF xls not flagged IsDoc")
	}
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("XLM-HIDDEN-MACROSHEET veryHidden Macro1")) {
		t.Fatalf("expected XLM-HIDDEN-MACROSHEET veryHidden Macro1; streams=%d joined=%q",
			len(res.Streams), joined)
	}
}

// TestXLMBIFF_HiddenMacro checks that dt=0x01 + state=hidden (bits=1) emits
// the "hidden" variant of the marker.
func TestXLMBIFF_HiddenMacro(t *testing.T) {
	buf := buildBIFFWorkbook(t, "MacroSheet", 0x01, 0x01)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("XLM-HIDDEN-MACROSHEET hidden MacroSheet")) {
		t.Fatalf("expected XLM-HIDDEN-MACROSHEET hidden MacroSheet; got %q", joined)
	}
}

// TestXLMBIFF_VisibleWorksheetNoMarker checks that a visible worksheet
// (dt=0x00, hidden=0) does NOT emit a marker.
func TestXLMBIFF_VisibleWorksheetNoMarker(t *testing.T) {
	buf := buildBIFFWorkbook(t, "Sheet1", 0x00, 0x00)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("XLM-HIDDEN-MACROSHEET")) {
		t.Fatalf("visible worksheet wrongly emitted XLM marker; got %q", joined)
	}
}

// TestXLMBIFF_VisibleMacroNoMarker checks that a visible XLM macro sheet
// (dt=0x01, hidden=0) does NOT emit the hidden-macrosheet marker — we only
// flag hidden/veryHidden ones.
func TestXLMBIFF_VisibleMacroNoMarker(t *testing.T) {
	buf := buildBIFFWorkbook(t, "VisMacro", 0x01, 0x00)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("XLM-HIDDEN-MACROSHEET")) {
		t.Fatalf("visible XLM macro sheet wrongly emitted hidden marker; got %q", joined)
	}
}

// buildBIFFFormulaWorkbook constructs a Workbook stream containing a BOF record
// of the given substream type (dt) followed by a single FORMULA (0x06) record
// whose ptg rgce is the supplied token bytes, wrapped in a CFB. Used to exercise
// the XLM-3 BIFF8 formula-folding path. dt 0x0040 = macrosheet, 0x0010 = worksheet.
func buildBIFFFormulaWorkbook(t *testing.T, dt uint16, rgce []byte) []byte {
	t.Helper()
	var wb bytes.Buffer
	put16 := func(v uint16) { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); wb.Write(b) }
	rec := func(typ uint16, payload []byte) {
		put16(typ)
		put16(uint16(len(payload)))
		wb.Write(payload)
	}

	// BOF: vers(2) + dt(2) (+ padding tolerated; we emit exactly 4).
	bof := make([]byte, 4)
	binary.LittleEndian.PutUint16(bof[2:], dt)
	rec(0x0809, bof)

	// FORMULA: row(2) col(2) ixfe(2) result(8) grbit(2) chn(4) cce(2) rgce[cce].
	fp := make([]byte, 22+len(rgce))
	binary.LittleEndian.PutUint16(fp[20:], uint16(len(rgce))) // cce
	copy(fp[22:], rgce)
	rec(0x0006, fp)

	return buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "Workbook", mse: 2, data: wb.Bytes()},
	})
}

// ptgStr8 / ptgFuncTok mirror the BIFF8 ptg builders in biff_ptg_test.go; we
// rebuild small inline streams here to keep the xlm_test fixtures self-contained.
func biffStr8(s string) []byte { return append([]byte{0x17, byte(len(s)), 0x00}, []byte(s)...) }

// TestXLMBIFF_FormulaFoldsInMacrosheet checks that a FORMULA ptg stream inside a
// macrosheet substream (BOF dt 0x0040) is folded and surfaced, and that a
// dangerous-func wrapper emits the XLM-DANGEROUS-FUNC marker (XLM-3).
func TestXLMBIFF_FormulaFoldsInMacrosheet(t *testing.T) {
	// ptg: push "calc.exe payload", then ptgFunc EXEC (id 110) → =EXEC(calc.exe payload).
	rgce := append(biffStr8("calc.exe payload"), 0x21, 110, 0) // ptgFunc EXEC
	buf := buildBIFFFormulaWorkbook(t, 0x0040, rgce)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("calc.exe payload")) {
		t.Fatalf("macrosheet FORMULA not folded; streams=%d joined=%q", len(res.Streams), joined)
	}
	if !bytes.Contains(joined, []byte("XLM-DANGEROUS-FUNC EXEC")) {
		t.Fatalf("expected XLM-DANGEROUS-FUNC EXEC; got %q", joined)
	}
}

// TestXLMBIFF_FormulaNotFoldedInWorksheet checks the FP gate: a FORMULA in an
// ordinary worksheet substream (BOF dt 0x0010) must NOT be folded/surfaced, so
// benign worksheet formulas can't fabricate streams.
func TestXLMBIFF_FormulaNotFoldedInWorksheet(t *testing.T) {
	rgce := append(biffStr8("benign worksheet text"), 0x21, 110, 0)
	buf := buildBIFFFormulaWorkbook(t, 0x0010, rgce)
	res := Extract(buf, time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("benign worksheet text")) {
		t.Fatalf("worksheet FORMULA wrongly folded; got %q", joined)
	}
	if bytes.Contains(joined, []byte("XLM-DANGEROUS-FUNC")) {
		t.Fatalf("worksheet FORMULA wrongly emitted dangerous marker; got %q", joined)
	}
}

// buildBIFFNAMEWorkbook constructs a minimal BIFF8 Workbook stream containing a
// single NAME record (0x0018). grbit controls the flags word (LE uint16); cch is the
// name-length byte at payload[3]; builtinCode is payload[14] (the builtin name code).
// Bytes [2] and [4..13] are zero-padded, matching the MS-XLS NAME record layout.
func buildBIFFNAMEWorkbook(t *testing.T, grbit uint16, cch byte, builtinCode byte) []byte {
	t.Helper()

	// NAME payload must be at least 15 bytes to cover rgch[0] (the builtin code).
	// Layout: grbit(2) [2](1 pad) cch(1) [4..13](10 pad) rgch[0](1) = 15 bytes total.
	payload := make([]byte, 15)
	binary.LittleEndian.PutUint16(payload[0:], grbit) // [0..1] grbit
	// payload[2] = 0 (reserved)
	payload[3] = cch // [3] cch
	// payload[4..13] = zero (itab, reserved, nameindex, etc.)
	payload[14] = builtinCode // [14] rgch[0] = builtin name code

	var record bytes.Buffer
	b2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(b2, 0x0018) // NAME record type
	record.Write(b2)
	binary.LittleEndian.PutUint16(b2, uint16(len(payload)))
	record.Write(b2)
	record.Write(payload)

	return buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "Workbook", mse: 2, data: record.Bytes()},
	})
}

// TestXLMBIFF_NameAutoOpen checks that a NAME record with fBuiltin set and
// builtin code 0x01 emits XLM-AUTO-OPEN.
func TestXLMBIFF_NameAutoOpen(t *testing.T) {
	// grbit 0x0020 = fBuiltin; cch=1 (single-byte builtin name); code 0x01 = Auto_Open.
	buf := buildBIFFNAMEWorkbook(t, 0x0020, 1, 0x01)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("XLM-AUTO-OPEN")) {
		t.Fatalf("expected XLM-AUTO-OPEN; streams=%d joined=%q", len(res.Streams), joined)
	}
}

// TestXLMBIFF_NameAutoClose checks that builtin code 0x02 emits XLM-AUTO-CLOSE.
func TestXLMBIFF_NameAutoClose(t *testing.T) {
	buf := buildBIFFNAMEWorkbook(t, 0x0020, 1, 0x02)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("XLM-AUTO-CLOSE")) {
		t.Fatalf("expected XLM-AUTO-CLOSE; streams=%d joined=%q", len(res.Streams), joined)
	}
}

// TestXLMBIFF_NameNonBuiltinNoMarker checks that a NAME record without fBuiltin
// (grbit bit 0x0020 clear) does NOT emit an autorun marker (FP guard).
func TestXLMBIFF_NameNonBuiltinNoMarker(t *testing.T) {
	// grbit 0x0000 — fBuiltin NOT set; code byte = 0x01 (would be Auto_Open if builtin).
	buf := buildBIFFNAMEWorkbook(t, 0x0000, 1, 0x01)
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("XLM-AUTO-")) {
		t.Fatalf("non-builtin NAME wrongly emitted autorun marker; got %q", joined)
	}
}

// TestXLMBIFF_NameTooShortNoMarker checks that a NAME record shorter than 15
// bytes is silently skipped — no marker, no panic.
func TestXLMBIFF_NameTooShortNoMarker(t *testing.T) {
	// Build a NAME record with a 10-byte payload (< 15 minimum).
	payload := make([]byte, 10)
	binary.LittleEndian.PutUint16(payload[0:], 0x0020) // fBuiltin set
	payload[3] = 1                                     // cch = 1

	var record bytes.Buffer
	b2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(b2, 0x0018)
	record.Write(b2)
	binary.LittleEndian.PutUint16(b2, uint16(len(payload)))
	record.Write(b2)
	record.Write(payload)

	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "Workbook", mse: 2, data: record.Bytes()},
	})
	res := Extract(buf, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if bytes.Contains(joined, []byte("XLM-AUTO-")) {
		t.Fatalf("short NAME record wrongly emitted autorun marker; got %q", joined)
	}
}

// TestXLMDeadline checks that an already-expired deadline causes fromBIFFXLM
// and fromOOXMLXLM to return immediately with nothing emitted.
func TestXLMDeadline(t *testing.T) {
	past := time.Now().Add(-time.Second)

	// OOXML path
	buf := makeOOXMLWithXLM(t, "Macro1", "veryHidden")
	res := Extract(buf, past)
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("XLM-HIDDEN-MACROSHEET")) {
			t.Errorf("expired deadline: OOXML XLM marker emitted anyway: %q", s)
		}
	}

	// BIFF path
	buf2 := buildBIFFWorkbook(t, "Macro1", 0x01, 0x02)
	res2 := Extract(buf2, past)
	for _, s := range res2.Streams {
		if bytes.HasPrefix(s, []byte("XLM-HIDDEN-MACROSHEET")) {
			t.Errorf("expired deadline: BIFF XLM marker emitted anyway: %q", s)
		}
	}
}
