package extract

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// --- varint ---

func TestReadVarint(t *testing.T) {
	cases := []struct {
		in   []byte
		want int
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{[]byte{0xff, 0x7f}, 16383, 2},
		{[]byte{0x80, 0x80, 0x01}, 16384, 3},
		{[]byte{}, 0, 0},                       // truncated
		{[]byte{0x80}, 0, 0},                   // continuation but truncated
		{[]byte{0x80, 0x80, 0x80, 0x80}, 0, 0}, // 4 bytes, still continuing → malformed
	}
	for _, c := range cases {
		v, n := readVarint(c.in)
		if v != c.want || n != c.n {
			t.Errorf("readVarint(%v) = (%d,%d), want (%d,%d)", c.in, v, n, c.want, c.n)
		}
	}
}

// --- BIFF12 ptg parser ---

// strPtg builds a BIFF12 ptgStr token: 0x17 + uint16 charcount + UTF-16LE.
func strPtg(s string) []byte {
	out := []byte{ptgStr}
	out = binary.LittleEndian.AppendUint16(out, uint16(len([]rune(s))))
	for _, r := range s {
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}

func TestParseBIFF12Formula_StringUTF16(t *testing.T) {
	got := parseBIFF12Formula(strPtg("http://evil.test"))
	if got != "http://evil.test" {
		t.Fatalf("got %q", got)
	}
}

func TestParseBIFF12Formula_Concat(t *testing.T) {
	// "ab" & "cd" → ptgStr ab, ptgStr cd, ptgConcat
	rgce := append(strPtg("ab"), strPtg("cd")...)
	rgce = append(rgce, ptgConcat)
	if got := parseBIFF12Formula(rgce); got != "abcd" {
		t.Fatalf("got %q", got)
	}
}

func TestParseBIFF12Formula_ExecFuncVar(t *testing.T) {
	// =EXEC("calc.exe") : ptgStr arg, then ptgFuncVar argc=1 funcid=110(EXEC)
	rgce := strPtg("calc.exe")
	rgce = append(rgce, ptgFuncVar, 1)
	rgce = binary.LittleEndian.AppendUint16(rgce, 110)
	got := parseBIFF12Formula(rgce)
	if !strings.Contains(got, "=EXEC(calc.exe)") {
		t.Fatalf("got %q", got)
	}
}

func TestParseBIFF12Formula_FixedArityMID(t *testing.T) {
	rgce := strPtg("calc.exe")
	rgce = append(rgce, ptgIntTok(1)...)
	rgce = append(rgce, ptgIntTok(8)...)
	rgce = append(rgce, ptgFuncTok(31)...)
	if got := parseBIFF12Formula(rgce); got != "=MID(calc.exe,1,8)" {
		t.Fatalf("BIFF12 MID arity: got %q, want =MID(calc.exe,1,8)", got)
	}
}

func TestParseBIFF12Formula_PtgAttrChooseSkip(t *testing.T) {
	rgce := strPtg("func")
	rgce = append(rgce, ptgAttr, 0x04, 0x02, 0x00)
	rgce = append(rgce, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00)
	rgce = append(rgce, strPtg("result")...)
	if got := parseBIFF12Formula(rgce); got != "funcresult" {
		t.Fatalf("BIFF12 ptgAttrChoose skip: got %q, want funcresult", got)
	}
}

func TestParseBIFF8FormulaWithRefs_FixedArityMID(t *testing.T) {
	stream := ptgStr8("calc.exe")
	stream = append(stream, ptgIntTok(1)...)
	stream = append(stream, ptgIntTok(8)...)
	stream = append(stream, ptgFuncTok(31)...)
	if got := parseBIFF8FormulaWithRefs(stream); got != "=MID(calc.exe,1,8)" {
		t.Fatalf("BIFF8 WithRefs MID arity: got %q, want =MID(calc.exe,1,8)", got)
	}
}

func TestParseBIFF12FormulaWithRefs_FixedArityMID(t *testing.T) {
	rgce := strPtg("calc.exe")
	rgce = append(rgce, ptgIntTok(1)...)
	rgce = append(rgce, ptgIntTok(8)...)
	rgce = append(rgce, ptgFuncTok(31)...)
	if got := parseBIFF12FormulaWithRefs(rgce); got != "=MID(calc.exe,1,8)" {
		t.Fatalf("BIFF12 WithRefs MID arity: got %q, want =MID(calc.exe,1,8)", got)
	}
}

func TestParseBIFF12Formula_FailOpenTruncated(t *testing.T) {
	// charcount says 5 but no bytes follow → fold-what-we-have, no panic.
	rgce := []byte{ptgStr, 0x05, 0x00}
	if got := parseBIFF12Formula(rgce); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestVersionContainsBIFF12Fmla(t *testing.T) {
	if !strings.Contains(Version, "+biff12fmla") {
		t.Errorf("Version %q does not contain +biff12fmla", Version)
	}
}

// --- record extraction ---

// fmlaNumRecord builds a FMLA_NUM payload: col4 style4 value8 grbit2 cce4 rgce.
func fmlaNumRecord(rgce []byte) []byte {
	return fmlaNumRecordWithTrailer(rgce, nil)
}

func fmlaNumRecordWithTrailer(rgce, trailer []byte) []byte {
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, 0) // col
	p = binary.LittleEndian.AppendUint32(p, 0) // style
	p = append(p, make([]byte, 8)...)          // value (double)
	p = binary.LittleEndian.AppendUint16(p, 0) // grbit
	p = binary.LittleEndian.AppendUint32(p, uint32(len(rgce)))
	p = append(p, rgce...)
	p = append(p, trailer...)
	return p
}

func fmlaStringRecord(rgce []byte, value string) []byte {
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, 0) // col
	p = binary.LittleEndian.AppendUint32(p, 0) // style
	p = binary.LittleEndian.AppendUint32(p, uint32(len([]rune(value))))
	for _, r := range value {
		p = binary.LittleEndian.AppendUint16(p, uint16(r))
	}
	p = binary.LittleEndian.AppendUint16(p, 0) // grbit
	p = binary.LittleEndian.AppendUint32(p, uint32(len(rgce)))
	p = append(p, rgce...)
	return p
}

func fmlaErrorRecordWithTrailer(rgce, trailer []byte) []byte {
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, 0) // col
	p = binary.LittleEndian.AppendUint32(p, 0) // style
	p = append(p, 0)                           // value (error)
	p = binary.LittleEndian.AppendUint16(p, 0) // grbit
	p = binary.LittleEndian.AppendUint32(p, uint32(len(rgce)))
	p = append(p, rgce...)
	p = append(p, trailer...)
	return p
}

func rowHdrRecord(row uint32) []byte {
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, row)
	return biff12Record(0, p)
}

func cellIsstRecord(idx uint32) []byte {
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, 0) // col
	p = binary.LittleEndian.AppendUint32(p, 0) // style
	p = binary.LittleEndian.AppendUint32(p, idx)
	return biff12Record(biff12CellIsst, p)
}

func ptgRef12(row uint32, col uint16) []byte {
	return []byte{0x44, byte(row), byte(row >> 8), byte(row >> 16), byte(row >> 24), byte(col), byte(col >> 8)}
}

func TestBIFF12FormulaRgce(t *testing.T) {
	rgce := strPtg("payload")
	p := fmlaNumRecord(rgce)
	got := biff12FormulaRgce(biff12FmlaNum, p)
	if !bytes.Equal(got, rgce) {
		t.Fatalf("got %v want %v", got, rgce)
	}
}

func TestBIFF12FormulaRgce_StringRecord(t *testing.T) {
	rgce := strPtg("payload")
	p := fmlaStringRecord(rgce, "cached")
	got := biff12FormulaRgce(biff12FmlaString, p)
	if !bytes.Equal(got, rgce) {
		t.Fatalf("got %v want %v", got, rgce)
	}
}

func TestBIFF12FormulaRgce_WithTrailer(t *testing.T) {
	rgce := strPtg("payload")
	p := fmlaNumRecordWithTrailer(rgce, []byte{0xde, 0xad, 0xbe, 0xef})
	got := biff12FormulaRgce(biff12FmlaNum, p)
	if !bytes.Equal(got, rgce) {
		t.Fatalf("trailer must not be folded into rgce: got %v want %v", got, rgce)
	}
}

func TestBIFF12FormulaRgce_TooShort(t *testing.T) {
	if got := biff12FormulaRgce(biff12FmlaNum, make([]byte, 14)); got != nil {
		t.Fatalf("payload < 15 bytes must return nil, got %v", got)
	}
}

func TestBIFF12FormulaRgce_DeclaredLengthOverrun(t *testing.T) {
	p := fmlaNumRecord(strPtg("payload"))
	binary.LittleEndian.PutUint32(p[18:22], uint32(len(p)))
	if got := biff12FormulaRgce(biff12FmlaNum, p); got != nil {
		t.Fatalf("overrunning cce must return nil, got %v", got)
	}
}

// --- end-to-end through a zip ---

// putVarint appends a value as a pyxlsb2 varint.
func putVarint(b []byte, v int) []byte {
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b = append(b, c|0x80)
		} else {
			b = append(b, c)
			return b
		}
	}
}

func biff12Record(id int, payload []byte) []byte {
	var b []byte
	b = putVarint(b, id)
	b = putVarint(b, len(payload))
	return append(b, payload...)
}

func buildXLSBWithRecord(t *testing.T, partPath string, rec []byte) []byte {
	t.Helper()
	return buildXLSBWithParts(t, map[string][]byte{partPath: rec})
}

func buildXLSBWithParts(t *testing.T, parts map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for path, body := range parts {
		w, err := zw.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sharedStringsBin(items ...string) []byte {
	var raw []byte
	raw = append(raw, biff12Record(biff12BrtSSTBegin, make([]byte, 8))...)
	for _, item := range items {
		var p []byte
		p = append(p, 0) // flags
		p = binary.LittleEndian.AppendUint32(p, uint32(len([]rune(item))))
		for _, r := range item {
			p = binary.LittleEndian.AppendUint16(p, uint16(r))
		}
		raw = append(raw, biff12Record(biff12BrtSSTItem, p)...)
	}
	return raw
}

// buildXLSB makes a minimal OOXML zip with one .bin part at the given path
// holding a single FMLA_NUM record whose formula folds to wantFold.
func buildXLSB(t *testing.T, partPath, formula string) []byte {
	t.Helper()
	// =EXEC("formula") ptg stream.
	rgce := strPtg(formula)
	rgce = append(rgce, ptgFuncVar, 1)
	rgce = binary.LittleEndian.AppendUint16(rgce, 110) // EXEC
	rec := biff12Record(biff12FmlaNum, fmlaNumRecord(rgce))
	return buildXLSBWithRecord(t, partPath, rec)
}

func foldStreams(t *testing.T, data []byte) [][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromXLSBXLMFold(zr, &out, time.Time{}, nil)
	return out
}

func TestXLSBFold_Macrosheet(t *testing.T) {
	data := buildXLSB(t, "xl/macrosheets/sheet1.bin", "http://evil.test/x.exe")
	out := foldStreams(t, data)

	var sawFold, sawDanger bool
	for _, s := range out {
		if strings.Contains(string(s), "http://evil.test/x.exe") {
			sawFold = true
		}
		if string(s) == "XLM-DANGEROUS-FUNC EXEC" {
			sawDanger = true
		}
	}
	if !sawFold {
		t.Errorf("folded formula string not emitted; streams=%q", out)
	}
	if !sawDanger {
		t.Errorf("XLM-DANGEROUS-FUNC EXEC marker not emitted; streams=%q", out)
	}
}

func TestXLSBFold_StringRecordID8(t *testing.T) {
	rgce := strPtg("http://evil.test/string.exe")
	rgce = append(rgce, ptgFuncVar, 1)
	rgce = binary.LittleEndian.AppendUint16(rgce, 110) // EXEC
	rec := biff12Record(biff12FmlaString, fmlaStringRecord(rgce, "cached"))
	data := buildXLSBWithRecord(t, "xl/macrosheets/sheet1.bin", rec)
	out := foldStreams(t, data)
	if !bytes.Contains(bytes.Join(out, []byte("\n")), []byte("http://evil.test/string.exe")) {
		t.Fatalf("BrtFmlaString id 8 formula not emitted; streams=%q", out)
	}
}

func TestXLSBFold_CellIsstMIDReference(t *testing.T) {
	rgce := ptgRef12(0, 0xc000)
	rgce = append(rgce, ptgIntTok(2)...)
	rgce = append(rgce, ptgIntTok(8)...)
	rgce = append(rgce, ptgFuncTok(31)...) // MID(A1,2,8)
	rgce = append(rgce, ptgIntTok('!')...)
	rgce = append(rgce, ptgFuncTok(111)...) // CHAR("!")
	rgce = append(rgce, ptgConcat)

	var sheet []byte
	sheet = append(sheet, rowHdrRecord(0)...)
	sheet = append(sheet, cellIsstRecord(0)...)
	sheet = append(sheet, rowHdrRecord(1)...)
	sheet = append(sheet, biff12Record(biff12FmlaBool, fmlaErrorRecordWithTrailer(rgce, []byte{0, 0, 0, 0}))...)

	data := buildXLSBWithParts(t, map[string][]byte{
		"xl/sharedStrings.bin":      sharedStringsBin("ABCDEFGHIJK"),
		"xl/macrosheets/sheet1.bin": sheet,
	})
	out := foldStreams(t, data)
	if !bytes.Contains(bytes.Join(out, []byte("\n")), []byte("BCDEFGHI!")) {
		t.Fatalf("BrtCellIsst + MID ref not emitted; streams=%q", out)
	}
}

func TestXLSBFold_ErrorRecordTrailerCharConcatFallback(t *testing.T) {
	rgce := ptgCharConcat("http://evil.test/hancitor")
	rec := biff12Record(biff12FmlaError, fmlaErrorRecordWithTrailer(rgce, []byte{0, 0, 0, 0}))
	data := buildXLSBWithRecord(t, "xl/macrosheets/sheet1.bin", rec)
	out := foldStreams(t, data)
	if !bytes.Contains(bytes.Join(out, []byte("\n")), []byte("http://evil.test/hancitor")) {
		t.Fatalf("trailer-bearing BrtFmlaError CHAR concat not emitted; streams=%q", out)
	}
}

// --- ptg-binop-skip BIFF12 mirror tests -----------------------------------------

// TestParseBIFF12Formula_BinopSkip_EQBeforeEXEC mirrors the BIFF8 motivating
// bug for the BIFF12 path: a ptgEQ operator between a ref+int and an EXEC
// FuncVar must no longer cause early abort.
func TestParseBIFF12Formula_BinopSkip_EQBeforeEXEC(t *testing.T) {
	// BIFF12 ptgRef placeholder (7 bytes), ptgInt(1) (3 bytes), ptgEQ (1 byte),
	// then ptgStr("calc"), then ptgFuncVar EXEC argc=1.
	rgce := ptgRef12(0, 0)
	rgce = append(rgce, ptgInt, 1, 0) // ptgInt value=1
	rgce = append(rgce, ptgEQ)
	rgce = append(rgce, strPtg("calc")...)
	rgce = append(rgce, ptgFuncVar, 1)
	rgce = binary.LittleEndian.AppendUint16(rgce, 110) // EXEC
	got := parseBIFF12Formula(rgce)
	if !strings.Contains(got, "EXEC") {
		t.Errorf("BIFF12 EQ+EXEC: EXEC not in output; got %q", got)
	}
	if !strings.Contains(got, "calc") {
		t.Errorf("BIFF12 EQ+EXEC: 'calc' not in output; got %q", got)
	}
}

// TestParseBIFF12Formula_BinopSkip_NoPanic verifies a binop-only stream does
// not panic on the BIFF12 path.
func TestParseBIFF12Formula_BinopSkip_NoPanic(t *testing.T) {
	rgce := []byte{ptgInt, 2, 0, ptgInt, 3, 0, ptgAdd}
	_ = parseBIFF12Formula(rgce)
}

func TestXLSBFold_WorksheetFPGated(t *testing.T) {
	// Same record content but in xl/worksheets/ — must NOT be folded (only
	// xl/macrosheets/ is a macro carrier).
	data := buildXLSB(t, "xl/worksheets/sheet1.bin", "http://evil.test/x.exe")
	out := foldStreams(t, data)
	if len(out) != 0 {
		t.Fatalf("worksheet .bin must not fold; got %q", out)
	}
}

// xlNullableWideString builds an [MS-XLSB] XLNullableWideString: 4-byte cch + UTF-16LE.
func xlNullableWideString(s string) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, uint32(len([]rune(s))))
	for _, r := range s { // UTF-16LE, no terminator (cch is explicit)
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

// buildXLSBExternalDDE makes an OOXML zip with an externalLink .bin holding a
// BrtBeginSupBook record (sbt as given) + server/topic strings.
func buildXLSBExternalDDE(t *testing.T, sbt uint16, server, topic string) []byte {
	t.Helper()
	var body []byte
	body = binary.LittleEndian.AppendUint16(body, sbt)
	body = append(body, xlNullableWideString(server)...)
	body = append(body, xlNullableWideString(topic)...)
	rec := biff12Record(biff12BrtBeginSupBook, body)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("xl/externalLinks/externalLink1.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(rec); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func ddeStreams(t *testing.T, data []byte) [][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromXLSBExternalDDE(zr, &out, time.Time{})
	return out
}

// TestXLSBExternalDDE_Sbt1 verifies a DDE supporting book (sbt=1) surfaces an
// XLSB-DDE marker carrying the command server|topic — the strings live as
// UTF-16LE in a binary record and are invisible to a plain-text scan.
func TestXLSBExternalDDE_Sbt1(t *testing.T) {
	data := buildXLSBExternalDDE(t, 1, "cmd", "/c calc.exe")
	out := ddeStreams(t, data)
	joined := bytes.Join(out, []byte("\n"))
	if !bytes.Contains(joined, []byte("XLSB-DDE cmd|/c calc.exe")) {
		t.Fatalf("DDE supbook not surfaced; got %q", joined)
	}
}

// TestXLSBExternalDDE_WorkbookSbt0NoMarker is the FP gate: a normal workbook
// supporting book (sbt=0) must NOT emit a DDE marker.
func TestXLSBExternalDDE_WorkbookSbt0NoMarker(t *testing.T) {
	data := buildXLSBExternalDDE(t, 0, "C:\\refs\\book.xlsb", "")
	out := ddeStreams(t, data)
	if bytes.Contains(bytes.Join(out, []byte("\n")), []byte("XLSB-DDE")) {
		t.Fatalf("workbook supbook (sbt=0) wrongly emitted a DDE marker; got %q", out)
	}
}
