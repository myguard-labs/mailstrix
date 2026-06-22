package extract

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

// --- foldXLMFormula unit tests ---

func TestFoldXLMFormula_CHARConcat(t *testing.T) {
	// =CHAR(104)&CHAR(116)&CHAR(116)&CHAR(112) → "http"
	got := foldXLMFormula("=CHAR(104)&CHAR(116)&CHAR(116)&CHAR(112)")
	if got != "http" {
		t.Errorf("CHAR concat: got %q, want %q", got, "http")
	}
}

func TestFoldXLMFormula_StringLiterals(t *testing.T) {
	got := foldXLMFormula(`="foo"&"bar"`)
	if got != "foobar" {
		t.Errorf("string literals: got %q, want %q", got, "foobar")
	}
}

func TestFoldXLMFormula_Mixed(t *testing.T) {
	got := foldXLMFormula(`=CHAR(104)&CHAR(116)&"tp://evil.com"`)
	if got != "http://evil.com" {
		t.Errorf("mixed: got %q, want %q", got, "http://evil.com")
	}
}

func TestFoldXLMFormula_CaseInsensitive(t *testing.T) {
	got := foldXLMFormula("=char(65)&Char(66)")
	if got != "AB" {
		t.Errorf("case insensitive CHAR: got %q, want %q", got, "AB")
	}
}

func TestFoldXLMFormula_Empty(t *testing.T) {
	if got := foldXLMFormula(""); got != "" {
		t.Errorf("empty: got %q", got)
	}
}

func TestFoldXLMFormula_PlainString(t *testing.T) {
	got := foldXLMFormula(`="https://evil.com/payload"`)
	if got != "https://evil.com/payload" {
		t.Errorf("plain string: got %q, want %q", got, "https://evil.com/payload")
	}
}

func TestFoldXLMFormula_CellRefSkipped(t *testing.T) {
	// Cell references can't be folded — they should be skipped.
	got := foldXLMFormula("=A1&CHAR(65)&B2")
	// A1 and B2 can't fold; only CHAR(65)=A survives.
	if got != "A" {
		t.Errorf("cell ref skip: got %q, want %q", got, "A")
	}
}

func TestFoldXLMFormula_InvalidCHAR(t *testing.T) {
	// CHAR with value > 127 should be skipped.
	got := foldXLMFormula("=CHAR(200)&CHAR(65)")
	if got != "A" {
		t.Errorf("invalid CHAR: got %q, want %q", got, "A")
	}
}

func TestFoldXLMFormula_ControlCharSkipped(t *testing.T) {
	// CHAR(1) = non-printable, should be skipped.
	got := foldXLMFormula("=CHAR(1)&CHAR(65)")
	if got != "A" {
		t.Errorf("control char: got %q, want %q", got, "A")
	}
}

func TestFoldXLMFormula_EscapedQuotes(t *testing.T) {
	got := foldXLMFormula(`="say ""hello"""`)
	if got != `say "hello"` {
		t.Errorf("escaped quotes: got %q, want %q", got, `say "hello"`)
	}
}

func TestFoldXLMFormula_DangerousFunc(t *testing.T) {
	got := foldXLMFormula(`=EXEC("cmd /c calc")`)
	if !strings.Contains(got, "=EXEC(") {
		t.Errorf("dangerous func not preserved: got %q", got)
	}
	if !strings.Contains(got, "cmd /c calc") {
		t.Errorf("dangerous func args not folded: got %q", got)
	}
}

func TestFoldXLMFormula_TabNewline(t *testing.T) {
	// Tab and newline are allowed.
	got := foldXLMFormula("=CHAR(9)&CHAR(10)")
	if got != "\t\n" {
		t.Errorf("tab/newline: got %q, want %q", got, "\t\n")
	}
}

// --- emitDangerousMarkers unit tests ---

func TestEmitDangerousMarkers(t *testing.T) {
	var out [][]byte
	emitDangerousMarkers("=EXEC(calc)", &out)
	if len(out) != 1 {
		t.Fatalf("expected 1 marker, got %d", len(out))
	}
	if !bytes.Equal(out[0], []byte("XLM-DANGEROUS-FUNC EXEC")) {
		t.Errorf("marker: got %q", out[0])
	}
}

func TestEmitDangerousMarkers_Multiple(t *testing.T) {
	var out [][]byte
	emitDangerousMarkers("=EXEC(x)&=CALL(y)", &out)
	if len(out) != 2 {
		t.Fatalf("expected 2 markers, got %d", len(out))
	}
}

func TestEmitDangerousMarkers_None(t *testing.T) {
	var out [][]byte
	emitDangerousMarkers("just a string", &out)
	if len(out) != 0 {
		t.Fatalf("expected 0 markers, got %d", len(out))
	}
}

// TestEmitDangerousMarkers_DDE covers the DDE command-execution verbs
// (ftab 175 INITIATE / 178 EXECUTE): EXECUTE must fire its own marker and not
// be masked by the =EXEC( substring rule, and INITIATE flags the VBA->DDE bridge.
func TestEmitDangerousMarkers_DDE(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"=EXECUTE(cmd)", "XLM-DANGEROUS-FUNC EXECUTE"},
		{"=INITIATE(srv)", "XLM-DANGEROUS-FUNC INITIATE"},
	} {
		var out [][]byte
		emitDangerousMarkers(tc.in, &out)
		if len(out) != 1 || !bytes.Equal(out[0], []byte(tc.want)) {
			t.Errorf("%q: got %q, want [%q]", tc.in, out, tc.want)
		}
	}
}

// TestEmitDangerousMarkers_ExecNotExecute guards the substring boundary:
// =EXECUTE( must NOT also match the shorter EXEC verb.
func TestEmitDangerousMarkers_ExecNotExecute(t *testing.T) {
	var out [][]byte
	emitDangerousMarkers("=EXECUTE(cmd)", &out)
	for _, m := range out {
		if bytes.Equal(m, []byte("XLM-DANGEROUS-FUNC EXEC")) {
			t.Errorf("EXEC marker wrongly fired on =EXECUTE(")
		}
	}
}

// --- emitFoldedFormula shared-sink tests (XLM-1) ---

func TestEmitFoldedFormula_BelowFloor(t *testing.T) {
	var out [][]byte
	total := 0
	// shorter than minXLMFoldResult — skipped but keep-scanning (true).
	if !emitFoldedFormula("short", &out, &total, true) {
		t.Fatalf("below-floor emit should return true (continue)")
	}
	if len(out) != 0 || total != 0 {
		t.Fatalf("below-floor must not emit: out=%d total=%d", len(out), total)
	}
}

func TestEmitFoldedFormula_Emits(t *testing.T) {
	var out [][]byte
	total := 0
	s := "http://evil.example.com/payload"
	if !emitFoldedFormula(s, &out, &total, false) {
		t.Fatalf("emit should return true")
	}
	if len(out) != 1 || !bytes.Equal(out[0], []byte(s)) {
		t.Fatalf("expected the string emitted, got %v", out)
	}
	if total != len(s) {
		t.Fatalf("total: got %d want %d", total, len(s))
	}
}

func TestEmitFoldedFormula_DangerousFlag(t *testing.T) {
	// checkDangerous=true emits the value AND the marker.
	var withMarker [][]byte
	totalA := 0
	emitFoldedFormula("=EXEC(calc.exe)", &withMarker, &totalA, true)
	if len(withMarker) != 2 {
		t.Fatalf("checkDangerous=true: want value+marker (2), got %d", len(withMarker))
	}
	if !bytes.Equal(withMarker[1], []byte("XLM-DANGEROUS-FUNC EXEC")) {
		t.Errorf("marker: got %q", withMarker[1])
	}

	// checkDangerous=false emits the value only (no marker scan) — <v> behaviour.
	var noMarker [][]byte
	totalB := 0
	emitFoldedFormula("=EXEC(calc.exe)", &noMarker, &totalB, false)
	if len(noMarker) != 1 {
		t.Fatalf("checkDangerous=false: want value only (1), got %d", len(noMarker))
	}
}

func TestEmitFoldedFormula_OutputCap(t *testing.T) {
	var out [][]byte
	total := maxXLMFoldOutputLen - 4 // only 4 bytes of budget left
	s := "this is longer than four bytes"
	if emitFoldedFormula(s, &out, &total, false) {
		t.Fatalf("over-cap emit must return false (stop)")
	}
	if len(out) != 0 {
		t.Fatalf("over-cap must not emit, got %d", len(out))
	}
}

// --- fromOOXMLXLMFold integration tests ---

// makeOOXMLWithXLMFold builds a minimal xlsm zip with a macrosheet containing
// formulas in <f> elements.
func makeOOXMLWithXLMFold(t *testing.T, formulas []string) []byte {
	t.Helper()

	// Build macrosheet XML with formula cells.
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	sb.WriteString(`<sheetData>`)
	for i, f := range formulas {
		sb.WriteString(`<row r="`)
		sb.WriteString(strings.Repeat("0", 0)) // row number not critical
		sb.WriteString(`"><c r="A`)
		sb.WriteString(strings.Repeat("0", 0))
		// Use simple row numbering.
		sb.WriteString(`"><f>`)
		// Escape XML special chars in formula.
		var esc strings.Builder
		_ = xml.EscapeText(&esc, []byte(f))
		sb.WriteString(esc.String())
		sb.WriteString(`</f></c></row>`)
		_ = i
	}
	sb.WriteString(`</sheetData></worksheet>`)

	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	addZipEntry(t, zw, "xl/macrosheets/sheet1.xml", sb.String())
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestFromOOXMLXLMFold_Basic(t *testing.T) {
	formulas := []string{
		`=CHAR(104)&CHAR(116)&CHAR(116)&CHAR(112)&CHAR(115)&CHAR(58)&CHAR(47)&CHAR(47)&"evil.com"`,
	}
	buf := makeOOXMLWithXLMFold(t, formulas)

	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLXLMFold(zr, &out, time.Time{})

	joined := bytes.Join(out, []byte("\n"))
	if !bytes.Contains(joined, []byte("https://evil.com")) {
		t.Errorf("expected folded URL; streams=%d joined=%q", len(out), joined)
	}
}

func TestFromOOXMLXLMFold_DangerousFunc(t *testing.T) {
	formulas := []string{
		`=EXEC(CHAR(99)&CHAR(97)&CHAR(108)&CHAR(99)&CHAR(46)&CHAR(101)&CHAR(120)&CHAR(101))`,
	}
	buf := makeOOXMLWithXLMFold(t, formulas)

	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLXLMFold(zr, &out, time.Time{})

	joined := bytes.Join(out, []byte("\n"))
	if !bytes.Contains(joined, []byte("XLM-DANGEROUS-FUNC EXEC")) {
		t.Errorf("expected EXEC marker; streams=%d joined=%q", len(out), joined)
	}
	if !bytes.Contains(joined, []byte("calc.exe")) {
		t.Errorf("expected folded calc.exe; streams=%d joined=%q", len(out), joined)
	}
}

func TestFromOOXMLXLMFold_NoMacrosheets(t *testing.T) {
	// Zip with no xl/macrosheets/ — should be a no-op.
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	addZipEntry(t, zw, "xl/worksheets/sheet1.xml", `<worksheet/>`)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLXLMFold(zr, &out, time.Time{})
	if len(out) != 0 {
		t.Errorf("no macrosheets: expected 0 streams, got %d", len(out))
	}
}

func TestFromOOXMLXLMFold_ShortResultFiltered(t *testing.T) {
	// Formula that folds to < 8 bytes should be filtered (no real emulator/interpreter output).
	// The emulator always emits the depth marker (D8), so we expect exactly 1 stream.
	formulas := []string{`=CHAR(65)&CHAR(66)`} // "AB" — only 2 bytes
	buf := makeOOXMLWithXLMFold(t, formulas)

	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLXLMFold(zr, &out, time.Time{})
	// Exactly 1 stream: the XLM-EMUL-DEPTH marker (emitted always); no real formula output.
	if len(out) != 1 {
		t.Errorf("expected 1 stream (depth marker only), got %d", len(out))
	}
	if len(out) == 1 && !bytes.Contains(out[0], []byte("XLM-EMUL-DEPTH")) {
		t.Errorf("expected depth marker in the single stream, got %q", out[0])
	}
}

func TestFromOOXMLXLMFold_FormulaCap(t *testing.T) {
	// Exceed maxXLMFoldFormulas — should stop processing.
	formulas := make([]string, maxXLMFoldFormulas+10)
	for i := range formulas {
		formulas[i] = `="AAAAAAAA"` // 8 bytes, meets minimum
	}
	buf := makeOOXMLWithXLMFold(t, formulas)

	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLXLMFold(zr, &out, time.Time{})
	if len(out) > maxXLMFoldFormulas {
		t.Errorf("formula cap exceeded: got %d streams, max %d", len(out), maxXLMFoldFormulas)
	}
}

func TestFromOOXMLXLMFold_Deadline(t *testing.T) {
	formulas := []string{
		`=CHAR(104)&CHAR(116)&CHAR(116)&CHAR(112)&CHAR(115)&CHAR(58)&CHAR(47)&CHAR(47)&"evil.com"`,
	}
	buf := makeOOXMLWithXLMFold(t, formulas)

	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	past := time.Now().Add(-time.Second)
	fromOOXMLXLMFold(zr, &out, past)
	if len(out) != 0 {
		t.Errorf("expired deadline: expected 0 streams, got %d", len(out))
	}
}

func TestFromOOXMLXLMFold_TooLongFormula(t *testing.T) {
	// Formula exceeding maxXLMFoldFormulaLen should be skipped.
	long := "=" + strings.Repeat(`CHAR(65)&`, maxXLMFoldFormulaLen/9+1)
	formulas := []string{long}
	buf := makeOOXMLWithXLMFold(t, formulas)

	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLXLMFold(zr, &out, time.Time{})
	if len(out) != 0 {
		t.Errorf("too-long formula not skipped: got %d streams", len(out))
	}
}

// --- Integration: full Extract pipeline ---

func TestExtractXLMFold_Integration(t *testing.T) {
	formulas := []string{
		`=CHAR(104)&CHAR(116)&CHAR(116)&CHAR(112)&CHAR(115)&CHAR(58)&CHAR(47)&CHAR(47)&"evil.com"`,
	}
	// Build a full OOXML zip that Extract will recognise.
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	// Need [Content_Types].xml for OOXML detection.
	addZipEntry(t, zw, "[Content_Types].xml", `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`)

	// Build macrosheet.
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for _, f := range formulas {
		sb.WriteString(`<row><c><f>`)
		var esc strings.Builder
		_ = xml.EscapeText(&esc, []byte(f))
		sb.WriteString(esc.String())
		sb.WriteString(`</f></c></row>`)
	}
	sb.WriteString(`</sheetData></worksheet>`)
	addZipEntry(t, zw, "xl/macrosheets/sheet1.xml", sb.String())
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	res := Extract(b.Bytes(), time.Time{})
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("https://evil.com")) {
		t.Errorf("Extract integration: expected folded URL in streams; got %q", joined)
	}
	if !res.HasXLMFold {
		t.Error("Extract integration: HasXLMFold not set")
	}
}

func TestFromOOXMLXLMFold_ValueElement(t *testing.T) {
	// Test that <v> elements are also captured.
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	sb.WriteString(`<row><c><v>https://evil.com/payload</v></c></row>`)
	sb.WriteString(`</sheetData></worksheet>`)

	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	addZipEntry(t, zw, "xl/macrosheets/sheet1.xml", sb.String())
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLXLMFold(zr, &out, time.Time{})

	joined := bytes.Join(out, []byte("\n"))
	if !bytes.Contains(joined, []byte("https://evil.com/payload")) {
		t.Errorf("value element not captured; got %q", joined)
	}
}

// TestFoldXLMFormulaDeepNestingTerminates guards the foldXLMFormula↔
// foldFunctionCall mutual recursion (STAB-1): a pathologically nested XLM
// formula must terminate without overflowing the stack (a fatal, unrecoverable
// crash). At maxXLMFoldDepth the inner args are kept verbatim and a partial
// result is returned.
func TestFoldXLMFormulaDeepNestingTerminates(t *testing.T) {
	// Build =EXEC(EXEC(EXEC(…CHAR(65)…))) far deeper than maxXLMFoldDepth.
	const nest = maxXLMFoldDepth * 8
	formula := "CHAR(65)"
	for i := 0; i < nest; i++ {
		formula = "EXEC(" + formula + ")"
	}
	formula = "=" + formula

	done := make(chan string, 1)
	go func() { done <- foldXLMFormula(formula) }()

	select {
	case got := <-done:
		// Must still recognise the outermost dangerous function.
		if !strings.Contains(strings.ToUpper(got), "EXEC(") {
			t.Errorf("folded result lost EXEC wrapper: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("foldXLMFormula did not terminate on deeply nested input")
	}
}

// TestFoldXLMFormulaDeadlineBails verifies STAB-2: an already-expired deadline
// short-circuits the fold (at entry) instead of processing the whole formula.
func TestFoldXLMFormulaDeadlineBails(t *testing.T) {
	past := time.Now().Add(-time.Second)
	if got := foldXLMFormulaDepth("=CHAR(65)&CHAR(66)&CHAR(67)", 0, past); got != "" {
		t.Errorf("expired deadline should bail with empty result, got %q", got)
	}
	// Zero deadline (the foldXLMFormula wrapper case) never expires.
	if got := foldXLMFormulaDepth("=CHAR(65)&CHAR(66)", 0, time.Time{}); got != "AB" {
		t.Errorf("zero deadline should fold normally, got %q", got)
	}
}

// TestFoldFunctionCallDepthCap verifies the cap keeps args verbatim instead of
// recursing once maxXLMFoldDepth is reached.
func TestFoldFunctionCallDepthCap(t *testing.T) {
	got := foldFunctionCall("EXEC(CHAR(65))", maxXLMFoldDepth, time.Time{})
	if got != "=EXEC(CHAR(65))" {
		t.Errorf("at depth cap want verbatim args, got %q", got)
	}
	// Below the cap it folds CHAR(65) -> A.
	got = foldFunctionCall("EXEC(CHAR(65))", 0, time.Time{})
	if got != "=EXEC(A)" {
		t.Errorf("below cap want folded args, got %q", got)
	}
}
