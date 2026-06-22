package extract

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestBiffCellToA1
// ---------------------------------------------------------------------------
func TestBiffCellToA1(t *testing.T) {
	tests := []struct {
		row, col uint16
		want     string
	}{
		{0, 0, "A1"},
		{0, 25, "Z1"},
		{0, 26, "AA1"},
		{9999, 0, "A10000"},
		{0, 0x4000, "A1"}, // rel-ref bit 14 masked → col becomes 0 → A, row 0 → 1
	}
	for _, tc := range tests {
		got := biffCellToA1(tc.row, tc.col)
		if got != tc.want {
			t.Errorf("biffCellToA1(%d, 0x%04x) = %q, want %q", tc.row, tc.col, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TestParseBIFF8FormulaWithRefs_NoRef
// ptgStr token with 3-byte payload ("foo") — no ref, same as parseBIFF8Formula.
// ---------------------------------------------------------------------------
func TestParseBIFF8FormulaWithRefs_NoRef(t *testing.T) {
	// ptgStr: token=0x17, cch=3, fHighByte=0x00, 'f','o','o'
	data := []byte{0x17, 3, 0x00, 'f', 'o', 'o'}
	got := parseBIFF8FormulaWithRefs(data)
	if got != "foo" {
		t.Errorf("parseBIFF8FormulaWithRefs ptgStr: got %q, want %q", got, "foo")
	}
}

// ---------------------------------------------------------------------------
// TestParseBIFF8FormulaWithRefs_WithRef
// ptgRef at row=0, col=0 → [[REF:A1]] placeholder.
// ---------------------------------------------------------------------------
func TestParseBIFF8FormulaWithRefs_WithRef(t *testing.T) {
	// ptgRef (0x24): token + row(uint16 LE) + col(uint16 LE)
	data := []byte{0x24, 0, 0, 0, 0}
	got := parseBIFF8FormulaWithRefs(data)
	if !strings.Contains(got, "[[REF:A1]]") {
		t.Errorf("parseBIFF8FormulaWithRefs ptgRef: got %q, want [[REF:A1]] in result", got)
	}
}

// ---------------------------------------------------------------------------
// TestParseBIFF8FormulaWithRefs_PtgRef3d
// ptgRef3d (0x3A) still pushes "" (unchanged from base parser).
// ---------------------------------------------------------------------------
func TestParseBIFF8FormulaWithRefs_PtgRef3d(t *testing.T) {
	// ptgRef3d: 1-byte token + 6-byte payload
	data := []byte{0x3A, 0, 0, 0, 0, 0, 0}
	got := parseBIFF8FormulaWithRefs(data)
	if got != "" {
		t.Errorf("parseBIFF8FormulaWithRefs ptgRef3d: got %q, want %q", got, "")
	}
}

// ---------------------------------------------------------------------------
// TestResolveRefPlaceholders_Found
// Cell A1 has value "calc.exe"; placeholder resolves to it.
// ---------------------------------------------------------------------------
func TestResolveRefPlaceholders_Found(t *testing.T) {
	var out [][]byte
	total := 0
	m := newMachine(&out, &total, time.Time{})
	m.setCell("Sheet1", "A1", "", "calc.exe")
	got := resolveRefPlaceholders(m, "Sheet1", "[[REF:A1]]")
	if got != "calc.exe" {
		t.Errorf("resolveRefPlaceholders found: got %q, want %q", got, "calc.exe")
	}
}

// ---------------------------------------------------------------------------
// TestResolveRefPlaceholders_NotFound
// No A1 cell — placeholder left unchanged.
// ---------------------------------------------------------------------------
func TestResolveRefPlaceholders_NotFound(t *testing.T) {
	var out [][]byte
	total := 0
	m := newMachine(&out, &total, time.Time{})
	got := resolveRefPlaceholders(m, "Sheet1", "[[REF:B99]]")
	if got != "[[REF:B99]]" {
		t.Errorf("resolveRefPlaceholders not found: got %q, want %q", got, "[[REF:B99]]")
	}
}

// ---------------------------------------------------------------------------
// TestResolveRefPlaceholders_Mixed
// Known ref resolves; unknown ref left as-is.
// ---------------------------------------------------------------------------
func TestResolveRefPlaceholders_Mixed(t *testing.T) {
	var out [][]byte
	total := 0
	m := newMachine(&out, &total, time.Time{})
	m.setCell("Sheet1", "A1", "", "calc.exe")

	// Known ref embedded in surrounding text.
	got := resolveRefPlaceholders(m, "Sheet1", "run[[REF:A1]]end")
	if got != "runcalc.exeend" {
		t.Errorf("resolveRefPlaceholders mixed known: got %q, want %q", got, "runcalc.exeend")
	}

	// Unknown ref left as-is.
	got2 := resolveRefPlaceholders(m, "Sheet1", "x[[REF:Z99]]y")
	if got2 != "x[[REF:Z99]]y" {
		t.Errorf("resolveRefPlaceholders mixed unknown: got %q, want %q", got2, "x[[REF:Z99]]y")
	}
}

// ---------------------------------------------------------------------------
// TestStripRefPlaceholders
// [[REF:...]] tokens removed; surrounding text preserved.
// ---------------------------------------------------------------------------
func TestStripRefPlaceholders(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"[[REF:A1]]", ""},
		{"prefix[[REF:ZZ123]]suffix", "prefixsuffix"},
		{"no refs here", "no refs here"},
	}
	for _, tc := range tests {
		got := stripRefPlaceholders(tc.in)
		if got != tc.want {
			t.Errorf("stripRefPlaceholders(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TestEmulateXLMBIFF_EmulatorProducesOutput
// A cell with =EXEC("calc.exe") run through emulateXLMCells must produce
// at least one stream containing "calc.exe".
// ---------------------------------------------------------------------------
func TestEmulateXLMBIFF_EmulatorProducesOutput(t *testing.T) {
	cells := []xlmCell{
		{coord: "A1", formula: `=EXEC("calc.exe")`},
	}
	var out [][]byte
	total := 0
	emulateXLMCells(cells, &out, &total, time.Time{})
	joined := bytes.Join(out, []byte("\n"))
	if !bytes.Contains(joined, []byte("calc.exe")) {
		t.Errorf("expected calc.exe in output; got %q", joined)
	}
}

// ---------------------------------------------------------------------------
// TestVersionContainsXLMEmulBiff
// Version constant must carry +xlmemulbiff tag (D7 sentinel).
// ---------------------------------------------------------------------------
func TestVersionContainsXLMEmulBiff(t *testing.T) {
	if !strings.Contains(Version, "+xlmemulbiff") {
		t.Errorf("Version %q does not contain +xlmemulbiff", Version)
	}
}
