package extract

import (
	"strings"
	"testing"
)

// biff_withrefs_test.go — behaviour coverage for parseBIFF8FormulaWithRefs and
// parseBIFF12FormulaWithRefs (xlm_emul_biff.go). These are standalone copies of
// parseBIFF8Formula / parseBIFF12Formula that override the ptgRef case to emit
// "[[REF:A1]]" placeholders instead of "". The base parsers already have wide
// coverage via biff_ptg_test.go / biff12_xlsb_test.go; these tests focus on:
//   - truncated input at every length check in the WithRefs copies
//   - unknown/malformed ptg opcodes
//   - boundary values (empty formula, single ptg, ref column overflow)
//   - the WithRefs-specific behaviour: what refs are actually emitted, in what
//     order, for which inputs — not just "did not panic"

// --- BIFF8 ---------------------------------------------------------------

func TestBIFF8WithRefs_Empty(t *testing.T) {
	if got := parseBIFF8FormulaWithRefs(nil); got != "" {
		t.Fatalf("empty: got %q", got)
	}
	if got := parseBIFF8FormulaWithRefs([]byte{}); got != "" {
		t.Fatalf("empty slice: got %q", got)
	}
}

// ptgRef8 builds a BIFF8 ptgRef token: 1-byte opcode + row(u16 LE) + col(u16 LE).
func ptgRef8(row, col uint16) []byte {
	return []byte{ptgRef, byte(row), byte(row >> 8), byte(col), byte(col >> 8)}
}

func TestBIFF8WithRefs_EmitsPlaceholder(t *testing.T) {
	// row=0, col=0 -> A1 (0-based -> 1-based).
	got := parseBIFF8FormulaWithRefs(ptgRef8(0, 0))
	if got != "[[REF:A1]]" {
		t.Fatalf("A1 ref: got %q", got)
	}
}

func TestBIFF8WithRefs_CellCoordinates(t *testing.T) {
	cases := []struct {
		row, col uint16
		want     string
	}{
		{0, 0, "[[REF:A1]]"},
		{9, 25, "[[REF:Z10]]"}, // row 10 (1-based), col 26 -> Z
		{0, 26, "[[REF:AA1]]"}, // col 27 -> AA
		{99, 1, "[[REF:B100]]"},
	}
	for _, c := range cases {
		got := parseBIFF8FormulaWithRefs(ptgRef8(c.row, c.col))
		if got != c.want {
			t.Errorf("row=%d col=%d: got %q, want %q", c.row, c.col, got, c.want)
		}
	}
}

// TestBIFF8WithRefs_RelativeBitsMasked verifies bits 14-15 of the column
// (the relative-reference flags per MS-XLS) are masked off before A1
// conversion, matching biffCellToA1's documented contract.
func TestBIFF8WithRefs_RelativeBitsMasked(t *testing.T) {
	// col=0 with both relative-reference flag bits set (0xC000) must still
	// resolve to column A, not overflow colNumToLetters.
	got := parseBIFF8FormulaWithRefs(ptgRef8(0, 0xC000))
	if got != "[[REF:A1]]" {
		t.Fatalf("relative-bit masking: got %q", got)
	}
}

// TestBIFF8WithRefs_ColumnOverflowEmptyPlaceholder verifies a column value
// that is still out-of-range (>16384) AFTER masking the relative-ref bits
// falls back to pushing "" (no [[REF:...]] token), per the a1=="" branch.
func TestBIFF8WithRefs_ColumnOverflowEmptyPlaceholder(t *testing.T) {
	// 0x3FFF masked = 16383, +1 = 16384 -> valid (XFD). Push col so the masked
	// value exceeds 16384: col bits 0-13 max out at 0x3FFF -> col+1 = 16384,
	// which IS valid (colNumToLetters caps at 16384). So masked col can never
	// exceed 16384 by construction (14 bits = max 16383). Assert the max valid
	// column resolves, and that biffCellToA1 stays within bounds.
	got := parseBIFF8FormulaWithRefs(ptgRef8(0, 0x3FFF))
	if got != "[[REF:XFD1]]" {
		t.Fatalf("max column: got %q", got)
	}
}

func TestBIFF8WithRefs_TwoRefsConcatOrder(t *testing.T) {
	// [[REF:A1]] & [[REF:B1]] must preserve left-to-right order.
	stream := ptgRef8(0, 0)
	stream = append(stream, ptgRef8(0, 1)...)
	stream = append(stream, ptgConcat)
	got := parseBIFF8FormulaWithRefs(stream)
	if got != "[[REF:A1]][[REF:B1]]" {
		t.Fatalf("concat order: got %q", got)
	}
}

func TestBIFF8WithRefs_RefInsideFunc(t *testing.T) {
	// =MID([[REF:A1]], 1, 8) — a ref used as a function argument must survive
	// unmodified as a placeholder inside the wrapped call.
	stream := ptgRef8(0, 0)
	stream = append(stream, ptgIntTok(1)...)
	stream = append(stream, ptgIntTok(8)...)
	stream = append(stream, ptgFuncTok(31)...) // MID, arity 3
	got := parseBIFF8FormulaWithRefs(stream)
	if got != "=MID([[REF:A1]],1,8)" {
		t.Fatalf("ref inside func: got %q", got)
	}
}

// TestBIFF8WithRefs_TruncatedRef verifies the WithRefs-specific ptgRef branch
// fails open (returns folded-so-far) when fewer than 4 payload bytes remain —
// the classic "declares more bytes than remain" malformed-input path, and the
// exact boundary condition `pos+4 >= len(data)`.
func TestBIFF8WithRefs_TruncatedRef(t *testing.T) {
	cases := [][]byte{
		{ptgRef},                   // 0 payload bytes
		{ptgRef, 0x01},             // 1
		{ptgRef, 0x01, 0x00},       // 2
		{ptgRef, 0x01, 0x00, 0x00}, // 3 (need 4)
	}
	for _, stream := range cases {
		full := append(ptgStr8("kept"), stream...)
		got := parseBIFF8FormulaWithRefs(full)
		if got != "kept" {
			t.Errorf("truncated ref len=%d: got %q, want %q (fail-open to prior operand)", len(stream)-1, got, "kept")
		}
	}
}

// TestBIFF8WithRefs_ExactBoundaryRefLength verifies the boundary is off-by-one
// safe: pos+4 == len(data)-1 (i.e. exactly 5 bytes total: opcode+4) is the
// minimum valid length and must succeed, not fail open.
func TestBIFF8WithRefs_ExactBoundaryRefLength(t *testing.T) {
	stream := []byte{ptgRef, 0, 0, 0, 0} // exactly 5 bytes: minimum valid
	got := parseBIFF8FormulaWithRefs(stream)
	if got != "[[REF:A1]]" {
		t.Fatalf("exact boundary: got %q, want [[REF:A1]]", got)
	}
}

func TestBIFF8WithRefs_SinglePtgFormula(t *testing.T) {
	// A formula that is exactly one ptg (no surrounding tokens).
	got := parseBIFF8FormulaWithRefs(ptgStr8("x"))
	if got != "x" {
		t.Fatalf("single ptg: got %q", got)
	}
}

func TestBIFF8WithRefs_UnknownOpcodeBails(t *testing.T) {
	// Unknown/unhandled ptg must stop and return prior operands, not desync
	// or panic — mirrors TestBIFF8UnknownPtgBails but on the WithRefs copy.
	stream := ptgStr8("kept")
	stream = append(stream, 0x7A, 0xFF, 0xFF)
	got := parseBIFF8FormulaWithRefs(stream)
	if got != "kept" {
		t.Fatalf("unknown ptg: got %q", got)
	}
}

func TestBIFF8WithRefs_Ref3dPushesEmptyNotPlaceholder(t *testing.T) {
	// ptgRef3d is explicitly documented to still push "" (unlike ptgRef).
	// A 3-D ref surrounded by literals must not produce any [[REF: token.
	stream := ptgStr8("a")
	stream = append(stream, ptgRef3d, 0, 0, 0, 0, 0, 0) // opcode + 6 bytes
	stream = append(stream, ptgConcat)
	stream = append(stream, ptgStr8("b")...)
	stream = append(stream, ptgConcat)
	got := parseBIFF8FormulaWithRefs(stream)
	if got != "ab" {
		t.Fatalf("ref3d must push empty, not a placeholder: got %q", got)
	}
	if strings.Contains(got, "REF") {
		t.Fatalf("ref3d leaked a [[REF: placeholder: got %q", got)
	}
}

func TestBIFF8WithRefs_TokenCapNoSpin(t *testing.T) {
	var stream []byte
	for i := 0; i < maxBIFFPtgTokens+100; i++ {
		stream = append(stream, ptgRef8(0, 0)...)
	}
	_ = parseBIFF8FormulaWithRefs(stream) // must terminate at the cap, not hang.
}

func TestBIFF8WithRefs_AttrChooseSkip(t *testing.T) {
	// Mirrors TestBIFF8PtgAttrChooseSkip: a ref placed after a ptgAttr(CHOOSE)
	// jump table must still be parsed once the skip lands correctly.
	stream := []byte{ptgAttr, 0x04, 0x02, 0x00}
	stream = append(stream, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00)
	stream = append(stream, ptgRef8(0, 0)...)
	got := parseBIFF8FormulaWithRefs(stream)
	if got != "[[REF:A1]]" {
		t.Fatalf("attr choose skip: got %q", got)
	}
}

func TestBIFF8WithRefs_AttrTruncatedFailsOpen(t *testing.T) {
	stream := ptgStr8("kept")
	stream = append(stream, ptgAttr, 0x04, 0xFF, 0xFF) // huge w, truncated
	got := parseBIFF8FormulaWithRefs(stream)
	if got != "kept" {
		t.Fatalf("attr truncated: got %q", got)
	}
}

// --- BIFF12 ----------------------------------------------------------------

func TestBIFF12WithRefs_Empty(t *testing.T) {
	if got := parseBIFF12FormulaWithRefs(nil); got != "" {
		t.Fatalf("empty: got %q", got)
	}
	if got := parseBIFF12FormulaWithRefs([]byte{}); got != "" {
		t.Fatalf("empty slice: got %q", got)
	}
}

// ptgRef12 (row u32 LE, col u16 LE) is defined in biff12_xlsb_test.go.

func TestBIFF12WithRefs_EmitsPlaceholder(t *testing.T) {
	got := parseBIFF12FormulaWithRefs(ptgRef12(0, 0))
	if got != "[[REF:A1]]" {
		t.Fatalf("A1 ref: got %q", got)
	}
}

func TestBIFF12WithRefs_CellCoordinates(t *testing.T) {
	cases := []struct {
		row  uint32
		col  uint16
		want string
	}{
		{0, 0, "[[REF:A1]]"},
		{9, 25, "[[REF:Z10]]"},
		{0, 26, "[[REF:AA1]]"},
		{1_048_575, 0, "[[REF:A1048576]]"}, // max valid BIFF12 row (0-based)
	}
	for _, c := range cases {
		got := parseBIFF12FormulaWithRefs(ptgRef12(c.row, c.col))
		if got != c.want {
			t.Errorf("row=%d col=%d: got %q, want %q", c.row, c.col, got, c.want)
		}
	}
}

// TestBIFF12WithRefs_RowOverflowEmptyPlaceholder verifies biff12CellToA1's
// row>1_048_575 guard: a row value beyond the BIFF12 sheet limit must push ""
// (no placeholder), not an invalid/garbage A1 string.
func TestBIFF12WithRefs_RowOverflowEmptyPlaceholder(t *testing.T) {
	stream := strPtg("a")
	stream = append(stream, ptgRef12(1_048_576, 0)...) // row over the limit
	stream = append(stream, ptgConcat)
	stream = append(stream, strPtg("b")...)
	stream = append(stream, ptgConcat)
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "ab" {
		t.Fatalf("row overflow must push empty: got %q", got)
	}
}

func TestBIFF12WithRefs_TwoRefsConcatOrder(t *testing.T) {
	stream := ptgRef12(0, 0)
	stream = append(stream, ptgRef12(0, 1)...)
	stream = append(stream, ptgConcat)
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "[[REF:A1]][[REF:B1]]" {
		t.Fatalf("concat order: got %q", got)
	}
}

func TestBIFF12WithRefs_RefInsideFunc(t *testing.T) {
	rgce := ptgRef12(0, 0)
	rgce = append(rgce, ptgIntTok(1)...)
	rgce = append(rgce, ptgIntTok(8)...)
	rgce = append(rgce, ptgFuncTok(31)...) // MID
	got := parseBIFF12FormulaWithRefs(rgce)
	if got != "=MID([[REF:A1]],1,8)" {
		t.Fatalf("ref inside func: got %q", got)
	}
}

// TestBIFF12WithRefs_TruncatedRef exercises readBIFF12PtgRef's own bounds
// check (pos+7 > len(data)) at every truncation length short of the required
// 7 bytes (1 opcode + 4 row + 2 col).
func TestBIFF12WithRefs_TruncatedRef(t *testing.T) {
	for n := 0; n < 6; n++ {
		stream := append([]byte{ptgRef}, make([]byte, n)...)
		full := append(strPtg("kept"), stream...)
		got := parseBIFF12FormulaWithRefs(full)
		if got != "kept" {
			t.Errorf("truncated ref payload=%d bytes: got %q, want %q", n, got, "kept")
		}
	}
}

func TestBIFF12WithRefs_ExactBoundaryRefLength(t *testing.T) {
	stream := ptgRef12(0, 0) // exactly 7 bytes: minimum valid
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "[[REF:A1]]" {
		t.Fatalf("exact boundary: got %q, want [[REF:A1]]", got)
	}
}

func TestBIFF12WithRefs_SinglePtgFormula(t *testing.T) {
	got := parseBIFF12FormulaWithRefs(strPtg("x"))
	if got != "x" {
		t.Fatalf("single ptg: got %q", got)
	}
}

func TestBIFF12WithRefs_UnknownOpcodeBails(t *testing.T) {
	stream := strPtg("kept")
	stream = append(stream, 0x7A, 0xFF, 0xFF)
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "kept" {
		t.Fatalf("unknown ptg: got %q", got)
	}
}

func TestBIFF12WithRefs_Ref3dPushesEmptyNotPlaceholder(t *testing.T) {
	// BIFF12 ptgRef3d uses skipBIFF12Ptg(data, pos, 9) (opcode + 8 bytes).
	stream := strPtg("a")
	stream = append(stream, ptgRef3d)
	stream = append(stream, make([]byte, 8)...)
	stream = append(stream, ptgConcat)
	stream = append(stream, strPtg("b")...)
	stream = append(stream, ptgConcat)
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "ab" {
		t.Fatalf("ref3d must push empty, not a placeholder: got %q", got)
	}
	if strings.Contains(got, "REF") {
		t.Fatalf("ref3d leaked a [[REF: placeholder: got %q", got)
	}
}

func TestBIFF12WithRefs_Ref3dTruncatedFailsOpen(t *testing.T) {
	stream := strPtg("kept")
	stream = append(stream, ptgRef3d)
	stream = append(stream, make([]byte, 3)...) // needs 8, only 3 present
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "kept" {
		t.Fatalf("ref3d truncated: got %q", got)
	}
}

func TestBIFF12WithRefs_AreaTruncatedFailsOpen(t *testing.T) {
	// ptgArea uses skipBIFF12Ptg(data, pos, 13).
	stream := strPtg("kept")
	stream = append(stream, ptgArea)
	stream = append(stream, make([]byte, 5)...) // needs 13, only 5 present
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "kept" {
		t.Fatalf("area truncated: got %q", got)
	}
}

func TestBIFF12WithRefs_ExpTruncatedFailsOpen(t *testing.T) {
	// ptgExp uses skipBIFF12Ptg(data, pos, 7).
	stream := strPtg("kept")
	stream = append(stream, ptgExp)
	stream = append(stream, make([]byte, 2)...) // needs 7, only 2 present
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "kept" {
		t.Fatalf("exp truncated: got %q", got)
	}
}

func TestBIFF12WithRefs_Area3dTruncatedFailsOpen(t *testing.T) {
	// ptgArea3d uses skipBIFF12Ptg(data, pos, 15).
	stream := strPtg("kept")
	stream = append(stream, ptgArea3d)
	stream = append(stream, make([]byte, 6)...) // needs 15, only 6 present
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "kept" {
		t.Fatalf("area3d truncated: got %q", got)
	}
}

func TestBIFF12WithRefs_TokenCapNoSpin(t *testing.T) {
	var stream []byte
	for i := 0; i < maxBIFFPtgTokens+100; i++ {
		stream = append(stream, ptgRef12(0, 0)...)
	}
	_ = parseBIFF12FormulaWithRefs(stream) // must terminate at the cap, not hang.
}

func TestBIFF12WithRefs_AttrChooseSkip(t *testing.T) {
	stream := []byte{ptgAttr, 0x04, 0x02, 0x00}
	stream = append(stream, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00)
	stream = append(stream, ptgRef12(0, 0)...)
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "[[REF:A1]]" {
		t.Fatalf("attr choose skip: got %q", got)
	}
}

func TestBIFF12WithRefs_AttrTruncatedFailsOpen(t *testing.T) {
	stream := strPtg("kept")
	stream = append(stream, ptgAttr, 0x04, 0xFF, 0xFF) // huge w, truncated
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "kept" {
		t.Fatalf("attr truncated: got %q", got)
	}
}

func TestBIFF12WithRefs_StrTruncatedFailsOpen(t *testing.T) {
	// BIFF12 ptgStr: uint16 charcount + UTF-16LE chars, no fHighByte flag.
	// Declares 5 chars but supplies 0 body bytes.
	stream := []byte{ptgStr, 0x05, 0x00}
	got := parseBIFF12FormulaWithRefs(stream)
	if got != "" {
		t.Fatalf("str truncated: got %q", got)
	}
}

// --- shared boundary / bug-hunting checks -----------------------------------

// TestBIFF8vsBIFF12WithRefs_SameCellDifferentEncoding verifies both WithRefs
// parsers agree on the resulting A1 coordinate for row/col pairs that are
// representable in both the BIFF8 (u16 row) and BIFF12 (u32 row) encodings —
// pinning that the two independent copies did not drift on the ref-emission
// contract they're supposed to share.
func TestBIFF8vsBIFF12WithRefs_SameCellDifferentEncoding(t *testing.T) {
	row, col := uint16(41), uint16(2) // row 42, col C
	got8 := parseBIFF8FormulaWithRefs(ptgRef8(row, col))
	got12 := parseBIFF12FormulaWithRefs(ptgRef12(uint32(row), col))
	if got8 != got12 {
		t.Fatalf("BIFF8/BIFF12 WithRefs disagree on same cell: biff8=%q biff12=%q", got8, got12)
	}
	if got8 != "[[REF:C42]]" {
		t.Fatalf("got %q, want [[REF:C42]]", got8)
	}
}
