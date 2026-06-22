package extract

import (
	"strings"
	"testing"
)

// ptg stream builders ---------------------------------------------------------

func ptgStr8(s string) []byte {
	b := []byte{ptgStr, byte(len(s)), 0x00}
	return append(b, []byte(s)...)
}

func ptgStr16(s string) []byte {
	out := []byte{ptgStr, byte(len([]rune(s))), 0x01}
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func ptgIntTok(v uint16) []byte {
	return []byte{ptgInt, byte(v), byte(v >> 8)}
}

func ptgFuncTok(id uint16) []byte {
	return []byte{ptgFunc, byte(id), byte(id >> 8)}
}

func ptgFuncVarTok(argc byte, id uint16) []byte {
	return []byte{ptgFuncVar, argc, byte(id), byte(id >> 8)}
}

// tests -----------------------------------------------------------------------

func TestBIFF8Empty(t *testing.T) {
	if got := parseBIFF8Formula(nil); got != "" {
		t.Fatalf("empty: got %q", got)
	}
}

func TestBIFF8Str8Bit(t *testing.T) {
	got := parseBIFF8Formula(ptgStr8("http://evil.com"))
	if got != "http://evil.com" {
		t.Fatalf("str8: got %q", got)
	}
}

func TestBIFF8Str16(t *testing.T) {
	got := parseBIFF8Formula(ptgStr16("hello"))
	if got != "hello" {
		t.Fatalf("str16: got %q", got)
	}
}

func TestBIFF8ConcatReassembly(t *testing.T) {
	// "http" & "://evil.com"  → push "http", push "://evil.com", concat
	stream := append(ptgStr8("http"), ptgStr8("://evil.com")...)
	stream = append(stream, ptgConcat)
	got := parseBIFF8Formula(stream)
	if got != "http://evil.com" {
		t.Fatalf("concat: got %q", got)
	}
}

func TestBIFF8ConcatOrder(t *testing.T) {
	// Verify left/right operand order: "AB" not "BA".
	stream := append(ptgStr8("A"), ptgStr8("B")...)
	stream = append(stream, ptgConcat)
	if got := parseBIFF8Formula(stream); got != "AB" {
		t.Fatalf("concat order: got %q", got)
	}
}

func TestBIFF8Int(t *testing.T) {
	if got := parseBIFF8Formula(ptgIntTok(12345)); got != "12345" {
		t.Fatalf("int: got %q", got)
	}
}

func TestBIFF8FuncExecMarkerShape(t *testing.T) {
	// push "calc.exe", EXEC (fixed-argc, id 110) → "=EXEC(calc.exe)"
	stream := append(ptgStr8("calc.exe"), ptgFuncTok(110)...)
	got := parseBIFF8Formula(stream)
	if got != "=EXEC(calc.exe)" {
		t.Fatalf("exec wrap: got %q", got)
	}
	// Confirm the shared dangerous-marker sink would fire on this shape.
	var out [][]byte
	emitDangerousMarkers(got, &out)
	if len(out) != 1 || string(out[0]) != "XLM-DANGEROUS-FUNC EXEC" {
		t.Fatalf("dangerous marker not emitted: %v", out)
	}
}

func TestBIFF8FuncVarMultiArg(t *testing.T) {
	// CALL (id 150) with 2 args: push "kernel32", push "VirtualAlloc", FuncVar argc=2.
	stream := append(ptgStr8("kernel32"), ptgStr8("VirtualAlloc")...)
	stream = append(stream, ptgFuncVarTok(2, 150)...)
	got := parseBIFF8Formula(stream)
	if got != "=CALL(kernel32,VirtualAlloc)" {
		t.Fatalf("funcvar args: got %q", got)
	}
}

func TestBIFF8FuncVarUserDefinedTrailer(t *testing.T) {
	// USERDEFINED (0x806D) carries a 9-byte trailer that must be skipped, else
	// the following token desyncs. argc=0, then 9 trailer bytes, then a string.
	stream := ptgFuncVarTok(0, funcUserDefined)
	stream = append(stream, make([]byte, 9)...) // trailer
	stream = append(stream, ptgStr8("after")...)
	got := parseBIFF8Formula(stream)
	if !strings.Contains(got, "after") {
		t.Fatalf("userdefined trailer desync: got %q", got)
	}
}

func TestBIFF8UnknownFuncNeutral(t *testing.T) {
	// Unknown func id → FUNC_<hex>(arg), no dangerous marker.
	stream := append(ptgStr8("x"), ptgFuncTok(0x1234)...)
	got := parseBIFF8Formula(stream)
	if got != "FUNC_1234(x)" {
		t.Fatalf("unknown func: got %q", got)
	}
}

func TestBIFF8RefPlaceholder(t *testing.T) {
	// ptgRef pushes "" — concat of "a" & ref & "b" preserves a/b, drops ref.
	stream := ptgStr8("a")
	stream = append(stream, ptgRef, 0, 0, 0, 0) // ptgRef + 4 bytes
	stream = append(stream, ptgConcat)
	stream = append(stream, ptgStr8("b")...)
	stream = append(stream, ptgConcat)
	got := parseBIFF8Formula(stream)
	if got != "ab" {
		t.Fatalf("ref placeholder: got %q", got)
	}
}

func TestBIFF8TruncatedStrFailOpen(t *testing.T) {
	// cch says 10 but only 2 chars present — must fail-open, not panic, and
	// return what was folded before (a prior literal).
	stream := ptgStr8("good")
	stream = append(stream, ptgStr, 10, 0x00, 'h', 'i') // truncated
	got := parseBIFF8Formula(stream)
	if got != "good" {
		t.Fatalf("truncated str: got %q", got)
	}
}

func TestBIFF8UnknownPtgBails(t *testing.T) {
	// 0x7A is not a handled ptg; parser must stop and return prior operands,
	// not desync.
	stream := ptgStr8("kept")
	stream = append(stream, 0x7A, 0xFF, 0xFF)
	got := parseBIFF8Formula(stream)
	if got != "kept" {
		t.Fatalf("unknown ptg: got %q", got)
	}
}

func TestBIFF8AttrBails(t *testing.T) {
	// ptgAttr (variable-size control token) must bail cleanly.
	stream := ptgStr8("safe")
	stream = append(stream, ptgAttr, 0x04, 0x00, 0x00)
	got := parseBIFF8Formula(stream)
	if got != "safe" {
		t.Fatalf("attr bail: got %q", got)
	}
}

func TestBIFF8ClassVariantsNormalize(t *testing.T) {
	// ptgFuncV (0x41) must dispatch as ptgFunc.
	stream := append(ptgStr8("calc"), 0x41, 110, 0) // EXEC, value-class
	got := parseBIFF8Formula(stream)
	if got != "=EXEC(calc)" {
		t.Fatalf("class variant: got %q", got)
	}
}

func TestBIFF8TokenCapNoSpin(t *testing.T) {
	// A huge run of ptgInt tokens must terminate at the token cap, not hang.
	var stream []byte
	for i := 0; i < maxBIFFPtgTokens+100; i++ {
		stream = append(stream, ptgIntTok(1)...)
	}
	_ = parseBIFF8Formula(stream) // must return (cap stops it); no assertion beyond no-hang.
}

func TestBIFF8OutputCapBounded(t *testing.T) {
	// Repeated concat of large strings must stay within the output cap.
	big := strings.Repeat("A", 40000)
	stream := append(ptgStr8a(big), ptgStr8a(big)...)
	stream = append(stream, ptgConcat)
	got := parseBIFF8Formula(stream)
	if len(got) > maxBIFFPtgOutputLen {
		t.Fatalf("output cap exceeded: %d", len(got))
	}
}

// --- ptg-binop-skip tests -------------------------------------------------------

// TestBIFF8BinopSkip_EQBeforeEXEC tests the motivating bug: a comparison
// operator (ptgEQ) before a ptgFuncVar EXEC token previously caused early abort,
// so the EXEC marker was never emitted. Now the operator is consumed (pop 2,
// push "") and the stream stays in sync so EXEC folds correctly.
//
// Stream encodes roughly: IF(A1=1, EXEC("calc")) at the ptg level, simplified to
// the minimal sequence that exercises the EQ operator:
//
//	ptgRef(A1), ptgInt(1), ptgEQ → pop 2 push "", ptgStr("calc"), ptgFuncVar EXEC(1)
func TestBIFF8BinopSkip_EQBeforeEXEC(t *testing.T) {
	stream := []byte{ptgRef, 0, 0, 0, 0} // A1 ref placeholder
	stream = append(stream, ptgIntTok(1)...)
	stream = append(stream, ptgEQ)
	stream = append(stream, ptgStr8("calc")...)
	stream = append(stream, ptgFuncVarTok(1, 110)...) // EXEC id=110
	got := parseBIFF8Formula(stream)
	if !strings.Contains(got, "EXEC") {
		t.Errorf("EXEC not in folded output; got %q", got)
	}
	if !strings.Contains(got, "calc") {
		t.Errorf("'calc' arg not in folded output; got %q", got)
	}
	var out [][]byte
	emitDangerousMarkers(got, &out)
	var sawMarker bool
	for _, s := range out {
		if string(s) == "XLM-DANGEROUS-FUNC EXEC" {
			sawMarker = true
		}
	}
	if !sawMarker {
		t.Errorf("XLM-DANGEROUS-FUNC EXEC marker not emitted; streams=%q", out)
	}
}

// TestBIFF8BinopSkip_BinopOnlyNoPanic verifies a stream of only binary-operator
// tokens (ptgInt, ptgInt, ptgAdd) does not panic and terminates cleanly.
func TestBIFF8BinopSkip_BinopOnlyNoPanic(t *testing.T) {
	stream := append(ptgIntTok(2), ptgIntTok(3)...)
	stream = append(stream, ptgAdd)
	// Must not panic; result is neutral (empty or "").
	_ = parseBIFF8Formula(stream)
}

// TestBIFF8BinopSkip_AllBinaryOps verifies that every binary-op ptg is
// consumed as 1 byte without desync — a string pushed AFTER the operator
// must still appear in the output.
func TestBIFF8BinopSkip_AllBinaryOps(t *testing.T) {
	binops := []byte{
		ptgAdd, ptgSub, ptgMul, ptgDiv, ptgPower,
		ptgLT, ptgLE, ptgEQ, ptgGE, ptgGT, ptgNE,
		ptgIsect, ptgUnion, ptgRange,
	}
	for _, op := range binops {
		stream := append(ptgIntTok(1), ptgIntTok(2)...)
		stream = append(stream, op)
		stream = append(stream, ptgStr8("sentinel")...)
		got := parseBIFF8Formula(stream)
		if !strings.Contains(got, "sentinel") {
			t.Errorf("op 0x%02x: 'sentinel' not in output; got %q", op, got)
		}
	}
}

// TestBIFF8BinopSkip_UnaryOps verifies that unary-op ptgs are consumed
// as 1 byte and the operand is passed through unchanged.
func TestBIFF8BinopSkip_UnaryOps(t *testing.T) {
	unaryOps := []byte{ptgUplus, ptgUminus, ptgPercent}
	for _, op := range unaryOps {
		stream := append(ptgStr8("x"), op)
		stream = append(stream, ptgStr8("after")...)
		got := parseBIFF8Formula(stream)
		// Both "x" (passed through by unary) and "after" must appear.
		if !strings.Contains(got, "x") || !strings.Contains(got, "after") {
			t.Errorf("op 0x%02x: got %q", op, got)
		}
	}
}

// TestBIFF8BinopSkip_Paren verifies ptgParen is a no-op on the stack (just
// advances 1 byte) so surrounding tokens fold normally.
func TestBIFF8BinopSkip_Paren(t *testing.T) {
	stream := append(ptgStr8("hello"), ptgParen)
	stream = append(stream, ptgStr8("world")...)
	stream = append(stream, ptgConcat)
	got := parseBIFF8Formula(stream)
	if got != "helloworld" {
		t.Errorf("paren: got %q", got)
	}
}

// TestBIFF8BinopSkip_MissArg verifies ptgMissArg pushes "" so a following
// ptgFuncVar still receives the correct argument count.
func TestBIFF8BinopSkip_MissArg(t *testing.T) {
	// EXEC(, "calc") — first arg is missing, second is "calc"; argc=2.
	stream := []byte{ptgMissArg}
	stream = append(stream, ptgStr8("calc")...)
	stream = append(stream, ptgFuncVarTok(2, 110)...) // EXEC
	got := parseBIFF8Formula(stream)
	if !strings.Contains(got, "EXEC") {
		t.Errorf("MissArg: EXEC not in output; got %q", got)
	}
}

// ptgStr8a builds a ptgStr with a >255 length by using the raw cch byte
// truncated — for cap testing we only need a long body, so cap cch at 255 and
// pad the body; parseBIFF8Formula reads exactly cch chars.
func ptgStr8a(s string) []byte {
	n := len(s)
	if n > 255 {
		n = 255
	}
	b := []byte{ptgStr, byte(n), 0x00}
	return append(b, []byte(s[:n])...)
}

// TestBIFF8FuncNames_DDE verifies the DDE ftab ids (175 INITIATE / 177 POKE /
// 179 TERMINATE) now render as named functions so their args stay YARA-visible
// and (for INITIATE) the dangerous-func marker can fire downstream.
func TestBIFF8FuncNames_DDE(t *testing.T) {
	for _, tc := range []struct {
		id   uint16
		name string
	}{
		{175, "INITIATE"},
		{177, "POKE"},
		{179, "TERMINATE"},
	} {
		stream := append(ptgStr8("x"), ptgFuncVarTok(1, tc.id)...)
		got := parseBIFF8Formula(stream)
		if !strings.Contains(got, tc.name) {
			t.Errorf("ftab %d: %q not in folded output; got %q", tc.id, tc.name, got)
		}
	}
}
