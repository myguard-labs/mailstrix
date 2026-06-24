package extract

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// minimalPE builds the smallest byte sequence isValidPEAt accepts: an "MZ" DOS
// header whose e_lfanew (uint32 at 0x3C) points to a "PE\0\0" signature.
func minimalPE() []byte {
	buf := make([]byte, 0x40+4)
	copy(buf, mzMagic)
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x40) // e_lfanew -> 0x40
	copy(buf[0x40:], peMagic)
	return buf
}

func plainZip(t *testing.T) []byte {
	t.Helper()
	return buildZip(t, map[string][]byte{"a.txt": []byte("benign member")})
}

// A PE with an appended ZIP must be flagged POLYGLOT-PE-ZIP.
func TestPolyglotPEThenZip(t *testing.T) {
	buf := append(minimalPE(), plainZip(t)...)
	res := Extract(buf, time.Time{})
	if !res.Polyglot {
		t.Error("PE+ZIP polyglot not flagged")
	}
	if !streamsContain(res, "POLYGLOT-PE-ZIP") {
		t.Error("PE+ZIP polyglot did not emit marker")
	}
}

// A ZIP with an appended PE must be flagged too (dispatch routes to the zip path
// first, so the PE half would otherwise be invisible).
func TestPolyglotZipThenPE(t *testing.T) {
	buf := append(plainZip(t), minimalPE()...)
	res := Extract(buf, time.Time{})
	if !res.Polyglot {
		t.Error("ZIP+PE polyglot not flagged")
	}
}

// A plain ZIP (no PE) must NOT be flagged.
func TestPolyglotPlainZipClean(t *testing.T) {
	res := Extract(plainZip(t), time.Time{})
	if res.Polyglot {
		t.Error("plain zip falsely flagged polyglot")
	}
	if streamsContain(res, "POLYGLOT-PE-ZIP") {
		t.Error("plain zip falsely emitted polyglot marker")
	}
}

// A bare PE (no ZIP) must NOT be flagged.
func TestPolyglotBarePEClean(t *testing.T) {
	res := Extract(minimalPE(), time.Time{})
	if res.Polyglot {
		t.Error("bare PE falsely flagged polyglot")
	}
}

// An "MZ" pair that is NOT a real PE (e_lfanew does not point at "PE\0\0") inside
// content that also contains a zip must NOT be flagged — the PE half is validated
// through e_lfanew so an incidental MZ cannot trip it.
func TestPolyglotFakeMZNotFlagged(t *testing.T) {
	z := plainZip(t)
	// Prepend a bare "MZ...." with no valid PE signature.
	fake := append([]byte("MZ this is just text, not an executable header at all..............."), z...)
	res := Extract(fake, time.Time{})
	if res.Polyglot {
		t.Error("incidental MZ + zip falsely flagged polyglot")
	}
}

// isValidPEAt unit coverage: valid header accepted, out-of-range e_lfanew
// rejected.
func TestIsValidPEAt(t *testing.T) {
	if !isValidPEAt(minimalPE(), 0) {
		t.Error("minimal valid PE rejected")
	}
	bad := minimalPE()
	binary.LittleEndian.PutUint32(bad[0x3C:], 0xFFFFFFF0) // e_lfanew way out of range
	if isValidPEAt(bad, 0) {
		t.Error("PE with out-of-range e_lfanew accepted")
	}
	// "MZ" too short to hold a DOS header.
	if isValidPEAt([]byte("MZ"), 0) {
		t.Error("short MZ accepted")
	}
}

// A zip-as-zip with a member that itself happens to embed a PE is fine — the
// polyglot check operates on the top-level buffer only, and a member PE inside a
// normal zip (a legitimately archived .exe) is not a file-type confusion. Guard
// that hasZIP/findPE on the OUTER buffer still fire when the PE lands in the
// concatenation, but a normal archived exe (zipped, compressed) does not surface
// a raw PE signature in the outer bytes.
func TestPolyglotArchivedExeNotPolyglot(t *testing.T) {
	// A real PE stored *compressed* inside a zip: the outer bytes are the
	// compressed stream, so no raw "MZ..PE" survives in the container — not a
	// polyglot. (zip.Deflate is the default for buildZip's Create.)
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.Create("real.exe")
	_, _ = w.Write(minimalPE())
	_ = zw.Close()
	res := Extract(b.Bytes(), time.Time{})
	if res.Polyglot {
		t.Error("a compressed archived exe was falsely flagged polyglot")
	}
}
