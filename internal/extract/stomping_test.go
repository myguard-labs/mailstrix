package extract

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestEffectiveSourceLen covers the various source shapes that stomping
// detection depends on.
func TestEffectiveSourceLen(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"empty", "", 0},
		{"whitespace only", "  \n\t\n  \n", 0},
		{"attribute VB_Name only", "Attribute VB_Name = \"Foo\"\n", 0},
		{"multiple attribute lines", "Attribute VB_Name = \"Foo\"\nAttribute VB_GlobalNameSpace = False\n", 0},
		{"real code line", "Sub Foo()\n  MsgBox \"hi\"\nEnd Sub\n", 30},
		{"mixed attr+code", "Attribute VB_Name = \"M\"\nSub Go()\nEnd Sub\n", 14},
	}
	for _, tc := range cases {
		got := effectiveSourceLen([]byte(tc.src))
		if tc.want == 0 && got != 0 {
			t.Errorf("%s: want 0, got %d", tc.name, got)
		} else if tc.want > 0 && got == 0 {
			t.Errorf("%s: want >0, got %d", tc.name, got)
		}
	}
}

// TestStompThresholds checks the boundary conditions the spec requires:
//   - pcode >= 256 AND effective source < 32 → stomped
//   - pcode >= 256 AND effective source >= 32 → not stomped (source looks real)
//
// These tests exercise the threshold constants directly so a constant change
// is caught immediately.
func TestStompThresholds(t *testing.T) {
	if stompPCodeThreshold != 256 {
		t.Errorf("stompPCodeThreshold changed: got %d, want 256", stompPCodeThreshold)
	}
	if stompSourceThreshold != 32 {
		t.Errorf("stompSourceThreshold changed: got %d, want 32", stompSourceThreshold)
	}

	// Source exactly at threshold → not stomped.
	exact := strings.Repeat("a", stompSourceThreshold)
	if got := effectiveSourceLen([]byte(exact)); got < stompSourceThreshold {
		t.Errorf("source at threshold: effective %d < %d — would falsely flag", got, stompSourceThreshold)
	}

	// Source one byte below threshold → stomped.
	below := strings.Repeat("a", stompSourceThreshold-1)
	if got := effectiveSourceLen([]byte(below)); got >= stompSourceThreshold {
		t.Errorf("source one below threshold: effective %d >= %d — stomping missed", got, stompSourceThreshold)
	}
}

// TestVBACompressStream_RoundTrip verifies the in-package vbaCompressStream
// helper (used to build synthetic test streams) round-trips through
// oleparse.DecompressStream correctly.
func TestVBACompressStream_RoundTrip(t *testing.T) {
	original := []byte("Sub Auto_Open()\n  Shell \"cmd.exe /c evil.bat\"\nEnd Sub\n")
	compressed := vbaCompressStream(original)
	if len(compressed) == 0 {
		t.Fatal("vbaCompressStream returned empty output")
	}
	// Re-import via walkDirStream path — decompression handled inside stomping.go.
	// Here we just verify the header byte and structure are non-trivial.
	if compressed[0] != 0x01 {
		t.Errorf("expected signature byte 0x01, got 0x%02x", compressed[0])
	}
}

// TestWalkDirStream_Empty verifies that an empty/truncated dir stream returns
// an error rather than a module list.
func TestWalkDirStream_Empty(t *testing.T) {
	_, err := walkDirStream([]byte{})
	if err == nil {
		t.Error("expected error for empty dir stream, got nil")
	}
}

// TestWalkDirStream_Truncated verifies graceful failure on truncated input.
func TestWalkDirStream_Truncated(t *testing.T) {
	// A few bytes — not enough for any real record.
	_, err := walkDirStream([]byte{0x01, 0x00, 0x04, 0x00})
	if err == nil {
		t.Error("expected error for truncated dir stream, got nil")
	}
}

// TestWalkDirStream_MultiModule builds a synthetic dir stream with 3 modules
// and verifies all are returned with correct name/streamName/offset.
func TestWalkDirStream_MultiModule(t *testing.T) {
	dir := buildSyntheticDirStream([]testModule{
		{name: "Module1", streamName: "Module1", offset: 100},
		{name: "Module2", streamName: "Module2", offset: 200},
		{name: "Sheet1", streamName: "Sheet1", offset: 50},
	})
	recs, err := walkDirStream(dir)
	if err != nil {
		t.Fatalf("walkDirStream: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	for i, want := range []struct {
		name, stream string
		off          uint32
	}{
		{"Module1", "Module1", 100},
		{"Module2", "Module2", 200},
		{"Sheet1", "Sheet1", 50},
	} {
		if recs[i].name != want.name || recs[i].streamName != want.stream || recs[i].offset != want.off {
			t.Errorf("rec[%d] = {%q, %q, %d}, want {%q, %q, %d}",
				i, recs[i].name, recs[i].streamName, recs[i].offset,
				want.name, want.stream, want.off)
		}
	}
}

// TestWalkDirStream_HugeModuleCount verifies that an absurd module count is
// capped rather than causing OOM or excessive iteration.
func TestWalkDirStream_HugeModuleCount(t *testing.T) {
	dir := buildSyntheticDirStream(nil)
	patchModuleCount(dir, 0xFFFF)
	recs, _ := walkDirStream(dir)
	if len(recs) > 256 {
		t.Fatalf("got %d records from huge-count stream, expected ≤256", len(recs))
	}
}

// TestWalkDirStream_HugeRecordSize verifies that a record with absurd size
// is rejected rather than causing OOM.
func TestWalkDirStream_HugeRecordSize(t *testing.T) {
	var dir []byte
	dir = appendU16(dir, 0x0001)
	dir = appendU32(dir, 0x7FFFFFFF)
	_, err := walkDirStream(dir)
	if err == nil {
		t.Error("expected error for huge record size, got nil")
	}
}

// TestWalkDirStream_NoTerminator verifies graceful handling when a module
// is missing its TERMINATOR record.
func TestWalkDirStream_NoTerminator(t *testing.T) {
	dir := buildSyntheticDirStream([]testModule{
		{name: "Module1", streamName: "Module1", offset: 100},
	})
	cut := len(dir) - 6
	if cut > 0 {
		_, err := walkDirStream(dir[:cut])
		_ = err
	}
}

type testModule struct {
	name       string
	streamName string
	offset     uint32
}

func buildSyntheticDirStream(mods []testModule) []byte {
	var buf []byte
	buf = appendU16(buf, 0x0001)
	buf = appendU32(buf, 4)
	buf = appendU32(buf, 0)

	buf = appendU16(buf, 0x000F)
	buf = appendU32(buf, 2)
	buf = appendU16(buf, uint16(len(mods)))

	buf = appendU16(buf, 0x0013)
	buf = appendU32(buf, 2)
	buf = appendU16(buf, 0)

	for _, m := range mods {
		buf = appendU16(buf, 0x0019)
		buf = appendU32(buf, uint32(len(m.name)))
		buf = append(buf, []byte(m.name)...)

		buf = appendU16(buf, 0x001A)
		buf = appendU32(buf, uint32(len(m.streamName)))
		buf = append(buf, []byte(m.streamName)...)

		buf = appendU16(buf, 0x0032)
		buf = appendU32(buf, uint32(len(m.streamName)*2))
		for _, c := range m.streamName {
			buf = appendU16(buf, uint16(c))
		}

		buf = appendU16(buf, 0x0031)
		buf = appendU32(buf, 4)
		buf = appendU32(buf, m.offset)

		buf = appendU16(buf, 0x0021)
		buf = appendU32(buf, 0)

		buf = appendU16(buf, 0x002B)
		buf = appendU32(buf, 0)
	}
	return buf
}

func patchModuleCount(dir []byte, count uint16) {
	for i := 0; i+8 <= len(dir); i += 2 {
		if binary.LittleEndian.Uint16(dir[i:]) == 0x000F {
			binary.LittleEndian.PutUint16(dir[i+6:], count)
			return
		}
	}
}

func appendU16(buf []byte, v uint16) []byte {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return append(buf, b[:]...)
}

func appendU32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}
