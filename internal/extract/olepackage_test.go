package extract

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// buildOle10Native assembles an Ole10Native stream wrapping nativeData, with the
// given label/filename/filepath. ndSizeOverride, if non-zero, is written as the
// NativeDataSize field instead of len(nativeData) — to exercise a hostile claim.
func buildOle10Native(label, filename, filepath string, nativeData []byte, ndSizeOverride uint32) []byte {
	var b bytes.Buffer
	var u32 [4]byte
	var u16 [2]byte
	binary.LittleEndian.PutUint32(u32[:], 0) // TotalSize (unused by carver)
	b.Write(u32[:])
	binary.LittleEndian.PutUint16(u16[:], 0x0002) // Flags1
	b.Write(u16[:])
	b.WriteString(label)
	b.WriteByte(0)
	b.WriteString(filename)
	b.WriteByte(0)
	binary.LittleEndian.PutUint16(u16[:], 0) // Flags2
	b.Write(u16[:])
	binary.LittleEndian.PutUint16(u16[:], 0) // Unknown1
	b.Write(u16[:])
	binary.LittleEndian.PutUint32(u32[:], uint32(len(filepath)+1)) // FilePathSize
	b.Write(u32[:])
	b.WriteString(filepath)
	b.WriteByte(0)
	nd := uint32(len(nativeData))
	if ndSizeOverride != 0 {
		nd = ndSizeOverride
	}
	binary.LittleEndian.PutUint32(u32[:], nd) // NativeDataSize
	b.Write(u32[:])
	b.Write(nativeData)
	return b.Bytes()
}

// An OLE2 document carrying an embedded OLE Package object must have the dropped
// file's native data carved and surfaced.
func TestExtractOLEPackage(t *testing.T) {
	payload := []byte("MZ\x90\x00 embedded ole package dropper payload calc.exe")
	stream := buildOle10Native("calc.exe", "C:\\evil\\calc.exe", "C:\\Temp\\calc.exe", payload, 0)
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "\x01Ole10Native", mse: 2, data: stream},
	})
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Fatal("doc not flagged IsDoc")
	}
	if !res.IsOLEPackage {
		t.Fatal("embedded package not flagged IsOLEPackage")
	}
	if !streamsContain(res, "embedded ole package dropper payload") {
		t.Errorf("package native data not surfaced; got %d streams", len(res.Streams))
	}
}

// A hostile NativeDataSize larger than the stream must clamp to the bytes
// present, never over-read or panic.
func TestExtractOLEPackageOversized(t *testing.T) {
	payload := []byte("short payload lying about its size")
	stream := buildOle10Native("x", "x", "x", payload, 1<<30) // claim 1 GiB
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "\x01Ole10Native", mse: 2, data: stream},
	})
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Fatal("oversized NativeDataSize panicked")
	}
	// The oversized claim must be clamped to the bytes actually present in the
	// stream (here the CFB sector-padded stream, ~4 KiB), NOT to the 1 GiB claim:
	// the guarantee is "never over-read", not "exact size". A multi-MiB result
	// would mean the clamp failed.
	for _, s := range res.Streams {
		if len(s) > maxBytesPerPackage {
			t.Errorf("emitted %d bytes from oversized claim; clamp failed", len(s))
		}
	}
	if !res.IsOLEPackage {
		t.Error("oversized package not flagged IsOLEPackage")
	}
}

// A truncated Ole10Native stream (header cut mid-field) must be skipped without
// panic and surface nothing.
func TestExtractOLEPackageTruncated(t *testing.T) {
	stream := []byte{0x10, 0x00, 0x00, 0x00, 0x02, 0x00} // header then nothing
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "\x01Ole10Native", mse: 2, data: stream},
	})
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Fatal("truncated Ole10Native panicked")
	}
	if streamsContain(res, "MZ") {
		t.Error("truncated stream wrongly surfaced data")
	}
}

// An OLE2 without an Ole10Native stream must not be flagged IsOLEPackage.
func TestExtractNoOLEPackage(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "WordDocument", mse: 2, data: []byte("ordinary doc body, no package")},
	})
	res := Extract(buf, time.Time{})
	if res.IsOLEPackage {
		t.Error("doc without package wrongly flagged IsOLEPackage")
	}
}
