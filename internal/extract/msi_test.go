package extract

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// buildMinimalMSI hand-builds the smallest valid OLE2/CFB that oleparse will
// parse, carrying the MSI root CLSID and a single stream holding payload. It is
// a fixture generator (no MSI tooling exists in CI), exercising the real parse
// path in fromMSI rather than mocking it.
//
// Layout (512-byte v3 sectors; the stream is >= MiniSectorCutoff so it lives in
// the regular FAT and we can skip the mini-FAT entirely):
//
//	header (the 512 bytes before sector 0)
//	sector 0 : FAT
//	sector 1 : directory (4 * 128-byte entries)
//	sector 2.: payload stream data
func buildMinimalMSI(t *testing.T, payload []byte) []byte {
	t.Helper()
	const (
		sectorSize = 512
		endOfChain = 0xFFFFFFFE
		fatSect    = 0xFFFFFFFD
		freeSect   = 0xFFFFFFFF
		miniCutoff = 4096
		dirEntries = 4
		dirEntrySz = 128
	)
	if len(payload) < miniCutoff {
		// Pad so the stream uses the regular FAT, not the mini stream.
		payload = append(payload, make([]byte, miniCutoff-len(payload))...)
	}

	streamSectors := (len(payload) + sectorSize - 1) / sectorSize
	// sector 0 FAT, sector 1 dir, sectors 2..2+streamSectors-1 = stream.
	firstStreamSect := uint32(2)

	// --- header ---
	hdr := make([]byte, sectorSize)
	copy(hdr[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}) // AbSig
	// Clid (header) left zero. MinorVersion 0x3E, MajorVersion 3, ByteOrder 0xFFFE.
	binary.LittleEndian.PutUint16(hdr[24:], 0x3E) // MinorVersion
	binary.LittleEndian.PutUint16(hdr[26:], 3)    // MajorVersion
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE)
	binary.LittleEndian.PutUint16(hdr[30:], 9) // SectorShift => 512
	binary.LittleEndian.PutUint16(hdr[32:], 6) // MiniSectorShift => 64
	binary.LittleEndian.PutUint32(hdr[44:], 1) // CsectFat = 1
	binary.LittleEndian.PutUint32(hdr[48:], 1) // SectDirStart = sector 1
	binary.LittleEndian.PutUint32(hdr[56:], miniCutoff)
	binary.LittleEndian.PutUint32(hdr[60:], endOfChain) // SectMiniFatStart
	binary.LittleEndian.PutUint32(hdr[64:], 0)          // CsectMiniFat
	binary.LittleEndian.PutUint32(hdr[68:], endOfChain) // SectDifStart
	binary.LittleEndian.PutUint32(hdr[72:], 0)          // CsectDif
	// SectFat[0] = sector 0; rest FREESECT.
	off := 76
	binary.LittleEndian.PutUint32(hdr[off:], 0)
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(hdr[off+i*4:], freeSect)
	}

	// --- FAT (sector 0) ---
	fat := make([]byte, sectorSize)
	put := func(idx int, v uint32) { binary.LittleEndian.PutUint32(fat[idx*4:], v) }
	for i := 0; i < sectorSize/4; i++ {
		put(i, freeSect)
	}
	put(0, fatSect)    // sector 0 is the FAT itself
	put(1, endOfChain) // directory chain (single sector)
	for i := 0; i < streamSectors; i++ {
		s := int(firstStreamSect) + i
		if i == streamSectors-1 {
			put(s, endOfChain)
		} else {
			put(s, uint32(s+1))
		}
	}

	// --- directory (sector 1) ---
	dir := make([]byte, dirEntries*dirEntrySz)
	writeName := func(b []byte, name string) {
		// CFB names are UTF-16LE, CB = byte length incl. the NUL terminator.
		u := utf16le(name)
		copy(b[0:64], u)
		binary.LittleEndian.PutUint16(b[64:], uint16(len(u)))
	}
	// entry 0: root storage, MSI CLSID, Mse=5.
	root := dir[0:dirEntrySz]
	writeName(root, "Root Entry")
	root[66] = 5 // Mse
	copy(root[80:96], msiRootCLSID[:])
	binary.LittleEndian.PutUint32(root[116:], endOfChain) // SectStart (mini stream) none
	binary.LittleEndian.PutUint32(root[120:], 0)          // Size
	binary.LittleEndian.PutUint32(root[68:], freeSect)    // SidLeftSib
	binary.LittleEndian.PutUint32(root[72:], freeSect)    // SidRightSib
	binary.LittleEndian.PutUint32(root[76:], 1)           // SidChild -> entry 1
	// entry 1: the payload stream, Mse=2.
	st := dir[dirEntrySz : 2*dirEntrySz]
	writeName(st, "\x05Payload")
	st[66] = 2 // Mse = stream
	binary.LittleEndian.PutUint32(st[68:], freeSect)
	binary.LittleEndian.PutUint32(st[72:], freeSect)
	binary.LittleEndian.PutUint32(st[76:], freeSect)
	binary.LittleEndian.PutUint32(st[116:], firstStreamSect)
	binary.LittleEndian.PutUint32(st[120:], uint32(len(payload)))
	// entries 2,3: unallocated (Mse=0) — left zero.
	dirSect := make([]byte, sectorSize)
	copy(dirSect, dir)

	// --- stream data sectors ---
	streamPadded := make([]byte, streamSectors*sectorSize)
	copy(streamPadded, payload)

	var buf bytes.Buffer
	buf.Write(hdr)
	buf.Write(fat)
	buf.Write(dirSect)
	buf.Write(streamPadded)
	return buf.Bytes()
}

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	out = append(out, 0, 0) // NUL terminator
	return out
}

// A Windows Installer database must be recognised and its stream payload dumped
// so keyword rules can match an embedded CustomAction script.
func TestExtractMSIStreamsDumped(t *testing.T) {
	marker := "CustomAction WScript.Shell powershell -enc SQBFAFgA"
	buf := buildMinimalMSI(t, []byte(marker))
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Fatal("MSI not flagged IsDoc")
	}
	if !res.IsMSI {
		t.Fatal("MSI not flagged IsMSI")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("powershell -enc")) {
			found = true
		}
	}
	if !found {
		t.Errorf("MSI payload stream not surfaced for scanning; got %d streams", len(res.Streams))
	}
}

// A non-MSI OLE2 (no MSI CLSID) must NOT trigger the stream dump — dumping every
// macro-less document's streams would scan body text and invite false positives.
func TestExtractNonMSIOLENotDumped(t *testing.T) {
	// Same builder but clobber the root CLSID so it is no longer an MSI.
	buf := buildMinimalMSI(t, []byte("ordinary stream contents, not an installer"))
	// Root CLSID lives at dir entry 0, offset 80, in sector 1 (= header+FAT before it).
	clsidOff := 512 + 512 + 80
	for i := 0; i < 16; i++ {
		buf[clsidOff+i] = 0
	}
	res := Extract(buf, time.Time{})
	if res.IsMSI {
		t.Error("non-MSI OLE2 wrongly flagged IsMSI")
	}
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("ordinary stream contents")) {
			t.Error("non-MSI OLE2 stream wrongly dumped (FP risk)")
		}
	}
}
