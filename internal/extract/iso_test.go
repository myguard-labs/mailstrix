package extract

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildISO assembles a minimal but valid ISO9660 image with a single regular
// file in the root directory, so the walk path is exercised end to end. Layout
// (2048-byte sectors): 0-15 system area, 16 PVD, 17 terminator, 18 root
// directory extent, 19 file data. When joliet is true a supplementary
// descriptor (UCS-2 escape) is inserted before the terminator so the Joliet
// branch of isoRootRecord is taken; both descriptors point at the same root.
func buildISO(name string, data []byte, joliet bool) []byte {
	const sec = isoSectorSize
	rootLBA := uint32(18)
	fileLBA := uint32(19)

	// File identifier: UCS-2BE under Joliet (so the test exercises the real
	// Joliet directory-record layout, where ASCII names start with a 0x00 byte),
	// plain bytes otherwise.
	fileID := []byte(name)
	if joliet {
		fileID = ucs2BE(name)
	}

	// Root directory extent: ".", "..", and the file record. The "." / ".."
	// self/parent entries keep their single-byte 0x00 / 0x01 identifiers even
	// under Joliet.
	rootDir := make([]byte, sec)
	off := 0
	off += copy(rootDir[off:], dirRecord(rootLBA, sec, true, []byte{0x00})) // "."
	off += copy(rootDir[off:], dirRecord(rootLBA, sec, true, []byte{0x01})) // ".."
	copy(rootDir[off:], dirRecord(fileLBA, uint32(len(data)), false, fileID))

	img := make([]byte, int(fileLBA+1)*sec)

	// PVD (type 1) at sector 16 with its 34-byte root record at offset 156.
	pvd := volDescriptor(1, dirRecord(rootLBA, sec, true, []byte{0x00}))
	copy(img[isoSystemArea*sec:], pvd)

	termSector := isoSystemArea + 1
	if joliet {
		svd := volDescriptor(isoVDSupplementary, dirRecord(rootLBA, sec, true, []byte{0x00}))
		copy(svd[88:91], []byte("%/E")) // Joliet UCS-2 level-3 escape
		copy(img[(isoSystemArea+1)*sec:], svd)
		termSector = isoSystemArea + 2
	}

	term := volDescriptor(isoVDTerminator, nil)
	copy(img[termSector*sec:], term)

	copy(img[int(rootLBA)*sec:], rootDir)
	copy(img[int(fileLBA)*sec:], data)
	return img
}

// ucs2BE encodes an ASCII string as big-endian UTF-16, the on-disk form of a
// Joliet file identifier (each char becomes 0x00 <byte>).
func ucs2BE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, c := range []byte(s) {
		out = append(out, 0x00, c)
	}
	return out
}

// volDescriptor builds a 2048-byte volume descriptor: type byte, "CD001",
// version, and (for PVD/SVD) the 34-byte root directory record at offset 156.
func volDescriptor(typ byte, root []byte) []byte {
	d := make([]byte, isoSectorSize)
	d[0] = typ
	copy(d[1:6], isoMagic)
	d[6] = 1
	if root != nil {
		copy(d[156:], root)
	}
	return d
}

// dirRecord builds a directory record (both-endian extent at offset 2, length at
// offset 10, flags at 25, id at 33). Length is padded even per ECMA-119.
func dirRecord(extent, size uint32, isDir bool, id []byte) []byte {
	recLen := 33 + len(id)
	if recLen%2 != 0 {
		recLen++ // records are padded to an even length
	}
	r := make([]byte, recLen)
	r[0] = byte(recLen)
	binary.LittleEndian.PutUint32(r[2:6], extent)
	binary.BigEndian.PutUint32(r[6:10], extent)
	binary.LittleEndian.PutUint32(r[10:14], size)
	binary.BigEndian.PutUint32(r[14:18], size)
	if isDir {
		r[25] = isoFlagDir
	}
	r[32] = byte(len(id))
	copy(r[33:], id)
	return r
}

func TestExtractISOMemberFile(t *testing.T) {
	payload := []byte("MZ\x90\x00 iso dropper member payload invoke calc.exe")
	buf := buildISO("DROP.EXE;1", payload, false)
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Fatal("ISO not flagged IsDoc")
	}
	if !res.IsISO {
		t.Fatal("ISO not flagged IsISO")
	}
	if !streamsContain(res, "iso dropper member payload") {
		t.Fatal("ISO member file not surfaced to streams")
	}
}

func TestExtractISOJoliet(t *testing.T) {
	payload := []byte("joliet member payload script payload")
	buf := buildISO("RUN.JS;1", payload, true)
	res := Extract(buf, time.Time{})
	if !res.IsISO {
		t.Fatal("Joliet ISO not flagged IsISO")
	}
	if !streamsContain(res, "joliet member payload") {
		t.Fatal("Joliet ISO member not surfaced to streams")
	}
}

// A non-ISO buffer must not be flagged IsISO.
func TestExtractISONegative(t *testing.T) {
	res := Extract([]byte("not a disc image, just plain text content here"), time.Time{})
	if res.IsISO {
		t.Fatal("plain text wrongly flagged IsISO")
	}
}

// A truncated image (header present, directory/file extents missing) must
// fail open: flagged IsISO, no panic, no streams.
func TestExtractISOTruncated(t *testing.T) {
	full := buildISO("X.EXE;1", []byte("payload"), false)
	buf := full[:isoSystemArea*isoSectorSize+10] // only into the PVD
	res := Extract(buf, time.Time{})
	if len(res.Streams) != 0 {
		t.Fatal("truncated ISO should yield no streams")
	}
}
