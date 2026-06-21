package extract

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// cfbEntry is one directory entry for buildCFB: a named storage (mse=1) or
// stream (mse=2). Stream data is laid out in the regular FAT (we pad each stream
// to >= MiniSectorCutoff so the mini-FAT is never needed).
type cfbEntry struct {
	name string
	mse  byte // 1 = storage, 2 = stream, 5 = root
	data []byte

	// Optional explicit red-black-tree links (original CFB SIDs). When linksSet
	// is true, buildCFB writes these verbatim into SidLeftSib/SidRightSib/
	// SidChild; otherwise it uses the legacy auto layout (root.SidChild=1, all
	// siblings freeSect). The OLEDIR-1 orphan tests need a real reachable tree
	// plus an unreferenced entry, which the auto layout cannot express.
	left, right, child uint32
	linksSet           bool

	// Optional CFB directory-entry FILETIMEs (100-ns ticks since 1601), written
	// to offsets 100/108. Zero leaves them null, matching a real Office stamp.
	// The OLETIMES-1 tests set these to synthesize future-dated / synthetic-
	// identical anomalies.
	ctime, mtime uint64
}

// buildCFB hand-builds a minimal valid OLE2/CFB that oleparse parses, with an
// arbitrary set of named streams/storages. Used to synthesize a .msg fixture in
// CI (no Outlook tooling available). Layout: header, FAT sector(s), directory
// sector(s), then each stream's data sectors in order.
func buildCFB(t *testing.T, entries []cfbEntry) []byte {
	t.Helper()
	const (
		sectorSize = 512
		endOfChain = 0xFFFFFFFE
		fatSect    = 0xFFFFFFFD
		freeSect   = 0xFFFFFFFF
		miniCutoff = 4096
		dirEntrySz = 128
	)

	// Pad every stream to >= miniCutoff so it lives in the regular FAT.
	for i := range entries {
		if entries[i].mse == 2 && len(entries[i].data) < miniCutoff {
			entries[i].data = append(entries[i].data, make([]byte, miniCutoff-len(entries[i].data))...)
		}
	}

	// Directory sector(s): 4 entries per 512-byte sector. Round entry count up.
	nEntries := len(entries)
	dirSectors := (nEntries*dirEntrySz + sectorSize - 1) / sectorSize
	// Sector 0 = FAT. Sectors 1..dirSectors = directory. Streams follow.
	firstDirSect := 1
	nextSect := firstDirSect + dirSectors

	// Assign each stream a starting sector + sector run.
	type placed struct {
		start   uint32
		sectors int
	}
	pl := make([]placed, nEntries)
	for i, e := range entries {
		if e.mse != 2 || len(e.data) == 0 {
			pl[i] = placed{start: endOfChain}
			continue
		}
		secs := (len(e.data) + sectorSize - 1) / sectorSize
		pl[i] = placed{start: uint32(nextSect), sectors: secs}
		nextSect += secs
	}
	totalSectors := nextSect // count after the header sector

	// --- header ---
	hdr := make([]byte, sectorSize)
	copy(hdr[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(hdr[24:], 0x3E)
	binary.LittleEndian.PutUint16(hdr[26:], 3)
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE)
	binary.LittleEndian.PutUint16(hdr[30:], 9) // 512-byte sectors
	binary.LittleEndian.PutUint16(hdr[32:], 6)
	binary.LittleEndian.PutUint32(hdr[44:], 1)                    // CsectFat = 1
	binary.LittleEndian.PutUint32(hdr[48:], uint32(firstDirSect)) // SectDirStart
	binary.LittleEndian.PutUint32(hdr[56:], miniCutoff)
	binary.LittleEndian.PutUint32(hdr[60:], endOfChain) // SectMiniFatStart
	binary.LittleEndian.PutUint32(hdr[64:], 0)
	binary.LittleEndian.PutUint32(hdr[68:], endOfChain) // SectDifStart
	binary.LittleEndian.PutUint32(hdr[72:], 0)
	off := 76
	binary.LittleEndian.PutUint32(hdr[off:], 0) // SectFat[0] = sector 0
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(hdr[off+i*4:], freeSect)
	}

	// --- FAT (sector 0) ---
	fat := make([]byte, sectorSize)
	put := func(idx int, v uint32) { binary.LittleEndian.PutUint32(fat[idx*4:], v) }
	for i := 0; i < sectorSize/4; i++ {
		put(i, freeSect)
	}
	put(0, fatSect)
	for i := 0; i < dirSectors; i++ {
		s := firstDirSect + i
		if i == dirSectors-1 {
			put(s, endOfChain)
		} else {
			put(s, uint32(s+1))
		}
	}
	for _, p := range pl {
		for i := 0; i < p.sectors; i++ {
			s := int(p.start) + i
			if i == p.sectors-1 {
				put(s, endOfChain)
			} else {
				put(s, uint32(s+1))
			}
		}
	}

	// --- directory ---
	dir := make([]byte, dirSectors*sectorSize)
	for i, e := range entries {
		b := dir[i*dirEntrySz : (i+1)*dirEntrySz]
		u := utf16le(e.name)
		copy(b[0:64], u)
		binary.LittleEndian.PutUint16(b[64:], uint16(len(u)))
		b[66] = e.mse
		if e.linksSet {
			binary.LittleEndian.PutUint32(b[68:], e.left)
			binary.LittleEndian.PutUint32(b[72:], e.right)
			binary.LittleEndian.PutUint32(b[76:], e.child)
		} else {
			binary.LittleEndian.PutUint32(b[68:], freeSect) // SidLeftSib
			binary.LittleEndian.PutUint32(b[72:], freeSect) // SidRightSib
			// SidChild: root points at entry 1 if present (enough for oleparse to walk).
			if e.mse == 5 && nEntries > 1 {
				binary.LittleEndian.PutUint32(b[76:], 1)
			} else {
				binary.LittleEndian.PutUint32(b[76:], freeSect)
			}
		}
		binary.LittleEndian.PutUint64(b[100:], e.ctime)
		binary.LittleEndian.PutUint64(b[108:], e.mtime)
		binary.LittleEndian.PutUint32(b[116:], pl[i].start)
		binary.LittleEndian.PutUint32(b[120:], uint32(len(e.data)))
	}

	// --- stream data ---
	var streams bytes.Buffer
	for i, e := range entries {
		if e.mse != 2 || len(e.data) == 0 {
			continue
		}
		padded := make([]byte, pl[i].sectors*sectorSize)
		copy(padded, e.data)
		streams.Write(padded)
	}

	_ = totalSectors
	var out bytes.Buffer
	out.Write(hdr)
	out.Write(fat)
	out.Write(dir)
	out.Write(streams.Bytes())
	return out.Bytes()
}

// An Outlook .msg must be recognised and its nested attachment data stream
// (PR_ATTACH_DATA_BIN) surfaced for scanning.
func TestExtractMSGAttachment(t *testing.T) {
	marker := []byte("MZ\x90\x00 this is the embedded attachment payload EICAR-ish")
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "__properties_version1.0", mse: 2, data: []byte("props blob")},
		{name: "__attach_version1.0_#00000000", mse: 1},
		{name: "__substg1.0_3701000D", mse: 2, data: marker},
	})
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Fatal(".msg not flagged IsDoc")
	}
	if !res.IsMSG {
		t.Fatal(".msg not flagged IsMSG")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("embedded attachment payload")) {
			found = true
		}
	}
	if !found {
		t.Errorf("attachment data stream not surfaced; got %d streams", len(res.Streams))
	}
}

// An OLE2 with a props stream but NO attachment storage must not be read as a
// .msg (and so its props are not dumped as attachments).
func TestExtractNonMSGNoAttach(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "__properties_version1.0", mse: 2, data: []byte("props only, no attachments here")},
	})
	res := Extract(buf, time.Time{})
	if res.IsMSG {
		t.Error("OLE2 without an attachment storage wrongly flagged IsMSG")
	}
}
