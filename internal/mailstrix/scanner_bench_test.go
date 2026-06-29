package mailstrix

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// writeRulesBench writes a single YARA rule file into a temp dir and returns
// the dir path. Duplicates writeRules for *testing.B callers.
func writeRulesBench(b *testing.B, content string) string {
	b.Helper()
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bench.yar"), []byte(content), 0o600); err != nil {
		b.Fatal(err)
	}
	return dir
}

// newScannerBench creates a Scanner from a rule directory for benchmarks.
func newScannerBench(b *testing.B, dir string) *Scanner {
	b.Helper()
	cfg := &Config{RulesDir: dir, ScanTimeout: 0}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		b.Fatalf("NewScanner: %v", err)
	}
	return s
}

// BenchmarkScanTiny benchmarks scanning a small clean buffer (no extraction, no matches).
func BenchmarkScanTiny(b *testing.B) {
	s := newScannerBench(b, writeRulesBench(b, eicarRule))
	buf := bytes.Repeat([]byte{0x20}, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scanT(s, buf, ScanMeta{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScanEICAR benchmarks scanning a buffer that matches (EICAR string present).
func BenchmarkScanEICAR(b *testing.B) {
	s := newScannerBench(b, writeRulesBench(b, eicarRule))
	buf := eicar()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scanT(s, buf, ScanMeta{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanOneMetaLessMatch(b *testing.B) {
	s := newScannerBench(b, writeRulesBench(b, `rule No_Meta { strings: $x = "TOKEN" condition: $x }`))
	rules := s.rules.Load()
	buf := []byte("TOKEN")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m, err := s.scanOne(rules, buf, scanVars{}, 0); err != nil || len(m) != 1 {
			b.Fatalf("scanOne = %+v, %v", m, err)
		}
	}
}

// BenchmarkScan8KiB benchmarks scanning an 8 KiB buffer with no matches.
func BenchmarkScan8KiB(b *testing.B) {
	s := newScannerBench(b, writeRulesBench(b, eicarRule))
	buf := make([]byte, 8*1024)
	for i := range buf {
		buf[i] = byte(i * 7)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scanT(s, buf, ScanMeta{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScanOLE2 benchmarks extraction + scan of a synthetic OLE2 container.
// The rule fires on a string only present in the raw stream payload, exercising
// the full extract→scan pipeline.
func BenchmarkScanOLE2(b *testing.B) {
	rule := `rule BenchPayload { strings: $p = "BENCH_PAYLOAD_MARKER" condition: $p }`
	s := newScannerBench(b, writeRulesBench(b, rule))
	buf := buildBenchCFB()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scanT(s, buf, ScanMeta{}); err != nil {
			b.Fatal(err)
		}
	}
}

// buildBenchCFB constructs a minimal valid OLE2/CFB compound document for
// benchmarking. It replicates the layout from internal/extract/msg_test.go
// buildCFB: header + FAT sector + directory sector + one data sector.
//
// The payload contains "BENCH_PAYLOAD_MARKER" so BenchmarkScanOLE2's rule fires
// through the raw-scan path (no VBA decompression needed for this synthetic doc).
func buildBenchCFB() []byte {
	const (
		sectorSize = 512
		endOfChain = uint32(0xFFFFFFFE)
		fatSect    = uint32(0xFFFFFFFD)
		freeSect   = uint32(0xFFFFFFFF)
		miniCutoff = 4096
		dirEntrySz = 128
	)

	// One stream: padded to miniCutoff so it lives in the regular FAT.
	payload := make([]byte, miniCutoff)
	copy(payload, []byte("BENCH_PAYLOAD_MARKER for OLE2 scanner benchmark"))

	// Layout: sector 0 = FAT, sector 1 = directory, sectors 2..N = stream data.
	dataStart := uint32(2)
	dataSectors := (uint32(len(payload)) + sectorSize - 1) / sectorSize

	// FAT: sector 0 is the FAT sector itself, sector 1 is the dir sector,
	// sectors 2..2+dataSectors-1 chain for the stream.
	fatEntries := make([]uint32, sectorSize/4)
	for i := range fatEntries {
		fatEntries[i] = freeSect
	}
	fatEntries[0] = fatSect    // sector 0 = FAT
	fatEntries[1] = endOfChain // sector 1 = directory (single sector)
	for i := uint32(0); i < dataSectors; i++ {
		if i+1 < dataSectors {
			fatEntries[dataStart+i] = dataStart + i + 1
		} else {
			fatEntries[dataStart+i] = endOfChain
		}
	}

	fatSector := make([]byte, sectorSize)
	for i, v := range fatEntries {
		binary.LittleEndian.PutUint32(fatSector[i*4:], v)
	}

	// Directory: 4 entries per 512-byte sector.
	dirSector := make([]byte, sectorSize)
	writeDirEntry := func(off int, name string, mse byte, childSID, start uint32, size uint64) {
		nameUTF16 := encodeUTF16LE(name)
		copy(dirSector[off:], nameUTF16)
		binary.LittleEndian.PutUint16(dirSector[off+64:], uint16(len(nameUTF16)+2))
		dirSector[off+66] = mse
		dirSector[off+67] = 0x01 // black node (RB tree)
		// left/right/child sibling SIDs = FREESECT (0xFFFFFFFF)
		binary.LittleEndian.PutUint32(dirSector[off+68:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(dirSector[off+72:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(dirSector[off+76:], childSID)
		// CLSID zeros, state bits zeros
		binary.LittleEndian.PutUint32(dirSector[off+116:], start)
		binary.LittleEndian.PutUint64(dirSector[off+120:], size)
	}
	// Entry 0: Root Entry (mse=5), child = entry 1
	writeDirEntry(0, "Root Entry", 5, 1, endOfChain, 0)
	// Entry 1: stream (mse=2)
	writeDirEntry(dirEntrySz, "BenchStream", 2, 0xFFFFFFFF, dataStart, uint64(len(payload)))
	// Entries 2,3: unused (mse=0)
	// (already zero)

	// OLE2 header (512 bytes).
	hdr := make([]byte, sectorSize)
	// Magic
	copy(hdr[0:], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	// Minor version = 0x003E, major = 0x0003
	binary.LittleEndian.PutUint16(hdr[24:], 0x003E)
	binary.LittleEndian.PutUint16(hdr[26:], 0x0003)
	// Byte order: little-endian
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE)
	// Sector size: 2^9 = 512
	binary.LittleEndian.PutUint16(hdr[30:], 9)
	// Mini sector size: 2^6 = 64
	binary.LittleEndian.PutUint16(hdr[32:], 6)
	// Total FAT sectors = 1
	binary.LittleEndian.PutUint32(hdr[44:], 1)
	// First directory sector = 1
	binary.LittleEndian.PutUint32(hdr[48:], 1)
	// Mini stream cutoff = 4096
	binary.LittleEndian.PutUint32(hdr[56:], miniCutoff)
	// First mini FAT sector = ENDOFCHAIN (no mini FAT)
	binary.LittleEndian.PutUint32(hdr[60:], endOfChain)
	// Mini FAT sector count = 0
	binary.LittleEndian.PutUint32(hdr[64:], 0)
	// First DIFAT sector = ENDOFCHAIN
	binary.LittleEndian.PutUint32(hdr[68:], endOfChain)
	// DIFAT sector count = 0
	binary.LittleEndian.PutUint32(hdr[72:], 0)
	// DIFAT array: first FAT sector at index 0 = sector 0
	binary.LittleEndian.PutUint32(hdr[76:], 0)
	// Remaining 109 DIFAT slots = FREESECT
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(hdr[76+i*4:], freeSect)
	}

	// Assemble: header + FAT + dir + data sectors (padded to full sectors)
	var out bytes.Buffer
	out.Write(hdr)
	out.Write(fatSector)
	out.Write(dirSector)
	// Write data sectors
	padded := make([]byte, int(dataSectors)*sectorSize)
	copy(padded, payload)
	out.Write(padded)
	return out.Bytes()
}

// encodeUTF16LE encodes a string as UTF-16LE bytes (no BOM, no terminator).
func encodeUTF16LE(s string) []byte {
	out := make([]byte, len(s)*2)
	for i, r := range s {
		binary.LittleEndian.PutUint16(out[i*2:], uint16(r))
	}
	return out
}

// BenchmarkScanMissRawKeyReuse measures the miss-path scan of a large buffer
// using a precomputed RawKey (PERF-22). Compare with BenchmarkScanMissNoKey to
// confirm the xxhash pass is eliminated: the miss path should hash the buffer
// exactly ONCE (for the streamDedupKey in handleScan) instead of twice.
func BenchmarkScanMissRawKeyReuse(b *testing.B) {
	s := newScannerBench(b, writeRulesBench(b, eicarRule))
	buf := bytes.Repeat([]byte{0xAB}, 512*1024) // 512 KiB
	rawKey := streamDedupKey(buf)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scanT(s, buf, ScanMeta{RawKey: rawKey}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScanMissNoKey measures the fallback path where RawKey is not
// precomputed (e.g. CLI callers that don't set it). The dedup seed is computed
// inline by Scanner.Scan, identical to pre-PERF-22 behavior.
func BenchmarkScanMissNoKey(b *testing.B) {
	s := newScannerBench(b, writeRulesBench(b, eicarRule))
	buf := bytes.Repeat([]byte{0xAB}, 512*1024) // 512 KiB
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scanT(s, buf, ScanMeta{}); err != nil {
			b.Fatal(err)
		}
	}
}
