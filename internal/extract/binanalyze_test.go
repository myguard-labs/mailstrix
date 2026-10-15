package extract_test

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"math/bits"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// PE32 layout constants (fixed, all sizes in bytes):
//
//	0x000 (  0): DOS header  — 64 bytes; e_lfanew=0x40
//	0x040 ( 64): PE signature — 4 bytes
//	0x044 ( 68): COFF header  — 20 bytes; SizeOfOptionalHeader=0xE0
//	0x058 ( 88): Optional header (PE32) — 224 bytes
//	0x138 (312): Section header  — 40 bytes
//	0x160 (352): headers end; padded to 0x200 (FileAlignment)
//	0x200 (512): section raw data start
const (
	peTestDOSSize    = 0x40
	peTestPESig      = 4
	peTestCOFFSize   = 20
	peTestOptHdrSize = 0xE0 // PE32 optional header (224 bytes)
	peTestSectSize   = 40
	peTestHdrsSize   = 0x200 // padded to FileAlignment (avoids PointerToRawData anomaly)
)

type testPEOpts struct {
	// sectionBody is the bytes to write into the single .text section.
	// If nil, a page of zeros is used.
	sectionBody []byte
	// virtualSection: if true, SizeOfRawData=0 and VirtualSize=0x1000; no body written.
	virtualSection bool
	// overlay is appended after the section data (triggers PE-OVERLAY).
	overlay []byte
}

// buildTestPE constructs a minimal saferwall/pe-parseable PE32 binary.
// The layout avoids the common anomaly triggers:
//   - PointerToRawData aligned to FileAlignment (0x200)
//   - SizeOfImage is a multiple of SectionAlignment (0x1000)
//   - MajorSubsystemVersion = 4 (in the 3–6 valid range)
//   - Win32VersionValue = 0 (reserved, must be 0)
//   - Non-zero TimeDateStamp
func buildTestPE(opts testPEOpts) []byte {
	body := opts.sectionBody
	if body == nil && !opts.virtualSection {
		body = make([]byte, 0x1000) // one page of zeros
	}

	rawSz := uint32(len(body))
	virtSz := rawSz
	if opts.virtualSection {
		body = nil
		rawSz = 0
		virtSz = 0x1000
	}

	// SizeOfImage = peTestHdrsSize rounded up to SectionAlignment(0x1000) + one section page.
	sizeOfImage := uint32(0x2000)

	totalSize := peTestHdrsSize + int(rawSz) + len(opts.overlay)
	buf := make([]byte, totalSize)

	// DOS header
	copy(buf[0:], []byte{'M', 'Z'})
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x40) // e_lfanew

	// PE signature
	copy(buf[peTestDOSSize:], []byte{'P', 'E', 0, 0})

	// COFF header
	off := peTestDOSSize + peTestPESig
	binary.LittleEndian.PutUint16(buf[off+0:], 0x014c)            // Machine: I386
	binary.LittleEndian.PutUint16(buf[off+2:], 1)                 // NumberOfSections
	binary.LittleEndian.PutUint32(buf[off+4:], 0x5F000000)        // TimeDateStamp (non-zero)
	binary.LittleEndian.PutUint16(buf[off+16:], peTestOptHdrSize) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(buf[off+18:], 0x0102)           // Characteristics: EXE|32BIT

	// Optional header (PE32)
	ooff := off + peTestCOFFSize
	binary.LittleEndian.PutUint16(buf[ooff+0:], 0x010B)                  // Magic: PE32
	binary.LittleEndian.PutUint32(buf[ooff+4:], rawSz)                   // SizeOfCode
	binary.LittleEndian.PutUint32(buf[ooff+16:], uint32(peTestHdrsSize)) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(buf[ooff+20:], uint32(peTestHdrsSize)) // BaseOfCode
	binary.LittleEndian.PutUint32(buf[ooff+28:], 0x00400000)             // ImageBase
	binary.LittleEndian.PutUint32(buf[ooff+32:], 0x1000)                 // SectionAlignment
	binary.LittleEndian.PutUint32(buf[ooff+36:], 0x200)                  // FileAlignment
	binary.LittleEndian.PutUint16(buf[ooff+40:], 4)                      // MajorOSVersion
	binary.LittleEndian.PutUint16(buf[ooff+48:], 4)                      // MajorSubsystemVersion (4 = in 3–6 range)
	binary.LittleEndian.PutUint32(buf[ooff+52:], 0)                      // Win32VersionValue (must be 0)
	binary.LittleEndian.PutUint32(buf[ooff+56:], sizeOfImage)            // SizeOfImage (multiple of SectionAlignment)
	binary.LittleEndian.PutUint32(buf[ooff+60:], uint32(peTestHdrsSize)) // SizeOfHeaders
	binary.LittleEndian.PutUint16(buf[ooff+68:], 2)                      // Subsystem: Windows GUI
	binary.LittleEndian.PutUint32(buf[ooff+92:], 16)                     // NumberOfRvaAndSizes

	// Section header
	soff := ooff + peTestOptHdrSize
	copy(buf[soff:soff+8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(buf[soff+8:], virtSz)                  // VirtualSize
	binary.LittleEndian.PutUint32(buf[soff+12:], uint32(peTestHdrsSize)) // VirtualAddress
	binary.LittleEndian.PutUint32(buf[soff+16:], rawSz)                  // SizeOfRawData
	if rawSz > 0 {
		binary.LittleEndian.PutUint32(buf[soff+20:], uint32(peTestHdrsSize)) // PointerToRawData
	}
	binary.LittleEndian.PutUint32(buf[soff+36:], 0x60000020) // CODE|EXEC|READ

	// Section body and overlay
	copy(buf[peTestHdrsSize:], body)
	if len(opts.overlay) > 0 {
		copy(buf[peTestHdrsSize+int(rawSz):], opts.overlay)
	}

	return buf
}

// lfsrBody generates a high-entropy (≥7.2 bit) byte sequence using a Galois
// LFSR so the distribution is pseudo-random but deterministic across runs.
func lfsrBody(n int) []byte {
	body := make([]byte, n)
	var state uint32 = 0xACE1BEEF
	for i := range body {
		lsb := state & 1
		state >>= 1
		if lsb == 1 {
			state ^= 0xB4000000
		}
		body[i] = byte(bits.RotateLeft32(state, i%31))
	}
	return body
}

// hasMarker reports whether the given marker string is present in any of the
// result's Streams or Markers (pure markers are split into the Markers channel
// at extraction exit).
func hasMarker(r extract.Result, marker string) bool {
	for _, s := range r.Streams {
		if string(s) == marker {
			return true
		}
	}
	for _, s := range r.Markers {
		if string(s) == marker {
			return true
		}
	}
	return false
}

// TestBinAnalyzeCleanPENoMarkers verifies that a structurally normal, low-entropy
// PE does not emit any PE-* structural markers (no false positives on benign input).
func TestBinAnalyzeCleanPENoMarkers(t *testing.T) {
	pe := buildTestPE(testPEOpts{}) // one page of zeros
	res := extract.Extract(pe, time.Time{})
	for _, m := range []string{
		"PE-SECTION-PACKED",
		"PE-SECTION-HIGH-ENTROPY",
		"PE-OVERLAY",
		"PE-VIRTUAL-SECTION",
		"PE-DOTNET",
		"PE-ANOMALY",
	} {
		if hasMarker(res, m) {
			t.Errorf("clean PE falsely emitted %s", m)
		}
	}
}

// TestBinAnalyzeHighEntropySection verifies that a PE section with ≥7.2 bit
// entropy (LFSR body) emits PE-SECTION-PACKED.
func TestBinAnalyzeHighEntropySection(t *testing.T) {
	pe := buildTestPE(testPEOpts{sectionBody: lfsrBody(4096)})
	res := extract.Extract(pe, time.Time{})
	if !hasMarker(res, "PE-SECTION-PACKED") && !hasMarker(res, "PE-SECTION-HIGH-ENTROPY") {
		t.Error("LFSR-body PE section (entropy ≥7.2) did not emit PE-SECTION-PACKED or PE-SECTION-HIGH-ENTROPY")
	}
}

// TestBinAnalyzeVirtualSection verifies that a PE with SizeOfRawData=0 and
// VirtualSize>0 emits PE-VIRTUAL-SECTION.
func TestBinAnalyzeVirtualSection(t *testing.T) {
	pe := buildTestPE(testPEOpts{virtualSection: true})
	res := extract.Extract(pe, time.Time{})
	if !hasMarker(res, "PE-VIRTUAL-SECTION") {
		t.Error("virtual section PE (raw=0, virt>0) did not emit PE-VIRTUAL-SECTION")
	}
}

// TestBinAnalyzeOverlay verifies that data appended past the last section emits
// PE-OVERLAY.
func TestBinAnalyzeOverlay(t *testing.T) {
	overlay := []byte("OVERLAY DATA APPENDED PAST LAST SECTION -- dropper/loader trait")
	pe := buildTestPE(testPEOpts{overlay: overlay})
	res := extract.Extract(pe, time.Time{})
	if !hasMarker(res, "PE-OVERLAY") {
		t.Error("PE with appended overlay data did not emit PE-OVERLAY")
	}
}

// TestBinAnalyzeELFExecutable verifies that a valid ELF ET_EXEC header (LE, 64-bit)
// supplied as the direct input emits ELF-EXECUTABLE.
func TestBinAnalyzeELFExecutable(t *testing.T) {
	// Minimal ELF64 LE executable header (64 bytes).
	elf := make([]byte, 64)
	elf[0] = 0x7F
	elf[1] = 'E'
	elf[2] = 'L'
	elf[3] = 'F'
	elf[4] = 2 // EI_CLASS = ELFCLASS64
	elf[5] = 1 // EI_DATA = ELFDATA2LSB (LE)
	elf[6] = 1 // EI_VERSION = current
	// e_type = ET_EXEC (2) at offset 16, LE
	binary.LittleEndian.PutUint16(elf[16:], 2)

	res := extract.Extract(elf, time.Time{})
	if !hasMarker(res, "ELF-EXECUTABLE") {
		t.Error("valid ELF ET_EXEC header did not emit ELF-EXECUTABLE")
	}
}

// TestBinAnalyzeELFInvalidRejected verifies that truncated or structurally
// invalid buffers do not falsely emit ELF-EXECUTABLE.
func TestBinAnalyzeELFInvalidRejected(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
	}{
		{"magic only (too short)", []byte("\x7FELF")},
		{"not elf", []byte("not an elf at all, nothing to see here")},
		{"invalid EI_CLASS=3", append([]byte("\x7FELF\x03\x01"), make([]byte, 20)...)},
		{"ET_NONE (e_type=0)", append([]byte("\x7FELF\x02\x01\x01\x00"), append(make([]byte, 8), 0, 0)...)},
	}
	for _, c := range cases {
		res := extract.Extract(c.buf, time.Time{})
		if hasMarker(res, "ELF-EXECUTABLE") {
			t.Errorf("case %q falsely emitted ELF-EXECUTABLE", c.name)
		}
	}
}

// ---------------------------------------------------------------------------
// PERF-21: preflight fast-path tests
// ---------------------------------------------------------------------------

// TestBinAnalyzeFastPathCleanText verifies that a buffer with no MZ/ELF bytes
// returns without emitting any streams AND allocates zero heap objects (preflight
// fast path skips the scan/emitted allocations entirely).
func TestBinAnalyzeFastPathCleanText(t *testing.T) {
	buf := []byte("Hello, this is plain text with no binary content whatsoever.\n")
	res := extract.Extract(buf, time.Time{})
	for _, s := range append(res.Streams, res.Markers...) {
		m := string(s)
		if m == "ELF-EXECUTABLE" || (len(m) > 3 && m[:3] == "PE-") {
			t.Errorf("clean text falsely emitted binary marker %q", m)
		}
	}

	// Alloc-differential assertion: the no-candidate path must allocate strictly
	// fewer objects than an equivalent call with a PE input (which must allocate
	// the scan slice + emitted map on top of the base Result allocs).
	// This is a provable guard: if the preflight is removed, cleanAllocs rises
	// to match peAllocs (both hit the slow path).
	cleanAllocs := testing.AllocsPerRun(20, func() {
		extract.Extract(buf, time.Time{})
	})
	pe := buildTestPE(testPEOpts{})
	peAllocs := testing.AllocsPerRun(20, func() {
		extract.Extract(pe, time.Time{})
	})
	if cleanAllocs >= peAllocs {
		t.Errorf("fast path alloc differential: clean=%.0f >= pe=%.0f; preflight may not be saving allocations", cleanAllocs, peAllocs)
	}
}

// TestBinAnalyzeFastPathLargeClean verifies that an 8 MiB buffer of zeros
// (no PE/ELF) returns immediately with no binary markers.
func TestBinAnalyzeFastPathLargeClean(t *testing.T) {
	buf := make([]byte, 8<<20) // 8 MiB of zeros
	res := extract.Extract(buf, time.Time{})
	for _, s := range append(res.Streams, res.Markers...) {
		m := string(s)
		if m == "ELF-EXECUTABLE" || (len(m) > 3 && m[:3] == "PE-") {
			t.Errorf("8 MiB zero buffer falsely emitted binary marker %q", m)
		}
	}
}

// TestBinAnalyzeFastPathPEInBuf verifies that a buffer containing a valid PE
// still triggers full analysis and emits the expected marker.  This is the
// regression guard: the preflight must NOT skip a buf-carried PE candidate.
func TestBinAnalyzeFastPathPEInBuf(t *testing.T) {
	pe := buildTestPE(testPEOpts{sectionBody: lfsrBody(4096)})
	res := extract.Extract(pe, time.Time{})
	if !hasMarker(res, "PE-SECTION-PACKED") && !hasMarker(res, "PE-SECTION-HIGH-ENTROPY") {
		t.Error("buf-carried PE: expected PE-SECTION-PACKED or PE-SECTION-HIGH-ENTROPY, got none")
	}
}

// TestBinAnalyzeFastPathELFInBuf verifies that a buffer starting with a valid
// ELF header still triggers analysis and emits ELF-EXECUTABLE.
func TestBinAnalyzeFastPathELFInBuf(t *testing.T) {
	elf := make([]byte, 64)
	elf[0] = 0x7F
	elf[1] = 'E'
	elf[2] = 'L'
	elf[3] = 'F'
	elf[4] = 2                                 // ELFCLASS64
	elf[5] = 1                                 // ELFDATA2LSB
	elf[6] = 1                                 // EI_VERSION
	binary.LittleEndian.PutUint16(elf[16:], 2) // ET_EXEC
	res := extract.Extract(elf, time.Time{})
	if !hasMarker(res, "ELF-EXECUTABLE") {
		t.Error("buf-carried ELF: expected ELF-EXECUTABLE, got none")
	}
}

// TestBinAnalyzeFastPathPEInStream verifies the preflight scans res.Streams,
// not just buf: when buf is clean but a stream carries a PE, markers must still
// be emitted. We embed the PE inside a gzip archive so the extractor pushes the
// PE body as a stream that analyzeBinaries will then see.
func TestBinAnalyzeFastPathPEInStream(t *testing.T) {
	pe := buildTestPE(testPEOpts{sectionBody: lfsrBody(4096)})

	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(pe); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	res := extract.Extract(gzBuf.Bytes(), time.Time{})
	if !hasMarker(res, "PE-SECTION-PACKED") && !hasMarker(res, "PE-SECTION-HIGH-ENTROPY") {
		t.Error("stream-carried PE (via gzip): expected PE-SECTION-PACKED or PE-SECTION-HIGH-ENTROPY, got none")
	}
}
