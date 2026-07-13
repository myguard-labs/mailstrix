package oleparse

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestReadSectorRejectsFreeSectWithoutWrapping(t *testing.T) {
	ole := &OLEFile{
		data:       make([]byte, 2*sectorSize),
		SectorSize: sectorSize,
	}

	if got := ole.ReadSector(FREESECT); got != nil {
		t.Fatalf("ReadSector(FREESECT) wrapped to %d bytes, want nil", len(got))
	}
}

func TestNewOLEFilePreservesDirectorySIDsWithUnallocatedEntries(t *testing.T) {
	want := []byte("sparse directory stream")
	buf := miniOLE(t, map[string][]byte{"Workbook": want})

	const (
		dirOffset  = 2 * sectorSize
		dirEntSize = 128
	)
	entry := append([]byte(nil), buf[dirOffset+dirEntSize:dirOffset+2*dirEntSize]...)
	for i := dirOffset + dirEntSize; i < dirOffset+2*dirEntSize; i++ {
		buf[i] = 0
	}
	copy(buf[dirOffset+2*dirEntSize:dirOffset+3*dirEntSize], entry)

	ole, err := NewOLEFile(buf)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}

	d := ole.FindStreamByName("Workbook")
	if d == nil {
		t.Fatal("Workbook stream not found")
	}
	if d.Index != 2 {
		t.Fatalf("Workbook SID = %d, want 2", d.Index)
	}
	got := ole.GetStream(d.Index)
	if !bytes.HasPrefix(got, want) {
		t.Fatalf("GetStream(%d) = %q, want prefix %q", d.Index, got[:min(len(got), len(want))], want)
	}
}

func TestNewOLEFileRejectsMissingRootDirectory(t *testing.T) {
	buf := miniOLE(t, map[string][]byte{"Workbook": []byte("data")})

	const dirOffset = 2 * sectorSize
	buf[dirOffset+66] = 0 // root Mse: unallocated

	if _, err := NewOLEFile(buf); err == nil {
		t.Fatal("NewOLEFile succeeded with an unallocated root directory")
	}
}

func TestNewOLEFileRejectsUnexpectedMiniSectorShift(t *testing.T) {
	buf := miniOLE(t, map[string][]byte{"Workbook": []byte("data")})
	binary.LittleEndian.PutUint16(buf[32:], miniSectorShift+1)

	if _, err := NewOLEFile(buf); err == nil {
		t.Fatal("NewOLEFile succeeded with an invalid MiniSectorShift")
	}
}

func TestGetStreamCacheDoesNotAliasReturnedSlice(t *testing.T) {
	want := []byte("cache alias regression")
	buf := miniOLE(t, map[string][]byte{"Workbook": want})
	ole, err := NewOLEFile(buf)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	d := ole.FindStreamByName("Workbook")
	if d == nil {
		t.Fatal("Workbook stream not found")
	}

	first := ole.GetStream(d.Index)
	if !bytes.HasPrefix(first, want) {
		t.Fatalf("first GetStream = %q, want prefix %q", first[:min(len(first), len(want))], want)
	}
	first[0] ^= 0xFF

	second := ole.GetStream(d.Index)
	if !bytes.HasPrefix(second, want) {
		t.Fatalf("cache returned mutated data: got prefix %q want %q", second[:min(len(second), len(want))], want)
	}
}

func TestGetUintRejectsNegativeOffsetNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("getUint helper panicked on negative offset: %v", r)
		}
	}()

	offset := -1
	if got := getUint16([]byte{1, 2, 3, 4}, &offset); got != 0 {
		t.Fatalf("getUint16 with negative offset = %d, want 0", got)
	}
	if offset != -1 {
		t.Fatalf("getUint16 changed offset to %d, want -1", offset)
	}
	if got := getUint32([]byte{1, 2, 3, 4}, &offset); got != 0 {
		t.Fatalf("getUint32 with negative offset = %d, want 0", got)
	}
}

func TestExtractMacrosRejectsHugeModuleOffsetNoPanic(t *testing.T) {
	dirStream := vbaDirStreamWithModuleOffset(t, "Module1", 0xFFFFFFFF)
	projectStream := []byte("Module=Module1\n")
	codeStream := append([]byte{0x01}, uncompressedChunk()...)

	dirs := []*Directory{
		{Index: 0, Name: "PROJECT"},
		{Index: 1, Name: "dir"},
		{Index: 2, Name: "Module1"},
	}
	ole := &OLEFile{
		Directory: dirs,
		nameIdx: map[string]*Directory{
			"PROJECT": dirs[0],
			"dir":     dirs[1],
			"Module1": dirs[2],
		},
		streamCache: map[uint32][]byte{
			0: projectStream,
			1: compressedRawChunk(t, dirStream),
			2: codeStream,
		},
	}

	modules, err := ExtractMacros(ole)
	if err != nil {
		t.Fatalf("ExtractMacros: %v", err)
	}
	if len(modules) != 0 {
		t.Fatalf("ExtractMacros returned %d modules, want 0 for out-of-range offset", len(modules))
	}
}

// oleWithModule builds a minimal one-module VBA OLEFile whose module code
// stream decompresses to `payload`. Used to exercise the decompressed-output
// budget on the macro extractors.
func oleWithModule(t testing.TB, payload []byte) *OLEFile {
	t.Helper()
	dirStream := vbaDirStreamWithModuleOffset(t, "Module1", 0)
	projectStream := []byte("Module=Module1\n")
	codeStream := compressedRawChunk(t, payload)
	dirs := []*Directory{
		{Index: 0, Name: "PROJECT"},
		{Index: 1, Name: "dir"},
		{Index: 2, Name: "Module1"},
	}
	return &OLEFile{
		Directory: dirs,
		nameIdx: map[string]*Directory{
			"PROJECT": dirs[0],
			"dir":     dirs[1],
			"Module1": dirs[2],
		},
		streamCache: map[uint32][]byte{
			0: projectStream,
			1: compressedRawChunk(t, dirStream),
			2: codeStream,
		},
	}
}

// The legacy ExtractMacros / ExtractMacroBlobs compat APIs take no caller
// budget. They must still enforce a cumulative decompressed-output cap so a
// crafted multi-module project cannot amplify unbounded. Regression guard: the
// default total cap is non-zero (an earlier revision passed 0 = unbounded).
func TestLegacyExtractMacrosHasCumulativeCap(t *testing.T) {
	if MAX_TOTAL_DECOMPRESSED <= 0 {
		t.Fatalf("MAX_TOTAL_DECOMPRESSED = %d, want a positive cumulative cap", MAX_TOTAL_DECOMPRESSED)
	}

	payload := bytes.Repeat([]byte{0x41}, 64) // 64 cleartext bytes
	ole := oleWithModule(t, payload)

	mods, err := ExtractMacros(ole)
	if err != nil {
		t.Fatalf("ExtractMacros: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("ExtractMacros returned %d modules, want 1", len(mods))
	}
	if mods[0].Code != string(payload) {
		t.Fatalf("module code = %q, want %q (default cap must not truncate a 64-byte module)", mods[0].Code, payload)
	}
}

// A tight cumulative budget must truncate module output so the summed
// decompressed size cannot exceed the cap. This exercises the maxTotalBytes
// gate the legacy APIs now feed via MAX_TOTAL_DECOMPRESSED.
func TestExtractMacrosCumulativeBudgetTruncates(t *testing.T) {
	payload := bytes.Repeat([]byte{0x41}, 64)
	ole := oleWithModule(t, payload)

	mods, err := extractMacros(ole, false, MAX_DECOMPRESSED, 8) // 8-byte total budget
	if err != nil {
		t.Fatalf("extractMacros: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("got %d modules, want 1", len(mods))
	}
	if len(mods[0].CodeBytes) > 8 {
		t.Fatalf("module decompressed %d bytes, want <= 8 (cumulative budget must cap)", len(mods[0].CodeBytes))
	}
}

func TestParseFileRejectsOversizedOLEInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.doc")
	data := append([]byte(OLE_SIGNATURE), bytes.Repeat([]byte{0}, maxParseFileOLEBytes-len(OLE_SIGNATURE)+1)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFile(path); err == nil {
		t.Fatal("ParseFile accepted an oversized OLE input")
	}
}

func TestParseFileSkipsOversizedZipBin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.docm")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("word/vbaProject.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte{'A'}, maxParseFileBinBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	mods, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(mods) != 0 {
		t.Fatalf("oversized vbaProject.bin should be skipped, got %d modules", len(mods))
	}
}

func TestIsBinFileName(t *testing.T) {
	for _, name := range []string{"vbaProject.bin", "xl/VBAPROJECT.BIN", "a.bIn"} {
		if !isBinFileName(name) {
			t.Fatalf("isBinFileName(%q) = false", name)
		}
	}
	for _, name := range []string{"bin", "vbaProject.binary", "vbaProject.bin/evil"} {
		if isBinFileName(name) {
			t.Fatalf("isBinFileName(%q) = true", name)
		}
	}
}

func compressedRawChunk(t testing.TB, data []byte) []byte {
	t.Helper()
	if len(data) == 0 || len(data) > 4093 {
		t.Fatalf("test raw chunk length %d out of range", len(data))
	}
	out := make([]byte, 3, 3+len(data))
	out[0] = 0x01
	binary.LittleEndian.PutUint16(out[1:], 0x3000|uint16(len(data)-1))
	out = append(out, data...)
	return out
}

func vbaDirStreamWithModuleOffset(t testing.TB, moduleName string, moduleOffset uint32) []byte {
	t.Helper()
	var b bytes.Buffer
	putU16 := func(v uint16) {
		t.Helper()
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			t.Fatalf("write uint16: %v", err)
		}
	}
	putU32 := func(v uint32) {
		t.Helper()
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			t.Fatalf("write uint32: %v", err)
		}
	}
	putSizedString := func(s string) {
		putU32(uint32(len(s)))
		b.WriteString(s)
	}

	putU16(0x0001) // PROJECTSYSKIND
	putU32(0x0004)
	putU32(0x0001)
	putU16(0x0002) // PROJECTLCID
	putU32(0x0004)
	putU32(0x0409)
	putU16(0x0014) // PROJECTLCIDINVOKE
	putU32(0x0004)
	putU32(0x0409)
	putU16(0x0003) // PROJECTCODEPAGE
	putU32(0x0002)
	putU16(1252)
	putU16(0x0004) // PROJECTNAME
	putSizedString("P")
	putU16(0x0005) // PROJECTDOCSTRING
	putU32(0)
	putU16(0x0040)
	putU32(0)
	putU16(0x0006) // PROJECTHELPFILEPATH
	putU32(0)
	putU16(0x003D)
	putU32(0)
	putU16(0x0007) // PROJECTHELPCONTEXT
	putU32(0x0004)
	putU32(0)
	putU16(0x0008) // PROJECTLIBFLAGS
	putU32(0x0004)
	putU32(0)
	putU16(0x0009) // PROJECTVERSION
	putU32(0x0004)
	putU32(0)
	putU16(0)
	putU16(0x000F) // PROJECTMODULES
	putU32(0x0002)
	putU16(1)
	putU16(0x0013) // PROJECTCOOKIE
	putU32(0x0002)
	putU16(0)

	putU16(0x0019) // MODULENAME
	putSizedString(moduleName)
	putU16(0x001A) // MODULESTREAMNAME
	putSizedString(moduleName)
	putU16(0x0032)
	putU32(0)
	putU16(0x0031) // MODULEOFFSET
	putU32(0x0004)
	putU32(moduleOffset)
	putU16(0x002B) // TERMINATOR
	putU32(0)

	return b.Bytes()
}

// --- CFB structural hardening (codex-audit follow-up) ---

func TestNewOLEFileRejectsDuplicateFatRef(t *testing.T) {
	data := miniOLE(t, map[string][]byte{"s": []byte("x")})
	// Declare a second header FAT entry duplicating sector 0.
	binary.LittleEndian.PutUint32(data[44:], 2) // CsectFat = 2
	binary.LittleEndian.PutUint32(data[80:], 0) // SectFat[1] = 0 (dup)
	if _, err := NewOLEFile(data); err == nil {
		t.Fatal("duplicate FAT sector reference was not rejected")
	}
}

func TestNewOLEFileHonorsCsectFatCount(t *testing.T) {
	data := miniOLE(t, map[string][]byte{"s": []byte("x")})
	// Junk beyond the declared count must be ignored, not dereferenced.
	binary.LittleEndian.PutUint32(data[80:], 0) // SectFat[1] = 0 (dup, but unused)
	ole, err := NewOLEFile(data)
	if err != nil {
		t.Fatalf("junk SectFat entry beyond CsectFat broke parsing: %v", err)
	}
	if got, err := ole.OpenStreamByName("s"); err != nil || len(got) == 0 {
		t.Fatalf("stream lost: %v", err)
	}
}

func TestNewOLEFileRejectsImpossibleCsectFat(t *testing.T) {
	data := miniOLE(t, map[string][]byte{"s": []byte("x")})
	binary.LittleEndian.PutUint32(data[44:], 0xFFFF) // CsectFat >> file sectors
	if _, err := NewOLEFile(data); err == nil {
		t.Fatal("impossible CsectFat was not rejected")
	}
}

func TestNewOLEFileRejectsFatSectorOutOfRange(t *testing.T) {
	data := miniOLE(t, map[string][]byte{"s": []byte("x")})
	binary.LittleEndian.PutUint32(data[76:], 0x00FFFFFF) // SectFat[0] beyond EOF
	if _, err := NewOLEFile(data); err == nil {
		t.Fatal("out-of-range FAT sector ID was not rejected")
	}
}

func TestNewOLEFileRejectsUnnecessaryDif(t *testing.T) {
	data := miniOLE(t, map[string][]byte{"s": []byte("x")})
	// CsectDif stays 0 but the start points at a real sector.
	binary.LittleEndian.PutUint32(data[68:], 0) // SectDifStart = sector 0
	if _, err := NewOLEFile(data); err == nil {
		t.Fatal("DIF start with zero declared DIF count was not rejected")
	}
}

func TestNewOLEFileStopsDifAtDeclaredCount(t *testing.T) {
	base := miniOLE(t, map[string][]byte{"s": []byte("x")})
	// Append one DIF sector that points at itself: an unbounded walk would
	// loop; honoring CsectDif=1 stops after the first sector.
	difSect := uint32(len(base)/512 - 1) // ID of the appended sector
	dif := make([]byte, 512)
	for off := 0; off < 512; off += 4 {
		binary.LittleEndian.PutUint32(dif[off:], FREESECT)
	}
	binary.LittleEndian.PutUint32(dif[508:], difSect) // next = itself
	data := append(append([]byte(nil), base...), dif...)
	binary.LittleEndian.PutUint32(data[68:], difSect) // SectDifStart
	binary.LittleEndian.PutUint32(data[72:], 1)       // CsectDif = 1
	ole, err := NewOLEFile(data)
	if err != nil {
		t.Fatalf("bounded DIF walk failed: %v", err)
	}
	if got, err := ole.OpenStreamByName("s"); err != nil || len(got) == 0 {
		t.Fatalf("stream lost: %v", err)
	}
}

func TestDirectoryNameHonorsCB(t *testing.T) {
	entry := make([]byte, 128)
	name := utf16leEncode("dir")
	copy(entry[0:], name)                                          // "dir" + NUL at units 0-3
	copy(entry[8:], utf16leEncode("JUNK"))                         // junk after terminator
	binary.LittleEndian.PutUint16(entry[64:], uint16(len(name)+2)) // CB incl. terminator
	entry[66] = 2                                                  // stream
	d, err := NewDirectory(entry, 1)
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}
	if d.Name != "dir" {
		t.Fatalf("junk after CB terminator leaked into name: %q", d.Name)
	}
}

func TestDirectoryNameNonSpecCBFallback(t *testing.T) {
	// CB omitting the terminator (historical fixtures) must still resolve.
	entry := make([]byte, 128)
	name := utf16leEncode("dir")
	copy(entry[0:], name)
	binary.LittleEndian.PutUint16(entry[64:], uint16(len(name))) // no terminator
	entry[66] = 2
	d, err := NewDirectory(entry, 1)
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}
	if d.Name != "dir" {
		t.Fatalf("non-spec CB fallback broken: %q", d.Name)
	}
}

func TestGetStreamIgnoresHeaderMiniSectorCutoff(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 4096) // FAT-resident (== cutoff)
	data := miniOLE(t, map[string][]byte{"s": payload})
	// Hostile header cutoff would misroute the read through the mini stream.
	binary.LittleEndian.PutUint32(data[56:], 0x10000)
	ole, err := NewOLEFile(data)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	got, err := ole.OpenStreamByName("s")
	if err != nil {
		t.Fatalf("OpenStreamByName: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("stream misread under hostile MiniSectorCutoff: %d bytes", len(got))
	}
}

func TestDirectoryStreamSizeV3HighBitsMasked(t *testing.T) {
	data := miniOLE(t, map[string][]byte{"s": []byte("x")})
	// Poison the high 32 bits of the stream entry's 8-byte size field.
	// miniOLE layout: header sector 0, FAT sector 0 at 512, directory at 1024;
	// entry 1 is the stream.
	dirEntry := 1024 + 128
	binary.LittleEndian.PutUint32(data[dirEntry+124:], 0xDEADBEEF)
	ole, err := NewOLEFile(data)
	if err != nil {
		t.Fatalf("v3 high size bits not masked: %v", err)
	}
	d := ole.FindStreamByName("s")
	if d == nil || d.Header.Size>>32 != 0 {
		t.Fatalf("v3 size mask missing: %#x", d.Header.Size)
	}
}
