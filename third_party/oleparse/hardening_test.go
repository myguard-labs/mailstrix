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
