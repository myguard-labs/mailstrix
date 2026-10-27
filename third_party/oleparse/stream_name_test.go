package oleparse

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func utf16LE(s string) []byte {
	words := utf16.Encode([]rune(s))
	out := make([]byte, len(words)*2)
	for i, word := range words {
		binary.LittleEndian.PutUint16(out[i*2:], word)
	}
	return out
}

func vbaDirStreamWithNames(t testing.TB, ansiName, unicodeName []byte, codePage uint16) []byte {
	t.Helper()
	dir := vbaDirStreamWithModuleOffset(t, "Module1", 0)

	codePageRecord := []byte{0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0xe4, 0x04}
	codePageAt := bytes.Index(dir, codePageRecord)
	if codePageAt < 0 {
		t.Fatal("PROJECTCODEPAGE record not found in test fixture")
	}
	binary.LittleEndian.PutUint16(dir[codePageAt+6:], codePage)

	var oldRecord bytes.Buffer
	if err := binary.Write(&oldRecord, binary.LittleEndian, uint16(0x001A)); err != nil {
		t.Fatalf("write old stream-name id: %v", err)
	}
	if err := binary.Write(&oldRecord, binary.LittleEndian, uint32(len("Module1"))); err != nil {
		t.Fatalf("write old stream-name size: %v", err)
	}
	oldRecord.WriteString("Module1")
	if err := binary.Write(&oldRecord, binary.LittleEndian, uint16(0x0032)); err != nil {
		t.Fatalf("write old stream-name reserved: %v", err)
	}
	if err := binary.Write(&oldRecord, binary.LittleEndian, uint32(0)); err != nil {
		t.Fatalf("write old Unicode stream-name size: %v", err)
	}

	var newRecord bytes.Buffer
	put := func(value any) {
		t.Helper()
		if err := binary.Write(&newRecord, binary.LittleEndian, value); err != nil {
			t.Fatalf("write stream-name record: %v", err)
		}
	}
	put(uint16(0x001A))
	put(uint32(len(ansiName)))
	newRecord.Write(ansiName)
	put(uint16(0x0032))
	put(uint32(len(unicodeName)))
	newRecord.Write(unicodeName)

	if !bytes.Contains(dir, oldRecord.Bytes()) {
		t.Fatal("MODULESTREAMNAME record not replaced in test fixture")
	}
	return bytes.Replace(dir, oldRecord.Bytes(), newRecord.Bytes(), 1)
}

func oleWithStreamNames(t testing.TB, ansiName, unicodeName []byte, codePage uint16, directoryName string) *OLEFile {
	t.Helper()
	ole := oleWithModule(t, []byte("Sub Test()\nEnd Sub\n"))
	ole.streamCache[1] = compressedRawChunk(t, vbaDirStreamWithNames(t, ansiName, unicodeName, codePage))
	delete(ole.nameIdx, "Module1")
	ole.Directory[2].Name = directoryName
	ole.nameIdx[directoryName] = ole.Directory[2]
	return ole
}

func TestExtractMacrosFindsUnicodeAndCodePageStreamNames(t *testing.T) {
	tests := []struct {
		name          string
		ansiName      []byte
		unicodeName   []byte
		codePage      uint16
		directoryName string
		wantModules   int
	}{
		{name: "ASCII", ansiName: []byte("Module1"), unicodeName: utf16LE("Module1"), codePage: 1252, directoryName: "Module1", wantModules: 1},
		{name: "accented Unicode", ansiName: []byte{'C', 'a', 'f', 0xe9}, unicodeName: utf16LE("Café"), codePage: 1252, directoryName: "Café", wantModules: 1},
		{name: "non-Latin Unicode", ansiName: []byte("Module1"), unicodeName: utf16LE("漢字"), codePage: 1252, directoryName: "漢字", wantModules: 1},
		{name: "code-page ANSI fallback", ansiName: []byte{'C', 'a', 'f', 0xe9}, unicodeName: utf16LE("Missing"), codePage: 1252, directoryName: "Café", wantModules: 1},
		{name: "absent exact stream", ansiName: []byte("Missing"), unicodeName: utf16LE("Missing"), codePage: 1252, directoryName: "Module1"},
		{name: "case remains exact", ansiName: []byte("module1"), unicodeName: utf16LE("module1"), codePage: 1252, directoryName: "Module1"},
		{name: "malformed Unicode name falls back", ansiName: []byte("Module1"), unicodeName: []byte{0x41}, codePage: 1252, directoryName: "Module1", wantModules: 1},
		{name: "unsupported code page falls back", ansiName: []byte("Module1"), codePage: 42, directoryName: "Module1", wantModules: 1},
		{name: "malformed UTF-8 falls back", ansiName: []byte{0xff}, codePage: 65001, directoryName: string([]byte{0xff}), wantModules: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ole := oleWithStreamNames(t, test.ansiName, test.unicodeName, test.codePage, test.directoryName)
			modules, err := ExtractMacros(ole)
			if err != nil {
				t.Fatalf("ExtractMacros: %v", err)
			}
			if len(modules) != test.wantModules {
				t.Fatalf("ExtractMacros returned %d modules, want %d", len(modules), test.wantModules)
			}
		})
	}
}

func TestFindModuleStreamPrefersExactUnicodeName(t *testing.T) {
	unicodeDirectory := &Directory{Index: 1, Name: "UnicodeName"}
	ansiDirectory := &Directory{Index: 2, Name: "AnsiName"}
	ole := &OLEFile{nameIdx: map[string]*Directory{
		unicodeDirectory.Name: unicodeDirectory,
		ansiDirectory.Name:    ansiDirectory,
	}}

	got := ole.findModuleStream(utf16LE(unicodeDirectory.Name), []byte(ansiDirectory.Name), 1252)
	if got != unicodeDirectory {
		t.Fatalf("findModuleStream returned %#v, want exact Unicode directory %#v", got, unicodeDirectory)
	}
}

func TestDecodeANSIStreamNameRejectsMalformedUTF8(t *testing.T) {
	if _, err := decodeANSIStreamName([]byte{0xff}, 65001); err == nil {
		t.Fatal("decodeANSIStreamName error = nil, want malformed UTF-8 error")
	}
}
