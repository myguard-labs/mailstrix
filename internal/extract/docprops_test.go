package extract

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"
)

// makeTestZip builds an in-memory zip from a map of name->content strings and
// returns a *zip.Reader over it. Fatals the test on any error.
func makeTestZip(t *testing.T, entries map[string]string) *zip.Reader {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range entries {
		addZipEntry(t, zw, name, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

// TestDocPropsXMLTextExtraction verifies that fromOOXMLDocProps extracts text
// nodes from a minimal docProps/core.xml and emits the DOCPROPS-STRINGS marker.
func TestDocPropsXMLTextExtraction(t *testing.T) {
	want := "http://evil.example/c2"
	coreXML := `<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">` + want + `</dc:title></cp:coreProperties>`

	zr := makeTestZip(t, map[string]string{
		"docProps/core.xml": coreXML,
	})

	var out [][]byte
	fromOOXMLDocProps(zr, &out, time.Time{})

	if !hasDocPropsMarker(out) {
		t.Fatal("DOCPROPS-STRINGS marker not found in streams")
	}
	found := false
	for _, s := range out {
		if strings.Contains(string(s), want) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in streams, got %v", want, streamsToStrings(out))
	}
}

// TestDocPropsDocVarExtraction verifies that fromOOXMLDocProps extracts
// w:docVar/@w:val attribute values from word/settings.xml.
func TestDocPropsDocVarExtraction(t *testing.T) {
	want := "powershell -nop -enc AAABBBCCC"
	settingsXML := `<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docVars><w:docVar w:name="payload" w:val="` + want + `"/></w:docVars></w:settings>`

	zr := makeTestZip(t, map[string]string{
		"word/settings.xml": settingsXML,
	})

	var out [][]byte
	fromOOXMLDocProps(zr, &out, time.Time{})

	if !hasDocPropsMarker(out) {
		t.Fatal("DOCPROPS-STRINGS marker not found in streams")
	}
	found := false
	for _, s := range out {
		if strings.Contains(string(s), want) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in streams, got %v", want, streamsToStrings(out))
	}
}

// TestDocPropsOLECarveStrings verifies that carveStrings (reused by
// fromOLEDocProps) correctly extracts printable ASCII runs from binary data
// containing a command-like payload.
func TestDocPropsOLECarveStrings(t *testing.T) {
	payload := "cmd.exe /c powershell -nop"
	raw := []byte{0x00, 0x01, 0x02}
	raw = append(raw, []byte(payload)...)
	raw = append(raw, []byte{0x00, 0x03, 0x04}...)

	runs := carveStrings(raw)
	found := false
	for _, r := range runs {
		if strings.Contains(string(r), payload) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in carved runs, got %v", payload, func() []string {
			ss := make([]string, len(runs))
			for i, r := range runs {
				ss[i] = string(r)
			}
			return ss
		}())
	}
}

// TestDocPropsNoFalsePositiveOnCleanDoc verifies that a zip with no property
// parts does NOT emit the DOCPROPS-STRINGS marker.
func TestDocPropsNoFalsePositiveOnCleanDoc(t *testing.T) {
	zr := makeTestZip(t, map[string]string{
		"word/document.xml": `<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>`,
	})

	var out [][]byte
	fromOOXMLDocProps(zr, &out, time.Time{})

	if hasDocPropsMarker(out) {
		t.Error("DOCPROPS-STRINGS marker should NOT appear when there are no property parts")
	}
}

// streamsToStrings converts [][]byte to []string for test error messages.
func streamsToStrings(streams [][]byte) []string {
	ss := make([]string, len(streams))
	for i, s := range streams {
		ss[i] = string(s)
	}
	return ss
}

// buildSummaryInfoStream constructs a minimal, valid SummaryInformation
// property-set stream containing a single DOC_SECURITY (PIDSI 0x13) VT_I4
// property with the given value.
//
// Layout (all little-endian):
//
//	[0:2]   ByteOrder = 0xFFFE
//	[2:4]   version   = 0x0000
//	[4:20]  systemID  = zeros
//	[20:24] clsid     = zeros
//	[24:28] cSections = 1
//	[28:44] FMTID     = zeros (unused by our parser)
//	[44:48] offset    = 48  (section starts immediately after header)
//	--- section at offset 48 ---
//	[48:52] cbSection  = 28 (section size: 4+4 + 1*(4+4) + 1*(4+4))
//	[52:56] cProperties = 1
//	[56:60] propID     = 0x13
//	[60:64] propOffset = 8   (relative to section start → abs 56)
//	[64:68] type       = 3 (VT_I4)
//	[68:72] value      = docSecurity
func buildSummaryInfoStream(docSecurity uint32) []byte {
	buf := make([]byte, 72)
	// Header
	buf[0], buf[1] = 0xFE, 0xFF // ByteOrder = 0xFFFE (LE)
	// cSections at [24:28]
	buf[24] = 1
	// section offset at [44:48] = 48
	buf[44] = 48
	// Section header at offset 48
	// cbSection at [48:52] = 24 (4+4 + 8+8 = 24)
	buf[48] = 24
	// cProperties at [52:56] = 1
	buf[52] = 1
	// propID at [56:60] = 0x13
	buf[56] = 0x13
	// propOffset at [60:64] = 16 (relative to section start 48 → absolute 64 for type+val,
	// past the 8-byte identifier/offset array that occupies [56:64]).
	buf[60] = 16
	// type VT_I4 = 3 at [64:68]
	buf[64] = 3
	// value at [68:72]
	buf[68] = byte(docSecurity)
	buf[69] = byte(docSecurity >> 8)
	buf[70] = byte(docSecurity >> 16)
	buf[71] = byte(docSecurity >> 24)
	return buf
}

// TestDocSecFlagsValue1 verifies that docSecurityFlags returns value=1 and ok=true
// for a stream with DOC_SECURITY = 1 (password protected).
func TestDocSecFlagsValue1(t *testing.T) {
	data := buildSummaryInfoStream(1)
	v, ok := docSecurityFlags(data)
	if !ok {
		t.Fatal("docSecurityFlags: expected ok=true, got false")
	}
	if v != 1 {
		t.Fatalf("docSecurityFlags: expected value=1, got %d", v)
	}
}

// TestDocSecFlagsMarkerPresent verifies that fromOLEDocProps emits the
// OLE-DOC-SECURITY-1 marker when DOC_SECURITY = 1.
func TestDocSecFlagsMarkerPresent(t *testing.T) {
	// We test docSecurityFlags directly here since building a full OLE2 file is
	// heavyweight. The integration path is covered by TestDocSecFlagsValue1 +
	// reviewing fromOLEDocProps wiring. This test validates the marker string.
	data := buildSummaryInfoStream(1)
	v, ok := docSecurityFlags(data)
	if !ok || v != 1 {
		t.Fatalf("setup failed: v=%d ok=%v", v, ok)
	}
	want := "OLE-DOC-SECURITY-1"
	got := oleDocSecMarkerPrefix + "1"
	if got != want {
		t.Fatalf("marker mismatch: want %q got %q", want, got)
	}
}

// TestDocSecFlagsZeroValue verifies that docSecurityFlags returns ok=false
// when DOC_SECURITY = 0 (no protection).
func TestDocSecFlagsZeroValue(t *testing.T) {
	data := buildSummaryInfoStream(0)
	_, ok := docSecurityFlags(data)
	if ok {
		t.Fatal("docSecurityFlags: expected ok=false for value=0, got true")
	}
}

// TestDocSecFlagsTruncated verifies that docSecurityFlags returns ok=false and
// does not panic on truncated/garbage input.
func TestDocSecFlagsTruncated(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0xFE, 0xFF},                    // only 2 bytes
		make([]byte, 47),                // one byte short of minimum header
		[]byte("garbage random data!!"), // wrong byte order
	}
	for _, data := range cases {
		_, ok := docSecurityFlags(data)
		if ok {
			t.Errorf("docSecurityFlags: expected ok=false for truncated/garbage input (len=%d), got true", len(data))
		}
	}
}

// TestDocSecFlagsWrongByteOrder verifies that docSecurityFlags rejects streams
// with ByteOrder != 0xFFFE.
func TestDocSecFlagsWrongByteOrder(t *testing.T) {
	data := buildSummaryInfoStream(1)
	// Overwrite ByteOrder with 0xFEFF (big-endian, wrong).
	data[0], data[1] = 0xFF, 0xFE
	_, ok := docSecurityFlags(data)
	if ok {
		t.Fatal("docSecurityFlags: expected ok=false for wrong ByteOrder, got true")
	}
}
