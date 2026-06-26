package extract

import (
	"encoding/binary"
	"testing"
	"time"
)

// biffRecord builds a BIFF record: u16 type, u16 len, body.
func biffRecord(typ uint16, body []byte) []byte {
	b := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint16(b[0:], typ)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(body)))
	copy(b[4:], body)
	return b
}

// workbookWithFilepass returns a minimal Workbook stream: BOF then a FILEPASS
// (0x2F) record whose first word is the encryption type.
func workbookWithFilepass(encType uint16) []byte {
	bof := biffRecord(0x0809, []byte{0x00, 0x06, 0x05, 0x00}) // BOF, dt=workbook globals
	fp := make([]byte, 2)
	binary.LittleEndian.PutUint16(fp, encType)
	return append(bof, biffRecord(0x002F, fp)...)
}

func TestEncTypeXOR(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "Workbook", mse: 2, data: workbookWithFilepass(0), // 0 = XOR
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if !streamHasNeedle(&res, "ENCRYPTION-XOR") {
		t.Fatalf("XOR FILEPASS not classified; streams=%d", len(res.Streams))
	}
	if !res.Encrypted {
		t.Errorf("Encrypted flag not set on FILEPASS")
	}
}

func TestEncTypeRC4(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "Workbook", mse: 2, data: workbookWithFilepass(1), // 1 = RC4
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if !streamHasNeedle(&res, "ENCRYPTION-RC4") {
		t.Fatalf("RC4 FILEPASS not classified; streams=%d", len(res.Streams))
	}
	if streamHasNeedle(&res, "ENCRYPTION-XOR") {
		t.Errorf("RC4 misclassified as XOR")
	}
}

// A workbook with no FILEPASS must not emit any encryption marker.
func TestEncTypeUnencrypted(t *testing.T) {
	wb := append(biffRecord(0x0809, []byte{0x00, 0x06, 0x05, 0x00}),
		biffRecord(0x000A, nil)...) // BOF then EOF, no FILEPASS
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "Workbook", mse: 2, data: wb,
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if streamHasNeedle(&res, "ENCRYPTION-") {
		t.Fatalf("unencrypted workbook falsely flagged encrypted")
	}
}

// A _signatures storage is surfaced as DIGITAL-SIGNATURE.
func TestDigSig(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "_signatures", mse: 1, // storage
			left: cfbFree, right: 2, child: cfbFree, linksSet: true},
		{name: "Workbook", mse: 2, data: []byte("just a plain workbook stream body padding"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if !streamHasNeedle(&res, "DIGITAL-SIGNATURE") {
		t.Fatalf("_signatures storage not surfaced; streams=%d", len(res.Streams))
	}
}

// A doc with no signature storage does not emit the marker.
func TestDigSigAbsent(t *testing.T) {
	var res Result
	fromOLEDigSig(nil, &res, time.Time{}) // nil must not panic
	if len(res.Streams) != 0 {
		t.Fatalf("nil OLE produced streams: %d", len(res.Streams))
	}
}

// wordDocStream builds a minimal WordDocument stream whose FibBase flags word
// (offset 10) is set to flags. wIdent 0xA5EC is always written at offset 0.
func wordDocStream(flags uint16) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint16(b[0:], 0xA5EC) // wIdent
	binary.LittleEndian.PutUint16(b[10:], flags) // flags (fEncrypted = bit 0x0100)
	return b
}

// TestWordFibEncrypted: a WordDocument stream with fEncrypted set emits ENCRYPTION-RC4.
func TestWordFibEncrypted(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "WordDocument", mse: 2, data: wordDocStream(0x0100), // fEncrypted
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if !streamHasNeedle(&res, "ENCRYPTION-RC4") {
		t.Fatalf("fEncrypted FibBase not detected; streams=%v", streamsAsStrings(res))
	}
	if !res.Encrypted {
		t.Errorf("Encrypted flag not set on fEncrypted FibBase")
	}
}

// TestWordFibUnencrypted: WordDocument with fEncrypted=0 must not emit encryption marker.
func TestWordFibUnencrypted(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "WordDocument", mse: 2, data: wordDocStream(0x0000),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if streamHasNeedle(&res, "ENCRYPTION-RC4") || streamHasNeedle(&res, "ENCRYPTION-XOR") {
		t.Fatalf("unencrypted WordDocument falsely flagged encrypted; streams=%v", streamsAsStrings(res))
	}
}

// TestWordFibBadIdent: a stream with wrong wIdent (not 0xA5EC) must not emit marker.
func TestWordFibBadIdent(t *testing.T) {
	wd := wordDocStream(0x0100)
	binary.LittleEndian.PutUint16(wd[0:], 0x1234) // wrong ident
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "WordDocument", mse: 2, data: wd,
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if streamHasNeedle(&res, "ENCRYPTION-RC4") {
		t.Fatalf("bad wIdent accepted; streams=%v", streamsAsStrings(res))
	}
}

// TestPPTEncryptedSummary: OLE2 with EncryptedSummary storage emits ENCRYPTION-RC4.
func TestPPTEncryptedSummary(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "EncryptedSummary", mse: 2, data: []byte("enc summary stub data"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if !streamHasNeedle(&res, "ENCRYPTION-RC4") {
		t.Fatalf("EncryptedSummary storage not detected; streams=%v", streamsAsStrings(res))
	}
	if !res.Encrypted {
		t.Errorf("Encrypted flag not set on EncryptedSummary")
	}
}

// TestPPTEncryptedSummaryAbsent: OLE2 without EncryptedSummary does not emit marker.
func TestPPTEncryptedSummaryAbsent(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "PowerPoint Document", mse: 2, data: []byte("ppt stub data"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	if streamHasNeedle(&res, "ENCRYPTION-RC4") {
		t.Fatalf("plain PPT falsely flagged encrypted; streams=%v", streamsAsStrings(res))
	}
}
