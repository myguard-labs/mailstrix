package ci_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// The producer in internal/extract/rc4md5_fixture_test.go verifies these bytes
// against its independent #384 reference encryptor on every test run.
func rc4MD5BIFFFixture(t *testing.T) []byte {
	t.Helper()
	buf, err := os.ReadFile("testdata/rc4md5-biff.xls")
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func hasExactExtractStream(streams [][]byte, want string) bool {
	for _, stream := range streams {
		if bytes.Equal(stream, []byte(want)) {
			return true
		}
	}
	return false
}

// TestRC4MD5PublicOLEExtraction proves the full open/verifier/decrypt/BIFF
// path. The hidden sheet starts at the 1024-byte RC4 rekey boundary, and its
// name is absent from the OLE ciphertext. Clear BIFF header and lbPlyPos bytes
// discriminate this fixture from an encrypted raw stream.
func TestRC4MD5PublicOLEExtraction(t *testing.T) {
	fixture := rc4MD5BIFFFixture(t)
	const sheet = "XLM-HIDDEN-MACROSHEET hidden RC4SecretSheet"
	const boundSheetOffset = 3*512 + 1024
	if !bytes.Equal(fixture[boundSheetOffset:boundSheetOffset+8], []byte{0x85, 0, 0x16, 0, 0x12, 0x34, 0x56, 0x78}) {
		t.Fatal("fixture lacks clear BoundSheet8 header and lbPlyPos at 1024-byte rekey boundary")
	}
	if bytes.Contains(fixture, []byte("RC4SecretSheet")) {
		t.Fatal("encrypted OLE fixture contains plaintext sheet name")
	}
	got := extract.Extract(fixture, time.Time{})
	if !got.IsDoc || !got.Encrypted || got.Panicked {
		t.Fatalf("public OLE flags: IsDoc=%t Encrypted=%t Panicked=%t", got.IsDoc, got.Encrypted, got.Panicked)
	}
	if !hasExactExtractStream(got.Markers, "DEFAULTPW-DECRYPTED") || !hasExactExtractStream(got.Streams, sheet) {
		t.Fatalf("public Extract omitted decrypted plaintext or marker: streams=%q markers=%q", got.Streams, got.Markers)
	}
}

func TestRC4MD5PublicOLEWrongVerifier(t *testing.T) {
	fixture := rc4MD5BIFFFixture(t)
	// CFB header, FAT, directory, then Workbook. Its BOF is 12 bytes;
	// FILEPASS header is 4 bytes and the encrypted hash starts at body +38.
	const encryptedHashOffset = 3*512 + 12 + 4 + 38
	fixture[encryptedHashOffset] ^= 0x80
	got := extract.Extract(fixture, time.Time{})
	if !got.IsDoc || !got.Encrypted || got.Panicked {
		t.Fatalf("wrong-verifier OLE flags: IsDoc=%t Encrypted=%t Panicked=%t", got.IsDoc, got.Encrypted, got.Panicked)
	}
	if hasExactExtractStream(got.Markers, "DEFAULTPW-DECRYPTED") || hasExactExtractStream(got.Streams, "XLM-HIDDEN-MACROSHEET hidden RC4SecretSheet") {
		t.Fatalf("wrong verifier emitted decrypted content: streams=%q markers=%q", got.Streams, got.Markers)
	}
}

func TestRC4MD5PublicOLEMalformedRecord(t *testing.T) {
	fixture := rc4MD5BIFFFixture(t)
	const boundSheetOffset = 3*512 + 1024
	// The clear BoundSheet8 size now exceeds the 4096-byte Workbook stream.
	fixture[boundSheetOffset+2] = 0xff
	fixture[boundSheetOffset+3] = 0xff
	got := extract.Extract(fixture, time.Time{})
	if !got.IsDoc || !got.Encrypted || got.Panicked {
		t.Fatalf("malformed BIFF flags: IsDoc=%t Encrypted=%t Panicked=%t", got.IsDoc, got.Encrypted, got.Panicked)
	}
	if !hasExactExtractStream(got.Markers, "DEFAULTPW-DECRYPTED") || hasExactExtractStream(got.Streams, "XLM-HIDDEN-MACROSHEET hidden RC4SecretSheet") {
		t.Fatalf("malformed BoundSheet8 record should preserve the decrypted prefix only: streams=%q markers=%q", got.Streams, got.Markers)
	}
}

func TestRC4MD5PublicOLEMalformedTailKeepsSheet(t *testing.T) {
	fixture := rc4MD5BIFFFixture(t)
	const followingRecordOffset = 3*512 + 1024 + 4 + 22
	// Corrupt the record after BoundSheet8. Its clear length now exceeds the
	// Workbook stream, but the already decrypted sheet must remain visible.
	fixture[followingRecordOffset+2] = 0xff
	fixture[followingRecordOffset+3] = 0xff
	got := extract.Extract(fixture, time.Time{})
	if !hasExactExtractStream(got.Markers, "DEFAULTPW-DECRYPTED") || !hasExactExtractStream(got.Streams, "XLM-HIDDEN-MACROSHEET hidden RC4SecretSheet") {
		t.Fatalf("malformed BIFF tail hid a decrypted sheet: streams=%q markers=%q", got.Streams, got.Markers)
	}
}
