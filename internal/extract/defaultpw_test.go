package extract

// defaultpw_test.go — tests for VelvetSweatshop XOR decryption helpers.
//
// Key-index formula (from Python reference): an encrypted run of N bytes
// starting at stream position P uses xorArray[(P+N+j) % 16] for the j-th byte
// (0-indexed). Cleartext bytes advance streamPos but do not consume key bytes.
//
// The hard test vector is: verifyXORPassword("VelvetSweatshop", 0x9a0a) == true.
// This value comes directly from the oletools doctest comment in
// xor_obfuscation.py: `(key,) = unpack('<H', b'\x0A\x9A')  # 0x9a0a`.

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Hard test vector — must never be removed.

// TestVerifyXORPassword_HardVector asserts the known-good test vector from
// the oletools Python doctest. This is a ground-truth check: if it fails, the
// verifypw port is wrong.
//
//	from struct import unpack
//	(key,) = unpack('<H', b'\x0A\x9A')  # 0x9a0a
//	DocumentXOR.verifypw('VelvetSweatshop', key)  # True
func TestVerifyXORPassword_HardVector(t *testing.T) {
	if !verifyXORPassword("VelvetSweatshop", 0x9a0a) {
		t.Fatal("HARD VECTOR FAILED: verifyXORPassword(\"VelvetSweatshop\", 0x9a0a) must be true")
	}
}

// ---------------------------------------------------------------------------
// Helpers to build minimal BIFF8 streams for round-trip testing.

// biffBOF returns a minimal BIFF8 BOF record (type 0x0809, 8-byte payload).
// BOF is a cleartext record: header (4) + body (8) = 12 bytes total.
func biffBOF() []byte {
	p := make([]byte, 8)
	binary.LittleEndian.PutUint16(p[0:], 0x0600) // vers = BIFF8
	binary.LittleEndian.PutUint16(p[2:], 0x0010) // dt = workbook globals
	return biffRecord(0x0809, p)
}

// biffFilePasXOR returns a FILEPASS record with wEncryptionType=0 and the
// given key/verifier words (MS-XLS 2.4.117 Method1 body).
func biffFilePasXOR(xorKey, verifier uint16) []byte {
	p := make([]byte, 6)
	binary.LittleEndian.PutUint16(p[0:], 0x0000)   // wEncryptionType = XOR
	binary.LittleEndian.PutUint16(p[2:], xorKey)   // key word
	binary.LittleEndian.PutUint16(p[4:], verifier) // password verifier
	return biffRecord(0x002F, p)
}

// encryptBIFFBody encrypts a record body for round-trip testing.
//
// MS-OFFCRYPTO §2.3.7.2: decrypt = ror8(cipher ^ xorArray[idx], 5).
// Encryption is the exact inverse: cipher = xorArray[idx] ^ rol8(plain, 5).
//
// bodyStart is the absolute stream position of the first body byte (i.e.
// after the 4-byte record header). The j-th body byte uses xorArray[(bodyStart+j)%16].
func encryptBIFFBody(plain []byte, xorArray [16]byte, bodyStart int) []byte {
	out := make([]byte, len(plain))
	for j, b := range plain {
		idx := (bodyStart + j) % 16
		out[j] = xorArray[idx] ^ rol8(b, 5)
	}
	return out
}

// ---------------------------------------------------------------------------
// Tests for verifyXORPassword.

func TestVerifyXORPassword_WrongPasswordRejected(t *testing.T) {
	if verifyXORPassword("wrongpassword", 0x9a0a) {
		t.Fatal("wrong password must not verify against VelvetSweatshop verifier")
	}
}

func TestVerifyXORPassword_EmptyPasswordRejected(t *testing.T) {
	// Empty password returns false unconditionally.
	if verifyXORPassword("", 0x9a0a) {
		t.Fatal("empty password must not match VelvetSweatshop verifier")
	}
}

func TestVerifyXORPassword_SelfConsistent(t *testing.T) {
	// Compute a verifier independently using the same algorithm, then verify.
	v := computeVerifierForTest("VelvetSweatshop")
	if !verifyXORPassword("VelvetSweatshop", v) {
		t.Fatalf("self-consistency check failed: computed verifier 0x%04x rejected", v)
	}
}

// computeVerifierForTest is an independent re-implementation of the Python
// DocumentXOR.verifypw algorithm for use as a test oracle.
// It does NOT call verifyXORPassword — it reimplements the Python loop.
func computeVerifierForTest(password string) uint16 {
	if len(password) == 0 || len(password) > 15 {
		return 0
	}
	// Build password_array = [len(password)] + [ord(ch) for ch in password]
	arr := make([]int, len(password)+1)
	arr[0] = len(password)
	for i, ch := range password {
		arr[i+1] = int(ch)
	}
	// Reverse.
	for i, j := 0, len(arr)-1; i < j; i, j = i+1, j-1 {
		arr[i], arr[j] = arr[j], arr[i]
	}

	verifier := 0
	for _, b := range arr {
		var intermediate1 int
		if verifier&0x4000 != 0 {
			intermediate1 = 1
		}
		intermediate2 := (verifier * 2) & 0x7FFF
		verifier = (intermediate1 ^ intermediate2) ^ b
	}
	return uint16(verifier ^ 0xCE4B)
}

// ---------------------------------------------------------------------------
// Tests for createXORArrayMethod1.

func TestCreateXORArrayMethod1_Deterministic(t *testing.T) {
	k1 := createXORArrayMethod1(velvetPassword)
	k2 := createXORArrayMethod1(velvetPassword)
	if k1 != k2 {
		t.Fatalf("createXORArrayMethod1 not deterministic: %x vs %x", k1, k2)
	}
}

func TestCreateXORArrayMethod1_DifferentPasswords(t *testing.T) {
	k1 := createXORArrayMethod1(velvetPassword)
	k2 := createXORArrayMethod1("wrong")
	if k1 == k2 {
		t.Fatal("different passwords must produce different xor arrays")
	}
}

func TestCreateXORArrayMethod1_LenClamped(t *testing.T) {
	long := "VelvetSweatshopX"
	clamped := long[:15]
	k1 := createXORArrayMethod1(long)
	k2 := createXORArrayMethod1(clamped)
	if k1 != k2 {
		t.Fatalf("passwords >15 chars should be clamped: %x vs %x", k1, k2)
	}
}

// ---------------------------------------------------------------------------
// Round-trip tests for decryptXORMethod1.
//
// Stream layout used in most tests:
//   BOF (cleartext):  4-byte header + 8-byte body = bytes 0..11, streamPos after = 12
//   DATA record:      4-byte header (bytes 12..15, streamPos 12..15) + N-byte body
//                     body starts at streamPos = 16
//
// For an encrypted body starting at streamPos 16:
//   j-th byte uses xorArray[(16+j)%16] = xorArray[j%16]

// TestDecryptXORMethod1_RoundTrip verifies that encrypt→decrypt produces the
// original plaintext for a typical stream: BOF (cleartext) + data record.
func TestDecryptXORMethod1_RoundTrip(t *testing.T) {
	xorArray := createXORArrayMethod1(velvetPassword)

	plainPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	// Build plaintext stream: BOF (cleartext) + data record with plain body.
	var plainStream []byte
	plainStream = append(plainStream, biffBOF()...)
	plainStream = append(plainStream, biffRecord(0x003C, plainPayload)...)

	// Build encrypted stream: BOF unchanged + data record with encrypted body.
	// BOF is 12 bytes (4 hdr + 8 body). DATA record header at pos 12..15.
	// DATA body starts at streamPos 16.
	encPayload := encryptBIFFBody(plainPayload, xorArray, 16)
	var encStream []byte
	encStream = append(encStream, biffBOF()...)
	encStream = append(encStream, biffRecord(0x003C, encPayload)...)

	decrypted := decryptXORMethod1(encStream, xorArray)
	if !bytes.Equal(decrypted, plainStream) {
		t.Fatalf("round-trip mismatch\nwant % x\n got % x", plainStream, decrypted)
	}
}

// TestDecryptXORMethod1_BOFCleartext verifies that BOF and EOF records pass
// through unchanged.
func TestDecryptXORMethod1_BOFCleartext(t *testing.T) {
	xorArray := createXORArrayMethod1(velvetPassword)
	bof := biffBOF()
	eof := biffRecord(0x000A, nil)
	stream := append(bof, eof...)

	decrypted := decryptXORMethod1(stream, xorArray)
	if !bytes.Equal(decrypted, stream) {
		t.Fatalf("BOF/EOF records should be cleartext; got % x", decrypted)
	}
}

// TestDecryptXORMethod1_FilepassCleartext verifies that FILEPASS records are
// not decrypted.
func TestDecryptXORMethod1_FilepassCleartext(t *testing.T) {
	xorArray := createXORArrayMethod1(velvetPassword)
	fp := biffFilePasXOR(0xABCD, 0x1234)
	decrypted := decryptXORMethod1(fp, xorArray)
	if !bytes.Equal(decrypted, fp) {
		t.Fatalf("FILEPASS should be cleartext; got % x", decrypted)
	}
}

// TestDecryptXORMethod1_BoundSheet8LbPlyPosCleartext verifies that BoundSheet8
// records have their first 4 body bytes (lbPlyPos) cleartext and the rest
// encrypted.
func TestDecryptXORMethod1_BoundSheet8LbPlyPosCleartext(t *testing.T) {
	xorArray := createXORArrayMethod1(velvetPassword)

	// Plain payload: lbPlyPos(4) + grbit(2) + cch(1) + fHighByte(1) + name(3)
	plain := []byte{0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 'A', 'B', 'C'}

	// The record header will be at stream position 0 (no preceding records).
	// Header: 4 bytes (pos 0..3), streamPos after header = 4.
	// lbPlyPos: 4 bytes cleartext (pos 4..7), streamPos after = 8.
	// Encrypted body: 7 bytes, starts at streamPos 8.
	encBodyStart := 8
	encBody := encryptBIFFBody(plain[4:], xorArray, encBodyStart)

	enc := make([]byte, len(plain))
	copy(enc[:4], plain[:4]) // lbPlyPos cleartext
	copy(enc[4:], encBody)

	encRecord := biffRecord(0x0085, enc)
	decrypted := decryptXORMethod1(encRecord, xorArray)
	if len(decrypted) < 4+len(plain) {
		t.Fatalf("output too short: %d", len(decrypted))
	}
	gotPayload := decrypted[4:]
	if !bytes.Equal(gotPayload, plain) {
		t.Fatalf("BoundSheet8 mismatch\nwant % x\n got % x", plain, gotPayload)
	}
}

// TestDecryptXORMethod1_KeyAdvancesAcrossRecords verifies that the key index
// advances continuously across records (not reset per record).
//
// Two consecutive CONTINUE records (type 0x003C), each with a 4-byte body:
//
//	Record 1: header at streamPos 0–3, body at streamPos 4
//	          j-th byte uses xorArray[(4+j)%16]
//	Record 2: record 1 total = 8 bytes; header at streamPos 8–11,
//	          body at streamPos 12
//	          j-th byte uses xorArray[(12+j)%16]
func TestDecryptXORMethod1_KeyAdvancesAcrossRecords(t *testing.T) {
	xorArray := createXORArrayMethod1(velvetPassword)

	plainPayload := bytes.Repeat([]byte{0x42}, 4)

	// Record 1: body starts at streamPos 4, N=4.
	enc1 := encryptBIFFBody(plainPayload, xorArray, 4)
	// Record 2: record 1 = 8 bytes (4 hdr + 4 body); header at 8, body at streamPos 12, N=4.
	enc2 := encryptBIFFBody(plainPayload, xorArray, 12)

	var stream []byte
	stream = append(stream, biffRecord(0x003C, enc1)...)
	stream = append(stream, biffRecord(0x003C, enc2)...)

	dec := decryptXORMethod1(stream, xorArray)

	want := bytes.Repeat([]byte{0x42}, 4)
	// Record 1 payload: bytes 4..7 (after 4-byte header).
	got1 := dec[4:8]
	// Record 2 payload: bytes 12..15 (8 bytes for rec1 + 4-byte header = offset 12).
	got2 := dec[12:16]
	if !bytes.Equal(got1, want) || !bytes.Equal(got2, want) {
		t.Fatalf("key advance failed: r1=% x r2=% x (want % x)", got1, got2, want)
	}
}

// ---------------------------------------------------------------------------
// Edge-case / robustness tests.

func TestDecryptXORMethod1_TruncatedRecordNoPanic(t *testing.T) {
	xorArray := createXORArrayMethod1(velvetPassword)
	// Record claiming 10 bytes but only 3 provided.
	bad := make([]byte, 7)
	binary.LittleEndian.PutUint16(bad[0:], 0x003C)
	binary.LittleEndian.PutUint16(bad[2:], 0x000A) // claims 10 bytes
	bad[4], bad[5], bad[6] = 0xAA, 0xBB, 0xCC
	_ = decryptXORMethod1(bad, xorArray)
}

func TestDecryptXORMethod1_8MiBCapEnforced(t *testing.T) {
	xorArray := createXORArrayMethod1(velvetPassword)
	chunk := make([]byte, 1<<20) // 1 MiB
	var bigStream []byte
	for i := 0; i < 10; i++ {
		bigStream = append(bigStream, biffRecord(0x003C, chunk)...)
	}
	out := decryptXORMethod1(bigStream, xorArray)
	if len(out) > maxDefaultPWOut+4 {
		t.Fatalf("output exceeds 8 MiB cap: %d bytes", len(out))
	}
}

// ---------------------------------------------------------------------------
// fromDefaultPWXOR integration smoke tests (nil OLE path).

func TestFromDefaultPWXOR_NilOLENoPanic(t *testing.T) {
	res := &Result{}
	fromDefaultPWXOR(nil, res, time.Time{})
	if len(res.Streams) != 0 {
		t.Fatal("nil OLE must emit no streams")
	}
}

func TestFromDefaultPWXOR_DeadlineExpired(t *testing.T) {
	res := &Result{}
	fromDefaultPWXOR(nil, res, time.Now().Add(-time.Second))
	if len(res.Streams) != 0 {
		t.Fatal("expired deadline must emit no streams")
	}
}
