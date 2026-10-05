package extract

import (
	"bytes"
	"crypto/md5" //#nosec G501 -- test fixture for the legacy Office RC4-MD5 protocol
	"crypto/rc4" //#nosec G503 -- test fixture for the legacy Office RC4 protocol
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// BIFF8 RC4 v1.1 (MD5) fixtures — independent reference key derivation
// ---------------------------------------------------------------------------
//
// All fixture ciphertext below is built with an in-test reference KDF taken
// from the RC4 v1.1 MD5 derivation as implemented by msoffcrypto's
// DocumentRC4._makekey, which the production code labels MS-OFFCRYPTO §2.3.7.3:
// MD5(utf16le(password))[0:5] || salt repeated 16 times, MD5 again, take [0:5]
// || blockLE32, MD5 again, take [0:16]. The production rc4MD5MakeKey/
// rc4MD5Decrypt are never called to build ciphertext, so a KDF or decrypt drift
// fails the round-trip. (The packet's "0x30..0x3B zeroing" note belongs to the
// separate XOR-obfuscation transform; production rc4MD5MakeKey has no such
// zeroing and this fixture encodes the observed behavior.)

func fixtureRefRC4MD5UTF16LE(password string) []byte {
	// Matches production pwUTF16LE's byte-wise encoding; identical to true
	// UTF-16LE for the ASCII passwords this fixture uses.
	out := make([]byte, len(password)*2)
	for i := 0; i < len(password); i++ {
		out[i*2] = password[i]
	}
	return out
}

func fixtureRefRC4MD5Key(password string, salt []byte, block uint32) []byte {
	h0 := md5.Sum(fixtureRefRC4MD5UTF16LE(password)) //#nosec G401 -- MS-OFFCRYPTO §2.3.6.2 mandates MD5
	unit := make([]byte, 0, (5+len(salt))*16)
	for i := 0; i < 16; i++ {
		unit = append(unit, h0[:5]...)
		unit = append(unit, salt...)
	}
	h1 := md5.Sum(unit) //#nosec G401 -- protocol-mandated MD5
	var blockBytes [4]byte
	binary.LittleEndian.PutUint32(blockBytes[:], block)
	hfinal := md5.Sum(append(h1[:5], blockBytes[:]...)) //#nosec G401 -- protocol-mandated MD5
	return hfinal[:16]
}

func fixtureRefRC4MD5Encrypt(t *testing.T, plain []byte, password string, salt []byte) []byte {
	t.Helper()
	out := make([]byte, len(plain))
	for start := 0; start < len(plain); start += 512 {
		end := min(start+512, len(plain))
		key := fixtureRefRC4MD5Key(password, salt, uint32(start/512))
		c, err := rc4.NewCipher(key) //#nosec G405 -- encrypt public test data for the legacy Office RC4 protocol
		if err != nil {
			t.Fatal(err)
		}
		c.XORKeyStream(out[start:end], plain[start:end])
	}
	return out
}

// fixtureRefRC4MD5EncryptBIFF applies the MS-XLS record rules with the #384
// reference KDF. It deliberately does not call any production decrypt helper.
func fixtureRefRC4MD5EncryptBIFF(t *testing.T, plain []byte, password string, salt []byte) []byte {
	t.Helper()
	clear := make([]bool, len(plain))
	for off := 0; off+4 <= len(plain); {
		typ := binary.LittleEndian.Uint16(plain[off:])
		size := int(binary.LittleEndian.Uint16(plain[off+2:]))
		if off+4+size > len(plain) {
			t.Fatal("fixture BIFF record exceeds Workbook")
		}
		for i := off; i < off+4; i++ {
			clear[i] = true
		}
		bodyClear := 0
		switch typ {
		case 0x0809, 0x002F: // BOF, FILEPASS
			bodyClear = size
		case 0x0085: // BoundSheet8.lbPlyPos
			if size >= 4 {
				bodyClear = 4
			}
		}
		for i := off + 4; i < off+4+bodyClear; i++ {
			clear[i] = true
		}
		off += 4 + size
	}
	out := bytes.Clone(plain)
	var c *rc4.Cipher
	var scratch [1]byte
	for i := range out {
		if i%1024 == 0 {
			var err error
			// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-rc4 -- protocol-mandated BIFF fixture encryption
			c, err = rc4.NewCipher(fixtureRefRC4MD5Key(password, salt, uint32(i/1024))) //#nosec G405 -- encrypt public legacy Office fixture
			if err != nil {
				t.Fatal(err)
			}
		}
		if clear[i] {
			c.XORKeyStream(scratch[:], []byte{0})
		} else {
			c.XORKeyStream(out[i:i+1], plain[i:i+1])
		}
	}
	return out
}

func fixturePatternBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + 11)
	}
	return out
}

func fixtureRefRC4MD5RoundTrip(t *testing.T, name, password string, salt, plain []byte) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		enc := fixtureRefRC4MD5Encrypt(t, plain, password, salt)
		got := rc4MD5Decrypt(password, salt, enc)
		if !bytes.Equal(got, plain) {
			t.Fatalf("RC4-MD5 decrypted bytes differ from known plaintext: want % x\n got % x", plain, got)
		}
	})
}

// TestRC4MD5DecryptFixture_BlockSpanning covers a single partial block, an
// exact single block, multi-block inputs, and a ~4 KiB stream across rekey
// boundaries. Each 512-byte block (including a partial final block) is
// encrypted under the block-indexed reference key.
func TestRC4MD5DecryptFixture_BlockSpanning(t *testing.T) {
	const password = "VelvetSweatshop"
	salt := []byte("0123456789abcdef")
	for _, size := range []int{128, 512, 513, 1500, 4096} {
		t.Run(fmt.Sprintf("plain-%d-bytes", size), func(t *testing.T) {
			plain := fixturePatternBytes(size)
			got := rc4MD5Decrypt(password, salt, fixtureRefRC4MD5Encrypt(t, plain, password, salt))
			if !bytes.Equal(got, plain) {
				t.Fatalf("RC4-MD5 decrypted bytes differ from known plaintext: want % x\n got % x", plain, got)
			}
		})
	}
}

// TestRC4MD5DecryptFixture_BoundaryAndMalformed asserts the OBSERVED production
// behavior of rc4MD5Decrypt for degenerate inputs: it decrypts with any salt
// length (including empty) and any password (including empty); a ciphertext
// length that is not a multiple of 512 decrypts the partial final block under
// the block-indexed key; empty ciphertext yields empty output.
func TestRC4MD5DecryptFixture_BoundaryAndMalformed(t *testing.T) {
	const password = "VelvetSweatshop"
	salt := []byte("0123456789abcdef")

	t.Run("empty-ciphertext", func(t *testing.T) {
		if got := rc4MD5Decrypt(password, salt, nil); len(got) != 0 {
			t.Fatalf("empty ciphertext produced %d output bytes", len(got))
		}
	})

	t.Run("ciphertext-not-multiple-of-512", func(t *testing.T) {
		plain := fixturePatternBytes(100)
		got := rc4MD5Decrypt(password, salt, fixtureRefRC4MD5Encrypt(t, plain, password, salt))
		if !bytes.Equal(got, plain) {
			t.Fatalf("partial final block decrypted to % x", got)
		}
	})

	// The reference KDF only equals the production KDF for ASCII passwords
	// (see fixtureRefRC4MD5UTF16LE); all cases below stay ASCII.
	fixtureRefRC4MD5RoundTrip(t, "empty-password", "", salt, fixturePatternBytes(80))
	fixtureRefRC4MD5RoundTrip(t, "odd-length-password", "abc", salt, fixturePatternBytes(80))
	fixtureRefRC4MD5RoundTrip(t, "salt-shorter-than-16", password, salt[:15], fixturePatternBytes(80))
	fixtureRefRC4MD5RoundTrip(t, "salt-longer-than-16", password, append(append([]byte{}, salt...), 0x21), fixturePatternBytes(80))
	fixtureRefRC4MD5RoundTrip(t, "salt-empty", password, nil, fixturePatternBytes(80))
}

// TestRC4MD5VerifyPWFixture builds the verifier with the independent reference
// KDF/RC4 (never production), then confirms the production verifier accepts the
// right password and rejects a wrong one.
func TestRC4MD5VerifyPWFixture(t *testing.T) {
	const password = "VelvetSweatshop"
	salt := []byte("0123456789abcdef")
	verifier := []byte("16-byte fixture?")
	hash := md5.Sum(verifier) //#nosec G401 -- protocol-mandated MD5
	combined := append(append([]byte{}, verifier...), hash[:]...)
	enc := fixtureRefRC4MD5Encrypt(t, combined, password, salt)
	if !rc4MD5VerifyPW(password, salt, enc[:16], enc[16:]) {
		t.Fatal("known RC4-MD5 verifier password rejected")
	}
	if rc4MD5VerifyPW("wrong-password", salt, enc[:16], enc[16:]) {
		t.Fatal("wrong RC4-MD5 verifier password accepted")
	}
}

// fixtureRC4MD5Workbook uses the independent #384 encryptor for both the
// FILEPASS verifier and post-FILEPASS BIFF records. The sheet name exists only
// inside ciphertext; public Extract must open OLE, verify, decrypt, then scan.
func fixtureRC4MD5Workbook(t *testing.T, boundary bool, corruptVerifier bool) []byte {
	t.Helper()
	password := velvetPassword
	salt := []byte("0123456789abcdef")
	verifier := []byte("16-byte fixture?")
	// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5 -- legacy Office verifier fixture
	hash := md5.Sum(verifier) //#nosec G401 -- legacy Office verifier fixture
	verification := fixtureRefRC4MD5Encrypt(t, append(bytes.Clone(verifier), hash[:]...), password, salt)
	if corruptVerifier {
		verification[16] ^= 0x80
	}
	filepass := make([]byte, 6+48)
	binary.LittleEndian.PutUint16(filepass, 1)
	binary.LittleEndian.PutUint16(filepass[2:], 1)
	binary.LittleEndian.PutUint16(filepass[4:], 1)
	copy(filepass[6:], salt)
	copy(filepass[22:], verification)

	workbook := append(biffBOF(), biffRecord(0x002F, filepass)...)
	if boundary {
		// BOF + FILEPASS use 70 bytes. This record ends exactly at the
		// 1024-byte workbook-stream rekey boundary.
		workbook = append(workbook, biffRecord(0x003C, make([]byte, 950))...)
	}
	const sheet = "RC4SecretSheet"
	bound := append([]byte{0x12, 0x34, 0x56, 0x78, 1, 1, byte(len(sheet)), 0}, sheet...)
	workbook = append(workbook, biffRecord(0x0085, bound)...)
	if boundary {
		// Align the minimal CFB builder's regular-FAT zero padding to a
		// complete four-byte BIFF header after the final EOF.
		workbook = append(workbook, biffRecord(0x003C, []byte{0, 0})...)
	}
	workbook = append(workbook, biffRecord(0x000A, nil)...)
	encrypted := fixtureRefRC4MD5EncryptBIFF(t, workbook, password, salt)
	if bytes.Contains(encrypted, []byte(sheet)) {
		t.Fatal("fixture leaked plaintext sheet name")
	}
	return fixtureCFB(t, []cfbEntry{{name: "Workbook", mse: 2, data: encrypted}})
}

func TestRC4MD5PublicExtraction(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		boundary, wrongVerifier bool
	}{
		{"short", false, false},
		{"block-boundary", true, false},
		{"wrong-verifier", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := fixtureRC4MD5Workbook(t, tc.boundary, tc.wrongVerifier)
			res := Extract(fixture, time.Time{})
			if !res.IsDoc || !res.Encrypted || res.Panicked {
				t.Fatalf("public extraction flags: IsDoc=%t Encrypted=%t Panicked=%t", res.IsDoc, res.Encrypted, res.Panicked)
			}
			decrypted := bytes.Contains(bytes.Join(res.Markers, nil), []byte("DEFAULTPW-DECRYPTED"))
			if decrypted != !tc.wrongVerifier {
				t.Fatalf("DEFAULTPW-DECRYPTED=%t, wrongVerifier=%t", decrypted, tc.wrongVerifier)
			}
			found := false
			for _, stream := range res.Streams {
				found = found || bytes.Equal(stream, []byte("XLM-HIDDEN-MACROSHEET hidden RC4SecretSheet"))
			}
			if found != !tc.wrongVerifier {
				t.Fatalf("decrypted plaintext marker found=%t, wrongVerifier=%t", found, tc.wrongVerifier)
			}
		})
	}
}

func TestRC4MD5CommittedFixtureMatchesReference(t *testing.T) {
	want := fixtureRC4MD5Workbook(t, true, false)
	got, err := os.ReadFile("../../ci/testdata/rc4md5-biff.xls")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("committed RC4-MD5 OLE fixture differs from independent reference producer")
	}
}

func TestRC4MD5BIFFCapKeepsPrefix(t *testing.T) {
	const sheet = "CapSheet"
	salt := []byte("0123456789abcdef")
	bound := append([]byte{0, 0, 0, 0, 1, 1, byte(len(sheet)), 0}, sheet...)
	plain := biffRecord(0x0085, bound)
	encrypted := fixtureRefRC4MD5EncryptBIFF(t, plain, velvetPassword, salt)
	workbook := append(encrypted, make([]byte, maxDefaultPWOut+4-len(encrypted))...)
	got := rc4MD5DecryptBIFF(velvetPassword, salt, workbook)
	if len(got) != maxDefaultPWOut || !bytes.Equal(got[:len(plain)], plain) {
		t.Fatalf("BIFF cap lost known plaintext prefix: output=%d, want=%d", len(got), maxDefaultPWOut)
	}
}
