package extract

import (
	"bytes"
	"crypto/rc4"  //#nosec G503 -- legacy Office protocol fixture
	"crypto/sha1" //#nosec G505 -- legacy Office protocol fixture
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func cryptoAPIHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Fixed public test keys computed independently with Python hashlib:
// h = SHA1(bytes(range(16)) + password.encode("utf-16le"));
// k = SHA1(h + struct.pack("<I", block)); take 16 bytes for 128 bits,
// or the first five bytes followed by eleven zero bytes for 40 bits.
func TestRC4SHA1KeyPreservesSharedInput(t *testing.T) {
	for _, tc := range []struct {
		bits int
		keys [2]string
	}{
		{40, [2]string{"ac2a7b17240000000000000000000000", "f5648bfcf20000000000000000000000"}},
		{128, [2]string{"ac2a7b172474c79c0b1292e558dfd9b1", "f5648bfcf2dc15ff7dd417b6af542bcb"}},
	} {
		for block, wantKey := range tc.keys {
			t.Run(fmt.Sprintf("%d/block%d", tc.bits, block), func(t *testing.T) {
				shared := bytes.Repeat([]byte{0x5A}, 80)
				binary.LittleEndian.PutUint32(shared, 16)
				copy(shared[4:20], cryptoAPIHex(t, "000102030405060708090a0b0c0d0e0f"))
				before := bytes.Clone(shared)
				// A normal EncryptionVerifier exposes its salt as a slice followed
				// by verifier/hash fields in the same backing buffer.
				key := rc4SHA1MakeKey(velvetPassword, shared[4:20], tc.bits, uint32(block))
				if !bytes.Equal(key, cryptoAPIHex(t, wantKey)) {
					t.Fatalf("CryptoAPI key differs from known key: got %x", key)
				}
				if !bytes.Equal(shared, before) {
					t.Fatal("CryptoAPI key derivation modified caller-owned verifier bytes")
				}
			})
		}
	}
}

func cryptoAPIEncrypt(t *testing.T, plain, key []byte) []byte {
	t.Helper()
	c, err := rc4.NewCipher(key) //#nosec G405 -- encrypt public data for a legacy Office fixture
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(plain))
	c.XORKeyStream(out, plain)
	return out
}

func cryptoAPIFilepass(bits uint32, salt, verification []byte) []byte {
	const provider = "Microsoft Enhanced Cryptographic Provider v1.0"
	const headerSize = 32 + 2*(len(provider)+1)
	body := make([]byte, 6+8+headerSize+60)
	copy(body, []byte{1, 0, 4, 0, 2, 0}) // CryptoAPI v4.2
	binary.LittleEndian.PutUint32(body[6:], 4)
	binary.LittleEndian.PutUint32(body[10:], uint32(headerSize))
	header := body[14 : 14+headerSize]
	binary.LittleEndian.PutUint32(header, 4)
	binary.LittleEndian.PutUint32(header[8:], 0x6801)  // RC4
	binary.LittleEndian.PutUint32(header[12:], 0x8004) // SHA1
	binary.LittleEndian.PutUint32(header[16:], bits)
	binary.LittleEndian.PutUint32(header[20:], 1)
	copy(header[32:], utf16le(provider))
	verifier := body[14+headerSize:]
	binary.LittleEndian.PutUint32(verifier, 16)
	copy(verifier[4:20], salt)
	copy(verifier[20:36], verification[:16])
	binary.LittleEndian.PutUint32(verifier[36:], 20)
	copy(verifier[40:], verification[16:])
	return biffRecord(0x002F, body)
}

func requireCryptoAPIStream(t *testing.T, streams [][]byte, want string) {
	t.Helper()
	for _, stream := range streams {
		if bytes.Equal(stream, []byte(want)) {
			return
		}
	}
	t.Fatalf("missing exact CryptoAPI plaintext stream %q", want)
}

func TestExtractCryptoAPISharedSalt(t *testing.T) {
	for _, tc := range []struct {
		bits uint32
		keys [2]string
	}{
		{40, [2]string{"3c542f4f6f0000000000000000000000", "ca4fc87de60000000000000000000000"}},
		{128, [2]string{"3c542f4f6f849cf6bd88d11f278082af", "ca4fc87de6f9596c02f491a9610e28b6"}},
	} {
		t.Run(fmt.Sprint(tc.bits), func(t *testing.T) {
			// "1234" is tried after incorrect candidates, exercising input
			// immutability across password attempts as well as the successful one.
			salt := cryptoAPIHex(t, "000102030405060708090a0b0c0d0e0f")
			key0, key1 := cryptoAPIHex(t, tc.keys[0]), cryptoAPIHex(t, tc.keys[1])
			verifier := []byte("Fixture verifier")
			hash := sha1.Sum(verifier) //#nosec G401 -- required by the legacy Office fixture
			verification := cryptoAPIEncrypt(t, append(verifier, hash[:]...), key0)
			if rc4SHA1VerifyPW("wrong-password", salt, verification[:16], verification[16:], int(tc.bits)) {
				t.Fatal("wrong CryptoAPI password accepted")
			}

			// Synthetic post-FILEPASS byte-stream coverage, not a full
			// application-generated BIFF workbook. No executable macro content.
			// The known sheet name is in block 1, beyond the 512-byte rekey.
			plain := biffRecord(0x003C, make([]byte, 508))
			const sheet = "FixtureSheet"
			bound := append([]byte{0, 0, 0, 0, 1, 1, byte(len(sheet)), 0}, sheet...)
			plain = append(plain, biffRecord(0x0085, bound)...)
			plain = append(plain, biffRecord(0x000A, nil)...)
			enc := append(cryptoAPIEncrypt(t, plain[:512], key0), cryptoAPIEncrypt(t, plain[512:], key1)...)
			workbook := append(biffBOF(), cryptoAPIFilepass(tc.bits, salt, verification)...)
			workbook = append(workbook, enc...)
			buf := buildCFB(t, []cfbEntry{
				{name: "Root Entry", mse: 5},
				{name: "Workbook", mse: 2, data: workbook},
			})
			before := bytes.Clone(buf)
			res := Extract(buf, time.Time{})
			requireCryptoAPIStream(t, res.Streams, "XLM-HIDDEN-MACROSHEET hidden "+sheet)
			requireCryptoAPIStream(t, res.Markers, "DEFAULTPW-DECRYPTED")
			if !res.IsDoc || !res.Encrypted || res.Panicked {
				t.Fatalf("CryptoAPI fixture flags: IsDoc=%t Encrypted=%t Panicked=%t", res.IsDoc, res.Encrypted, res.Panicked)
			}
			if !bytes.Equal(buf, before) {
				t.Fatal("CryptoAPI extraction modified the input document")
			}
		})
	}
}
