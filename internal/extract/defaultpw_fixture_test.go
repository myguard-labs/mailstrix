package extract

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"  //#nosec G503 -- test fixture for the legacy Office RC4 protocol
	"crypto/sha1" //#nosec G505 -- test fixture for the legacy Office SHA1 protocol
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// These fixed, public test keys were computed independently with Python hashlib,
// not the production key derivation helpers. Password is VelvetSweatshop;
// salt is bytes(range(16)); Agile uses two SHA512 iterations, Standard 50000
// SHA1 iterations. Keeping encryption independent catches decryption/KDF drift.
// This file builds small parser fixtures, not complete Office application files.
const fixtureSaltHex = "000102030405060708090a0b0c0d0e0f"

func fixtureHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureAES(t *testing.T, plain, key, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padded := make([]byte, (len(plain)+15)/16*16)
	copy(padded, plain)
	out := make([]byte, len(padded))
	if iv != nil {
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	} else {
		for i := 0; i < len(padded); i += aes.BlockSize {
			block.Encrypt(out[i:], padded[i:])
		}
	}
	return out
}

func fixtureRC4(t *testing.T, plain, key []byte) []byte {
	t.Helper()
	c, err := rc4.NewCipher(key) //#nosec G405 -- encrypt public test data for the legacy Office RC4 protocol
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(plain))
	c.XORKeyStream(out, plain)
	return out
}

// fixtureEncryptionHeader builds the shared binary EncryptionHeader and
// EncryptionVerifier layout used by CryptoAPI and Standard encryption.
func fixtureEncryptionHeader(keyBits, algID, flags, provider uint32, salt, verifier, hash []byte) []byte {
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header, flags)
	binary.LittleEndian.PutUint32(header[8:], algID)
	binary.LittleEndian.PutUint32(header[12:], 0x8004) // SHA1
	binary.LittleEndian.PutUint32(header[16:], keyBits)
	binary.LittleEndian.PutUint32(header[20:], provider)
	header = append(header, utf16le("Microsoft Enhanced Cryptographic Provider v1.0")...)
	out := make([]byte, 8)
	binary.LittleEndian.PutUint32(out, flags)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(header)))
	out = append(out, header...)
	out = binary.LittleEndian.AppendUint32(out, 16)
	out = append(out, salt...)
	out = append(out, verifier...)
	out = binary.LittleEndian.AppendUint32(out, 20)
	return append(out, hash...)
}

func TestRC4CryptoAPIFixture(t *testing.T) {
	for _, tc := range []struct {
		bits int
		keys [2]string
	}{
		{40, [2]string{"ac2a7b17240000000000000000000000", "f5648bfcf20000000000000000000000"}},
		{128, [2]string{"ac2a7b172474c79c0b1292e558dfd9b1", "f5648bfcf2dc15ff7dd417b6af542bcb"}},
	} {
		t.Run(fmt.Sprint(tc.bits), func(t *testing.T) {
			salt := fixtureHex(t, fixtureSaltHex)
			key0, key1 := fixtureHex(t, tc.keys[0]), fixtureHex(t, tc.keys[1])
			verifier := []byte("Fixture verifier")
			hash := sha1.Sum(verifier) //#nosec G401 -- SHA1 required by the fixture's Office encryption format
			verification := fixtureRC4(t, append(verifier, hash[:]...), key0)
			if !rc4SHA1VerifyPW(velvetPassword, salt, verification[:16], verification[16:], tc.bits) {
				t.Fatal("known CryptoAPI password rejected")
			}
			if rc4SHA1VerifyPW("wrong-password", salt, verification[:16], verification[16:], tc.bits) {
				t.Fatal("wrong CryptoAPI password accepted")
			}

			// Cover a full block followed by a partial block with a different key.
			// This exercises raw CryptoAPI decryption, not the BIFF orchestrator.
			plain := bytes.Repeat([]byte("CryptoAPI quarterly report fixture\n"), 20)
			enc := append(fixtureRC4(t, plain[:512], key0), fixtureRC4(t, plain[512:], key1)...)
			if !bytes.Equal(rc4SHA1Decrypt(velvetPassword, salt, tc.bits, enc), plain) {
				t.Fatal("CryptoAPI decrypted bytes differ from known plaintext across rekey")
			}
		})
	}
}

func fixtureAgile(t *testing.T, plain []byte) (infoData, packageData []byte) {
	t.Helper()
	salt := fixtureHex(t, fixtureSaltHex)
	key := bytes.Repeat([]byte{0x42}, 32)
	verifier := []byte("Fixture verifier")
	hash := sha512.Sum512(verifier)
	k1 := fixtureHex(t, "dafe8d5f5b392dc447258d0b7521e3a2d2996e17416ea5a94476e7a9fec6ab97")
	k2 := fixtureHex(t, "076ccccdcf60f5064c456f8ba123f8a59c98103dc6bea7fb93c33734996c01ee")
	k3 := fixtureHex(t, "96e2ee05dc43335a78af84d69c2c8f199c07a2b3d2466f4c34497d60f668c3b4")
	b64 := base64.StdEncoding.EncodeToString
	xml := fmt.Sprintf(`<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption">
<keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="%s"/>
<keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
<p:encryptedKey xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password" spinCount="2" saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="%s" encryptedVerifierHashInput="%s" encryptedVerifierHashValue="%s" encryptedKeyValue="%s"/>
</keyEncryptor></keyEncryptors></encryption>`, b64(salt), b64(salt), b64(fixtureAES(t, verifier, k1, salt)), b64(fixtureAES(t, hash[:], k2, salt)), b64(fixtureAES(t, key, k3, salt)))
	infoData = append([]byte{4, 0, 4, 0, 0x40, 0, 0, 0}, xml...)
	// buildCFB promotes short streams to the regular FAT by NUL-padding. XML
	// needs whitespace instead, so fill the stream to its 4096-byte cutoff here.
	infoData = append(infoData, bytes.Repeat([]byte{' '}, 4096-len(infoData))...)
	packageData = binary.LittleEndian.AppendUint64(nil, uint64(len(plain)))
	for segment, start := uint32(0), 0; start < len(plain); segment, start = segment+1, start+4096 {
		end := min(start+4096, len(plain))
		iv := sha512.Sum512(binary.LittleEndian.AppendUint32(bytes.Clone(salt), segment))
		packageData = append(packageData, fixtureAES(t, plain[start:end], key, iv[:16])...)
	}
	return infoData, packageData
}

func fixtureStandard(t *testing.T, plain []byte) (infoData, packageData []byte) {
	t.Helper()
	salt := fixtureHex(t, fixtureSaltHex)
	key := fixtureHex(t, "a8174295e8b270d10580d3578390fd5e")
	verifier := []byte("Fixture verifier")
	hash := sha1.Sum(verifier) //#nosec G401 -- SHA1 required by the fixture's Office encryption format
	infoData = append([]byte{4, 0, 2, 0}, fixtureEncryptionHeader(128, 0x660E, 0x24, 0x18, salt, fixtureAES(t, verifier, key, nil), fixtureAES(t, hash[:], key, nil))...)
	packageData = binary.LittleEndian.AppendUint64(nil, uint64(len(plain)))
	packageData = append(packageData, fixtureAES(t, plain, key, nil)...)
	return infoData, packageData
}

func TestExtractEncryptedOOXMLFixture(t *testing.T) {
	const title = "Encrypted quarterly report fixture"
	plain := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`),
		"word/document.xml":   []byte(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>`),
		"docProps/core.xml":   []byte(`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>` + title + `</dc:title></cp:coreProperties>`),
	})
	// A ZIP comment keeps the valid plaintext ZIP above one Agile segment while
	// leaving the final AES block partial. The property remains inside the ZIP.
	comment := bytes.Repeat([]byte("benign fixture padding "), 220)
	binary.LittleEndian.PutUint16(plain[len(plain)-2:], uint16(len(comment)))
	plain = append(plain, comment...)
	for _, tc := range []struct {
		name  string
		build func(*testing.T, []byte) ([]byte, []byte)
	}{
		{"Agile", fixtureAgile},
		{"Standard", fixtureStandard},
	} {
		t.Run(tc.name, func(t *testing.T) {
			infoData, packageData := tc.build(t, plain)
			var decrypted []byte
			if tc.name == "Agile" {
				info, err := parseAgileInfo(infoData[8:])
				if err != nil {
					t.Fatal(err)
				}
				if agileVerifyPW("wrong-password", info) {
					t.Fatal("wrong Agile password accepted")
				}
				decrypted = agileDecrypt(agileExtractKey(velvetPassword, info), info, packageData)
			} else {
				info, err := parseStandardInfo(infoData[4:])
				if err != nil {
					t.Fatal(err)
				}
				if standardVerifyPW("wrong-password", info) {
					t.Fatal("wrong Standard password accepted")
				}
				decrypted = standardDecrypt(velvetPassword, info, packageData)
			}
			if !bytes.Equal(decrypted, plain) {
				t.Fatal("Office decrypted ZIP differs from known plaintext")
			}
			res := Extract(fixtureCFB(t, []cfbEntry{
				{name: "EncryptionInfo", mse: 2, data: infoData},
				{name: "EncryptedPackage", mse: 2, data: packageData},
			}), time.Time{})
			requireFixtureStream(t, res.Streams, title)
			if !res.IsDoc || !res.Encrypted || res.Failed || res.Panicked || !res.HasDocProps {
				t.Fatalf("Office fixture flags: IsDoc=%t Encrypted=%t Failed=%t Panicked=%t HasDocProps=%t", res.IsDoc, res.Encrypted, res.Failed, res.Panicked, res.HasDocProps)
			}
			requireFixtureStream(t, res.Markers, "DEFAULTPW-DECRYPTED")
			requireFixtureMarker(t, res, "DOCPROPS-STRINGS", title)
		})
	}
}
