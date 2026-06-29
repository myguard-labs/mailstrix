package extract

// defaultpw.go — BIFF8 default-password decryption: XOR (B1), RC4 (B2), OOXML (B2).
//
// Many malware XLS/Office files are encrypted with well-known default passwords
// ("VelvetSweatshop" etc.). Excel/Office opens them silently without prompting,
// making them appear unprotected to users and opaque to scanners.
//
// B1 (XOR): FILEPASS wEncryptionType==0, Method 1 — XOR-obfuscated BIFF8.
//   Faithfully ported from MS-OFFCRYPTO §2.3.7.2, verified against the
//   msoffcrypto-tool reference (xor_obfuscation.py DocumentXOR class).
//
// B2 (RC4 + OOXML): FILEPASS RC4 v1.1 (MD5-based) and CryptoAPI (SHA1-based),
//   plus ECMA-376 Agile (AES-256-CBC + SHA-512) and Standard (AES-ECB + SHA-1).
//   All implemented from public specs and reference algorithm descriptions.
//   No code derived from oletools or any GPL source — only the public spec
//   algorithm constants are shared.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"  //#nosec G501 -- MD5 required by MS-OFFCRYPTO §2.3.7.3 BIFF8 RC4 v1.1 key derivation; protocol-mandated interop
	"crypto/rc4"  //#nosec G503 -- RC4 required by MS-OFFCRYPTO BIFF8 RC4 decryption; protocol-mandated interop
	"crypto/sha1" //#nosec G505 -- SHA1 required by MS-OFFCRYPTO CryptoAPI and ECMA-376 Standard key derivation; protocol-mandated interop
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"time"

	"www.velocidex.com/golang/oleparse"
)

const velvetPassword = "VelvetSweatshop"

// maxDefaultPWOut caps decrypted output fed to scanBIFFXLMStream (8 MiB).
const maxDefaultPWOut = 8 << 20

// MS-OFFCRYPTO §2.3.7.2 algorithm constants.

// xorPadArray — 15-byte padding sequence for short passwords.
var xorPadArray = [15]byte{
	0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80,
	0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00,
}

// xorInitialCode — per-password-length starting accumulator, indexed [len-1].
var xorInitialCode = [15]uint16{
	0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE,
	0x313E, 0x1872, 0xE139, 0xD40F, 0x84F9, 0x280C, 0xA96A, 0x4EC3,
}

// xorMatrix — 105-entry uint16 table used in key derivation.
// Indexed from current_element = 104 downward per character bit.
var xorMatrix = [105]uint16{
	0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09,
	0x7B61, 0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7, 0x9DCF, 0x2BBF,
	0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0,
	0x0375, 0x06EA, 0x0DD4, 0x1BA8, 0x3750, 0x6EA0, 0xDD40,
	0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D, 0xAA7A, 0x44D5,
	0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A,
	0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC, 0x5FD9,
	0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0,
	0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC,
	0x45A0, 0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10,
	0xAA51, 0x4483, 0x8906, 0x022D, 0x045A, 0x08B4, 0x1168,
	0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C,
	0x3730, 0x6E60, 0xDCC0, 0xA9A1, 0x4363, 0x86C6, 0x1DAD,
	0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373, 0x06E6, 0x0DCC,
	0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4,
}

// ror8 rotates an 8-bit value right by n positions.
func ror8(b byte, n uint) byte {
	n &= 7
	return (b >> n) | (b << (8 - n))
}

// rol8 rotates an 8-bit value left by n positions.
func rol8(b byte, n uint) byte {
	n &= 7
	return (b << n) | (b >> (8 - n))
}

// xorRor computes xor_ror(b1, b2) = ror(b1^b2, 1, 8) per the spec.
func xorRor(b1, b2 byte) byte {
	return ror8(b1^b2, 1)
}

// createXORKeyMethod1 derives the 16-bit XOR key from a password (MS-OFFCRYPTO §2.3.7.2).
// Faithful port of DocumentXOR.create_xor_key_method1.
func createXORKeyMethod1(password string) uint16 {
	if len(password) > 15 {
		password = password[:15]
	}
	n := len(password)
	if n == 0 {
		return 0
	}
	xorKey := uint32(xorInitialCode[n-1])
	currentElement := 0x68 // 104 — starts at top of xorMatrix, walks down

	// Iterate over reversed password characters.
	for i := n - 1; i >= 0; i-- {
		ch := uint32(password[i])
		for bit := 0; bit < 7; bit++ {
			if ch&0x40 != 0 {
				xorKey = (xorKey ^ uint32(xorMatrix[currentElement])) & 0xFFFF
			}
			ch = (ch << 1) & 0xFF
			currentElement--
		}
	}
	return uint16(xorKey) //#nosec G115 -- xorKey is masked to 0xFFFF throughout
}

// createXORArrayMethod1 builds the 16-byte decryption key array from a password.
// Faithful port of DocumentXOR.create_xor_array_method1 — mirrors the Python
// index/pad_index walk exactly so the byte layout matches the spec.
func createXORArrayMethod1(password string) [16]byte {
	if len(password) > 15 {
		password = password[:15]
	}
	n := len(password)
	xorKey := createXORKeyMethod1(password)
	hi := byte(xorKey >> 8)
	lo := byte(xorKey & 0xFF)

	var arr [16]byte
	index := n // mirrors Python's `index = len(password)`

	if index%2 == 1 {
		// Odd password length: seed the last two slots with pad_array[0] / last char.
		arr[index] = xorRor(xorPadArray[0], hi)
		index--
		arr[index] = xorRor(password[n-1], lo)
		index--
	}

	// Fill password characters two at a time (Python: while index > 0 with index-=1 each step).
	for index > 0 {
		index--
		arr[index] = xorRor(password[index], hi)
		index--
		if index >= 0 {
			arr[index] = xorRor(password[index], lo)
		}
	}

	// Fill remaining high slots (index 15 down to n) with xorPadArray bytes.
	// Python: index=15, pad_index=15-len(password), while pad_index > 0.
	arrIdx := 15
	padIdx := 15 - n
	for padIdx > 0 {
		arr[arrIdx] = xorRor(xorPadArray[padIdx], hi)
		arrIdx--
		padIdx--
		arr[arrIdx] = xorRor(xorPadArray[padIdx], lo)
		arrIdx--
		padIdx--
	}

	return arr
}

// verifyXORPassword checks a password against the 16-bit FILEPASS verifier.
// Faithful port of DocumentXOR.verifypw (MS-OFFCRYPTO §2.3.7.2).
// Known test vector: verifyXORPassword("VelvetSweatshop", 0x9a0a) == true.
func verifyXORPassword(password string, storedVerifier uint16) bool {
	if len(password) > 15 {
		password = password[:15]
	}
	n := len(password)

	// password_array = [len(password)] + chars, then reversed.
	arr := make([]int, 0, n+1)
	arr = append(arr, n)
	for i := 0; i < n; i++ {
		arr = append(arr, int(password[i]))
	}
	// Reverse.
	for i, j := 0, len(arr)-1; i < j; i, j = i+1, j-1 {
		arr[i], arr[j] = arr[j], arr[i]
	}

	verifier := uint16(0)
	for _, pwByte := range arr {
		var intermediate1 uint16
		if verifier&0x4000 != 0 {
			intermediate1 = 1
		}
		intermediate2 := (verifier * 2) & 0x7FFF
		verifier = (intermediate1 ^ intermediate2) ^ uint16(pwByte) //#nosec G115 -- pwByte is ASCII char (0–127) or len (1–15)
	}
	return (verifier ^ 0xCE4B) == storedVerifier
}

// isClearTextBIFF8Record returns true for BIFF8 record types that must NOT be
// decrypted (MS-OFFCRYPTO §2.3.7.2, Table 2-1 ClearText records).
func isClearTextBIFF8Record(t uint16) bool {
	switch t {
	case 0x0809, // BOF
		0x002F, // FilePass
		0x0194, // UsrExcl
		0x01A7, // FileLock
		0x00E1, // InterfaceHdr
		0x0196, // RRDInfo
		0x0138: // RRDHead
		return true
	}
	return false
}

// decryptXORMethod1 decrypts a BIFF8 Workbook stream that was XOR-obfuscated
// with the given 16-byte key array (Method 1, MS-OFFCRYPTO §2.3.7.2).
//
// The stream is walked record by record. Clear-text records are copied as-is.
// Encrypted bytes are decrypted as: ror(b ^ xorArray[streamPos%16], 5, 8).
// streamPos is the absolute byte offset in the stream (the record 4-byte
// header counts toward streamPos for index tracking even though it's cleartext).
// BoundSheet8 (0x0085): first 4 payload bytes (lbPlyPos) are cleartext.
// Output is capped at maxDefaultPWOut; truncated records fail-open.
func decryptXORMethod1(workbook []byte, xorArray [16]byte) []byte {
	out := make([]byte, 0, len(workbook))
	streamPos := 0 // absolute byte position in the stream (drives xorArray index)
	off := 0

	for off+4 <= len(workbook) {
		if len(out) >= maxDefaultPWOut {
			break
		}
		recType := binary.LittleEndian.Uint16(workbook[off:])
		recLen := int(binary.LittleEndian.Uint16(workbook[off+2:]))
		bodyOff := off + 4

		// Record header (4 bytes) is always cleartext; advance streamPos for it.
		out = append(out, workbook[off:off+4]...)
		streamPos += 4

		if bodyOff+recLen > len(workbook) {
			// Truncated — copy remaining bytes verbatim and bail.
			out = append(out, workbook[bodyOff:]...)
			break
		}

		body := workbook[bodyOff : bodyOff+recLen]

		if isClearTextBIFF8Record(recType) {
			// Cleartext record: copy unchanged; streamPos still advances.
			out = append(out, body...)
			streamPos += recLen
		} else if recType == 0x0085 && recLen >= 4 {
			// BoundSheet8: lbPlyPos (first 4 bytes) cleartext, rest encrypted.
			out = append(out, body[:4]...)
			streamPos += 4
			for _, b := range body[4:] {
				dec := ror8(b^xorArray[streamPos%16], 5)
				out = append(out, dec)
				streamPos++
			}
		} else {
			// Normal encrypted record.
			for _, b := range body {
				dec := ror8(b^xorArray[streamPos%16], 5)
				out = append(out, dec)
				streamPos++
			}
		}

		off = bodyOff + recLen
	}
	return out
}

// filepassXORVerifier reads the 16-bit password verifier from a FILEPASS
// wEncryptionType==0 record body.
//
// FILEPASS Method1 body layout (MS-XLS 2.4.117):
//
//	[0:2]  wEncryptionType  uint16 — must be 0 for XOR
//	[2:4]  key              uint16 — XOR key (unused here)
//	[4:6]  hash             uint16 — password verifier
func filepassXORVerifier(body []byte) (uint16, bool) {
	if len(body) < 6 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(body[4:]), true
}

// defaultPasswords is the ordered list of default passwords to try.
var defaultPasswords = []string{
	"VelvetSweatshop",
	"123",
	"1234",
	"12345",
	"123456",
	"4321",
}

// hasDecryptedMarker returns true if the DEFAULTPW-DECRYPTED stream was
// already emitted (double-call guard used by all fromDefaultPW* functions).
func hasDecryptedMarker(res *Result) bool {
	for _, s := range res.Streams {
		if string(s) == "DEFAULTPW-DECRYPTED" {
			return true
		}
	}
	return false
}

// emitDecrypted appends the DEFAULTPW-DECRYPTED marker and feeds the
// plaintext to the BIFF XLM scanner. Used by RC4 and XOR paths.
func emitDecrypted(res *Result, plaintext []byte, deadline time.Time) {
	res.Streams = append(res.Streams, []byte("DEFAULTPW-DECRYPTED"))
	scanBIFFXLMStream(plaintext, res, deadline)
}

// ---------------------------------------------------------------------------
// B2 — BIFF8 RC4 v1.1 (MD5-based key derivation, MS-OFFCRYPTO §2.3.7.3)
// ---------------------------------------------------------------------------

// rc4MD5MakeKey derives the 16-byte RC4 key for a given password, salt, and
// block counter. Faithful port of DocumentRC4._makekey (md5 variant).
func rc4MD5MakeKey(password string, salt []byte, block uint32) []byte {
	h0 := md5.Sum([]byte(pwUTF16LE(password))) //#nosec G401 -- MD5 required by MS-OFFCRYPTO §2.3.7.3; protocol-mandated
	truncated := h0[:5]
	// intermediateBuffer = (truncated + salt) repeated 16 times = 336 bytes
	unit := append(truncated, salt...) //nolint:gocritic // intentional local copy
	buf := make([]byte, 0, len(unit)*16)
	for i := 0; i < 16; i++ {
		buf = append(buf, unit...)
	}
	h1 := md5.Sum(buf) //#nosec G401 -- protocol-mandated MD5
	truncated2 := h1[:5]
	var blockBytes [4]byte
	binary.LittleEndian.PutUint32(blockBytes[:], block)
	hfinal := md5.Sum(append(truncated2, blockBytes[:]...)) //#nosec G401 -- protocol-mandated MD5
	return hfinal[:16]
}

// rc4MD5VerifyPW returns true when the password matches the FILEPASS RC4 v1.1
// verifier. Uses a single RC4 stream: decrypt encryptedVerifier (16 bytes)
// then encryptedVerifierHash (16 bytes) with the same keystream; compare
// MD5(verifier) == verifierHash.
func rc4MD5VerifyPW(password string, salt, encVerifier, encVerifierHash []byte) bool {
	key := rc4MD5MakeKey(password, salt, 0)
	c, err := rc4.NewCipher(key) //#nosec G405 -- RC4 required by MS-OFFCRYPTO BIFF8 protocol; protocol-mandated interop
	if err != nil {
		return false
	}
	verifier := make([]byte, 16)
	c.XORKeyStream(verifier, encVerifier[:16])
	verifierHash := make([]byte, 16)
	c.XORKeyStream(verifierHash, encVerifierHash[:16])
	actual := md5.Sum(verifier) //#nosec G401 -- protocol-mandated MD5
	return actual[:] != nil && string(actual[:]) == string(verifierHash)
}

// rc4MD5Decrypt decrypts the raw BIFF8 workbook stream encrypted with RC4 v1.1.
// Each 512-byte block is decrypted with a fresh RC4 key (block counter starts at 0).
// Output is capped at maxDefaultPWOut.
func rc4MD5Decrypt(password string, salt, ciphertext []byte) []byte {
	const blockSize = 512
	out := make([]byte, 0, len(ciphertext))
	for blk := 0; ; blk++ {
		if len(out) >= maxDefaultPWOut {
			break
		}
		start := blk * blockSize
		if start >= len(ciphertext) {
			break
		}
		end := start + blockSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		chunk := ciphertext[start:end]
		key := rc4MD5MakeKey(password, salt, uint32(blk)) //#nosec G115 -- blk bounded by ciphertext length
		c, err := rc4.NewCipher(key)                      //#nosec G405 -- RC4 required by MS-OFFCRYPTO BIFF8 protocol; protocol-mandated interop
		if err != nil {
			break
		}
		plain := make([]byte, len(chunk))
		c.XORKeyStream(plain, chunk)
		remaining := maxDefaultPWOut - len(out)
		if len(plain) > remaining {
			plain = plain[:remaining]
		}
		out = append(out, plain...)
	}
	return out
}

// ---------------------------------------------------------------------------
// B2 — BIFF8 RC4 CryptoAPI (SHA1-based key derivation, MS-OFFCRYPTO §2.3.6)
// ---------------------------------------------------------------------------

// rc4SHA1MakeKey derives the RC4 key for CryptoAPI (SHA1-based) encryption.
// keySize is in bits (typically 40 or 128). block is the 512-byte chunk index.
func rc4SHA1MakeKey(password string, salt []byte, keySize int, block uint32) []byte {
	pw := []byte(pwUTF16LE(password))
	h0 := sha1.Sum(append(salt, pw...)) //#nosec G401 -- protocol-mandated SHA1
	var blockBytes [4]byte
	binary.LittleEndian.PutUint32(blockBytes[:], block)
	hfinal := sha1.Sum(append(h0[:], blockBytes[:]...)) //#nosec G401 -- protocol-mandated SHA1
	if keySize == 40 {
		key := make([]byte, 16)
		copy(key, hfinal[:5])
		// remaining 11 bytes are zero from make
		return key
	}
	return hfinal[:keySize/8]
}

// rc4SHA1VerifyPW returns true when the password matches the CryptoAPI verifier.
// Uses a single RC4 stream: decrypt encryptedVerifier (16 bytes) then
// encryptedVerifierHash (20 bytes); compare SHA1(verifier) == verifierHash.
func rc4SHA1VerifyPW(password string, salt, encVerifier, encVerifierHash []byte, keySize int) bool {
	key := rc4SHA1MakeKey(password, salt, keySize, 0)
	c, err := rc4.NewCipher(key) //#nosec G405 -- RC4 required by MS-OFFCRYPTO BIFF8 protocol; protocol-mandated interop
	if err != nil {
		return false
	}
	verifier := make([]byte, 16)
	c.XORKeyStream(verifier, encVerifier[:16])
	hashLen := 20 // SHA1 digest size
	if len(encVerifierHash) < hashLen {
		return false
	}
	verifierHash := make([]byte, hashLen)
	c.XORKeyStream(verifierHash, encVerifierHash[:hashLen])
	actual := sha1.Sum(verifier) //#nosec G401 -- protocol-mandated SHA1
	return string(actual[:]) == string(verifierHash[:hashLen])
}

// rc4SHA1Decrypt decrypts a CryptoAPI RC4 encrypted stream.
// Each 512-byte block uses a fresh key. Output capped at maxDefaultPWOut.
func rc4SHA1Decrypt(password string, salt []byte, keySize int, ciphertext []byte) []byte {
	const blockSize = 512
	out := make([]byte, 0, len(ciphertext))
	for blk := 0; ; blk++ {
		if len(out) >= maxDefaultPWOut {
			break
		}
		start := blk * blockSize
		if start >= len(ciphertext) {
			break
		}
		end := start + blockSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		chunk := ciphertext[start:end]
		key := rc4SHA1MakeKey(password, salt, keySize, uint32(blk)) //#nosec G115 -- blk bounded by ciphertext length
		c, err := rc4.NewCipher(key)                                //#nosec G405 -- RC4 required by MS-OFFCRYPTO BIFF8 protocol; protocol-mandated interop
		if err != nil {
			break
		}
		plain := make([]byte, len(chunk))
		c.XORKeyStream(plain, chunk)
		remaining := maxDefaultPWOut - len(out)
		if len(plain) > remaining {
			plain = plain[:remaining]
		}
		out = append(out, plain...)
	}
	return out
}

// ---------------------------------------------------------------------------
// B2 — OOXML Agile (ECMA-376, AES-256-CBC + SHA-512)
// ---------------------------------------------------------------------------

// agileInfo carries the parsed fields from an agile EncryptionInfo XML.
type agileInfo struct {
	keyDataSalt          []byte
	keyDataHashAlg       string
	keyDataBlockSize     int
	passwordSalt         []byte
	passwordHashAlg      string
	passwordKeyBits      int
	spinCount            int
	encVerifierHashInput []byte
	encVerifierHashValue []byte
	encKeyValue          []byte
}

// maxAgileSpinCount caps the password spin count to guard against DoS
// via a file-controlled field.
const maxAgileSpinCount = 200000

// agileXML is the subset of EncryptionInfo XML fields needed for decryption.
type agileXML struct {
	XMLName xml.Name `xml:"encryption"`
	KeyData struct {
		SaltValue     string `xml:"saltValue,attr"`
		HashAlgorithm string `xml:"hashAlgorithm,attr"`
		BlockSize     string `xml:"blockSize,attr"`
		KeyBits       string `xml:"keyBits,attr"`
		HashSize      string `xml:"hashSize,attr"`
	} `xml:"keyData"`
	KeyEncryptors struct {
		KeyEncryptor struct {
			EncryptedKey struct {
				SpinCount                  string `xml:"spinCount,attr"`
				SaltValue                  string `xml:"saltValue,attr"`
				HashAlgorithm              string `xml:"hashAlgorithm,attr"`
				KeyBits                    string `xml:"keyBits,attr"`
				EncryptedVerifierHashInput string `xml:"encryptedVerifierHashInput,attr"`
				EncryptedVerifierHashValue string `xml:"encryptedVerifierHashValue,attr"`
				EncryptedKeyValue          string `xml:"encryptedKeyValue,attr"`
			} `xml:"encryptedKey"`
		} `xml:"keyEncryptor"`
	} `xml:"keyEncryptors"`
}

// parseAgileInfo parses the XML body from an agile EncryptionInfo stream.
// The caller must have already skipped the 8-byte version+reserved header.
func parseAgileInfo(xmlData []byte) (agileInfo, error) {
	var doc agileXML
	if err := xml.Unmarshal(xmlData, &doc); err != nil {
		return agileInfo{}, err
	}
	ek := doc.KeyEncryptors.KeyEncryptor.EncryptedKey
	info := agileInfo{
		keyDataHashAlg:  doc.KeyData.HashAlgorithm,
		passwordHashAlg: ek.HashAlgorithm,
	}
	var err error
	if info.keyDataSalt, err = base64.StdEncoding.DecodeString(doc.KeyData.SaltValue); err != nil {
		return agileInfo{}, err
	}
	info.keyDataBlockSize = atoi(doc.KeyData.BlockSize)
	info.passwordKeyBits = atoi(ek.KeyBits)
	info.spinCount = atoi(ek.SpinCount)
	if info.spinCount <= 0 || info.spinCount > maxAgileSpinCount {
		info.spinCount = maxAgileSpinCount
	}
	if info.passwordSalt, err = base64.StdEncoding.DecodeString(ek.SaltValue); err != nil {
		return agileInfo{}, err
	}
	if info.encVerifierHashInput, err = base64.StdEncoding.DecodeString(ek.EncryptedVerifierHashInput); err != nil {
		return agileInfo{}, err
	}
	if info.encVerifierHashValue, err = base64.StdEncoding.DecodeString(ek.EncryptedVerifierHashValue); err != nil {
		return agileInfo{}, err
	}
	if info.encKeyValue, err = base64.StdEncoding.DecodeString(ek.EncryptedKeyValue); err != nil {
		return agileInfo{}, err
	}
	return info, nil
}

// agileHashIter computes the iterated SHA-512 hash for agile key derivation:
// h = SHA512(salt + passwordUTF16LE), then for i in [0, spinCount):
// h = SHA512(le32(i) + h).
func agileHashIter(password string, salt []byte, spinCount int) []byte {
	pw := []byte(pwUTF16LE(password))
	h := sha512.Sum512(append(salt, pw...))
	for i := 0; i < spinCount; i++ {
		var iBytes [4]byte
		binary.LittleEndian.PutUint32(iBytes[:], uint32(i)) //#nosec G115 -- i < maxAgileSpinCount (200000), fits in uint32
		buf := make([]byte, 4+len(h))
		copy(buf, iBytes[:])
		copy(buf[4:], h[:])
		h = sha512.Sum512(buf)
	}
	return h[:]
}

// agileHashFinal computes SHA512(h + blkKey) and returns the first keyBits/8 bytes.
func agileHashFinal(h, blkKey []byte, keyBits int) []byte {
	buf := make([]byte, len(h)+len(blkKey))
	copy(buf, h)
	copy(buf[len(h):], blkKey)
	sum := sha512.Sum512(buf)
	n := keyBits / 8
	if n > len(sum) {
		n = len(sum)
	}
	return sum[:n]
}

// aesCBCDecrypt decrypts data with AES-CBC using key and iv. Returns nil on error.
func aesCBCDecrypt(data, key, iv []byte) []byte {
	// Pad data to AES block size if needed
	if len(data)%aes.BlockSize != 0 {
		padded := make([]byte, ((len(data)+aes.BlockSize-1)/aes.BlockSize)*aes.BlockSize)
		copy(padded, data)
		data = padded
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	if len(iv) != aes.BlockSize {
		return nil
	}
	if len(data) < aes.BlockSize {
		return nil
	}
	out := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(out, data)
	return out
}

// agileBlockKeys for agile verify+extract operations (ECMA-376, MS-OFFCRYPTO §2.3.4.14).
var (
	agileBlkKeyVerifierHashInput = []byte{0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79}
	agileBlkKeyVerifierHashValue = []byte{0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E}
	agileBlkKeyEncryptedKeyValue = []byte{0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6}
)

// agileVerifyPW returns true if the password matches the agile EncryptionInfo verifier.
func agileVerifyPW(password string, info agileInfo) bool {
	if info.passwordKeyBits <= 0 || info.passwordKeyBits > 512 {
		return false
	}
	h := agileHashIter(password, info.passwordSalt, info.spinCount)
	key1 := agileHashFinal(h, agileBlkKeyVerifierHashInput, info.passwordKeyBits)
	key2 := agileHashFinal(h, agileBlkKeyVerifierHashValue, info.passwordKeyBits)

	// IV for AES-CBC is the passwordSalt.
	hashInput := aesCBCDecrypt(info.encVerifierHashInput, key1, info.passwordSalt)
	if hashInput == nil {
		return false
	}
	expectedHash := aesCBCDecrypt(info.encVerifierHashValue, key2, info.passwordSalt)
	if expectedHash == nil {
		return false
	}
	actualHash := sha512.Sum512(hashInput)
	// expectedHash may be padded to AES block size; compare only actualHash length bytes.
	n := len(actualHash)
	if n > len(expectedHash) {
		n = len(expectedHash)
	}
	return string(actualHash[:n]) == string(expectedHash[:n])
}

// agileExtractKey decrypts and returns the document secret key from the agile info.
func agileExtractKey(password string, info agileInfo) []byte {
	if info.passwordKeyBits <= 0 || info.passwordKeyBits > 512 {
		return nil
	}
	h := agileHashIter(password, info.passwordSalt, info.spinCount)
	key3 := agileHashFinal(h, agileBlkKeyEncryptedKeyValue, info.passwordKeyBits)
	skey := aesCBCDecrypt(info.encKeyValue, key3, info.passwordSalt)
	if skey == nil {
		return nil
	}
	n := info.passwordKeyBits / 8
	if n > len(skey) {
		n = len(skey)
	}
	return skey[:n]
}

// agileDecrypt decrypts the EncryptedPackage stream using the extracted secret key.
// The first 8 bytes are the totalSize uint64 LE; then 4096-byte segments follow.
// Each segment IV = SHA512(keyDataSalt + le32(segmentIndex))[:blockSize].
func agileDecrypt(key []byte, info agileInfo, encPkg []byte) []byte {
	if len(encPkg) < 8 {
		return nil
	}
	totalSize := binary.LittleEndian.Uint64(encPkg[:8])
	if totalSize > maxDefaultPWOut {
		totalSize = maxDefaultPWOut
	}
	const segLen = 4096
	out := make([]byte, 0, int(totalSize))
	data := encPkg[8:]
	for i := 0; len(data) > 0 && len(out) < int(totalSize); i++ {
		chunk := data
		if len(chunk) > segLen {
			chunk = chunk[:segLen]
		}
		data = data[len(chunk):]

		// Compute IV: SHA512(keyDataSalt + le32(i))[:blockSize]
		var iBytes [4]byte
		binary.LittleEndian.PutUint32(iBytes[:], uint32(i)) //#nosec G115 -- segment index, bounded by maxDefaultPWOut/4096 < 2048
		ivSrc := append(info.keyDataSalt, iBytes[:]...)
		ivFull := sha512.Sum512(ivSrc)
		blockSize := info.keyDataBlockSize
		if blockSize <= 0 || blockSize > 16 {
			blockSize = 16
		}
		iv := ivFull[:blockSize]

		plain := aesCBCDecrypt(chunk, key, iv)
		if plain == nil {
			break
		}
		remaining := int(totalSize) - len(out)
		if len(plain) > remaining {
			plain = plain[:remaining]
		}
		out = append(out, plain...)
	}
	return out
}

// ---------------------------------------------------------------------------
// B2 — OOXML Standard (ECMA-376, AES-ECB + SHA-1)
// ---------------------------------------------------------------------------

// standardInfo carries parsed fields from a standard EncryptionInfo stream.
type standardInfo struct {
	salt            []byte
	keySize         int // bits
	encVerifier     []byte
	encVerifierHash []byte
}

// parseStandardInfo parses the binary standard EncryptionInfo body.
// Caller has already consumed the 4-byte version header; the stream starts
// at the flags uint32.
func parseStandardInfo(data []byte) (standardInfo, error) {
	// Layout: flags(4) + headerSize(4) + EncryptionHeader[headerSize] + EncryptionVerifier
	if len(data) < 8 {
		return standardInfo{}, errTruncated
	}
	headerSize := int(binary.LittleEndian.Uint32(data[4:8]))
	if len(data) < 8+headerSize {
		return standardInfo{}, errTruncated
	}
	header := data[8 : 8+headerSize]
	// EncryptionHeader field offsets (each 4 bytes):
	// [0] flags, [4] sizeExtra, [8] algId, [12] algIdHash, [16] keySize, [20] providerType, ...
	if len(header) < 20 {
		return standardInfo{}, errTruncated
	}
	keyBits := int(binary.LittleEndian.Uint32(header[16:20]))
	if keyBits <= 0 || keyBits > 256 {
		keyBits = 128 // default
	}
	// EncryptionVerifier follows the header.
	verifier := data[8+headerSize:]
	// Layout: saltSize(4) + salt(16) + encryptedVerifier(16) + verifierHashSize(4) + encryptedVerifierHash(32)
	if len(verifier) < 4+16+16+4+32 {
		return standardInfo{}, errTruncated
	}
	salt := make([]byte, 16)
	copy(salt, verifier[4:20])
	encVerifier := make([]byte, 16)
	copy(encVerifier, verifier[20:36])
	encVerifierHash := make([]byte, 32)
	copy(encVerifierHash, verifier[40:72])
	return standardInfo{
		salt:            salt,
		keySize:         keyBits,
		encVerifier:     encVerifier,
		encVerifierHash: encVerifierHash,
	}, nil
}

// standardMakeKey derives the AES key from a password using the ECMA-376
// standard method (SHA-1 spin + XOR pad, MS-OFFCRYPTO §2.3.4.7).
func standardMakeKey(password string, info standardInfo) []byte {
	const spinCount = 50000
	salt := info.salt
	pw := []byte(pwUTF16LE(password))
	h := sha1.Sum(append(salt, pw...)) //#nosec G401 -- protocol-mandated SHA1
	for i := 0; i < spinCount; i++ {
		var iBytes [4]byte
		binary.LittleEndian.PutUint32(iBytes[:], uint32(i)) //#nosec G115 -- i < 50000, fits uint32
		buf := make([]byte, 4+len(h))
		copy(buf, iBytes[:])
		copy(buf[4:], h[:])
		h = sha1.Sum(buf) //#nosec G401 -- protocol-mandated SHA1
	}
	// Block 0 finalization.
	var blockBytes [4]byte
	// blockBytes stays zero for block 0
	hfinal := sha1.Sum(append(h[:], blockBytes[:]...)) //#nosec G401 -- protocol-mandated SHA1

	cbHash := 20 // SHA1 digest size
	// XOR derivation (MS-OFFCRYPTO §2.3.4.7):
	buf1 := make([]byte, 64)
	for i := 0; i < 64; i++ {
		if i < cbHash {
			buf1[i] = hfinal[i] ^ 0x36 //#nosec G602 -- i < cbHash == 20 < len(hfinal) == 20; guarded
		} else {
			buf1[i] = 0x36
		}
	}
	x1 := sha1.Sum(buf1) //#nosec G401 -- protocol-mandated SHA1
	buf2 := make([]byte, 64)
	for i := 0; i < 64; i++ {
		if i < cbHash {
			buf2[i] = hfinal[i] ^ 0x5C //#nosec G602 -- i < cbHash == 20 < len(hfinal) == 20; guarded
		} else {
			buf2[i] = 0x5C
		}
	}
	x2 := sha1.Sum(buf2) //#nosec G401 -- protocol-mandated SHA1
	x3 := append(x1[:], x2[:]...)
	n := info.keySize / 8
	if n > len(x3) {
		n = len(x3)
	}
	return x3[:n]
}

// standardVerifyPW returns true if the key (derived from password) decrypts the
// verifier to produce the expected SHA-1 hash. Uses AES-ECB mode.
func standardVerifyPW(password string, info standardInfo) bool {
	key := standardMakeKey(password, info)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	// AES-ECB: decrypt encryptedVerifier (16 bytes)
	verifier := make([]byte, 16)
	block.Decrypt(verifier, info.encVerifier[:16])
	expectedHash := sha1.Sum(verifier) //#nosec G401 -- protocol-mandated SHA1

	// AES-ECB: decrypt encryptedVerifierHash (first 16 bytes, take first 20 bytes of result)
	verifierHash := make([]byte, 16)
	block.Decrypt(verifierHash, info.encVerifierHash[:16])

	// Compare first 16 bytes of SHA1 (SHA1 is 20; only 16 decrypted bytes available).
	return string(expectedHash[:16]) == string(verifierHash[:16])
}

// standardDecrypt decrypts the EncryptedPackage stream using AES-ECB.
// Layout: totalSize uint32 LE at [0:4], reserved at [4:8], ciphertext at [8:].
func standardDecrypt(password string, info standardInfo, encPkg []byte) []byte {
	if len(encPkg) < 8 {
		return nil
	}
	totalSize := int(binary.LittleEndian.Uint32(encPkg[:4]))
	if totalSize > maxDefaultPWOut {
		totalSize = maxDefaultPWOut
	}
	ciphertext := encPkg[8:]
	if len(ciphertext) == 0 {
		return nil
	}
	key := standardMakeKey(password, info)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	// AES-ECB: decrypt 16 bytes at a time.
	if len(ciphertext)%aes.BlockSize != 0 {
		// Pad to block boundary
		padded := make([]byte, ((len(ciphertext)+aes.BlockSize-1)/aes.BlockSize)*aes.BlockSize)
		copy(padded, ciphertext)
		ciphertext = padded
	}
	plain := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plain[i:], ciphertext[i:])
	}
	if totalSize > len(plain) {
		totalSize = len(plain)
	}
	return plain[:totalSize]
}

// ---------------------------------------------------------------------------
// B2 — BIFF8 RC4 orchestrator (fromDefaultPWRC4)
// ---------------------------------------------------------------------------

// fromDefaultPWRC4 tries to decrypt a BIFF8 Workbook/Book stream protected
// with FILEPASS RC4 encryption (wEncryptionType==1). It handles both v1.1
// (MD5-based, vMajor=1, vMinor=1) and CryptoAPI (SHA1-based, vMajor in
// {2,3,4}, vMinor=2). On success it emits DEFAULTPW-DECRYPTED and feeds the
// plaintext to scanBIFFXLMStream. Called alongside fromDefaultPWXOR.
func fromDefaultPWRC4(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || expired(deadline) || hasDecryptedMarker(res) {
		return
	}

	var wb []byte
	for _, name := range []string{"Workbook", "Book"} {
		if s := ole.FindStreamByName(name); s != nil {
			wb = ole.GetStreamView(s.Index)
			break
		}
	}
	if len(wb) < 4 {
		return
	}

	// Scan the first maxScanRecords records for FILEPASS.
	const maxScanRecords = 64
	off := 0
	for r := 0; r < maxScanRecords; r++ {
		if expired(deadline) || off+4 > len(wb) {
			return
		}
		recType := binary.LittleEndian.Uint16(wb[off:])
		recLen := int(binary.LittleEndian.Uint16(wb[off+2:]))
		bodyOff := off + 4
		if bodyOff+recLen > len(wb) {
			return
		}
		if recType == 0x002F { // FILEPASS
			body := wb[bodyOff : bodyOff+recLen]
			if len(body) < 2 {
				return
			}
			encType := binary.LittleEndian.Uint16(body)
			if encType != 0x0001 { // must be RC4 (1), not XOR (0)
				return
			}
			if len(body) < 6 {
				return
			}
			vMajor := binary.LittleEndian.Uint16(body[2:])
			vMinor := binary.LittleEndian.Uint16(body[4:])

			// The Workbook stream encrypted data starts right AFTER the FILEPASS record.
			encData := wb[bodyOff+recLen:]

			if vMajor == 1 && vMinor == 1 {
				// RC4 v1.1 (MD5-based): salt[0:16] encVerifier[16:32] encVerifierHash[32:48]
				if len(body) < 6+48 {
					return
				}
				salt := body[6:22]
				encVerifier := body[22:38]
				encVerifierHash := body[38:54]
				for _, pw := range defaultPasswords {
					if expired(deadline) {
						return
					}
					if !rc4MD5VerifyPW(pw, salt, encVerifier, encVerifierHash) {
						continue
					}
					plain := rc4MD5Decrypt(pw, salt, encData)
					if len(plain) == 0 {
						return
					}
					emitDecrypted(res, plain, deadline)
					return
				}
			} else if (vMajor == 2 || vMajor == 3 || vMajor == 4) && vMinor == 2 {
				// CryptoAPI (SHA1-based): parse EncryptionHeader + EncryptionVerifier
				// Body after wEncryptionType(2) + vMajor(2) + vMinor(2) = offset 6
				cryptoBody := body[6:]
				if len(cryptoBody) < 8 {
					return
				}
				headerSize := int(binary.LittleEndian.Uint32(cryptoBody[4:8]))
				if len(cryptoBody) < 8+headerSize {
					return
				}
				header := cryptoBody[8 : 8+headerSize]
				if len(header) < 20 {
					return
				}
				keyBits := int(binary.LittleEndian.Uint32(header[16:20]))
				if keyBits <= 0 {
					keyBits = 40
				}
				verifier := cryptoBody[8+headerSize:]
				// EncryptionVerifier: saltSize(4) salt(16) encVerifier(16) verifierHashSize(4) encVerifierHash(20)
				if len(verifier) < 4+16+16+4+20 {
					return
				}
				salt := verifier[4:20]
				encVerifier := verifier[20:36]
				encVerifierHash := verifier[40:60]
				for _, pw := range defaultPasswords {
					if expired(deadline) {
						return
					}
					if !rc4SHA1VerifyPW(pw, salt, encVerifier, encVerifierHash, keyBits) {
						continue
					}
					plain := rc4SHA1Decrypt(pw, salt, keyBits, encData)
					if len(plain) == 0 {
						return
					}
					emitDecrypted(res, plain, deadline)
					return
				}
			}
			return
		}
		if recType == 0x000A { // EOF
			return
		}
		off = bodyOff + recLen
	}
}

// ---------------------------------------------------------------------------
// B2 — OOXML orchestrator (fromDefaultPWOOXML)
// ---------------------------------------------------------------------------

// fromDefaultPWOOXML tries default passwords against an ECMA-376 encrypted
// OOXML document. It reads EncryptionInfo to detect agile vs standard
// encryption, tries each password, and if one succeeds decrypts the
// EncryptedPackage stream, then routes the plaintext ZIP through fromOOXML.
// Called BEFORE the encrypted-early-return block in fromOLE.
func fromDefaultPWOOXML(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || expired(deadline) || hasDecryptedMarker(res) {
		return
	}
	ei := ole.FindStreamByName("EncryptionInfo")
	ep := ole.FindStreamByName("EncryptedPackage")
	if ei == nil || ep == nil {
		return
	}
	infoData := ole.GetStreamView(ei.Index)
	encPkgData := ole.GetStreamView(ep.Index)
	if len(infoData) < 4 || len(encPkgData) == 0 {
		return
	}

	// Version header: versionMajor(2) + versionMinor(2)
	vMajor := binary.LittleEndian.Uint16(infoData[0:2])
	vMinor := binary.LittleEndian.Uint16(infoData[2:4])

	if vMajor == 4 && vMinor == 4 {
		// Agile encryption: skip 8-byte header (4-byte version + 4-byte reserved)
		if len(infoData) < 8 {
			return
		}
		xmlData := infoData[8:]
		info, err := parseAgileInfo(xmlData)
		if err != nil {
			return
		}
		for _, pw := range defaultPasswords {
			if expired(deadline) {
				return
			}
			if !agileVerifyPW(pw, info) {
				continue
			}
			key := agileExtractKey(pw, info)
			if key == nil {
				return
			}
			plain := agileDecrypt(key, info, encPkgData)
			if len(plain) == 0 {
				return
			}
			res.Streams = append(res.Streams, []byte("DEFAULTPW-DECRYPTED"))
			fromOOXML(plain, res, deadline, nil)
			return
		}
	} else if (vMajor == 2 || vMajor == 3 || vMajor == 4) && vMinor == 2 {
		// Standard encryption: version header already consumed (4 bytes), body follows
		body := infoData[4:]
		info, err := parseStandardInfo(body)
		if err != nil {
			return
		}
		for _, pw := range defaultPasswords {
			if expired(deadline) {
				return
			}
			if !standardVerifyPW(pw, info) {
				continue
			}
			plain := standardDecrypt(pw, info, encPkgData)
			if len(plain) == 0 {
				return
			}
			res.Streams = append(res.Streams, []byte("DEFAULTPW-DECRYPTED"))
			fromOOXML(plain, res, deadline, nil)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// pwUTF16LE encodes a password string as UTF-16 little-endian bytes (ASCII fast path).
// Returns a string to avoid allocation at call sites that wrap with []byte().
func pwUTF16LE(s string) string {
	out := make([]byte, len(s)*2)
	for i := 0; i < len(s); i++ {
		out[i*2] = s[i]
		// out[i*2+1] stays 0 (little-endian high byte for ASCII)
	}
	return string(out)
}

// atoi parses a decimal string to int, returning 0 on any error.
func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// errTruncated is a sentinel error for short binary reads in parseStandardInfo.
var errTruncated = errTruncatedT{}

type errTruncatedT struct{}

func (e errTruncatedT) Error() string { return "truncated EncryptionInfo" }

// fromDefaultPWXOR attempts to decrypt a BIFF8 Workbook/Book stream that is
// XOR-obfuscated (FILEPASS wEncryptionType==0) using the VelvetSweatshop
// transparent password. On success it emits "DEFAULTPW-DECRYPTED" and feeds
// the decrypted stream to scanBIFFXLMStream so hidden macros surface.
//
// Called after fromOLEEncType so ENCRYPTION-XOR is already in res.Streams —
// YARA rules can stack both markers. Emits the marker at most once.
func fromDefaultPWXOR(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || expired(deadline) || hasDecryptedMarker(res) {
		return
	}

	var wb []byte
	for _, name := range []string{"Workbook", "Book"} {
		if s := ole.FindStreamByName(name); s != nil {
			wb = ole.GetStreamView(s.Index)
			break
		}
	}
	if len(wb) < 4 {
		return
	}

	// Locate FILEPASS in the first few records (globals substream).
	const maxScanRecords = 64
	off := 0
	for r := 0; r < maxScanRecords; r++ {
		if expired(deadline) || off+4 > len(wb) {
			return
		}
		recType := binary.LittleEndian.Uint16(wb[off:])
		recLen := int(binary.LittleEndian.Uint16(wb[off+2:]))
		bodyOff := off + 4
		if bodyOff+recLen > len(wb) {
			return
		}
		if recType == 0x002F { // FILEPASS
			body := wb[bodyOff : bodyOff+recLen]
			if len(body) < 2 {
				return
			}
			if binary.LittleEndian.Uint16(body) != 0x0000 {
				return // not XOR obfuscation
			}
			verifier, ok := filepassXORVerifier(body)
			if !ok {
				return
			}
			if !verifyXORPassword(velvetPassword, verifier) {
				return // wrong password — not VelvetSweatshop
			}
			xorArray := createXORArrayMethod1(velvetPassword)
			decrypted := decryptXORMethod1(wb, xorArray)
			if len(decrypted) == 0 {
				return
			}
			res.Streams = append(res.Streams, []byte("DEFAULTPW-DECRYPTED"))
			scanBIFFXLMStream(decrypted, res, deadline)
			return
		}
		if recType == 0x000A { // EOF — FILEPASS must precede it
			return
		}
		off = bodyOff + recLen
	}
}
