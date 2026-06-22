package extract

// defaultpw.go — BIFF8 VelvetSweatshop default-password XOR decryption.
//
// Many malware XLS files are encrypted with the Excel transparent (default)
// password "VelvetSweatshop". Excel opens them silently without prompting —
// making them appear unprotected to users and opaque to scanners that only
// inspect raw bytes. The Workbook stream is XOR-obfuscated (FILEPASS
// wEncryptionType==0, Method 1); after decrypting we feed the plaintext to the
// existing XLM scanner so hidden macros are not missed.
//
// Faithfully ported from MS-OFFCRYPTO §2.3.7.2, verified against the
// msoffcrypto-tool reference (xor_obfuscation.py DocumentXOR class).
// No code derived from oletools or any GPL source — only the public spec
// algorithm constants are shared.

import (
	"encoding/binary"
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

// fromDefaultPWXOR attempts to decrypt a BIFF8 Workbook/Book stream that is
// XOR-obfuscated (FILEPASS wEncryptionType==0) using the VelvetSweatshop
// transparent password. On success it emits "DEFAULTPW-DECRYPTED" and feeds
// the decrypted stream to scanBIFFXLMStream so hidden macros surface.
//
// Called after fromOLEEncType so ENCRYPTION-XOR is already in res.Streams —
// YARA rules can stack both markers. Emits the marker at most once.
func fromDefaultPWXOR(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || expired(deadline) {
		return
	}

	// Double-call guard.
	for _, s := range res.Streams {
		if string(s) == "DEFAULTPW-DECRYPTED" {
			return
		}
	}

	var wb []byte
	for _, name := range []string{"Workbook", "Book"} {
		if s := ole.FindStreamByName(name); s != nil {
			wb = ole.GetStream(s.Index)
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
