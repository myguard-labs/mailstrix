package extract

import (
	"encoding/binary"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// ENC-TYPE + DIGSIG: classify encryption strength and flag digital signatures on
// a legacy OLE2 document — structural metadata that oletools' oleid/ClamAV
// surface but yarad previously reduced to a presence-only Encrypted flag.
//
// ENC-TYPE distinguishes the BIFF8 FILEPASS encryption kind so a rule can score
// weak XOR obfuscation (trivially removed, used to smuggle a macro past naive
// scanners) differently from real RC4/AES. DIGSIG records that the document
// carries a signature storage — benign on its own, but a SIGNAL when it rides
// alongside macros (a code-signed-looking maldoc), so it is scored low and
// matters only stacked.
//
// All markers are FP-safe by construction (yarad-only literals) and emitted at
// most once; both helpers fail open and are deadline-bounded.

const (
	// FILEPASS encryption types from the wEncryptionType word (MS-XLS 2.4.117 /
	// ClamAV ole2_extract.c:815). 0 = XOR obfuscation, >=1 = RC4 family
	// (RC4 / RC4 CryptoAPI — both real stream ciphers; the distinction does not
	// change the threat tier, so both report RC4).
	filepassXOR = 0
)

// fromOLEEncType scans the legacy BIFF8 Workbook/Book stream for a FILEPASS
// (0x002F) record and emits ENCRYPTION-XOR / ENCRYPTION-RC4 accordingly. It is a
// no-op on a non-spreadsheet OLE2 (no Workbook stream) and on an unencrypted one
// (no FILEPASS record). Bounded by a fixed record-scan budget.
func fromOLEEncType(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || expired(deadline) {
		return
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
	// FILEPASS appears early (right after BOF), so a small record budget suffices
	// and keeps the scan cheap on a hostile file.
	const maxRecords = 64
	off := 0
	for r := 0; r < maxRecords; r++ {
		if expired(deadline) || off+4 > len(wb) {
			return
		}
		recType := binary.LittleEndian.Uint16(wb[off:])
		recLen := int(binary.LittleEndian.Uint16(wb[off+2:]))
		body := off + 4
		if body+recLen > len(wb) {
			return
		}
		if recType == 0x002F { // FILEPASS
			// A FILEPASS with no encryption-type word is malformed/truncated, not
			// RC4 — fail open rather than fabricate an RC4 verdict (and an
			// Encrypted flag) from a broken record.
			if recLen < 2 {
				return
			}
			marker := "ENCRYPTION-RC4"
			if binary.LittleEndian.Uint16(wb[body:]) == filepassXOR {
				marker = "ENCRYPTION-XOR"
			}
			res.Encrypted = true
			res.Streams = append(res.Streams, []byte(marker))
			return
		}
		// EOF (0x000A) ends the workbook globals substream; FILEPASS, if present,
		// lives before it, so stop once we leave globals.
		if recType == 0x000A {
			return
		}
		off = body + recLen
	}
}

// fromOLEEncInfo emits ENCRYPTION-AES for an ECMA-376 encrypted OOXML wrapper
// (the CDFV2 OLE2 holding EncryptionInfo + EncryptedPackage). The container is
// always AES (standard or agile); we do not decrypt. Caller still sets
// res.Encrypted — this only enriches it with the type marker.
func fromOLEEncInfo(ole *oleparse.OLEFile, res *Result) {
	if ole == nil {
		return
	}
	res.Streams = append(res.Streams, []byte("ENCRYPTION-AES"))
}

// fromWordFibEncryption reads the FibBase (MS-DOC 2.5.1) from the WordDocument
// stream and emits ENCRYPTION-RC4 when bit 0x0100 of the flags word (offset 10)
// is set — indicating a password-protected (RC4-family) Word 97-2003 document.
// Complement to fromOLEEncType (which handles BIFF8 FILEPASS for spreadsheets).
// O(1) reads; fail-open on malformed/missing stream.
func fromWordFibEncryption(ole *oleparse.OLEFile, res *Result) {
	if ole == nil {
		return
	}
	s := ole.FindStreamByName("WordDocument")
	if s == nil {
		return
	}
	wd := ole.GetStream(s.Index)
	// FibBase starts at offset 0; need 12 bytes for flags at offset 10.
	if len(wd) < 12 {
		return
	}
	// wIdent must be 0xA5EC for a Word 97-2003 FIB (MS-DOC 2.5.1).
	if binary.LittleEndian.Uint16(wd[0:]) != 0xA5EC {
		return
	}
	if binary.LittleEndian.Uint16(wd[10:])&0x0100 != 0 { // fEncrypted
		res.Encrypted = true
		res.Streams = append(res.Streams, []byte("ENCRYPTION-RC4"))
	}
}

// fromPPTEncryptedSummary emits ENCRYPTION-RC4 for a legacy PowerPoint file
// that carries an EncryptedSummary storage. The presence of this OLE2 storage
// signals RC4/RC4-CryptoAPI encryption (the same family as BIFF8 FILEPASS RC4).
// Fail-open: missing storage → no marker, no side effects.
func fromPPTEncryptedSummary(ole *oleparse.OLEFile, res *Result) {
	if ole == nil {
		return
	}
	if ole.FindStreamByName("EncryptedSummary") != nil {
		res.Encrypted = true
		res.Streams = append(res.Streams, []byte("ENCRYPTION-RC4"))
	}
}

// fromOLEDigSig emits DIGITAL-SIGNATURE when the OLE2 carries a signature
// storage (_signatures or _xmlsignatures — ClamAV ole2_extract.c:1073). Office
// stores Authenticode/XML-DSIG material there; on a macro-bearing document it
// reads as a code-signed-looking lure, so a rule scores it low and only stacked.
func fromOLEDigSig(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || expired(deadline) {
		return
	}
	for _, name := range []string{"_signatures", "_xmlsignatures"} {
		if ole.FindStreamByName(name) != nil {
			res.Streams = append(res.Streams, []byte("DIGITAL-SIGNATURE"))
			return
		}
	}
}
