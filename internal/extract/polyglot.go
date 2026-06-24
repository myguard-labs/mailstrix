package extract

import (
	"bytes"
	"encoding/binary"
)

// Polyglot / file-type-confusion detection. A polyglot file satisfies two
// formats at once so that the security boundary and the execution boundary
// disagree: the secure email gateway parses it as one (allowed) type while the
// endpoint loads it as another (executable) type. The standard mail-malware
// form is a Windows PE (.exe/.dll) carrying an appended ZIP, or a ZIP carrying
// an appended PE — the gateway's archive parser walks the ZIP and clears it,
// while the OS happily runs the PE. yarad's extractor dispatches on the FIRST
// magic only (see ExtractWithOptions), so the second structure is never
// examined; this check surfaces the contradiction itself as a marker.
//
// FP-safety: a benign file is virtually never simultaneously a *valid* PE and a
// *valid* ZIP. Both halves are validated structurally (a real PE header reached
// through e_lfanew; a real ZIP end-of-central-directory record) so an incidental
// "MZ" or "PK" byte pair in ordinary content cannot trip the marker.

const (
	// peMaxScan bounds how far we look for an embedded PE so a large benign blob
	// is not walked end to end. A real appended loader sits near a boundary.
	peMaxScan = 8 << 20
	// dosHeaderMin is the minimum bytes for a DOS header carrying e_lfanew.
	dosHeaderMin = 0x40
)

var (
	mzMagic  = []byte{'M', 'Z'}
	peMagic  = []byte{'P', 'E', 0x00, 0x00}
	zipEOCD  = []byte{'P', 'K', 0x05, 0x06} // ZIP end-of-central-directory
	zipLocal = []byte{'P', 'K', 0x03, 0x04} // ZIP local file header (== zipMagic)
)

// isValidPEAt reports whether buf[off:] is a real PE image: an "MZ" DOS header
// whose e_lfanew (uint32 at +0x3C) points, within buf, to the "PE\0\0" signature.
// Validating through e_lfanew (not just the "MZ" pair) is what keeps an
// incidental "MZ" in text from being mistaken for an executable.
func isValidPEAt(buf []byte, off int) bool {
	if off < 0 || off+dosHeaderMin > len(buf) {
		return false
	}
	if !bytes.HasPrefix(buf[off:], mzMagic) {
		return false
	}
	e := off + int(binary.LittleEndian.Uint32(buf[off+0x3C:off+0x40]))
	if e < off+dosHeaderMin || e+len(peMagic) > len(buf) {
		return false
	}
	return bytes.Equal(buf[e:e+len(peMagic)], peMagic)
}

// findPE returns the offset of the first valid PE image in buf at or after
// `from`, or -1. Candidate "MZ" positions are validated through isValidPEAt.
func findPE(buf []byte, from int) int {
	limit := len(buf)
	if limit > peMaxScan {
		limit = peMaxScan
	}
	i := from
	for i < limit {
		j := bytes.Index(buf[i:limit], mzMagic)
		if j < 0 {
			return -1
		}
		at := i + j
		if isValidPEAt(buf, at) {
			return at
		}
		i = at + 1
	}
	return -1
}

// hasZIP reports whether buf contains a structurally valid ZIP: a local file
// header somewhere AND an end-of-central-directory record (the EOCD is what a
// ZIP parser scans backwards for, so its presence is the real "this is a ZIP"
// tell, independent of the leading magic).
func hasZIP(buf []byte) bool {
	return bytes.Contains(buf, zipLocal) && bytes.Contains(buf, zipEOCD)
}

// fromPolyglot emits the POLYGLOT marker when buf is simultaneously a valid PE
// and a valid ZIP — the two structures whose parsers disagree in the email
// gateway-vs-endpoint split. Called once on the top-level buffer; it never
// re-routes extraction. Best-effort and bounded.
func fromPolyglot(buf []byte, res *Result) {
	if len(buf) < dosHeaderMin {
		return
	}
	pe := findPE(buf, 0) >= 0
	zip := hasZIP(buf)
	if pe && zip {
		res.Polyglot = true
		res.Streams = append(res.Streams, []byte("POLYGLOT-PE-ZIP"))
	}
}
