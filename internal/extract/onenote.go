package extract

import (
	"bytes"
	"encoding/binary"
	"time"
)

// MS-ONESTORE (OneNote) embedded-file extraction. A standalone OneNote section
// (.one) is a recognised malware-delivery vector: the attacker embeds an
// executable payload (.exe/.hta/.cmd/.vbs/.lnk/.iso) as a FileDataStoreObject
// and overlays a "Double click to view" image so the victim launches it. The
// .one binary is neither OLE2 nor ZIP, so the existing container paths never see
// the payload; raw-byte scanning sees it buried among ONESTORE structures and
// often misses it.
//
// Rather than implement the full MS-ONESTORE object graph (revision stores, file
// node lists, property sets), we carve every FileDataStoreObject by its 16-byte
// sentinel GUID — exactly the approach ClamAV's OneNote unpacker uses. The
// embedded file bytes are then emitted as their own stream so the keyword/PE/
// container rules match them directly. Best-effort and bounded; a truncated or
// hostile structure is skipped, never fatal (Extract's recover still covers a
// panic).
//
// References:
//   - [MS-ONESTORE] §2.2.4 FileDataStoreObject, §2.8 header guidFileType
//   - ClamAV libclamav/onenote.c

// OneNote file-type GUIDs, on-disk little-endian byte order (Data1/2/3 LE,
// Data4 raw). A .one section and a .onetoc2 table-of-contents both carry one of
// these as the first 16 bytes of the file (guidFileType in the ONESTORE header).
var (
	// {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3} — OneNote section (.one)
	oneSectionGUID = []byte{
		0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
		0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3,
	}
	// {43FF2FA1-EFD9-4C76-9EE2-10EA5722765F} — OneNote TOC (.onetoc2)
	oneTOCGUID = []byte{
		0xA1, 0x2F, 0xFF, 0x43, 0xD9, 0xEF, 0x76, 0x4C,
		0x9E, 0xE2, 0x10, 0xEA, 0x57, 0x22, 0x76, 0x5F,
	}
	// {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC} — guidHeader marking the start of a
	// FileDataStoreObject (MS-ONESTORE §2.2.4).
	oneFDSOHeaderGUID = []byte{
		0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
		0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC,
	}
)

const (
	// FileDataStoreObject header after guidHeader: cbLength (uint64) +
	// unused (uint32) + reserved (uint64). Total 16 + 8 + 4 + 8 = 36 bytes
	// before the embedded file data begins.
	oneFDSODataOffset = 16 + 8 + 4 + 8

	// maxONEFiles bounds how many embedded files we emit from one .one section.
	maxONEFiles = 128
	// maxBytesPerONEFile caps one emitted embedded file (raw scan covers the rest).
	maxBytesPerONEFile = 16 << 20
	// maxTotalONE caps the cumulative embedded bytes emitted from one .one section.
	maxTotalONE = 64 << 20
	// oneFDSOMaxLen rejects an absurd cbLength before allocating/slicing — a
	// hostile FileDataStoreObject can claim a huge size; cap the claim at the
	// per-file ceiling and let the bounds check below clamp to what's present.
	oneFDSOMaxLen = maxBytesPerONEFile
)

// isOneNote reports whether buf begins with a OneNote file-type GUID.
func isOneNote(buf []byte) bool {
	return bytes.HasPrefix(buf, oneSectionGUID) || bytes.HasPrefix(buf, oneTOCGUID)
}

// fromOneNote carves every FileDataStoreObject out of a OneNote section and
// appends its embedded file bytes to res.Streams. Sets IsOneNote when buf was a
// recognised OneNote file (whether or not any embedded file was found). Bounded
// by the maxONE* caps; best-effort, a malformed object is skipped.
func fromOneNote(buf []byte, res *Result, deadline time.Time) {
	defer func() {
		if recover() != nil {
			res.Panicked = true
		}
	}()
	res.IsOneNote = true
	var total int
	rest := buf
	for len(res.Streams) < maxStreams && len(res.Streams) < maxONEFiles && total < maxTotalONE && !expired(deadline) {
		i := bytes.Index(rest, oneFDSOHeaderGUID)
		if i < 0 {
			break
		}
		hdr := rest[i:]
		if len(hdr) < oneFDSODataOffset {
			break // truncated header: nothing usable past here
		}
		cb := binary.LittleEndian.Uint64(hdr[16:24])
		data := hdr[oneFDSODataOffset:]
		// Clamp a hostile/oversized length claim to what's actually present and to
		// the per-file ceiling, so a lying cbLength can't drive a huge slice.
		n := cb
		if n > oneFDSOMaxLen {
			n = oneFDSOMaxLen
		}
		if n > uint64(len(data)) {
			n = uint64(len(data))
		}
		if n > 0 {
			b := append([]byte(nil), data[:n]...)
			res.Streams = append(res.Streams, b)
			total += len(b)
		}
		// Advance past the data we just consumed so the next bytes.Index can't
		// re-find a sentinel GUID *inside* the bytes already emitted (which would
		// emit overlapping near-duplicates and waste the per-doc budget). When the
		// claimed length was clamped to 0/short, still step past the header so the
		// loop always makes forward progress.
		adv := oneFDSODataOffset + int(n)
		if adv <= oneFDSODataOffset {
			adv = oneFDSODataOffset
		}
		if adv > len(hdr) {
			adv = len(hdr)
		}
		rest = hdr[adv:]
	}
}
