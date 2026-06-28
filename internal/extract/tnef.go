package extract

import (
	"time"

	"github.com/Teamwork/tnef"
)

// TNEF (Transport Neutral Encapsulation Format, "winmail.dat") attachment
// extraction. Outlook/Exchange wraps a message's rich-text body and its file
// attachments into a single proprietary winmail.dat blob; the real payload
// (.exe/.docm/.zip/.lnk/.iso …) lives inside as a TNEF attachment object and is
// invisible to the MIME-part walker and to raw-byte scanning, which sees only the
// opaque TNEF TLV stream. A dropper mailed as winmail.dat therefore slips past
// any scanner that does not unwrap the container — still common on corporate
// Exchange routes.
//
// The buffer starts with the fixed 32-bit TNEF signature 0x223E9F78 (on-disk
// little-endian bytes 78 9F 3E 22). We hand the whole blob to the pure-Go
// Teamwork/tnef decoder, emit each attachment's bytes as its own stream so the
// keyword/PE/container rules match the payload directly, and route every
// attachment back through extractChild so a nested zip/OLE2/OOXML/PDF/LNK carrier
// is unwrapped rather than left opaque. The HTML/RTF body is emitted too: a TNEF
// body can smuggle a scripted-HTML payload. Best-effort and bounded; a truncated
// or hostile blob is recovered, never fatal.
//
// Reference: [MS-OXTNEF] Transport Neutral Encapsulation Format.

const (
	// maxTNEFParts bounds how many attachment/body streams we emit from one blob.
	maxTNEFParts = 64
	// maxBytesPerTNEFPart caps one emitted part (raw scan covers any overflow).
	maxBytesPerTNEFPart = 16 << 20
	// maxTotalTNEF caps the cumulative emitted bytes from one winmail.dat.
	maxTotalTNEF = 64 << 20
)

// isTNEF reports whether buf begins with the fixed TNEF signature 0x223E9F78
// (little-endian on disk → bytes 78 9F 3E 22).
func isTNEF(buf []byte) bool {
	return len(buf) >= 4 &&
		buf[0] == 0x78 && buf[1] == 0x9F && buf[2] == 0x3E && buf[3] == 0x22
}

// fromTNEF decodes a winmail.dat blob, appends each attachment (and the RTF/HTML
// body) to res.Streams, and routes each attachment back through extractChild so a
// nested container payload is unwrapped. Sets IsTNEF when buf was a recognised
// TNEF blob (whether or not any part was extracted). Bounded by the maxTNEF*
// caps; best-effort — a malformed blob is recovered, never fatal.
func fromTNEF(buf []byte, res *Result, bud *archiveBudget, depth int, deadline time.Time) {
	defer func() {
		if recover() != nil {
			res.Panicked = true
		}
	}()
	res.IsTNEF = true
	data, err := tnef.Decode(buf)
	if err != nil || data == nil {
		return
	}

	var total int
	emit := func(b []byte, recurse bool) {
		if len(b) == 0 ||
			len(res.Streams) >= maxStreams ||
			total >= maxTotalTNEF ||
			expired(deadline) {
			return
		}
		if len(b) > maxBytesPerTNEFPart {
			b = b[:maxBytesPerTNEFPart]
		}
		s := append([]byte(nil), b...)
		res.Streams = append(res.Streams, s)
		total += len(s)
		// Recurse an attachment as a child carrier so a nested zip/OLE2/OOXML/
		// PDF/LNK payload is unwrapped, not just raw-scanned. nil bud (direct
		// callers / tests) → skip recursion; the raw stream still carries the
		// keyword/PE signal. Charge the shared archive budget for this member
		// (like fromArchive/fromOfficeZipCarriers) and stop recursing once it is
		// spent, so many TNEF attachments can't outrun the cross-carrier cap.
		if recurse && bud != nil && !bud.spent() {
			bud.members++
			bud.total += len(s)
			extractChild(s, res, bud, depth+1, deadline)
		}
	}

	parts := 0
	for _, a := range data.Attachments {
		if a == nil || parts >= maxTNEFParts {
			break
		}
		emit(a.Data, true)
		parts++
	}
	// The HTML/RTF body can itself smuggle a scripted payload — emit it (and let
	// extractChild route an HTML/SVG body through the smuggling path).
	emit(data.BodyHTML, true)
	emit(data.Body, true)
}
