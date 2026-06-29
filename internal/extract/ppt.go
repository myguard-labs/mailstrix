package extract

// PPT-VBA-EXTRACT: surface VBA macro code embedded inside legacy PowerPoint
// (.ppt/.pps) binary files.
//
// Problem: PowerPoint stores its VBA project inside ExternalObjectStorage records
// (record type 0x1011) in the "PowerPoint Document" binary stream — not as a
// standalone OLE2 VBA project at the root level. oleparse.ExtractMacros therefore
// finds no _VBA_PROJECT stream and reports no modules, leaving PPT VBA invisible
// to yarad's existing macro scanner.
//
// Fix: walk the MS-PPT record tree (see [MS-PPT] §2.1) inside the
// "PowerPoint Document" stream. Each ExternalObjectStorage record body is itself
// a sub-OLE2 container; parse it and extract macros from the nested compound file
// exactly as fromOLE does for a top-level doc. A PPT-VBA-EXTRACTED marker stream
// is emitted once so YARA rules can score the indicator.
//
// Bounds: maxPPTRecords iterations, maxPPTVBABlobs blobs, maxBytesPerModule per
// decompressed blob. Fail-open: every error path is a silent skip.

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"time"

	"www.velocidex.com/golang/oleparse"
)

const (
	// maxPPTRecords bounds how many MS-PPT record headers we scan before stopping.
	maxPPTRecords = 4096
	// maxPPTVBABlobs bounds how many ExternalObjectStorage blobs we process.
	maxPPTVBABlobs = 16
	// pptRecTypeExternalObjectStorage is the MS-PPT RecordType for ExternalObjectStorage.
	// [MS-PPT] §2.4.20.1
	pptRecTypeExternalObjectStorage = 0x1011
)

// fromPPTVBA scans the "PowerPoint Document" binary stream of an already-parsed
// OLE2 for ExternalObjectStorage records (RecordType 0x1011). Each such record
// body is a sub-OLE2 container (possibly zlib-compressed); the function parses
// each container, extracts any VBA macros, and appends them to res.Streams.
// A PPT-VBA-EXTRACTED marker is emitted exactly once if at least one VBA blob
// produced new streams. All errors are silently skipped (fail-open).
func fromPPTVBA(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if ole == nil || expired(deadline) {
		return
	}

	s := ole.FindStreamByName("PowerPoint Document")
	if s == nil {
		return // not a PPT OLE2
	}

	data := ole.GetStreamView(s.Index)
	if len(data) < 8 {
		return
	}
	if len(data) > maxTotalBin {
		data = data[:maxTotalBin]
	}

	streamsBefore := len(res.Streams)
	blobsProcessed := 0
	off := 0

	for r := 0; r < maxPPTRecords; r++ {
		if expired(deadline) {
			break
		}
		if off+8 > len(data) {
			break
		}

		// MS-PPT record header layout (8 bytes) — [MS-PPT] §2.1.1:
		//   [0:2] verAndInstance: low 4 bits = version, high 12 bits = instance
		//   [2:4] recType uint16 LE
		//   [4:8] recSize uint32 LE (bytes of record body; excludes the 8-byte header)
		verAndInst := binary.LittleEndian.Uint16(data[off:])
		ver := verAndInst & 0x0F
		inst := verAndInst >> 4
		rt := binary.LittleEndian.Uint16(data[off+2:])
		size := binary.LittleEndian.Uint32(data[off+4:])

		bodyOff := off + 8
		bodyEnd := bodyOff + int(size)

		// Sanity-check body bounds before any access.
		if bodyEnd < bodyOff || bodyEnd > len(data) {
			break
		}

		if rt == pptRecTypeExternalObjectStorage && blobsProcessed < maxPPTVBABlobs {
			body := data[bodyOff:bodyEnd]
			pptExtractEOS(body, inst, res, deadline)
			blobsProcessed++
		}

		if ver == 0x0F {
			// Container record (version == 0xF): body is a sequence of child records.
			// Advance INTO the body so we reach nested ExternalObjectStorage records
			// without skipping them (the size covers all children, not a flat payload).
			off = bodyOff
		} else {
			// Leaf record: body is opaque data; skip past it.
			off = bodyEnd
		}
	}

	// Emit the marker exactly once, only when at least one extraction produced
	// new VBA streams.
	if len(res.Streams) > streamsBefore {
		res.Streams = append(res.Streams, []byte("PPT-VBA-EXTRACTED"))
	}
}

// pptExtractEOS decompresses (if needed) one ExternalObjectStorage body and
// extracts any VBA macros from the resulting sub-OLE2 container, appending
// decoded module source to res.Streams.
//
//   - inst == 0: body is a raw OLE2 container.
//   - inst == 1: body is a 4-byte LE decompressed-size prefix followed by a
//     zlib-compressed OLE2 container.
//
// Any other inst value, parse error, or empty module set is silently skipped.
func pptExtractEOS(body []byte, inst uint16, res *Result, deadline time.Time) {
	var oleBytes []byte

	switch inst {
	case 0:
		// Uncompressed: body is already a raw OLE2 container.
		oleBytes = body

	case 1:
		oleBytes = inflatePPTCompressedEOS(body)
		if len(oleBytes) == 0 {
			return
		}

	default:
		return // unknown instance value — skip
	}

	if len(oleBytes) < 8 {
		return
	}

	subOLE, err := oleparse.NewOLEFile(oleBytes)
	if err != nil {
		return
	}

	remainingCode := maxTotalCode - streamBytes(res.Streams)
	if remainingCode <= 0 {
		return
	}
	mods, err := oleparse.ExtractMacroBlobsLimited(subOLE, maxBytesPerModule, remainingCode)
	if err != nil || len(mods) == 0 {
		return
	}

	res.Streams = codes(res, mods, res.Streams)
	detectStompingModules(mods, res, deadline)
}

func inflatePPTCompressedEOS(body []byte) []byte {
	// zlib-compressed with a 4-byte LE decompressed-size prefix.
	// The prefix is attacker-controlled; do NOT pre-allocate from it.
	if len(body) < 4 {
		return nil
	}
	compressed := body[4:] // skip the 4-byte declared-size prefix
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil
	}
	buf, readErr := io.ReadAll(io.LimitReader(zr, maxBytesPerModule))
	_ = zr.Close() // #nosec G104 — any decompressor error is already surfaced in readErr; zlib.Reader.Close at this point returns the same error or nil
	if readErr != nil && len(buf) == 0 {
		return nil
	}
	// Partial decompression accepted (fail-open): oleparse.NewOLEFile will reject a corrupt blob.
	return buf
}
