package extract

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// OLE Package-object / embedded-EXE carve. A classic maldoc trick embeds an
// executable inside an Office document as an OLE "Package" object: the user sees
// an icon ("double-click to open") and launching it runs the dropped
// .exe/.bat/.scr/.js. The embedded file lives in an `\x01Ole10Native` stream
// (legacy Packager) inside the document's OLE2 storage — bytes that the macro
// path never returns and that raw-byte scanning sees only as opaque OLE2
// structure.
//
// fromOLEPackage carves the native file data out of every Ole10Native stream and
// surfaces it as its own stream so the keyword/PE rules match the dropped binary.
// Best-effort and fail-open; a malformed stream is skipped, never fatal (Extract's
// recover still covers a panic).
//
// Ole10Native (OLE10_NATIVE) stream layout (little-endian), per [MS-OLEDS] §2.3.6
// and the long-documented Packager format:
//
//	uint32  NativeDataSize-or-TotalSize (header total; not used directly here)
//	uint16  Flags1 (== 0x0002 for a packaged file)
//	cstr    Label        (NUL-terminated ANSI; original file name shown to user)
//	cstr    FileName     (NUL-terminated ANSI; original full path)
//	uint16  Flags2       (== 0x0000)
//	uint16  Unknown1
//	uint32  FilePathSize ; FilePath bytes (NUL-terminated ANSI temp path)
//	uint32  NativeDataSize ; NativeData bytes  <-- the embedded file
//	... (trailer/UTF paths ignored)
//
// We locate NativeData by walking the variable-length header rather than trusting
// any single size field, and clamp every length against the remaining buffer so a
// hostile stream can't drive an out-of-range slice.

const (
	// ole10NativeStream is the storage name of a Packager native-data stream. The
	// leading byte is 0x01 (a control prefix MAPI/OLE uses); oleparse exposes the
	// directory name with that byte, so match on the suffix.
	ole10NativeSuffix = "ole10native"

	// maxPackageObjects bounds how many embedded packages we carve from one doc.
	maxPackageObjects = 64
	// maxBytesPerPackage caps one carved embedded file (raw scan covers the rest).
	maxBytesPerPackage = 16 << 20
	// maxTotalPackage caps cumulative carved bytes from one document.
	maxTotalPackage = 48 << 20
)

// fromOLEPackage scans an OLE2's directory for Ole10Native streams and appends
// each embedded file's NativeData to res.Streams. Returns true if at least one
// Ole10Native stream was found (whether or not its data parsed). Bounded by the
// maxPackage* caps. A carved payload that is itself a carrier (a dropped
// .docm/.zip/.pdf/.msg) is additionally routed through extractChild so its own
// format is cracked, not just scanned as raw bytes; bud/depth are the shared
// nested-carrier budget (see nested.go).
func fromOLEPackage(ole *oleparse.OLEFile, res *Result, bud *archiveBudget, depth int, deadline time.Time) bool {
	if ole == nil {
		return false
	}
	var found bool
	var total int
	var emitted int // THIS format's emitted count — must not be confused with the
	// global len(res.Streams), or a parent that already filled Streams would wrongly
	// pre-consume this package's per-format budget and suppress its objects.
	for _, d := range ole.Directory {
		if d == nil || d.Header.Mse != 2 || d.Header.Size == 0 {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(d.Name), ole10NativeSuffix) {
			continue
		}
		found = true
		if emitted >= maxPackageObjects || len(res.Streams) >= maxStreams || total >= maxTotalPackage || expired(deadline) || bud.spent() {
			break
		}
		b := ole.GetStream(d.Index)
		data := carveOle10Native(b)
		if len(data) == 0 {
			continue
		}
		if len(data) > maxBytesPerPackage {
			data = data[:maxBytesPerPackage]
		}
		payload := append([]byte(nil), data...)
		res.Streams = append(res.Streams, payload)
		res.IsOLEPackage = true
		total += len(data)
		emitted++
		// Charge the shared nested-carrier budget, then crack the dropped file's
		// own carrier layer if it is one (depth+1). See nested.go.
		bud.members++
		bud.total += len(payload)
		extractChild(payload, res, bud, depth+1, deadline)
	}
	return found
}

// carveOle10Native walks one Ole10Native stream and returns the embedded
// NativeData bytes, or nil if the stream is too short / malformed. Every field
// length is bounds-checked against the remaining buffer.
func carveOle10Native(b []byte) []byte {
	// uint32 total + uint16 flags1 = 6 bytes minimum before the Label.
	if len(b) < 6 {
		return nil
	}
	p := 6 // skip TotalSize(4) + Flags1(2)

	// Label and FileName: two NUL-terminated ANSI strings.
	if p, _ = skipCString(b, p); p < 0 {
		return nil
	}
	if p, _ = skipCString(b, p); p < 0 {
		return nil
	}

	// Flags2(2) + Unknown1(2).
	if p+4 > len(b) {
		return nil
	}
	p += 4

	// FilePathSize(4) + FilePath bytes.
	if p+4 > len(b) {
		return nil
	}
	fpLen := binary.LittleEndian.Uint32(b[p:])
	p += 4
	if uint64(p)+uint64(fpLen) > uint64(len(b)) {
		return nil
	}
	p += int(fpLen)

	// NativeDataSize(4) + NativeData bytes (the embedded file).
	if p+4 > len(b) {
		return nil
	}
	ndLen := binary.LittleEndian.Uint32(b[p:])
	p += 4
	if ndLen == 0 {
		return nil
	}
	// Clamp to what's present: a hostile NativeDataSize larger than the stream
	// must not over-read; take what we actually have. p is >= 0 and <= len(b)
	// here (every field walk above bounds-checks against len(b)), so avail is a
	// safe non-negative int and no int<->uint64 conversion is needed.
	avail := len(b) - p
	n := int(ndLen)
	if n > avail {
		n = avail
	}
	if n <= 0 {
		return nil
	}
	return b[p : p+n]
}

// skipCString advances past one NUL-terminated byte string starting at off,
// returning the index just past the NUL. Returns -1 if no NUL is found within
// the buffer (malformed/hostile).
func skipCString(b []byte, off int) (int, bool) {
	if off < 0 || off >= len(b) {
		return -1, false
	}
	i := bytes.IndexByte(b[off:], 0)
	if i < 0 {
		return -1, false
	}
	return off + i + 1, true
}
