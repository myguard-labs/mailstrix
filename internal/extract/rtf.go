package extract

import (
	"bytes"

	"www.velocidex.com/golang/oleparse"
)

// RTF embedded-object carve. A classic maldoc trick (CVE-2017-0199,
// CVE-2017-11882, OLE2Link/malrtf) embeds an OLE object inside an RTF document
// as an `{\object ... {\*\objdata <hex>}}` group: the `\objdata` control word is
// followed by the object's OLESaveToStream bytes encoded as ASCII hex. Those
// bytes are an OLENativeStream/Ole10Native payload or a full OLE2 (CFB) compound
// document — neither of which raw-byte scanning of the RTF source can see,
// because the dropped file is hex-text, not binary.
//
// fromRTF decodes every `\objdata` hex blob and surfaces (a) the OLE2 streams if
// the blob is a CFB compound file (reusing the same VBA/MSI/.msg/package
// extraction the OLE path uses) and (b) the carved Ole10Native native-data if the
// blob is a bare OLENativeStream. This is the sibling of the OLE Package carve
// (#14), which only covered the OLE2-storage case; here the package rides inside
// RTF hex instead of inside an Office document's storage.
//
// Best-effort and fail-open: a malformed group is skipped, never fatal (Extract's
// recover still covers a panic).

const (
	// rtfObjData is the control word introducing the hex-encoded object bytes.
	rtfObjDataKW = "\\objdata"

	// maxRTFObjects bounds how many \objdata groups we carve from one document.
	maxRTFObjects = 64
	// maxBytesPerRTFObject caps one decoded object blob (raw scan covers the rest).
	maxBytesPerRTFObject = 16 << 20
	// maxTotalRTF caps cumulative carved/decoded bytes from one document.
	maxTotalRTF = 48 << 20
)

// utf8BOM is the UTF-8 byte-order mark some editors prepend to RTF.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// isRTF reports whether buf opens an RTF document: `{\rt` after an optional
// UTF-8 BOM and leading whitespace. RTF has no binary magic, so the signature
// group header is the recogniser. We accept `{\rtf` and the rare `{\rtxxx`
// variants by matching the `{\rt` prefix.
func isRTF(buf []byte) bool {
	buf = bytes.TrimPrefix(buf, utf8BOM)
	i := 0
	for i < len(buf) && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\r' || buf[i] == '\n') {
		i++
	}
	return bytes.HasPrefix(buf[i:], []byte("{\\rt"))
}

// fromRTF scans an RTF document for `\objdata` groups, hex-decodes each one, and
// surfaces the embedded object's payload to res.Streams. For a CFB blob it runs
// the same OLE2 extraction as a standalone document (macros + package + MSI +
// .msg); for a bare OLENativeStream it carves the native file via
// carveOle10Native. Sets res.IsRTF whenever the buffer is RTF (whether or not any
// object decoded). Bounded by the maxRTF* caps.
func fromRTF(buf []byte, res *Result) {
	res.IsRTF = true
	var total, objs int
	rest := buf
	for {
		// Bound both the cumulative byte/stream work AND the number of \objdata
		// groups examined — a hostile message stuffed with thousands of empty/
		// malformed groups yields no streams, so a stream-count guard alone would
		// never trip; objs caps the decode/index work regardless of yield.
		if objs >= maxRTFObjects || len(res.Streams) >= maxStreams || total >= maxTotalRTF {
			break
		}
		idx := bytes.Index(rest, []byte(rtfObjDataKW))
		if idx < 0 {
			break
		}
		objs++
		// Advance past the control word; the hex run starts after any control-word
		// delimiter (a space, or the bytes up to the next `{`/`}`/`\`).
		rest = rest[idx+len(rtfObjDataKW):]
		blob := decodeRTFHex(rest)
		if len(blob) == 0 {
			continue
		}
		if len(blob) > maxBytesPerRTFObject {
			blob = blob[:maxBytesPerRTFObject]
		}
		total += len(blob)
		carveRTFObject(blob, res)
	}
}

// decodeRTFHex reads the ASCII-hex run that follows an `\objdata` control word
// and returns the decoded bytes. It accepts hex digits, skips RTF whitespace
// (space, CR, LF, tab) and the control-word leading space, and stops at the first
// non-hex/non-whitespace byte (the group's closing `}` or a nested control word).
// An odd trailing nibble is dropped. Bounded by maxBytesPerRTFObject so a hostile
// multi-MiB hex run can't exhaust memory.
func decodeRTFHex(b []byte) []byte {
	out := make([]byte, 0, 256)
	var hi byte
	var haveHi bool
	for _, c := range b {
		switch {
		case c == ' ' || c == '\r' || c == '\n' || c == '\t':
			continue
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			// End of the hex run (closing brace, control word, etc.).
			return out
		}
		if !haveHi {
			hi = c
			haveHi = true
			continue
		}
		out = append(out, hi<<4|c)
		haveHi = false
		if len(out) >= maxBytesPerRTFObject {
			break
		}
	}
	return out
}

// carveRTFObject inspects one decoded \objdata blob and surfaces its payload. The
// blob is an OLESaveToStream image: it may be a full OLE2 (CFB) compound file or a
// bare OLENativeStream/Ole10Native. Try OLE2 first (covers the embedded-doc and
// OLE-package cases via the existing helpers); fall back to a direct Ole10Native
// carve for the bare-stream case. Best-effort; a parse failure is skipped.
func carveRTFObject(blob []byte, res *Result) {
	// An OLENativeStream begins with the OLE2 magic only when it wraps a CFB; the
	// bare Packager form does not. Many \objdata blobs are prefixed with an
	// OLEStream header before the CFB magic, so search rather than require a prefix.
	if i := bytes.Index(blob, oleMagic); i >= 0 {
		if ole, err := oleparse.NewOLEFile(blob[i:]); err == nil {
			// Reuse the full OLE2 extraction surface: macros, embedded package,
			// MSI and .msg. Each helper is a no-op when the OLE2 isn't theirs.
			if mods, err := oleparse.ExtractMacros(ole); err == nil {
				res.Streams = codes(mods, res.Streams)
			}
			fromOLEPackage(ole, res)
			if !fromMSG(ole, res) {
				fromMSI(ole, res)
			}
			return
		}
	}
	// Not a CFB: treat the blob as a bare Ole10Native/OLENativeStream and carve the
	// native file data directly (sibling of the #14 OLE2-storage path).
	if data := carveOle10Native(blob); len(data) > 0 {
		res.IsOLEPackage = true
		res.Streams = append(res.Streams, append([]byte(nil), data...))
	}
}
