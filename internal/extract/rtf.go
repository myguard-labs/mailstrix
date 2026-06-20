package extract

import (
	"bytes"
	"strconv"
	"strings"
	"time"

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
	// maxRTFDDEFields caps how many DDE field instructions we emit per document.
	maxRTFDDEFields = 16
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
// detectRTFDDE scans buf for DDE/DDEAUTO field instructions inside RTF \fldinst
// groups and for bare \ddeauto / \dde control words. Each match emits a synthetic
// stream "RTF-DDE-FIELD <instruction>" so YARA rules can match the payload.
// Bounded by maxRTFDDEFields.
func detectRTFDDE(buf []byte, res *Result, deadline time.Time) {
	count := 0
	// Scan for \fldinst groups.
	rest := buf
	for count < maxRTFDDEFields && !expired(deadline) {
		idx := bytes.Index(rest, []byte("\\fldinst"))
		if idx < 0 {
			break
		}
		rest = rest[idx+len("\\fldinst"):]
		// Skip optional delimiter space / whitespace
		i := 0
		for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t' || rest[i] == '\r' || rest[i] == '\n') {
			i++
		}
		// Skip optional opening brace
		if i < len(rest) && rest[i] == '{' {
			i++
		}
		// Skip whitespace again
		for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t' || rest[i] == '\r' || rest[i] == '\n') {
			i++
		}
		// Collect text until closing brace
		start := i
		for i < len(rest) && rest[i] != '}' {
			i++
		}
		instr := strings.TrimSpace(string(rest[start:i]))
		upper := strings.ToUpper(instr)
		if strings.HasPrefix(upper, "DDEAUTO ") || strings.HasPrefix(upper, "DDE ") ||
			upper == "DDEAUTO" || upper == "DDE" {
			res.Streams = append(res.Streams, []byte("RTF-DDE-FIELD "+instr))
			count++
		}
	}

	// Scan for bare \ddeauto and \dde control words (outside field groups).
	for _, kw := range []string{"\\ddeauto", "\\dde"} {
		search := buf
		for count < maxRTFDDEFields && !expired(deadline) {
			idx := bytes.Index(search, []byte(kw))
			if idx < 0 {
				break
			}
			after := idx + len(kw)
			// Control word must be followed by a non-alpha char (delimiter)
			if after < len(search) {
				next := search[after]
				if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') {
					search = search[after:]
					continue
				}
			}
			label := strings.ToUpper(kw[1:]) // "DDEAUTO" or "DDE"
			res.Streams = append(res.Streams, []byte("RTF-DDE-FIELD "+label))
			count++
			search = search[after:]
		}
	}
}

// fromRTF scans an RTF document for `\objdata` groups, hex-decodes each one, and
// surfaces the embedded object's payload to res.Streams. For a CFB blob it runs
// the same OLE2 extraction as a standalone document (macros + package + MSI +
// .msg); for a bare OLENativeStream it carves the native file via
// carveOle10Native. Sets res.IsRTF whenever the buffer is RTF (whether or not any
// object decoded). Bounded by the maxRTF* caps.
func fromRTF(buf []byte, res *Result, deadline time.Time) {
	res.IsRTF = true

	// DDE field detection (runs before objdata scan).
	detectRTFDDE(buf, res, deadline)

	// \objupdate detection — Word auto-fetches the remote OLE link on open
	// (CVE-2017-0199 vector). Emit a marker so YARA can match.
	if bytes.Contains(buf, []byte("\\objupdate")) {
		res.Streams = append(res.Streams, []byte("RTF-OBJUPDATE"))
	}

	var total, objs int
	rest := buf
	for {
		// Bound both the cumulative byte/stream work AND the number of \objdata
		// groups examined — a hostile message stuffed with thousands of empty/
		// malformed groups yields no streams, so a stream-count guard alone would
		// never trip; objs caps the decode/index work regardless of yield.
		if objs >= maxRTFObjects || len(res.Streams) >= maxStreams || total >= maxTotalRTF || expired(deadline) {
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
		carveRTFObject(blob, res, deadline)
	}
}

// decodeRTFHex reads the ASCII-hex run that follows an `\objdata` control word
// and returns the decoded bytes. It handles nested RTF groups (which obfuscators
// inject to break naive hex decoders), \binN binary runs, and backslash control
// words. An odd trailing nibble is dropped. Bounded by maxBytesPerRTFObject so a
// hostile multi-MiB hex run can't exhaust memory.
func decodeRTFHex(b []byte) []byte {
	out := make([]byte, 0, 256)
	var hi byte
	var haveHi bool
	depth := 0
	i := 0
	for i < len(b) {
		c := b[i]

		// Track nested groups — objdata can contain nested RTF groups
		// that obfuscators insert to break hex decoders.
		if c == '{' {
			depth++
			i++
			continue
		}
		if c == '}' {
			if depth > 0 {
				depth--
				i++
				continue
			}
			// depth 0 closing brace = end of objdata group
			break
		}
		// Skip everything inside nested groups
		if depth > 0 {
			i++
			continue
		}

		// Handle backslash-escaped control words at depth 0
		if c == '\\' {
			i++
			if i >= len(b) {
				break
			}
			// \binN — skip N binary bytes
			if i+2 < len(b) && b[i] == 'b' && b[i+1] == 'i' && b[i+2] == 'n' {
				j := i + 3
				numStart := j
				for j < len(b) && b[j] >= '0' && b[j] <= '9' {
					j++
				}
				if j > numStart {
					n, _ := strconv.Atoi(string(b[numStart:j]))
					// Skip the delimiter (space) after the number if present
					if j < len(b) && b[j] == ' ' {
						j++
					}
					i = j + n
					if i > len(b) {
						i = len(b)
					}
					continue
				}
			}
			// Skip any other control word: advance past alphabetic chars + optional numeric param + delimiter
			for i < len(b) && b[i] >= 'a' && b[i] <= 'z' {
				i++
			}
			// Skip optional numeric parameter (including negative)
			if i < len(b) && (b[i] == '-' || (b[i] >= '0' && b[i] <= '9')) {
				i++
				for i < len(b) && b[i] >= '0' && b[i] <= '9' {
					i++
				}
			}
			// Skip delimiter space
			if i < len(b) && b[i] == ' ' {
				i++
			}
			continue
		}

		// Whitespace — skip
		if c == ' ' || c == '\r' || c == '\n' || c == '\t' {
			i++
			continue
		}

		// Hex digit
		var nibble byte
		switch {
		case c >= '0' && c <= '9':
			nibble = c - '0'
		case c >= 'a' && c <= 'f':
			nibble = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			nibble = c - 'A' + 10
		default:
			// Non-hex, non-control: stop
			return out
		}

		if !haveHi {
			hi = nibble
			haveHi = true
		} else {
			out = append(out, hi<<4|nibble)
			haveHi = false
			if len(out) >= maxBytesPerRTFObject {
				break
			}
		}
		i++
	}
	return out
}

// carveRTFObject inspects one decoded \objdata blob and surfaces its payload. The
// blob is an OLESaveToStream image: it may be a full OLE2 (CFB) compound file or a
// bare OLENativeStream/Ole10Native. Try OLE2 first (covers the embedded-doc and
// OLE-package cases via the existing helpers); fall back to a direct Ole10Native
// carve for the bare-stream case. Best-effort; a parse failure is skipped.
func carveRTFObject(blob []byte, res *Result, deadline time.Time) {
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
			fromOLEPackage(ole, res, deadline)
			if !fromMSG(ole, res, deadline) {
				fromMSI(ole, res, deadline)
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
