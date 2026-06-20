package extract

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"io"
	"time"
)

// PDF pre-extraction. Malicious PDFs hide their payload inside FlateDecode
// (zlib-deflated) object streams: the `/OpenAction`/`/Launch`/`/JS`/
// `/JavaScript` action and the JavaScript body, or an embedded file, are
// compressed, so raw-byte keyword rules scanning the .pdf never see the
// decompressed script. yarad's other extractors don't recognise a PDF (it is
// neither OLE2, ZIP, nor a shell link).
//
// fromPDF carves every `stream … endstream` object body, inflates it
// (zlib, then raw-deflate as a fallback), and surfaces the decompressed bytes so
// the rules match the hidden JS / actions / embedded data. We deliberately do
// NOT build a full PDF object/xref parser — carving by the stream delimiters is
// robust against the malformed/linearised/hybrid xref tricks maldocs use, the
// same pragmatic approach AV unpackers take. Best-effort and fail-open: a stream
// that isn't deflate, or is truncated, is skipped, never fatal (Extract's recover
// also covers a panic).

// pdfMagic — "%PDF-" appears at (or very near) the start of every PDF.
var (
	pdfMagic     = []byte("%PDF-")
	pdfStreamKW  = []byte("stream")
	pdfEndStream = []byte("endstream")
)

// PDF dropper indicator names (pdfid keyword set, mail-relevant high-risk
// subset — pdfid.py:433-453). Each is a PDF *name* token; matched as a whole
// name (trailing delimiter required) so /JS doesn't fire on /JStuff. The /JS and
// /JavaScript pair is the script body; /OpenAction and /AA auto-fire on open.
var (
	pdfNameOpenAction   = []byte("/OpenAction")
	pdfNameAA           = []byte("/AA")
	pdfNameLaunch       = []byte("/Launch")
	pdfNameJS           = []byte("/JS")
	pdfNameJavaScript   = []byte("/JavaScript")
	pdfNameEmbeddedFile = []byte("/EmbeddedFile")
	pdfNameJBIG2        = []byte("/JBIG2Decode")
	pdfNameObjStm       = []byte("/ObjStm")
)

const (
	// maxPDFStreams bounds how many object streams we inflate from one PDF.
	maxPDFStreams = 256
	// maxBytesPerPDFStream caps one inflated stream (decompression-bomb guard);
	// the raw scan still covers anything larger.
	maxBytesPerPDFStream = 8 << 20
	// maxTotalPDF caps cumulative inflated bytes emitted from one PDF.
	maxTotalPDF = 64 << 20
	// maxPDFScan bounds how far into the file we look for stream delimiters, so a
	// huge PDF can't cause an unbounded number of carve attempts.
	maxPDFScan = 64 << 20
)

// isPDF reports whether buf is a PDF. The magic is usually at offset 0 but the
// spec tolerates leading bytes, so accept it within the first 1 KiB.
func isPDF(buf []byte) bool {
	if bytes.HasPrefix(buf, pdfMagic) {
		return true
	}
	head := buf
	if len(head) > 1024 {
		head = head[:1024]
	}
	return bytes.Contains(head, pdfMagic)
}

// fromPDF carves and inflates the object streams of a PDF, appending each
// decompressed body to res.Streams. Sets IsPDF. Bounded by the maxPDF* caps.
func fromPDF(buf []byte, res *Result, deadline time.Time) {
	res.IsPDF = true
	scan := buf
	if len(scan) > maxPDFScan {
		scan = scan[:maxPDFScan]
	}
	var total, attempts int
	pos := 0
	// Cap inflate ATTEMPTS, not just emitted streams: a hostile PDF stuffed with
	// many non-deflate `stream … endstream` bodies would otherwise force unbounded
	// zlib/flate attempts (none of which increment len(res.Streams)). The deadline
	// also bounds wall-clock so many FlateDecode inflates can't overrun the budget.
	for attempts < maxPDFStreams && len(res.Streams) < maxStreams && total < maxTotalPDF && !expired(deadline) {
		rel := bytes.Index(scan[pos:], pdfStreamKW)
		if rel < 0 {
			break
		}
		kwAt := pos + rel
		bodyStart := kwAt + len(pdfStreamKW)
		// Require a real `stream` token, not a substring of `endstream` or of a
		// name/comment: the keyword must be preceded by a PDF whitespace/delimiter
		// (typically `>>` then EOL) and followed by EOL. Otherwise skip just past
		// this match and keep looking — so a stray "stream" can't make us carve
		// through the next endstream and hide the real object.
		if !pdfTokenBoundary(scan, kwAt, bodyStart) {
			pos = bodyStart
			continue
		}
		// Per the spec the keyword is followed by CRLF or LF before the data. Skip a
		// single EOL so the inflater sees the real first byte.
		bodyStart = skipPDFEOL(scan, bodyStart)
		endRel := bytes.Index(scan[bodyStart:], pdfEndStream)
		if endRel < 0 {
			break // no terminator: truncated/hostile, stop
		}
		body := scan[bodyStart : bodyStart+endRel]
		pos = bodyStart + endRel + len(pdfEndStream)

		attempts++
		dec := inflatePDFStream(body)
		if len(dec) == 0 {
			continue // not a deflate stream (e.g. raw image) — raw scan covers it
		}
		res.Streams = append(res.Streams, dec)
		total += len(dec)
	}

	// Structural dropper indicators (PDF-DEEPEN): action/JS/launch/embedded-file
	// keywords that auto-fire or carry a payload. These are name tokens in the
	// PDF body itself (not the inflated streams), so they are surfaced separately.
	fromPDFIndicators(scan, res, deadline)
}

// fromPDFIndicators emits pdfid-style structural markers for a PDF's high-risk
// name tokens. To defeat hex-name obfuscation (/J#61vaScript → /JavaScript,
// pdfid.py:510-527) it canonicalises name tokens first — but only when a '#' is
// actually present, so the common case pays nothing. The hex-escape count itself
// is an evasion signal (PDF-HEXOBFUSC). Bounded, fail-open, deadline-aware.
func fromPDFIndicators(scan []byte, res *Result, deadline time.Time) {
	if expired(deadline) || len(res.Streams) >= maxStreams {
		return
	}
	buf := scan
	hexCount := 0
	if bytes.IndexByte(scan, '#') >= 0 {
		buf, hexCount = canonicalizePDFNames(scan)
	}

	emit := func(marker string) {
		if len(res.Streams) < maxStreams {
			res.Streams = append(res.Streams, []byte(marker))
		}
	}

	// Hex-escaped name(s) present at all → obfuscation/evasion signal.
	if hexCount > 0 {
		emit("PDF-HEXOBFUSC")
	}
	// /OpenAction + a script body = JavaScript that auto-runs on document open.
	if pdfHasName(buf, pdfNameOpenAction) &&
		(pdfHasName(buf, pdfNameJS) || pdfHasName(buf, pdfNameJavaScript)) {
		emit("PDF-OPENACTION-JS")
	}
	if pdfHasName(buf, pdfNameAA) {
		emit("PDF-AA-ACTION") // additional-actions dictionary — auto-fire on open/page
	}
	if pdfHasName(buf, pdfNameLaunch) {
		emit("PDF-LAUNCH") // /Launch action runs an external program
	}
	if pdfHasName(buf, pdfNameEmbeddedFile) {
		emit("PDF-EMBEDDEDFILE")
	}
	if pdfHasName(buf, pdfNameJBIG2) {
		emit("PDF-JBIG2") // JBIG2Decode — CVE-2009-3459 exploit vector
	}
	if pdfHasName(buf, pdfNameObjStm) {
		emit("PDF-OBJSTM") // object stream — hides objects from naive scanners
	}
}

// pdfHasName reports whether buf contains name as a complete PDF name token,
// i.e. followed by a name terminator (whitespace/delimiter) or end-of-buffer, so
// a short name like /JS does not match inside /JStuff.
func pdfHasName(buf, name []byte) bool {
	from := 0
	for {
		rel := bytes.Index(buf[from:], name)
		if rel < 0 {
			return false
		}
		end := from + rel + len(name)
		if end >= len(buf) || isPDFNameTerminator(buf[end]) {
			return true
		}
		from = from + rel + 1
	}
}

// isPDFNameTerminator reports whether c ends a PDF name token: PDF whitespace or
// one of the delimiter characters ()<>[]{}/% (PDF spec 7.2.2).
func isPDFNameTerminator(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '\f', 0,
		'(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

// canonicalizePDFNames returns a copy of scan with #XX hex escapes inside name
// tokens decoded to their literal byte (pdfid's EqualCanonical, pdf-parser:1003),
// plus the number of escapes decoded. Hex decoding is confined to name context
// (between a '/' and the next terminator) so a '#' in stream/binary data is left
// untouched and cannot fabricate a keyword.
func canonicalizePDFNames(scan []byte) ([]byte, int) {
	out := make([]byte, 0, len(scan))
	count := 0
	inName := false
	for i := 0; i < len(scan); i++ {
		c := scan[i]
		if c == '/' {
			inName = true
			out = append(out, c)
			continue
		}
		if inName {
			if isPDFNameTerminator(c) {
				inName = false
				out = append(out, c)
				continue
			}
			if c == '#' && i+2 < len(scan) {
				hi := hexVal(scan[i+1])
				lo := hexVal(scan[i+2])
				if hi >= 0 && lo >= 0 {
					b := byte(hi<<4 | lo)
					count++ // a hex escape was used — obfuscation signal regardless
					// An escaped byte is a LITERAL name character (PDF 7.3.5), even
					// when it decodes to a delimiter/whitespace. Emitting that raw
					// byte would fabricate a name boundary (/foo#2FLaunch -> /Launch,
					// /OpenAction#20x -> a terminated /OpenAction), so only substitute
					// when the result is a name-regular char; otherwise keep the
					// escape verbatim. The high-risk keywords are all letters, so this
					// loses no real de-obfuscation.
					if !isPDFNameTerminator(b) {
						out = append(out, b)
					} else {
						out = append(out, '#', scan[i+1], scan[i+2])
					}
					i += 2
					continue
				}
			}
		}
		out = append(out, c)
	}
	return out, count
}

// hexVal returns the value of a hex digit, or -1 if c is not one.
func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// pdfTokenBoundary reports whether the `stream` match at kwAt (body byte at
// after) is a genuine stream-object keyword: the byte before must be a PDF
// whitespace/delimiter (so `endstream` and `upstream` don't match) and the byte
// after must begin an EOL (\r or \n), as the spec mandates.
func pdfTokenBoundary(b []byte, kwAt, after int) bool {
	if kwAt > 0 {
		switch b[kwAt-1] {
		case ' ', '\t', '\r', '\n', '\f', 0, '>':
		default:
			return false
		}
	}
	return after < len(b) && (b[after] == '\r' || b[after] == '\n')
}

// skipPDFEOL advances past one EOL sequence (\r\n, \n, or \r) at off, returning
// the new offset. PDF writes exactly one EOL after the `stream` keyword.
func skipPDFEOL(b []byte, off int) int {
	if off < len(b) && b[off] == '\r' {
		off++
	}
	if off < len(b) && b[off] == '\n' {
		off++
	}
	return off
}

// inflatePDFStream tries to decompress one object body as FlateDecode: zlib
// (the PDF default — a 0x78 header) first, then raw deflate as a fallback for
// producers that omit the zlib wrapper. Output is bounded by maxBytesPerPDFStream
// via io.LimitReader. Returns nil if the body isn't deflate or yields nothing.
func inflatePDFStream(body []byte) []byte {
	if len(body) < 2 {
		return nil
	}
	if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
		if out := readInflated(zr); len(out) > 0 {
			return out
		}
	}
	fr := flate.NewReader(bytes.NewReader(body))
	return readInflated(fr)
}

// readInflated reads a decompressor bounded by maxBytesPerPDFStream. A
// decompression error after some output still returns what was produced (a
// truncated-but-useful stream is better than nothing); zero output returns nil.
func readInflated(r io.Reader) []byte {
	var b bytes.Buffer
	_, _ = b.ReadFrom(io.LimitReader(r, maxBytesPerPDFStream))
	if rc, ok := r.(io.Closer); ok {
		_ = rc.Close()
	}
	if b.Len() == 0 {
		return nil
	}
	return b.Bytes()
}
