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
	pdfObjKW     = []byte("obj")
	pdfEndObjKW  = []byte("endobj")
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
	pdfNameLength       = []byte("/Length")
	pdfNameFilter       = []byte("/Filter")
)

const (
	// maxPDFStreams bounds how many object streams we emit from one PDF.
	maxPDFStreams = 256
	// maxPDFAttempts bounds every stream body examined, junk included.
	maxPDFAttempts = 4 * maxPDFStreams
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
func fromPDF(buf []byte, res *Result, opts *Options) {
	deadline := opts.Deadline
	res.IsPDF = true
	scan := buf
	if len(scan) > maxPDFScan {
		scan = scan[:maxPDFScan]
	}
	var total, attempts int
	pos := 0
	// Pre-scan the bare-integer length objects so an indirect `/Length N G R`
	// resolves without an xref (AUDIT-PDF-ENDSTREAM); nil when none exist.
	lengths := pdfIndirectLengths(scan)
	// Cap inflate ATTEMPTS, not just emitted streams: a hostile PDF stuffed with
	// many non-deflate `stream … endstream` bodies would otherwise force unbounded
	// zlib/flate attempts (none of which increment len(res.Streams)). The deadline
	// also bounds wall-clock so many FlateDecode inflates can't overrun the budget.
	// COR-07: maxPDFStreams counts only streams that decoded to something;
	// non-deflate junk bodies spend the larger maxPDFAttempts instead, so a run
	// of junk streams cannot hide a later FlateDecode ObjStm.
	var produced int
	for attempts < maxPDFAttempts && produced < maxPDFStreams && len(res.Streams) < maxStreams && total < maxTotalPDF && !expired(deadline) {
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
		// Size the body by the declared /Length when it aligns with `endstream`
		// (AUDIT-PDF-ENDSTREAM): a FlateDecode body whose (e.g. stored-block)
		// compressed bytes contain the literal `endstream` would otherwise be
		// truncated at the first occurrence, so the inflate drops the real payload
		// tail. This mirrors the scrub path in scrubPDFForNames. Fall back to the
		// first-`endstream` substring when /Length is indirect/absent or doesn't
		// align — the narrowed residual.
		var body []byte
		sized := false
		if l := pdfStreamLength(scan, kwAt, lengths); l >= 0 && bodyStart+l <= len(scan) {
			after := bytes.TrimLeft(scan[bodyStart+l:], " \t\r\n\f")
			if bytes.HasPrefix(after, pdfEndStream) {
				body = scan[bodyStart : bodyStart+l]
				pos = bodyStart + l + (len(scan[bodyStart+l:]) - len(after)) + len(pdfEndStream)
				sized = true
			}
		}
		if !sized {
			endRel := bytes.Index(scan[bodyStart:], pdfEndStream)
			if endRel < 0 {
				break // no terminator: truncated/hostile, stop
			}
			body = scan[bodyStart : bodyStart+endRel]
			pos = bodyStart + endRel + len(pdfEndStream)
		}

		attempts++
		// Decode any leading ASCII85/ASCIIHex text-armour prefilters (AUDIT-PDF-
		// FILTER-CHAIN) so a `/Filter [/ASCII85Decode /FlateDecode]` chain (ASCII85
		// text wrapping deflate) is unwrapped. /Filter is treated as ADVISORY, not
		// authoritative: it can be a decoy picked from a string/comment by the
		// context-blind dict scan, so the un-armouring below is also retried
		// opportunistically — a bogus /Filter can neither disable extraction of a
		// real deflate stream nor hide a real armoured one.
		decoded, surface, _ := applyPDFPrefilters(body, pdfStreamFilters(scan, kwAt))
		var dec []byte
		if surface {
			// The /Filter chain parsed as text-prefilters-only, so decoded SHOULD be
			// cleartext — but a mis-parsed /Filter (a decoy in an unbalanced string, an
			// obj-misclip) could have dropped a trailing FlateDecode, leaving decoded
			// still zlib-compressed. zlib inflation is header+adler32-validated, so it
			// succeeds ONLY on genuinely-compressed data and never on cleartext: use it
			// when it works (self-correcting the mis-parse), else surface the cleartext.
			if x := zlibInflatePDF(decoded); len(x) > 0 {
				dec = x
			} else {
				dec = decoded
				if len(dec) > maxBytesPerPDFStream {
					dec = dec[:maxBytesPerPDFStream]
				}
				// A prefilter-only /Filter that actually wraps RAW deflate (the dict
				// dropped a trailing /FlateDecode, or used the headerless variant) leaves
				// `decoded` still compressed but past zlib's header/adler32 validation, so
				// the cleartext surfaced above is really deflate bytes — YARA would see
				// garbage (an evasion). Raw deflate has no checksum, so an inflate of
				// genuine cleartext often yields junk; we therefore do NOT replace `dec`
				// with it (that would corrupt the common cleartext case) but emit it as an
				// ADDITIONAL stream so a real raw-deflate payload is still surfaced.
				if x := rawInflatePDF(decoded); len(x) > 0 && !bytes.Equal(x, dec) &&
					len(res.Streams) < maxStreams && total+len(x) < maxTotalPDF {
					res.Streams = append(res.Streams, x)
					total += len(x)
				}
			}
		} else {
			// Terminal FlateDecode / unknown / no-/Filter: inflate the (prefiltered)
			// body; fall back to the raw body (decoy /Filter armoured a real deflate),
			// then to an opportunistic un-armour (decoy /Filter hid a real armoured
			// deflate). All bounded — at most a few inflate attempts.
			dec = inflatePDFStream(decoded)
			if len(dec) == 0 {
				dec = inflatePDFStream(body)
			}
			if len(dec) == 0 {
				for _, d := range [][]byte{decodeASCII85PDF(body), decodeASCIIHexPDF(body)} {
					if len(d) > 0 {
						if x := inflatePDFStream(d); len(x) > 0 {
							dec = x
							break
						}
					}
				}
			}
			if len(dec) == 0 {
				continue // not deflate / not armoured-deflate — raw scan covers it
			}
		}
		res.Streams = append(res.Streams, dec)
		total += len(dec)
		produced++
	}

	// Structural dropper indicators (PDF-DEEPEN): action/JS/launch/embedded-file
	// keywords that auto-fire or carry a payload. These are name tokens in the
	// PDF body itself (not the inflated streams), so they are surfaced separately.
	// EFFORT-4: gated on opts.PDFDeepen — a low effort level scans only the
	// inflated object streams (above), not the structural-indicator markers.
	if opts.PDFDeepen {
		fromPDFIndicators(scan, res, deadline)
	}
}

// pdfIndicatorNames is the set of name tokens fromPDFIndicators looks for, used
// for a cheap "any candidate present?" pre-check before the (more expensive)
// content scrub.
var pdfIndicatorNames = [][]byte{
	pdfNameOpenAction, pdfNameAA, pdfNameLaunch, pdfNameJS, pdfNameJavaScript,
	pdfNameEmbeddedFile, pdfNameJBIG2, pdfNameObjStm,
}

// fromPDFIndicators emits pdfid-style structural markers for a PDF's high-risk
// name tokens. The match runs over a SCRUBBED copy of the PDF where literal
// strings, hex strings, comments, and stream bodies are blanked (AUDIT-PDF-LEXER)
// — otherwise an attacker could embed `(/OpenAction /JS)` inside a string or a
// stream and fabricate a high-score marker, a false-positive injection. The
// scrub also de-obfuscates hex-name escapes (/J#61vaScript → /JavaScript) and the
// escape count is itself an evasion signal (PDF-HEXOBFUSC). The scrub runs only
// when a '#' or a candidate name actually appears in the raw bytes, so a PDF with
// none of these pays nothing. Bounded, fail-open, deadline-aware.
func fromPDFIndicators(scan []byte, res *Result, deadline time.Time) {
	if expired(deadline) || len(res.Streams) >= maxStreams {
		return
	}
	buf := scan
	hexCount := 0
	needScrub := bytes.IndexByte(scan, '#') >= 0
	if !needScrub {
		for _, nm := range pdfIndicatorNames {
			if bytes.Contains(scan, nm) {
				needScrub = true
				break
			}
		}
	}
	if needScrub {
		buf, hexCount = scrubPDFForNames(scan)
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

// scrubPDFForNames returns a copy of scan in which the byte regions that must NOT
// be searched for indicator names — literal strings `(...)`, hex strings `<...>`,
// comments `%...`, and `stream`…`endstream` bodies — are blanked to spaces, while
// real name tokens are preserved and their #XX hex escapes canonicalised. It also
// returns the number of hex escapes decoded inside names. This keeps the
// dictionary structure intact (so /OpenAction in a real dictionary still matches)
// but stops an attacker fabricating a marker from a name embedded in a string,
// comment, or binary stream (AUDIT-PDF-LEXER). Single linear pass, fail-open.
func scrubPDFForNames(scan []byte) ([]byte, int) {
	out := make([]byte, 0, len(scan))
	count := 0
	n := len(scan)
	i := 0
	lengths := pdfIndirectLengths(scan)
	for i < n {
		c := scan[i]
		switch {
		case c == '%':
			// Comment: blank to end of line.
			for i < n && scan[i] != '\n' && scan[i] != '\r' {
				out = append(out, ' ')
				i++
			}
		case c == '(':
			// Literal string: blank to the balanced ')', honouring '\' escapes and
			// nested parens (PDF 7.3.4.2).
			depth := 1
			out = append(out, ' ')
			i++
			for i < n && depth > 0 {
				switch scan[i] {
				case '\\':
					out = append(out, ' ')
					i++
					if i < n {
						out = append(out, ' ')
						i++
					}
					continue
				case '(':
					depth++
				case ')':
					depth--
				}
				out = append(out, ' ')
				i++
			}
		case c == '<':
			if i+1 < n && scan[i+1] == '<' {
				// Dictionary open '<<' — structural, keep it.
				out = append(out, '<', '<')
				i += 2
			} else {
				// Hex string '<...>' — blank to the closing '>'.
				out = append(out, ' ')
				i++
				for i < n && scan[i] != '>' {
					out = append(out, ' ')
					i++
				}
				if i < n {
					out = append(out, ' ')
					i++
				}
			}
		case c == 's' && bytes.HasPrefix(scan[i:], pdfStreamKW) &&
			pdfTokenBoundary(scan, i, i+len(pdfStreamKW)):
			// `stream` keyword + EOL begins a binary body. Prefer the declared
			// /Length (looked up in THIS stream's preceding dict): skip the keyword,
			// one EOL, then exactly that many body bytes, and only trust it when
			// `endstream` actually follows. Otherwise fall back to the first
			// `endstream` substring (so a body containing those bytes can still leak
			// — that residual is AUDIT-PDF-ENDSTREAM, narrowed here to bodies whose
			// /Length is indirect/absent).
			bodyStart := skipPDFEOL(scan, i+len(pdfStreamKW))
			stop := -1
			if l := pdfStreamLength(scan, i, lengths); l >= 0 && bodyStart+l <= n {
				after := bytes.TrimLeft(scan[bodyStart+l:], " \t\r\n\f")
				if bytes.HasPrefix(after, pdfEndStream) {
					stop = (bodyStart + l) + (len(scan[bodyStart+l:]) - len(after)) + len(pdfEndStream)
				}
			}
			if stop < 0 {
				if endRel := bytes.Index(scan[bodyStart:], pdfEndStream); endRel >= 0 {
					stop = bodyStart + endRel + len(pdfEndStream)
				} else {
					stop = n
				}
			}
			for ; i < stop; i++ {
				out = append(out, ' ')
			}
		case c == '/':
			// Name token: keep '/', canonicalise #XX escapes (name-regular only —
			// an escaped delimiter stays verbatim so it can't fabricate a boundary,
			// /foo#2FLaunch -> kept, not /Launch; PDF 7.3.5).
			out = append(out, '/')
			i++
			for i < n && !isPDFNameTerminator(scan[i]) {
				if scan[i] == '#' && i+2 < n {
					hi := hexVal(scan[i+1])
					lo := hexVal(scan[i+2])
					if hi >= 0 && lo >= 0 {
						b := byte(hi<<4 | lo) // #nosec G115 -- hexVal returns 0..15, so hi<<4|lo is 0..255
						count++
						if !isPDFNameTerminator(b) {
							out = append(out, b)
						} else {
							out = append(out, '#', scan[i+1], scan[i+2])
						}
						i += 3
						continue
					}
				}
				out = append(out, scan[i])
				i++
			}
		default:
			out = append(out, c)
			i++
		}
	}
	return out, count
}

// maxPDFLengthObjs caps how many `N G obj <int> endobj` length objects
// pdfIndirectLengths records, bounding the one-pass scan on a hostile PDF.
const maxPDFLengthObjs = 4096

// pdfIndirectLengths builds a map objNum -> direct-integer value for every
// numeric object of the common form `N G obj <int> endobj` (the shape a /Length
// indirect reference points at). It lets pdfStreamLength resolve a `/Length N G R`
// reference without an xref table (AUDIT-PDF-ENDSTREAM): the residual was that an
// indirect /Length fell back to the first-`endstream` substring, truncating a
// FlateDecode body whose compressed bytes happen to contain `endstream`. Only
// bare-integer length objects are recorded — a length is always a direct integer,
// so this is sufficient and can't be steered by string/dict content. Bounded by
// maxPDFLengthObjs and a single linear pass; returns nil when none are present.
func pdfIndirectLengths(b []byte) map[int]int {
	var m map[int]int
	n := len(b)
	pos := 0
	for len(m) < maxPDFLengthObjs {
		rel := bytes.Index(b[pos:], pdfObjKW)
		if rel < 0 {
			break
		}
		at := pos + rel
		pos = at + len(pdfObjKW)
		// `obj` must be a real keyword: preceded by whitespace and followed by
		// whitespace/EOL, else it's a substring of `endobj`/`globj`/etc.
		if at == 0 || !isPDFWS(b[at-1]) {
			continue
		}
		if pos < n && !isPDFWS(b[pos]) {
			continue
		}
		// Parse the object number `N` and generation `G` immediately before `obj`.
		num, ok := pdfTrailingObjNum(b, at)
		if !ok {
			continue
		}
		// The value must be a bare integer directly followed (mod whitespace) by
		// `endobj` — anything else (a dict, array, string) isn't a length object.
		j := skipPDFWS(b, pos)
		start := j
		val := 0
		for j < n && b[j] >= '0' && b[j] <= '9' {
			val = val*10 + int(b[j]-'0')
			if val > maxPDFScan {
				val = -1
				break
			}
			j++
		}
		if j == start || val < 0 {
			continue
		}
		if k := skipPDFWS(b, j); !bytes.HasPrefix(b[k:], pdfEndObjKW) {
			continue
		}
		if m == nil {
			m = make(map[int]int)
		}
		if _, seen := m[num]; !seen { // first definition wins; ignore redefinitions
			m[num] = val
		}
	}
	return m
}

// pdfTrailingObjNum parses the `N G` (object number, generation) integers that
// precede the `obj` keyword at objAt, returning the object number. It scans
// backward over `G`, whitespace, then `N`. Bounded; fail-safe (ok=false on any
// malformed shape).
func pdfTrailingObjNum(b []byte, objAt int) (int, bool) {
	i := objAt - 1
	for i >= 0 && isPDFWS(b[i]) { // gap before `obj`
		i--
	}
	// generation digits
	genEnd := i
	for i >= 0 && b[i] >= '0' && b[i] <= '9' {
		i--
	}
	if i == genEnd { // no generation digits
		return 0, false
	}
	for i >= 0 && isPDFWS(b[i]) { // gap between N and G
		i--
	}
	numEnd := i
	for i >= 0 && b[i] >= '0' && b[i] <= '9' {
		i--
	}
	if i == numEnd { // no object-number digits
		return 0, false
	}
	num := 0
	for j := i + 1; j <= numEnd; j++ {
		num = num*10 + int(b[j]-'0')
		if num > maxPDFScan {
			return 0, false
		}
	}
	return num, true
}

// pdfStreamLength returns the direct-integer /Length for the stream whose
// `stream` keyword is at streamPos, by searching a bounded window of the bytes
// just before it (the stream's own dictionary). Looking it up per stream — rather
// than carrying state forward — means a /Length from an earlier object can never
// be mis-applied to a later stream. An indirect `/Length N G R` is resolved
// against lengths (built by pdfIndirectLengths) when supplied; lengths may be nil.
// Returns -1 when none is found nearby, or the indirect ref is unresolvable.
func pdfStreamLength(b []byte, streamPos int, lengths map[int]int) int {
	const window = 512 // a stream dict is small; bound the backward scan
	lo := streamPos - window
	if lo < 0 {
		lo = 0
	}
	// Clip the search to THIS object: the `obj` keyword that opens it (or the
	// previous object's `endobj`, both matched by "obj") sits right before this
	// dict, so starting after the nearest "obj" stops a prior object's /Length
	// from being mis-picked. A wrong clip only yields -1 (safe fallback).
	if oi := bytes.LastIndex(b[lo:streamPos], []byte("obj")); oi >= 0 {
		lo += oi + len("obj")
	}
	rel := bytes.LastIndex(b[lo:streamPos], pdfNameLength)
	if rel < 0 {
		return -1
	}
	after := lo + rel + len(pdfNameLength)
	// Require a name boundary so "/Length1"/"/LengthFoo" don't shadow "/Length".
	// On a shadow we conservatively return -1 (the caller falls back to the
	// `endstream` substring — the AUDIT-PDF-ENDSTREAM residual, not a new leak).
	if after < streamPos && !isPDFNameTerminator(b[after]) {
		return -1
	}
	return readPDFLength(b, after, lengths)
}

// readPDFLength parses a stream's /Length value starting at j (just past the
// "/Length" name). It returns the direct integer, or -1 when the value is absent
// or an indirect reference (`N G R`) that can't be resolved. An indirect ref is
// resolved against lengths (the objNum->value map from pdfIndirectLengths) when
// supplied (AUDIT-PDF-ENDSTREAM); on a miss, or when lengths is nil, it returns -1
// and the caller falls back to the `endstream` substring. Whitespace skipping is
// comment-aware (a `%…` comment is whitespace in PDF), so an indirect length
// split by a comment is still recognised. Bounded; reads only a short digit run.
func readPDFLength(b []byte, j int, lengths map[int]int) int {
	n := len(b)
	j = skipPDFWS(b, j)
	start := j
	val := 0
	for j < n && b[j] >= '0' && b[j] <= '9' {
		val = val*10 + int(b[j]-'0')
		if val > maxPDFScan { // implausibly large — treat as unusable
			return -1
		}
		j++
	}
	if j == start { // no digits
		return -1
	}
	// Detect an indirect reference `<int> <int> R`: another integer then 'R'.
	k := skipPDFWS(b, j)
	if k < n && b[k] >= '0' && b[k] <= '9' {
		for k < n && b[k] >= '0' && b[k] <= '9' {
			k++
		}
		k = skipPDFWS(b, k)
		if k < n && b[k] == 'R' {
			// Indirect /Length: resolve `val` (the object number) against the
			// pre-scanned length objects. Miss / nil map → fall back (-1).
			if lengths != nil {
				if rv, ok := lengths[val]; ok {
					return rv
				}
			}
			return -1
		}
	}
	return val
}

// isPDFWS reports whether c is a PDF whitespace byte (PDF 7.2.2).
func isPDFWS(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '\f', 0:
		return true
	}
	return false
}

// skipPDFWS advances past PDF whitespace AND comments (`%` to end of line), which
// the spec treats as whitespace, returning the next significant-byte offset.
func skipPDFWS(b []byte, j int) int {
	n := len(b)
	for j < n {
		switch b[j] {
		case ' ', '\t', '\r', '\n', '\f', 0:
			j++
		case '%':
			for j < n && b[j] != '\n' && b[j] != '\r' {
				j++
			}
		default:
			return j
		}
	}
	return j
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

// zlibInflatePDF inflates body as a zlib stream ONLY (no raw-deflate fallback).
// zlib validates a 2-byte header and a trailing adler32 checksum, so this returns
// output only for genuinely zlib-compressed data and effectively never for
// cleartext — used to tell a still-compressed body apart from real cleartext when
// a /Filter chain mis-parsed. Bounded by maxBytesPerPDFStream.
func zlibInflatePDF(body []byte) []byte {
	if len(body) < 2 {
		return nil
	}
	zr, err := zlib.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	return readInflated(zr)
}

// rawInflatePDF inflates body as RAW deflate ONLY (no zlib header/checksum). Used
// to recover a raw-deflate payload that a prefilter-only /Filter chain left after
// text-unarmouring (the dict omitted the trailing /FlateDecode). Raw deflate is
// unchecksummed, so this can yield junk from genuine cleartext — the caller emits
// the result as an ADDITIONAL stream, never as a replacement. Bounded.
func rawInflatePDF(body []byte) []byte {
	if len(body) < 2 {
		return nil
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
