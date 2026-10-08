package extract

// HTML smuggling extraction — HTML-SMUGGLING-* / SVG-SCRIPT.
//
// Since Office macros were disabled by default, the dominant mail-malware
// delivery method is "HTML smuggling": an .html / .htm / .svg attachment (or an
// HTML mail body) that carries the payload as a base64 blob inside a <script>,
// reconstructs it client-side with JavaScript (atob → Blob / byte array →
// URL.createObjectURL), and forces it to disk via an anchor with a download
// attribute that is .click()ed. The bytes never traverse the network as the
// payload, so a content scanner that only sees the outer HTML text misses it.
// None of yarad's container paths look at HTML, and oletools has no HTML triage
// at all, so this is new coverage that leads the comparison set (mirrors the
// PDF-DEEPEN rationale).
//
// Two signals, both self-gating so the pass is safe on arbitrary text:
//
//  1. HTML-SMUGGLING-BLOB — the canonical client-side file-delivery combo:
//       a Blob/object-URL/msSaveBlob reconstruct API  AND  a forced download
//       (a download= attribute or an anchor .click()). In an email HTML part a
//       script that assembles a Blob and auto-downloads it is malicious by
//       context — mail clients are not web apps. Requiring BOTH halves keeps a
//       benign lone createObjectURL (image preview) or lone download attribute
//       (an ordinary "save this file" link) from firing. A decode primitive
//       (atob / String.fromCharCode) raises confidence and, when present with a
//       large base64 run, drives the carve in signal 2.
//
//  2. HTML-SMUGGLING-DATAURI — a base64 data: URI that is force-downloaded
//       (a download= attribute on/near the data: href). Benign inline
//       data:image without a download attribute never fires. When matched, the
//       base64 payload is decoded and, if it carries a known container magic
//       (PK/OLE2/MZ/%PDF), routed back through extractChild so the reconstructed
//       dropper is scanned by the full rule set — not just the HTML text.
//
//  3. SVG-SCRIPT — an <svg> root carrying <script> / onload= / <foreignObject>.
//       SVG is XML the browser executes; a scripted SVG attachment is a
//       redirect / smuggling / phishing vector. Scored low (legitimate
//       interactive SVG exists), marker-only, no carve.
//
//  4. SVG-EMBEDDED-PAYLOAD — an <svg> carrying a base64 data: URI (typically an
//       <image href>) whose decoded bytes are a CONTAINER magic (PK/OLE2/MZ/
//       %PDF). Legitimate SVG inlines raster art (PNG/JPEG/GIF) — never a zip,
//       OLE2 doc, PE or PDF — so the container magic is the dropper tell.
//       Decoded blob is routed through extractChild for full scanning. No
//       download attribute required (the SVG renders client-side).
//
// Fail-open + bounded: the scan is capped to a leading window, data-URI carves
// and decoded output are capped and count-limited, and at most a few markers are
// emitted. Malformed input yields nothing (Extract's recover covers a panic).

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// asciiContainsFold reports whether haystack contains needle using ASCII
// case-insensitive comparison. needle MUST already be lowercase ASCII.
// Only bytes 'A'–'Z' (0x41–0x5A) are folded in haystack; non-ASCII bytes
// (0x80–0xFF) are compared as-is, exactly matching what
// bytes.Contains(bytes.ToLower(haystack), needle) produces for pure-ASCII
// needles.
func asciiContainsFold(haystack, needle []byte) bool {
	n := len(needle)
	if n == 0 {
		return true
	}
	h := len(haystack)
	if n > h {
		return false
	}
	first := needle[0] // needle is lowercase; first byte is 'a'–'z' or digit/symbol
	limit := h - n
	for i := 0; i <= limit; i++ {
		hb := haystack[i]
		if hb >= 'A' && hb <= 'Z' {
			hb += 'a' - 'A'
		}
		if hb != first {
			continue
		}
		match := true
		for j := 1; j < n; j++ {
			hj := haystack[i+j]
			if hj >= 'A' && hj <= 'Z' {
				hj += 'a' - 'A'
			}
			if hj != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

const (
	// htmlScanCap bounds how many leading bytes of a part we inspect for the
	// smuggling signatures. Smuggling glue (the script + anchor) sits near the
	// top of the document; a multi-MiB tail is the encoded payload, which the
	// data-URI carve handles separately, so we do not regex-scan all of it.
	htmlScanCap = 1 << 20 // 1 MiB
	// htmlMaxDataURIs caps how many base64 data: URIs we carve+decode per part.
	htmlMaxDataURIs = 8
	// htmlMaxDataURIB64 caps the base64 source length of a single data: URI we
	// decode (a multi-tens-of-MiB blob is not decoded into memory wholesale).
	htmlMaxDataURIB64 = 8 << 20 // 8 MiB of base64 source
	// htmlMaxDecoded caps the decoded output of a single data: URI payload.
	htmlMaxDecoded = 6 << 20 // 6 MiB decoded
)

// HTML/SVG/JS smuggling signatures. JS builtin identifiers (atob, Blob,
// createObjectURL, msSaveBlob) are case-SENSITIVE and matched as-is; HTML tags
// and attributes (<svg>, <script>, download=) are case-INSENSITIVE and matched
// via asciiContainsFold or (?i) regex — no full-window ToLower allocation.
var (
	// reHTMLDownloadAttr matches a forced download in either form: the HTML anchor
	// attribute (download="x") or the JS property assignment (a.download='x').
	// (?i) makes it case-insensitive so it can run against the original (uncopied)
	// window instead of a lowercased copy. Always paired with a blob-reconstruct
	// API by the caller, so a lone "download=" cannot fire.
	reHTMLDownloadAttr = regexp.MustCompile(`(?i)(?:\s|;|"|\.)download\s*=`)
	// reDataURIBase64 captures the base64 body of a base64 data: URI. Case-
	// insensitive scheme; the body is the standard base64 alphabet.
	reDataURIBase64 = regexp.MustCompile(`(?i)data:[a-z0-9.+/-]*;base64,([A-Za-z0-9+/=\s]+)`)
)

// blobReconstructAPIs are the case-sensitive JS APIs that assemble bytes into a
// downloadable object — the reconstruct half of HTML smuggling.
var blobReconstructAPIs = [][]byte{
	[]byte("createObjectURL"),
	[]byte("msSaveBlob"),
	[]byte("msSaveOrOpenBlob"),
	[]byte("new Blob"),
}

// looksLikeMarkup is the cheap gate: only run the (more expensive) signature
// matching when the buffer plausibly contains HTML/SVG/JS smuggling glue. Keeps
// the pass safe and fast on arbitrary text/binary (mirrors fromCSVDDE's gate).
func looksLikeMarkup(head []byte) bool {
	if !bytes.ContainsRune(head, '<') {
		// Pure-JS smuggling with no surrounding tags can still carry the blob
		// combo; allow it through if it has both a blob API hint and "download".
		return bytes.Contains(head, []byte("Blob")) || bytes.Contains(head, []byte("data:"))
	}
	return asciiContainsFold(head, []byte("<script")) ||
		asciiContainsFold(head, []byte("<svg")) ||
		asciiContainsFold(head, []byte("<a ")) ||
		asciiContainsFold(head, []byte("download")) ||
		bytes.Contains(head, []byte("Blob")) ||
		bytes.Contains(head, []byte("data:"))
}

// scriptURIAttrs are the attribute names whose value is navigated/executed.
var scriptURIAttrs = map[string]bool{"href": true, "src": true, "action": true, "formaction": true}

// Bounds for the IE spaced/NUL entity pre-pass (ICAP-385-1b). The pre-pass
// reads at most maxEntityPrepassIn bytes and never writes more than it read
// (a normalised entity is never longer than its source), so the output is
// bounded by maxEntityPrepassIn as well. One entity may span at most
// maxSpacedEntity source bytes; longer candidates are left as-is.
const (
	maxEntityPrepassIn = 1 << 20
	maxSpacedEntity    = 32
)

// isEntityPad reports bytes IE tolerates inside a numeric character reference.
func isEntityPad(c byte) bool {
	return c == 0 || c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// normalizeSpacedEntities rewrites IE-style numeric character references that
// are broken by whitespace/NUL (`& #1  1   8;`) into the canonical `&#118;`
// form so the tokenizer decodes them. Only references that actually contained
// padding are rewritten; malformed ones (no digits, no ';', over
// maxSpacedEntity bytes) are left untouched. It returns buf itself (no
// allocation) when nothing changed.
func normalizeSpacedEntities(buf []byte) []byte {
	if len(buf) > maxEntityPrepassIn {
		buf = buf[:maxEntityPrepassIn]
	}
	var out []byte
	last := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] != '&' {
			continue
		}
		end, canon, ok := parseSpacedEntity(buf, i)
		if !ok {
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(buf))
		}
		out = append(out, buf[last:i]...)
		out = append(out, canon...)
		last = end
		i = end - 1
	}
	if out == nil {
		return buf
	}
	return append(out, buf[last:]...)
}

// parseSpacedEntity parses a padded numeric reference starting at buf[i]=='&'.
// ok is true only when at least one pad byte was skipped and the reference is
// well formed.
func parseSpacedEntity(buf []byte, i int) (end int, canon []byte, ok bool) {
	lim := i + maxSpacedEntity
	if lim > len(buf) {
		lim = len(buf)
	}
	j, padded := i+1, false
	skip := func() {
		for j < lim && isEntityPad(buf[j]) {
			j++
			padded = true
		}
	}
	skip()
	if j >= lim || buf[j] != '#' {
		return 0, nil, false
	}
	j++
	skip()
	hex := false
	if j < lim && (buf[j] == 'x' || buf[j] == 'X') {
		hex = true
		j++
	}
	var digits []byte
	for ; j < lim; j++ {
		c := buf[j]
		switch {
		case isEntityPad(c):
			padded = true
		case c >= '0' && c <= '9', hex && (c|0x20 >= 'a' && c|0x20 <= 'f'):
			digits = append(digits, c)
		case c == ';':
			if !padded || len(digits) == 0 {
				return 0, nil, false
			}
			canon = append(canon, '&', '#')
			if hex {
				canon = append(canon, 'x')
			}
			canon = append(canon, digits...)
			canon = append(canon, ';')
			return j + 1, canon, true
		default:
			return 0, nil, false
		}
	}
	return 0, nil, false
}

// rawAttrValues returns the raw (still entity-encoded) attribute values of a
// start tag in source order, mirroring the tokenizer's attribute order.
func rawAttrValues(raw []byte) [][]byte {
	var vals [][]byte
	i := 1
	for i < len(raw) && !isHTMLSpace(raw[i]) && raw[i] != '/' && raw[i] != '>' {
		i++ // tag name
	}
	for i < len(raw) {
		for i < len(raw) && (isHTMLSpace(raw[i]) || raw[i] == '/') {
			i++
		}
		if i >= len(raw) || raw[i] == '>' {
			break
		}
		i++ // first name byte (may be '=')
		for i < len(raw) && !isHTMLSpace(raw[i]) && raw[i] != '=' && raw[i] != '/' && raw[i] != '>' {
			i++
		}
		for i < len(raw) && isHTMLSpace(raw[i]) {
			i++
		}
		if i >= len(raw) || raw[i] != '=' {
			vals = append(vals, nil)
			continue
		}
		i++
		for i < len(raw) && isHTMLSpace(raw[i]) {
			i++
		}
		start := i
		if i < len(raw) && (raw[i] == '"' || raw[i] == '\'') {
			q := raw[i]
			i++
			start = i
			for i < len(raw) && raw[i] != q {
				i++
			}
			vals = append(vals, raw[start:i])
			i++
			continue
		}
		for i < len(raw) && !isHTMLSpace(raw[i]) && raw[i] != '>' {
			i++
		}
		vals = append(vals, raw[start:i])
	}
	return vals
}

func isHTMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// hasScriptURIAttr reports whether any href/src/action/formaction attribute
// of a start tag has a value that starts (after leading C0 controls and
// space, ignoring ASCII tab/LF/CR anywhere, as browsers do) with javascript:
// or vbscript: (case-insensitive). See scanScriptURIAttr for the plain vs
// obfuscated split.
func hasScriptURIAttr(buf []byte, deadline time.Time) bool {
	plain, obf := scanScriptURIAttr(buf, deadline)
	return plain || obf
}

// scanScriptURIAttr scans start tags (tokenization, comments and raw-text
// elements follow golang.org/x/net/html). plain is set when a script URI is
// literally present in the source; obf when the scheme only appears after
// entity decoding (raw attribute bytes do not start with it but the decoded
// value does), including IE spaced/NUL entity forms normalised by the bounded
// pre-pass. A link counts for exactly one of the two.
// The caller passes the already-capped head; MaxBuf is bounded to len(buf).
func scanScriptURIAttr(buf []byte, deadline time.Time) (plain, obf bool) {
	buf = normalizeSpacedEntities(buf)
	z := html.NewTokenizer(bytes.NewReader(buf))
	z.SetMaxBuf(len(buf) + 1)
	for n := 1; !plain || !obf; n++ {
		if n&0xff == 0 && expired(deadline) {
			return
		}
		switch z.Next() {
		case html.ErrorToken:
			return
		case html.StartTagToken, html.SelfClosingTagToken:
			// TagAttr unescapes in place, so snapshot the raw tag first;
			// without '&' raw and decoded values are identical.
			var raw []byte
			if r := z.Raw(); bytes.IndexByte(r, '&') >= 0 {
				raw = append([]byte(nil), r...)
			}
			var rawVals [][]byte
			rawParsed := false
			for idx, more := 0, true; more; idx++ {
				var key, val []byte
				key, val, more = z.TagAttr()
				if !scriptURIAttrs[string(key)] || !isScriptURI(val) {
					continue
				}
				if raw == nil {
					plain = true
					continue
				}
				if !rawParsed {
					rawVals, rawParsed = rawAttrValues(raw), true
				}
				if idx < len(rawVals) && !isScriptURI(rawVals[idx]) {
					obf = true
				} else {
					plain = true
				}
			}
		}
	}
	return
}

// isScriptURI reports whether v starts with javascript: or vbscript: after
// browser URL normalisation (leading C0/space stripped, tab/LF/CR removed).
func isScriptURI(v []byte) bool {
	i := 0
	for i < len(v) && v[i] <= ' ' {
		i++
	}
	var w [11]byte // len("javascript:")
	k := 0
	for ; i < len(v) && k < len(w); i++ {
		if c := v[i]; c != '\t' && c != '\n' && c != '\r' {
			w[k] = foldByte(c)
			k++
		}
	}
	s := string(w[:k])
	return s == "javascript:" || strings.HasPrefix(s, "vbscript:")
}

// foldByte lowercases ASCII letters only; every other byte is unchanged.
func foldByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c | 0x20
	}
	return c
}

// fromHTMLSmuggling inspects a plain-text/markup buffer for HTML-smuggling and
// scripted-SVG signatures, emitting PURE markers and (for force-downloaded
// data: URIs) carving the decoded payload back through extractChild. Self-
// gating, bounded, fail-open.
func fromHTMLSmuggling(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	if len(buf) == 0 || expired(deadline) {
		return
	}
	head := buf
	if len(head) > htmlScanCap {
		head = head[:htmlScanCap]
	}
	if !looksLikeMarkup(head) {
		return
	}

	// Signal 1: blob reconstruct + forced download.
	hasBlobAPI := false
	for _, a := range blobReconstructAPIs {
		if bytes.Contains(head, a) {
			hasBlobAPI = true
			break
		}
	}
	// reHTMLDownloadAttr is now (?i) so it runs against the original head.
	hasDownload := reHTMLDownloadAttr.Match(head) || bytes.Contains(head, []byte(".click("))
	if hasBlobAPI && hasDownload && len(res.Streams) < maxStreams {
		res.Streams = append(res.Streams, []byte("HTML-SMUGGLING-BLOB"))
	}

	// Signal 4: javascript:/vbscript: URI in a navigational attribute.
	plainURI, obfURI := scanScriptURIAttr(head, deadline)
	if plainURI && len(res.Streams) < maxStreams {
		res.Streams = append(res.Streams, []byte("HTML-SCRIPT-URI"))
	}
	if obfURI && len(res.Streams) < maxStreams {
		res.Streams = append(res.Streams, []byte("HTML-SCRIPT-URI-OBFUSCATED"))
	}

	// Signal 3: scripted SVG. Only when an <svg> root is present AND it carries
	// an execution vector (script/onload/foreignObject).
	isSVG := asciiContainsFold(head, []byte("<svg"))
	if isSVG {
		if asciiContainsFold(head, []byte("<script")) ||
			asciiContainsFold(head, []byte("onload=")) ||
			asciiContainsFold(head, []byte("<foreignobject")) {
			if len(res.Streams) < maxStreams {
				res.Streams = append(res.Streams, []byte("SVG-SCRIPT"))
			}
		}
		// SVG-deepen: carve base64 payloads embedded in <image href|xlink:href=
		// "data:...;base64,..."> blobs. An SVG legitimately inlines raster art
		// (PNG/JPEG/GIF), so we only flag a blob that decodes to a CONTAINER magic
		// (PK/OLE2/MZ/%PDF) — a dropper hidden in the image href, never benign
		// SVG art. Unlike signal 2 this does NOT require a download attribute,
		// because the SVG renders client-side and the container payload is the
		// tell on its own. Bounded + fail-open.
		svgCarved := 0
		for _, m := range reDataURIBase64.FindAllSubmatch(head, htmlMaxDataURIs*2) {
			if svgCarved >= htmlMaxDataURIs || len(res.Streams) >= maxStreams || expired(deadline) {
				break
			}
			dec := decodeDataURIB64(m[1])
			// FP gate: only carve when the decoded blob is a real dropper container.
			if dec == nil || !hasContainerMagic(dec) {
				continue
			}
			if svgCarved == 0 && len(res.Streams) < maxStreams {
				res.Streams = append(res.Streams, []byte("SVG-EMBEDDED-PAYLOAD"))
			}
			svgCarved++
			extractChild(dec, res, b, depth+1, deadline)
			if len(res.Streams) < maxStreams {
				res.Streams = append(res.Streams, dec)
			}
		}
	}

	// Signal 2: base64 data: URI carve. SVG data: URIs are already handled by the
	// SVG-deepen path above, so skip them here to avoid a double carve.
	if isSVG {
		return
	}
	// Fires on EITHER a force-download intent (a smuggled file regardless of
	// content) OR a container-magic payload in plain HTML (a dropper hidden in a
	// non-downloaded data: URI — e.g. an iframe/meta-refresh/JS-fetched blob).
	// The container-magic gate is the FP firewall for the no-download case: a
	// benign inline data:image never decodes to PK/OLE2/MZ/%PDF — same rationale
	// as SVG-EMBEDDED-PAYLOAD. When download intent IS present we keep the
	// content-agnostic behaviour (any decoded payload counts).
	dataURIMarker := "HTML-SMUGGLING-DATAURI"
	if !hasDownload {
		dataURIMarker = "HTML-DATAURI-CONTAINER"
	}
	carved := 0
	for _, m := range reDataURIBase64.FindAllSubmatch(head, htmlMaxDataURIs*2) {
		if carved >= htmlMaxDataURIs || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		dec := decodeDataURIB64(m[1])
		if dec == nil {
			continue
		}
		isContainer := hasContainerMagic(dec)
		// Without a download attribute, only a real dropper container carves;
		// a benign inline data:image is skipped.
		if !hasDownload && !isContainer {
			continue
		}
		if carved == 0 && len(res.Streams) < maxStreams {
			res.Streams = append(res.Streams, []byte(dataURIMarker))
		}
		carved++
		// If the decoded bytes carry a container magic, route them through the
		// nested extractor so the reconstructed dropper is fully scanned; either
		// way the decoded blob is added as a stream for the rule set.
		if isContainer {
			extractChild(dec, res, b, depth+1, deadline)
		}
		if len(res.Streams) < maxStreams {
			res.Streams = append(res.Streams, dec)
		}
	}
}

// decodeDataURIB64 strips whitespace from a captured base64 data: URI body and
// decodes it, returning the decoded bytes (capped to htmlMaxDecoded) or nil when
// the source is out of bounds or not valid base64. Fail-open: callers treat nil
// as "skip this URI".
func decodeDataURIB64(raw []byte) []byte {
	b64 := bytes.ReplaceAll(raw, []byte{'\n'}, nil)
	b64 = bytes.ReplaceAll(b64, []byte{'\r'}, nil)
	b64 = bytes.ReplaceAll(b64, []byte{' '}, nil)
	b64 = bytes.ReplaceAll(b64, []byte{'\t'}, nil)
	if len(b64) < 16 || len(b64) > htmlMaxDataURIB64 {
		return nil
	}
	dec := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(dec, b64)
	if err != nil || n == 0 {
		return nil
	}
	dec = dec[:n]
	if len(dec) > htmlMaxDecoded {
		dec = dec[:htmlMaxDecoded]
	}
	return dec
}
