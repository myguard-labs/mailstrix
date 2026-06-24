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
// Fail-open + bounded: the scan is capped to a leading window, data-URI carves
// and decoded output are capped and count-limited, and at most a few markers are
// emitted. Malformed input yields nothing (Extract's recover covers a panic).

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"time"
)

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
// against a lowercased copy of the scan window.
var (
	// reHTMLDownloadAttr matches a forced download in either form: the HTML anchor
	// attribute (download="x") or the JS property assignment (a.download='x').
	// Case-insensitive; run against the lowercased window. Always paired with a
	// blob-reconstruct API by the caller, so a lone "download=" cannot fire.
	reHTMLDownloadAttr = regexp.MustCompile(`(?:\s|;|"|\.)download\s*=`)
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
	lower := bytes.ToLower(head)
	return bytes.Contains(lower, []byte("<script")) ||
		bytes.Contains(lower, []byte("<svg")) ||
		bytes.Contains(lower, []byte("<a ")) ||
		bytes.Contains(lower, []byte("download")) ||
		bytes.Contains(head, []byte("Blob")) ||
		bytes.Contains(head, []byte("data:"))
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
	lower := bytes.ToLower(head)

	// Signal 1: blob reconstruct + forced download.
	hasBlobAPI := false
	for _, a := range blobReconstructAPIs {
		if bytes.Contains(head, a) {
			hasBlobAPI = true
			break
		}
	}
	hasDownload := reHTMLDownloadAttr.Match(lower) || bytes.Contains(head, []byte(".click("))
	if hasBlobAPI && hasDownload && len(res.Streams) < maxStreams {
		res.Streams = append(res.Streams, []byte("HTML-SMUGGLING-BLOB"))
	}

	// Signal 3: scripted SVG. Only when an <svg> root is present AND it carries
	// an execution vector (script/onload/foreignObject).
	if bytes.Contains(lower, []byte("<svg")) {
		if bytes.Contains(lower, []byte("<script")) ||
			bytes.Contains(lower, []byte("onload=")) ||
			bytes.Contains(lower, []byte("<foreignobject")) {
			if len(res.Streams) < maxStreams {
				res.Streams = append(res.Streams, []byte("SVG-SCRIPT"))
			}
		}
	}

	// Signal 2: force-downloaded base64 data: URI. Gate on a download intent
	// anywhere in the window so a benign inline data:image never carves.
	if !hasDownload {
		return
	}
	carved := 0
	for _, m := range reDataURIBase64.FindAllSubmatch(head, htmlMaxDataURIs*2) {
		if carved >= htmlMaxDataURIs || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		b64 := bytes.ReplaceAll(m[1], []byte{'\n'}, nil)
		b64 = bytes.ReplaceAll(b64, []byte{'\r'}, nil)
		b64 = bytes.ReplaceAll(b64, []byte{' '}, nil)
		b64 = bytes.ReplaceAll(b64, []byte{'\t'}, nil)
		if len(b64) < 16 || len(b64) > htmlMaxDataURIB64 {
			continue
		}
		dec := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
		n, err := base64.StdEncoding.Decode(dec, b64)
		if err != nil || n == 0 {
			continue
		}
		dec = dec[:n]
		if len(dec) > htmlMaxDecoded {
			dec = dec[:htmlMaxDecoded]
		}
		// A force-downloaded base64 data: URI is a smuggled file regardless of
		// content; emit the marker once we have a real decoded payload.
		if carved == 0 && len(res.Streams) < maxStreams {
			res.Streams = append(res.Streams, []byte("HTML-SMUGGLING-DATAURI"))
		}
		carved++
		// If the decoded bytes carry a container magic, route them through the
		// nested extractor so the reconstructed dropper is fully scanned; either
		// way the decoded blob is added as a stream for the rule set.
		if hasContainerMagic(dec) {
			extractChild(dec, res, b, depth+1, deadline)
		}
		if len(res.Streams) < maxStreams {
			res.Streams = append(res.Streams, dec)
		}
	}
}
