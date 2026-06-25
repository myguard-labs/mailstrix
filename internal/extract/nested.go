package extract

import (
	"bytes"
	"time"
)

// Nested-carrier recursion. A maldoc payload is routinely one carrier deep: a
// PDF whose FlateDecode JavaScript rides inside a .msg attachment, an Office
// macro inside an archive member, an encoded .vbe inside a zip, a dropped OLE
// document inside an RTF \objdata blob. Each of those CHILD blobs was previously
// surfaced only as raw bytes (the leaf scan) — its OWN container layer was never
// cracked, so the inflated JS / decompressed macro / decoded script the keyword
// rules need stayed invisible.
//
// extractChild is the single bounded walker that closes that gap: every site
// that carves a child carrier (an archive member, a .msg attachment, an OLE
// Package payload, an RTF object) routes the child through it, and it dispatches
// the child to its matching extractor by magic exactly as the top-level Extract
// does. The whole nested walk shares ONE budget and ONE depth so a deeply nested
// or fan-out carrier set is bounded as a unit, not per-carrier.

// maxNestDepth bounds how deep the nested-carrier walk recurses across carrier
// boundaries (a .msg holding a zip holding a .docm; an RTF object that is itself
// an archive). It shares the archive depth limit — real droppers nest 1–2
// carriers, and this stops a carrier "quine" from recursing without end.
const maxNestDepth = maxArchiveDepth

// extractChild routes a child blob carved out of a parent carrier to the
// matching extractor by magic so a nested document/archive/script/shortcut is
// ENRICHED the same as a top-level input, instead of reaching only the raw-bytes
// scan. The shared budget b (cumulative members/bytes across the whole walk) and
// depth bound it; a child matching no carrier magic is left as the raw stream its
// emitter already appended (the leaf scan still covers it). Best-effort and
// fail-open like the rest of the package (Extract's recover still covers a panic
// from any sub-parser).
func extractChild(data []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	if b == nil || len(data) == 0 || depth > maxNestDepth || b.spent() ||
		len(res.Streams) >= maxStreams || expired(deadline) {
		return
	}
	switch {
	case bytes.HasPrefix(data, zipMagic):
		// A zip: an Office document gets the macro path only — part-dumping its body
		// XML would scan ordinary text and invite FPs (mirror the top-level guard);
		// a plain archive gets member unpacking.
		if isOfficeZip(data) {
			// Thread the request's effort/decode/XLM-fold caps into the nested OOXML
			// (same as the PDF branch below). With nil opts the XLM-fold sheet/formula
			// caps fall back to the package MAX, so a nested .docm/.xlsm did MORE fold
			// work than a low-effort request asked for — effort could only be shed at
			// the top level, never on a carried Office doc. res.childOpts carries the
			// caps; the call's own deadline is the live budget, so it is passed
			// separately and overrides childOpts.Deadline. nil childOpts (top-level
			// Extract / tests building Result directly) keeps the prior MAX-cap
			// behaviour via the opts accessors' nil fallback.
			fromOOXML(data, res, deadline, res.childOpts)
			// Also carrier-unpack non-office sibling members of a nested Office zip
			// (spoofed-container dropper carried inside an archive/.msg). Zero
			// body-text FP — only carrier members are routed through extractChild.
			fromOfficeZipCarriers(data, res, b, depth, deadline)
		} else {
			fromArchive(data, res, b, depth, deadline)
		}
	case isArchive(data):
		fromArchive(data, res, b, depth, deadline)
	case bytes.HasPrefix(data, oleMagic):
		// OLE2: legacy macro doc, MSI, .msg, or embedded package — fromOLE covers all.
		fromOLE(data, res, b, depth, deadline)
	case isPDF(data):
		// A PDF carried inside another container (archive/.msg/RTF object). The
		// effort caps ARE now threaded via res.childOpts: a nested PDF honors the
		// same PDFDeepen / DecodeDepth / DecodeIterations caps as a top-level one.
		// Falls back to FullOptions when childOpts is unset (top-level Extract /
		// tests that build Result directly). The current call's deadline overrides
		// childOpts.Deadline so the live budget is always respected.
		{
			opts := FullOptions(deadline)
			if res.childOpts != nil {
				o := *res.childOpts
				o.Deadline = deadline
				opts = &o
			}
			fromPDF(data, res, opts)
		}
	case isRTF(data):
		fromRTF(data, res, b, depth, deadline)
	case isLNK(data):
		fromLNK(data, res)
	case isOneNote(data):
		fromOneNote(data, res, b, depth, deadline)
	default:
		// Not a recognised container — it may still be an MS Script Encoder block
		// (#@~^…^#~@) carried as a child (.vbe/.jse inside an archive/.msg). Decode
		// it so the keyword rules match; a no-op for ordinary bytes.
		fromEncodedScript(data, res, deadline)
		// It may also be an HTML/SVG part smuggling a payload (atob→Blob→download,
		// a force-downloaded base64 data: URI, or a scripted <svg>) — e.g. an .html
		// attachment delivered inside a .zip or .msg rather than as the top-level
		// part. PR #190 wired this into the top-level text path only; cover the
		// nested case here. Self-gating (emits a marker only on the dangerous combo
		// and carves a force-downloaded data: URI back through extractChild at
		// depth+1), so it is safe on arbitrary child bytes and bounded by the same
		// shared budget/deadline as every other carrier.
		fromHTMLSmuggling(data, res, b, depth, deadline)
	}
}
