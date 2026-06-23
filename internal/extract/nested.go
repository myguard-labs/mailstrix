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
			fromOOXML(data, res, deadline, nil)
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
		// effort caps aren't threaded through the nested-carrier chain (sink-only
		// EFFORT-4 scope); a nested PDF is rare and already deep in a carrier, so
		// run it at full PDF-deepen depth — the more-detection default. The shared
		// deadline still bounds it.
		fromPDF(data, res, FullOptions(deadline))
	case isRTF(data):
		fromRTF(data, res, b, depth, deadline)
	case isLNK(data):
		fromLNK(data, res)
	case isOneNote(data):
		fromOneNote(data, res, deadline)
	default:
		// Not a recognised container — it may still be an MS Script Encoder block
		// (#@~^…^#~@) carried as a child (.vbe/.jse inside an archive/.msg). Decode
		// it so the keyword rules match; a no-op for ordinary bytes.
		fromEncodedScript(data, res, deadline)
	}
}
