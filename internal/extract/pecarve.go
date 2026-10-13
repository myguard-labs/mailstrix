package extract

// Base64-PE carving. A dropper hides a Windows PE inside a document by
// base64-encoding it into a text field (e.g. an OOXML docProps <dc:description>),
// commonly with a leading pad ("AAAA…") so that the MZ DOS header lands at a
// NON-ZERO offset of the decoded blob. The static decode pass (fromEncoded)
// decodes the base64/hex run and emits the bytes as a stream, but YARA's `pe`
// module anchors on an MZ header at offset 0, so a pad-prefixed decoded blob never
// satisfies a pe rule and the embedded executable goes entirely unscored.
//
// carveEmbeddedPEs rescans the streams the decode pass just produced for a
// STRUCTURALLY VALID PE (an MZ DOS header whose e_lfanew reaches "PE\0\0", via
// isValidPEAt) that starts past offset 0, and appends the MZ-aligned slice as a
// new stream so the pe rules see a real header at offset 0. It also emits a single
// BASE64-PE-CARVE marker so the realignment itself is scored — a full PE smuggled
// base64 inside a document body has no benign analogue.
//
// FP-safety: isValidPEAt validates THROUGH e_lfanew, so an incidental "MZ" pair in
// decoded text cannot trip it; and the carve runs ONLY over the decode-pass output
// (already-decoded payload bytes), never over raw document body. A blob already
// MZ-aligned at offset 0 is skipped (the pe module already sees it).

const (
	// b64PECarveMax bounds the carved PE children appended per document so a blob
	// crafted with many embedded MZ/PE pairs cannot blow the stream budget.
	b64PECarveMax = 8
	// b64PECarveMarker is the PURE marker emitted once when at least one
	// pad-prefixed PE is carved. Registered in pureMarkerLiterals + parityMarkers.
	b64PECarveMarker = "BASE64-PE-CARVE"
)

// carveEmbeddedPEs scans res.Streams[start:] (the streams the decode pass just
// appended) for a valid PE that begins at a non-zero offset, appends an MZ-aligned
// view of each, and — if any were carved — appends one BASE64-PE-CARVE marker.
func carveEmbeddedPEs(res *Result, start int) {
	if start < 0 || start >= len(res.Streams) {
		return
	}
	// Snapshot the decode-pass region: appends below grow res.Streams, and a carved
	// child is already MZ-aligned (offset 0) so it must not be re-scanned here.
	snap := res.Streams[start:len(res.Streams)]
	carved := 0
	for _, s := range snap {
		if carved >= b64PECarveMax || len(res.Streams) >= maxStreams {
			break
		}
		off := findPE(s, 0)
		if off <= 0 {
			// -1 == no valid PE; 0 == already MZ-aligned (pe module already sees it).
			continue
		}
		// Re-slice (no copy): s is a decoded blob owned by res.Streams and stays
		// intact for its own rules; the aligned view is read-only to the scanner.
		view := s[off:]
		res.recordRetained(view)
		res.Streams = append(res.Streams, view)
		carved++
	}
	if carved > 0 && len(res.Streams) < maxStreams {
		marker := []byte(b64PECarveMarker)
		res.recordRetained(marker)
		res.Streams = append(res.Streams, marker)
	}
}
