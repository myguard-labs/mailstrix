package extract

import (
	"bytes"
	"math/rand"
	"testing"
)

// p19Pad returns deterministic, only mildly compressible filler (26-letter
// alphabet) so zip/zlib layers keep
// a stable size and every level's retained bytes are predictable.
func p19Pad(seed int64, n int) []byte {
	b := make([]byte, n)
	// math/rand with a fixed seed is deliberate: reproducible fixture bytes,
	// no security use.
	r := rand.New(rand.NewSource(seed))
	for i := range b { // printable, so no binary-only paths change
		b[i] = byte('a' + r.Intn(26))
	}
	return b
}

// p19Chain builds the reachable composition archive -> TNEF -> ZIP(PDF, TNEF).
// PDF does not recurse into TNEF (pdf.go never calls extractChild), so the
// reachable shape nests the PDF and the second TNEF as siblings under the
// TNEF-carried ZIP. The TNEF leaf member precedes the PDF in the ZIP because
// extractChild tests isPDF (magic anywhere in the first 1 KiB) before isTNEF: a
// PDF member stored in the first KiB of the TNEF-carried bytes would hijack the
// dispatch. Every layer stays far below its own per-format cap.
func p19Chain(t *testing.T, leafMarker string) []byte {
	t.Helper()
	const pad = 3000
	pdf := pdfWithStream(zlibDeflate(append([]byte("/JavaScript (p19-pdf) "), p19Pad(1, pad)...)))
	leaf := buildTNEF(append([]byte(leafMarker), p19Pad(2, pad)...))
	inner := zipOfMembers(t, []string{"inner.dat", "doc.pdf"}, [][]byte{leaf, pdf})
	mid := buildTNEF(inner)
	return zipOfMembers(t, []string{"winmail.dat"}, [][]byte{mid})
}

func p19Has(res *Result, needle string) bool { return streamsContain(*res, needle) }

// p19Unwrapped reports whether the leaf TNEF's attachment was carved: a stream
// that STARTS with the marker. The raw leaf TNEF also contains the marker, so
// a substring test cannot tell the two apart.
func p19Unwrapped(res *Result, marker string) bool {
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte(marker)) {
			return true
		}
	}
	return false
}

// TestP19GlobalBudgetStopsReachableChain asserts the shared request ledger
// stops archive->TNEF->ZIP(PDF,TNEF) where each format's own total (maxTotalTNEF,
// per-archive and PDF caps) would have admitted the whole chain.
func TestP19GlobalBudgetStopsReachableChain(t *testing.T) {
	const leaf = "P19-LEAF-MARKER"
	chain := p19Chain(t, leaf)
	opts := func(limit int64) *Options {
		return &Options{RetainedBytesLimit: limit, DecodeDepth: 1, DecodeIterations: 1}
	}

	// Independent per-format totals only: a roomy request ceiling.
	free := ExtractWithOptions(chain, opts(1<<30))
	if len(free.CapHits) != 0 || free.RetainedTruncated || !p19Unwrapped(&free, leaf) || !p19Has(&free, "p19-pdf") {
		t.Fatalf("roomy run must reach the whole chain: capHits=%v truncated=%v leaf=%v pdf=%v",
			free.CapHits, free.RetainedTruncated, p19Unwrapped(&free, leaf), p19Has(&free, "p19-pdf"))
	}
	if free.Retained.Bytes() < 12000 {
		t.Fatalf("chain retained only %d bytes; fixture too small", free.Retained.Bytes())
	}

	// Global ceiling well under the chain total, yet above every single layer's
	// size and far under every per-format cap: only the shared ledger can stop it.
	limit := int64(retainedReserveBytes) + int64(free.Retained.Bytes())/2
	cut := ExtractWithOptions(chain, opts(limit))
	if !cut.RetainedTruncated {
		t.Fatal("global budget did not truncate the chain")
	}
	if cut.Retained.Bytes() > uint64(limit) || !p17bWithinBound(&cut, uint64(limit)) {
		t.Fatalf("retained %d exceeds E=%d", cut.Retained.Bytes(), limit)
	}
	if p19Unwrapped(&cut, leaf) || p19Has(&cut, "p19-pdf") {
		t.Fatal("chain content below the first layers emitted past the global budget")
	}
	if cut.Failed || cut.Panicked {
		t.Fatalf("truncation mapped to failure: failed=%v panicked=%v", cut.Failed, cut.Panicked)
	}
	if countMarker(cut.Markers, capHitMarkerPrefix+"retained-bytes") != 1 {
		t.Fatalf("expected one retained-bytes marker, got %q", cut.Markers)
	}
}
