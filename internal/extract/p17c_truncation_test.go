package extract

import (
	"strings"
	"testing"
)

func countMarker(markers [][]byte, want string) int {
	n := 0
	for _, m := range markers {
		if string(m) == want {
			n++
		}
	}
	return n
}

func TestP17cTruncationFlagCapHitAndReservedMarker(t *testing.T) {
	const ordinary = 200
	limit := int64(retainedReserveBytes + ordinary)
	res := ExtractWithOptions(p17bZip(t, 8, 64), &Options{RetainedBytesLimit: limit, DecodeDepth: 1, DecodeIterations: 1})
	if !res.RetainedTruncated {
		t.Fatal("refused entries did not set RetainedTruncated")
	}
	n := 0
	for _, k := range res.CapHits {
		if k == "retained-bytes" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("retained-bytes cap hit count %d, caps %v", n, res.CapHits)
	}
	if c := countMarker(res.Markers, capHitMarkerPrefix+"retained-bytes"); c != 1 {
		t.Fatalf("reserved marker count %d markers %q", c, res.Markers)
	}
	if res.Panicked || res.Failed {
		t.Fatalf("truncation mapped to failure: failed=%v panicked=%v", res.Failed, res.Panicked)
	}
	if !p17bWithinBound(&res, uint64(limit)) || res.Retained.Bytes() > uint64(limit) {
		t.Fatalf("retained %d exceeds E=%d", res.Retained.Bytes(), limit)
	}
}

func TestP17cUnderLimitNotTruncated(t *testing.T) {
	res := ExtractWithOptions(p17bZip(t, 4, 64), &Options{RetainedBytesLimit: 1 << 20, DecodeDepth: 1, DecodeIterations: 1})
	if res.RetainedTruncated {
		t.Fatal("under-limit extraction flagged truncated")
	}
	for _, k := range res.CapHits {
		if k == "retained-bytes" {
			t.Fatal("retained-bytes cap hit below the ceiling")
		}
	}
	if strings.Contains(string(joinBytes(res.Markers)), capHitMarkerPrefix+"retained-bytes") {
		t.Fatal("reserve marker emitted below the ceiling")
	}
}

func joinBytes(b [][]byte) []byte {
	var out []byte
	for _, x := range b {
		out = append(out, x...)
		out = append(out, '\n')
	}
	return out
}

func TestP17cExactFitNotTruncatedAndFinalizeIdempotent(t *testing.T) {
	r, ledger := p17bLedger(10)
	r.appendStream(ptr(p17bEntry(10, 'a')))
	r.noteRetainedTruncation()
	if r.RetainedTruncated || ledger.exhausted {
		t.Fatal("exact fit flagged")
	}
	r.appendStream(ptr(p17bEntry(1, 'b'))) // real refusal
	r.noteRetainedTruncation()
	r.noteRetainedTruncation()
	if !r.RetainedTruncated || len(r.CapHits) != 1 {
		t.Fatalf("flag=%v caps=%v", r.RetainedTruncated, r.CapHits)
	}
	finalizeStreams(r, -1)
	finalizeStreams(r, -1)
	if c := countMarker(r.Markers, capHitMarkerPrefix+"retained-bytes"); c > 1 {
		t.Fatalf("repeated finalization duplicated marker: %d", c)
	}
	if ledger.snapshot().Bytes() > uint64(retainedReserveBytes+10) {
		t.Fatalf("bound exceeded %d", ledger.snapshot().Bytes())
	}
}

func TestP17cPanicExitStillFlagged(t *testing.T) {
	limit := int64(retainedReserveBytes + 32)
	withAfterFormatHook(t, func(r *Result) {
		r.appendStream(ptr(p17bEntry(32, 'k')))
		r.appendStream(ptr(p17bEntry(32, 'r')))
		panic("injected")
	})
	res := ExtractWithOptions([]byte("hello"), &Options{RetainedBytesLimit: limit})
	if !res.Panicked || !res.RetainedTruncated {
		t.Fatalf("panicked=%v truncated=%v", res.Panicked, res.RetainedTruncated)
	}
}
