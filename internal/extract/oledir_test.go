package extract

import (
	"bytes"
	"testing"
	"time"
)

const cfbFree = 0xFFFFFFFF

// TestOLEOrphanCarved: an allocated stream that is NOT reachable from the root
// red-black tree (no sib/child points at it) is carved and surfaced, while a
// genuinely reachable stream is NOT re-emitted by the orphan path.
func TestOLEOrphanCarved(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "Reachable", mse: 2, data: []byte("REACHABLE-DATA marker"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
		{name: "Orphan", mse: 2, data: []byte("ORPHAN-SECRET payload"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})

	var res Result
	streamHas := func(needle string) bool {
		for _, s := range res.Streams {
			if bytes.Contains(s, []byte(needle)) {
				return true
			}
		}
		return false
	}

	res = Result{}
	fromOLEForTest(t, buf, &res)

	if !streamHas("ORPHAN-SECRET") {
		t.Errorf("orphan stream not carved; streams=%d", len(res.Streams))
	}
	if streamHas("REACHABLE-DATA") {
		t.Errorf("reachable stream must NOT be carved by the orphan path")
	}
}

// TestOLENoOrphanWhenAllReachable: when every stream is linked into the tree,
// nothing is carved.
func TestOLENoOrphanWhenAllReachable(t *testing.T) {
	// Root.child=1; entry1.right=2 → both reachable as siblings.
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "S1", mse: 2, data: []byte("S1-DATA reachable"),
			left: cfbFree, right: 2, child: cfbFree, linksSet: true},
		{name: "S2", mse: 2, data: []byte("S2-DATA reachable"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	var res Result
	fromOLEForTest(t, buf, &res)
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("S1-DATA")) || bytes.Contains(s, []byte("S2-DATA")) {
			t.Fatalf("reachable stream carved as orphan: %q", s)
		}
	}
}

// TestOLEOrphanCapped: more than maxOLEOrphans unreferenced streams → carving
// stops at the cap (no unbounded fan-out).
func TestOLEOrphanCapped(t *testing.T) {
	entries := []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "Reachable", mse: 2, data: []byte("anchor"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	}
	const nOrphans = maxOLEOrphans + 5
	for i := 0; i < nOrphans; i++ {
		entries = append(entries, cfbEntry{
			name: "Orphan", mse: 2,
			data:     []byte("ORPHANMARK-" + string(rune('A'+i)) + " payload"),
			left:     cfbFree,
			right:    cfbFree,
			child:    cfbFree,
			linksSet: true,
		})
	}
	buf := buildCFB(t, entries)
	var res Result
	fromOLEForTest(t, buf, &res)

	carved := 0
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("ORPHANMARK-")) {
			carved++
		}
	}
	if carved == 0 {
		t.Fatal("no orphans carved")
	}
	if carved > maxOLEOrphans {
		t.Fatalf("orphan carve exceeded cap: %d > %d", carved, maxOLEOrphans)
	}
}

// TestOLEOrphanDeadline: an expired deadline carves nothing and never panics.
func TestOLEOrphanDeadline(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
		{name: "Reachable", mse: 2, data: []byte("anchor"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
		{name: "Orphan", mse: 2, data: []byte("ORPHAN-SECRET payload"),
			left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
	})
	res := Extract(buf, time.Now().Add(-time.Second))
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("ORPHAN-SECRET")) {
			t.Fatal("expired deadline must not carve orphans")
		}
	}
}

// TestOLEOrphanNilSafe: nil/empty inputs fail-open without panic.
func TestOLEOrphanNilSafe(t *testing.T) {
	var res Result
	fromOLEOrphans(nil, &res, time.Time{}) // must not panic
	if len(res.Streams) != 0 {
		t.Fatalf("nil OLE produced streams: %d", len(res.Streams))
	}
}

// fromOLEForTest drives the full OLE path so fromOLEOrphans runs exactly as in
// production (it is invoked from fromOLE). We use Extract and copy the streams
// into res for the assertions above; the raw-buffer scan does not populate
// res.Streams, so a needle found there came from the extractor, not raw bytes.
func fromOLEForTest(t *testing.T, buf []byte, res *Result) {
	t.Helper()
	out := Extract(buf, time.Time{})
	if !out.IsDoc {
		t.Fatalf("fixture not recognised as a document")
	}
	*res = out
}
