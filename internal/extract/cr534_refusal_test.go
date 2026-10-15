package extract

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

// CR534: one refused oversized entry must not latch the ledger shut. The
// refusal still flags truncation, but every later entry that fits the
// remaining ordinary capacity E-D-used is admitted, so a decoy member larger
// than the budget cannot hide a small malicious sibling.

// TestCR534DecoyDoesNotHideLaterSibling is the named negative-control test:
// restoring the refuse-everything-after latch in retainedBudget.admit makes it
// fail on the sibling admission.
func TestCR534DecoyDoesNotHideLaterSibling(t *testing.T) {
	r, ledger := p17bLedger(100)
	if r.appendStream(ptr(p17bEntry(101, 'D'))) {
		t.Fatal("decoy larger than the remaining budget was admitted")
	}
	sibling := []byte("SIBLING-AFTER-DECOY")
	if !r.appendStream(ptr(sibling)) {
		t.Fatal("sibling that fits was refused after an oversized decoy (refusal latched)")
	}
	if len(r.Streams) != 1 || !bytes.Equal(r.Streams[0], sibling) {
		t.Fatalf("streams=%q, want only the sibling", r.Streams)
	}
	if !ledger.refused || ledger.snapshot().Bytes() != uint64(len(sibling)) {
		t.Fatalf("refused=%v bytes=%d", ledger.refused, ledger.snapshot().Bytes())
	}
	// The refusal still produces the once-only truncation outcome.
	r.noteRetainedTruncation()
	r.noteRetainedTruncation()
	if !r.RetainedTruncated || len(r.CapHits) != 1 || r.CapHits[0] != retainedBytesKind {
		t.Fatalf("truncated=%v caps=%v", r.RetainedTruncated, r.CapHits)
	}
}

// TestCR534DecoyMemberDoesNotHideArchiveSibling drives the same order through
// the archive member emitter: the decoy is neither published nor charged to
// the nested-carrier budget, the later sibling is.
func TestCR534DecoyMemberDoesNotHideArchiveSibling(t *testing.T) {
	r, _ := p17bLedger(64)
	bud := &archiveBudget{}
	emitMember(p17bEntry(65, 'D'), r, bud, 0, time.Time{})
	if len(r.Streams) != 0 || bud.members != 0 || bud.total != 0 {
		t.Fatalf("decoy published=%d members=%d total=%d", len(r.Streams), bud.members, bud.total)
	}
	emitMember([]byte("small sibling member"), r, bud, 0, time.Time{})
	if len(r.Streams) != 1 || string(r.Streams[0]) != "small sibling member" || bud.members != 1 {
		t.Fatalf("sibling streams=%q members=%d", r.Streams, bud.members)
	}
}

// TestCR534BoundaryAfterRefusal pins the fit boundary once a refusal has
// happened: remaining R admits exactly R and R-1, and refuses R+1.
func TestCR534BoundaryAfterRefusal(t *testing.T) {
	const capacity, used = 50, 20
	const remaining = capacity - used
	cases := []struct {
		name  string
		size  int
		admit bool
		bytes uint64
	}{
		{"exact fit", remaining, true, capacity},
		{"fits by one byte", remaining - 1, true, capacity - 1},
		{"exceeds by one byte", remaining + 1, false, used},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ledger := p17bLedger(capacity)
			if !r.appendStream(ptr(p17bEntry(used, 'u'))) {
				t.Fatal("prefix refused")
			}
			if r.appendStream(ptr(p17bEntry(capacity, 'D'))) {
				t.Fatal("decoy admitted")
			}
			if got := r.appendStream(ptr(p17bEntry(tc.size, 's'))); got != tc.admit {
				t.Fatalf("admit(%d) after refusal = %v, want %v", tc.size, got, tc.admit)
			}
			if ledger.snapshot().Bytes() != tc.bytes || !ledger.refused {
				t.Fatalf("bytes=%d refused=%v", ledger.snapshot().Bytes(), ledger.refused)
			}
		})
	}
	// Zero-size entries stay no-ops after a refusal.
	r, ledger := p17bLedger(1)
	r.appendStream(ptr(p17bEntry(2, 'D')))
	if !r.appendStream(ptr(nil)) || ledger.snapshot().Bytes() != 0 {
		t.Fatal("empty entry after refusal was refused or debited")
	}
}

// TestCR534ManyRefusalsNeverExceedCeiling interleaves refusals and admissions
// and checks every step against an independent greedy model, the request
// ceiling E, and the reserve materialized at the end.
func TestCR534ManyRefusalsNeverExceedCeiling(t *testing.T) {
	const capacity = 997
	r, ledger := p17bLedger(capacity)
	limit := ledger.limit
	var model uint64
	refusals, admissions := 0, 0
	seed := uint32(2463534242)
	for i := 0; i < 2000; i++ {
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5
		size := int(seed % 300)
		want := size == 0 || uint64(size) <= capacity-model
		got := r.appendStream(ptr(p17bEntry(size, 'x')))
		if got != want {
			t.Fatalf("step %d size %d: admitted=%v model=%v (used=%d)", i, size, got, want, model)
		}
		if got {
			model += uint64(size)
			admissions++
		} else {
			refusals++
		}
		if ledger.snapshot().Bytes() != model || model > capacity {
			t.Fatalf("step %d: ledger=%d model=%d", i, ledger.snapshot().Bytes(), model)
		}
		if !p17bWithinBound(r, limit) {
			t.Fatalf("step %d: output exceeds E=%d", i, limit)
		}
	}
	if refusals == 0 || admissions == 0 {
		t.Fatalf("sweep did not mix outcomes: refusals=%d admissions=%d", refusals, admissions)
	}
	if !ledger.admitReserve() || ledger.snapshot().Bytes() > limit {
		t.Fatalf("reserve after many refusals: bytes=%d limit=%d", ledger.snapshot().Bytes(), limit)
	}
	// Post-reserve ordinary admissions still respect E-D.
	for size := 1; size <= int(capacity); size++ {
		r.appendStream(ptr(p17bEntry(size, 'y')))
		if ledger.snapshot().Bytes() > limit {
			t.Fatalf("post-reserve size %d pushed bytes=%d past E=%d", size, ledger.snapshot().Bytes(), limit)
		}
	}
}

// cr534ZipCarrier returns a zip carrier whose only member is inner, so a
// cracked carrier publishes inner as a derived stream.
func cr534ZipCarrier(t *testing.T, inner []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "inner.txt", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(inner); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func cr534HasStream(streams [][]byte, want []byte) bool {
	for _, s := range streams {
		if bytes.Equal(s, want) {
			return true
		}
	}
	return false
}

// TestCR534RefusedCarrierPayloadIsNotCracked covers fromMSG and fromOLEPackage:
// a refused attachment/package payload is neither charged to the nested-carrier
// budget nor recursed, so its smaller derived member cannot slip in after the
// parent was refused. The positive leg shows the same fixture is cracked when
// it fits, so the negative leg is not vacuous.
func TestCR534RefusedCarrierPayloadIsNotCracked(t *testing.T) {
	inner := []byte("CR534-INNER-DERIVED-MEMBER")
	carrier := cr534ZipCarrier(t, inner)
	msgBuf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "__properties_version1.0", mse: 2, data: []byte("props")},
		{name: "__attach_version1.0_#00000000", mse: 1},
		{name: "__substg1.0_3701000D", mse: 2, data: carrier},
	})
	pkgBuf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "\x01Ole10Native", mse: 2, data: buildOle10Native("x", "x", "x", carrier, 0)},
	})
	// buildCFB pads a stream to its sector, so the published MSG attachment is
	// the padded stream view; the package payload is the carved NativeData.
	msgPayload := 0
	for _, d := range parseP16bOLE(t, msgBuf).Directory {
		if d != nil && d.Name == "__substg1.0_3701000D" {
			msgPayload = int(d.Header.Size)
		}
	}
	if msgPayload < len(carrier) {
		t.Fatalf("msg attachment stream size %d < carrier %d", msgPayload, len(carrier))
	}
	fixtures := []struct {
		name    string
		payload int
		run     func(t *testing.T, res *Result, bud *archiveBudget)
	}{
		{"msg", msgPayload, func(t *testing.T, res *Result, bud *archiveBudget) {
			if !fromMSG(parseP16bOLE(t, msgBuf), res, bud, 0, time.Time{}) {
				t.Fatal("MSG fixture not recognized")
			}
		}},
		{"ole_package", len(carrier), func(t *testing.T, res *Result, bud *archiveBudget) {
			if !fromOLEPackage(parseP16bOLE(t, pkgBuf), res, bud, 0, time.Time{}) {
				t.Fatal("package fixture not recognized")
			}
		}},
	}
	for _, fx := range fixtures {
		t.Run(fx.name+"/fits", func(t *testing.T) {
			res, _ := p17bLedger(uint64(fx.payload + len(inner)))
			bud := &archiveBudget{}
			fx.run(t, res, bud)
			if len(res.Streams) == 0 || !bytes.HasPrefix(res.Streams[0], carrier) || !cr534HasStream(res.Streams, inner) || bud.members == 0 {
				t.Fatalf("admitted carrier not cracked: streams=%d members=%d", len(res.Streams), bud.members)
			}
			if fx.name == "ole_package" && !res.IsOLEPackage {
				t.Fatal("admitted package payload did not set IsOLEPackage")
			}
		})
		t.Run(fx.name+"/refused", func(t *testing.T) {
			// Room for the derived member but not for the carrier payload itself.
			res, ledger := p17bLedger(uint64(fx.payload - 1))
			bud := &archiveBudget{}
			fx.run(t, res, bud)
			if len(res.Streams) != 0 || !ledger.refused {
				t.Fatalf("refused carrier leaked streams=%d refused=%v", len(res.Streams), ledger.refused)
			}
			if bud.members != 0 || bud.total != 0 {
				t.Fatalf("refused carrier charged the nested budget: members=%d total=%d", bud.members, bud.total)
			}
			if res.IsOLEPackage {
				t.Fatal("refused package payload set IsOLEPackage")
			}
		})
	}
}
