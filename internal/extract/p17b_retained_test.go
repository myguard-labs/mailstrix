package extract

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"net/textproto"
	"testing"
	"time"
)

// p17bLedger returns an enforcing ledger whose ordinary capacity is exactly n.
func p17bLedger(n uint64) (*Result, *retainedBudget) {
	ledger := newRetainedBudget(int64(retainedReserveBytes + n))
	return &Result{childOpts: &Options{retained: ledger}}, ledger
}

func p17bEntry(n int, fill byte) []byte { return bytes.Repeat([]byte{fill}, n) }

// p17bWithinBound is the bound assertion the negative control must trip.
func p17bWithinBound(res *Result, limit uint64) bool {
	var total uint64
	for _, s := range res.Streams {
		total += uint64(len(s))
	}
	return total <= limit && res.Retained.Bytes() <= limit
}

func TestP17bExactFitAndOneByteExcess(t *testing.T) {
	r, ledger := p17bLedger(10)
	if !r.appendStream(ptr(p17bEntry(10, 'a'))) {
		t.Fatal("exact fit refused")
	}
	if got := ledger.snapshot().Bytes(); got != 10 || ledger.refused {
		t.Fatalf("exact fit bytes=%d exhausted=%v", got, ledger.refused)
	}
	r2, ledger2 := p17bLedger(10)
	if r2.appendStream(ptr(p17bEntry(11, 'b'))) {
		t.Fatal("one-byte excess admitted")
	}
	if len(r2.Streams) != 0 || ledger2.snapshot().Bytes() != 0 || !ledger2.refused {
		t.Fatalf("excess left state streams=%d bytes=%d exhausted=%v", len(r2.Streams), ledger2.snapshot().Bytes(), ledger2.refused)
	}
	// No refuse-everything latch (CR534): an oversized refusal must not hide a
	// later entry that still fits, so a tiny entry is admitted while the
	// refusal stays recorded for the truncation outcome.
	if !r2.appendStream(ptr(p17bEntry(1, 'c'))) || len(r2.Streams) != 1 || !ledger2.refused {
		t.Fatalf("fitting entry after a refusal streams=%d refused=%v", len(r2.Streams), ledger2.refused)
	}
}

func ptr(b []byte) *[]byte { return &b }

func TestP17bZeroAndNoOpNeverExhaust(t *testing.T) {
	r, ledger := p17bLedger(4)
	if !r.appendStream(ptr(nil)) || !r.appendStream(ptr([]byte{})) {
		t.Fatal("empty entry refused")
	}
	if ledger.refused || ledger.snapshot().Bytes() != 0 {
		t.Fatalf("empty entries exhausted=%v bytes=%d", ledger.refused, ledger.snapshot().Bytes())
	}
	if !r.appendStream(ptr(p17bEntry(4, 'x'))) {
		t.Fatal("full-size entry refused after empties")
	}
	// A zero-capacity ordinary budget still tolerates empties, refuses data.
	r0, l0 := p17bLedger(0)
	if !r0.appendStream(ptr(nil)) || l0.refused {
		t.Fatal("empty entry on zero-capacity budget exhausted it")
	}
	if r0.appendStream(ptr([]byte("y"))) || !l0.refused {
		t.Fatal("data entry on zero-capacity budget admitted")
	}
	// Limits below the reserve still saturate to zero capacity, never wrap.
	tiny := newRetainedBudget(1)
	if tiny.ordinaryCap() != 0 {
		t.Fatalf("tiny ceiling ordinary cap=%d", tiny.ordinaryCap())
	}
	// Non-positive limit selects the default, never disables enforcement.
	if def := newRetainedBudget(-5); def.limit != uint64(DefaultRetainedBytesLimit) {
		t.Fatalf("default limit=%d", def.limit)
	}
}

func TestP17bOverflowSaturatesWithoutWrapping(t *testing.T) {
	_, ledger := p17bLedger(100)
	if _, ok := ledger.admit(math.MaxUint64); ok {
		t.Fatal("MaxUint64 admission accepted")
	}
	if ledger.snapshot().Bytes() != 0 {
		t.Fatalf("refused debit recorded %d", ledger.snapshot().Bytes())
	}
	// A saturated total never underflows the ordinary-usage arithmetic.
	sat := newRetainedBudget(2048)
	sat.total = math.MaxUint64
	if _, ok := sat.admit(1); ok {
		t.Fatal("admission accepted against a saturated total")
	}
	sat.reserved = true
	if got := sat.ordinaryUsed(); got != sat.ordinaryCap() {
		t.Fatalf("saturated ordinaryUsed=%d want clamp %d", got, sat.ordinaryCap())
	}
	// The non-enforcing shadow ledger still saturates instead of refusing.
	shadow := &retainedBudget{}
	shadow.record(math.MaxUint64 - 1)
	if _, ok := shadow.admit(5); !ok || shadow.snapshot().Bytes() != math.MaxUint64 {
		t.Fatalf("shadow ledger ok=%v bytes=%d", ok, shadow.snapshot().Bytes())
	}
	var none *retainedBudget
	if _, ok := none.admit(1); ok {
		t.Fatal("nil ledger admitted")
	}
	if none.admitReserve() {
		t.Fatal("nil ledger reserve admitted")
	}
}

func TestP17bDiagnosticReserveStaysInsideCeiling(t *testing.T) {
	const limit = 1024
	ledger := newRetainedBudget(limit)
	capacity := ledger.ordinaryCap()
	if capacity != limit-retainedReserveBytes || retainedReserveBytes != uint64(len("EXTRACT-CAP-HIT kind=retained-bytes")) {
		t.Fatalf("reserve D=%d capacity=%d", retainedReserveBytes, capacity)
	}
	if _, ok := ledger.admit(capacity); !ok {
		t.Fatal("exact E-D fit refused")
	}
	if _, ok := ledger.admit(1); ok {
		t.Fatal("E-D+1 admitted")
	}
	if !ledger.admitReserve() || ledger.admitReserve() {
		t.Fatal("reserve must materialize exactly once")
	}
	if got := ledger.snapshot().Bytes(); got != limit {
		t.Fatalf("ordinary plus diagnostic=%d want exactly E=%d", got, limit)
	}
	if _, ok := ledger.admit(1); ok {
		t.Fatal("admission after reserve exceeded E")
	}
	small := newRetainedBudget(1)
	small.limit = retainedReserveBytes - 1
	if small.admitReserve() {
		t.Fatal("reserve admitted into a ceiling smaller than D")
	}
}

func TestP17bLargeBackingShortViewIsCopied(t *testing.T) {
	backing := p17bEntry(1<<20, 'q')
	view := backing[100:108]
	r, ledger := p17bLedger(8)
	if !r.appendStreamOwned(&view) {
		t.Fatal("short view refused")
	}
	if got := ledger.snapshot().Bytes(); got != 8 {
		t.Fatalf("debit=%d want 8, never the backing length", got)
	}
	got := r.Streams[0]
	if cap(got) != 8 || len(got) != 8 {
		t.Fatalf("accepted array len=%d cap=%d, backing still pinned", len(got), cap(got))
	}
	backing[100] = 'Z'
	if got[0] != 'q' {
		t.Fatal("accepted array aliases the unknown backing")
	}
	if &view[0] != &got[0] {
		t.Fatal("caller pointer was not updated to the accepted array")
	}
}

func TestP17bKnownAdmittedViewIsReusedNotCopied(t *testing.T) {
	r, ledger := p17bLedger(64)
	parent := p17bEntry(16, 'p')
	view := parent[4:]
	if !r.appendStream(&view) {
		t.Fatal("known view refused")
	}
	if &r.Streams[0][0] != &parent[4] {
		t.Fatal("known admitted view was copied")
	}
	if ledger.snapshot().Bytes() != 12 {
		t.Fatalf("view debit=%d", ledger.snapshot().Bytes())
	}
}

func TestP17bRefusedEntryExposesNoPrefixOrAlias(t *testing.T) {
	r, _ := p17bLedger(8)
	big := []byte("0123456789ABCDEF")
	original := append([]byte(nil), big...)
	p := big
	if r.appendStreamOwned(&p) {
		t.Fatal("oversized entry admitted")
	}
	if len(r.Streams) != 0 {
		t.Fatalf("refused entry exposed %q", r.Streams)
	}
	if !bytes.Equal(p, original) || &p[0] != &big[0] {
		t.Fatal("refusal rewrote the caller's slice")
	}
	var out [][]byte
	if r.appendOut(&out, &p, true) || len(out) != 0 {
		t.Fatal("refused entry reached a local output slice")
	}
}

func TestP17bBatchHasPerEntryOutcomes(t *testing.T) {
	r, ledger := p17bLedger(10)
	entries := [][]byte{[]byte("abc"), p17bEntry(100, 'x'), nil, []byte("de")}
	r.appendStreams(entries, false)
	// The oversized entry is refused on its own; "de" still fits after it
	// (CR534 removed the latch that used to refuse every later entry).
	if len(r.Streams) != 3 || string(r.Streams[0]) != "abc" || len(r.Streams[1]) != 0 || string(r.Streams[2]) != "de" {
		t.Fatalf("batch outcomes %q", r.Streams)
	}
	if ledger.snapshot().Bytes() != 5 || !ledger.refused {
		t.Fatalf("batch bytes=%d exhausted=%v", ledger.snapshot().Bytes(), ledger.refused)
	}
}

func TestP17bNoLedgerResultStaysNonEnforcing(t *testing.T) {
	var nilRes *Result
	data := p17bEntry(64, 'n')
	if _, ok := nilRes.admitStream(&data, true); !ok {
		t.Fatal("nil result refused")
	}
	direct := &Result{}
	if !direct.appendStream(&data) || len(direct.Streams) != 1 {
		t.Fatal("direct Result lost its stream")
	}
	if !direct.appendStreamOwned(&data) || !direct.appendOut(&direct.Streams, &data, false) {
		t.Fatal("direct Result refused")
	}
	unledgered := &Result{childOpts: &Options{}}
	if !unledgered.appendStream(&data) {
		t.Fatal("result with nil ledger refused")
	}
}

func p17bZip(t *testing.T, members int, size int) []byte {
	names := make([]string, members)
	bodies := make([][]byte, members)
	for i := range names {
		names[i] = fmt.Sprintf("m%02d.txt", i)
		bodies[i] = []byte(fmt.Sprintf("member-%02d:", i) + string(p17bEntry(size-10, byte('a'+i%26))))
	}
	return zipOfMembers(t, names, bodies)
}

func TestP17bExtractionRespectsCeilingEndToEnd(t *testing.T) {
	const ordinary = 200
	limit := int64(retainedReserveBytes + ordinary)
	res := ExtractWithOptions(p17bZip(t, 8, 64), &Options{RetainedBytesLimit: limit, DecodeDepth: 1, DecodeIterations: 1})
	if len(res.Streams) == 0 {
		t.Fatal("no stream admitted below the ceiling")
	}
	if !p17bWithinBound(&res, uint64(limit)) {
		t.Fatalf("retained %d (ordinary %d) exceeds E=%d", res.Retained.Bytes(), ordinaryDebit(&res), limit)
	}
	if res.Retained.Bytes() > ordinary+retainedReserveBytes || ordinaryDebit(&res) > ordinary {
		t.Fatalf("ordinary debit %d exceeds E-D=%d", ordinaryDebit(&res), ordinary)
	}
	// Whole members only: every admitted stream is a complete original member.
	for _, s := range res.Streams {
		if len(s) != 64 || !bytes.HasPrefix(s, []byte("member-")) {
			t.Fatalf("partial or foreign stream %q", s)
		}
	}
	if len(res.Streams) != 3 {
		t.Fatalf("expected the first three 64-byte members, got %d", len(res.Streams))
	}
}

func TestP17bExtractionUnderCeilingIsUnchanged(t *testing.T) {
	zipped := p17bZip(t, 4, 64)
	small := ExtractWithOptions(zipped, &Options{RetainedBytesLimit: 1 << 20, DecodeDepth: 1, DecodeIterations: 1})
	def := ExtractWithOptions(zipped, FullOptions(time.Time{}))
	if len(small.Streams) < 4 || len(small.Streams) != len(def.Streams) {
		t.Fatalf("under-limit streams small=%d default=%d", len(small.Streams), len(def.Streams))
	}
	for i := range small.Streams {
		if !bytes.Equal(small.Streams[i], def.Streams[i]) {
			t.Fatalf("stream %d differs under a larger ceiling", i)
		}
	}
}

// Negative control: the accept-all primitive (the P16 record path) passes the
// same fixture with a total above E, so the bound assertion rejects it.
func TestP17bControlAcceptAllExceedsBound(t *testing.T) {
	const ordinary = 200
	limit := retainedReserveBytes + ordinary
	ledger := newRetainedBudget(int64(limit))
	res := &Result{childOpts: &Options{retained: ledger}}
	for i := 0; i < 8; i++ {
		entry := p17bEntry(64, 'c')
		ledger.record(uint64(len(entry))) // accept-all, as in P16
		res.Streams = append(res.Streams, entry)
	}
	res.Retained = ledger.snapshot()
	if p17bWithinBound(res, limit) {
		t.Fatal("bound assertion failed to detect an accept-all overrun")
	}
}

func TestP17bMIMEAttachmentSharesOneOwnedArray(t *testing.T) {
	payload := p17bEntry(40, 'm')
	h := p16fHeader("application/octet-stream; name=a.bin", "", "attachment; filename=a.bin")

	r, ledger := p17bLedger(64)
	walkMIMEEntity(h, bytes.NewReader(payload), r, &archiveBudget{}, 0, time.Time{}, new(int), true)
	if len(r.Streams) != 1 || len(r.MIMEAttachments) != 1 || !p16fSameSlice(r.Streams[0], r.MIMEAttachments[0]) {
		t.Fatalf("alias lost streams=%d attachments=%d", len(r.Streams), len(r.MIMEAttachments))
	}
	if cap(r.Streams[0]) != len(payload) || ledger.snapshot().Bytes() != 40 || ledger.admissions != 1 {
		t.Fatalf("accepted array cap=%d bytes=%d admissions=%d", cap(r.Streams[0]), ledger.snapshot().Bytes(), ledger.admissions)
	}

	// One byte over E-D: the file is never published as a complete identity.
	r2, l2 := p17bLedger(39)
	walkMIMEEntity(h, bytes.NewReader(payload), r2, &archiveBudget{}, 0, time.Time{}, new(int), true)
	if len(r2.Streams) != 0 || len(r2.MIMEAttachments) != 0 || l2.snapshot().Bytes() != 0 || !l2.refused {
		t.Fatalf("refused attachment leaked streams=%d attachments=%d bytes=%d", len(r2.Streams), len(r2.MIMEAttachments), l2.snapshot().Bytes())
	}

	// A nonattachment part is debited exactly once on the stream path.
	plain := textproto.MIMEHeader{}
	plain.Set("Content-Type", "text/plain")
	r3, l3 := p17bLedger(40)
	walkMIMEEntity(plain, bytes.NewReader(payload), r3, &archiveBudget{}, 0, time.Time{}, new(int), true)
	if len(r3.Streams) != 1 || len(r3.MIMEAttachments) != 0 || l3.snapshot().Bytes() != 40 {
		t.Fatalf("plain part streams=%d bytes=%d", len(r3.Streams), l3.snapshot().Bytes())
	}
	r4, l4 := p17bLedger(39)
	walkMIMEEntity(plain, bytes.NewReader(payload), r4, &archiveBudget{}, 0, time.Time{}, new(int), true)
	if len(r4.Streams) != 0 || l4.snapshot().Bytes() != 0 {
		t.Fatalf("refused plain part leaked streams=%d bytes=%d", len(r4.Streams), l4.snapshot().Bytes())
	}
}

func TestP17bRetainedOnlyWrapperConsumesOrdinarySpace(t *testing.T) {
	inner := p16fMessage("text/plain", []byte("inner body text"))
	h := p16fHeader("message/rfc822", "", "attachment; filename=m.eml")

	r, ledger := p17bLedger(uint64(len(inner)))
	walkMIMEEntity(h, bytes.NewReader(inner), r, &archiveBudget{}, 0, time.Time{}, new(int), true)
	if len(r.MIMEAttachments) != 1 || ledger.snapshot().Bytes() < uint64(len(inner)) {
		t.Fatalf("wrapper attachments=%d bytes=%d", len(r.MIMEAttachments), ledger.snapshot().Bytes())
	}
	if ledger.snapshot().Bytes() > ledger.ordinaryCap() {
		t.Fatalf("wrapper plus descendants %d exceed E-D %d", ledger.snapshot().Bytes(), ledger.ordinaryCap())
	}

	r2, l2 := p17bLedger(uint64(len(inner)) - 1)
	walkMIMEEntity(h, bytes.NewReader(inner), r2, &archiveBudget{}, 0, time.Time{}, new(int), true)
	if len(r2.MIMEAttachments) != 0 || len(r2.Streams) != 0 || l2.snapshot().Bytes() != 0 {
		t.Fatalf("refused wrapper leaked attachments=%d streams=%d bytes=%d", len(r2.MIMEAttachments), len(r2.Streams), l2.snapshot().Bytes())
	}
}

func TestP17bPanicExitKeepsAcceptedAndStaysBounded(t *testing.T) {
	const ordinary = 32
	limit := int64(retainedReserveBytes + ordinary)
	accepted := p17bEntry(ordinary, 'k')
	refused := p17bEntry(ordinary, 'r')
	withAfterFormatHook(t, func(r *Result) {
		r.appendStream(ptr(append([]byte(nil), accepted...)))
		r.appendStream(ptr(refused)) // does not fit; must be dropped, not truncated
		panic("injected after admission")
	})
	res := ExtractWithOptions([]byte("hello"), &Options{RetainedBytesLimit: limit})
	if !res.Panicked {
		t.Fatal("panic not recorded")
	}
	if !hasStream(res.Streams, accepted) || hasStream(res.Streams, refused) {
		t.Fatalf("streams after panic %q", res.Streams)
	}
	if !p17bWithinBound(&res, uint64(limit)) || ordinaryDebit(&res) != ordinary {
		t.Fatalf("panic exit retained=%d ordinary=%d E=%d", res.Retained.Bytes(), ordinaryDebit(&res), limit)
	}
}

func p17bHTMLRun(in string, ordinary uint64) (*Result, *retainedBudget) {
	r, ledger := p17bLedger(ordinary)
	r.childOpts = &Options{retained: ledger, DecodeDepth: 1, DecodeIterations: 1}
	fromHTMLSmuggling([]byte(in), r, &archiveBudget{}, 0, time.Time{})
	return r, ledger
}

func TestP17bHTMLCarvedBlobAdmission(t *testing.T) {
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x41}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><image href="data:application/octet-stream;base64,` + b64 + `"/></svg>`
	link := `<a download="x.zip" href="data:application/octet-stream;base64,` + b64 + `">get</a>`
	for name, in := range map[string]string{"svg": svg, "datauri": link} {
		// Roomy ceiling: the blob is carved as one whole accepted entry.
		r, ledger := p17bHTMLRun(in, 4096)
		var carved []byte
		for _, s := range r.Streams {
			if bytes.HasPrefix(s, []byte("PK\x03\x04")) {
				carved = s
			}
		}
		if !bytes.Equal(carved, payload) || cap(carved) != len(payload) {
			t.Fatalf("%s: carved blob len=%d cap=%d", name, len(carved), cap(carved))
		}
		if ledger.snapshot().Bytes() > ledger.ordinaryCap() {
			t.Fatalf("%s: retained %d over E-D", name, ledger.snapshot().Bytes())
		}
		// Ceiling smaller than the blob: no prefix, no stream, still bounded.
		r2, l2 := p17bHTMLRun(in, uint64(len(payload)-1))
		for _, s := range r2.Streams {
			if bytes.HasPrefix(s, []byte("PK")) {
				t.Fatalf("%s: refused blob exposed %q", name, s)
			}
		}
		if l2.snapshot().Bytes() > l2.ordinaryCap() {
			t.Fatalf("%s: refused run retained %d", name, l2.snapshot().Bytes())
		}
		// Streams already full: the blob is neither debited nor appended.
		r3, l3 := p17bLedger(4096)
		for i := 0; i < maxStreams; i++ {
			r3.Streams = append(r3.Streams, nil)
		}
		fromHTMLSmuggling([]byte(in), r3, &archiveBudget{}, 0, time.Time{})
		if l3.snapshot().Bytes() != 0 || len(r3.Streams) != maxStreams {
			t.Fatalf("%s: full Streams debited %d / grew to %d", name, l3.snapshot().Bytes(), len(r3.Streams))
		}
	}
}

func TestP17bReleaseRestoresUnpublishedDebit(t *testing.T) {
	r, ledger := p17bLedger(100)
	data := p17bEntry(30, 'u')
	if _, ok := r.admitStream(&data, true); !ok {
		t.Fatal("admission refused")
	}
	r.releaseRetained(data)
	if ledger.snapshot().Bytes() != 0 {
		t.Fatalf("release left %d bytes", ledger.snapshot().Bytes())
	}
	r.releaseRetained(data) // over-release saturates at zero, never wraps
	if ledger.snapshot().Bytes() != 0 {
		t.Fatalf("over-release wrapped to %d", ledger.snapshot().Bytes())
	}
	var none *retainedBudget
	none.release(5)
	(*Result)(nil).releaseRetained(data)
	(&Result{}).releaseRetained(data)
}

func TestP17bHTMLUnpublishedBlobIsReleased(t *testing.T) {
	member := p17bEntry(64, 'z')
	zipped := buildZip(t, map[string][]byte{"in.txt": member})
	b64 := base64.StdEncoding.EncodeToString(zipped)
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><image href="data:application/octet-stream;base64,` + b64 + `"/></svg>`
	link := `<a download="x.zip" href="data:application/octet-stream;base64,` + b64 + `">get</a>`
	for name, in := range map[string]string{"svg": svg, "datauri": link} {
		r, ledger := p17bLedger(1 << 16)
		r.childOpts = &Options{retained: ledger, DecodeDepth: 1, DecodeIterations: 1}
		// Two free slots: the marker takes one, the child member the other,
		// so the decoded zip itself is never published.
		for i := 0; i < maxStreams-2; i++ {
			r.Streams = append(r.Streams, nil)
		}
		fromHTMLSmuggling([]byte(in), r, &archiveBudget{}, 0, time.Time{})
		var retained uint64
		for _, s := range r.Streams {
			retained += uint64(len(s))
		}
		if len(r.Streams) != maxStreams || ledger.snapshot().Bytes() != retained {
			t.Fatalf("%s: streams=%d ledger=%d published=%d", name, len(r.Streams), ledger.snapshot().Bytes(), retained)
		}
	}
}

// ordinaryDebit is the logical debit excluding the single reserved marker.
func ordinaryDebit(res *Result) uint64 {
	d := res.Retained.Bytes()
	if res.RetainedTruncated && d >= retainedReserveBytes {
		d -= retainedReserveBytes
	}
	return d
}
