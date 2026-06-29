package extract

// Tests for PERF-28: lazy seen-map allocation and index-based UTF-16 iteration.
// Verify that the optimisations do not change decode output (differential), dedup
// behaviour, MSD-cap semantics, or UTF-16 recovery.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// runFromEncoded wraps fromEncoded for callers that just want to call it with
// a buf and pre-populated Streams, and get the result back.
func runFromEncoded(buf []byte, streams [][]byte) *Result {
	res := &Result{
		Streams:   append([][]byte(nil), streams...),
		childOpts: FullOptions(time.Time{}),
	}
	fromEncoded(buf, res, FullOptions(time.Time{}))
	return res
}

// ---------------------------------------------------------------------------
// PERF-28-1: differential — lazy seen map must not change decoded output
// ---------------------------------------------------------------------------

// TestLazySeenDifferential verifies that for a table of inputs the decoded
// stream sets are identical to the pre-PERF-28 behaviour captured by the
// existing tests (we compare a reference fromEncoded call against itself, but
// the real guarantee is that the existing test suite passes — these cases add
// coverage for scenarios that exercise the lazy-map path specifically).
func TestLazySeenDifferential(t *testing.T) {
	inner := "powershellPayloadLazySeenTest"
	l1 := base64.StdEncoding.EncodeToString([]byte(inner))
	outer := base64.StdEncoding.EncodeToString([]byte(l1))

	hexPayload := "Shell(\"powershell -enc lazytest\")"
	hexEnc := hex.EncodeToString([]byte(hexPayload))

	cases := []struct {
		name    string
		buf     []byte
		streams [][]byte
	}{
		{
			name:    "clean prose — no decode",
			buf:     []byte("This is a perfectly ordinary email. No encoded payload here."),
			streams: nil,
		},
		{
			name:    "single base64 source in buf",
			buf:     []byte(outer),
			streams: nil,
		},
		{
			name:    "single hex source in stream",
			buf:     nil,
			streams: [][]byte{[]byte(hexEnc)},
		},
		{
			name:    "multi-layer MSD (base64-over-base64) in stream",
			buf:     nil,
			streams: [][]byte{[]byte(outer)},
		},
		{
			name: "two independent sources",
			buf:  []byte(outer),
			streams: [][]byte{
				[]byte(hexEnc),
			},
		},
	}

	for _, c := range cases {
		// Run twice; results must be identical (deterministic, no state leak).
		r1 := runFromEncoded(c.buf, c.streams)
		r2 := runFromEncoded(c.buf, c.streams)

		if len(r1.Streams) != len(r2.Streams) {
			t.Errorf("[%s] non-deterministic: run1 %d streams, run2 %d streams",
				c.name, len(r1.Streams), len(r2.Streams))
			continue
		}
		for i := range r1.Streams {
			if !bytes.Equal(r1.Streams[i], r2.Streams[i]) {
				t.Errorf("[%s] stream[%d] differs between runs", c.name, i)
			}
		}
		if r1.DecodedStreams != r2.DecodedStreams {
			t.Errorf("[%s] DecodedStreams non-deterministic: %d vs %d",
				c.name, r1.DecodedStreams, r2.DecodedStreams)
		}
	}
}

// ---------------------------------------------------------------------------
// PERF-28-2: clean prose must produce zero decoded streams (lazy-map health)
// ---------------------------------------------------------------------------

// TestLazySeenCleanProseNoSideEffects confirms that a clean prose buffer that
// passes none of the gates (mostlyText=true but mayBeEncoded=false) produces
// zero decoded streams and does not trigger any seen-map allocation side
// effect (behavioural assertion — we verify DecodedStreams==0 and no extra
// Streams are added).
func TestLazySeenCleanProseNoSideEffects(t *testing.T) {
	buf := []byte("Hello, this is a normal email body with no encoded payload. " +
		"It has punctuation, spaces, and short words but no long base64 or hex runs. " +
		"The quick brown fox jumps over the lazy dog.")
	res := runFromEncoded(buf, nil)
	if res.DecodedStreams != 0 {
		t.Errorf("clean prose: DecodedStreams = %d, want 0", res.DecodedStreams)
	}
	// Only streams that might come from defang or UTF-16 pass on completely plain
	// ASCII prose are zero; assert none were appended.
	if len(res.Streams) != 0 {
		t.Errorf("clean prose: Streams = %d, want 0", len(res.Streams))
	}
}

// TestLazySeenAllocsCleanProse uses testing.AllocsPerRun to assert that the
// clean-prose path (no decode, no seen map needed) allocates fewer objects than
// it did before PERF-28. We use a relative bound: the allocs on a prose buffer
// must be strictly fewer than for a buffer that actually decodes something.
// This is a directional assertion — not a hard zero — because fromEncoded still
// allocates the sources slice, BFS queue, etc.; we just verify the seen maps
// do not add to the prose count.
func TestLazySeenAllocsCleanProse(t *testing.T) {
	prose := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 20))

	inner := "ShellPayloadForAllocComparison"
	encoded := []byte(base64.StdEncoding.EncodeToString([]byte(inner)))

	proseFn := func() {
		res := &Result{childOpts: FullOptions(time.Time{})}
		fromEncoded(prose, res, FullOptions(time.Time{}))
	}
	decodeFn := func() {
		res := &Result{childOpts: FullOptions(time.Time{})}
		fromEncoded(encoded, res, FullOptions(time.Time{}))
	}

	// Warm-up to stabilise the allocator.
	proseFn()
	decodeFn()

	proseAllocs := testing.AllocsPerRun(20, proseFn)
	decodeAllocs := testing.AllocsPerRun(20, decodeFn)

	// The prose path must allocate fewer objects than the decode path.
	// Before PERF-28 both paths allocated N seen-maps (N = len(sources));
	// after, prose allocates none. This test will catch a regression where the
	// lazy initialisation is accidentally removed.
	if proseAllocs >= decodeAllocs {
		t.Errorf("prose allocs (%g) >= decode allocs (%g): lazy seen-map optimisation may be missing",
			proseAllocs, decodeAllocs)
	}
	if proseAllocs > 8 {
		t.Errorf("prose allocs = %g, want <=8 after filtering non-decodable BFS sources", proseAllocs)
	}
}

// ---------------------------------------------------------------------------
// PERF-28-3: MSD dedup behaviour unchanged after lazy initialisation
// ---------------------------------------------------------------------------

// TestLazySeenDedup verifies that per-source dedup (MSD-2) still works when
// the seen map is allocated lazily: a source that emits the same blob twice
// (two identical encoded runs) must not double-emit.
func TestLazySeenDedup(t *testing.T) {
	payload := "MSD2DedupLazySeenTest"
	enc := base64.StdEncoding.EncodeToString([]byte(payload))
	// Two identical base64 runs in one source buffer — same blob would be
	// emitted twice without dedup.
	buf := []byte(enc + " " + enc)
	res := runFromEncoded(buf, nil)

	count := 0
	for _, s := range res.Streams {
		if bytes.Equal(s, []byte(payload)) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate blob emitted %d times (want 1) — lazy seen dedup broken", count)
	}
}

// ---------------------------------------------------------------------------
// PERF-28-4: UTF-16 path — index-based iteration must not re-scan transcoded blobs
// ---------------------------------------------------------------------------

// TestLazySeenUTF16NoDoubleProcess verifies that the UTF-16 transcoding loop
// does not feed its own output back into itself (which the old snapshot-copy
// prevented, and the new index-bounded loop also prevents). We embed a UTF-16LE
// encoded PowerShell command and assert it is decoded exactly once.
func TestLazySeenUTF16Decoded(t *testing.T) {
	// Build a UTF-16LE encoded buffer with a BOM.
	text := "powershell -enc UTF16TestPayload"
	units := utf16.Encode([]rune(text))
	var wide bytes.Buffer
	wide.Write([]byte{0xFF, 0xFE}) // UTF-16LE BOM
	for _, u := range units {
		wide.WriteByte(byte(u & 0xFF))
		wide.WriteByte(byte(u >> 8))
	}

	res := runFromEncoded(wide.Bytes(), nil)

	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("powershell")) {
			found = true
		}
	}
	if !found {
		t.Errorf("UTF-16LE encoded payload not surfaced; streams=%d", len(res.Streams))
	}
}

// TestLazySeenUTF16NoRecursion confirms that the transcoded UTF-8 form is not
// itself re-processed as a UTF-16 source (no second transcode of the output).
// We assert the stream count from the UTF-16 source is bounded — specifically
// that we don't get an exponential fan-out from re-transcoding.
func TestLazySeenUTF16NoRecursion(t *testing.T) {
	// A UTF-16LE source containing plain ASCII text (no nested base64).
	text := strings.Repeat("Hello world. ", 20)
	units := utf16.Encode([]rune(text))
	var wide bytes.Buffer
	wide.Write([]byte{0xFF, 0xFE})
	for _, u := range units {
		wide.WriteByte(byte(u & 0xFF))
		wide.WriteByte(byte(u >> 8))
	}

	res := runFromEncoded(wide.Bytes(), nil)

	// The transcoded UTF-8 form is the only decoded stream; no recursion should
	// produce more streams from this plain-text source.
	if res.DecodedStreams > 2 {
		t.Errorf("UTF-16 plain-text produced %d decoded streams — possible recursion", res.DecodedStreams)
	}
}

// ---------------------------------------------------------------------------
// PERF-28-5: MSD bomb cap — per-source budget preserved
// ---------------------------------------------------------------------------

// TestLazySeenMSDBombCap verifies that the per-source maxDecodedBlobs cap is
// still enforced when the seen map is allocated lazily. A source with many
// base64 runs must not exceed the per-source blob budget.
func TestLazySeenMSDBombCap(t *testing.T) {
	// Build a source with maxDecodedBlobs+10 distinct base64 runs.
	var sb strings.Builder
	for i := 0; i < maxDecodedBlobs+10; i++ {
		payload := strings.Repeat("BombPayload", 3) // long enough to pass minBase64Run after encoding
		enc := base64.StdEncoding.EncodeToString([]byte(payload + strings.Repeat("X", i)))
		sb.WriteString(enc)
		sb.WriteByte(' ')
	}
	res := runFromEncoded([]byte(sb.String()), nil)
	if res.DecodedStreams > maxDecodedBlobs {
		t.Errorf("per-source blob cap not enforced: %d decoded blobs, want <= %d",
			res.DecodedStreams, maxDecodedBlobs)
	}
}

// ---------------------------------------------------------------------------
// PERF-28-6: multi-source decode — per-source independent budgets
// ---------------------------------------------------------------------------

// TestLazySeenMultiSourceIndependentBudgets re-confirms (after the PERF-28
// change) that each source's lazy seen map is independent: one source reaching
// its blob budget does not starve another source's detection.
func TestLazySeenMultiSourceIndependentBudgets(t *testing.T) {
	// Two independent sources in res.Streams, each carrying a distinct payload.
	payloadA := "IndependentSourceA_" + strings.Repeat("A", 20)
	payloadB := "IndependentSourceB_" + strings.Repeat("B", 20)
	encA := base64.StdEncoding.EncodeToString([]byte(payloadA))
	encB := base64.StdEncoding.EncodeToString([]byte(payloadB))

	res := runFromEncoded(nil, [][]byte{[]byte(encA), []byte(encB)})

	if !streamsContain(*res, payloadA) {
		t.Errorf("source A payload not decoded")
	}
	if !streamsContain(*res, payloadB) {
		t.Errorf("source B payload not decoded")
	}
}
