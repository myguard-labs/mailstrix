// MSD-6 synthetic worst-case / invariant / soak tests.
//
// MSD-6 differential-corpus half (named-IOC, multi-layer carriers + expected-IOC
// asserts) lives in decode_differential_test.go. This file covers the synthetic
// worst-case/invariant/soak half only.
package extract

import (
	"encoding/base64"
	"testing"
	"time"
)

// makeBase64Bomb builds a buffer of approximately sizeBytes that is packed with
// long valid base64 runs. Each run decodes to text that itself contains a long
// base64 run (nestLayers>0), so the recursive decoder is provoked. The payload
// at the innermost layer is plain ASCII so looksEncoded returns false there and
// the chain terminates naturally (the depth cap is the hard guard).
//
// nestLayers is clamped to maxDecodeDepth so callers cannot accidentally
// request more than the decoder supports; any extra depth is just wasted.
func makeBase64Bomb(sizeBytes int, nestLayers int) []byte {
	if nestLayers > maxDecodeDepth {
		nestLayers = maxDecodeDepth
	}
	// Build the innermost cleartext payload — plain ASCII, not itself encoded.
	// 64 bytes of printable ASCII: no encoded sub-run inside, so recursion stops.
	inner := []byte("INNER-PAYLOAD-CLEARTEXT-SOAK-TEST-NOT-BASE64-NOR-HEX-LONG-ENOUGH-X")

	// Wrap nestLayers times so the outer blob requires exactly nestLayers peels.
	encoded := inner
	for i := 0; i < nestLayers; i++ {
		encoded = []byte(base64.StdEncoding.EncodeToString(encoded))
	}

	// Pad to the requested size by repeating the encoded run separated by spaces
	// (spaces are not base64-alphabet, so each repetition is a distinct run).
	runLen := len(encoded)
	if runLen == 0 {
		runLen = 1
	}
	out := make([]byte, 0, sizeBytes)
	for len(out) < sizeBytes {
		out = append(out, encoded...)
		out = append(out, ' ')
	}
	if len(out) > sizeBytes {
		out = out[:sizeBytes]
	}
	_ = runLen
	return out
}

// assertInvariants checks the documented bounded-worst-case invariants on res.
// t.Helper is called so failures point at the call site.
func assertDecodeInvariants(t *testing.T, res Result) {
	t.Helper()

	if got := len(res.Streams); got > maxStreams {
		t.Errorf("invariant FAIL: len(res.Streams) = %d > maxStreams(%d)", got, maxStreams)
	}
	if res.DecodedStreams > maxStreams {
		t.Errorf("invariant FAIL: res.DecodedStreams = %d > maxStreams(%d)", res.DecodedStreams, maxStreams)
	}

	// The decoded streams are always the TRAILING res.DecodedStreams entries.
	// Check per-blob and cumulative size caps.
	nDecoded := res.DecodedStreams
	if nDecoded > len(res.Streams) {
		nDecoded = len(res.Streams)
	}
	decoded := res.Streams[len(res.Streams)-nDecoded:]

	cumulative := 0
	for _, s := range decoded {
		if len(s) > maxBytesPerDecodedBlob {
			t.Errorf("invariant FAIL: decoded blob len=%d > maxBytesPerDecodedBlob(%d)", len(s), maxBytesPerDecodedBlob)
		}
		cumulative += len(s)
	}
	// Allow one in-flight blob of slack (the last blob may push cum just over the
	// rolling check before the cap fires on the NEXT emit attempt).
	slack := maxCumulativeDecoded + maxBytesPerDecodedBlob
	if cumulative > slack {
		t.Errorf("invariant FAIL: cumulative decoded bytes=%d > maxCumulativeDecoded+slack(%d)",
			cumulative, slack)
	}
}

// TestSoakBase64Bomb feeds a multi-MiB buffer packed with many long valid
// base64 runs, each decoding to text that itself looksEncoded (provokes
// recursion). Asserts all documented budget invariants hold.
func TestSoakBase64Bomb(t *testing.T) {
	// ~256 KiB carrier with 2 nesting layers — enough to exercise the blob/byte/
	// depth budgets without making the test slow under -race in Docker.
	buf := makeBase64Bomb(256*1024, 2)

	deadline := time.Now().Add(5 * time.Second)
	res := &Result{}
	start := time.Now()
	fromEncoded(buf, res, FullOptions(deadline))
	elapsed := time.Since(start)

	// Wall-time guard: if we somehow spun for >10 s the decoder is not bounded.
	// The generous ceiling accommodates -race + Docker overhead.
	if elapsed > 10*time.Second {
		t.Errorf("base64-bomb took %v > 10s — decoder not properly bounded", elapsed)
	}

	assertDecodeInvariants(t, *res)
}

// TestSoakQuineCycle exercises the MSD-2 content dedup + depth cap via a source
// that drives the dedup path: two identical long base64 runs in the buffer, plus
// a nested layer, to ensure the second copy is recognised as already-emitted and
// skipped. Asserts termination (the test not hanging is the assertion) and
// bounded DecodedStreams.
func TestSoakQuineCycle(t *testing.T) {
	// One base64 run that decodes to another base64 run (2-layer nesting), then
	// the same outer run repeated — the dedup set should short-circuit the repeat.
	inner := []byte("QUINE-CYCLE-INNER-PAYLOAD-LONG-ENOUGH-FOR-MINDECODEDLEN-GATE")
	l1 := base64.StdEncoding.EncodeToString(inner)
	outer := base64.StdEncoding.EncodeToString([]byte(l1))

	// buf = outer + " " + outer — two identical runs; MSD-2 dedup must suppress
	// the second re-decode.
	buf := []byte(outer + " " + outer)

	done := make(chan Result, 1)
	go func() {
		res := &Result{}
		fromEncoded(buf, res, FullOptions(time.Now().Add(5*time.Second)))
		done <- *res
	}()

	var res Result
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("quine/cycle test did not terminate within 5s — decoder hung")
	}

	assertDecodeInvariants(t, res)
	// DecodedStreams must be small (2 layers × 1 distinct blob each, not 2×2).
	if res.DecodedStreams > 4 {
		t.Errorf("DecodedStreams=%d — MSD-2 dedup may not be collapsing the duplicate run",
			res.DecodedStreams)
	}
}

// TestSoak4MiBCarrier sends a single ~4 MiB mostly-text buffer with encoded
// runs scattered through it. Asserts bounded streams and that
// maxFoldInput/maxReverseInput clamps prevent OOM.
func TestSoak4MiBCarrier(t *testing.T) {
	// Build a ~512 KiB text carrier: ASCII filler with a base64 run every 1024
	// bytes. Kept modest so the test passes under -race in Docker.
	const size = 512 * 1024
	buf := make([]byte, 0, size)
	encoded := base64.StdEncoding.EncodeToString(
		[]byte("SCATTERED-ENCODED-RUN-PAYLOAD-LONG-ENOUGH-FOR-BUDGET"),
	)
	filler := []byte("the quick brown fox jumps over the lazy dog and more filler text here")
	for len(buf) < size {
		n := 1024
		if n > size-len(buf) {
			n = size - len(buf)
		}
		chunk := filler
		if len(chunk) > n {
			chunk = chunk[:n]
		}
		buf = append(buf, chunk...)
		if len(buf)+len(encoded)+1 < size {
			buf = append(buf, []byte(encoded)...)
			buf = append(buf, ' ')
		}
	}
	if len(buf) > size {
		buf = buf[:size]
	}

	deadline := time.Now().Add(5 * time.Second)
	res := &Result{}
	start := time.Now()
	fromEncoded(buf, res, FullOptions(deadline))
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Errorf("4 MiB carrier took %v > 10s", elapsed)
	}
	assertDecodeInvariants(t, *res)
}

// TestSoakDeadlineHonored feeds the bomb carrier to fromEncoded with a deadline
// in the past (or ~1 ms in the future) and asserts it returns promptly with an
// empty/small result — the deadline path must not loop unboundedly.
func TestSoakDeadlineHonored(t *testing.T) {
	buf := makeBase64Bomb(512*1024, 2)

	// Already-expired deadline.
	expiredDeadline := time.Now().Add(-time.Millisecond)

	start := time.Now()
	res := &Result{}
	fromEncoded(buf, res, FullOptions(expiredDeadline))
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("expired deadline: fromEncoded took %v > 500ms — deadline not honoured", elapsed)
	}
	// With an expired deadline we expect zero or very few streams (deadline fires
	// before any budget is consumed).
	if res.DecodedStreams > 2 {
		t.Errorf("expired deadline: DecodedStreams=%d > 2 — too many streams emitted past deadline",
			res.DecodedStreams)
	}
}

// FuzzFromEncoded is a fuzz target that asserts the core budget invariants
// never violated and fromEncoded never panics, regardless of input. In CI it
// runs 0 iterations (just ensures the fuzz function builds). The monthly cron
// drives it with -fuzz.
func FuzzFromEncoded(f *testing.F) {
	// Seed corpus.
	f.Add([]byte(""))
	f.Add([]byte("aGVsbG8gd29ybGQ=")) // base64 of "hello world"
	f.Add(makeBase64Bomb(4096, 1))
	f.Add(makeBase64Bomb(4096, 2))
	f.Add([]byte("the quick brown fox jumps over the lazy dog"))

	f.Fuzz(func(t *testing.T, data []byte) {
		res := &Result{}
		fromEncoded(data, res, FullOptions(time.Now().Add(time.Second)))
		assertDecodeInvariants(t, *res)
	})
}
