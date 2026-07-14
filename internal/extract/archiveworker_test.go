package extract

// archiveworker_test.go — containment tests for the archive-decrypt worker pool.
//
// The property under test is NOT "the watchdog returns on time" (it always did) but
// "an unkillable decoder cannot be made to accumulate". Every test here injects a
// permanently-blocking fn — the worst case the real decoders can degrade to — and
// asserts a fixed global ceiling on live workers, that further attempts degrade to
// clean misses instead of spawning more work, and that a stalled archive stops
// consuming candidates.
//
// runBounded clamps its wait to the remaining scan deadline, so a short deadline is
// the injection point for a fast watchdog; maxDecryptAttemptTime stays a production
// const with no test-only seam.

import (
	"sync"
	"testing"
	"time"
)

// blockingFn returns a fn that never returns until release is closed, plus a counter
// of how many times it was actually entered (i.e. how many workers really started).
func blockingFn(release <-chan struct{}, started *sync.WaitGroup, entered *int64, mu *sync.Mutex) func() bool {
	return func() bool {
		mu.Lock()
		*entered++
		mu.Unlock()
		started.Done()
		<-release
		return false
	}
}

// waitFor polls cond until it holds or the timeout expires. Pool bookkeeping is done
// by the worker goroutine on its way out, so a released worker's slot/gauge returns
// asynchronously — polling is the honest way to observe it without sleeping blindly.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// drainPool waits until the pool is fully idle. Tests share process-global pool state,
// so each must both start clean and leave clean.
func drainPool(t *testing.T) {
	t.Helper()
	waitFor(t, "worker pool to go idle", func() bool {
		live, abandoned, _, _ := DecryptWorkerStats()
		return live == 0 && abandoned == 0
	})
}

// TestDecryptWorkerPoolCapsAbandonedWorkers is the audit's headline test: a decoder
// that never returns must not be able to accumulate. Fire far more blocking attempts
// than the pool has slots and assert live workers never exceed the limit, the excess
// is REFUSED (never queued, never spawned), and every refusal is a clean miss.
func TestDecryptWorkerPoolCapsAbandonedWorkers(t *testing.T) {
	drainPool(t)
	release := make(chan struct{})
	defer func() {
		close(release)
		drainPool(t) // unblock the workers and let them hand their slots back
	}()

	var mu sync.Mutex
	var entered int64
	var started sync.WaitGroup
	started.Add(maxDecryptWorkers)
	fn := blockingFn(release, &started, &entered, &mu)

	_, _, refusedBefore, _ := DecryptWorkerStats()

	// Fill every slot. Each of these blocks forever, so each returns a stall and
	// leaves its worker behind holding the slot.
	const overshoot = 3
	attempts := maxDecryptWorkers + overshoot
	for i := 0; i < attempts; i++ {
		deadline := time.Now().Add(20 * time.Millisecond)
		out, stalled := runBounded(deadline, fn)
		if out {
			t.Fatalf("attempt %d: blocking fn must never yield a result, got true", i)
		}
		if i < maxDecryptWorkers && !stalled {
			t.Fatalf("attempt %d: a blocked worker must report a stall", i)
		}
		if live, _, _, limit := DecryptWorkerStats(); live > int64(limit) {
			t.Fatalf("attempt %d: live workers %d exceeded the pool limit %d", i, live, limit)
		}
	}

	// Exactly maxDecryptWorkers decoders ever ran; the overshoot never spawned one.
	started.Wait()
	mu.Lock()
	got := entered
	mu.Unlock()
	if got != int64(maxDecryptWorkers) {
		t.Fatalf("started %d decoders, want exactly the pool size %d — the pool did not refuse the excess", got, maxDecryptWorkers)
	}

	live, abandoned, refusedAfter, limit := DecryptWorkerStats()
	if live != int64(limit) {
		t.Fatalf("live = %d, want the pool to be exactly full at %d", live, limit)
	}
	if abandoned != int64(limit) {
		t.Fatalf("abandoned = %d, want all %d hung workers accounted for", abandoned, limit)
	}
	if refusedAfter-refusedBefore != overshoot {
		t.Fatalf("refused %d attempts, want %d (one per attempt past the pool limit)", refusedAfter-refusedBefore, overshoot)
	}
}

// TestDecryptWorkerSlotHeldUntilDecoderReturns pins the property that makes the pool a
// real bound: the slot is released when the decoder actually exits, NOT when the
// watchdog stops waiting for it. Were it released at the watchdog, an unkillable
// decoder would be free to accumulate without limit — the very bug being fixed.
func TestDecryptWorkerSlotHeldUntilDecoderReturns(t *testing.T) {
	drainPool(t)
	release := make(chan struct{})

	var mu sync.Mutex
	var entered int64
	var started sync.WaitGroup
	started.Add(1)
	fn := blockingFn(release, &started, &entered, &mu)

	if _, stalled := runBounded(time.Now().Add(20*time.Millisecond), fn); !stalled {
		t.Fatal("blocked decoder did not report a stall")
	}
	started.Wait()

	// Watchdog has returned. The decoder is still in fn, so its slot must still be held.
	live, abandoned, _, _ := DecryptWorkerStats()
	if live != 1 || abandoned != 1 {
		t.Fatalf("after the watchdog gave up: live=%d abandoned=%d, want 1/1 — the slot must outlive the wait", live, abandoned)
	}

	// Let the decoder finish: only now may the slot and both gauges come back.
	close(release)
	drainPool(t)
	if _, abandoned, _, _ := DecryptWorkerStats(); abandoned != 0 {
		t.Fatalf("abandoned = %d after the decoder returned, want 0", abandoned)
	}
}

// TestDecryptWorkerFastPathNoLeak guards the ordinary case: a decoder that finishes
// inside its watchdog is not a stall, is not counted abandoned, and hands its slot
// straight back. Without this, a bug that marked every attempt stalled would still
// pass the containment tests while silently disabling decryption altogether.
func TestDecryptWorkerFastPathNoLeak(t *testing.T) {
	drainPool(t)
	for i := 0; i < maxDecryptWorkers*4; i++ {
		out, stalled := runBounded(time.Now().Add(5*time.Second), func() bool { return true })
		if !out || stalled {
			t.Fatalf("attempt %d: out=%v stalled=%v, want true/false for a decoder that finished in time", i, out, stalled)
		}
	}
	drainPool(t)
	if live, abandoned, _, _ := DecryptWorkerStats(); live != 0 || abandoned != 0 {
		t.Fatalf("live=%d abandoned=%d after clean runs, want 0/0 — slots leaked", live, abandoned)
	}
}

// TestDecryptWorkerTimerRaceKeepsResult guards the select-randomness hazard: when the
// decoder finishes at almost exactly the moment the watchdog fires, BOTH select cases
// are ready and Go picks one at random. If the timer branch simply discarded the
// result, a successful decrypt would be thrown away AND the stall latch would trip —
// disabling decryption for the whole archive on a coin flip. A finished decoder must
// always yield its result, never a stall, however the race lands.
func TestDecryptWorkerTimerRaceKeepsResult(t *testing.T) {
	drainPool(t)
	// Hammer the boundary: fn returns at the same instant the watchdog expires.
	for i := 0; i < 300; i++ {
		const wait = 2 * time.Millisecond
		out, stalled := runBounded(time.Now().Add(wait), func() bool {
			time.Sleep(wait)
			return true
		})
		// Either the decoder won (true/false) or it genuinely overran (false/true).
		// The one forbidden outcome is a successful decode reported as a stall, or a
		// result silently dropped while the run was NOT a stall.
		if out && stalled {
			t.Fatalf("iteration %d: a decoder that produced a result was reported as stalled", i)
		}
		if !out && !stalled {
			t.Fatalf("iteration %d: out=false stalled=false — a result was dropped without reporting a stall", i)
		}
	}
	drainPool(t)
}

// TestDecryptStalledLatchStopsCandidates pins rule 2: one stalled attempt poisons the
// archive's budget, so the candidate loops launch nothing further for that input.
// Without the latch, a single member that reliably hangs the decoder would convert
// each of its (up to 64) candidates into another abandoned worker and drain the pool
// on its own.
func TestDecryptStalledLatchStopsCandidates(t *testing.T) {
	b := &archiveBudget{}
	if b.decryptExhausted() {
		t.Fatal("a fresh budget must not be exhausted")
	}
	b.markDecryptStalled()
	if !b.decryptExhausted() {
		t.Fatal("a stalled budget must report exhausted so no further candidate is launched")
	}
	// The latch must not depend on the attempt counters — it stands on its own.
	b.decryptAttempts, b.kdfAttempts = 0, 0
	if !b.decryptExhausted() {
		t.Fatal("the stall latch must hold independently of the attempt counters")
	}
}

// TestDecrypted7zMemberIsPooled pins the containment of the POST-crack read. Finding
// the password does not make the member safe: decrypt+LZMA of attacker-authored
// plaintext is the same uncancellable third-party code as the crack itself. If that
// read ran on the scan goroutine it would escape the pool entirely — the crack would
// be contained and the extraction would not.
func TestDecrypted7zMemberIsPooled(t *testing.T) {
	drainPool(t)

	// A budget already latched as stalled must launch NO further decoder work, so the
	// pooled read is never entered and nothing is decrypted.
	b := &archiveBudget{}
	b.markDecryptStalled()
	if data, ok := boundedDecrypted7zMember(nil, 0, b, time.Time{}); ok || data != nil {
		t.Fatal("a stalled budget still ran a decrypted-member read — the latch does not gate the post-crack path")
	}

	// And an expired deadline must not spawn a worker either.
	if _, ok := boundedDecrypted7zMember(nil, 0, &archiveBudget{}, time.Now().Add(-time.Second)); ok {
		t.Fatal("an expired deadline still produced a decrypted member")
	}
	drainPool(t)
	if live, _, _, _ := DecryptWorkerStats(); live != 0 {
		t.Fatalf("live = %d, want 0 — the gated paths must not leave workers behind", live)
	}
}

// TestDecrypt7zStillWorksThroughThePool is the counterweight to every containment test
// above: the pool and the stall latch must not have broken decryption itself. A too-
// eager latch, or a pool that refuses when it should not, would silently turn every
// encrypted archive into ARCHIVE-ENCRYPTED and quietly stop finding hidden droppers —
// a detection loss that no containment assertion would catch.
func TestDecrypt7zStillWorksThroughThePool(t *testing.T) {
	drainPool(t)
	for _, name := range []string{"sevenzip-pw.7z", "sevenzip-pwhe.7z"} {
		t.Run(name, func(t *testing.T) {
			res := ExtractWithOptions(readFixture(t, name), pwOpts(testPW))
			if !res.DecryptedArchive {
				t.Fatalf("%s: not decrypted — the worker pool broke the decrypt path", name)
			}
			if !streamsContain(res, childMarker) {
				t.Errorf("%s: decrypted plaintext not surfaced through the pooled read", name)
			}
		})
	}
	drainPool(t)
	if live, abandoned, _, _ := DecryptWorkerStats(); live != 0 || abandoned != 0 {
		t.Fatalf("live=%d abandoned=%d after clean decrypts, want 0/0 — the pool leaks on the success path", live, abandoned)
	}
}

// TestDecryptZeroDeadlineDoesNotSpawn checks the cheapest refusal path: an already-
// expired scan deadline must not start a decoder at all — no slot, no goroutine, no
// retained buffer.
func TestDecryptZeroDeadlineDoesNotSpawn(t *testing.T) {
	drainPool(t)
	var mu sync.Mutex
	var entered int64
	fn := func() bool {
		mu.Lock()
		entered++
		mu.Unlock()
		return true
	}
	out, stalled := runBounded(time.Now().Add(-time.Second), fn)
	if out || stalled {
		t.Fatalf("out=%v stalled=%v, want false/false for an expired deadline", out, stalled)
	}
	mu.Lock()
	got := entered
	mu.Unlock()
	if got != 0 {
		t.Fatalf("the decoder ran %d times on an already-expired deadline, want 0", got)
	}
}
