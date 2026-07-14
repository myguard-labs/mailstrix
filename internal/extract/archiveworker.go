package extract

// archiveworker.go — the global bounded worker pool that contains non-cancellable
// third-party archive decoders.
//
// The decrypt attempt loop (archivepw.go) feeds attacker-controlled ciphertext to
// yeka/zip, sevenzip and rardecode. None of them takes a context, so a decoder that
// spins on a crafted member cannot be cancelled: the best we can do is stop WAITING
// for it. The previous design did exactly that — a per-attempt watchdog returned a
// miss after the deadline and left the goroutine running — and that is not a cost
// cap at all. Nothing bounded how many abandoned decoders were alive at once, each
// one still held the whole archive buffer and still burned a core, and the candidate
// loop happily launched the NEXT attempt on the same archive while the previous one
// was still spinning. Repeated crafted inputs therefore accumulated live goroutines
// and retained buffers without limit, well past the scan deadline that was supposed
// to have ended the work.
//
// The fix is to make abandonment cost something. Two rules, both required:
//
//  1. A GLOBAL slot cap (maxDecryptWorkers). A slot is acquired BEFORE the decoder
//     starts and released only when the decoder actually returns — never when the
//     watchdog gives up on it. So an abandoned decoder keeps occupying its slot for
//     as long as it really runs, and the pool is a hard ceiling on live decoder
//     goroutines (and hence on retained archive buffers and burned cores) no matter
//     how many hostile inputs arrive. When every slot is held, a new attempt does
//     not queue and does not spawn: it misses immediately (fail-open, the member
//     stays ARCHIVE-ENCRYPTED). Refusing beats queueing here — a queue would just
//     move the unbounded growth from goroutines to waiters.
//
//  2. A PER-ARCHIVE stall latch (see archiveBudget.decryptStalled). The first
//     attempt on an archive that overruns its watchdog poisons that archive: no
//     further candidate is launched for it. Without this, one crafted member that
//     reliably hangs the decoder turns each of its ≤64 candidates into another
//     abandoned worker, so a single input could drain the whole pool by itself.
//
// Together these bound the blast radius of a permanently-hanging decoder to
// maxDecryptWorkers live goroutines process-wide, with every further attempt
// degrading to a clean miss instead of piling on more work.

import (
	"runtime"
	"sync/atomic"
	"time"
)

// maxDecryptWorkers is the process-wide ceiling on concurrently running decrypt
// decoders, including ones the watchdog has already abandoned. It is deliberately
// small: these are CPU-bound calls into third-party decompressors, each retaining
// its archive buffer, and (unlike the scan-CPU slots) an abandoned one cannot be
// reclaimed — only outlived. Sizing it to the core count means a pool fully clogged
// with permanently-hung decoders costs at most what a single busy scan costs, and
// every further attempt is refused rather than queued.
var maxDecryptWorkers = defaultMaxDecryptWorkers()

func defaultMaxDecryptWorkers() int {
	n := runtime.NumCPU()
	switch {
	case n < 2:
		return 2
	case n > 8:
		return 8
	}
	return n
}

// decryptWorkers is the slot semaphore. A token in the channel is a free slot, so a
// non-blocking send acquires and a receive releases; an empty buffer means every
// worker is busy and the next attempt is refused. Buffered channels give us the
// try-acquire we need (a sync.WaitGroup or a counter+mutex cannot refuse).
var decryptWorkers = make(chan struct{}, maxDecryptWorkers)

// Live decrypt-worker telemetry. Exported through DecryptWorkerStats so the ICAP
// server can publish it without dragging a metrics dependency into this package.
// abandoned is the one that matters operationally: a non-zero, non-decreasing
// abandoned count means real decoders are hanging in the field, which is exactly the
// condition the pool exists to survive and the operator needs to see.
var (
	decryptLive      atomic.Int64 // decoders currently running (incl. abandoned)
	decryptAbandoned atomic.Int64 // decoders still running after their watchdog gave up
	decryptRefused   atomic.Int64 // attempts refused because the pool was full
	decryptPanicked  atomic.Int64 // decoders that panicked (recovered by the pool, not the caller)
	// plainDropped counts PLAIN-path members (no password involved) that were left
	// unextracted because their decoder stalled or the pool was full. Unlike the
	// decrypt counters this is a DETECTION-LOSS signal, not just a load signal: each
	// one is a member whose bytes were never scanned. It is the price of keeping the
	// scan goroutine off the uncancellable decoders, and it must be visible — a
	// silent cap reads as "we extracted everything" when we did not.
	plainDropped atomic.Int64
)

// DecryptWorkerStats reports the archive-decrypt worker pool state:
//
//	live      — decoder goroutines running right now, abandoned ones included.
//	abandoned — of those, how many outlived their watchdog and are unkillable.
//	refused   — cumulative attempts that never started because the pool was full.
//	limit     — the pool ceiling (live can never exceed it).
//
// Steady-state live and abandoned are 0. A persistently non-zero abandoned count is
// the signal that a third-party decoder is hanging on hostile input.
func DecryptWorkerStats() (live, abandoned, refused int64, limit int) {
	return decryptLive.Load(), decryptAbandoned.Load(), decryptRefused.Load(), maxDecryptWorkers
}

// PlainDroppedMembers reports how many plain-path (non-password) archive members
// were left unextracted because the decoder stalled or the pool was full. Each is a
// member whose bytes never reached the scanner: a rising count means an input is
// inducing real detection loss, not merely load. Steady state is 0.
func PlainDroppedMembers() int64 { return plainDropped.Load() }

// runBoundedPlain runs a PLAIN-path (no password) decoder call on the same pooled
// worker as the decrypt path, and returns the zero value if it stalls or if no slot
// was free.
//
// It shares runBounded's pool but NOT its failure semantics, and the difference is
// the whole point of A8. The decrypt path may refuse freely: a refused crack just
// leaves the member ARCHIVE-ENCRYPTED, which is a correct verdict either way, and
// one stall latches the archive so the candidate loop stops feeding the decoder. The
// plain path has no such luxury — it runs on EVERY archive, with the password feature
// off, and its "refusal" is a member nobody ever scanned. So:
//
//   - A miss here degrades THAT MEMBER ONLY. The walk continues to the next member.
//     It must never latch the archive-wide decrypt stall: reusing that latch would
//     turn one hostile member into a whole-archive abort and hand the attacker a
//     cheap way to suppress extraction of everything after it.
//   - Every miss is counted in plainDropped, because it is detection loss and the
//     operator has to be able to see it.
//
// What we buy for that price is the thing A8 is actually about: the uncancellable
// third-party decoder no longer runs on the scan goroutine, so a crafted archive that
// spins it can no longer pin a scan slot against the server's admission cap. The
// decoder still runs — it cannot be killed — but it runs on a pooled worker whose slot
// is held until it genuinely returns, exactly like the decrypt path.
//
// fn must not mutate state shared with the caller: an abandoned fn keeps running
// concurrently with everything that follows. Callers therefore hand it a decoder that
// owns its own reader over the (immutable) archive buffer — never a shared streaming
// cursor. See emitRarMembers for why RAR needs a fresh per-member reader.
func runBoundedPlain[T any](deadline time.Time, fn func() T) (out T, ok bool) {
	v, ran, stalled := runBoundedRan(deadline, fn)
	if !ran || stalled {
		// Never started (pool full / deadline blown) or abandoned mid-decode. Either
		// way this member's bytes were never scanned — count the detection loss and
		// tell the caller to skip THIS member, not the archive.
		plainDropped.Add(1)
		return out, false
	}
	return v, true
}

// runBounded runs fn on a pooled worker and returns its result, or the zero value if
// fn does not finish within maxDecryptAttemptTime (and before the scan deadline), or
// if no worker slot was free. A zero return is always a plain miss: the caller keeps
// ARCHIVE-ENCRYPTED and moves on (fail-open).
//
// The slot outlives the wait. When the watchdog fires we stop waiting for fn, but the
// goroutine holds its slot until fn genuinely returns — that is what makes the pool a
// real bound on abandoned work rather than a bound on how long we look at it.
//
// stalled reports whether the attempt was abandoned mid-flight (as opposed to
// finishing, or never starting). The caller latches it on the archive's budget and
// launches no further candidate for that archive, so one hanging member cannot spawn
// one abandoned worker per candidate.
//
// fn must not mutate state shared with the caller: an abandoned fn keeps running
// concurrently with everything that follows it. The decrypt helpers only read the
// (immutable) archive buffer and build a fresh output, and each builds its own
// third-party reader, so abandoning one is safe.
func runBounded[T any](deadline time.Time, fn func() T) (out T, stalled bool) {
	v, _, stalled := runBoundedRan(deadline, fn)
	return v, stalled
}

// runBoundedRan is runBounded with the third outcome made explicit. runBounded folds
// "the decoder finished" and "we never started it" into the same (zero, false) return,
// which is fine for the decrypt path (both mean "no password recovered") but WRONG for
// the plain path, where a refused member must be counted as dropped rather than
// reported as a clean empty read. ran distinguishes them: it is false only when the
// work never ran at all (deadline already blown, or the pool was full).
func runBoundedRan[T any](deadline time.Time, fn func() T) (out T, ran, stalled bool) {
	limit := maxDecryptAttemptTime
	if !deadline.IsZero() {
		if rem := time.Until(deadline); rem < limit {
			limit = rem
		}
	}
	if limit <= 0 {
		return out, false, false // deadline already passed: don't even spawn the work
	}

	// Try-acquire a slot. Never block: a full pool means abandoned decoders are
	// hogging the workers, and making the scan queue behind them would hand the
	// attacker the stall we are trying to prevent.
	select {
	case decryptWorkers <- struct{}{}:
	default:
		decryptRefused.Add(1)
		return out, false, false
	}

	// state is the single source of truth for who got there first, so the abandoned
	// gauge is never double-counted and never leaked: the watchdog and the worker
	// race to CAS it exactly once. stateRunning → stateAbandoned means the watchdog
	// gave up first (the worker will decrement the gauge on its way out);
	// stateRunning → stateDone means the worker finished first (nothing was ever
	// abandoned). Whoever loses the CAS does no accounting at all.
	const (
		stateRunning = iota
		stateAbandoned
		stateDone
	)
	state := new(atomic.Int32)

	ch := make(chan T, 1) // buffered: an abandoned worker must never block on send
	decryptLive.Add(1)
	go func() {
		// The worker runs on its OWN goroutine, so the extractor's top-level recover
		// (extract.go) cannot see a panic raised here — an unrecovered one would kill
		// the whole daemon. fn is third-party archive code fed attacker-authored bytes,
		// which is exactly the code most likely to panic, so the pool recovers for every
		// caller rather than trusting each of them to remember. A panicking decoder
		// yields the zero value: a clean miss, same as a stall (fail-open).
		defer func() {
			if r := recover(); r != nil {
				decryptPanicked.Add(1)
				var zero T
				select {
				case ch <- zero:
				default: // a result was already sent; the panic came after it
				}
			}
			// If the watchdog already abandoned us, retire the gauge it raised.
			// Otherwise claim a clean finish so the watchdog knows not to raise it.
			if !state.CompareAndSwap(stateRunning, stateDone) {
				decryptAbandoned.Add(-1)
			}
			decryptLive.Add(-1)
			<-decryptWorkers // release the slot only now — after fn really returned
		}()
		ch <- fn()
	}()

	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case v := <-ch:
		return v, true, false
	case <-timer.C:
		// The timer fired — but when both cases are ready Go picks one at RANDOM, so a
		// decoder that finished just in time can land here with its result already sent.
		// Take it rather than throw it away: discarding it would lose a successful
		// decrypt AND latch the stall, disabling decryption for the whole archive on a
		// coin flip. Only a genuinely still-running decoder is a stall.
		select {
		case v := <-ch:
			return v, true, false
		default:
		}
		// Overran the per-attempt cap. Stop waiting, but the worker keeps its slot
		// until it exits. Raise the abandoned gauge — unless the worker won the CAS in
		// the gap between the check above and here, in which case it finished cleanly
		// and nothing is abandoned. Its result is then dropped (a miss), which is the
		// honest outcome for a decoder that did blow the cap.
		if state.CompareAndSwap(stateRunning, stateAbandoned) {
			decryptAbandoned.Add(1)
		}
		return out, true, true
	}
}
