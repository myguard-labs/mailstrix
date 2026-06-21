package yarad

import (
	"context"
	"sync"
)

// flightGroup coalesces concurrent scans of the same message. When one body
// fans out to N recipients (or an MTA retries during a burst), all the
// duplicate requests arrive in the same window with an identical SHA256 key;
// without coalescing each would run its own libyara scan. With it, the first
// caller scans and the other N-1 block on the same result. Under bulk mail this
// is the difference between 1 scan and hundreds for one campaign.
//
// It is the same idea as gozer's flight group, specialised to the scan result.
//
// Coalescing is CONTEXT-AWARE (AUDIT-FLIGHT-CONTEXT):
//   - A follower waits with its OWN request context, so a disconnected/timed-out
//     follower stops waiting immediately and releases the resources it holds (the
//     admission slot held for the whole request) instead of blocking until the
//     leader's full scan completes.
//   - A leader that ABANDONS its scan (its own client went away before a scan
//     slot was free, so it produced no real verdict — fail-open nil) must NOT
//     impose that empty non-verdict on the still-connected followers. The leader
//     marks the flight ABORTED; a waiting follower then promotes itself and
//     re-runs fn rather than accepting the leader's poisoned nil.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flight
}

type flight struct {
	done    chan struct{} // closed when the leader finishes (or aborts)
	matches []Match
	joiners int  // followers still waiting on this flight (under flightGroup.mu)
	shared  bool // ≥1 follower was still waiting when the leader finished (under .mu)
	aborted bool // leader produced no real verdict (its client went away)
}

// Do runs fn for key, ensuring only one fn runs at a time per key. Concurrent
// callers for the same key wait — bounded by their own ctx — and receive the
// leader's result.
//
// fn returns (matches, aborted): aborted=true means it did NOT compute a real
// verdict (e.g. the leader's client disconnected before a scan slot was free),
// so the result must not be shared with followers.
//
// Do returns:
//   - matches: the verdict (nil on a fail-open / ctx-cancelled path);
//   - shared:  true if this call joined an in-flight leader rather than running fn;
//   - err:     ctx.Err() if THIS caller's context was cancelled while waiting
//     (the caller treats it as "client gone", not a verdict).
func (g *flightGroup) Do(ctx context.Context, key string, fn func() (matches []Match, aborted bool)) (matches []Match, shared bool, err error) {
	for {
		g.mu.Lock()
		if g.m == nil {
			g.m = make(map[string]*flight)
		}
		if fl, ok := g.m[key]; ok {
			// Register as a live follower; the leader counts only followers STILL
			// waiting when it finishes, so a follower that cancels (and decrements
			// below) is never counted — cacheCoalesced reflects real coalesced
			// consumers, not abandoned waiters.
			fl.joiners++
			g.mu.Unlock()
			// Wait bounded by OUR context: a disconnected follower bails at once and
			// frees its admission slot instead of blocking on the leader's full scan.
			select {
			case <-fl.done:
			case <-ctx.Done():
				g.mu.Lock()
				fl.joiners--
				g.mu.Unlock()
				return nil, true, ctx.Err()
			}
			// The leader abandoned its scan (its client went away → no real verdict).
			// Don't accept that poisoned nil; loop to promote ourselves / join the
			// next leader. Our own ctx still bounds the retry via the select above.
			if fl.aborted {
				if ctx.Err() != nil {
					return nil, true, ctx.Err()
				}
				continue
			}
			return fl.matches, true, nil
		}
		fl := &flight{done: make(chan struct{})}
		g.m[key] = fl
		g.mu.Unlock()

		// Release waiters (close done) and drop the map entry via defer so that a
		// panic in fn (e.g. a libyara binding fault) cannot leave coalesced callers
		// blocked forever with the key permanently stuck in g.m. The panic is
		// re-raised after cleanup so the leader still fails loudly. fl.shared is
		// computed in finishLeader from the live-follower count under g.mu.
		var aborted bool
		func() {
			defer func() {
				// On a panic in fn, mark the flight aborted so waiting followers
				// re-run rather than inheriting the leader's empty (panicking)
				// non-verdict; the panic still propagates after cleanup so the leader
				// fails loudly and dispatch's own recover logs it.
				if r := recover(); r != nil {
					aborted = true
					g.finishLeader(fl, key, aborted)
					panic(r)
				}
				g.finishLeader(fl, key, aborted)
			}()
			matches, aborted = fn()
			fl.matches = matches
		}()
		g.mu.Lock()
		shared = fl.shared
		g.mu.Unlock()
		return matches, shared, nil
	}
}

// finishLeader publishes the leader's outcome: record whether the verdict was
// abandoned, drop the map entry, and release waiters. Map mutation is under the
// lock; close(done) is after the unlock (a closed channel needs no lock and the
// waiters re-take g.mu themselves on wake).
func (g *flightGroup) finishLeader(fl *flight, key string, aborted bool) {
	g.mu.Lock()
	fl.aborted = aborted
	// shared = "≥1 follower was still registered when the leader finished". A
	// follower that already cancelled has decremented, so it isn't counted. NB this
	// is an APPROXIMATION for the cacheCoalesced metric, not an exact consumer
	// count: a follower whose ctx is already cancelled at the instant done closes
	// may still pick the ctx.Done() branch (Go select is pseudo-random when both
	// cases are ready) and decrement AFTER this read — so shared can be optimistic
	// by one in that race. That's acceptable for a metric (no verdict is affected).
	fl.shared = fl.joiners > 0
	delete(g.m, key)
	g.mu.Unlock()
	close(fl.done)
}
