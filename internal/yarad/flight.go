package yarad

import "sync"

// flightGroup coalesces concurrent scans of the same message. When one body
// fans out to N recipients (or an MTA retries during a burst), all the
// duplicate requests arrive in the same window with an identical SHA256 key;
// without coalescing each would run its own libyara scan. With it, the first
// caller scans and the other N-1 block on the same result. Under bulk mail this
// is the difference between 1 scan and hundreds for one campaign.
//
// It is the same idea as gozer's flight group, specialised to the scan result.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flight
}

type flight struct {
	wg      sync.WaitGroup
	matches []Match
	shared  bool // set true if any later caller joined this flight
}

// Do runs fn for key, ensuring only one fn runs at a time per key. Concurrent
// callers for the same key wait and receive the leader's result. shared reports
// whether this call joined an in-flight leader rather than running fn itself.
func (g *flightGroup) Do(key string, fn func() []Match) (matches []Match, shared bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*flight)
	}
	if fl, ok := g.m[key]; ok {
		fl.shared = true
		g.mu.Unlock()
		fl.wg.Wait()
		return fl.matches, true
	}
	fl := &flight{}
	fl.wg.Add(1)
	g.m[key] = fl
	g.mu.Unlock()

	// Release waiters and drop the map entry via defer so that a panic in fn
	// (e.g. a libyara binding fault) cannot leave coalesced callers blocked
	// forever on fl.wg.Wait() with the key permanently stuck in g.m. The
	// panic is re-raised after cleanup so the leader still fails loudly.
	// fl.shared is read here under g.mu — a late joiner sets it under the same
	// lock, so this is the only race-free place to read it.
	defer func() {
		fl.wg.Done()
		g.mu.Lock()
		delete(g.m, key)
		shared = fl.shared
		g.mu.Unlock()
	}()

	matches = fn()
	fl.matches = matches
	return
}
