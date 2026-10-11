package mailstrix

import (
	"errors"
	"runtime"
	"sync"

	yara "github.com/hillu/go-yara/v4"
)

// ErrScannerClosed rejects native work after Close without certifying a verdict.
var ErrScannerClosed = errors.New("scanner closed")

// scannerGeneration is an immutable pin of a published generation. Reload
// prepares fresh native bundles, then publishes main/big/marker rules, the deny
// map and their identity together under generationMu. Native bundles and deny
// maps are never mutated after publication. Retained fallback bundles retain
// their identity as well as their rules.
//
// A request acquires its pin BEFORE forming a cache key and owns it until its
// cache hit, coalesced wait, or native scan and cache publication completes.
// Old requests may publish only under their pinned fingerprint, even after a
// reload/FlushCache. The native worker owns this pin, not the client connection.
// A canceled follower drops only its own pin; the leader keeps its pin until
// native work finishes. Reference-counted pins own retirement of managed native Rules.
// No publication lock is held over cache I/O or native work, and snapshot-bound
// operations never reacquire that lock.
type scannerGeneration struct {
	rules, bigRules, markerRules *yara.Rules
	deny                         *map[string]struct{}
	topEpoch                     uint64 // topMatches epoch pinned with this generation
}

type scanLease struct {
	err          error
	fingerprint  string
	scan         func([]byte, ScanMeta) ([]Match, error)
	releaseToken *leaseRelease
}

// generationPin owns one reference per distinct managed Rules identity. The
// publication root and each request retain this immutable ownership set.
type generationPin struct {
	mu     sync.Mutex
	refs   int
	owners []*nativeRulesOwner
}

func (g *generationPin) retain() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refs == 0 {
		panic("retaining retired rules generation")
	}
	g.refs++
}
func (g *generationPin) release() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.refs == 0 {
		g.mu.Unlock()
		panic("unbalanced generation release")
	}
	g.refs--
	last := g.refs == 0
	g.mu.Unlock()
	if last {
		for _, o := range g.owners {
			o.release()
		}
	}
}

type leaseRelease struct {
	once sync.Once
	pin  *generationPin
}

func (s *Scanner) acquireScanLease() scanLease {
	s.generationMu.RLock()
	defer s.generationMu.RUnlock()
	if s.closed {
		return scanLease{err: ErrScannerClosed, fingerprint: s.fingerprintLocked(), scan: func([]byte, ScanMeta) ([]Match, error) { return nil, ErrScannerClosed }}
	}
	generation := scannerGeneration{
		rules: s.rules.Load(), bigRules: s.bigRules.Load(), markerRules: s.markerRules.Load(),
		deny: s.denylist.Load(), topEpoch: s.topMatches.Epoch(),
	}
	s.generation.retain()
	return scanLease{
		fingerprint:  s.fingerprintLocked(),
		releaseToken: &leaseRelease{pin: s.generation},
		scan: func(buf []byte, meta ScanMeta) ([]Match, error) {
			return s.scanGeneration(buf, meta, generation)
		},
	}
}

func leaseScanEngine(engine ScanEngine) scanLease {
	if e, ok := engine.(interface{ acquireScanLease() scanLease }); ok {
		return e.acquireScanLease()
	}
	// ScanEngine's public API is unchanged; fixed-generation test/third-party
	// engines retain the existing behavior. The production Scanner pins rules.
	return scanLease{fingerprint: engine.Fingerprint(), scan: engine.Scan}
}

// release marks the end of the request's ownership, including cache publication.
func (l scanLease) release() {
	if l.releaseToken != nil {
		l.releaseToken.once.Do(func() { l.releaseToken.pin.release() })
	}
	runtime.KeepAlive(l)
}
