package mailstrix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	yara "github.com/hillu/go-yara/v4"
)

// Main-only fixtures deliberately exercise P7 without P8's auxiliary finalizers.
func p7Scanner(t *testing.T, logf func(string, ...any)) *Scanner {
	t.Helper()
	saved := serializeRules
	serializeRules = func(*yara.Rules, io.Writer) error { return errors.New("P7 main-only fixture") }
	t.Cleanup(func() { serializeRules = saved })
	s, err := NewScanner(&Config{RulesDir: writeRules(t, "rule Stable { condition: false }"), BigFileThreshold: 1}, logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
func p7Owner(t *testing.T, s *Scanner) *nativeRulesOwner {
	t.Helper()
	s.generationMu.RLock()
	defer s.generationMu.RUnlock()
	if len(s.generation.owners) != 1 {
		t.Fatalf("main fixture owners=%d want=1", len(s.generation.owners))
	}
	return s.generation.owners[0]
}
func p7Alive(t *testing.T, o *nativeRulesOwner, label string) {
	t.Helper()
	o.mu.Lock()
	alive := o.refs > 0 && !o.destroyClaimed && !o.destroyed
	o.mu.Unlock()
	if !alive {
		t.Fatalf("%s: native owner dead before native use", label)
	}
}
func p7Dead(t *testing.T, o *nativeRulesOwner) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.refs != 0 || !o.destroyed {
		t.Fatalf("native owner not destroyed after final release: refs=%d destroyed=%v", o.refs, o.destroyed)
	}
}
func TestP7HeldScanTwoReloads(t *testing.T) {
	awaitObserverCount(t, &observedRuleGenerations, 0)
	baseline := observedRuleGenerations.count()
	reached, resume := make(chan struct{}), make(chan struct{})
	s := p7Scanner(t, func(format string, _ ...any) {
		if strings.HasPrefix(format, "WARNING: oversized buffer") {
			close(reached)
			<-resume
		}
	})
	owner := p7Owner(t, s)
	oldFP := s.Fingerprint()
	result := make(chan error, 1)
	var resumeOnce sync.Once
	t.Cleanup(func() {
		owner.mu.Lock()
		alive := owner.refs > 0 && !owner.destroyClaimed
		owner.mu.Unlock()
		if alive {
			resumeOnce.Do(func() { close(resume) })
			if e := generationWait(t, result); e != nil {
				t.Error(e)
			}
		}
	})
	go func() {
		m, e := s.Scan([]byte("ordinary"), ScanMeta{})
		if e == nil && len(m) != 0 {
			e = fmt.Errorf("old verdict changed: %v", m)
		}
		result <- e
	}()
	generationWait(t, reached)
	for range 2 {
		generationWrite(t, s.srcDir, "rule Stable { condition: true }")
		if e := s.Reload(); e != nil {
			t.Fatal(e)
		}
	}
	// Fail before releasing the barrier: a disabled-retain control never executes
	// any native method on the freed object, including Scanner.Destroy.
	p7Alive(t, owner, "held scan after two reloads")
	if s.Fingerprint() == oldFP || s.RuleGenerations() != baseline+2 {
		t.Fatalf("pinned native count=%d want=%d", s.RuleGenerations(), baseline+2)
	}
	resumeOnce.Do(func() { close(resume) })
	if e := generationWait(t, result); e != nil {
		t.Fatal(e)
	}
	p7Dead(t, owner)
	if s.RuleGenerations() != baseline+1 {
		t.Fatalf("main-only native gauge=%d want=%d", s.RuleGenerations(), baseline+1)
	}
	if m, e := s.Scan([]byte("ordinary"), ScanMeta{}); e != nil || len(m) != 1 {
		t.Fatalf("new verdict=%v err=%v", m, e)
	}
}
func TestP7CopiedLeaseReleaseAndClose(t *testing.T) {
	s := p7Scanner(t, func(string, ...any) {})
	owner := p7Owner(t, s)
	lease := s.acquireScanLease()
	copied := lease
	s.Close()
	s.Close()
	p7Alive(t, owner, "lease across Close")
	if m, e := lease.scan([]byte("ordinary"), ScanMeta{Filename: "ordinary.txt"}); e != nil || len(m) != 0 {
		t.Fatalf("held closed scan=%v %v", m, e)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); copied.release() }()
	}
	wg.Wait()
	lease.release()
	p7Dead(t, owner)
	if _, e := s.Scan(nil, ScanMeta{}); !errors.Is(e, ErrScannerClosed) {
		t.Fatalf("closed scan error=%v", e)
	}
	if e := s.Reload(); !errors.Is(e, ErrScannerClosed) {
		t.Fatalf("closed reload error=%v", e)
	}
	if s.RuleCount() != 1 || s.Fingerprint() == "" {
		t.Fatal("closed metadata disappeared")
	}
}
func TestP7ScannerDependencies(t *testing.T) {
	for _, kind := range []string{"idle", "checked-out", "late"} {
		t.Run(kind, func(t *testing.T) {
			s := p7Scanner(t, func(string, ...any) {})
			owner := p7Owner(t, s)
			lease := s.acquireScanLease()
			var sc *yara.Scanner
			var gen *scannerGen
			if kind == "late" {
				getScannerAfterSelectHook = func() {
					getScannerAfterSelectHook = nil
					if e := s.Reload(); e != nil {
						t.Fatal(e)
					}
				}
				t.Cleanup(func() { getScannerAfterSelectHook = nil })
			}
			sc, gen = poolGet(t, s, owner.rules)
			if kind == "idle" {
				s.putScanner(sc, gen)
			}
			if kind != "late" {
				if e := s.Reload(); e != nil {
					t.Fatal(e)
				}
			}
			lease.release()
			if kind == "idle" {
				p7Dead(t, owner)
				return
			}
			// The lease and old root are gone: only the scanner's own dependency remains.
			owner.mu.Lock()
			alive := owner.refs > 0 && !owner.destroyed
			owner.mu.Unlock()
			if !alive {
				// Safe control failure: suppress scanner cleanup before reporting; never
				// destroy a native scanner after its rules dependency was mutated away.
				gen.mu.Lock()
				dep := gen.dependencies[sc]
				gen.mu.Unlock()
				runtime.SetFinalizer(dep, nil)
				runtime.SetFinalizer(sc, nil)
				t.Fatal("scanner dependency: native owner dead before Scanner.Destroy")
			}
			if kind == "late" && !gen.retired {
				t.Fatal("late scanner installed stale live pool")
			}
			s.putScanner(sc, gen)
			p7Dead(t, owner)
		})
	}
}
func TestP7ManagedAliasExactOnce(t *testing.T) {
	o := new(ruleGenerationObserver)
	r := observerRules(t)
	a := o.adopt(r)
	b := o.adopt(r)
	if a == nil || b == nil {
		t.Fatal("non-nil native rules were not adopted")
	}
	if a != b {
		runtime.SetFinalizer(a, nil)
		runtime.SetFinalizer(b, nil)
		runtime.SetFinalizer(r, nil)
		t.Fatal("duplicate native owner for aliased Rules identity before native use")
	}
	o.observe(r)
	if o.count() != 1 {
		t.Fatal("managed alias counted twice")
	}
	a.release()
	p7Alive(t, b, "retained auxiliary alias")
	b.release()
	p7Dead(t, b)
	b.destroy()
	if o.count() != 0 {
		t.Fatal("alias native object destroyed more than once or retained")
	}
	// Actual cross-generation main/auxiliary alias transfer uses the same owner.
	s := p7Scanner(t, func(string, ...any) {})
	old := p7Owner(t, s)
	s.bigRules.Store(old.rules)
	if e := s.Reload(); e != nil {
		t.Fatal(e)
	}
	p7Alive(t, old, "managed main retained as auxiliary")
	for range 2 {
		if e := s.Reload(); e != nil {
			t.Fatal(e)
		}
	}
	p7Alive(t, old, "managed auxiliary across two more reloads")
	s.Close()
	p7Dead(t, old)
}
func TestP7RollbackAndFailedReload(t *testing.T) {
	s := p7Scanner(t, func(string, ...any) {})
	owner := p7Owner(t, s)
	fp, content, manifest := s.Fingerprint(), s.contentFP.Load(), s.loadedManifest.Load()
	generationWrite(t, s.srcDir, "broken source")
	deny := map[string]struct{}{"stable": {}}
	if e := s.reloadWithDenylist(context.Background(), &deny); e == nil {
		t.Fatal("malformed main accepted")
	}
	if s.rules.Load() != owner.rules || s.contentFP.Load() != content || s.loadedManifest.Load() != manifest {
		t.Fatal("main failure changed native/content/manifest identity")
	}
	if s.Fingerprint() == fp {
		t.Fatal("existing failed-load deny override lost")
	}
	p7Alive(t, owner, "failed main reload")
	// A preparation panic discards an adopted fresh candidate after both locks
	// unlock. Its gauge disappears synchronously, without collection.
	generationWrite(t, s.srcDir, "rule Stable { condition: true }")
	before := s.RuleGenerations()
	observedRuleGenerations.mu.Lock()
	observedRuleGenerations.beforeDestroy = func(*yara.Rules) {
		if !s.mu.TryLock() {
			t.Error("actual native destruction under reload mutex")
		} else {
			s.mu.Unlock()
		}
		if !s.generationMu.TryLock() {
			t.Error("actual native destruction under publication mutex")
		} else {
			s.generationMu.Unlock()
		}
	}
	observedRuleGenerations.mu.Unlock()
	defer func() {
		observedRuleGenerations.mu.Lock()
		observedRuleGenerations.beforeDestroy = nil
		observedRuleGenerations.mu.Unlock()
	}()
	oldLog := s.logf
	s.logf = func(format string, _ ...any) {
		if strings.HasPrefix(format, "loaded %d YARA rules from") {
			panic("candidate rollback")
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected preparation panic")
			}
		}()
		if e := s.Reload(); e != nil {
			t.Errorf("unexpected preparation error: %v", e)
		}
	}()
	s.logf = oldLog
	if s.RuleGenerations() != before || s.rules.Load() != owner.rules {
		t.Fatal("discarded candidate was not rolled back")
	}
	if !s.mu.TryLock() {
		t.Fatal("rollback retained reload lock")
	}
	s.mu.Unlock()
	if !s.generationMu.TryLock() {
		t.Fatal("rollback retained publication lock")
	}
	s.generationMu.Unlock()
	if e := s.Reload(); e != nil {
		t.Fatal(e)
	}
	p7Dead(t, owner)
}
func TestP7LeasePathsBalance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := p7Scanner(t, func(string, ...any) {})
		srv := newCachingServer(s, "")
		body := []byte("ordinary")
		meta := ScanMeta{RawKey: streamDedupKey(body)}
		pin := s.generation
		check := func() {
			pin.mu.Lock()
			refs := pin.refs
			pin.mu.Unlock()
			if refs != 1 {
				t.Fatalf("request lease refs=%d want root only", refs)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		outcome, status, fp := srv.lookupScanOutcomeStarted(ctx, "", body, meta, nil)
		if status != "canceled" || !errors.Is(outcome.err, context.Canceled) || fp != s.Fingerprint() {
			t.Fatal(status)
		}
		check()
		outcome, status, fp = srv.lookupScanOutcomeStarted(context.Background(), "", body, meta, nil)
		if status != "miss" || outcome.err != nil || fp != s.Fingerprint() {
			t.Fatal(status)
		}
		check()
		outcome, status, fp = srv.lookupScanOutcomeStarted(context.Background(), "", body, meta, nil)
		if status != "hit" || outcome.err != nil || fp != s.Fingerprint() {
			t.Fatal(status)
		}
		check()
		srv.FlushCache()
		for len(srv.sem) < cap(srv.sem) {
			srv.sem <- struct{}{}
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			o, status, fp := srv.lookupScanOutcomeStarted(context.Background(), "", body, meta, nil)
			if !errors.Is(o.err, errScanBusy) || status != "miss" || fp != s.Fingerprint() {
				t.Errorf("busy error=%v", o.err)
			}
		}()
		<-done
		for len(srv.sem) > 0 {
			<-srv.sem
		}
		check()
		s.Close()
		o, status, fp := srv.lookupScanOutcomeStarted(context.Background(), "", body, meta, nil)
		if !errors.Is(o.err, ErrScannerClosed) || status != "miss" || fp != s.Fingerprint() {
			t.Fatalf("closed dispatch error=%v", o.err)
		}
	})
}
func TestP7AbandonedOwnerFallback(t *testing.T) {
	o := new(ruleGenerationObserver)
	func() { r := observerRules(t); a := o.adopt(r); runtime.KeepAlive(a) }()
	awaitObserverCount(t, o, 0)
}

// The adapter injects dispatch failures while retaining a real Scanner lease;
// it does not replace ownership, cache, flight or release implementations.
type p7FailureEngine struct {
	*Scanner
	mode string
}

func (e *p7FailureEngine) acquireScanLease() scanLease {
	lease := e.Scanner.acquireScanLease()
	lease.scan = func([]byte, ScanMeta) ([]Match, error) {
		if e.mode == "panic" {
			panic("P7 injected panic")
		}
		return nil, errors.New("P7 injected error")
	}
	return lease
}
func TestP7ErrorPanicBalance(t *testing.T) {
	for _, mode := range []string{"error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			s := p7Scanner(t, func(string, ...any) {})
			srv := newCachingServer(&p7FailureEngine{Scanner: s, mode: mode}, "")
			for range 2 {
				outcome, status, fp := srv.lookupScanOutcomeStarted(context.Background(), "", []byte("ordinary"), ScanMeta{}, nil)
				if outcome.err == nil || status == "hit" || fp != s.Fingerprint() {
					t.Fatalf("%s dispatch cached or certified: %v %s", mode, outcome.err, status)
				}
				s.generation.mu.Lock()
				refs := s.generation.refs
				s.generation.mu.Unlock()
				if refs != 1 {
					t.Fatalf("%s lease refs=%d want=1", mode, refs)
				}
			}
		})
	}
}
func TestP7ConcurrentAcquirePublishRelease(t *testing.T) {
	s := p7Scanner(t, func(string, ...any) {})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				l := s.acquireScanLease()
				m, e := l.scan([]byte("ordinary"), ScanMeta{})
				if e != nil || len(m) != 0 {
					t.Errorf("concurrent verdict=%v %v", m, e)
				}
				l.release()
				l.release()
			}
		}()
	}
	for range 3 {
		if e := s.Reload(); e != nil {
			t.Fatal(e)
		}
	}
	wg.Wait()
	s.generation.mu.Lock()
	refs := s.generation.refs
	s.generation.mu.Unlock()
	if refs != 1 {
		t.Fatalf("concurrent lease refs=%d want=1", refs)
	}
}

func TestP7ConstructionErrorBalancesDependency(t *testing.T) {
	s := p7Scanner(t, func(string, ...any) {})
	owner := p7Owner(t, s)
	saved := newNativeScanner
	t.Cleanup(func() { newNativeScanner = saved })
	newNativeScanner = func(r *yara.Rules) (*yara.Scanner, error) {
		owner.mu.Lock()
		refs := owner.refs
		owner.mu.Unlock()
		if refs != 2 || r != owner.rules {
			t.Fatalf("before constructor refs=%d rules=%p", refs, r)
		}
		return nil, errors.New("P7 constructor error")
	}
	if _, _, e := s.getScanner(owner.rules); e == nil {
		t.Fatal("constructor failure lost")
	}
	owner.mu.Lock()
	refs := owner.refs
	owner.mu.Unlock()
	if refs != 1 {
		t.Fatalf("failed constructor dependency refs=%d want=1", refs)
	}
}
func TestP7NilAndTerminalOwnerStates(t *testing.T) {
	var g *generationPin
	g.retain()
	g.release()
	var o *nativeRulesOwner
	o.retain()
	o.release()
	observer := new(ruleGenerationObserver)
	if observer.adopt(nil) != nil || observer.retainManaged(nil) != nil {
		t.Fatal("nil object gained owner")
	}
	expectPanic := func(name string, fn func()) {
		t.Helper()
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not reject terminal state", name)
				}
			}()
			fn()
		}()
	}
	retired := &generationPin{}
	expectPanic("generation resurrection", retired.retain)
	expectPanic("generation underflow", retired.release)
	dead := &nativeRulesOwner{}
	expectPanic("owner resurrection", dead.retain)
	expectPanic("owner underflow", dead.release)
	// Aliases are deduplicated even when two auxiliary fields share the same main.
	s := p7Scanner(t, func(string, ...any) {})
	old := p7Owner(t, s)
	s.bigRules.Store(old.rules)
	s.markerRules.Store(old.rules)
	if e := s.Reload(); e != nil {
		t.Fatal(e)
	}
	s.generationMu.RLock()
	owners := len(s.generation.owners)
	s.generationMu.RUnlock()
	if owners != 2 {
		t.Fatalf("main and two retained aliases have %d owners want=2", owners)
	}
	s.Close()
	p7Dead(t, old)
}

// The old install passes its final live check, then lands after publication.
// A second reload detaches it before its post-CAS cleanup. The detached pool
// receives an idle scanner and becomes its rules' sole owner before retirement.
func TestP7DelayedInstallRetiresOutsideLocks(t *testing.T) {
	s := p7Scanner(t, func(string, ...any) {})
	owner := p7Owner(t, s)
	lease := s.acquireScanLease()
	defer lease.release()
	beforeCAS, allowCAS := make(chan struct{}), make(chan struct{})
	afterCAS, allowPostCAS := make(chan struct{}), make(chan struct{})
	detached, allowRetire := make(chan struct{}), make(chan struct{})
	installGenBeforeCASHook = func(r *yara.Rules) {
		if r == owner.rules {
			close(beforeCAS)
			<-allowCAS
		}
	}
	installGenAfterCASHook = func(g *scannerGen) {
		if g.rules == owner.rules {
			close(afterCAS)
			<-allowPostCAS
		}
	}
	retireStaleAfterCASHook = func(g *scannerGen) {
		if g.rules == owner.rules {
			close(detached)
			<-allowRetire
		}
	}
	defer func() {
		installGenBeforeCASHook, installGenAfterCASHook, retireStaleAfterCASHook = nil, nil, nil
	}()
	type acquired struct {
		sc  *yara.Scanner
		gen *scannerGen
		err error
	}
	ready := make(chan acquired, 1)
	go func() { sc, gen, err := s.getScanner(owner.rules); ready <- acquired{sc, gen, err} }()
	generationWait(t, beforeCAS)
	generationWrite(t, s.srcDir, "rule Second { condition: false }")
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	p7Alive(t, owner, "delayed install before native construction")
	close(allowCAS)
	generationWait(t, afterCAS)
	reloaded := make(chan error, 1)
	go func() { reloaded <- s.Reload() }()
	generationWait(t, detached)
	close(allowPostCAS)
	got := generationWait(t, ready)
	if got.err != nil {
		t.Fatal(got.err)
	}
	p7Alive(t, owner, "delayed scanner before idle return")
	s.putScanner(got.sc, got.gen)
	wantGen(t, "detached before drain", got.gen, 1, false)
	lease.release()
	owner.mu.Lock()
	refs := owner.refs
	owner.mu.Unlock()
	if refs != 1 {
		t.Fatalf("idle scanner must be sole native owner: refs=%d", refs)
	}
	destroyed := false
	observedRuleGenerations.mu.Lock()
	observedRuleGenerations.beforeDestroy = func(r *yara.Rules) {
		if r != owner.rules {
			return
		}
		destroyed = true
		// Safe pre-destruction assertion: never call a native method on freed rules.
		if !s.mu.TryLock() {
			t.Error("delayed idle native destruction under reload mutex")
		} else {
			s.mu.Unlock()
		}
		if !s.generationMu.TryLock() {
			t.Error("delayed idle native destruction under publication mutex")
		} else {
			s.generationMu.Unlock()
		}
	}
	observedRuleGenerations.mu.Unlock()
	defer func() {
		observedRuleGenerations.mu.Lock()
		observedRuleGenerations.beforeDestroy = nil
		observedRuleGenerations.mu.Unlock()
	}()
	close(allowRetire)
	if err := generationWait(t, reloaded); err != nil {
		t.Fatal(err)
	}
	if !destroyed {
		t.Fatal("delayed idle destruction assertion was not reached")
	}
	wantGen(t, "detached after drain", got.gen, 0, true)
	p7Dead(t, owner)
}
