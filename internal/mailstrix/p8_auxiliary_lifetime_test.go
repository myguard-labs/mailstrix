package mailstrix

import (
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"

	yara "github.com/hillu/go-yara/v4"
)

func p8Scanner(t *testing.T) *Scanner {
	t.Helper()
	s, e := NewScanner(&Config{RulesDir: writeRules(t, "rule Main { condition: false } rule Marker : marker { condition: true }"), BigFileRules: writeRules(t, "rule Big { condition: true }"), BigFileThreshold: 1}, func(string, ...any) {})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}

func p8Owner(t *testing.T, s *Scanner, r *yara.Rules) *nativeRulesOwner {
	t.Helper()
	s.generationMu.RLock()
	defer s.generationMu.RUnlock()
	for _, o := range s.generation.owners {
		if o.rules == r {
			return o
		}
	}
	t.Fatal("auxiliary Rules missing explicit generation owner")
	return nil
}

func TestP8PinnedAuxiliaryRetirement(t *testing.T) {
	s := p8Scanner(t)
	big, marker := s.bigRules.Load(), s.markerRules.Load()
	bo, mo := p8Owner(t, s, big), p8Owner(t, s, marker)
	lease := s.acquireScanLease()
	defer lease.release()
	for range 2 {
		if e := s.Reload(); e != nil {
			t.Fatal(e)
		}
	}
	// Check ownership before native use: the disabled-retain control is safe.
	p7Alive(t, bo, "pinned big")
	p7Alive(t, mo, "pinned marker")
	if m, e := lease.scan([]byte("ordinary"), ScanMeta{}); e != nil || ruleNames(m) != "[Big]" {
		t.Fatalf("old auxiliary scan: %v %v", m, e)
	}
	if m, e := s.scanOne(marker, []byte("ordinary"), scanVars{}, 0); e != nil || ruleNames(m) != "[Marker]" {
		t.Fatalf("old marker scan: %v %v", m, e)
	}
	lease.release()
	p7Dead(t, bo)
	p7Dead(t, mo)
}

func TestP8FailedAuxiliaryRetainsOwnerAndIdentity(t *testing.T) {
	s := p8Scanner(t)
	big, marker := s.bigRules.Load(), s.markerRules.Load()
	bo, mo := p8Owner(t, s, big), p8Owner(t, s, marker)
	bigID, markerID := s.bigContent, s.markerContent
	generationWrite(t, s.bigSrcDir, "malformed big source")
	saved := serializeRules
	serializeRules = func(*yara.Rules, io.Writer) error { return errors.New("forced marker failure") }
	defer func() { serializeRules = saved }()
	for range 2 {
		generationWrite(t, s.srcDir, "rule Changed { condition: false }")
		if e := s.Reload(); e != nil {
			t.Fatal(e)
		}
		if s.bigRules.Load() != big || s.markerRules.Load() != marker || s.bigContent != bigID || s.markerContent != markerID {
			t.Fatal("failed auxiliary reload changed retained pointer or identity")
		}
		if p8Owner(t, s, big) != bo || p8Owner(t, s, marker) != mo {
			t.Fatal("failed auxiliary reload replaced owner")
		}
		p7Alive(t, bo, "retained big")
		p7Alive(t, mo, "retained marker")
		if m, e := s.Scan([]byte("ordinary"), ScanMeta{}); e != nil || ruleNames(m) != "[Big]" {
			t.Fatalf("retained big scan: %v %v", m, e)
		}
		if m, e := s.scanOne(marker, []byte("ordinary"), scanVars{}, 0); e != nil || ruleNames(m) != "[Marker]" {
			t.Fatalf("retained marker scan: %v %v", m, e)
		}
	}
	s.Close()
	p7Dead(t, bo)
	p7Dead(t, mo)
	s.Close()
}

func TestP8AuxiliaryAliasDeduplicated(t *testing.T) {
	s := p8Scanner(t)
	oldMain := s.rules.Load()
	o := p8Owner(t, s, oldMain)
	// Publish an auxiliary-only owner shared by both slots, then transfer it to
	// another generation. Each publication owns exactly one reference to it.
	aux := observerRules(t)
	b := &reloadBundle{rules: oldMain, bigRules: aux, markerRules: aux, deny: map[string]struct{}{}}
	retired := s.publishReload(b)
	retired.release()
	owner := p8Owner(t, s, aux)
	if len(s.generation.owners) != 2 {
		t.Fatal("auxiliary aliases not deduplicated")
	}
	retired = s.publishReload(b)
	retired.release()
	if p8Owner(t, s, aux) != owner {
		t.Fatal("auxiliary alias owner changed")
	}
	owner.mu.Lock()
	refs := owner.refs
	owner.mu.Unlock()
	if refs != 1 {
		t.Fatalf("auxiliary alias refs=%d want=1", refs)
	}
	p7Alive(t, owner, "transferred alias")
	s.Close()
	p7Dead(t, owner)
	p7Dead(t, o)
}

func TestP8ClosePinnedAuxiliariesAndNil(t *testing.T) {
	s := p8Scanner(t)
	bo, mo := p8Owner(t, s, s.bigRules.Load()), p8Owner(t, s, s.markerRules.Load())
	lease := s.acquireScanLease()
	defer lease.release()
	s.Close()
	p7Alive(t, bo, "big across Close")
	p7Alive(t, mo, "marker across Close")
	if m, e := lease.scan([]byte("ordinary"), ScanMeta{}); e != nil || ruleNames(m) != "[Big]" {
		t.Fatalf("closed pinned auxiliary: %v %v", m, e)
	}
	lease.release()
	p7Dead(t, bo)
	p7Dead(t, mo)
	// No auxiliaries is a valid generation, including a repeated Close.
	mainOnly := p7Scanner(t, func(string, ...any) {})
	mainOnly.Close()
	mainOnly.Close()
}

func TestP8CandidateRollbackAndDestructionLocks(t *testing.T) {
	s := p8Scanner(t)
	big := s.bigRules.Load()
	// Strong identities are collected before rollback; finalizers cannot change
	// this fixture's membership or its per-object destruction counts.
	var hookMu sync.Mutex
	candidates := make(map[*yara.Rules]int)
	unrelated := []*yara.Rules{observerRules(t), observerRules(t)}
	for _, r := range unrelated {
		observedRuleGenerations.observe(r)
	}
	existing := make(map[weak.Pointer[yara.Rules]]bool)
	observedRuleGenerations.mu.Lock()
	for key := range observedRuleGenerations.managed {
		existing[key] = true
	}
	observedRuleGenerations.mu.Unlock()
	saved := serializeRules
	serializeRules = func(main *yara.Rules, _ io.Writer) error {
		hookMu.Lock()
		candidates[main] = 0
		observedRuleGenerations.mu.Lock()
		for key := range observedRuleGenerations.managed {
			r := key.Value()
			if !existing[key] && r != nil && r != main {
				candidates[r] = 0
			}
		}
		observedRuleGenerations.mu.Unlock()
		n := len(candidates)
		hookMu.Unlock()
		if n != 2 {
			t.Errorf("rollback candidate identities=%d want=2", n)
		}
		// Execute the unmanaged finalizer's exact callback body concurrently while
		// Reload still owns s.mu. Neither identity belongs to this rollback.
		var done sync.WaitGroup
		for _, r := range unrelated {
			done.Add(1)
			go func(r *yara.Rules) { defer done.Done(); observedRuleGenerations.destroy(r, weak.Make(r)) }(r)
		}
		done.Wait()
		panic("P8 marker preparation rollback")
	}
	defer func() { serializeRules = saved }()
	observedRuleGenerations.mu.Lock()
	observedRuleGenerations.beforeDestroy = func(r *yara.Rules) {
		hookMu.Lock()
		_, selected := candidates[r]
		if selected {
			candidates[r]++
		}
		hookMu.Unlock()
		if !selected {
			return
		}
		if !s.mu.TryLock() {
			t.Error("auxiliary destruction holds reload lock")
		} else {
			s.mu.Unlock()
		}
		if !s.generationMu.TryLock() {
			t.Error("auxiliary destruction holds publication lock")
		} else {
			s.generationMu.Unlock()
		}
		// Check this identity, rather than a global count affected by finalizers.
		counted := p8CandidateClaimed(&observedRuleGenerations, r)
		if !counted {
			t.Error("candidate identity missing before native Destroy")
		}
	}
	observedRuleGenerations.mu.Unlock()
	defer func() {
		observedRuleGenerations.mu.Lock()
		observedRuleGenerations.beforeDestroy = nil
		observedRuleGenerations.mu.Unlock()
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("preparation panic missing")
			}
		}()
		_ = s.Reload()
	}()
	hookMu.Lock()
	defer hookMu.Unlock()
	if len(candidates) != 2 {
		t.Fatalf("rollback candidate identities=%d want=2", len(candidates))
	}
	for r, n := range candidates {
		if n != 1 {
			t.Errorf("rollback candidate destruction count=%d want=1", n)
		}
		observedRuleGenerations.mu.Lock()
		state := observedRuleGenerations.live[weak.Make(r)]
		_, managed := observedRuleGenerations.managed[weak.Make(r)]
		observedRuleGenerations.mu.Unlock()
		if state == nil || !state.claimed || managed {
			t.Error("rollback candidate remains live after Destroy")
		}
	}
	if s.bigRules.Load() != big {
		t.Fatal("auxiliary candidate rollback changed published big rules")
	}
}

// An isolated observer makes count sequencing exact even when unrelated global
// finalizers run. Both claimed objects overlap before their native destruction.
func TestP8CandidateCountUntilDestroy(t *testing.T) {
	o := new(ruleGenerationObserver)
	first, second := observerRules(t), observerRules(t)
	owners := []*nativeRulesOwner{o.adopt(first), o.adopt(second)}
	entered := make(chan *yara.Rules, 2)
	unblock := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	defer release()
	o.beforeDestroy = func(r *yara.Rules) { entered <- r; <-unblock }
	var done sync.WaitGroup
	for _, owner := range owners {
		done.Add(1)
		go func(owner *nativeRulesOwner) { defer done.Done(); owner.release() }(owner)
	}
	a, b := generationWait(t, entered), generationWait(t, entered)
	if a == b || (a != first && a != second) || (b != first && b != second) {
		t.Error("overlapping candidate identities differ from fixture")
	}
	// Both callbacks are waiting, so no other isolated observer operation can
	// contend with this explicit outside-observer assertion.
	if !o.mu.TryLock() {
		t.Error("candidate destruction holds observer lock")
	} else {
		o.mu.Unlock()
	}
	if got := o.count(); got != 2 {
		t.Errorf("claimed candidates count before native Destroy=%d want=2", got)
	}
	release()
	done.Wait()
	if got := o.count(); got != 0 {
		t.Errorf("candidate count after native Destroy=%d want=0", got)
	}
}

// Read the selected identity while tolerating another observer operation. The
// callback itself must run outside mu; the isolated regression proves that.
func p8CandidateClaimed(o *ruleGenerationObserver, r *yara.Rules) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	state := o.live[weak.Make(r)]
	return state != nil && state.claimed
}

func TestP8CandidateUnrelatedObserverContention(t *testing.T) {
	o := new(ruleGenerationObserver)
	r := observerRules(t)
	owner := o.adopt(r)
	entered := make(chan struct{})
	resume := make(chan struct{})
	result := make(chan bool, 1)
	done := make(chan struct{})
	o.beforeDestroy = func(r *yara.Rules) {
		close(entered)
		<-resume
		result <- p8CandidateClaimed(o, r)
	}
	go func() { owner.release(); close(done) }()
	generationWait(t, entered)
	// The callback has entered outside the observer lock. Hold that lock as an
	// unrelated operation, then allow the identity read to attempt acquisition.
	o.mu.Lock()
	close(resume)
	// Inspect the actual blocked reader stack, not elapsed time. A TryLock reader
	// returns false while this operation still owns mu and fails this regression.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-deadline.C:
			o.mu.Unlock()
			generationWait(t, done)
			t.Fatal("candidate identity reader did not reach observer mutex wait")
		case counted := <-result:
			o.mu.Unlock()
			generationWait(t, done)
			t.Fatalf("unrelated observer contention returned early: claimed=%v", counted)
		default:
		}
		buf := make([]byte, 64*1024)
		var stacks string
		for {
			n := runtime.Stack(buf, true)
			if n < len(buf) {
				stacks = string(buf[:n])
				break
			}
			buf = make([]byte, len(buf)*2)
		}
		blocked := false
		for _, stack := range strings.Split(stacks, "\n\n") {
			if strings.Contains(stack, "p8CandidateClaimed(") && strings.Contains(stack, "[sync.Mutex.Lock]") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		runtime.Gosched()
	}
	o.mu.Unlock()
	if !generationWait(t, result) {
		t.Error("candidate identity missing after unrelated observer contention")
	}
	generationWait(t, done)
	if got := o.count(); got != 0 {
		t.Errorf("candidate count after contention Destroy=%d want=0", got)
	}
}
