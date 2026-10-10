package mailstrix

import (
	"errors"
	"io"
	"testing"

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
	before := s.RuleGenerations()
	big := s.bigRules.Load()
	saved := serializeRules
	serializeRules = func(*yara.Rules, io.Writer) error { panic("P8 marker preparation rollback") }
	defer func() { serializeRules = saved }()
	destroyed := 0
	observedRuleGenerations.mu.Lock()
	observedRuleGenerations.beforeDestroy = func(*yara.Rules) {
		destroyed++
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
		// count takes the observer lock: destruction must run outside it, and the
		// object being destroyed must still count until native Destroy completes.
		if s.RuleGenerations() <= before {
			t.Error("candidate removed from count before native Destroy")
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
	if destroyed != 2 || s.RuleGenerations() != before || s.bigRules.Load() != big {
		t.Fatalf("auxiliary candidate rollback: destroys=%d count=%d want=%d", destroyed, s.RuleGenerations(), before)
	}
}
