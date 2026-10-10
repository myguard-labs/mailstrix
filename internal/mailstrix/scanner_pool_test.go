package mailstrix

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	yara "github.com/hillu/go-yara/v4"
)

// The scanner pool is unexported (Scanner.getScanner/putScanner and the
// scannerGen slots), so these AUD-P3 tests live in the package rather than in
// ci/: no exported API exposes scanner reuse or retirement.

func poolGet(t *testing.T, s *Scanner, rules *yara.Rules) (*yara.Scanner, *scannerGen) {
	t.Helper()
	sc, gen, err := s.getScanner(rules)
	if err != nil {
		t.Fatalf("getScanner: %v", err)
	}
	return sc, gen
}

// wantGen fails unless g holds wantIdle idle scanners and has the wanted
// retired state.
func wantGen(t *testing.T, label string, g *scannerGen, wantIdle int, wantRetired bool) {
	t.Helper()
	g.mu.Lock()
	idle, retired := len(g.free), g.retired
	g.mu.Unlock()
	if idle != wantIdle || retired != wantRetired {
		t.Fatalf("%s: idle=%d retired=%v, want %d/%v", label, idle, retired, wantIdle, wantRetired)
	}
}

// mainAndBig returns the scanner's distinct main and big-file rules.
func mainAndBig(t *testing.T, s *Scanner) (*yara.Rules, *yara.Rules) {
	t.Helper()
	main, big := s.rules.Load(), s.bigRules.Load()
	if main == nil || big == nil || main == big {
		t.Fatalf("need distinct main and big rules: main=%p big=%p", main, big)
	}
	return main, big
}

// Positive: alternating main and big-file scans reuse each set's pooled scanner
// instead of retiring the other set's generation on every switch.
func TestScannerPoolAlternatingMainBigReuses(t *testing.T) {
	s := newBigScanner(t, 1<<20)
	main, big := mainAndBig(t, s)
	m0, mg := poolGet(t, s, main)
	s.putScanner(m0, mg)
	b0, bg := poolGet(t, s, big)
	s.putScanner(b0, bg)
	for i := 0; i < 4; i++ {
		m, g := poolGet(t, s, main)
		if m != m0 || g != mg {
			t.Fatalf("switch %d: main scanner not reused (got %p gen %p, want %p gen %p)", i, m, g, m0, mg)
		}
		s.putScanner(m, g)
		b, h := poolGet(t, s, big)
		if b != b0 || h != bg {
			t.Fatalf("switch %d: big scanner not reused (got %p gen %p, want %p gen %p)", i, b, h, b0, bg)
		}
		s.putScanner(b, h)
	}
	wantGen(t, "main gen", mg, 1, false)
	wantGen(t, "big gen", bg, 1, false)
}

// Boundary: with no big-file ruleset only the main set is pooled.
func TestScannerPoolNoBigRules(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	if s.bigRules.Load() != nil {
		t.Fatal("expected nil bigRules")
	}
	main := s.rules.Load()
	m0, g0 := poolGet(t, s, main)
	s.putScanner(m0, g0)
	m1, g1 := poolGet(t, s, main)
	if m1 != m0 || g1 != g0 {
		t.Fatal("main scanner not reused without big rules")
	}
	s.putScanner(m1, g1)
	if s.bigScanners.Load() != nil {
		t.Fatal("big pool installed although bigRules is nil")
	}
	// putScanner tolerates nil inputs.
	s.putScanner(nil, g0)
	s.putScanner(m0, nil)
}

// Boundary: a reload that unsets the big-file ruleset retires its pool on the
// next pooled scan of the main set.
func TestScannerPoolBigRulesUnsetRetiresBigPool(t *testing.T) {
	s := newBigScanner(t, 1<<20)
	main, big := mainAndBig(t, s)
	b0, bg := poolGet(t, s, big)
	s.putScanner(b0, bg)
	s.bigRules.Store(nil)
	m, g := poolGet(t, s, main)
	s.putScanner(m, g)
	if s.bigScanners.Load() != nil {
		t.Fatal("big pool kept after bigRules was unset")
	}
	wantGen(t, "unset big gen", bg, 0, true)
}

// Negative/regression: Reload replaces both rules pointers; idle scanners of the
// old generations are destroyed and never handed out again, an in-flight
// old-rules scanner is destroyed on put, and a scan still holding the old rules
// gets a one-off generation that never becomes the pool.
func TestScannerPoolReloadRetiresOldGenerations(t *testing.T) {
	s := newBigScanner(t, 1<<20)
	lease := s.acquireScanLease()
	defer lease.release()
	oldMain, oldBig := mainAndBig(t, s)
	idle, mg := poolGet(t, s, oldMain)
	inflight, ig := poolGet(t, s, oldMain)
	if ig != mg || idle == inflight {
		t.Fatal("expected two distinct scanners from one main generation")
	}
	s.putScanner(idle, mg)
	b0, bg := poolGet(t, s, oldBig)
	s.putScanner(b0, bg)

	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	newMain, newBig := mainAndBig(t, s)
	if newMain == oldMain || newBig == oldBig {
		t.Fatal("Reload did not replace the rules pointers")
	}

	m, g := poolGet(t, s, newMain)
	if m == idle || m == inflight || g == mg {
		t.Fatal("stale main scanner or generation reused after reload")
	}
	wantGen(t, "old main gen", mg, 0, true)
	wantGen(t, "old big gen", bg, 0, true)
	s.putScanner(m, g)

	s.putScanner(inflight, ig) // in-flight old-rules scanner: destroyed, not pooled
	wantGen(t, "in-flight old scanner pooled into retired gen", ig, 0, true)

	stale, sg := poolGet(t, s, oldMain)
	if s.scanners.Load() != g || sg == g {
		t.Fatal("old-rules scan replaced the live main pool")
	}
	s.putScanner(stale, sg)
	wantGen(t, "one-off gen", sg, 0, true)
	wantGen(t, "live main pool disturbed by stale scan", g, 1, false)

	b, h := poolGet(t, s, newBig)
	if b == b0 || h == bg {
		t.Fatal("stale big scanner or generation reused after reload")
	}
	s.putScanner(b, h)
}

// Concurrency: alternating main/big scans racing reloads. Run under -race.
func TestScannerPoolConcurrentAlternatingReload(t *testing.T) {
	s := newBigScanner(t, 1<<20)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.generationMu.RLock()
				pin := s.generation
				pin.retain()
				rules := s.rules.Load()
				if (i+w)%2 == 1 {
					rules = s.bigRules.Load()
				}
				s.generationMu.RUnlock()
				sc, gen, err := s.getScanner(rules)
				if err != nil {
					t.Error(err)
					return
				}
				if gen.rules != rules {
					t.Error("generation bound to different rules")
				}
				s.putScanner(sc, gen)
				pin.release()
			}
		}(w)
	}
	for i := 0; i < 3; i++ {
		if err := s.Reload(); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
	main, big := s.rules.Load(), s.bigRules.Load()
	sc, gen := poolGet(t, s, main) // retires any slot a late reload left stale
	s.putScanner(sc, gen)
	for _, p := range []struct {
		slot  *scannerGen
		rules *yara.Rules
	}{{s.scanners.Load(), main}, {s.bigScanners.Load(), big}} {
		if p.slot != nil && p.slot.rules != p.rules {
			t.Fatal("pool slot left bound to stale rules")
		}
	}
}

// staleCallerCase drives the AUD-P3a-r1 interleave for one slot: a getScanner
// call that selected the slot for rules R0 is paused (hook) while Reload stores
// R1 and a new caller installs the live generation for R1. The paused call must
// neither retire that live generation nor install one bound to R0.
func staleCallerCase(t *testing.T, big bool) {
	t.Helper()
	s := newBigScanner(t, 1<<20)
	live, slot := &s.rules, &s.scanners
	if big {
		live, slot = &s.bigRules, &s.bigScanners
	}
	r0 := live.Load()
	sc, g0 := poolGet(t, s, r0)
	s.putScanner(sc, g0)
	if slot.Load() != g0 {
		t.Fatal("live generation for R0 not installed")
	}
	r1, err := compileDir(writeRules(t, eicarRule), func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Destroy()

	var g1 *scannerGen
	getScannerAfterSelectHook = func() {
		getScannerAfterSelectHook = nil // simulate Reload exactly once
		live.Store(r1)
		sc1, gen1 := poolGet(t, s, r1)
		s.putScanner(sc1, gen1)
		g1 = gen1
	}
	t.Cleanup(func() { getScannerAfterSelectHook = nil })

	stale, sg := poolGet(t, s, r0)
	if g1 == nil {
		t.Fatal("hook did not run")
	}
	if slot.Load() != g1 {
		t.Fatalf("live slot is not the R1 generation: %p, want %p", slot.Load(), g1)
	}
	if slot.Load().rules != r1 {
		t.Fatal("live slot bound to replaced rules")
	}
	wantGen(t, "live R1 generation retired by stale caller", g1, 1, false)
	if sg == g1 || sg == g0 {
		t.Fatal("stale caller got a pooled generation")
	}
	wantGen(t, "stale caller generation", sg, 0, true)
	s.putScanner(stale, sg)
	wantGen(t, "live R1 generation after stale put", g1, 1, false)
}

// Regression (AUD-P3a-r1): a getScanner call paused across a Reload must not
// retire the new live main generation or install one for replaced rules.
func TestScannerPoolStaleCallerDoesNotRetireLivePool(t *testing.T) {
	staleCallerCase(t, false)
}

// Same interleave on the big-file slot.
func TestScannerPoolStaleCallerDoesNotRetireLiveBigPool(t *testing.T) {
	staleCallerCase(t, true)
}

// populateSlots fills the main and big pool slots with one idle scanner each
// and returns their generations plus a main scanner still checked out.
func populateSlots(t *testing.T, s *Scanner) (mg, bg *scannerGen, inflight *yara.Scanner) {
	t.Helper()
	main, big := mainAndBig(t, s)
	idle, g := poolGet(t, s, main)
	inflight, ig := poolGet(t, s, main)
	if ig != g || idle == inflight {
		t.Fatal("expected two distinct scanners from one main generation")
	}
	s.putScanner(idle, g)
	b, h := poolGet(t, s, big)
	s.putScanner(b, h)
	if s.scanners.Load() != g || s.bigScanners.Load() != h {
		t.Fatal("pool slots not installed")
	}
	return g, h, inflight
}

// AUD-P3b positive: a successful Reload retires both replaced generations and
// frees their idle scanners at publication, with no further pooled scan. A
// scanner checked out across the Reload is destroyed on put, never reused.
func TestScannerPoolReloadRetiresEagerly(t *testing.T) {
	s := newBigScanner(t, 1<<20)
	mg, bg, inflight := populateSlots(t, s)

	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.scanners.Load() != nil || s.bigScanners.Load() != nil {
		t.Fatalf("Reload left stale slots: main=%p big=%p", s.scanners.Load(), s.bigScanners.Load())
	}
	wantGen(t, "old main gen after reload", mg, 0, true)
	wantGen(t, "old big gen after reload", bg, 0, true)

	s.putScanner(inflight, mg) // checked out across Reload: destroyed, not pooled
	wantGen(t, "old main gen after in-flight put", mg, 0, true)

	newMain := s.rules.Load()
	m, g := poolGet(t, s, newMain)
	if m == inflight || g == mg {
		t.Fatal("in-flight scanner or old generation reused after reload")
	}
	s.putScanner(m, g)
}

// AUD-P3b boundary: a Reload that publishes no big-file ruleset retires the
// big slot at publication; the main slot is retired the same way.
func TestScannerPoolReloadBigUnsetRetiresEagerly(t *testing.T) {
	s := newBigScanner(t, 1<<20)
	mg, bg, inflight := populateSlots(t, s)
	s.putScanner(inflight, mg)
	s.mu.Lock()
	s.bigSrcDir, s.bigSrcFile = "", ""
	s.mu.Unlock()
	s.bigRules.Store(nil)

	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.bigRules.Load() != nil {
		t.Fatal("expected bigRules unset after reload")
	}
	if s.bigScanners.Load() != nil || s.scanners.Load() != nil {
		t.Fatal("Reload left a stale slot with big rules unset")
	}
	wantGen(t, "unset big gen", bg, 0, true)
	wantGen(t, "old main gen", mg, 0, true)
}

// AUD-P3b negative: a failed Reload keeps the previous rules, so their live
// generations stay installed with their idle scanners intact.
func TestScannerPoolFailedReloadKeepsLiveGenerations(t *testing.T) {
	s := newBigScanner(t, 1<<20)
	main, big := mainAndBig(t, s)
	mg, bg, inflight := populateSlots(t, s)
	s.mu.Lock()
	s.srcFile = filepath.Join(t.TempDir(), "missing.yac")
	s.mu.Unlock()

	if err := s.Reload(); err == nil {
		t.Fatal("Reload of a missing bundle succeeded")
	}
	if s.rules.Load() != main || s.bigRules.Load() != big {
		t.Fatal("failed Reload replaced the rules")
	}
	if s.scanners.Load() != mg || s.bigScanners.Load() != bg {
		t.Fatal("failed Reload removed a live generation")
	}
	wantGen(t, "live main gen after failed reload", mg, 1, false)
	wantGen(t, "live big gen after failed reload", bg, 1, false)
	s.putScanner(inflight, mg)
	wantGen(t, "live main gen after in-flight put", mg, 2, false)
}

// P9 bounds idle retention independently of active scanner admission. The
// forced 32-checkout case fills the old ceiling; ordinary four fits unchanged.
func TestP9IdlePoolCapBoundary(t *testing.T) {
	for _, checkout := range []int{4, 6, 7, 32} {
		t.Run(fmt.Sprint(checkout), func(t *testing.T) {
			s := p7Scanner(t, func(string, ...any) {})
			rules := s.rules.Load()
			scanners := make([]*yara.Scanner, checkout)
			var gen *scannerGen
			for i := range scanners {
				scanners[i], gen = poolGet(t, s, rules)
			}
			// A checked-out scanner survives other scanners overflowing the cap.
			held, heldGen := poolGet(t, s, rules)
			for i, sc := range scanners {
				s.putScanner(sc, gen)
				want := min(i+1, 6)
				wantGen(t, "idle cap boundary", gen, want, false)
				gen.mu.Lock()
				dependencies := len(gen.dependencies)
				gen.mu.Unlock()
				if dependencies != checkout-i-1+want+1 {
					t.Fatalf("overflow retained native dependency: got %d", dependencies)
				}
			}
			var matches yara.MatchRules
			held.SetCallback(&matches)
			if err := held.ScanMem([]byte("ordinary")); err != nil || len(matches) != 0 {
				t.Fatalf("checked-out scanner verdict changed: matches=%v err=%v", matches, err)
			}
			s.putScanner(held, heldGen)
			wantGen(t, "held return bounded", gen, min(checkout+1, 6), false)
			// Retained scanners still work when borrowed again.
			reused, reusedGen := poolGet(t, s, rules)
			reused.SetCallback(&matches)
			if err := reused.ScanMem([]byte("ordinary")); err != nil || len(matches) != 0 {
				t.Fatalf("reused scanner verdict changed: matches=%v err=%v", matches, err)
			}
			s.putScanner(reused, reusedGen)
		})
	}
}
