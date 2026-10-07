package mailstrix

import (
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
				rules := s.rules.Load()
				if (i+w)%2 == 1 {
					rules = s.bigRules.Load()
				}
				sc, gen, err := s.getScanner(rules)
				if err != nil {
					t.Error(err)
					return
				}
				if gen.rules != rules {
					t.Error("generation bound to different rules")
				}
				s.putScanner(sc, gen)
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
