package yarad

import (
	"sync"
	"testing"
	"time"
)

func TestResolveEffortLevel(t *testing.T) {
	cases := []struct {
		name   string
		hv     int
		hset   bool
		envDef int
		max    int
		want   int
	}{
		{"no header uses env default", 0, false, 7, 10, 7},
		{"header overrides env", 3, true, 7, 10, 3},
		{"header clamped to max (DoS guard)", 99, true, 5, 10, 10},
		{"header below 1 clamped up", 0, true, 5, 10, 1},
		{"negative header clamps to 1 (not env default)", -1, true, 9, 10, 1},
		{"env default above max clamped", 0, false, 50, 8, 8},
		{"negative env default floored", 0, false, -4, 10, 1},
		{"max below 1 floored to 1", 5, true, 5, 0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveEffortLevel(c.hv, c.hset, c.envDef, c.max); got != c.want {
				t.Errorf("ResolveEffortLevel(%d,%v,%d,%d) = %d, want %d",
					c.hv, c.hset, c.envDef, c.max, got, c.want)
			}
		})
	}
}

func TestEffortProfileFor(t *testing.T) {
	const max = 10

	// Level carried through; out-of-range floored/capped.
	if p := EffortProfileFor(5, max, 0); p.Level != 5 {
		t.Errorf("Level not carried: got %d", p.Level)
	}
	if p := EffortProfileFor(0, max, 0); p.Level != 1 {
		t.Errorf("stray 0 not floored to 1: got %d", p.Level)
	}
	if p := EffortProfileFor(99, max, 0); p.Level != max {
		t.Errorf("level above ceiling not capped: got %d", p.Level)
	}

	// Ceiling = full depth, every feature on.
	top := EffortProfileFor(max, max, 0)
	if top.DecodeDepth != fullDecodeDepth || top.DecodeIterations != fullDecodeIters ||
		!top.PDFDeepen || !top.ReputationFeeds {
		t.Errorf("ceiling profile must be full-depth/all-on, got %+v", top)
	}

	// Floor = shallowest: one decode layer, indicator pass + feeds shed.
	low := EffortProfileFor(1, max, 0)
	if low.DecodeDepth != 1 {
		t.Errorf("floor DecodeDepth must be 1, got %d", low.DecodeDepth)
	}
	if low.DecodeIterations < 1 {
		t.Errorf("floor DecodeIterations must be >=1, got %d", low.DecodeIterations)
	}
	if low.PDFDeepen {
		t.Error("floor must skip the PDF indicator pass")
	}
	if low.ReputationFeeds {
		t.Error("floor must skip the reputation feeds")
	}

	// Monotonic: depth and iters never decrease as the level rises.
	prevD, prevI := 0, 0
	for lvl := 1; lvl <= max; lvl++ {
		p := EffortProfileFor(lvl, max, 0)
		if p.DecodeDepth < prevD {
			t.Errorf("DecodeDepth not monotonic at level %d: %d < %d", lvl, p.DecodeDepth, prevD)
		}
		if p.DecodeIterations < prevI {
			t.Errorf("DecodeIterations not monotonic at level %d: %d < %d", lvl, p.DecodeIterations, prevI)
		}
		if p.DecodeDepth > fullDecodeDepth || p.DecodeIterations > fullDecodeIters {
			t.Errorf("level %d exceeds ceilings: %+v", lvl, p)
		}
		prevD, prevI = p.DecodeDepth, p.DecodeIterations
	}

	// Feeds turn on in the upper half (frac>=0.5). Level 6/10 → frac 0.55 → on;
	// level 3/10 → frac 0.22 → off.
	if p := EffortProfileFor(6, max, 0); !p.ReputationFeeds {
		t.Errorf("reputation feeds must be on at level 6/10, got %+v", p)
	}
	if p := EffortProfileFor(3, max, 0); p.ReputationFeeds {
		t.Errorf("reputation feeds must be off at level 3/10, got %+v", p)
	}

	// Degenerate 1-level ceiling: no room to shed → full depth.
	if p := EffortProfileFor(1, 1, 0); p.DecodeDepth != fullDecodeDepth || !p.PDFDeepen || !p.ReputationFeeds {
		t.Errorf("1-level ceiling must be full-depth, got %+v", p)
	}

	// ScanTimeout scaling: zero base → zero timeout regardless of level.
	if p := EffortProfileFor(1, max, 0); p.ScanTimeout != 0 {
		t.Errorf("zero base must yield zero ScanTimeout, got %v", p.ScanTimeout)
	}

	// At the ceiling, ScanTimeout == base.
	base := 10 * time.Second
	if p := EffortProfileFor(max, max, base); p.ScanTimeout != base {
		t.Errorf("ceiling ScanTimeout must equal base %v, got %v", base, p.ScanTimeout)
	}

	// At level 1 (frac=0), ScanTimeout == 50% of base (floored at minScanTimeout).
	p1 := EffortProfileFor(1, max, base)
	want50 := time.Duration(float64(base) * 0.5)
	if p1.ScanTimeout != want50 {
		t.Errorf("floor ScanTimeout must be 50%% of base (%v), got %v", want50, p1.ScanTimeout)
	}

	// Monotonic: ScanTimeout must not decrease as level rises.
	var prevT time.Duration
	for lvl := 1; lvl <= max; lvl++ {
		p := EffortProfileFor(lvl, max, base)
		if p.ScanTimeout < prevT {
			t.Errorf("ScanTimeout not monotonic at level %d: %v < %v", lvl, p.ScanTimeout, prevT)
		}
		prevT = p.ScanTimeout
	}

	// minScanTimeout floor: a tiny base at level 1 must not go below the floor.
	tiny := 100 * time.Millisecond // 50% = 50ms < minScanTimeout
	pFloor := EffortProfileFor(1, max, tiny)
	if pFloor.ScanTimeout < minScanTimeout {
		t.Errorf("ScanTimeout must be >= minScanTimeout (%v), got %v", minScanTimeout, pFloor.ScanTimeout)
	}

	// ExtractOptions mapping mirrors the profile.
	opts := top.ExtractOptions(time.Time{})
	if opts.DecodeDepth != top.DecodeDepth || opts.DecodeIterations != top.DecodeIterations ||
		opts.PDFDeepen != top.PDFDeepen {
		t.Errorf("ExtractOptions mismatch: %+v vs %+v", opts, top)
	}
}

func TestResolveScanEffort(t *testing.T) {
	// Unresolved (0 or negative) -> configured ceiling, NOT level 1.
	if got := resolveScanEffort(0, 10); got != 10 {
		t.Errorf("unresolved effort must run at ceiling 10, got %d", got)
	}
	if got := resolveScanEffort(-1, 7); got != 7 {
		t.Errorf("negative effort must run at ceiling 7, got %d", got)
	}
	// A resolved level passes through unchanged.
	if got := resolveScanEffort(3, 10); got != 3 {
		t.Errorf("resolved level must pass through, got %d", got)
	}
}

func TestConfigSanitizeEffort(t *testing.T) {
	cases := []struct {
		name                string
		effort, max         int
		wantEffort, wantMax int
	}{
		{"defaults: 0 effort becomes max", 0, 10, 10, 10},
		{"explicit in range", 4, 10, 4, 10},
		{"effort above max clamped to max", 20, 6, 6, 6},
		{"max above ceiling clamped", 5, 99, 5, defaultEffortMax},
		{"max below 1 clamped to default", 5, 0, 5, defaultEffortMax},
		{"negative effort floors to 1 (not max)", -3, 8, 1, 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &Config{Effort: c.effort, EffortMax: c.max,
				ScanTimeout: 1, MaxBody: 1, CacheSize: 1, Port: 8079,
				BackendTimeout: 1, MaxConcurrent: 1, MaxInflight: 1}
			cfg.sanitize()
			if cfg.Effort != c.wantEffort || cfg.EffortMax != c.wantMax {
				t.Errorf("got Effort=%d Max=%d, want Effort=%d Max=%d",
					cfg.Effort, cfg.EffortMax, c.wantEffort, c.wantMax)
			}
			if cfg.Effort < 1 || cfg.Effort > cfg.EffortMax {
				t.Errorf("post-sanitize Effort %d out of [1,%d]", cfg.Effort, cfg.EffortMax)
			}
		})
	}
}

func TestScanMetaCacheKeyIncludesEffort(t *testing.T) {
	a := ScanMeta{Filename: "x.doc", Effort: 2}
	b := ScanMeta{Filename: "x.doc", Effort: 9}
	if a.cacheKey() == b.cacheKey() {
		t.Fatal("cacheKey must differ by effort level (same bytes, different depth = different verdict)")
	}
	if a.cacheKey() != (ScanMeta{Filename: "x.doc", Effort: 2}).cacheKey() {
		t.Fatal("cacheKey must be stable for identical meta")
	}
}

func TestAutoTargetLevel(t *testing.T) {
	cases := []struct {
		name                                string
		occupied, capacity, idle, max, want int
	}{
		{"only request -> idle ceiling", 1, 8, 10, 10, 10},
		{"full gate -> 1", 8, 8, 10, 10, 1},
		{"half full ~ midpoint", 5, 9, 9, 10, 5}, // frac=4/8=0.5, span=8, drop=4 -> 5
		{"unbounded gate -> idle", 4, 0, 7, 10, 7},
		{"single-slot gate -> idle (no measurable pressure)", 1, 1, 6, 10, 6},
		{"idle clamped to max", 1, 4, 50, 8, 8},
		{"idle floored to 1 -> always 1", 1, 4, 0, 10, 1},
		{"occupied over capacity clamped", 99, 4, 10, 10, 1},
		{"occupied under 1 floored", 0, 4, 10, 10, 10},
		{"never drops below 1", 4, 4, 2, 10, 1}, // span=1, full -> drop 1 -> 1
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := autoTargetLevel(c.occupied, c.capacity, c.idle, c.max); got != c.want {
				t.Fatalf("autoTargetLevel(%d,%d,%d,%d)=%d want %d", c.occupied, c.capacity, c.idle, c.max, got, c.want)
			}
		})
	}
}

func TestAutoStepLevel(t *testing.T) {
	cases := []struct{ cur, target, want int }{
		{0, 7, 7}, // uninitialised snaps to target
		{0, 1, 1}, //
		{5, 9, 6}, // ramp up one
		{5, 2, 4}, // ramp down one
		{5, 5, 5}, // steady
		{5, 6, 6}, // adjacent up
		{5, 4, 4}, // adjacent down
	}
	for _, c := range cases {
		if got := autoStepLevel(c.cur, c.target); got != c.want {
			t.Fatalf("autoStepLevel(%d,%d)=%d want %d", c.cur, c.target, got, c.want)
		}
	}
}

func TestConfigEffortAuto(t *testing.T) {
	t.Setenv("YARAD_EFFORT", "auto")
	c := LoadConfig()
	if !c.EffortAuto {
		t.Fatal("YARAD_EFFORT=auto must set EffortAuto")
	}
	if c.Effort != c.EffortMax {
		t.Fatalf("auto idle level must default to EffortMax: Effort=%d EffortMax=%d", c.Effort, c.EffortMax)
	}
}

// TestAutoEnvDefaultConcurrent hammers the auto resolver from many goroutines to
// prove the CAS step is race-free (run under -race) and that the smoothed level
// stays in [1, EffortMax] and only ever moves one level per scan.
func TestAutoEnvDefaultConcurrent(t *testing.T) {
	cfg := &Config{Token: "t", MaxConcurrent: 8, MaxBody: 1 << 20, EffortAuto: true}
	cfg.sanitize() // sets Effort=EffortMax, MaxInflight=2×MaxConcurrent
	s := NewServer(cfg, &fakeEngine{count: 1})

	// Pre-load the admission gate to simulate pressure (half full).
	for i := 0; i < cap(s.admit)/2; i++ {
		s.admit <- struct{}{}
	}

	const G, N = 16, 200
	var wg sync.WaitGroup
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < N; i++ {
				lvl := s.autoEnvDefault(true)
				if lvl < 1 || lvl > cfg.EffortMax {
					t.Errorf("auto level %d out of [1,%d]", lvl, cfg.EffortMax)
					return
				}
			}
		}()
	}
	wg.Wait()
	if got := s.autoEffort.Load(); got < 1 || got > int64(cfg.EffortMax) {
		t.Fatalf("final autoEffort %d out of [1,%d]", got, cfg.EffortMax)
	}
}
