package yarad

import "testing"

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
	// EFFORT-1: inert full-depth profile, Level carried through, level floored.
	if p := EffortProfileFor(5); p.Level != 5 {
		t.Errorf("Level not carried: got %d", p.Level)
	}
	if p := EffortProfileFor(0); p.Level != 1 {
		t.Errorf("stray 0 not floored to 1: got %d", p.Level)
	}
	p := EffortProfileFor(3)
	if !p.PDFDeepen || !p.ReputationFeeds || p.DecodeDepth != 4 {
		t.Errorf("EFFORT-1 profile must be full-depth/inert, got %+v", p)
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
