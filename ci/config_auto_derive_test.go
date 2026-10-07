package ci

import (
	"testing"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

// loadAuto builds a Config from the given inflight/icap env values ("" = unset/auto).
func loadAuto(t *testing.T, inflight, icap string) *mailstrix.Config {
	t.Helper()
	t.Setenv("MAILSTRIX_MAX_CONCURRENT", "4")
	t.Setenv("MAILSTRIX_MAX_INFLIGHT", inflight)
	t.Setenv("MAILSTRIX_ICAP_MAX_CONNS", icap)
	return mailstrix.LoadConfig()
}

func TestAutoDeriveRaisedMaxConcurrent(t *testing.T) {
	c := loadAuto(t, "", "")
	if c.MaxInflight != 8 || c.ICAPMaxConns != 64 {
		t.Fatalf("initial = %d/%d, want 8/64", c.MaxInflight, c.ICAPMaxConns)
	}
	c.MaxConcurrent = 10
	c.Finalize()
	if c.MaxInflight != 20 || c.ICAPMaxConns != 160 {
		t.Fatalf("raised = %d/%d, want 20/160", c.MaxInflight, c.ICAPMaxConns)
	}
}

func TestAutoDeriveLoweredMaxConcurrent(t *testing.T) {
	c := loadAuto(t, "auto", "auto")
	c.MaxConcurrent = 1
	c.Finalize()
	if c.MaxInflight != 2 || c.ICAPMaxConns != 16 {
		t.Fatalf("lowered = %d/%d, want 2/16", c.MaxInflight, c.ICAPMaxConns)
	}
}

func TestExplicitValuesSurviveMaxConcurrentChange(t *testing.T) {
	c := loadAuto(t, "12", "33")
	c.MaxConcurrent = 10
	c.Finalize()
	if c.MaxInflight != 12 || c.ICAPMaxConns != 33 {
		t.Fatalf("explicit = %d/%d, want 12/33", c.MaxInflight, c.ICAPMaxConns)
	}
	c.MaxConcurrent = 1
	c.Finalize()
	if c.MaxInflight != 12 || c.ICAPMaxConns != 33 {
		t.Fatalf("explicit after lowering = %d/%d, want 12/33", c.MaxInflight, c.ICAPMaxConns)
	}
}

func TestExplicitInflightStillRaisedBelowMaxConcurrent(t *testing.T) {
	c := loadAuto(t, "5", "33")
	c.MaxConcurrent = 10
	c.Finalize()
	if c.MaxInflight != 20 || c.ICAPMaxConns != 33 {
		t.Fatalf("got %d/%d, want 20/33", c.MaxInflight, c.ICAPMaxConns)
	}
}

func TestExplicitInflightAutoICAPFollowsInflight(t *testing.T) {
	c := loadAuto(t, "12", "")
	c.MaxConcurrent = 10
	c.Finalize()
	if c.MaxInflight != 12 || c.ICAPMaxConns != 96 {
		t.Fatalf("got %d/%d, want 12/96", c.MaxInflight, c.ICAPMaxConns)
	}
}

func TestExplicitICAPBelowOneClamps(t *testing.T) {
	c := loadAuto(t, "", "-3")
	if c.ICAPMaxConns != 64 {
		t.Fatalf("negative icap = %d, want clamp 64", c.ICAPMaxConns)
	}
	c = loadAuto(t, "", "")
	c.ICAPMaxConns = -1
	c.Finalize()
	if c.ICAPMaxConns != 8*c.MaxInflight {
		t.Fatalf("post-load negative icap = %d, want %d", c.ICAPMaxConns, 8*c.MaxInflight)
	}
}

func TestFinalizeIdempotentAuto(t *testing.T) {
	c := loadAuto(t, "", "")
	c.MaxConcurrent = 7
	c.Finalize()
	a, b := c.MaxInflight, c.ICAPMaxConns
	c.Finalize()
	if c.MaxInflight != a || c.ICAPMaxConns != b || a != 14 || b != 112 {
		t.Fatalf("not idempotent: %d/%d then %d/%d", a, b, c.MaxInflight, c.ICAPMaxConns)
	}
}

func TestZeroValueConfigFinalize(t *testing.T) {
	c := &mailstrix.Config{MaxConcurrent: 3}
	c.Finalize()
	if c.MaxInflight != 6 || c.ICAPMaxConns != 48 {
		t.Fatalf("zero-value = %d/%d, want 6/48", c.MaxInflight, c.ICAPMaxConns)
	}
}

// An explicit value that happens to equal the one auto would have derived must
// not be mistaken for auto: auto is tracked by source (env unset/0), not value.
func TestExplicitEqualToDerivedSurvivesMaxConcurrentChange(t *testing.T) {
	c := loadAuto(t, "8", "64") // equals 2x4 and 8x8, the derived values
	c.MaxConcurrent = 3
	c.Finalize()
	if c.MaxInflight != 8 || c.ICAPMaxConns != 64 {
		t.Fatalf("explicit-equal-derived = %d/%d, want 8/64", c.MaxInflight, c.ICAPMaxConns)
	}
	c.MaxConcurrent = 6
	c.Finalize()
	if c.MaxInflight != 8 || c.ICAPMaxConns != 64 {
		t.Fatalf("explicit-equal-derived after raise = %d/%d, want 8/64", c.MaxInflight, c.ICAPMaxConns)
	}
}

// env=0 is auto, exactly like unset: the CLI-overlay re-derive applies.
func TestAutoDeriveEnvZeroIsAuto(t *testing.T) {
	c := loadAuto(t, "0", "0")
	c.MaxConcurrent = 5
	c.Finalize()
	if c.MaxInflight != 10 || c.ICAPMaxConns != 80 {
		t.Fatalf("env=0 = %d/%d, want 10/80", c.MaxInflight, c.ICAPMaxConns)
	}
}
