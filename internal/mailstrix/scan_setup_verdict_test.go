package mailstrix

// AUD-M4a4: direct tests for resolveScanSetup and finalScanVerdict, the helpers
// extracted from scanGeneration.

import (
	"context"
	"errors"
	"testing"
	"time"

	yara "github.com/hillu/go-yara/v4"
)

func TestResolveScanSetupDeadline(t *testing.T) {
	gen := scannerGeneration{rules: new(yara.Rules)}
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		zero    bool
	}{
		{"zero timeout disables deadline", 0, true},
		{"negative timeout disables deadline", -time.Second, true},
		{"positive timeout sets deadline", 5 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Scanner{scanTimeout: tc.timeout, effortMax: 1, logf: func(string, ...any) {}}
			got := s.resolveScanSetup(nil, ScanMeta{}, gen)
			if got.deadline.IsZero() != tc.zero {
				t.Fatalf("deadline.IsZero()=%v want %v", got.deadline.IsZero(), tc.zero)
			}
			if !tc.zero && !got.deadline.After(time.Now()) {
				t.Fatalf("deadline %v not in the future", got.deadline)
			}
		})
	}
}

func TestResolveScanSetupBigFileGate(t *testing.T) {
	full, big := new(yara.Rules), new(yara.Rules)
	newS := func(threshold int64) (*Scanner, *int) {
		logs := 0
		return &Scanner{effortMax: 1, bigFileThreshold: threshold, logf: func(string, ...any) { logs++ }}, &logs
	}
	t.Run("over threshold with bigRules swaps", func(t *testing.T) {
		s, logs := newS(4)
		got := s.resolveScanSetup(make([]byte, 5), ScanMeta{}, scannerGeneration{rules: full, bigRules: big})
		if got.rawRules != big {
			t.Fatal("rawRules not swapped to bigRules")
		}
		if s.BigFileScans() != 1 || *logs != 1 {
			t.Fatalf("bigFileScans=%d logs=%d", s.BigFileScans(), *logs)
		}
	})
	t.Run("at threshold does not swap", func(t *testing.T) {
		s, logs := newS(4)
		got := s.resolveScanSetup(make([]byte, 4), ScanMeta{}, scannerGeneration{rules: full, bigRules: big})
		if got.rawRules != full || s.BigFileScans() != 0 || *logs != 0 {
			t.Fatalf("boundary swapped: scans=%d logs=%d", s.BigFileScans(), *logs)
		}
	})
	t.Run("zero threshold disables gate", func(t *testing.T) {
		s, _ := newS(0)
		got := s.resolveScanSetup(make([]byte, 99), ScanMeta{}, scannerGeneration{rules: full, bigRules: big})
		if got.rawRules != full || s.BigFileScans() != 0 {
			t.Fatal("gate fired with threshold 0")
		}
	})
	t.Run("nil bigRules keeps full rules and warns once", func(t *testing.T) {
		s, logs := newS(4)
		gen := scannerGeneration{rules: full}
		for i := 0; i < 3; i++ {
			if got := s.resolveScanSetup(make([]byte, 5), ScanMeta{}, gen); got.rawRules != full {
				t.Fatal("rawRules changed without bigRules")
			}
		}
		if *logs != 1 || s.BigFileScans() != 0 {
			t.Fatalf("logs=%d (want 1) bigFileScans=%d (want 0)", *logs, s.BigFileScans())
		}
	})
}

func TestFinalScanVerdict(t *testing.T) {
	rawErr := errors.New("raw boom")
	hit := []Match{{Rule: "r1"}}
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name       string
		out        []Match
		incomplete bool
		completion error
		raw        error
		meta       ScanMeta
		deadline   time.Time
		wantErr    error
		wantRules  []string
	}{
		{name: "clean", wantErr: nil},
		{name: "incomplete adds marker and ErrScanIncomplete", out: hit, incomplete: true,
			wantErr: ErrScanIncomplete, wantRules: []string{"r1", scanIncompleteRule}},
		{name: "incomplete keeps existing completionErr for requireComplete", out: hit, incomplete: true,
			completion: rawErr, meta: ScanMeta{requireComplete: true}, deadline: future,
			wantErr: rawErr, wantRules: []string{"r1", scanIncompleteRule}},
		{name: "requireComplete expired deadline", out: hit, meta: ScanMeta{requireComplete: true},
			deadline: past, wantErr: context.DeadlineExceeded, wantRules: []string{"r1"}},
		{name: "requireComplete zero deadline is not expired", out: hit,
			meta: ScanMeta{requireComplete: true}, wantErr: nil, wantRules: []string{"r1"}},
		{name: "requireComplete future deadline ok", out: hit,
			meta: ScanMeta{requireComplete: true}, deadline: future, wantErr: nil, wantRules: []string{"r1"}},
		{name: "requireComplete returns completionErr with out", out: hit, completion: rawErr, raw: rawErr,
			meta: ScanMeta{requireComplete: true}, wantErr: rawErr, wantRules: []string{"r1"}},
		{name: "rawErr with empty out is nil+rawErr", completion: rawErr, raw: rawErr, wantErr: rawErr},
		{name: "rawErr with recovered matches stands", out: hit, completion: rawErr, raw: rawErr,
			wantErr: nil, wantRules: []string{"r1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := finalScanVerdict(tc.out, tc.incomplete, tc.completion, tc.raw, tc.meta, tc.deadline)
			if err != tc.wantErr {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
			if len(got) != len(tc.wantRules) {
				t.Fatalf("got %d matches want %d", len(got), len(tc.wantRules))
			}
			for i, r := range tc.wantRules {
				if got[i].Rule != r {
					t.Fatalf("match[%d]=%s want %s", i, got[i].Rule, r)
				}
			}
			if tc.wantRules == nil && got != nil {
				t.Fatalf("want nil matches, got %v", got)
			}
		})
	}
}
