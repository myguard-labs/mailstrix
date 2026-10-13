package extract

import (
	"math"
	"sync"
	"testing"
	"time"
)

func TestRetainedBudgetRecording(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		b := &retainedBudget{}
		token, ok := b.recordBytes(nil)
		if !ok || !b.owns(token) {
			t.Fatalf("empty admission ok=%v owned=%v", ok, b.owns(token))
		}
		if got := b.snapshot().Bytes(); got != 0 {
			t.Fatalf("empty admission recorded %d bytes", got)
		}
	})

	t.Run("exact and duplicate", func(t *testing.T) {
		b := &retainedBudget{}
		data := []byte("same")
		first, ok := b.recordBytes(data)
		if !ok {
			t.Fatal("first admission refused")
		}
		second, ok := b.recordBytes(data)
		if !ok {
			t.Fatal("duplicate admission refused")
		}
		if !b.owns(first) || !b.owns(second) {
			t.Fatal("admission token lost")
		}
		if got, want := b.snapshot().Bytes(), uint64(2*len(data)); got != want {
			t.Fatalf("recorded bytes=%d want=%d", got, want)
		}
	})

	t.Run("overflow saturates", func(t *testing.T) {
		b := &retainedBudget{}
		if _, ok := b.record(math.MaxUint64 - 2); !ok {
			t.Fatal("large admission refused")
		}
		if _, ok := b.record(3); !ok {
			t.Fatal("overflowing admission refused")
		}
		if got := b.snapshot().Bytes(); got != math.MaxUint64 {
			t.Fatalf("overflow wrapped to %d", got)
		}
	})

	t.Run("invalid owner", func(t *testing.T) {
		var nilBudget *retainedBudget
		if token, ok := nilBudget.record(1); ok || token != (retainedToken{}) {
			t.Fatalf("nil ledger admission ok=%v token=%+v", ok, token)
		}
		if got := nilBudget.snapshot().Bytes(); got != 0 {
			t.Fatalf("nil ledger snapshot=%d", got)
		}
		left, right := &retainedBudget{}, &retainedBudget{}
		token, ok := left.record(1)
		if !ok || right.owns(token) || left.owns(retainedToken{}) {
			t.Fatalf("token ownership ok=%v left-zero=%v right-token=%v", ok, left.owns(retainedToken{}), right.owns(token))
		}
		saturated := &retainedBudget{admissions: math.MaxUint64}
		token, ok = saturated.record(1)
		if !ok || !saturated.owns(token) || saturated.admissions != math.MaxUint64 {
			t.Fatalf("saturated token ok=%v owned=%v admissions=%d", ok, saturated.owns(token), saturated.admissions)
		}
	})
}

func TestRetainedChildOptionsShareLedger(t *testing.T) {
	parentOpts := FullOptions(time.Unix(1, 0))
	parentOpts.retained = &retainedBudget{}
	res := &Result{childOpts: parentOpts}
	if _, ok := parentOpts.retained.record(11); !ok {
		t.Fatal("parent admission refused")
	}
	childOpts := res.optionsForChild(time.Unix(2, 0))
	if childOpts == parentOpts {
		t.Fatal("child options reused the parent Options object")
	}
	if childOpts.Deadline.Equal(parentOpts.Deadline) {
		t.Fatal("child deadline was not overridden")
	}
	if _, ok := childOpts.retained.record(13); !ok {
		t.Fatal("child admission refused")
	}
	if got := parentOpts.retained.snapshot().Bytes(); got != 24 {
		t.Fatalf("recursive accounting bytes=%d want=24", got)
	}

	scratchOpts := res.optionsForChild(time.Time{})
	scratchOpts.retained = &retainedBudget{}
	if _, ok := scratchOpts.retained.record(17); !ok {
		t.Fatal("scratch admission refused")
	}
	if got := parentOpts.retained.snapshot().Bytes(); got != 24 {
		t.Fatalf("scratch accounting escaped into parent: %d", got)
	}

	standalone := (&Result{}).optionsForChild(time.Unix(3, 0))
	if standalone.retained == nil {
		t.Fatal("standalone child options have no ledger")
	}
}

func TestExtractWithOptionsOwnsLedgerPerInvocation(t *testing.T) {
	caller := FullOptions(time.Time{})
	caller.retained = &retainedBudget{}
	callerLedger := caller.retained

	const calls = 16
	results := make([]Result, calls)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = ExtractWithOptions(nil, caller)
		}(i)
	}
	wg.Wait()

	seen := make(map[*retainedBudget]struct{}, calls)
	for i := range results {
		ledger := results[i].childOpts.retained
		if ledger == nil || ledger == callerLedger {
			t.Fatalf("result %d reused caller ledger", i)
		}
		if _, exists := seen[ledger]; exists {
			t.Fatalf("result %d reused another invocation ledger", i)
		}
		seen[ledger] = struct{}{}
		if _, ok := ledger.record(uint64(i + 1)); !ok {
			t.Fatalf("result %d ledger refused recording", i)
		}
		if got := ledger.snapshot().Bytes(); got != uint64(i+1) {
			t.Fatalf("result %d ledger bytes=%d want=%d", i, got, i+1)
		}
	}
	if caller.retained != callerLedger || callerLedger.snapshot().Bytes() != 0 {
		t.Fatal("ExtractWithOptions mutated caller Options")
	}
}

func TestExtractRetainedSnapshotEmptyAndError(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
		opts *Options
	}{
		{name: "empty_nil_options"},
		{name: "empty_bare_options", opts: &Options{}},
		{name: "malformed_zip", buf: []byte("PK\x03\x04truncated"), opts: FullOptions(time.Time{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := ExtractWithOptions(tc.buf, tc.opts)
			if got := res.Retained.Bytes(); got != 0 {
				t.Fatalf("recorded bytes=%d want=0", got)
			}
		})
	}
}
