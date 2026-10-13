package extractionbudget_test

import (
	"sync"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func TestExtractionRetainedAccountingRequestBoundary(t *testing.T) {
	shared := extract.FullOptions(time.Time{})
	inputs := [][]byte{
		nil,
		[]byte("ordinary input"),
		[]byte("PK\x03\x04truncated"),
	}

	var wg sync.WaitGroup
	results := make([]extract.Result, len(inputs))
	for i := range inputs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = extract.ExtractWithOptions(inputs[i], shared)
		}(i)
	}
	wg.Wait()

	for i, res := range results {
		if got := res.Retained.Bytes(); got != 0 {
			t.Fatalf("result %d retained bytes=%d want=0 before emitter wiring", i, got)
		}
	}
}
