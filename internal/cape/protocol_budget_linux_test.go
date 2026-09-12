//go:build linux

package cape

import (
	"runtime"
	"strings"
	"sync"
	"testing"
)

func flatJSONDocument(elements int) []byte {
	var body strings.Builder
	body.Grow(2*elements + 8)
	body.WriteString(`{"x":[`)
	for i := 0; i < elements; i++ {
		if i != 0 {
			body.WriteByte(',')
		}
		body.WriteByte('0')
	}
	body.WriteString(`]}`)
	return []byte(body.String())
}

func TestJSONDocumentTokenBudgetAndConcurrentHeapReservation(t *testing.T) {
	near := flatJSONDocument(maxDecodedJSONTokens - 5)
	if _, err := jsonDocument(near, nil); err != nil {
		t.Fatal("near-limit flat array rejected", err)
	}
	over := flatJSONDocument(maxDecodedJSONTokens - 4)
	if _, err := jsonDocument(over, nil); outcomeCode(err) != Protocol {
		t.Fatalf("one-over decoded token budget error=%v want protocol", err)
	}
	const concurrency = 100
	start := make(chan struct{})
	errors := make(chan error, concurrency)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var workers sync.WaitGroup
	workers.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer workers.Done()
			<-start
			_, err := jsonDocument(over, nil)
			errors <- err
		}()
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		if outcomeCode(err) != Protocol {
			t.Fatalf("concurrent over-budget parse error=%v want protocol", err)
		}
	}
	runtime.ReadMemStats(&after)
	heapGrowth := int64(after.HeapSys - before.HeapSys)
	t.Logf("100 concurrent flat-array parses: heap_sys_delta=%d", heapGrowth)
	if heapGrowth > 512<<20 {
		t.Fatalf("bounded concurrent parses grew heap reservation by %d bytes", heapGrowth)
	}
}
