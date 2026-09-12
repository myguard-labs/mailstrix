//go:build linux

package cape

import (
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

func TestJSONDocumentTokenBudgetConcurrent(t *testing.T) {
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
}

func TestSchedulerAggregateReportBudget(t *testing.T) {
	const aggregateReportBudget = 64 << 20
	if got := MaxSchedulerWorkers * MaxReport; got != aggregateReportBudget {
		t.Fatalf("aggregate report body budget=%d, want %d", got, aggregateReportBudget)
	}
}

func BenchmarkJSONDocumentTokenBudget(b *testing.B) {
	over := flatJSONDocument(maxDecodedJSONTokens - 4)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := jsonDocument(over, nil); outcomeCode(err) != Protocol {
			b.Fatal("over-budget document lost protocol rejection", err)
		}
	}
}
