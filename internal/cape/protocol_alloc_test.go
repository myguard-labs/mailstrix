package cape

import (
	"strings"
	"testing"
)

func nestedAllocationDocument() []byte {
	return []byte(`{"signatures":[` + strings.Repeat(`{"name":"inert","details":{"values":[1,2,3]}},`, 31) + `{"name":"inert","details":{"values":[1,2,3]}}]}`)
}

func TestJSONDocumentOptionalVisitorAllocations(t *testing.T) {
	body := nestedAllocationDocument()
	measure := func(visit func(any)) float64 {
		return testing.AllocsPerRun(20, func() {
			if _, err := jsonDocument(body, visit); err != nil {
				t.Fatal(err)
			}
		})
	}
	without := measure(nil)
	with := measure(func(any) { t.Fatal("visitor called outside root data.task_ids") })
	t.Logf("allocations per nested document: no visitor %.0f; visitor %.0f; saved %.0f", without, with, with-without)
	// Relative to the same parser and document, avoid an allocator-version cap.
	// Each of the 32 nested objects has several visitor-only ancestry slices.
	if with-without < 32*4 {
		t.Fatal("no-visitor parsing retained ancestry allocations")
	}
}

func BenchmarkJSONDocumentOptionalVisitor(b *testing.B) {
	body := nestedAllocationDocument()
	for _, enabled := range []bool{false, true} {
		name := "without"
		var visit func(any)
		if enabled {
			name, visit = "with", func(any) {}
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := jsonDocument(body, visit); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
