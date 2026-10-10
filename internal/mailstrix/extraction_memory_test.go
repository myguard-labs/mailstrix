package mailstrix

import (
	"sync"
	"testing"
)

func TestRetainedExtractionHistogram(t *testing.T) {
	s := &Scanner{}
	s.extractionBytes.observe(nil)
	backing := make([]byte, extractionByteBounds[6]+1)
	for _, bound := range extractionByteBounds {
		s.extractionBytes.observe([][]byte{backing[:bound]})
	}
	s.extractionBytes.observe([][]byte{backing})
	got := s.ExtractionBytesRetained()
	var sum uint64
	for i, bound := range extractionByteBounds {
		sum += bound
		if got.Buckets[i] != uint64(i+2) {
			t.Fatalf("bucket %d=%d want=%d", i, got.Buckets[i], i+2)
		}
	}
	if got.Count != 9 || got.Sum != sum+extractionByteBounds[6]+1 {
		t.Fatalf("snapshot=%+v", got)
	}
	streams := [][]byte{[]byte("abc"), nil, []byte("defg")}
	if n := testing.AllocsPerRun(100, func() { s.extractionBytes.observe(streams) }); n != 0 {
		t.Fatalf("observation allocations=%g", n)
	}
}

func TestRetainedExtractionHistogramConcurrent(t *testing.T) {
	s := &Scanner{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.extractionBytes.observe([][]byte{[]byte("abc"), []byte("defg")})
				v := s.ExtractionBytesRetained()
				if v.Sum != v.Count*7 {
					t.Errorf("inconsistent sum/count: %+v", v)
				}
				for _, count := range v.Buckets {
					if count != v.Count {
						t.Errorf("inconsistent bucket: %+v", v)
					}
				}
			}
		}()
	}
	wg.Wait()
	if got := s.ExtractionBytesRetained(); got.Count != 800 || got.Sum != 5600 {
		t.Fatalf("snapshot=%+v", got)
	}
}
