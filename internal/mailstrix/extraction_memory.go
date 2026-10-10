package mailstrix

import "sync"

var extractionByteBounds = [...]uint64{1024, 16384, 262144, 1048576, 16777216, 67108864, 268435456}

// ExtractionBytesSnapshot is a consistent histogram of logical retained stream
// lengths at the end of extraction. Buckets are cumulative, in ascending order:
// 1 KiB, 16 KiB, 256 KiB, 1 MiB, 16 MiB, 64 MiB, 256 MiB. Count is the +Inf bucket.
// This measures stream lengths, not unique backing arrays or allocated capacity.
type ExtractionBytesSnapshot struct {
	Buckets    [7]uint64
	Sum, Count uint64
}

type retainedExtractionHistogram struct {
	mu    sync.Mutex
	value ExtractionBytesSnapshot
}

func (h *retainedExtractionHistogram) observe(streams [][]byte) {
	var total uint64
	for _, stream := range streams {
		total += uint64(len(stream))
	}
	h.mu.Lock()
	for i, bound := range extractionByteBounds {
		if total <= bound {
			h.value.Buckets[i]++
		}
	}
	h.value.Sum += total
	h.value.Count++
	h.mu.Unlock()
}

// ExtractionBytesRetained reports one sample per actual extraction invocation,
// including zero-byte and failed extraction results. Cache/flight hits do not
// invoke extraction. Observation does not copy streams or allocate per sample.
func (s *Scanner) ExtractionBytesRetained() ExtractionBytesSnapshot {
	s.extractionBytes.mu.Lock()
	defer s.extractionBytes.mu.Unlock()
	return s.extractionBytes.value
}
