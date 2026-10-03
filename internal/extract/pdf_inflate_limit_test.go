package extract

import (
	"testing"
)

// TestRawInflatePDFLimit (PERF-59): the inflate stops at the remaining budget
// instead of producing up to maxBytesPerPDFStream that is then discarded.
func TestRawInflatePDFLimit(t *testing.T) {
	body := rawDeflate(make([]byte, 1<<20))
	if got := rawInflatePDFLimit(body, 1000); len(got) != 1000 {
		t.Errorf("limit 1000: %d bytes", len(got))
	}
	if got := rawInflatePDFLimit(body, 0); got != nil {
		t.Errorf("limit 0: %d bytes", len(got))
	}
	if got := rawInflatePDFLimit(body, 1<<30); len(got) != 1<<20 {
		t.Errorf("large limit: %d bytes, want the whole 1 MiB", len(got))
	}
	if got := rawInflatePDFLimit([]byte{1}, 100); got != nil {
		t.Errorf("malformed short body: %d bytes", len(got))
	}
	if got := rawInflatePDF(body); len(got) != 1<<20 {
		t.Errorf("rawInflatePDF unchanged: %d bytes", len(got))
	}
}
