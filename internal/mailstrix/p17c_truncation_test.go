package mailstrix

import (
	"errors"
	"testing"
)

// TestScanRetainedTruncationIsIncomplete: a request whose retained-output
// ceiling refuses an entry returns ErrScanIncomplete (never cached as clean)
// and counts once; the same input under a roomy ceiling is complete.
func TestScanRetainedTruncationIsIncomplete(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()
	s.scanTimeout = 0
	zipped := makePlainZIP(t, distinctMembers(40))
	s.extractionRetainedBytes = 1024
	m, err := s.Scan(zipped, ScanMeta{})
	if !errors.Is(err, ErrScanIncomplete) || !hasRule(m, scanIncompleteRule) {
		t.Fatalf("want incomplete, got matches=%v err=%v", m, err)
	}
	if got := s.ExtractMetrics().Truncated; got != 1 {
		t.Fatalf("truncated counter = %d, want 1", got)
	}
	_, err = s.Scan(zipped, ScanMeta{requireComplete: true})
	if err == nil {
		t.Fatal("requireComplete admitted a truncated extraction")
	}
	s.extractionRetainedBytes = 64 << 20
	before := s.ExtractMetrics().Truncated
	m, err = s.Scan(zipped, ScanMeta{})
	if err != nil || hasRule(m, scanIncompleteRule) {
		t.Fatalf("roomy ceiling: matches=%v err=%v", m, err)
	}
	if s.ExtractMetrics().Truncated != before {
		t.Fatal("counter moved without truncation")
	}
}
