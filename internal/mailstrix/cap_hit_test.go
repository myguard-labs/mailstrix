package mailstrix

import (
	"errors"
	"fmt"
	"testing"
)

func distinctMembers(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("distinct member body %04d", i))
	}
	return out
}

// TestScanCapHitIsIncomplete (COR-07b): an archive with more members than
// the extraction stream cap returns ErrScanIncomplete and the marker, so the
// partial verdict is never cached as clean.
func TestScanCapHitIsIncomplete(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()
	s.scanTimeout = 0
	m, err := s.Scan(makePlainZIP(t, distinctMembers(300)), ScanMeta{})
	if !errors.Is(err, ErrScanIncomplete) || !hasRule(m, scanIncompleteRule) {
		t.Fatalf("want incomplete, got matches=%v err=%v", m, err)
	}
}

// TestScanUnderCapIsComplete (negative control): a small archive is scanned
// completely.
func TestScanUnderCapIsComplete(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()
	s.scanTimeout = 0
	m, err := s.Scan(makePlainZIP(t, distinctMembers(5)), ScanMeta{})
	if err != nil || hasRule(m, scanIncompleteRule) {
		t.Fatalf("want complete, got matches=%v err=%v", m, err)
	}
}
