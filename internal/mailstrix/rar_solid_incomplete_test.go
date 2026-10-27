package mailstrix

import (
	"errors"
	"os"
	"testing"
)

// rarSolidFlagOffset is the RAR5 main-header archive-flags byte of
// ../extract/testdata/payload.rar (see rarSolidBitOffset in the extract tests).
const rarSolidFlagOffset = 16

// TestScanSolidRarIsIncomplete (REL-RAR-SOLID-INCOMPLETE): a solid RAR is refused
// undecoded, so its members are never scanned. The scan must report
// ErrScanIncomplete with the incomplete rule, never a complete clean verdict that
// could be cached.
func TestScanSolidRarIsIncomplete(t *testing.T) {
	clean, err := os.ReadFile("../extract/testdata/payload.rar")
	if err != nil {
		t.Fatal(err)
	}
	if clean[rarSolidFlagOffset]&0x04 != 0 {
		t.Fatal("payload.rar fixture is already solid; offset assumption broken")
	}
	solid := append([]byte(nil), clean...)
	solid[rarSolidFlagOffset] |= 0x04

	s := newURLhausScanner(t)
	defer s.Close()
	s.scanTimeout = 0

	m, err := s.Scan(solid, ScanMeta{})
	if !errors.Is(err, ErrScanIncomplete) || !hasRule(m, scanIncompleteRule) {
		t.Fatalf("solid RAR: want incomplete, got matches=%v err=%v", m, err)
	}
	// Negative control: the same archive without the solid flag scans completely.
	m, err = s.Scan(clean, ScanMeta{})
	if err != nil || hasRule(m, scanIncompleteRule) {
		t.Fatalf("non-solid RAR: want complete, got matches=%v err=%v", m, err)
	}
}
