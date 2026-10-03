package mailstrix

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// urlHeavyZip builds n distinct ~1 MiB members whose text makes URL candidate
// extraction expensive (~90 ms each, ~1 s under -race) while YARA scans them
// quickly. Small members keep the one lookup in flight at the deadline short.
func urlHeavyZip(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	line := "see hxxp[:]// nothing here at all, words words words. "
	for i := 0; i < n; i++ {
		w, err := zw.Create(fmt.Sprintf("m%02d.txt", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(fmt.Sprintf("member %d ", i) + strings.Repeat(line, 20000))); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestReputationLoopStopsAtDeadline (PERF-52): with reputation feeds on, a
// container of many URL-heavy streams no longer runs seconds past the scan
// deadline; the result is marked incomplete instead of a clean verdict.
func TestReputationLoopStopsAtDeadline(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()
	s.scanTimeout = 1500 * time.Millisecond
	z := urlHeavyZip(t, 80)
	t0 := time.Now()
	m, err := s.Scan(z, ScanMeta{})
	elapsed := time.Since(t0)
	if elapsed > s.scanTimeout+3*time.Second {
		t.Fatalf("scan took %v, want close to the %v budget", elapsed, s.scanTimeout)
	}
	if !errors.Is(err, ErrScanIncomplete) || !hasRule(m, scanIncompleteRule) {
		t.Fatalf("want incomplete, got matches=%v err=%v", m, err)
	}
}

// TestReputationLoopCompletesWithinBudget (negative control): one small
// member with a feed URL is checked completely and still matches.
func TestReputationLoopCompletesWithinBudget(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()
	s.scanTimeout = 5 * time.Second
	m, err := s.Scan(makePlainZIP(t, [][]byte{[]byte(feedURLBody)}), ScanMeta{})
	if err != nil || !hasRule(m, "URLHAUS_MALWARE_URL") {
		t.Fatalf("matches=%v err=%v", m, err)
	}
}
