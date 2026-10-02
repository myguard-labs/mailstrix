package mailstrix

import (
	"archive/zip"
	"bytes"
	"errors"
	"testing"
	"time"
)

// slowBigRule stands in for the full production ruleset on multi-MiB members
// (PERF-50): any stream over 1 MiB spins in libyara until its timeout, so one
// padding member scanned first spends the whole remaining budget. The raw zip
// and the small dropper stay under 1 MiB and match nothing here.
const slowBigRule = `
rule Slow_Big_Stream
{
    condition:
        filesize > 1048576 and for all i in (1..1000000000): (i > 0)
}
`

// padSize is one padding member and padCount how many the padded fixture
// carries. The padding is a repeating control-byte pattern: it deflates to
// almost nothing and the static decoders skip it as non-text, so extraction
// stays fast even under -race on a loaded runner and only the (deliberately
// slow) stream scans compete for the budget.
// The slow rule spins until its timeout on any stream over 1 MiB, so a single
// padding member already spends the whole budget; two keep the fixture plural
// while keeping extraction (which scales with padding volume) small.
const (
	padSize       = 1<<20 + 4096
	padCount      = 2
	budgetTimeout = 4 * time.Second
)

func binaryPad(first byte) []byte {
	pad := make([]byte, padSize)
	for i := range pad {
		pad[i] = byte(i % 31)
	}
	pad[0] = first // distinct per member so stream dedup cannot collapse them
	return pad
}

// paddedDropperZip builds the PERF-50 shape: padding members that deflate to
// almost nothing but are slow to scan, followed by a small EICAR "dropper"
// member. The dropper is last in the archive, so it is found within budget
// only if the scanner visits small content streams first. pad=0 yields the
// unpadded control.
func paddedDropperZip(t *testing.T, pad int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for i := 0; i < pad; i++ {
		w, err := zw.Create("blob" + string(rune('a'+i)) + ".bin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(binaryPad(byte(0x80 + i))); err != nil {
			t.Fatal(err)
		}
	}
	w, err := zw.Create("z.vbs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(eicar()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func hasRule(ms []Match, rule string) bool {
	for _, m := range ms {
		if m.Rule == rule {
			return true
		}
	}
	return false
}

func budgetScanner(t *testing.T, timeout time.Duration) *Scanner {
	t.Helper()
	s := newScanner(t, writeRules(t, eicarRule+slowBigRule))
	s.scanTimeout = timeout
	return s
}

// TestScanPaddedZipFindsDropperAndMarksIncomplete: the padding members cost
// more than the whole budget to scan. The small dropper member must still
// be found, and the budget hit must surface as ErrScanIncomplete plus a
// log-only SCAN-INCOMPLETE marker rather than a nil-error verdict.
func TestScanPaddedZipFindsDropperAndMarksIncomplete(t *testing.T) {
	s := budgetScanner(t, budgetTimeout)
	m, err := s.Scan(paddedDropperZip(t, padCount), ScanMeta{})
	if !hasRule(m, "EICAR_Test_File") {
		t.Fatalf("padded zip: dropper member not detected; matches=%+v err=%v", m, err)
	}
	if !errors.Is(err, ErrScanIncomplete) {
		t.Fatalf("padded zip: err = %v, want ErrScanIncomplete", err)
	}
	var marker *Match
	for i := range m {
		if m[i].Rule == scanIncompleteRule {
			marker = &m[i]
		}
	}
	if marker == nil {
		t.Fatalf("padded zip: no %s marker in %+v", scanIncompleteRule, m)
	}
	if !matchIsLogOnly(*marker) {
		t.Fatalf("SCAN-INCOMPLETE marker must be log-only, got meta %v", marker.Meta)
	}
}

// TestScanUnpaddedZipCompleteControl: the same dropper without padding is found
// with a complete (nil-error) verdict and no SCAN-INCOMPLETE marker.
func TestScanUnpaddedZipCompleteControl(t *testing.T) {
	s := budgetScanner(t, budgetTimeout)
	m, err := s.Scan(paddedDropperZip(t, 0), ScanMeta{})
	if err != nil {
		t.Fatalf("unpadded zip: err = %v", err)
	}
	if !hasRule(m, "EICAR_Test_File") || hasRule(m, scanIncompleteRule) {
		t.Fatalf("unpadded zip: matches = %+v, want EICAR only", m)
	}
}

// TestScanBudgetBoundary: at the smallest budget (a 1ns base is floored to
// minScanTimeout) the padding cannot all be scanned, so the result must be
// incomplete with the marker, never a nil-error verdict (whether the dropper is
// reached first depends on unpack speed). With the limit disabled the same
// input completes with no marker.
func TestScanBudgetBoundary(t *testing.T) {
	m, err := budgetScanner(t, time.Nanosecond).Scan(paddedDropperZip(t, padCount), ScanMeta{})
	if !errors.Is(err, ErrScanIncomplete) || !hasRule(m, scanIncompleteRule) {
		t.Fatalf("minimum budget: matches=%+v err=%v, want incomplete", m, err)
	}
	// No limit: the slow-loop rule would run to completion (~30 s), so this
	// leg uses EICAR-only rules; it checks the no-limit path, not scan cost.
	unlimited := newScanner(t, writeRules(t, eicarRule))
	unlimited.scanTimeout = 0
	m, err = unlimited.Scan(paddedDropperZip(t, 1), ScanMeta{})
	if err != nil || !hasRule(m, "EICAR_Test_File") || hasRule(m, scanIncompleteRule) {
		t.Fatalf("no budget limit: matches=%+v err=%v, want complete EICAR", m, err)
	}
}

// TestScanNonZipControl: plain non-container bodies within budget keep the
// complete verdict contract, clean and infected.
func TestScanNonZipControl(t *testing.T) {
	s := budgetScanner(t, budgetTimeout)
	m, err := s.Scan(eicar(), ScanMeta{})
	if err != nil || len(m) != 1 || m[0].Rule != "EICAR_Test_File" {
		t.Fatalf("raw EICAR: matches=%+v err=%v", m, err)
	}
	m, err = s.Scan([]byte("a perfectly innocent body"), ScanMeta{})
	if err != nil || len(m) != 0 {
		t.Fatalf("clean body: matches=%+v err=%v", m, err)
	}
}

// stallOnQRule makes libyara time out on any buffer starting with 'Q' and
// match nothing on anything else, so only the extracted member stalls: the
// raw zip starts with "PK".
const stallOnQRule = `rule Stall_On_Q { condition: uint8(0) == 0x51 and for all i in (1..1000000000): (i > 0) }`

func singleMemberZip(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestScanExtractedStreamTimeoutIsIncomplete: libyara takes whole seconds, so
// with ~2.9 s left an extracted-stream scan gets 2 s and times out while the
// shared deadline has not passed. That stream was never scanned, so the
// verdict must still be ErrScanIncomplete with the marker, never a nil-error
// (cacheable) clean result.
func TestScanExtractedStreamTimeoutIsIncomplete(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule+stallOnQRule))
	s.scanTimeout = 2900 * time.Millisecond
	start := time.Now()
	m, err := s.Scan(singleMemberZip(t, "q.txt", []byte("Q stalls the native scan")), ScanMeta{})
	if elapsed := time.Since(start); elapsed >= s.scanTimeout {
		t.Fatalf("precondition: scan took %v, want the native timeout before the %v deadline", elapsed, s.scanTimeout)
	}
	if !errors.Is(err, ErrScanIncomplete) || !hasRule(m, scanIncompleteRule) {
		t.Fatalf("stream timeout: matches=%+v err=%v, want incomplete", m, err)
	}
}

// TestScanExtractedStreamCleanControl: the same container whose member does
// not stall completes with a nil error and no marker.
func TestScanExtractedStreamCleanControl(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule+stallOnQRule))
	s.scanTimeout = 2900 * time.Millisecond
	m, err := s.Scan(singleMemberZip(t, "a.txt", []byte("A harmless member")), ScanMeta{})
	if err != nil || len(m) != 0 {
		t.Fatalf("clean member: matches=%+v err=%v, want complete clean", m, err)
	}
}

// TestStreamScanOrder (PERF-50): real content streams are visited
// smallest-first ahead of the trailing decode blobs, deterministically and
// independent of runner speed. Boundary: zero/one content stream and a
// content count larger than the slice keep extractor order.
func TestStreamScanOrder(t *testing.T) {
	big, mid, small := make([]byte, 300), make([]byte, 200), make([]byte, 10)
	blob := make([]byte, 1)
	cases := []struct {
		name     string
		streams  [][]byte
		nContent int
		want     []int
	}{
		{"padding before dropper", [][]byte{big, mid, small, blob}, 3, []int{2, 1, 0, 3}},
		{"decode blobs stay last", [][]byte{big, blob, blob}, 1, []int{0, 1, 2}},
		{"equal sizes keep order", [][]byte{mid, mid, small}, 3, []int{2, 0, 1}},
		{"no content streams", [][]byte{big, small}, 0, []int{0, 1}},
		{"content count past end", [][]byte{big, small}, 9, []int{1, 0}},
		{"empty", nil, 0, []int{}},
	}
	for _, tc := range cases {
		got := streamScanOrder(tc.streams, tc.nContent)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
			}
		}
	}
}
