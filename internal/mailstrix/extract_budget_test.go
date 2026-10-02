package mailstrix

import (
	"archive/zip"
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// slowProseRule makes every prose stream expensive to scan, standing in for
// the full production ruleset on multi-MiB members (PERF-50): ~0.5 s/MiB in
// libyara, while unpacking the same bytes stays cheap even under -race.
const slowProseRule = `
rule Slow_Prose_Regex
{
    strings:
        $r = /[a-z]{1,64}\s+[a-z]{1,64}\s+[a-z]{1,64}\s+[a-z]{1,64}[0-9]/
    condition:
        $r
}
`

// proseParagraph returns a deterministic ~4 KiB paragraph of varied words: it
// deflates well when repeated but gives the scan real work.
func proseParagraph() string {
	words := []string{"invoice", "meeting", "quarterly", "Report", "attached", "please", "review", "budget",
		"approved", "Finance", "team", "schedule", "deadline", "Contract", "signed", "customer", "delivery",
		"project", "update", "Status", "pending", "regards", "thanks", "office", "Monday", "Friday"}
	var b strings.Builder
	x := uint32(2463534242)
	for b.Len() < 4096 {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b.WriteString(words[x%uint32(len(words))])
		if x%7 == 0 {
			b.WriteString(". ")
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// padSize is one padding member: six of them cost well over budgetTimeout to
// scan, while unpacking all six stays far below half of it.
const (
	padSize       = 2 << 20
	budgetTimeout = 4 * time.Second
)

// paddedDropperZip builds the PERF-50 shape: pad prose members that deflate to
// almost nothing but are slow to scan, followed by a small EICAR "dropper"
// member. pad=0 yields the unpadded control.
func paddedDropperZip(t *testing.T, pad int) []byte {
	t.Helper()
	prose := []byte(strings.Repeat(proseParagraph(), padSize/4096+1)[:padSize])
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for i := 0; i < pad; i++ {
		w, err := zw.Create("notes" + string(rune('a'+i)) + ".txt")
		if err != nil {
			t.Fatal(err)
		}
		// Distinct first byte per pad so stream dedup cannot collapse them.
		prose[0] = byte('a' + i)
		if _, err := w.Write(prose); err != nil {
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
	s := newScanner(t, writeRules(t, eicarRule+slowProseRule))
	s.scanTimeout = timeout
	return s
}

// TestScanPaddedZipFindsDropperAndMarksIncomplete: six 2 MiB prose members
// cost more than the whole budget to scan. The small dropper member must still
// be found, and the budget hit must surface as ErrScanIncomplete plus a
// log-only SCAN-INCOMPLETE marker rather than a nil-error verdict.
func TestScanPaddedZipFindsDropperAndMarksIncomplete(t *testing.T) {
	s := budgetScanner(t, budgetTimeout)
	m, err := s.Scan(paddedDropperZip(t, 6), ScanMeta{})
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
	m, err := budgetScanner(t, time.Nanosecond).Scan(paddedDropperZip(t, 6), ScanMeta{})
	if !errors.Is(err, ErrScanIncomplete) || !hasRule(m, scanIncompleteRule) {
		t.Fatalf("minimum budget: matches=%+v err=%v, want incomplete", m, err)
	}
	m, err = budgetScanner(t, 0).Scan(paddedDropperZip(t, 1), ScanMeta{})
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
