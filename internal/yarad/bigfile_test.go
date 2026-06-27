package yarad

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The oversized-buffer cost gate (YARAD_BIGFILE_THRESHOLD) scans a buffer larger
// than the threshold against a small targeted ruleset (BigFileRules) instead of
// the full bundle, so a multi-MB input completes fast and the local heuristics
// still fire instead of the full set timing out and fail-opening.
//
// These tests are hermetic: two tiny synthetic rulesets with DISTINCT marker
// strings stand in for "full set" vs "local big-file set". A buffer carrying BOTH
// markers lets us prove WHICH set was selected purely from which rule fired — no
// dependence on the real ~12k-rule bundle or the 8.86MB sample.

const fullSetRule = `
rule FullSetOnly_Rule : test
{
    strings:
        $m = "FULLSET_MARKER_AABBCC"
    condition:
        $m
}
`

const bigSetRule = `
rule BigFileOnly_Rule : test
{
    strings:
        $m = "BIGFILE_MARKER_XXYYZZ"
    condition:
        $m
}
`

// newBigScanner builds a scanner whose FULL set is fullSetRule and whose big-file
// set is bigSetRule, with the given byte threshold. When threshold==0 the gate is
// disabled. The two sets share no rule, so a match tells us which set was used.
func newBigScanner(t *testing.T, threshold int64) *Scanner {
	t.Helper()
	fullDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fullDir, "full.yar"), []byte(fullSetRule), 0o600); err != nil {
		t.Fatal(err)
	}
	bigDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(bigDir, "big.yar"), []byte(bigSetRule), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{RulesDir: fullDir, ScanTimeout: 0, BigFileThreshold: threshold, BigFileRules: bigDir}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

// bothMarkers returns a buffer containing both rulesets' marker strings, padded to
// at least n bytes so it can be pushed over a threshold.
func bothMarkers(n int) []byte {
	body := []byte("FULLSET_MARKER_AABBCC and BIGFILE_MARKER_XXYYZZ ")
	if len(body) < n {
		body = append(body, []byte(strings.Repeat("A", n-len(body)))...)
	}
	return body
}

func matchRuleNames(ms []Match) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Rule
	}
	return out
}

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// Over the threshold, the raw buffer is scanned against the big-file set: the
// big-file rule fires and the full-set rule does NOT (it isn't in that set), even
// though the buffer also carries the full-set marker. This is the core win: the
// local heuristic fires on an oversized buffer that would otherwise hit the full
// (slow, timeout-prone) set.
func TestBigFileGateSelectsBigRulesOverThreshold(t *testing.T) {
	s := newBigScanner(t, 100)
	buf := bothMarkers(512) // > 100 byte threshold
	m, err := s.Scan(buf, ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	names := matchRuleNames(m)
	if !has(names, "BigFileOnly_Rule") {
		t.Errorf("expected BigFileOnly_Rule to fire on oversized buffer, got %v", names)
	}
	if has(names, "FullSetOnly_Rule") {
		t.Errorf("full-set rule fired on oversized buffer; gate did not redirect to big-file set: %v", names)
	}
	if got := s.BigFileScans(); got != 1 {
		t.Errorf("BigFileScans = %d, want 1", got)
	}
}

// Below the threshold, behaviour is unchanged: the full set is used, so the
// full-set rule fires and the big-file rule does not. The metric stays 0.
func TestBigFileGateUsesFullSetBelowThreshold(t *testing.T) {
	s := newBigScanner(t, 1000)
	buf := bothMarkers(64) // < 1000 byte threshold
	m, err := s.Scan(buf, ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	names := matchRuleNames(m)
	if !has(names, "FullSetOnly_Rule") {
		t.Errorf("expected FullSetOnly_Rule below threshold, got %v", names)
	}
	if has(names, "BigFileOnly_Rule") {
		t.Errorf("big-file rule fired below threshold; gate triggered wrongly: %v", names)
	}
	if got := s.BigFileScans(); got != 0 {
		t.Errorf("BigFileScans = %d, want 0", got)
	}
}

// Threshold 0 disables the gate entirely: even a large buffer uses the full set.
func TestBigFileGateDisabledWhenThresholdZero(t *testing.T) {
	s := newBigScanner(t, 0)
	buf := bothMarkers(4096)
	m, err := s.Scan(buf, ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	names := matchRuleNames(m)
	if !has(names, "FullSetOnly_Rule") {
		t.Errorf("threshold=0 must use full set, got %v", names)
	}
	if has(names, "BigFileOnly_Rule") {
		t.Errorf("big-file rule fired with gate disabled: %v", names)
	}
	if got := s.BigFileScans(); got != 0 {
		t.Errorf("BigFileScans = %d, want 0", got)
	}
}

// When the big-file ruleset is nil (threshold set but no BigFileRules loaded), an
// oversized buffer must FALL BACK to the full set rather than crash or disarm.
func TestBigFileGateNilBigRulesFallsBack(t *testing.T) {
	// Build a scanner with a full set but no big-file ruleset configured, then set
	// the threshold low so an oversized buffer hits the gate with bigRules == nil.
	dir := writeRules(t, fullSetRule)
	cfg := &Config{RulesDir: dir, ScanTimeout: 0, BigFileThreshold: 100}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if s.bigRules.Load() != nil {
		t.Fatal("expected nil bigRules when BigFileRules unset")
	}
	buf := bothMarkers(512)
	m, err := s.Scan(buf, ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	names := matchRuleNames(m)
	if !has(names, "FullSetOnly_Rule") {
		t.Errorf("nil bigRules must fall back to full set, got %v", names)
	}
	if got := s.BigFileScans(); got != 0 {
		t.Errorf("BigFileScans = %d, want 0 (no big-file scan happened, fell back)", got)
	}
}

// zipWithMember builds an in-memory DEFLATE zip carrying one member. A highly
// compressible member (marker text + "A" padding) keeps the zip itself tiny while
// the extracted member is large — exactly the shape that must route the EXTRACTED
// stream (not the raw body) through the big-file gate.
func zipWithMember(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
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
	return buf.Bytes()
}

// An EXTRACTED stream over the threshold must be scanned against the big-file set,
// even when the RAW container is under it. We zip a large compressible member so
// the raw zip stays small (full set, no plaintext marker match) but the carved
// member is oversized: the big-file rule fires from the stream path and
// BigFileStreamScans increments. Without the fix the member would hit the full set
// and FullSetOnly_Rule would fire instead.
func TestBigFileGateRedirectsOversizedExtractedStream(t *testing.T) {
	s := newBigScanner(t, 100*1024) // 100 KiB threshold
	member := bothMarkers(300 * 1024)
	z := zipWithMember(t, "payload.bin", member)
	if int64(len(z)) > 100*1024 {
		t.Fatalf("raw zip %dB unexpectedly over threshold; test cannot isolate the stream path", len(z))
	}
	m, err := s.Scan(z, ScanMeta{Filename: "x.zip"})
	if err != nil {
		t.Fatal(err)
	}
	names := matchRuleNames(m)
	if !has(names, "BigFileOnly_Rule") {
		t.Errorf("expected BigFileOnly_Rule on oversized extracted member, got %v", names)
	}
	if has(names, "FullSetOnly_Rule") {
		t.Errorf("full-set rule fired on oversized extracted member; stream gate did not redirect: %v", names)
	}
	// The carved member can reach the scan path via more than one extractor route
	// (carrier child + member emit); each oversized hit counts. The contract is
	// "at least one oversized extracted stream was redirected", not an exact count.
	if got := s.BigFileStreamScans(); got < 1 {
		t.Errorf("BigFileStreamScans = %d, want >= 1", got)
	}
	if got := s.BigFileScans(); got != 0 {
		t.Errorf("BigFileScans = %d, want 0 (raw zip under threshold)", got)
	}
}

// A sub-threshold extracted member keeps full-rule coverage: the full-set rule
// fires from the stream path and the stream gate metric stays 0.
func TestBigFileGateKeepsFullSetForSmallExtractedStream(t *testing.T) {
	s := newBigScanner(t, 100*1024)
	member := bothMarkers(1024) // < 100 KiB
	z := zipWithMember(t, "payload.bin", member)
	m, err := s.Scan(z, ScanMeta{Filename: "x.zip"})
	if err != nil {
		t.Fatal(err)
	}
	names := matchRuleNames(m)
	if !has(names, "FullSetOnly_Rule") {
		t.Errorf("expected FullSetOnly_Rule on small extracted member, got %v", names)
	}
	if got := s.BigFileStreamScans(); got != 0 {
		t.Errorf("BigFileStreamScans = %d, want 0", got)
	}
}

// Config default: the threshold defaults to 6 MiB and a negative value disables.
func TestBigFileThresholdConfigDefaults(t *testing.T) {
	t.Setenv("YARAD_BIGFILE_THRESHOLD", "")
	c := LoadConfig()
	if c.BigFileThreshold != 6*1024*1024 {
		t.Errorf("default BigFileThreshold = %d, want %d", c.BigFileThreshold, 6*1024*1024)
	}
	t.Setenv("YARAD_BIGFILE_THRESHOLD", "-1")
	c = LoadConfig()
	if c.BigFileThreshold != 0 {
		t.Errorf("negative threshold should clamp to 0 (off), got %d", c.BigFileThreshold)
	}
}
