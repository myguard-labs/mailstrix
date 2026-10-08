package mailstrix

// AUD-M4a3: direct tests for extractScan.scan, extracted from scanGeneration.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

const extractScanMarkerRule = `
rule Marker_Literal : marker
{
    strings:
        $m = "OLEID-OBJECTPOOL"
    condition:
        $m
}
`

func newExtractScan(t *testing.T, src string, res *extract.Result) (*Scanner, *extractScan) {
	t.Helper()
	s := newScanner(t, writeRules(t, src))
	x := &extractScan{
		s:          s,
		seen:       map[[16]byte]struct{}{},
		res:        res,
		generation: scannerGeneration{rules: s.rules.Load(), bigRules: s.bigRules.Load(), markerRules: s.markerRules.Load()},
		rules:      s.rules.Load(),
		matchSeen:  map[matchKey]struct{}{},
	}
	return s, x
}

func TestExtractScanStreamMatch(t *testing.T) {
	s, x := newExtractScan(t, eicarRule, &extract.Result{Streams: [][]byte{eicar()}})
	b := eicar()
	if x.scan(b, streamDedupKey(b), false) {
		t.Fatal("stop = true, want false")
	}
	if len(x.out) != 1 || x.out[0].Rule != "EICAR_Test_File" {
		t.Fatalf("out = %+v", x.out)
	}
	if s.exStreamMatches.Load() != 1 || s.streamChannelScans.Load() != 1 || s.markerChannelScans.Load() != 0 {
		t.Fatalf("exStreamMatches=%d stream=%d marker=%d", s.exStreamMatches.Load(), s.streamChannelScans.Load(), s.markerChannelScans.Load())
	}
	if x.streamsVisited != 1 || x.markersVisited != 0 || x.incomplete || x.completionErr != nil {
		t.Fatalf("state = %+v", x)
	}
	// Already-seen rule on the raw scan is not appended twice.
	x.seen = map[[16]byte]struct{}{}
	x.scan(b, streamDedupKey(b), false)
	if len(x.out) != 1 || s.exStreamMatches.Load() != 1 {
		t.Fatalf("match-level dedup failed: out=%d exStreamMatches=%d", len(x.out), s.exStreamMatches.Load())
	}
}

func TestExtractScanDedup(t *testing.T) {
	s, x := newExtractScan(t, eicarRule, &extract.Result{})
	b := eicar()
	h := streamDedupKey(b)
	x.scan(b, h, false)
	if x.scan(b, h, false) {
		t.Fatal("stop = true on dup")
	}
	if s.exDeduped.Load() != 1 || s.streamChannelScans.Load() != 1 || x.streamsVisited != 2 {
		t.Fatalf("exDeduped=%d scans=%d visited=%d", s.exDeduped.Load(), s.streamChannelScans.Load(), x.streamsVisited)
	}
	// Seeded key (raw-body key) is skipped without a scan.
	s2, x2 := newExtractScan(t, eicarRule, &extract.Result{})
	x2.seen[h] = struct{}{}
	x2.scan(b, h, false)
	if s2.exDeduped.Load() != 1 || s2.streamChannelScans.Load() != 0 || len(x2.out) != 0 {
		t.Fatalf("seeded dedup: deduped=%d scans=%d out=%d", s2.exDeduped.Load(), s2.streamChannelScans.Load(), len(x2.out))
	}
	// Streams and markers share one seen set.
	x2.scan(b, h, true)
	if s2.exDeduped.Load() != 2 || s2.markerChannelScans.Load() != 0 || x2.markersVisited != 1 {
		t.Fatalf("shared seen: deduped=%d markerScans=%d", s2.exDeduped.Load(), s2.markerChannelScans.Load())
	}
}

func TestExtractScanMarkerChannel(t *testing.T) {
	s, x := newExtractScan(t, extractScanMarkerRule, &extract.Result{Markers: [][]byte{[]byte("OLEID-OBJECTPOOL")}})
	mk := []byte("OLEID-OBJECTPOOL")
	if x.scan(mk, streamDedupKey(mk), true) {
		t.Fatal("stop = true")
	}
	if s.markerChannelScans.Load() != 1 || s.streamChannelScans.Load() != 0 || x.markersVisited != 1 || x.streamsVisited != 0 {
		t.Fatalf("markerScans=%d streamScans=%d markers=%d streams=%d", s.markerChannelScans.Load(), s.streamChannelScans.Load(), x.markersVisited, x.streamsVisited)
	}
	if len(x.out) != 1 || x.out[0].Rule != "Marker_Literal" || s.exStreamMatches.Load() != 1 {
		t.Fatalf("out=%+v", x.out)
	}
	// Negative: the same marker on the content channel is rejected by the filter.
	s2, x2 := newExtractScan(t, extractScanMarkerRule, &extract.Result{})
	x2.scan(mk, streamDedupKey(mk), false)
	if len(x2.out) != 0 || s2.exStreamMatches.Load() != 0 {
		t.Fatalf("marker rule leaked into content channel: %+v", x2.out)
	}
}

func TestExtractScanBudgetExhausted(t *testing.T) {
	s, x := newExtractScan(t, eicarRule, &extract.Result{Streams: [][]byte{{1}, {2}, {3}}, Markers: [][]byte{{4}}})
	var mu sync.Mutex
	var logs []string
	s.logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, strings.TrimSpace(f))
	}
	x.deadline = time.Now().Add(-time.Second)
	b := eicar()
	if !x.scan(b, streamDedupKey(b), false) {
		t.Fatal("stop = false, want true on exhausted budget")
	}
	if !x.incomplete || len(x.out) != 0 || s.streamChannelScans.Load() != 0 {
		t.Fatalf("incomplete=%v out=%d scans=%d", x.incomplete, len(x.out), s.streamChannelScans.Load())
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "scan budget exhausted") {
		t.Fatalf("logs = %q", logs)
	}
	// Marker channel: the stream count stays, marker remainder is clamped at 0.
	_, y := newExtractScan(t, eicarRule, &extract.Result{})
	y.deadline = x.deadline
	y.s.logf = func(f string, a ...any) { logs = append(logs, f+"|") }
	logs = nil
	if !y.scan([]byte("m"), streamDedupKey([]byte("m")), true) || !y.incomplete {
		t.Fatal("marker budget exhaustion did not stop")
	}
	// Negative: a future deadline does not stop or mark incomplete.
	_, z := newExtractScan(t, eicarRule, &extract.Result{})
	z.deadline = time.Now().Add(time.Hour)
	if z.scan(b, streamDedupKey(b), false) || z.incomplete || len(z.out) != 1 {
		t.Fatalf("future deadline: incomplete=%v out=%d", z.incomplete, len(z.out))
	}
}

func TestExtractScanOversizedReroute(t *testing.T) {
	s, x := newExtractScan(t, eicarRule, &extract.Result{})
	s.bigFileThreshold = 4
	x.generation.bigRules = x.rules
	b := eicar()
	x.scan(b, streamDedupKey(b), false)
	if x.oversizedRerouted != 1 || s.bigFileStreamScans.Load() != 1 {
		t.Fatalf("rerouted=%d bigStreamScans=%d", x.oversizedRerouted, s.bigFileStreamScans.Load())
	}
	// No big ruleset: warn once, no reroute.
	s2, x2 := newExtractScan(t, eicarRule, &extract.Result{})
	s2.bigFileThreshold = 4
	x2.scan(b, streamDedupKey(b), false)
	if x2.oversizedRerouted != 0 || !s2.bigNilWarned.Load() || len(x2.out) != 1 {
		t.Fatalf("rerouted=%d warned=%v", x2.oversizedRerouted, s2.bigNilWarned.Load())
	}
}

const extractScanSlowRule = `
rule Slow_Loop
{
    condition:
        for all i in (0..2000000000) : (uint8(i % 8) >= 0)
}
`

// scanOne error path: a libyara timeout (reached via a pathologically slow
// rule and a 1s per-stream budget) must mark the verdict partial, record the
// error, and keep sweeping (stop = false). The budget comes from scanTimeout
// with no shared deadline, so a slow runner cannot turn this into the
// budget-exhausted path.
func TestExtractScanScanOneError(t *testing.T) {
	s, x := newExtractScan(t, extractScanSlowRule, &extract.Result{})
	var logged []string
	s.logf = func(f string, a ...any) { logged = append(logged, f) }
	x.deadline = time.Time{}
	s.scanTimeout = time.Second
	b := []byte("0123456789abcdef")
	if x.scan(b, streamDedupKey(b), false) {
		t.Fatal("stop = true on scanOne error, want false")
	}
	if x.completionErr == nil || !x.incomplete || len(x.out) != 0 {
		t.Fatalf("completionErr=%v incomplete=%v out=%d", x.completionErr, x.incomplete, len(x.out))
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "scan of extracted stream failed") {
		t.Fatalf("logged = %q", logged)
	}
}
