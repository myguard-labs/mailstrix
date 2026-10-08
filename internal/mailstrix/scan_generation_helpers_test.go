package mailstrix

// AUD-M4a5: direct tests for the helpers extracted from scanGeneration.

import (
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

const rawTimeoutRule = `rule Timeout { condition: uint8(0) == 99 and for all i in (1..1000000000): (i > 0) }`

func quietScanner(t *testing.T, rules string, timeout time.Duration) (*Scanner, *[]string) {
	t.Helper()
	cfg := &Config{RulesDir: writeRules(t, rules), ScanTimeout: timeout}
	cfg.sanitize()
	var logs []string
	s, err := NewScanner(cfg, func(f string, a ...any) { logs = append(logs, f) })
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s, &logs
}

func TestScanRawChannelSuccess(t *testing.T) {
	s, _ := quietScanner(t, eicarRule, 0)
	out, err := s.scanRawChannel(s.rules.Load(), eicar(), ScanMeta{}, EffortProfile{})
	if err != nil || len(out) != 1 || out[0].Rule != "EICAR_Test_File" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if s.rawChannelScans.Load() != 1 || s.rawScanErrs.Load() != 0 {
		t.Fatalf("rawChannelScans=%d rawScanErrs=%d", s.rawChannelScans.Load(), s.rawScanErrs.Load())
	}
}

// The raw failure is returned (never swallowed), counted and logged, and the
// matches are dropped so the caller continues to extraction.
func TestScanRawChannelFailureReturnsError(t *testing.T) {
	s, logs := quietScanner(t, rawTimeoutRule, time.Second)
	out, err := s.scanRawChannel(s.rules.Load(), []byte("c"), ScanMeta{}, EffortProfile{ScanTimeout: time.Second})
	requireCAPENativeTimeout(t, err)
	if out != nil {
		t.Fatalf("matches kept after raw failure: %+v", out)
	}
	if s.rawScanErrs.Load() != 1 || len(*logs) == 0 || !strings.Contains((*logs)[len(*logs)-1], "raw scan failed") {
		t.Fatalf("rawScanErrs=%d logs=%v", s.rawScanErrs.Load(), *logs)
	}
}

func TestScanRawChannelMarkerFilteredOnRaw(t *testing.T) {
	s, _ := quietScanner(t, extractScanMarkerRule, 0)
	out, err := s.scanRawChannel(s.rules.Load(), []byte("OLEID-OBJECTPOOL"), ScanMeta{}, EffortProfile{})
	if err != nil || len(out) != 0 {
		t.Fatalf("marker rule fired on raw bytes: out=%+v err=%v", out, err)
	}
}

func TestNewMatchSeen(t *testing.T) {
	if got := newMatchSeen(nil); len(got) != 0 {
		t.Fatalf("empty: %v", got)
	}
	got := newMatchSeen([]Match{{Namespace: "a", Rule: "r"}, {Namespace: "a", Rule: "r"}, {Namespace: "b", Rule: "r"}})
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
	if _, ok := got[matchKey{namespace: "b", rule: "r"}]; !ok {
		t.Fatal("missing key")
	}
}

func TestBuildExtractOptions(t *testing.T) {
	dl := time.Now().Add(time.Minute)
	s := &Scanner{}
	if x := s.buildExtractOptions(ScanMeta{PWCandidates: []string{"pw"}}, EffortProfile{}, dl); x.ArchivePWEnabled || len(x.PWCandidates) != 0 {
		t.Fatalf("archivePW off must not enable passwords: %+v", x)
	}
	s = &Scanner{archivePW: true, archivePWDefaults: []string{"infected"}, archivePWWordlist: []string{"wl"}}
	x := s.buildExtractOptions(ScanMeta{PWCandidates: []string{"body"}, Filename: "x.zip"}, EffortProfile{}, dl)
	if !x.ArchivePWEnabled || len(x.PWCandidates) < 3 || x.PWCandidates[0] != "body" {
		t.Fatalf("candidate order/enable wrong: %+v", x.PWCandidates)
	}
	s = &Scanner{archivePW: true}
	if x := s.buildExtractOptions(ScanMeta{}, EffortProfile{}, dl); x.ArchivePWEnabled {
		t.Fatal("no candidates must leave archive passwords disabled")
	}
}

func TestExtractionIncomplete(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Second)
	for _, tc := range []struct {
		name string
		res  extract.Result
		dl   time.Time
		want bool
		log  string
	}{
		{"clean", extract.Result{}, future, false, ""},
		{"no deadline", extract.Result{}, time.Time{}, false, ""},
		{"deadline passed", extract.Result{}, past, true, "budget exhausted"},
		{"panicked", extract.Result{Panicked: true}, future, true, ""},
		{"cap hit", extract.Result{CapHits: []string{"streams", "depth"}}, future, true, "streams,depth"},
		{"failed alone stays complete", extract.Result{Failed: true}, future, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs []string
			s := &Scanner{logf: func(f string, a ...any) { logs = append(logs, f+" "+strings.Join(anyStrings(a), ",")) }}
			if got := s.extractionIncomplete(&tc.res, tc.dl); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			if tc.log != "" && !strings.Contains(strings.Join(logs, "|"), tc.log) {
				t.Fatalf("log %v missing %q", logs, tc.log)
			}
			if tc.log == "" && len(logs) != 0 {
				t.Fatalf("unexpected logs %v", logs)
			}
		})
	}
}

func anyStrings(a []any) []string {
	var o []string
	for _, v := range a {
		if s, ok := v.(string); ok {
			o = append(o, s)
		}
	}
	return o
}

func TestVBAKeySet(t *testing.T) {
	if got := vbaKeySet(&extract.Result{}); got != nil {
		t.Fatalf("no VBA streams must give nil, got %v", got)
	}
	a, b := []byte("macro-a"), []byte("macro-b")
	got := vbaKeySet(&extract.Result{VBAStreams: [][]byte{a, b, a}})
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
	if _, ok := got[streamDedupKey(a)]; !ok {
		t.Fatal("missing key")
	}
}

func TestRecordTopMatches(t *testing.T) {
	s := &Scanner{topMatches: newMatchCounter(8)}
	s.recordTopMatches(nil, s.topMatches.Epoch())
	if got := s.TopMatches(5); len(got) != 0 {
		t.Fatalf("empty input recorded: %v", got)
	}
	ep := s.topMatches.Epoch()
	s.recordTopMatches([]Match{{Rule: "A"}, {Rule: "A"}, {Rule: "B"}}, ep)
	got := s.TopMatches(5)
	if len(got) != 2 || got[0].Rule != "A" {
		t.Fatalf("top=%v", got)
	}
	s.topMatches.Reset()
	s.recordTopMatches([]Match{{Rule: "STALE"}}, ep)
	if got := s.TopMatches(5); len(got) != 0 {
		t.Fatalf("stale epoch recorded: %v", got)
	}
}

func TestAppendReputationMatchesGated(t *testing.T) {
	in := []Match{{Rule: "X"}}
	for _, p := range []EffortProfile{{ReputationFeeds: false}, {ReputationFeeds: true}} {
		s := &Scanner{} // no feeds configured
		out, inc := s.appendReputationMatches(in, false, p, []byte("b"), &extract.Result{}, [][16]byte{}, [16]byte{}, time.Time{})
		if len(out) != 1 || inc {
			t.Fatalf("profile %+v: out=%v inc=%v", p, out, inc)
		}
	}
	_, inc := (&Scanner{}).appendReputationMatches(nil, true, EffortProfile{}, nil, &extract.Result{}, [][16]byte{}, [16]byte{}, time.Time{})
	if !inc {
		t.Fatal("incoming incomplete flag must be preserved")
	}
}

func TestScanStreamLoop(t *testing.T) {
	a, b := []byte("stream-a"), []byte("stream-b")
	m1, m2 := []byte("marker-1"), []byte("marker-2")
	keys := [][16]byte{streamDedupKey(a), streamDedupKey(b)}
	// Ample budget: every stream and marker is visited.
	res := &extract.Result{Streams: [][]byte{a, b}, Markers: [][]byte{m1, m2}}
	s, x := newExtractScan(t, eicarRule, res)
	s.scanStreamLoop(x, res, keys, ScanMeta{})
	if x.streamsVisited != 2 || x.markersVisited != 2 || x.incomplete {
		t.Fatalf("visited streams=%d markers=%d incomplete=%v", x.streamsVisited, x.markersVisited, x.incomplete)
	}
	// Spent budget: the first stop breaks each loop and marks the verdict incomplete.
	res = &extract.Result{Streams: [][]byte{a, b}, Markers: [][]byte{m1, m2}}
	s, x = newExtractScan(t, eicarRule, res)
	x.deadline = time.Now().Add(-time.Second)
	s.scanStreamLoop(x, res, keys, ScanMeta{})
	if x.streamsVisited != 1 || x.markersVisited != 1 || !x.incomplete {
		t.Fatalf("loops must stop at first stop: streams=%d markers=%d incomplete=%v", x.streamsVisited, x.markersVisited, x.incomplete)
	}
}
