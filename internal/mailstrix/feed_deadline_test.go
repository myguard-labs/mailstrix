package mailstrix

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// TestReputationLoopStopsAtDeadline (PERF-52) isolates the reputation loop.
// An expired deadline must stop before a distinct, known-malicious stream;
// disabling the deadline must check that same stream. This avoids conflating
// archive extraction and machine-dependent URL extraction timing with the loop.
func TestReputationLoopStopsAtDeadline(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()
	raw := []byte("no URLs here")
	stream := []byte(feedURLBody)
	res := &extract.Result{Streams: [][]byte{stream}}
	keys := [][16]byte{streamDedupKey(stream)}
	seed := streamDedupKey(raw)
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired=%v", expired), func(t *testing.T) {
			var deadline time.Time
			if expired {
				deadline = time.Now().Add(-time.Second)
			}
			hits, incomplete := s.urlFeedMatches(raw, res, keys, seed, deadline)
			if incomplete != expired || hasRule(hits, "URLHAUS_MALWARE_URL") == expired {
				t.Fatalf("deadline stop: expired=%v incomplete=%v hits=%v", expired, incomplete, hits)
			}
			matches, err := finalScanVerdict(hits, incomplete, nil, nil, ScanMeta{}, deadline)
			if expired && (!errors.Is(err, ErrScanIncomplete) || !hasRule(matches, scanIncompleteRule)) {
				t.Fatalf("want incomplete verdict, got matches=%v err=%v", matches, err)
			}
			if !expired && err != nil {
				t.Fatal(err)
			}
		})
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

// TestScanReputationDeadlineForwarding exercises the public caller chain with
// two distinct extracted members. Virtual time expires exactly at the shared
// deadline after extraction, before reputation matching starts.
func TestScanReputationDeadlineForwarding(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newURLhausScanner(t)
		defer s.Close()
		body := makePlainZIP(t, [][]byte{[]byte("ordinary first member"), []byte(feedURLBody)})
		const budget = time.Second
		s.scanTimeout = budget
		s.bigFileThreshold = 1
		rawReached := false
		reached := false
		s.logf = func(format string, args ...any) {
			// Consume half the budget at the real raw-channel setup log. Extraction
			// still has positive time; the native whole-second stream guard then fires.
			if strings.HasPrefix(format, "WARNING: oversized buffer") {
				rawReached = true
				time.Sleep(budget / 2)
			}
			if strings.HasPrefix(format, "scan budget exhausted;") {
				if reached {
					t.Fatal("budget barrier reached twice")
				}
				reached = true
				if args[0] != 2 {
					t.Fatalf("extracted streams remaining=%v want=2", args[0])
				}
				time.Sleep(budget / 2)
			}
		}
		started := time.Now()
		matches, err := s.Scan(body, ScanMeta{})
		if !rawReached || !reached {
			t.Fatal("public Scan did not reach extracted-stream budget barrier")
		}
		if elapsed := time.Since(started); elapsed != budget {
			t.Fatalf("scan elapsed=%v want shared budget=%v", elapsed, budget)
		}
		if !errors.Is(err, ErrScanIncomplete) || !hasRule(matches, scanIncompleteRule) {
			t.Fatalf("expired Scan verdict matches=%v err=%v", matches, err)
		}
		if hasRule(matches, "URLHAUS_MALWARE_URL") {
			t.Fatal("expired Scan forwarded no deadline to reputation matching")
		}
		// With the deadline disabled the same multi-stream archive must reach the
		// malicious second member and return a complete verdict.
		s.scanTimeout = 0
		s.logf = func(string, ...any) {}
		matches, err = s.Scan(body, ScanMeta{})
		if err != nil || !hasRule(matches, "URLHAUS_MALWARE_URL") || hasRule(matches, scanIncompleteRule) {
			t.Fatalf("complete multi-stream Scan matches=%v err=%v", matches, err)
		}
	})
}
