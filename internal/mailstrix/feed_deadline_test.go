package mailstrix

import (
	"errors"
	"fmt"
	"testing"
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
