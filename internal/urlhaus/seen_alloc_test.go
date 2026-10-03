package urlhaus

import (
	"testing"

	"github.com/myguard-labs/mailstrix/internal/urlcand"
)

// TestCheckCandidatesSingleNoSeenAlloc (PERF-70): one clean candidate needs
// no duplicate-tracking map.
func TestCheckCandidatesSingleNoSeenAlloc(t *testing.T) {
	c := testChecker(t)
	one := urlcand.Extract([]byte("see https://clean.example/page"), 64)
	if len(one) != 1 {
		t.Fatalf("setup: %d candidates", len(one))
	}
	allocs := testing.AllocsPerRun(100, func() { _ = c.CheckCandidates(one, 64) })
	if allocs != 0 {
		t.Errorf("single clean candidate allocs = %g", allocs)
	}
}

// TestCheckCandidatesDedup (control): a URL listed twice still yields one hit.
func TestCheckCandidatesDedup(t *testing.T) {
	c := testChecker(t)
	two := urlcand.Extract([]byte("http://evil.example/malware.exe and again http://evil.example/malware.exe"), 64)
	if hits := c.CheckCandidates(two, 64); len(hits) != 1 {
		t.Fatalf("hits = %+v, want exactly one", hits)
	}
}
