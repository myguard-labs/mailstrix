package extract

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

// AUD-03c: a blob the budget check rejects must NOT be recorded in the
// per-source seen set. The decodeSourceTree half of that contract is not
// observable (a budget rejection there ends the whole walk), so only the global
// BFS in fromEncoded is pinned here, through its later-queue-item consequence.
//
// Construction (one source, cumulative cap): depth 0 accepts filler blobs and an
// encoded child Y until cum sits exactly `slack` bytes under maxCumulativeDecoded,
// then meets B (len(B) > slack), which the cum cap rejects. Y is re-enqueued at
// depth 1 and decodes to B followed by C (len(C) <= slack). Correct code
// budget-fails the second B again, which stops Y's decoder chain, so C is never
// emitted. If the rejected B had been recorded as seen, the second B would dedup
// (return true) and C would be emitted.

const seenBudgetSlack = 24

func seenBudgetB() []byte { return []byte("BBBB-rejected-by-cum-cap-marker-0123456789") }

func seenBudgetC(n int) []byte {
	c := bytes.Repeat([]byte("c"), n)
	copy(c, "CCCC-")
	return c
}

func b64Of(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(b)) }

// seenBudgetSource builds the source for one case and returns it with the
// pieces the assertions need.
func seenBudgetSource(t *testing.T, yWithB bool, cSize int) (src, y, c []byte, fillers [][]byte) {
	t.Helper()
	b := seenBudgetB()
	c = seenBudgetC(cSize)
	var ybuf bytes.Buffer
	ybuf.WriteString("see ")
	if yWithB {
		ybuf.Write(b64Of(b))
		ybuf.WriteString(" then ")
	}
	ybuf.Write(b64Of(c))
	ybuf.WriteString("\n")
	y = ybuf.Bytes()

	total := maxCumulativeDecoded - seenBudgetSlack - len(y)
	const nf = 5
	for i := 0; i < nf; i++ {
		n := total / nf
		if i == nf-1 {
			n = total - (nf-1)*(total/nf)
		}
		// Prose with a unique prefix: distinct (no dedup), mostly text, and no
		// long base64-alphabet run, so it is never re-enqueued.
		f := make([]byte, 0, n)
		f = append(f, fmt.Appendf(nil, "filler number %d. ", i)...)
		for len(f) < n {
			f = append(f, "the quick brown fox. "...)
		}
		fillers = append(fillers, f[:n])
	}

	var sb bytes.Buffer
	for _, f := range fillers {
		sb.Write(b64Of(f))
		sb.WriteString("\n")
	}
	sb.Write(b64Of(y))
	sb.WriteString("\n")
	sb.Write(b64Of(b)) // rejected by the cum cap at depth 0
	sb.WriteString("\n")
	return sb.Bytes(), y, c, fillers
}

func seenBudgetHas(res *Result, want []byte) bool {
	for _, s := range res.Streams {
		if bytes.Equal(s, want) {
			return true
		}
	}
	return false
}

func TestSeenBudgetRejectedBlobNotRecorded(t *testing.T) {
	cases := []struct {
		name   string
		yWithB bool
		cSize  int
		wantC  bool
	}{
		// Positive: B rejected at depth 0 must be rejected again at depth 1, so
		// the chain stops before C.
		{"positive_rejected_B_blocks_C", true, seenBudgetSlack, false},
		// Boundary: no B on the path; C lands cum exactly on the cap and is
		// accepted (the check is a strict `>`).
		{"boundary_exact_cap_accepted", false, seenBudgetSlack, true},
		// Boundary: one byte over the cap is rejected.
		{"boundary_one_over_rejected", false, seenBudgetSlack + 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, y, c, fillers := seenBudgetSource(t, tc.yWithB, tc.cSize)
			b := seenBudgetB()
			if len(b) <= seenBudgetSlack {
				t.Fatalf("construction: len(B)=%d must exceed slack %d", len(b), seenBudgetSlack)
			}
			res := &Result{}
			fromEncoded(src, res, FullOptions(time.Time{}))

			// Anti-vacuity: all fillers and Y were accepted, B never was.
			for i, f := range fillers {
				if !seenBudgetHas(res, f) {
					t.Fatalf("filler %d missing: construction did not reach the cum fill", i)
				}
			}
			if !seenBudgetHas(res, y) {
				t.Fatalf("Y missing from res.Streams: depth-0 acceptance not reached")
			}
			if seenBudgetHas(res, b) {
				t.Fatalf("B was accepted; it must be rejected by the cum cap")
			}
			cum := 0
			for _, f := range fillers {
				cum += len(f)
			}
			cum += len(y)
			if cum != maxCumulativeDecoded-seenBudgetSlack {
				t.Fatalf("construction: cum before C = %d, want %d", cum, maxCumulativeDecoded-seenBudgetSlack)
			}

			if got := seenBudgetHas(res, c); got != tc.wantC {
				t.Fatalf("C present = %v, want %v (budget-rejected B recorded as seen?)", got, tc.wantC)
			}
			if tc.wantC && cum+len(c) != maxCumulativeDecoded {
				t.Fatalf("exact-cap case: cum+len(C) = %d, want %d", cum+len(c), maxCumulativeDecoded)
			}
		})
	}
}
