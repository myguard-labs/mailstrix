package mailstrix

import (
	"fmt"
	"slices"
	"sort"
	"sync"
	"testing"
)

var topMatchesBenchmarkSink []MatchCount

func topNWithMapSnapshot(c *matchCounter, n int) []MatchCount {
	c.mu.Lock()
	snap := make(map[string]uint64, len(c.counts))
	for rule, count := range c.counts {
		snap[rule] = count
	}
	c.mu.Unlock()

	all := make([]MatchCount, 0, len(snap))
	for rule, count := range snap {
		all = append(all, MatchCount{Rule: rule, Count: count})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Count > all[j].Count })
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

func snapshotCounter(entries int) *matchCounter {
	c := newMatchCounter(entries)
	for i := 0; i < entries; i++ {
		c.counts[fmt.Sprintf("RULE_%04d", i)] = uint64(i + 1)
	}
	return c
}

func sortedMatchCounts(matches []MatchCount) []MatchCount {
	copyOfMatches := slices.Clone(matches)
	slices.SortFunc(copyOfMatches, func(a, b MatchCount) int {
		if a.Count != b.Count {
			if a.Count < b.Count {
				return -1
			}
			return 1
		}
		return cmpString(a.Rule, b.Rule)
	})
	return copyOfMatches
}

func cmpString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func TestTopNSnapshotParity(t *testing.T) {
	tests := []struct {
		name    string
		entries int
		n       int
	}{
		{name: "empty", entries: 0, n: 10},
		{name: "zero requested", entries: 8, n: 0},
		{name: "truncated", entries: 9, n: 6},
		{name: "request exceeds entries", entries: 9, n: 20},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := snapshotCounter(test.entries)
			got := c.TopN(test.n)
			want := topNWithMapSnapshot(c, test.n)
			if len(got) != len(want) {
				t.Fatalf("TopN(%d) returned %d matches, want %d", test.n, len(got), len(want))
			}
			if !slices.Equal(sortedMatchCounts(got), sortedMatchCounts(want)) {
				t.Fatalf("TopN(%d) match multiset = %v, want %v", test.n, got, want)
			}
			for i := 1; i < len(got); i++ {
				if got[i-1].Count < got[i].Count {
					t.Fatalf("TopN(%d) is not descending: %v", test.n, got)
				}
			}
		})
	}

	t.Run("ties retain complete multiset", func(t *testing.T) {
		c := snapshotCounter(9)
		for rule := range c.counts {
			c.counts[rule] = c.counts[rule] % 3
		}
		got := c.TopN(20)
		want := topNWithMapSnapshot(c, 20)
		if !slices.Equal(sortedMatchCounts(got), sortedMatchCounts(want)) {
			t.Fatalf("TopN tie multiset = %v, want %v", got, want)
		}
	})
}

func TestTopNSnapshotAllocationReduction(t *testing.T) {
	c := snapshotCounter(matchCounterCap)
	var got []MatchCount
	directAllocs := testing.AllocsPerRun(25, func() {
		got = c.TopN(matchCounterCap)
	})
	mapAllocs := testing.AllocsPerRun(25, func() {
		got = topNWithMapSnapshot(c, matchCounterCap)
	})
	if directAllocs >= mapAllocs {
		t.Fatalf("direct snapshot allocations = %.0f, map snapshot = %.0f; want fewer", directAllocs, mapAllocs)
	}
	topMatchesBenchmarkSink = got
}

func TestTopNSnapshotConcurrentResetAndAdd(t *testing.T) {
	c := newMatchCounter(matchCounterCap)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				c.Add([]string{fmt.Sprintf("RULE_%d_%d", worker, i)})
				c.TopN(20)
			}
		}(worker)
	}
	for i := 0; i < 20; i++ {
		c.Reset()
		c.TopN(20)
	}
	wg.Wait()
}

func BenchmarkTopNSnapshot(b *testing.B) {
	c := snapshotCounter(matchCounterCap)
	for _, benchmark := range []struct {
		name string
		topN func(*matchCounter, int) []MatchCount
	}{
		{name: "direct_slice", topN: (*matchCounter).TopN},
		{name: "map_copy", topN: topNWithMapSnapshot},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				topMatchesBenchmarkSink = benchmark.topN(c, matchCounterCap)
			}
		})
	}
}
