package mailstrix

import (
	"fmt"
	"sync"
	"testing"
)

func TestMatchCounterBasic(t *testing.T) {
	c := newMatchCounter(matchCounterCap)
	c.Add([]string{"RULE_A", "RULE_B"})
	c.Add([]string{"RULE_A"})
	c.Add([]string{"RULE_A", "RULE_B", "RULE_C"})

	top := c.TopN(3)
	if len(top) != 3 {
		t.Fatalf("want 3 entries, got %d", len(top))
	}
	// RULE_A should be first (3 hits), RULE_B second (2), RULE_C third (1)
	if top[0].Rule != "RULE_A" || top[0].Count != 3 {
		t.Errorf("want RULE_A:3, got %s:%d", top[0].Rule, top[0].Count)
	}
	if top[1].Rule != "RULE_B" || top[1].Count != 2 {
		t.Errorf("want RULE_B:2, got %s:%d", top[1].Rule, top[1].Count)
	}
	if top[2].Rule != "RULE_C" || top[2].Count != 1 {
		t.Errorf("want RULE_C:1, got %s:%d", top[2].Rule, top[2].Count)
	}
	// TopN(1) should return only the top entry
	top1 := c.TopN(1)
	if len(top1) != 1 || top1[0].Rule != "RULE_A" {
		t.Errorf("TopN(1) want RULE_A, got %v", top1)
	}
	// TopN larger than count returns all
	topAll := c.TopN(100)
	if len(topAll) != 3 {
		t.Errorf("TopN(100) on 3-entry counter: want 3, got %d", len(topAll))
	}
}

func TestMatchCounterEviction(t *testing.T) {
	c := newMatchCounter(matchCounterCap)
	// Add matchCounterCap+1 unique rules — the lowest-hit one must be evicted.
	for i := 0; i <= matchCounterCap; i++ {
		c.Add([]string{fmt.Sprintf("RULE_%04d", i)})
	}
	c.mu.Lock()
	sz := len(c.counts)
	c.mu.Unlock()
	if sz > matchCounterCap {
		t.Errorf("map size %d exceeds cap %d", sz, matchCounterCap)
	}
}

func TestMatchCounterReset(t *testing.T) {
	c := newMatchCounter(matchCounterCap)
	c.Add([]string{"RULE_A", "RULE_B"})
	c.Reset()
	top := c.TopN(10)
	if len(top) != 0 {
		t.Errorf("after Reset, want empty TopN, got %v", top)
	}
}

func TestMatchCounterConcurrent(t *testing.T) {
	c := newMatchCounter(matchCounterCap)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Add([]string{fmt.Sprintf("RULE_%d_%d", id, j)})
			}
		}(i)
	}
	wg.Wait()
	// Just verify no panic and map is bounded.
	c.mu.Lock()
	sz := len(c.counts)
	c.mu.Unlock()
	if sz > matchCounterCap {
		t.Errorf("after concurrent adds, map size %d exceeds cap %d", sz, matchCounterCap)
	}
}

func TestMatchCounterAddAtDropsStaleEpoch(t *testing.T) {
	c := newMatchCounter(matchCounterCap)
	old := c.Epoch()
	c.AddAt(old, []string{"CUR"}) // same epoch: counted
	c.Reset()
	c.AddAt(old, []string{"OLD"}) // pinned before Reset: dropped
	if top := c.TopN(10); len(top) != 0 {
		t.Fatalf("stale-epoch hit leaked past Reset: %v", top)
	}
	c.AddAt(c.Epoch(), []string{"NEW"}) // negative control: current epoch counts
	if top := c.TopN(10); len(top) != 1 || top[0].Rule != "NEW" || top[0].Count != 1 {
		t.Fatalf("current-epoch hit lost: %v", top)
	}
}

// A scan that leased the old generation and finishes after a Reload must not
// count its hits in the new generation's top-matches (AUD-N6).
func TestTopMatchesIgnoresOldGenerationScanAfterReload(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	defer s.Close()
	stale := s.acquireScanLease()
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if m, err := stale.scan(eicar(), ScanMeta{}); err != nil || len(m) == 0 {
		t.Fatalf("stale lease scan: %v %v", m, err)
	}
	if top := s.TopMatches(10); len(top) != 0 {
		t.Fatalf("old-generation scan counted after reload: %v", top)
	}
	fresh := s.acquireScanLease() // negative control
	if m, err := fresh.scan(eicar(), ScanMeta{}); err != nil || len(m) == 0 {
		t.Fatalf("fresh lease scan: %v %v", m, err)
	}
	if top := s.TopMatches(10); len(top) != 1 || top[0].Rule != "EICAR_Test_File" {
		t.Fatalf("current-generation hit not counted: %v", top)
	}
}
