package yarad

import (
	"sync"
	"testing"
	"time"
)

func newLRU(t *testing.T, ttl time.Duration, size int) Cache {
	t.Helper()
	cfg := &Config{CacheTTL: ttl, CacheSize: size}
	cfg.sanitize()
	return NewCache(cfg, func(string, ...any) {})
}

func TestRedisBreaker(t *testing.T) {
	var b redisBreaker
	if !b.allow() {
		t.Fatal("a fresh breaker must allow")
	}
	// A run of real failures trips it.
	for i := 0; i < breakerTrip; i++ {
		b.fail()
	}
	if b.allow() {
		t.Error("breaker should be open after breakerTrip consecutive failures")
	}
	// A success closes it again.
	b.ok()
	if !b.allow() {
		t.Error("ok() must close the breaker")
	}
	// After the cooldown elapses it half-opens (allows a probe) even while open.
	for i := 0; i < breakerTrip; i++ {
		b.fail()
	}
	b.mu.Lock()
	b.openUntil = time.Now().Add(-time.Second) // simulate cooldown elapsed
	b.mu.Unlock()
	if !b.allow() {
		t.Error("breaker should half-open once the cooldown has passed")
	}
}

func TestCacheDisabledWhenTTLZero(t *testing.T) {
	c := newLRU(t, 0, 10)
	c.Put("k", []Match{{Rule: "R"}})
	if _, ok := c.Get("k"); ok {
		t.Error("ttl=0 should disable caching")
	}
}

func TestCacheHit(t *testing.T) {
	c := newLRU(t, time.Minute, 10)
	c.Put("k", []Match{{Rule: "EICAR"}})
	m, ok := c.Get("k")
	if !ok || len(m) != 1 || m[0].Rule != "EICAR" {
		t.Errorf("cache hit failed: %+v ok=%t", m, ok)
	}
	if _, ok := c.Get("absent"); ok {
		t.Error("absent key should miss")
	}
}

func TestCacheExpiry(t *testing.T) {
	c := newLRU(t, 20*time.Millisecond, 10)
	c.Put("k", []Match{{Rule: "R"}})
	time.Sleep(40 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Error("expired entry should miss")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	c := newLRU(t, time.Minute, 2)
	c.Put("a", nil)
	c.Put("b", nil)
	c.Get("a")      // touch a -> b now LRU
	c.Put("c", nil) // evicts b
	if _, ok := c.Get("b"); ok {
		t.Error("b should have been evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Error("a was touched, should survive")
	}
	if _, ok := c.Get("c"); !ok {
		t.Error("c just inserted, should be present")
	}
}

func TestCacheFlush(t *testing.T) {
	c := newLRU(t, time.Minute, 10)
	c.Put("k", []Match{{Rule: "R"}})
	c.Flush()
	if _, ok := c.Get("k"); ok {
		t.Error("flush should clear entries")
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := newLRU(t, time.Minute, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := string(rune('a' + i%26))
			c.Put(k, []Match{{Rule: k}})
			c.Get(k)
		}(i)
	}
	wg.Wait() // -race catches data races here
}

func TestFlightCoalesces(t *testing.T) {
	var g flightGroup
	var scans int
	var mu sync.Mutex
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([][]Match, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			m, _ := g.Do("samekey", func() []Match {
				mu.Lock()
				scans++
				mu.Unlock()
				time.Sleep(20 * time.Millisecond) // hold the flight so others join
				return []Match{{Rule: "X"}}
			})
			results[i] = m
		}(i)
	}
	close(start)
	wg.Wait()
	mu.Lock()
	got := scans
	mu.Unlock()
	if got >= 100 {
		t.Errorf("coalescing did nothing: %d scans for 100 identical requests", got)
	}
	for i, r := range results {
		if len(r) != 1 || r[0].Rule != "X" {
			t.Fatalf("result[%d] = %+v, all callers must get the leader's result", i, r)
		}
	}
}

func TestFlightDistinctKeysDontCoalesce(t *testing.T) {
	var g flightGroup
	_, sharedA := g.Do("a", func() []Match { return nil })
	_, sharedB := g.Do("b", func() []Match { return nil })
	if sharedA || sharedB {
		t.Error("sequential distinct keys must not report shared")
	}
}

// TestCacheGetReturnsIsolatedSlice guards the defensive copy in Get: a caller
// that mutates the returned matches in place (e.g. an in-place filter) must NOT
// corrupt the shared cached entry for other concurrent callers.
func TestCacheGetReturnsIsolatedSlice(t *testing.T) {
	c := newLRU(t, time.Minute, 16)
	orig := []Match{{Rule: "A"}, {Rule: "B"}, {Rule: "C"}}
	c.Put("k", orig)

	got, ok := c.Get("k")
	if !ok || len(got) != 3 {
		t.Fatalf("first Get: ok=%v len=%d", ok, len(got))
	}
	// Mutate the returned slice in place (overwrite + truncate), as an in-place
	// filter would.
	got[0] = Match{Rule: "MUTATED"}
	got = got[:1]
	_ = got

	again, ok := c.Get("k")
	if !ok || len(again) != 3 {
		t.Fatalf("second Get changed: ok=%v len=%d (cache corrupted by caller mutation)", ok, len(again))
	}
	if again[0].Rule != "A" || again[2].Rule != "C" {
		t.Errorf("cached entry mutated by caller: %+v", again)
	}
}

func TestNoopCacheDegraded(t *testing.T) {
	var c noopCache
	if d := c.Degraded(); d != "" {
		t.Errorf("noopCache.Degraded() = %q, want empty", d)
	}
}

func TestLRUCacheDegradedNoRedis(t *testing.T) {
	c := newLRU(t, time.Minute, 10)
	if d := c.Degraded(); d != "" {
		t.Errorf("lruCache without redis.Degraded() = %q, want empty", d)
	}
}

func TestBreakerIsOpenAfterTrip(t *testing.T) {
	var b redisBreaker
	for i := 0; i < breakerTrip; i++ {
		b.fail()
	}
	if !b.isOpen() {
		t.Error("breaker should be open after breakerTrip consecutive failures")
	}
}

func TestBreakerIsOpenResetsOnOK(t *testing.T) {
	var b redisBreaker
	for i := 0; i < breakerTrip; i++ {
		b.fail()
	}
	b.ok()
	if b.isOpen() {
		t.Error("ok() must close the breaker (isOpen should be false)")
	}
}

func TestBreakerIsOpenAfterCooldown(t *testing.T) {
	var b redisBreaker
	for i := 0; i < breakerTrip; i++ {
		b.fail()
	}
	// Simulate cooldown elapsed.
	b.mu.Lock()
	b.openUntil = time.Now().Add(-time.Second)
	b.mu.Unlock()
	if b.isOpen() {
		t.Error("breaker should be closed once cooldown has elapsed")
	}
}

// TestFlightPanicDoesNotHangWaiters guards STAB-1/STAB-3: if the flight leader's
// fn panics, deferred cleanup must still release fl.wg and delete the map entry,
// so coalesced waiters return (with no matches) instead of blocking forever, and
// the key is not permanently stuck coalescing. The leader's panic still
// propagates so it fails loudly.
func TestFlightPanicDoesNotHangWaiters(t *testing.T) {
	var g flightGroup

	// Leader panics.
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("leader panic was swallowed; it must propagate")
			}
		}()
		g.Do("boom", func() []Match { panic("scan fault") })
	}()

	// Map entry must be gone — a fresh call for the same key runs its own fn
	// (would block/hang if the dead flight were still registered).
	done := make(chan struct{})
	var ran bool
	go func() {
		g.Do("boom", func() []Match { ran = true; return nil })
		close(done)
	}()
	select {
	case <-done:
		if !ran {
			t.Fatal("follow-up call did not run its fn; stale flight entry left behind")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follow-up Do hung; panicked leader left the key registered")
	}
}
