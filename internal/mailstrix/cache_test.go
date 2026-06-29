package mailstrix

import (
	"context"
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
	if lru, ok := c.(*lruCache); ok {
		if got := lru.Evictions(); got != 1 {
			t.Errorf("Evictions() = %d, want 1", got)
		}
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
			m, _, _ := g.Do(context.Background(), "samekey", func() ([]Match, bool) {
				mu.Lock()
				scans++
				mu.Unlock()
				time.Sleep(20 * time.Millisecond) // hold the flight so others join
				return []Match{{Rule: "X"}}, false
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
	_, sharedA, _ := g.Do(context.Background(), "a", func() ([]Match, bool) { return nil, false })
	_, sharedB, _ := g.Do(context.Background(), "b", func() ([]Match, bool) { return nil, false })
	if sharedA || sharedB {
		t.Error("sequential distinct keys must not report shared")
	}
}

// TestCacheGetReturnsImmutableCachedSlice guards the no-copy cache-hit contract:
// Get returns the cached slice itself, and callers must treat it as immutable.
func TestCacheGetReturnsImmutableCachedSlice(t *testing.T) {
	c := newLRU(t, time.Minute, 16)
	orig := []Match{{Rule: "A"}, {Rule: "B"}, {Rule: "C"}}
	c.Put("k", orig)

	got, ok := c.Get("k")
	if !ok || len(got) != 3 {
		t.Fatalf("first Get: ok=%v len=%d", ok, len(got))
	}
	again, ok := c.Get("k")
	if !ok || len(again) != 3 {
		t.Fatalf("second Get: ok=%v len=%d", ok, len(again))
	}
	if &got[0] != &again[0] {
		t.Error("cache hit returned a copied slice; immutable hit path should be zero-copy")
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

// TestFlightFollowerCancelReleases (AUDIT-FLIGHT-CONTEXT): a follower whose own
// context is cancelled while waiting must return at once with ctx.Err(), not
// block until the leader's (slow) scan finishes.
func TestFlightFollowerCancelReleases(t *testing.T) {
	var g flightGroup
	leaderIn := make(chan struct{})
	leaderRelease := make(chan struct{})
	go func() {
		g.Do(context.Background(), "k", func() ([]Match, bool) {
			close(leaderIn)
			<-leaderRelease // hold the flight open
			return nil, false
		})
	}()
	<-leaderIn // leader is now the in-flight owner

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := g.Do(ctx, "k", func() ([]Match, bool) { return nil, false })
		done <- err
	}()
	cancel() // follower's client "disconnects"
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled follower must return ctx.Err(), got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled follower blocked on the leader instead of bailing")
	}
	close(leaderRelease)
}

// TestFlightAbortedLeaderFollowerRerun (AUDIT-FLIGHT-CONTEXT): when the leader
// ABORTS (no real verdict, e.g. its client went away before a scan slot), a
// still-connected follower must NOT inherit the empty non-verdict — it promotes
// itself and re-runs fn, producing a real result.
func TestFlightAbortedLeaderFollowerRerun(t *testing.T) {
	var g flightGroup
	leaderIn := make(chan struct{})
	leaderRelease := make(chan struct{})
	go func() {
		g.Do(context.Background(), "k", func() ([]Match, bool) {
			close(leaderIn)
			<-leaderRelease
			return nil, true // ABORT — no real verdict
		})
	}()
	<-leaderIn

	var ran bool
	done := make(chan []Match, 1)
	go func() {
		m, _, _ := g.Do(context.Background(), "k", func() ([]Match, bool) {
			ran = true
			return []Match{{Rule: "REAL"}}, false
		})
		done <- m
	}()
	close(leaderRelease) // leader aborts → follower should re-run
	select {
	case m := <-done:
		if !ran {
			t.Fatal("follower accepted the aborted leader's non-verdict instead of re-running")
		}
		if len(m) != 1 || m[0].Rule != "REAL" {
			t.Fatalf("follower re-run result = %+v, want [REAL]", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower hung after leader abort")
	}
}

// TestFlightCancelledFollowerNotCountedShared (AUDIT-FLIGHT-CONTEXT, golang-pro
// F1): a follower that cancels mid-wait must NOT cause the leader to report
// shared=true (which would overcount cacheCoalesced). The leader of a flight that
// only ever had a since-cancelled follower reports shared=false.
func TestFlightCancelledFollowerNotCountedShared(t *testing.T) {
	var g flightGroup
	leaderIn := make(chan struct{})
	leaderRelease := make(chan struct{})
	leaderShared := make(chan bool, 1)
	go func() {
		_, shared, _ := g.Do(context.Background(), "k", func() ([]Match, bool) {
			close(leaderIn)
			<-leaderRelease
			return []Match{{Rule: "X"}}, false
		})
		leaderShared <- shared
	}()
	<-leaderIn

	ctx, cancel := context.WithCancel(context.Background())
	followerGone := make(chan struct{})
	go func() {
		g.Do(ctx, "k", func() ([]Match, bool) { return nil, false })
		close(followerGone)
	}()
	cancel()
	<-followerGone       // follower has cancelled + decremented its registration
	close(leaderRelease) // leader now finishes with zero live followers
	if shared := <-leaderShared; shared {
		t.Error("leader reported shared=true though its only follower had cancelled")
	}
}

// TestFlightPanicDoesNotHangWaiters guards STAB-1/STAB-3: if the flight leader's
// fn panics, deferred cleanup must still close fl.done and delete the map entry,
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
		g.Do(context.Background(), "boom", func() ([]Match, bool) { panic("scan fault") })
	}()

	// Map entry must be gone — a fresh call for the same key runs its own fn
	// (would block/hang if the dead flight were still registered).
	done := make(chan struct{})
	var ran bool
	go func() {
		g.Do(context.Background(), "boom", func() ([]Match, bool) { ran = true; return nil, false })
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
