package mailstrix

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func newLRU(t *testing.T, ttl time.Duration, size int) Cache {
	t.Helper()
	cfg := &Config{CacheTTL: ttl, CacheSize: size}
	cfg.sanitize()
	return NewCache(cfg, func(string, ...any) {})
}

func newLRUBytes(t *testing.T, ttl time.Duration, size int, maxBytes uint64) *lruCache {
	t.Helper()
	if maxBytes > uint64(math.MaxInt64) {
		t.Fatalf("test byte budget %d exceeds int64", maxBytes)
	}
	c := NewCache(&Config{CacheTTL: ttl, CacheSize: size, CacheMaxBytes: int64(maxBytes)}, func(string, ...any) {}) // #nosec G115 -- range checked above.
	lru, ok := c.(*lruCache)
	if !ok {
		t.Fatalf("NewCache returned %T, want *lruCache", c)
	}
	return lru
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

func TestCacheByteEvictionBeforeCount(t *testing.T) {
	matches := []Match{{
		Rule:      strings.Repeat("rule", 64),
		Namespace: "fat-ruleset",
		Tags:      []string{"malware", "document"},
		Meta:      map[string]string{"description": strings.Repeat("x", 128)},
	}}
	one := cacheEntryRetainedBytes("a", matches)
	c := newLRUBytes(t, time.Minute, 10, one*2-1)
	c.Put("a", matches)
	c.Put("b", matches)
	if _, ok := c.Get("a"); ok {
		t.Fatal("byte budget retained the least-recently-used fat entry")
	}
	if got, ok := c.Get("b"); !ok || !reflect.DeepEqual(got, matches) {
		t.Fatalf("new complete entry missing or changed: ok=%v got=%+v", ok, got)
	}
	if c.ll.Len() >= c.max {
		t.Fatalf("byte eviction did not occur before count limit: len=%d max=%d", c.ll.Len(), c.max)
	}
	if c.Bytes() > c.maxBytes || c.Evictions() != 1 || c.ByteEvictions() != 1 || c.CountEvictions() != 0 {
		t.Fatalf("byte eviction stats bytes=%d/%d total=%d byte=%d count=%d", c.Bytes(), c.maxBytes, c.Evictions(), c.ByteEvictions(), c.CountEvictions())
	}
}

func TestCacheSimultaneousLimitsUseByteCause(t *testing.T) {
	matches := []Match{{Rule: strings.Repeat("x", 32)}}
	one := cacheEntryRetainedBytes("a", matches)
	c := newLRUBytes(t, time.Minute, 1, one*2-1)
	c.Put("a", matches)
	c.Put("b", matches)
	if c.Evictions() != 1 || c.ByteEvictions() != 1 || c.CountEvictions() != 0 {
		t.Fatalf("simultaneous breach cause total=%d byte=%d count=%d", c.Evictions(), c.ByteEvictions(), c.CountEvictions())
	}
}

func TestCacheReplacementGrowthShrinkAccounting(t *testing.T) {
	small := []Match{{Rule: "s"}}
	large := []Match{{Rule: strings.Repeat("L", 512), Meta: map[string]string{"detail": strings.Repeat("m", 256)}}}
	smallSize := cacheEntryRetainedBytes("a", small)
	largeSize := cacheEntryRetainedBytes("a", large)
	c := newLRUBytes(t, time.Minute, 10, largeSize+smallSize-1)
	c.Put("a", small)
	c.Put("b", small)
	c.Put("a", large)
	if _, ok := c.Get("b"); ok {
		t.Fatal("replacement growth should evict the LRU entry to satisfy bytes")
	}
	if got := c.Bytes(); got != largeSize {
		t.Fatalf("bytes after growth=%d want=%d", got, largeSize)
	}
	c.Put("a", small)
	if got := c.Bytes(); got != smallSize {
		t.Fatalf("bytes after shrink=%d want=%d", got, smallSize)
	}
}

func TestCacheRemovalAccounting(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		c := newLRUBytes(t, time.Nanosecond, 10, 1<<20)
		c.Put("k", []Match{{Rule: "R"}})
		time.Sleep(time.Millisecond)
		if _, ok := c.Get("k"); ok {
			t.Fatal("expired entry hit")
		}
		if c.Bytes() != 0 || c.Evictions() != 0 {
			t.Fatalf("expiry accounting bytes=%d evictions=%d", c.Bytes(), c.Evictions())
		}
	})
	t.Run("flush", func(t *testing.T) {
		c := newLRUBytes(t, time.Minute, 10, 1<<20)
		c.Put("k", []Match{{Rule: "R"}})
		c.Flush()
		if c.Bytes() != 0 || c.ll.Len() != 0 || len(c.items) != 0 {
			t.Fatalf("flush accounting bytes=%d list=%d items=%d", c.Bytes(), c.ll.Len(), len(c.items))
		}
	})
}

func TestCacheOversizedEntryDoesNotEvictUnrelated(t *testing.T) {
	keep := []Match{{Rule: "keep"}}
	limit := cacheEntryRetainedBytes("keep", keep)
	c := newLRUBytes(t, time.Minute, 10, limit)
	c.Put("keep", keep)
	c.Put("huge", []Match{{Rule: strings.Repeat("x", 4096)}})
	if _, ok := c.Get("keep"); !ok {
		t.Fatal("oversized insertion evicted unrelated entry")
	}
	if _, ok := c.Get("huge"); ok {
		t.Fatal("oversized entry was retained")
	}
	if c.Evictions() != 0 {
		t.Fatalf("unretained new oversized entry counted as eviction: %d", c.Evictions())
	}

	c.Put("keep", []Match{{Rule: strings.Repeat("y", 4096)}})
	if _, ok := c.Get("keep"); ok {
		t.Fatal("oversized replacement left stale value cached")
	}
	if c.Bytes() != 0 || c.ByteEvictions() != 1 || c.Evictions() != 1 {
		t.Fatalf("oversized replacement bytes=%d total=%d byte=%d", c.Bytes(), c.Evictions(), c.ByteEvictions())
	}
}

func TestCacheEntryAccountingIncludesCapacityTails(t *testing.T) {
	backing := []Match{
		{Rule: "visible", Tags: []string{"visible"}},
		{Rule: strings.Repeat("tail", 20), Tags: []string{"tail"}, Meta: map[string]string{"tail-key": "tail-value"}},
	}
	matches := backing[:1] // #nosec G602 -- literal backing has two elements.
	withTail := cacheEntryRetainedBytes("k", matches)
	withoutTail := cacheEntryRetainedBytes("k", append([]Match(nil), matches...))
	if withTail <= withoutTail {
		t.Fatalf("capacity-tail retention not charged: with=%d without=%d", withTail, withoutTail)
	}
	if got := saturatingAdd(^uint64(0)-1, 2); got != ^uint64(0) {
		t.Fatalf("saturatingAdd overflow=%d", got)
	}
}

func TestCacheEntryAccountingIncludesMetaPayloadBytes(t *testing.T) {
	const (
		keyGrowth   = 128
		valueGrowth = 4096
	)
	makeMatches := func(keyBytes, valueBytes int) []Match {
		return []Match{{
			Rule:      "same-rule",
			Namespace: "same-namespace",
			Tags:      []string{"same-tag"},
			Meta: map[string]string{
				strings.Repeat("k", keyBytes): strings.Repeat("v", valueBytes),
			},
		}}
	}
	base := makeMatches(1, 1)
	for _, tc := range []struct {
		name       string
		matches    []Match
		wantGrowth uint64
	}{
		{name: "key", matches: makeMatches(1+keyGrowth, 1), wantGrowth: keyGrowth},
		{name: "value", matches: makeMatches(1, 1+valueGrowth), wantGrowth: valueGrowth},
		{name: "key and value", matches: makeMatches(1+keyGrowth, 1+valueGrowth), wantGrowth: keyGrowth + valueGrowth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.matches) != len(base) || cap(tc.matches) != cap(base) ||
				len(tc.matches[0].Tags) != len(base[0].Tags) || cap(tc.matches[0].Tags) != cap(base[0].Tags) ||
				len(tc.matches[0].Meta) != len(base[0].Meta) {
				t.Fatal("metadata payload fixture changed retained container shape")
			}
			baseBytes := cacheEntryRetainedBytes("same-key", base)
			gotBytes := cacheEntryRetainedBytes("same-key", tc.matches)
			if gotBytes < baseBytes || gotBytes-baseBytes != tc.wantGrowth {
				t.Fatalf("metadata payload growth=%d want=%d (base=%d grown=%d)", gotBytes-baseBytes, tc.wantGrowth, baseBytes, gotBytes)
			}
		})
	}
}

func TestCacheAccountingBoundaryBranches(t *testing.T) {
	if got := saturatingMul(^uint64(0), 2); got != ^uint64(0) {
		t.Fatalf("saturatingMul overflow=%d", got)
	}
	if got := saturatingMul(0, ^uint64(0)); got != 0 {
		t.Fatalf("saturatingMul zero=%d", got)
	}
	if nilSize, emptySize := cacheEntryRetainedBytes("k", nil), cacheEntryRetainedBytes("k", []Match{}); nilSize != emptySize {
		t.Fatalf("nil/empty match accounting differs: nil=%d empty=%d", nilSize, emptySize)
	}
	nilMeta := cacheEntryRetainedBytes("k", []Match{{Rule: "r"}})
	emptyMeta := cacheEntryRetainedBytes("k", []Match{{Rule: "r", Meta: map[string]string{}}})
	if emptyMeta <= nilMeta {
		t.Fatalf("allocated empty Meta map not charged: nil=%d empty=%d", nilMeta, emptyMeta)
	}
	meta := make(map[string]string, 8)
	for i := 0; i < 8; i++ {
		meta[fmt.Sprintf("k%d", i)] = fmt.Sprintf("v%d", i)
	}
	if multi := cacheEntryRetainedBytes("k", []Match{{Meta: meta}}); multi <= emptyMeta+metaBucketBytes {
		t.Fatalf("multi-bucket Meta accounting too small: multi=%d empty=%d bucket=%d", multi, emptyMeta, metaBucketBytes)
	}

	t.Run("invalid list value", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("non-entry list value did not panic")
			}
		}()
		cacheEntryFromElement(list.New().PushBack("not-an-entry"))
	})
	t.Run("defensive byte floor", func(t *testing.T) {
		c := newLRUBytes(t, time.Minute, 10, 1<<20)
		c.Put("replace", []Match{{Rule: "old"}})
		c.bytes = 0 // simulate corrupted accounting; replacement must recover
		c.Put("replace", []Match{{Rule: "new"}})
		want := cacheEntryRetainedBytes("replace", []Match{{Rule: "new"}})
		if c.Bytes() != want {
			t.Fatalf("replacement recovery bytes=%d want=%d", c.Bytes(), want)
		}
		c.bytes = 0 // removal must also floor rather than underflow
		c.mu.Lock()
		c.removeElement(c.ll.Front())
		c.removeElement(nil)
		c.mu.Unlock()
		if c.Bytes() != 0 {
			t.Fatalf("removal recovery bytes=%d", c.Bytes())
		}
	})
}

func TestCacheCompleteValueParity(t *testing.T) {
	want := []Match{{Rule: "A", Namespace: "full.yar", Tags: []string{"tag-a", "tag-b"}, Meta: map[string]string{"author": "test", "score": "9"}}, {Rule: "B"}}
	c := newLRUBytes(t, time.Minute, 10, 1<<20)
	c.Put("k", want)
	got, ok := c.Get("k")
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("complete cache value changed: ok=%v got=%+v want=%+v", ok, got, want)
	}
}

func TestNewCacheNormalizesInvalidDirectLimits(t *testing.T) {
	for _, cfg := range []*Config{
		{CacheTTL: time.Minute},
		{CacheTTL: time.Minute, CacheSize: -1, CacheMaxBytes: -1},
	} {
		cache := NewCache(cfg, func(string, ...any) {})
		c, ok := cache.(*lruCache)
		if !ok {
			t.Fatalf("NewCache returned %T, want *lruCache", cache)
		}
		if c.max != 65536 || c.maxBytes != uint64(defaultCacheMaxBytes) {
			t.Fatalf("direct config limits max=%d bytes=%d", c.max, c.maxBytes)
		}
		c.Put("k", nil)
		if _, ok := c.Get("k"); !ok {
			t.Fatal("normalized direct config did not cache empty value")
		}
	}
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
		_, _, _ = g.Do(context.Background(), "k", func() ([]Match, bool) {
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
	for _, cancelAtRecheck := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancelAtRecheck=%v", cancelAtRecheck), func(t *testing.T) {
			var g flightGroup
			leaderIn := make(chan struct{})
			leaderRelease := make(chan struct{})
			release := sync.OnceFunc(func() { close(leaderRelease) })
			defer release()
			go func() {
				_, _, _ = g.Do(context.Background(), "k", func() ([]Match, bool) {
					close(leaderIn)
					<-leaderRelease
					return nil, true
				})
			}()
			<-leaderIn

			ctx := context.Background()
			if cancelAtRecheck {
				underlying, cancel := context.WithCancel(ctx)
				defer cancel()
				ctx = &flightCancelAtRecheck{Context: underlying, cancel: cancel}
			}
			type result struct {
				matches []Match
				err     error
			}
			done := make(chan result, 1)
			go func() {
				m, _, err := g.Do(ctx, "k", func() ([]Match, bool) {
					return []Match{{Rule: "REAL"}}, false
				})
				done <- result{m, err}
			}()
			// Releasing immediately after spawning can let the follower miss
			// the aborted flight entirely. Observe registration before release.
			deadline := time.Now().Add(2 * time.Second)
			for {
				g.mu.Lock()
				joined := g.m["k"].joiners == 1
				g.mu.Unlock()
				if joined {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("follower never joined the held leader")
				}
				runtime.Gosched()
			}
			release()
			select {
			case got := <-done:
				if cancelAtRecheck {
					if !errors.Is(got.err, context.Canceled) || len(got.matches) != 0 {
						t.Fatalf("canceled aborted-flight follower: matches=%v error=%v", got.matches, got.err)
					}
				} else if got.err != nil || len(got.matches) != 1 || got.matches[0].Rule != "REAL" {
					t.Fatalf("follower re-run result: matches=%v error=%v, want [REAL]", got.matches, got.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("follower hung after leader abort")
			}
		})
	}
}

// Cancel a real standard-library context precisely when the follower rechecks
// it after observing the aborted leader. Done closes before Err returns, as
// required by the context contract; cancellation timing is deterministic.
type flightCancelAtRecheck struct {
	context.Context
	cancel context.CancelFunc
}

func (c *flightCancelAtRecheck) Err() error {
	c.cancel()
	return c.Context.Err()
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
		_, _, _ = g.Do(ctx, "k", func() ([]Match, bool) { return nil, false })
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
		_, _, _ = g.Do(context.Background(), "boom", func() ([]Match, bool) { panic("scan fault") })
	}()

	// Map entry must be gone — a fresh call for the same key runs its own fn
	// (would block/hang if the dead flight were still registered).
	done := make(chan struct{})
	var ran bool
	go func() {
		_, _, _ = g.Do(context.Background(), "boom", func() ([]Match, bool) { ran = true; return nil, false })
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

// TestRedisPlaintextRemoteWarning tests the redisPlaintextRemote helper
// for detecting plaintext connections to remote (non-loopback) hosts.
func TestRedisPlaintextRemoteWarning(t *testing.T) {
	tests := []struct {
		name         string
		redisURL     string
		wantWarn     bool
		wantHost     string
		noCredInHost bool // if true, check that credentials do not appear in the returned host
	}{
		// Warn: plaintext to remote hosts
		{
			name:         "plaintext to remote IP",
			redisURL:     "redis://10.0.0.5:6379",
			wantWarn:     true,
			wantHost:     "10.0.0.5",
			noCredInHost: true,
		},
		{
			name:         "plaintext to hostname",
			redisURL:     "redis://cache.example:6379",
			wantWarn:     true,
			wantHost:     "cache.example",
			noCredInHost: true,
		},
		{
			name:         "plaintext remote with credentials",
			redisURL:     "redis://user:secret@10.0.0.5:6379/0",
			wantWarn:     true,
			wantHost:     "10.0.0.5",
			noCredInHost: true,
		},

		// No warn: TLS enabled
		{
			name:     "TLS to remote IP (rediss://)",
			redisURL: "rediss://10.0.0.5:6379",
			wantWarn: false,
		},

		// No warn: loopback addresses
		{
			name:     "plaintext to 127.0.0.1",
			redisURL: "redis://127.0.0.1:6379",
			wantWarn: false,
		},
		{
			name:     "plaintext to 127.8.9.10 (loopback range)",
			redisURL: "redis://127.8.9.10:6379",
			wantWarn: false,
		},
		{
			name:     "plaintext to localhost",
			redisURL: "redis://localhost:6379",
			wantWarn: false,
		},
		{
			name:     "plaintext to ::1 (IPv6 loopback)",
			redisURL: "redis://[::1]:6379",
			wantWarn: false,
		},

		// No warn: unix sockets
		{
			name:     "unix socket",
			redisURL: "unix:///var/run/redis.sock",
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt, err := redis.ParseURL(tt.redisURL)
			if err != nil {
				t.Fatalf("ParseURL failed: %v", err)
			}

			host, warn := redisPlaintextRemote(opt)

			if warn != tt.wantWarn {
				t.Errorf("warn=%v, want %v", warn, tt.wantWarn)
			}

			if tt.wantWarn && host != tt.wantHost {
				t.Errorf("host=%q, want %q", host, tt.wantHost)
			}

			// Verify credentials are not in the returned host string.
			if tt.noCredInHost && (host != "" && host != "localhost") {
				if contains(host, "secret") || contains(host, "user") {
					t.Errorf("host contains credentials: %q", host)
				}
			}
		})
	}
}

// TestNewCacheRedisPlaintextWarning tests that NewCache emits the plaintext warning
// when a plaintext Redis connection to a remote host is configured.
func TestNewCacheRedisPlaintextWarning(t *testing.T) {
	tests := []struct {
		name        string
		redisURL    string
		wantWarning bool
		description string
	}{
		{
			name:        "plaintext remote",
			redisURL:    "redis://10.0.0.5:6379",
			wantWarning: true,
			description: "should warn",
		},
		{
			name:        "TLS remote",
			redisURL:    "rediss://10.0.0.5:6379",
			wantWarning: false,
			description: "should not warn",
		},
		{
			name:        "plaintext localhost",
			redisURL:    "redis://localhost:6379",
			wantWarning: false,
			description: "should not warn for localhost",
		},
		{
			name:        "plaintext 127.0.0.1",
			redisURL:    "redis://127.0.0.1:6379",
			wantWarning: false,
			description: "should not warn for loopback IP",
		},
		{
			name:        "unix socket",
			redisURL:    "unix:///var/run/redis.sock",
			wantWarning: false,
			description: "should not warn for unix socket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs []string
			cfg := &Config{
				CacheTTL:  time.Minute,
				CacheSize: 10,
				RedisURL:  tt.redisURL,
			}
			cfg.sanitize()

			logf := func(format string, args ...any) {
				logs = append(logs, fmt.Sprintf(format, args...))
			}

			// Call NewCache, which will attempt to parse and validate the Redis URL.
			// For invalid URLs, it will log "redis cache disabled" and return normally.
			c := NewCache(cfg, logf)
			if c == nil {
				t.Fatal("NewCache returned nil")
			}

			// Check if the plaintext warning was emitted.
			foundWarning := false
			for _, log := range logs {
				if contains(log, "redis cache uses plaintext") {
					foundWarning = true
					break
				}
			}

			if foundWarning != tt.wantWarning {
				t.Errorf("%s: foundWarning=%v, want %v. logs=%v",
					tt.description, foundWarning, tt.wantWarning, logs)
			}
		})
	}
}

// Helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		len(s) > len(substr) && (s[:len(substr)] == substr || indexStr(s, substr) >= 0)
}

// Helper function for substring search.
func indexStr(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
