package mailstrix

import (
	"runtime"
	"testing"
	"time"
)

// allocBytes returns cumulative bytes allocated by fn (GC-independent).
func allocBytes(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

func TestNewCacheDoesNotPreSizeToCapacity(t *testing.T) {
	const bound = 128 << 10 // a 65536-entry pre-sized map costs MiBs
	var c Cache
	got := allocBytes(func() { c = newLRU(t, time.Minute, 65536) })
	if got > bound {
		t.Fatalf("NewCache(size=65536) allocated %d bytes, want <= %d", got, bound)
	}
	lru, ok := c.(*lruCache)
	if !ok {
		t.Fatalf("NewCache returned %T, want *lruCache", c)
	}
	if lru.max != 65536 {
		t.Fatalf("max=%d, want 65536 (capacity unchanged)", lru.max)
	}
	if fl := allocBytes(lru.Flush); fl > bound {
		t.Fatalf("Flush allocated %d bytes, want <= %d", fl, bound)
	}
}

func TestInitialMapHint(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{-1, 0}, {0, 0}, {1, 1}, {maxInitialMapHint, maxInitialMapHint}, {65536, maxInitialMapHint},
	} {
		if got := initialMapHint(tc.in); got != tc.want {
			t.Errorf("initialMapHint(%d)=%d want %d", tc.in, got, tc.want)
		}
	}
}

func TestCacheGrowsPastInitialHint(t *testing.T) {
	c := newLRU(t, time.Minute, 1000)
	for i := 0; i < 1000; i++ {
		c.Put(string(rune('a'+i%26))+time.Duration(i).String(), []Match{{Rule: "r"}})
	}
	lru, ok := c.(*lruCache)
	if !ok {
		t.Fatalf("NewCache returned %T, want *lruCache", c)
	}
	if n := len(lru.items); n < maxInitialMapHint*2 {
		t.Fatalf("items=%d, expected growth beyond hint", n)
	}
}
