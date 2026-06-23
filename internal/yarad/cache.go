package yarad

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache stores scan verdicts keyed by SHA256(body). A YARA verdict is a pure
// function of the scanned bytes and the rule set, so unlike gozer's collaborative
// verdicts there is nothing to invalidate per-message — entries only expire by
// TTL. On a rules reload the whole cache is dropped (Flush) since old verdicts
// were computed against the previous rule set.
type Cache interface {
	Get(key string) ([]Match, bool)
	Put(key string, matches []Match)
	Flush()
	// Degraded returns a non-empty human-readable reason when the cache is
	// operating in a reduced capacity (e.g. the Redis circuit breaker is open).
	// An empty string means fully operational. Disabled caching (noopCache) is
	// not degraded — it is an intentional configuration.
	Degraded() string
}

// noopCache is used when YARAD_CACHE_TTL=0 (caching disabled): every Get misses.
type noopCache struct{}

func (noopCache) Get(string) ([]Match, bool) { return nil, false }
func (noopCache) Put(string, []Match)        {}
func (noopCache) Flush()                     {}
func (noopCache) Degraded() string           { return "" }

// lruCache is the always-on in-process layer: a TTL'd LRU bounded to CacheSize
// entries. Concurrency is a single mutex — Get/Put are O(1) and hold it only for
// the map/list ops, never across a scan. Under load the lock is uncontended
// relative to scan cost.
type lruCache struct {
	mu        sync.Mutex
	ttl       time.Duration
	max       int
	ll        *list.List               // front = most recently used
	items     map[string]*list.Element // key -> element
	redis     *redisLayer              // optional shared L2 (nil when no YARAD_REDIS_URL)
	evictions atomic.Uint64            // LRU evictions (capacity-driven, not TTL expiry)
}

type entry struct {
	key     string
	matches []Match
	expires time.Time
}

// NewCache builds the verdict cache from cfg. TTL<=0 returns a noop cache. When
// RedisURL is set, a shared L2 is attached; a Redis that fails at runtime is
// treated as a miss (fail-open to scanning), never an error to the caller.
func NewCache(cfg *Config, logf func(string, ...any)) Cache {
	if cfg.CacheTTL <= 0 {
		return noopCache{}
	}
	c := &lruCache{
		ttl:   cfg.CacheTTL,
		max:   cfg.CacheSize,
		ll:    list.New(),
		items: make(map[string]*list.Element, cfg.CacheSize),
	}
	if cfg.RedisURL != "" {
		if rl, err := newRedisLayer(cfg); err != nil {
			logf("WARNING redis cache disabled: %v", err)
		} else {
			c.redis = rl
			logf("redis verdict cache enabled (prefix=%s)", cfg.RedisPrefix)
		}
	}
	return c
}

func (c *lruCache) Get(key string) ([]Match, bool) {
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry)
		if time.Now().Before(e.expires) {
			c.ll.MoveToFront(el)
			// Return a copy of the slice header so a caller that filters/sorts the
			// result in place (e.g. an in-place `[:0]` filter) can't corrupt the
			// shared cached entry for other concurrent goroutines. Match slices are
			// tiny (usually 0–few hits), so this copy is negligible even on the hot
			// path. The inner Tags/Meta are still shared but no caller mutates them.
			m := make([]Match, len(e.matches))
			copy(m, e.matches)
			c.mu.Unlock()
			return m, true
		}
		// expired — drop it and fall through to L2
		c.removeElement(el)
	}
	c.mu.Unlock()

	// L1 miss: try the shared Redis layer, and on a hit promote into L1.
	if c.redis != nil {
		if m, ok := c.redis.get(key); ok {
			c.Put(key, m)
			return m, true
		}
	}
	return nil, false
}

func (c *lruCache) Put(key string, matches []Match) {
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry)
		e.matches = matches
		e.expires = time.Now().Add(c.ttl)
		c.ll.MoveToFront(el)
		c.mu.Unlock()
	} else {
		el := c.ll.PushFront(&entry{key: key, matches: matches, expires: time.Now().Add(c.ttl)})
		c.items[key] = el
		for c.ll.Len() > c.max {
			c.removeElement(c.ll.Back())
			c.evictions.Add(1)
		}
		c.mu.Unlock()
	}
	if c.redis != nil {
		c.redis.put(key, matches, c.ttl)
	}
}

// Flush clears L1 (called on a rules reload). L2 is left to TTL-expire on its
// own: other replicas may still be on the old rule set mid-rollout, and Redis
// keys are namespaced so a stale entry just expires within CacheTTL.
func (c *lruCache) Flush() {
	c.mu.Lock()
	c.ll.Init()
	c.items = make(map[string]*list.Element, c.max)
	c.mu.Unlock()
}

// Degraded returns "redis breaker open" when a Redis L2 is configured and its
// circuit breaker is currently open (Redis is unreachable). An empty string
// means the cache is fully operational.
func (l *lruCache) Degraded() string {
	if l.redis != nil && l.redis.br.isOpen() {
		return "redis breaker open"
	}
	return ""
}

// Evictions returns the total number of LRU capacity-evictions since start.
// TTL expiry is not counted; only entries pushed out by new insertions into a full cache.
func (c *lruCache) Evictions() uint64 { return c.evictions.Load() }

// removeElement must be called with the lock held.
func (c *lruCache) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.items, el.Value.(*entry).key)
}

// --- optional Redis L2 ---

type redisLayer struct {
	rdb    *redis.Client
	prefix string
	br     redisBreaker
}

func newRedisLayer(cfg *Config) (*redisLayer, error) {
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, err
	}
	return &redisLayer{rdb: redis.NewClient(opt), prefix: cfg.RedisPrefix}, nil
}

// redisCallBudget bounds one Redis round-trip. It is deliberately short because
// the L2 op currently runs while a scan slot is held; the breaker below makes a
// genuinely dead Redis stop costing even this, after a few trips.
const redisCallBudget = 150 * time.Millisecond

// get/put fail open: any Redis error is treated as a miss, never surfaced. A
// blackholed Redis used to collapse throughput because every GET/PUT blocked the
// full budget while a scan slot was held; the circuit breaker trips after a run
// of failures and then short-circuits all Redis ops for a cooldown, so a dead
// Redis becomes an instant miss instead of a backpressure source.
func (r *redisLayer) get(key string) ([]Match, bool) {
	if !r.br.allow() {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), redisCallBudget)
	defer cancel()
	b, err := r.rdb.Get(ctx, r.prefix+key).Bytes()
	if err != nil {
		// redis.Nil is a normal cache miss (Redis is healthy) — it must NOT count
		// against the breaker; only real errors (timeout, refused) do.
		if errors.Is(err, redis.Nil) {
			r.br.ok()
		} else {
			r.br.fail()
		}
		return nil, false
	}
	r.br.ok()
	var m []Match
	if json.Unmarshal(b, &m) != nil {
		return nil, false
	}
	return m, true
}

func (r *redisLayer) put(key string, matches []Match, ttl time.Duration) {
	if !r.br.allow() {
		return
	}
	b, err := json.Marshal(matches)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), redisCallBudget)
	defer cancel()
	if err := r.rdb.Set(ctx, r.prefix+key, b, ttl).Err(); err != nil {
		r.br.fail()
	} else {
		r.br.ok()
	}
}

// redisBreaker is a minimal circuit breaker: after breakerTrip consecutive
// failures it opens for breakerCooldown, during which allow() returns false and
// all Redis ops are skipped (instant miss). After the cooldown it half-opens —
// allow() returns true again and the next op re-probes, re-opening on failure or
// resetting on success.
type redisBreaker struct {
	mu        sync.Mutex
	fails     int
	openUntil time.Time
}

const (
	breakerTrip     = 5
	breakerCooldown = 5 * time.Second
)

func (b *redisBreaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !time.Now().Before(b.openUntil)
}

func (b *redisBreaker) ok() {
	b.mu.Lock()
	b.fails = 0
	b.openUntil = time.Time{}
	b.mu.Unlock()
}

func (b *redisBreaker) fail() {
	b.mu.Lock()
	b.fails++
	if b.fails >= breakerTrip {
		b.openUntil = time.Now().Add(breakerCooldown)
		b.fails = 0
	}
	b.mu.Unlock()
}

// isOpen reports whether the breaker is currently open (Redis declared
// unreachable and the cooldown has not yet elapsed). fail() resets fails to 0
// when it trips and sets openUntil, so we only need to check the deadline.
func (b *redisBreaker) isOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().Before(b.openUntil)
}
