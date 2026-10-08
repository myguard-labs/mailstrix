package mailstrix

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache stores scan verdicts keyed by a Fingerprint-prefixed streamDedupKey:
// an unseeded xxh3 Hash128 (github.com/zeebo/xxh3, not cryptographic). Every
// mail sender writes entries: each scanned body/stream stores its verdict under
// its own key, populating both L1 (in-process LRU) and L2 (shared Redis). The
// residual risk is a crafted body whose key collides with an existing clean
// entry's key under the same Fingerprint; random collision at 128 bits is
// negligible, and targeted collision is the accepted risk. A per-process random
// seed would break the shared L2 (keys must agree across instances). Verdicts
// are pure functions of bytes and rules, so entries expire only by TTL. On a
// rules reload, the whole cache is Flush'd since old verdicts were computed
// against the previous rule set. Redis L2 is trusted; only strixd writes it.
type Cache interface {
	// Get returns an immutable match slice owned by the cache. Callers must not
	// mutate the returned slice or its Match entries.
	Get(key string) ([]Match, bool)
	// Put stores matches by reference; callers must treat matches as immutable
	// after insertion.
	Put(key string, matches []Match)
	Flush()
	// Degraded returns a non-empty human-readable reason when the cache is
	// operating in a reduced capacity (e.g. the Redis circuit breaker is open).
	// An empty string means fully operational. Disabled caching (noopCache) is
	// not degraded — it is an intentional configuration.
	Degraded() string
}

// noopCache is used when MAILSTRIX_CACHE_TTL=0 (caching disabled): every Get misses.
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
	redis     *redisLayer              // optional shared L2 (nil when no MAILSTRIX_REDIS_URL)
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
		if rl, err := newRedisLayer(cfg, logf); err != nil {
			logf("WARNING redis cache disabled: %v", err)
		} else {
			c.redis = rl
			logf("redis verdict cache enabled (prefix=%s)", cfg.RedisPrefix)
			// Warn if plaintext connection to a remote host.
			if host, warn := redisPlaintextRemote(rl.rdb.Options()); warn {
				logf("WARNING redis cache uses plaintext to non-loopback %s; use rediss:// for TLS", host)
			}
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
			m := e.matches
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
			// Promote into L1 only: writing the hit back to Redis would add a
			// marshal + SET on the request path and refresh the L2 TTL forever
			// (PERF-56).
			c.putLocal(key, m)
			return m, true
		}
	}
	return nil, false
}

func (c *lruCache) Put(key string, matches []Match) {
	c.putLocal(key, matches)
	if c.redis != nil {
		c.redis.put(key, matches, c.ttl)
	}
}

// putLocal stores matches in the in-process LRU only.
func (c *lruCache) putLocal(key string, matches []Match) {
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
	macKey []byte // optional HMAC key (MAILSTRIX_REDIS_MAC_KEY); nil = no MAC
	logf   func(string, ...any)
	warned atomic.Bool // rejected-value warning is logged once per process
}

// MinRedisMACKeyLen is the minimum length in bytes of MAILSTRIX_REDIS_MAC_KEY.
const MinRedisMACKeyLen = 32

// Framing of a MACed value: macVersion || HMAC-SHA256 (32 bytes) || JSON. The
// MAC covers redisKey || 0x00 || value so a valid value cannot be replayed under
// another hash. Un-MACed legacy values are JSON ('[' or 'n'), never macVersion.
const (
	macVersion byte = 0x01
	macLen          = sha256.Size
)

func redisMAC(key []byte, redisKey string, value []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(redisKey))
	h.Write([]byte{0})
	h.Write(value)
	return h.Sum(nil)
}

// sealRedisValue frames value with a MAC. With no key the value is unchanged.
func sealRedisValue(key []byte, redisKey string, value []byte) []byte {
	if len(key) == 0 {
		return value
	}
	out := make([]byte, 0, 1+macLen+len(value))
	out = append(out, macVersion)
	out = append(out, redisMAC(key, redisKey, value)...)
	return append(out, value...)
}

// openRedisValue verifies and strips the MAC. With no key the value is returned
// unchanged. A missing, malformed or wrong MAC returns ok=false (cache miss).
func openRedisValue(key []byte, redisKey string, framed []byte) ([]byte, bool) {
	if len(key) == 0 {
		return framed, true
	}
	if len(framed) <= 1+macLen || framed[0] != macVersion {
		return nil, false
	}
	value := framed[1+macLen:]
	if !hmac.Equal(framed[1:1+macLen], redisMAC(key, redisKey, value)) {
		return nil, false
	}
	return value, true
}

// redisPlaintextRemote returns the Redis host[:port] and a flag indicating whether
// the connection uses plaintext (redis://) to a non-loopback target. Local connections
// (unix sockets, localhost, loopback IPs) return warn=false and log no warning.
func redisPlaintextRemote(opt *redis.Options) (host string, warn bool) {
	// Unix sockets are local by definition.
	if opt.Network == "unix" {
		return "", false
	}

	// Check if TLS is enabled (rediss:// scheme or explicit TLSConfig).
	if opt.TLSConfig != nil {
		return "", false
	}

	// Extract host from opt.Addr (format: "host:port" or just "host").
	parsedHost, _, err := net.SplitHostPort(opt.Addr)
	if err != nil {
		// If SplitHostPort fails, opt.Addr might not have a port; treat as the host.
		parsedHost = opt.Addr
	}

	// Check if host is a loopback address (localhost, 127.0.0.1, ::1, etc.).
	ip := net.ParseIP(parsedHost)
	if ip != nil && ip.IsLoopback() {
		return parsedHost, false
	}

	// Check if host is the string "localhost".
	if parsedHost == "localhost" {
		return parsedHost, false
	}

	// Plaintext remote connection: log a warning.
	return parsedHost, true
}

func newRedisLayer(cfg *Config, logf func(string, ...any)) (*redisLayer, error) {
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, err
	}
	rl := &redisLayer{rdb: redis.NewClient(opt), prefix: cfg.RedisPrefix, logf: logf}
	if cfg.RedisMACKey != "" {
		rl.macKey = []byte(cfg.RedisMACKey)
	}
	return rl, nil
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
	rk := r.prefix + key
	b, err := r.rdb.Get(ctx, rk).Bytes()
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
	b, ok := openRedisValue(r.macKey, rk, b)
	if !ok {
		// Missing/bad MAC: a miss, never a verdict. Warn once, no secret material.
		if r.logf != nil && r.warned.CompareAndSwap(false, true) {
			r.logf("WARNING redis cache value failed MAC verification; treated as a miss (further occurrences not logged)")
		}
		return nil, false
	}
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
	rk := r.prefix + key
	if err := r.rdb.Set(ctx, rk, sealRedisValue(r.macKey, rk, b), ttl).Err(); err != nil {
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
