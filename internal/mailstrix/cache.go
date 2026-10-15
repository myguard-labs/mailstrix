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
	"unsafe"

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

// lruCache is the always-on in-process layer: a TTL'd LRU bounded by both entry
// count and an estimated retained-byte budget. Concurrency is a single mutex —
// Get/Put hold it only for map/list/accounting operations, never across a scan.
type lruCache struct {
	mu             sync.Mutex
	ttl            time.Duration
	max            int
	maxBytes       uint64
	bytes          uint64
	ll             *list.List               // front = most recently used
	items          map[string]*list.Element // key -> element
	redis          *redisLayer              // optional shared L2 (nil when no MAILSTRIX_REDIS_URL)
	evictions      atomic.Uint64            // LRU evictions (capacity-driven, not TTL expiry)
	byteEvictions  atomic.Uint64
	countEvictions atomic.Uint64
	oversized      atomic.Uint64 // new values refused because they exceed maxBytes alone
}

type entry struct {
	key     string
	matches []Match
	expires time.Time
	size    uint64
}

var (
	entryFixedBytes = uint64(unsafe.Sizeof(entry{})) + uint64(unsafe.Sizeof(list.Element{})) +
		uint64(unsafe.Sizeof(string(""))) + uint64(unsafe.Sizeof((*list.Element)(nil)))
	matchBytes      = uint64(unsafe.Sizeof(Match{}))
	stringSlotBytes = uint64(unsafe.Sizeof(string("")))
	// The Meta allowance is a fixed, architecture-scaled model: 8 scalar bytes,
	// one int and four pointer slots for map-level state, then eight hash bytes,
	// eight key headers, eight value headers and one pointer per modeled bucket.
	// It deliberately does not describe or depend on Go's runtime map layout.
	metaHeaderBytes = uint64(8 + unsafe.Sizeof(int(0)) + 4*unsafe.Sizeof(uintptr(0)))
	metaBucketBytes = uint64(8 + 16*unsafe.Sizeof(string("")) + unsafe.Sizeof(uintptr(0)))
)

func saturatingAdd(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

func saturatingMul(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}

// cacheEntryRetainedBytes returns a deterministic accounting estimate for the
// cache-owned key/index, entry/list nodes and everything reachable through the
// retained Match and Tags slice capacities and Meta maps. It intentionally does
// no JSON serialization or deep copy. String backing-store sharing, allocator
// size classes, map overflow buckets and pre-growth history are not observable;
// counting each reachable string separately makes the estimate conservative for
// common sharing cases, but this is not an exact heap or RSS measurement.
func cacheEntryRetainedBytes(key string, matches []Match) uint64 {
	total := saturatingAdd(entryFixedBytes, uint64(len(key)))
	total = saturatingAdd(total, saturatingMul(uint64(cap(matches)), matchBytes))
	if matches == nil || cap(matches) == 0 {
		return total
	}
	for _, match := range matches[:cap(matches)] {
		total = saturatingAdd(total, uint64(len(match.Rule)))
		total = saturatingAdd(total, uint64(len(match.Namespace)))
		total = saturatingAdd(total, saturatingMul(uint64(cap(match.Tags)), stringSlotBytes))
		if cap(match.Tags) > 0 {
			for _, tag := range match.Tags[:cap(match.Tags)] {
				total = saturatingAdd(total, uint64(len(tag)))
			}
		}
		if match.Meta == nil {
			continue
		}
		total = saturatingAdd(total, metaHeaderBytes)
		if len(match.Meta) > 0 {
			buckets := uint64(1)
			for uint64(len(match.Meta)) > saturatingMul(buckets, 13)/2 {
				// A map length is bounded by MaxInt, so the loop exits by
				// buckets=2^(word size-2); this guard documents the arithmetic
				// invariant and remains unreachable for a valid Go map.
				if buckets > ^uint64(0)/2 {
					return ^uint64(0)
				}
				buckets *= 2
			}
			total = saturatingAdd(total, saturatingMul(buckets, metaBucketBytes))
		}
		for k, v := range match.Meta {
			total = saturatingAdd(total, uint64(len(k)))
			total = saturatingAdd(total, uint64(len(v)))
		}
	}
	return total
}

func cacheEntryFromElement(el *list.Element) *entry {
	e, ok := el.Value.(*entry)
	if !ok {
		panic("mailstrix: non-entry value in verdict LRU")
	}
	return e
}

// maxInitialMapHint caps the map size hint so construction (and Flush) does not
// allocate buckets for the full entry capacity; the map grows lazily with use.
// Entry and byte bounds are enforced by the LRU, not by the map pre-size.
const maxInitialMapHint = 256

func initialMapHint(capacity int) int {
	if capacity < 0 {
		return 0
	}
	return min(capacity, maxInitialMapHint)
}

// NewCache builds the verdict cache from cfg. TTL<=0 returns a noop cache. When
// RedisURL is set, a shared L2 is attached; a Redis that fails at runtime is
// treated as a miss (fail-open to scanning), never an error to the caller.
func NewCache(cfg *Config, logf func(string, ...any)) Cache {
	if cfg.CacheTTL <= 0 {
		return noopCache{}
	}
	maxEntries := cfg.CacheSize
	if maxEntries < 1 {
		maxEntries = 65536
	}
	maxBytes := cfg.CacheMaxBytes
	if maxBytes < 1 {
		maxBytes = defaultCacheMaxBytes
	}
	c := &lruCache{
		ttl:      cfg.CacheTTL,
		max:      maxEntries,
		maxBytes: uint64(maxBytes),
		ll:       list.New(),
		items:    make(map[string]*list.Element, initialMapHint(maxEntries)),
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
		e := cacheEntryFromElement(el)
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
	size := cacheEntryRetainedBytes(key, matches)
	c.mu.Lock()
	defer c.mu.Unlock()
	if size > c.maxBytes {
		// An oversized replacement invalidates the old value for this key, but
		// must not evict unrelated entries in a futile attempt to make room.
		c.oversized.Add(1)
		if el, ok := c.items[key]; ok {
			c.removeElement(el)
			c.recordEviction(true)
		}
		return
	}
	if el, ok := c.items[key]; ok {
		e := cacheEntryFromElement(el)
		if e.size > c.bytes {
			c.bytes = 0
		} else {
			c.bytes -= e.size
		}
		e.matches = matches
		e.expires = time.Now().Add(c.ttl)
		e.size = size
		c.bytes = saturatingAdd(c.bytes, size)
		c.ll.MoveToFront(el)
	} else {
		el := c.ll.PushFront(&entry{key: key, matches: matches, expires: time.Now().Add(c.ttl), size: size})
		c.items[key] = el
		c.bytes = saturatingAdd(c.bytes, size)
	}
	for c.bytes > c.maxBytes || c.ll.Len() > c.max {
		byteCause := c.bytes > c.maxBytes // byte wins when both limits are exceeded
		c.removeElement(c.ll.Back())
		c.recordEviction(byteCause)
	}
}

// Flush clears L1 (called on a rules reload). L2 is left to TTL-expire on its
// own: other replicas may still be on the old rule set mid-rollout, and Redis
// keys are namespaced so a stale entry just expires within CacheTTL.
func (c *lruCache) Flush() {
	c.mu.Lock()
	c.ll.Init()
	c.items = make(map[string]*list.Element, initialMapHint(c.max))
	c.bytes = 0
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
// TTL expiry and rejected new oversized values are not counted. Insertions and
// replacements that remove a retained entry to satisfy a capacity limit are.
func (c *lruCache) Evictions() uint64 { return c.evictions.Load() }

func (c *lruCache) ByteEvictions() uint64 { return c.byteEvictions.Load() }

func (c *lruCache) CountEvictions() uint64 { return c.countEvictions.Load() }

// RejectedOversize returns the number of puts refused because the entry alone
// exceeds the byte budget. Each refusal is counted here, not as an eviction. A
// refused replacement that also removes the key's previous entry still records
// that removal as a limit eviction, as before.
func (c *lruCache) RejectedOversize() uint64 { return c.oversized.Load() }

func (c *lruCache) Bytes() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}

func (c *lruCache) recordEviction(byteCause bool) {
	c.evictions.Add(1)
	if byteCause {
		c.byteEvictions.Add(1)
	} else {
		c.countEvictions.Add(1)
	}
}

// removeElement must be called with the lock held.
func (c *lruCache) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	c.ll.Remove(el)
	e := cacheEntryFromElement(el)
	delete(c.items, e.key)
	if e.size > c.bytes {
		c.bytes = 0
	} else {
		c.bytes -= e.size
	}
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
