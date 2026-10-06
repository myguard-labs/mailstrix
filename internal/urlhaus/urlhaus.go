// Package urlhaus adds an abuse.ch URLhaus lookup to yarad: URLs pulled from a
// message (and from the decompressed VBA/RTF the extract package surfaces) are
// checked against a locally-cached feed of known malware-distribution URLs.
//
// Design (matches the high-volume constraints):
//   - The feed is downloaded ONCE per refresh interval (>=5 min, fair-use) into
//     an in-memory set; lookups are pure local map hits, never a per-message
//     remote API call.
//   - A failed refresh keeps the previous set (fail-static) and is counted.
//   - Cheap, bounded defanging ("hxxp", "[.]", "(dot)") catches URLs hidden in
//     document code; a hit found only after defanging is flagged Deobf.
//   - Matching is most-specific-wins: exact normalized URL (high confidence)
//     else the hostname (a known-bad host). Per-message URL count is bounded.
//
// Requires an abuse.ch Auth-Key (free, https://auth.abuse.ch/), sent as the
// Auth-Key header. With no key the checker is disabled (New returns nil).
package urlhaus

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/myguard-labs/mailstrix/internal/atomicio"
	"github.com/myguard-labs/mailstrix/internal/urlcand"
)

const (
	// feedURL is the "online" (currently-active) URLhaus URL dump — smaller and
	// more current than the full historical CSV, which is what a mail scanner
	// wants (live threats, bounded memory).
	feedURL = "https://urlhaus.abuse.ch/downloads/csv_online/"
	// minRefresh is abuse.ch's fair-use floor for the CSV dumps.
	minRefresh     = 5 * time.Minute
	defaultRefresh = 360 * time.Minute
	fetchTimeout   = 60 * time.Second
	maxFeedBytes   = 256 << 20 // hard ceiling on a downloaded feed
)

var errFeedTooLarge = errors.New("urlhaus feed exceeds byte limit")

// Hit is one URL in a scanned buffer that matched the feed.
type Hit struct {
	URL   string // the matched (normalized) URL or host
	Host  bool   // matched at host level (less specific) rather than exact URL
	Deobf bool   // only found after defanging (hxxp/[.] etc.) — more suspicious
}

// Rule returns the synthetic rule name for a hit, so the scanner can surface it
// as a match alongside YARA rules and the rspamd plugin can route it.
func (h Hit) Rule() string {
	name := "URLHAUS_MALWARE_URL"
	if h.Host {
		name = "URLHAUS_MALWARE_HOST"
	}
	if h.Deobf {
		name += "_DEOBF"
	}
	return name
}

// Metrics is a snapshot for /metrics.
type Metrics struct {
	Enabled         bool
	FeedURLs        int64
	FeedHosts       int64
	LastRefreshUnix int64
	RefreshFailures uint64
	Lookups         uint64 // buffers checked
	Hits            uint64 // buffers with >=1 hit
}

type ruleset struct {
	urls  map[string]struct{}
	hosts map[string]struct{}
}

// Checker holds the cached feed and serves lookups. The zero value is not
// usable; use New.
type Checker struct {
	rs        atomic.Pointer[ruleset]
	key       string
	refresh   time.Duration
	client    *http.Client
	logf      func(string, ...any)
	cachePath string // persisted feed snapshot ("" disables persistence)

	lastRefresh atomic.Int64
	failures    atomic.Uint64
	lookups     atomic.Uint64
	hits        atomic.Uint64

	// Close cancels fetches, then joins the loop through done; the loop owns
	// publication and persistence until it closes done.
	stop     chan struct{} // closed by Close to end refreshLoop
	done     chan struct{} // closed when refreshLoop has exited
	cancel   context.CancelFunc
	stopOnce sync.Once
}

// New builds a Checker and starts its background refresher. It returns nil when
// key is empty (feature disabled), so callers can guard on `c != nil`. refresh
// is clamped to the fair-use floor. When cacheDir is non-empty the feed snapshot
// is persisted there and loaded on startup, so a restart serves immediately from
// the last-good feed instead of an empty set until the first network refresh.
func New(key string, refresh time.Duration, cacheDir string, logf func(string, ...any)) *Checker {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	if refresh <= 0 {
		refresh = defaultRefresh
	}
	if refresh < minRefresh {
		refresh = minRefresh
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Checker{
		key:     key,
		refresh: refresh,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		cancel:  cancel,
		client:  newFeedHTTPClient(fetchTimeout),
		logf:    logf,
	}
	if cacheDir != "" {
		c.cachePath = filepath.Join(cacheDir, "urlhaus.csv")
	}
	c.rs.Store(&ruleset{urls: map[string]struct{}{}, hosts: map[string]struct{}{}})
	c.warmStart()
	go c.refreshLoop(ctx)
	return c
}

func newFeedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// warmStart loads the persisted feed snapshot (if any) into the set so lookups
// work from the last-good feed before the first network refresh completes.
func (c *Checker) warmStart() {
	if c.cachePath == "" {
		return
	}
	b, ok := atomicio.ReadCached(c.cachePath)
	if !ok {
		return
	}
	rs, err := parseFeed(bytes.NewReader(b))
	if err != nil {
		c.logf("urlhaus warm-start parse failed (ignoring cached feed): %v", err)
		return
	}
	c.rs.Store(rs)
	c.logf("urlhaus warm-start from cache: %d urls / %d hosts", len(rs.urls), len(rs.hosts))
}

func (c *Checker) refreshLoop(ctx context.Context) {
	defer close(c.done)
	// Immediate first fetch, then on the interval. A failure keeps the (empty or
	// previous) set; lookups just miss until a refresh succeeds.
	if err := c.refreshOnce(ctx); err != nil {
		if ctx.Err() != nil {
			return
		}
		c.failures.Add(1)
		c.logf("urlhaus initial feed fetch failed: %v", err)
	}
	t := time.NewTicker(c.refresh)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if err := c.refreshOnce(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				c.failures.Add(1)
				c.logf("urlhaus feed refresh failed (keeping previous set): %v", err)
			}
		}
	}
}

// Close cancels the background refresher and waits for its publication and
// cache writes to finish. Safe to call more than once and on a
// nil *Checker (the disabled-feature case), so shutdown code can call it
// unconditionally.
func (c *Checker) Close() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		c.cancel()
		close(c.stop)
	})
	<-c.done
}

func (c *Checker) refreshOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Auth-Key", c.key)
	req.Header.Set("Accept", "text/csv")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &statusError{resp.StatusCode}
	}
	// Read the capped feed into memory so it can be both parsed and persisted.
	// If it exceeds the cap, fail this refresh instead of caching/parsing a
	// truncated snapshot.
	body, err := readFeedBody(resp.Body, maxFeedBytes)
	if err != nil {
		return err
	}
	rs, err := parseFeed(bytes.NewReader(body))
	if err != nil {
		return err
	}
	prev := 0
	if old := c.rs.Load(); old != nil {
		prev = len(old.urls) + len(old.hosts)
	}
	if err := checkFeedSize(prev, len(rs.urls)+len(rs.hosts)); err != nil {
		return err
	}
	c.rs.Store(rs)
	c.lastRefresh.Store(time.Now().Unix())
	// Persist the snapshot for warm-start on the next boot (best-effort: a write
	// failure does not fail the refresh — the in-memory set is already updated).
	if c.cachePath != "" {
		if err := atomicio.WriteWithBackup(c.cachePath, body, 0o600); err != nil {
			c.logf("urlhaus feed cache write failed (non-fatal): %v", err)
		}
	}
	c.logf("urlhaus feed loaded: %d urls / %d hosts", len(rs.urls), len(rs.hosts))
	return nil
}

type statusError struct{ code int }

func (e *statusError) Error() string { return "urlhaus feed HTTP " + strconv.Itoa(e.code) }

func readFeedBody(r io.Reader, limit int64) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: limit + 1}
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errFeedTooLarge
	}
	return body, nil
}

// parseFeed reads the URLhaus CSV (`#`-comment header, quoted fields). The `url`
// is column 2 in the documented layout (id,dateadded,url,...); we take that when
// it's a URL, else fall back to the first URL-looking field so a column reorder
// can't silently empty the set. A malformed row is skipped, not fatal.
func parseFeed(r io.Reader) (*ruleset, error) {
	rs := &ruleset{urls: make(map[string]struct{}), hosts: make(map[string]struct{})}
	cr := csv.NewReader(io.LimitReader(r, maxFeedBytes))
	cr.Comment = '#'
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.ReuseRecord = true
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // skip a bad row, keep loading the rest
		}
		norm, host := normalizeURL(pickURL(rec))
		if norm == "" {
			continue
		}
		rs.urls[norm] = struct{}{}
		// These services host unrelated users' content. A listed URL must
		// remain an exact match, but its host cannot label every other URL.
		if host != "" && host != "github.com" && host != "raw.githubusercontent.com" {
			rs.hosts[host] = struct{}{}
		}
	}
	return rs, nil
}

func pickURL(rec []string) string {
	if len(rec) > 2 && looksURL(rec[2]) {
		return rec[2]
	}
	for _, f := range rec {
		if looksURL(f) {
			return f
		}
	}
	return ""
}

func looksURL(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// Check extracts URLs from data (and from a cheaply-defanged copy) via
// urlcand.Extract, looks each up in the feed, and returns the matches.
// maxURLs bounds the work per buffer. It is safe for concurrent use.
// Delegates to CheckCandidates.
func (c *Checker) Check(data []byte, maxURLs int) []Hit {
	return c.CheckCandidates(urlcand.Extract(data, maxURLs), maxURLs)
}

// CheckCandidates looks up pre-extracted URL candidates in the feed. cands is
// produced by urlcand.Extract; maxURLs caps how many candidates are processed.
// A shared dedup map prevents duplicate normalized URLs across the candidate
// list. c.hits is incremented if any hit is found.
func (c *Checker) CheckCandidates(cands []urlcand.Candidate, maxURLs int) []Hit {
	c.lookups.Add(1)
	if len(cands) == 0 {
		return nil
	}
	rs := c.rs.Load()
	if rs == nil || (len(rs.urls) == 0 && len(rs.hosts) == 0) {
		return nil
	}
	if maxURLs <= 0 {
		maxURLs = 64
	}

	var out []Hit
	var seen map[string]struct{}
	budget := maxURLs
	for i := range cands {
		if budget <= 0 {
			break
		}
		budget--
		cand := &cands[i]
		norm, host, _ := cand.Normalize()
		if norm == "" {
			continue
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		// A single candidate needs no duplicate check (PERF-70).
		if seen == nil && len(cands) > 1 {
			seen = make(map[string]struct{}, min(len(cands), budget+1))
		}
		if seen != nil {
			seen[norm] = struct{}{}
		}
		if _, ok := rs.urls[norm]; ok {
			out = append(out, Hit{URL: norm, Deobf: cand.Deobf})
		} else if host != "" {
			if _, ok := rs.hosts[host]; ok {
				out = append(out, Hit{URL: host, Host: true, Deobf: cand.Deobf})
			}
		}
	}
	if len(out) > 0 {
		c.hits.Add(1)
	}
	return out
}

// normalizeURL returns a canonical form for set comparison (lowercased scheme +
// host, default ports stripped, fragment dropped, a bare trailing "/" removed)
// and the bare hostname. Returns "","" for anything unparseable or non-http.
func normalizeURL(raw string) (norm, host string) {
	norm, host, _ = urlcand.NormalizeHTTPURL(raw)
	return norm, host
}

// Metrics returns a snapshot for /metrics.
func (c *Checker) Metrics() Metrics {
	rs := c.rs.Load()
	var nu, nh int
	if rs != nil {
		nu, nh = len(rs.urls), len(rs.hosts)
	}
	return Metrics{
		Enabled:         true,
		FeedURLs:        int64(nu),
		FeedHosts:       int64(nh),
		LastRefreshUnix: c.lastRefresh.Load(),
		RefreshFailures: c.failures.Load(),
		Lookups:         c.lookups.Load(),
		Hits:            c.hits.Load(),
	}
}

// COR-08: a refresh that returns HTTP 200 with zero entries, or with a tiny
// fraction of a large previous set, is a broken upstream response, not a
// real feed. Reject it so the last-good set and the warm-start cache stay.
const (
	minFeedForDropCheck = 1000
	maxFeedDropFactor   = 10
)

var errFeedShrank = errors.New("feed refresh rejected: empty or collapsed")

func checkFeedSize(prev, next int) error {
	if next == 0 || (prev >= minFeedForDropCheck && next*maxFeedDropFactor < prev) {
		return fmt.Errorf("%w (%d -> %d entries)", errFeedShrank, prev, next)
	}
	return nil
}
