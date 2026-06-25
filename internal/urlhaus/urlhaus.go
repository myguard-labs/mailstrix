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
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eilandert/rspamd-yarad/internal/atomicio"
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

	stop     chan struct{} // closed by Close to end refreshLoop
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
	c := &Checker{
		key:     key,
		refresh: refresh,
		stop:    make(chan struct{}),
		client:  &http.Client{Timeout: fetchTimeout},
		logf:    logf,
	}
	if cacheDir != "" {
		c.cachePath = filepath.Join(cacheDir, "urlhaus.csv")
	}
	c.rs.Store(&ruleset{urls: map[string]struct{}{}, hosts: map[string]struct{}{}})
	c.warmStart()
	go c.refreshLoop()
	return c
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

func (c *Checker) refreshLoop() {
	// Immediate first fetch, then on the interval. A failure keeps the (empty or
	// previous) set; lookups just miss until a refresh succeeds.
	if err := c.refreshOnce(); err != nil {
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
			if err := c.refreshOnce(); err != nil {
				c.failures.Add(1)
				c.logf("urlhaus feed refresh failed (keeping previous set): %v", err)
			}
		}
	}
}

// Close stops the background refresher. Safe to call more than once and on a
// nil *Checker (the disabled-feature case), so shutdown code can call it
// unconditionally.
func (c *Checker) Close() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() { close(c.stop) })
}

func (c *Checker) refreshOnce() error {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
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
	// Read the (capped) feed into memory so it can be both parsed and persisted.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return err
	}
	rs, err := parseFeed(bytes.NewReader(body))
	if err != nil {
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
		if host != "" {
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

var urlRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>)\]}\x00-\x1f]+`)

// Check extracts URLs from data (and from a cheaply-defanged copy), looks each
// up in the feed, and returns the matches. maxURLs bounds the work per buffer.
// It is safe for concurrent use.
func (c *Checker) Check(data []byte, maxURLs int) []Hit {
	c.lookups.Add(1)
	rs := c.rs.Load()
	if rs == nil || (len(rs.urls) == 0 && len(rs.hosts) == 0) {
		return nil
	}
	if maxURLs <= 0 {
		maxURLs = 64
	}

	var out []Hit
	seen := make(map[string]struct{})
	check := func(text []byte, deobf bool, budget *int) {
		for _, m := range urlRe.FindAll(text, *budget) {
			if *budget <= 0 {
				return
			}
			*budget--
			norm, host := normalizeURL(string(m))
			if norm == "" {
				continue
			}
			if _, dup := seen[norm]; dup {
				continue
			}
			seen[norm] = struct{}{}
			if _, ok := rs.urls[norm]; ok {
				out = append(out, Hit{URL: norm, Deobf: deobf})
			} else if host != "" {
				if _, ok := rs.hosts[host]; ok {
					out = append(out, Hit{URL: host, Host: true, Deobf: deobf})
				}
			}
		}
	}

	budget := maxURLs
	check(data, false, &budget)
	// Defanged copy: surface URLs written as hxxp://, host[.]tld, host(dot)tld.
	if defanged := defang(data); defanged != "" {
		check([]byte(defanged), true, &budget)
	}
	if len(out) > 0 {
		c.hits.Add(1)
	}
	return out
}

// defang rewrites the common URL-obfuscations malware uses in document code back
// to a scannable form. Returns "" when nothing changed (so the caller skips a
// redundant second pass). Cheap and bounded: plain string replacement only.
func defang(data []byte) string {
	// Check on the raw bytes BEFORE materialising a string: Check runs on the
	// whole message AND every extracted stream, so for the common no-defang case
	// this avoids a full-buffer copy (up to MaxBody) on the hot path.
	if !bytes.ContainsAny(data, "[({xX") {
		return ""
	}
	s := string(data)
	r := strings.NewReplacer(
		"hxxps", "https", "hXXps", "https", "hxxp", "http", "hXXp", "http",
		"[.]", ".", "(.)", ".", "{.}", ".",
		"[dot]", ".", "(dot)", ".", "{dot}", ".", "[DOT]", ".", " dot ", ".",
		"[:]", ":", "[://]", "://",
	)
	out := r.Replace(s)
	if out == s {
		return ""
	}
	return out
}

// normalizeURL returns a canonical form for set comparison (lowercased scheme +
// host, default ports stripped, fragment dropped, a bare trailing "/" removed)
// and the bare hostname. Returns "","" for anything unparseable or non-http.
func normalizeURL(raw string) (norm, host string) {
	raw = strings.TrimRight(strings.TrimSpace(raw), ".,);]}'\"")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", ""
	}
	h := strings.ToLower(u.Hostname())
	if h == "" {
		return "", ""
	}
	hostPort := h
	if p := u.Port(); p != "" && !defaultPort(u.Scheme, p) {
		hostPort = h + ":" + p
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	norm = u.Scheme + "://" + hostPort + path
	if u.RawQuery != "" {
		norm += "?" + u.RawQuery
	}
	return norm, h
}

func defaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
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
