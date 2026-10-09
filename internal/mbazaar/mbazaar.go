// Package mbazaar adds an abuse.ch MalwareBazaar attachment-hash lookup to
// yarad: the SHA256 of each scanned buffer (a MIME attachment, as the rspamd
// plugin POSTs it) is checked against a locally-cached set of SHA256 hashes of
// known malware samples. An exact hit is a direct known-bad verdict, independent
// of the YARA rules.
//
// Design mirrors the URLhaus checker (the same fail-open feed-cache infra):
//   - The full MalwareBazaar CSV dump is downloaded ONCE per refresh interval
//     (daily by default) into an in-memory set of raw 32-byte digests; lookups
//     are pure local map hits, never a per-message remote API call.
//   - A failed refresh keeps the previous set (fail-static) and is counted.
//   - The dump is a ZIP (one CSV inside); a plain-CSV feed (the "recent" export
//     or a custom URL override) is also accepted — the body is magic-sniffed.
//   - Digests are held as raw [32]byte map keys (not 64-char hex) to keep the
//     full set lean (~40 MB for ~1M samples) on a memory-limited container.
//
// Requires an abuse.ch Auth-Key (free, https://auth.abuse.ch/ — the SAME key as
// URLhaus). With no key the checker is disabled (New returns nil).
package mbazaar

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/myguard-labs/mailstrix/internal/atomicio"
	"github.com/myguard-labs/mailstrix/internal/feedrefresh"
)

const (
	// feedURLFull is the complete MalwareBazaar CSV dump (a ZIP holding one CSV).
	// The full set — not the "recent" export — is what a mail scanner wants:
	// malware attachments are routinely days/weeks old.
	feedURLFull = "https://bazaar.abuse.ch/export/csv/full/"
	// minRefresh is abuse.ch's fair-use floor; defaultRefresh is daily (the full
	// dump changes slowly relative to its size, and a daily pull is courteous).
	minRefresh     = 5 * time.Minute
	defaultRefresh = 24 * time.Hour
	// fetchTimeout is generous: the full dump is tens of MB to download + unzip.
	fetchTimeout = 5 * time.Minute
	// maxFeedBytes caps the DOWNLOADED (zipped) body so a runaway feed can't
	// exhaust memory.
	maxFeedBytes = 512 << 20
	// maxDecompressedBytes (var below) caps the DECOMPRESSED CSV stream. maxFeedBytes
	// only bounds the zipped body, so without this a zip bomb (or a single forged
	// multi-GB record csv.Reader must buffer whole) decompresses unbounded and OOMs
	// the mem-limited container before the maxHashes break can fire — mirrors the
	// io.LimitReader cap urlhaus/threatfox already apply.
	// maxHashes bounds the set size defensively (MalwareBazaar is ~1M samples).
	maxHashes = 10_000_000
)

// maxDecompressedBytes is a var (not const) so tests can lower it to exercise the
// truncation path without allocating a real gigabyte.
var maxDecompressedBytes int64 = 1 << 30

// Hit is one scanned buffer whose SHA256 matched a known malware sample.
type Hit struct {
	SHA256 string // hex digest of the matched buffer
}

// Rule returns the synthetic rule name for a hit, so the scanner can surface it
// as a match alongside YARA rules and the rspamd plugin can route it.
func (h Hit) Rule() string { return "MALWAREBAZAAR_MALWARE" }

// Metrics is a snapshot for /metrics.
type Metrics struct {
	Enabled         bool
	FeedHashes      int64
	LastRefreshUnix int64
	RefreshFailures uint64
	Lookups         uint64 // buffers hashed and checked
	Hits            uint64 // buffers whose hash matched
}

// hashSet wraps the digest set so the whole set can be swapped atomically on a
// refresh (a map is not directly storable in an atomic.Pointer).
type hashSet struct{ m map[[32]byte]struct{} }

// Checker holds the cached hash set and serves lookups. The zero value is not
// usable; use New.
type Checker struct {
	set       atomic.Pointer[hashSet]
	key       string
	feedURL   string
	refresh   time.Duration
	client    *http.Client
	logf      func(string, ...any)
	cachePath string // persisted feed snapshot ("" disables persistence)

	lastRefresh atomic.Int64
	failures    atomic.Uint64
	lookups     atomic.Uint64
	hits        atomic.Uint64

	// Close cancels fetches, then every caller joins the loop through done.
	// The loop owns publication and persistence until it closes done; callers
	// may release the cache directory only after Close returns.
	stop     chan struct{}
	done     chan struct{}
	cancel   context.CancelFunc
	stopOnce sync.Once
}

// New builds a Checker and starts its background refresher. It returns nil when
// key is empty (feature disabled), so callers can guard on `c != nil`. refresh
// is clamped to the fair-use floor; feedURL falls back to the full dump. When
// cacheDir is non-empty the feed snapshot is persisted there and loaded on
// startup, so a restart serves from the last-good feed instead of an empty set.
func New(key string, refresh time.Duration, feedURL, cacheDir string, logf func(string, ...any)) *Checker {
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
	if feedURL = strings.TrimSpace(feedURL); feedURL == "" {
		feedURL = feedURLFull
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Checker{
		key:     key,
		refresh: refresh,
		feedURL: feedURL,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		cancel:  cancel,
		client:  feedrefresh.NewHTTPClient(fetchTimeout),
		logf:    logf,
	}
	if cacheDir != "" {
		c.cachePath = filepath.Join(cacheDir, "malwarebazaar.bin")
	}
	c.set.Store(&hashSet{m: map[[32]byte]struct{}{}})
	c.warmStart()
	go func() {
		defer close(c.done)
		// Immediate first fetch, then on the interval; see feedrefresh.Loop.
		feedrefresh.Loop(ctx, c.stop, c.refresh, "malwarebazaar", c.refreshOnce, &c.failures, c.logf)
	}()
	return c
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.feedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Auth-Key", c.key)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &feedrefresh.StatusError{Feed: "malwarebazaar", Code: resp.StatusCode}
	}
	body, err := feedrefresh.ReadBody("malwarebazaar", resp.Body, maxFeedBytes)
	if err != nil {
		return err
	}
	hs, err := parseFeed(body)
	if err != nil {
		return err
	}
	prev := 0
	if old := c.set.Load(); old != nil {
		prev = len(old.m)
	}
	if err := feedrefresh.CheckSize(prev, len(hs.m)); err != nil {
		return err
	}
	c.set.Store(hs)
	c.lastRefresh.Store(time.Now().Unix())
	if c.cachePath != "" {
		if err := atomicio.WriteWithBackup(c.cachePath, body, 0o600); err != nil {
			c.logf("malwarebazaar feed cache write failed (non-fatal): %v", err)
		}
	}
	c.logf("malwarebazaar feed loaded: %d hashes", len(hs.m))
	return nil
}

// warmStart loads the persisted feed snapshot (if any) so lookups work from the
// last-good feed before the first network refresh.
func (c *Checker) warmStart() {
	if c.cachePath == "" {
		return
	}
	b, ok := atomicio.ReadCached(c.cachePath)
	if !ok {
		return
	}
	hs, err := parseFeed(b)
	if err != nil {
		c.logf("malwarebazaar warm-start parse failed (ignoring cached feed): %v", err)
		return
	}
	c.set.Store(hs)
	c.logf("malwarebazaar warm-start from cache: %d hashes", len(hs.m))
}

// parseFeed builds the digest set from the downloaded body — either the ZIP dump
// (one CSV inside) or a plain CSV (the "recent" export / a custom feed). The
// format is magic-sniffed. A malformed row is skipped, not fatal.
func parseFeed(body []byte) (*hashSet, error) {
	rc, err := openCSV(body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }() // read-only reader

	hs := &hashSet{m: make(map[[32]byte]struct{})}
	cr := csv.NewReader(io.LimitReader(rc, maxDecompressedBytes))
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
		d, ok := pickSHA256(rec)
		if !ok {
			continue
		}
		hs.m[d] = struct{}{}
		if len(hs.m) >= maxHashes {
			break
		}
	}
	return hs, nil
}

// openCSV returns a reader over the CSV: it unwraps the ZIP dump (first regular
// file entry) when the body is a zip, else reads the body as plain CSV.
func openCSV(body []byte) (io.ReadCloser, error) {
	if len(body) >= 4 && string(body[:4]) == "PK\x03\x04" {
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			// Skip an entry whose declared decompressed size already exceeds the
			// cap — defends against a zip bomb before a single byte is inflated.
			// maxDecompressedBytes is always positive (1<<30); the uint64 cast is
			// safe. #nosec G115 -- int64 constant is positive, no overflow.
			if f.UncompressedSize64 > uint64(maxDecompressedBytes) { //#nosec G115
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			// Read the decompressed bytes into memory, bounded by the cap. A
			// corrupt or adversarial deflate stream can cause the flate decompressor
			// to spin reading 0 bytes per iteration — io.LimitReader on the output
			// side cannot terminate that loop; only bounding the read here does.
			raw, err := io.ReadAll(io.LimitReader(rc, maxDecompressedBytes))
			_ = rc.Close() // zip entry fully read; a close error cannot change raw
			if err != nil {
				return nil, err
			}
			return io.NopCloser(bytes.NewReader(raw)), nil
		}
		return nil, errors.New("malwarebazaar: empty zip dump")
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

// pickSHA256 extracts the sample's SHA256 from a CSV row. It prefers the
// documented column (index 1: first_seen,sha256,md5,sha1,…) but falls back to
// the first 64-hex field so a column reorder can't silently empty the set (md5
// and sha1 are 32/40 chars, so length alone disambiguates).
func pickSHA256(rec []string) ([32]byte, bool) {
	if len(rec) > 1 {
		if d, ok := parseSHA256(rec[1]); ok {
			return d, true
		}
	}
	for _, f := range rec {
		if d, ok := parseSHA256(f); ok {
			return d, true
		}
	}
	return [32]byte{}, false
}

func parseSHA256(s string) ([32]byte, bool) {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return [32]byte{}, false
	}
	var d [32]byte
	if _, err := hex.Decode(d[:], []byte(s)); err != nil {
		return [32]byte{}, false
	}
	return d, true
}

// Check hashes data and reports a Hit when its SHA256 is a known malware sample.
// It returns a slice (0 or 1 hit) for symmetry with the URLhaus checker, and is
// safe for concurrent use.
func (c *Checker) Check(data []byte) []Hit {
	return c.CheckDigest(sha256.Sum256(data))
}

// CheckDigest is Check for a caller that has already computed the SHA256 of the
// buffer, so the (up to 8 MiB) body is not hashed a second time per scan.
func (c *Checker) CheckDigest(sum [32]byte) []Hit {
	c.lookups.Add(1)
	hs := c.set.Load()
	if hs == nil || len(hs.m) == 0 {
		return nil
	}
	if _, ok := hs.m[sum]; !ok {
		return nil
	}
	c.hits.Add(1)
	return []Hit{{SHA256: hex.EncodeToString(sum[:])}}
}

// Metrics returns a snapshot for /metrics.
func (c *Checker) Metrics() Metrics {
	var n int
	if hs := c.set.Load(); hs != nil {
		n = len(hs.m)
	}
	return Metrics{
		Enabled:         true,
		FeedHashes:      int64(n),
		LastRefreshUnix: c.lastRefresh.Load(),
		RefreshFailures: c.failures.Load(),
		Lookups:         c.lookups.Load(),
		Hits:            c.hits.Load(),
	}
}
