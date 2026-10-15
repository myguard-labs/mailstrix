// Package mbazaar adds an abuse.ch MalwareBazaar attachment-hash lookup to
// yarad: the SHA256 of each scanned buffer (a MIME attachment, as the rspamd
// plugin POSTs it) is checked against a locally-cached set of SHA256 hashes of
// known malware samples. An exact hit is a direct known-bad verdict, independent
// of the YARA rules.
//
// Design mirrors the URLhaus checker (the same fail-open feed-cache infra):
//   - The full MalwareBazaar CSV dump is downloaded ONCE per refresh interval
//     (daily by default) into an in-memory set of raw 32-byte digests (the
//     download is spooled to disk and stream-parsed, never buffered); lookups
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
	"os"
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
	// maxFeedBytes caps the DOWNLOADED (zipped) body, which is spooled to disk
	// while it arrives, so a runaway feed is cut off at the ceiling. Measured
	// 2026-10-15: the full dump is 225,432,017 bytes zipped (215 MiB); 320 MiB is
	// ~1.5x headroom for growth.
	maxFeedBytes = 320 << 20
	// maxDecompressedBytes (var below) caps the DECOMPRESSED CSV stream, checked
	// while reading (capReader) and against the zip header before inflating, so a
	// zip bomb or a forged multi-GB record is rejected before it is buffered. The
	// refresh then fails and the previous set is kept. Measured 2026-10-15: the
	// dump decompresses to 529,161,878 bytes (505 MiB); 768 MiB is ~1.5x headroom.
	// maxHashes bounds the set size defensively (MalwareBazaar is ~1M samples).
	maxHashes = 10_000_000
)

// maxDecompressedBytes is a var (not const) so tests can lower it to exercise the
// over-ceiling path without allocating hundreds of megabytes.
var maxDecompressedBytes int64 = 768 << 20

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
	SetBytes        int64 // estimated resident bytes of the loaded set
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
	setBytes    atomic.Int64 // estimate for the loaded digest set, updated with each swap
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
	// Spool the compressed download to disk (bounded by maxFeedBytes) instead of
	// holding it in memory: zip needs a seekable source, and the spool file is
	// then installed as the cache snapshot without a second copy in RAM. An
	// unusable cache directory is non-fatal, as before: spool to the OS temp dir
	// and skip persisting the snapshot.
	spoolDir := ""
	if c.cachePath != "" {
		spoolDir = filepath.Dir(c.cachePath)
		if err := os.MkdirAll(spoolDir, 0o750); err != nil {
			c.logf("malwarebazaar feed cache dir unusable (non-fatal): %v", err)
			spoolDir = ""
		}
	}
	f, err := os.CreateTemp(spoolDir, spoolPattern)
	if err != nil && spoolDir != "" {
		c.logf("malwarebazaar feed cache dir not writable (non-fatal): %v", err)
		spoolDir = ""
		f, err = os.CreateTemp("", spoolPattern)
	}
	if err != nil {
		return err
	}
	spool, size, err := spoolTo("malwarebazaar", resp.Body, maxFeedBytes, f)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(spool) }() // no-op once installed as the cache
	hint := 0
	if old := c.set.Load(); old != nil {
		hint = len(old.m)
	}
	hs, err := parseFile(spool, size, hint)
	if err != nil {
		return err
	}
	prev := hint
	if err := feedrefresh.CheckSize(prev, len(hs.m)); err != nil {
		return err
	}
	c.set.Store(hs)
	c.setBytes.Store(feedrefresh.DigestSetBytes(len(hs.m), sha256.Size))
	c.lastRefresh.Store(time.Now().Unix())
	if spoolDir != "" {
		if err := atomicio.InstallFile(spool, c.cachePath, 0o600); err != nil {
			c.logf("malwarebazaar feed cache write failed (non-fatal): %v", err)
		}
	}
	c.logf("malwarebazaar feed loaded: %d hashes", len(hs.m))
	return nil
}

const spoolPattern = ".mbazaar-spool-*.tmp"

// spoolBody is spoolTo into a new temp file in dir ("" = the OS temp dir).
func spoolBody(feed string, r io.Reader, limit int64, dir string) (path string, n int64, err error) {
	f, err := os.CreateTemp(dir, spoolPattern)
	if err != nil {
		return "", 0, err
	}
	return spoolTo(feed, r, limit, f)
}

// spoolTo copies r into the open temp file f and closes it, failing with
// feedrefresh.TooLargeError as soon as more than limit bytes arrive, so nothing
// past the ceiling is ever written. On error the file is removed. It returns
// the path and byte count.
func spoolTo(feed string, r io.Reader, limit int64, f *os.File) (path string, n int64, err error) {
	name := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(name)
		}
	}()
	n, err = io.Copy(f, &io.LimitedReader{R: r, N: limit + 1})
	if err == nil && n > limit {
		err = &feedrefresh.TooLargeError{Feed: feed}
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, err
	}
	return name, n, nil
}

// sweepSpools removes spool files a killed process left behind (a refresh
// removes its own spool on every normal path). Called once at startup, before
// any refresh can create a live spool.
func sweepSpools(dir string) {
	ms, _ := filepath.Glob(filepath.Join(dir, ".mbazaar-spool-*.tmp"))
	for _, m := range ms {
		_ = os.Remove(m)
	}
}

// warmStart loads the persisted feed snapshot (if any) so lookups work from the
// last-good feed before the first network refresh.
func (c *Checker) warmStart() {
	if c.cachePath == "" {
		return
	}
	sweepSpools(filepath.Dir(c.cachePath))
	fi, err := os.Stat(c.cachePath)
	if err != nil || fi.Size() == 0 {
		return
	}
	hs, err := parseFile(c.cachePath, fi.Size(), 0)
	if err != nil {
		c.logf("malwarebazaar warm-start parse failed (ignoring cached feed): %v", err)
		return
	}
	c.set.Store(hs)
	c.setBytes.Store(feedrefresh.DigestSetBytes(len(hs.m), sha256.Size))
	c.logf("malwarebazaar warm-start from cache: %d hashes", len(hs.m))
}

// errOverCeiling reports a feed whose decompressed CSV exceeds
// maxDecompressedBytes. The refresh is rejected and the previous set kept.
var errOverCeiling = errors.New("malwarebazaar: decompressed feed exceeds ceiling")

// capReader bounds a stream: it returns errOverCeiling the moment more than cap
// bytes have been produced, before the excess is handed to the parser, so the
// bound is enforced while reading and never after allocation.
type capReader struct {
	r    io.Reader
	left int64 // bytes still allowed
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, errOverCeiling
	}
	// Allow one probe byte past the cap so exactly-at-cap succeeds and cap+1 fails.
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return n - 1, errOverCeiling // drop the probe byte
	}
	return n, err
}

// parseFile opens path (size bytes) and stream-parses it; see parseReaderAt.
func parseFile(path string, size int64, hint int) (*hashSet, error) {
	f, err := os.Open(path) // #nosec G304 -- spool or operator-configured cache path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	return parseReaderAt(f, size, hint)
}

// parseFeed parses an in-memory body (tests and fuzzing).
func parseFeed(body []byte) (*hashSet, error) {
	return parseReaderAt(bytes.NewReader(body), int64(len(body)), 0)
}

// parseReaderAt builds the digest set from the feed — either the ZIP dump (one
// CSV inside) or a plain CSV (the "recent" export / a custom feed); the format
// is magic-sniffed. The CSV is streamed straight from the zip entry reader into
// csv.Reader: the decompressed body is never held in memory. A malformed row is
// skipped; a corrupt zip/deflate stream or a decompressed size over
// maxDecompressedBytes fails the whole parse. hint presizes the map.
func parseReaderAt(ra io.ReaderAt, size int64, hint int) (*hashSet, error) {
	rc, err := openCSV(ra, size)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }() // read-only reader

	if hint > maxHashes {
		hint = maxHashes
	}
	hs := &hashSet{m: make(map[[32]byte]struct{}, hint)}
	cr := csv.NewReader(&capReader{r: rc, left: maxDecompressedBytes})
	cr.Comment = '#'
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	// The live dump separates fields with ", "; without this the quoted sha256
	// keeps its quotes and every row is dropped.
	cr.TrimLeadingSpace = true
	cr.ReuseRecord = true
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				continue // skip a bad row, keep loading the rest
			}
			return nil, err // read failure: ceiling, corrupt deflate, bad CRC
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
// file entry) when the source is a zip, else reads it as plain CSV.
func openCSV(ra io.ReaderAt, size int64) (io.ReadCloser, error) {
	var magic [4]byte
	if n, _ := ra.ReadAt(magic[:], 0); n == 4 && string(magic[:]) == "PK\x03\x04" {
		zr, err := zip.NewReader(ra, size)
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			// A declared decompressed size over the ceiling is rejected before a
			// single byte is inflated (the capReader still bounds a lying header).
			// maxDecompressedBytes is positive; the uint64 cast is safe.
			if f.UncompressedSize64 > uint64(maxDecompressedBytes) { //#nosec G115
				return nil, errOverCeiling
			}
			return f.Open()
		}
		return nil, errors.New("malwarebazaar: empty zip dump")
	}
	return io.NopCloser(io.NewSectionReader(ra, 0, size)), nil
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
		SetBytes:        c.setBytes.Load(),
		LastRefreshUnix: c.lastRefresh.Load(),
		RefreshFailures: c.failures.Load(),
		Lookups:         c.lookups.Load(),
		Hits:            c.hits.Load(),
	}
}
