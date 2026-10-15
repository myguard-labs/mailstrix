package mbazaar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/feedrefresh"
)

func rowFor(i int) string {
	sum := sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
	return "\"2024-01-01 00:00:00\", \"" + hex.EncodeToString(sum[:]) + "\", \"md5\"\n"
}

// TestParseMultiEntryZipStreams: a zip with several entries parses the first
// regular file entry and skips directory entries, within the bound.
func TestParseMultiEntryZipStreams(t *testing.T) {
	var csvB strings.Builder
	for i := 0; i < 1000; i++ {
		csvB.WriteString(rowFor(i))
	}
	body := csvB.String()

	orig := maxDecompressedBytes
	maxDecompressedBytes = int64(len(body)) + 64 // measured size plus headroom
	defer func() { maxDecompressedBytes = orig }()

	hs, err := parseFeed(zipOf(t, []byte(body)))
	if err != nil || len(hs.m) != 1000 {
		t.Fatalf("n=%v err=%v, want 1000", hs, err)
	}
}

// TestParseStreamsBoundedHeap proves the decompressed body is never held in
// memory: a ~64 MiB decompressed entry must parse with live heap growth far
// below its size. A full-buffer read (io.ReadAll of the entry) fails this.
func TestParseStreamsBoundedHeap(t *testing.T) {
	const rows = 700_000
	row := rowFor(1)
	var b bytes.Buffer
	for i := 0; i < rows; i++ {
		b.WriteString(row)
	}
	decompressed := int64(b.Len())
	z := zipOf(t, b.Bytes())
	b = bytes.Buffer{}

	orig := maxDecompressedBytes
	maxDecompressedBytes = decompressed + 1024
	defer func() { maxDecompressedBytes = orig }()

	// A low GC target keeps the peak tied to live data, not to the GC schedule.
	gcPercent := debug.SetGCPercent(10)
	defer debug.SetGCPercent(gcPercent)
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak {
				peak = m.HeapAlloc
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	hs, err := parseFeed(z)
	close(stop)
	wg.Wait()
	if err != nil || len(hs.m) != 1 {
		t.Fatalf("n=%v err=%v", hs, err)
	}
	grew := int64(peak) - int64(base.HeapAlloc)
	if limit := decompressed / 3; grew > limit {
		t.Fatalf("heap grew %d bytes parsing %d decompressed bytes (limit %d): body is buffered", grew, decompressed, limit)
	}
}

func serveBody(t *testing.T, body *[]byte, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write(*body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRefreshOverCeilingKeepsPrevious: a refresh whose decompressed CSV is over
// the ceiling is rejected with a clear error, the previous set and the cached
// snapshot are kept, and no spool file is left behind.
func TestRefreshOverCeilingKeepsPrevious(t *testing.T) {
	var good strings.Builder
	for i := 0; i < 20; i++ {
		good.WriteString(rowFor(i))
	}
	var bad strings.Builder
	for i := 0; i < 200; i++ {
		bad.WriteString(rowFor(i))
	}
	orig := maxDecompressedBytes
	maxDecompressedBytes = int64(good.Len()) + 16
	defer func() { maxDecompressedBytes = orig }()

	var mu sync.Mutex
	body := zipOf(t, []byte(good.String()))
	srv := serveBody(t, &body, &mu)
	dir := t.TempDir()
	var logs []string
	c := &Checker{key: "k", feedURL: srv.URL, client: srv.Client(), cachePath: filepath.Join(dir, "malwarebazaar.bin"),
		logf: func(f string, a ...any) { logs = append(logs, f) }, stop: make(chan struct{})}
	if err := c.refreshOnce(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	cached, _ := os.ReadFile(c.cachePath)
	if !bytes.Equal(cached, body) {
		t.Fatal("cache snapshot is not the downloaded zip")
	}
	d, _ := parseSHA256(strings.Split(rowFor(3), "\"")[3])
	if _, ok := c.set.Load().m[d]; !ok {
		t.Fatal("hash missing after first refresh")
	}

	mu.Lock()
	body = zipOf(t, []byte(bad.String()))
	mu.Unlock()
	err := c.refreshOnce(context.Background())
	if err == nil || !errors.Is(err, errOverCeiling) || !strings.Contains(err.Error(), "exceeds ceiling") {
		t.Fatalf("err=%v, want errOverCeiling", err)
	}
	if n := len(c.set.Load().m); n != 20 {
		t.Fatalf("set replaced: %d hashes, want 20", n)
	}
	if _, ok := c.set.Load().m[d]; !ok {
		t.Fatal("a hash that hit before no longer hits")
	}
	if again, _ := os.ReadFile(c.cachePath); !bytes.Equal(again, cached) {
		t.Fatal("cache snapshot replaced by rejected feed")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".mbazaar-spool-") {
			t.Fatalf("spool file leaked: %s", e.Name())
		}
	}
}

// TestSpoolBodyLimit: the compressed download is bounded while copying; exactly
// at the limit is accepted, one byte over is a TooLargeError and leaves no file.
func TestSpoolBodyLimit(t *testing.T) {
	dir := t.TempDir()
	p, n, err := spoolBody("mb", strings.NewReader("12345678"), 8, dir)
	if err != nil || n != 8 {
		t.Fatalf("at limit: n=%d err=%v", n, err)
	}
	_ = os.Remove(p)
	if _, _, err := spoolBody("mb", strings.NewReader("123456789"), 8, dir); !errors.Is(err, feedrefresh.ErrTooLarge) {
		t.Fatalf("over limit: err=%v, want ErrTooLarge", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("spool leaked: %v", ents)
	}
	if _, _, err := spoolBody("mb", strings.NewReader("x"), 8, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("unwritable spool dir accepted")
	}
}

// TestWarmStartStreamsCache: a persisted zip snapshot warm-starts from disk.
func TestWarmStartStreamsCache(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "malwarebazaar.bin")
	if err := os.WriteFile(cp, zipOf(t, csvFor("warm")), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Checker{cachePath: cp, logf: func(string, ...any) {}}
	c.warmStart()
	if len(c.Check([]byte("warm"))) != 1 {
		t.Fatal("warm-start hash does not hit")
	}
	if err := os.WriteFile(cp, []byte("PK\x03\x04junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	c2 := &Checker{cachePath: cp, logf: func(string, ...any) {}}
	c2.warmStart()
	if c2.set.Load() != nil {
		t.Fatal("corrupt cache must not load")
	}
}

func TestSweepSpools(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".mbazaar-spool-123.tmp")
	keep := filepath.Join(dir, "mbazaar.csv")
	other := filepath.Join(dir, ".other-spool-1.tmp")
	for _, p := range []string{stale, keep, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sweepSpools(dir)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale spool not removed: %v", err)
	}
	for _, p := range []string{keep, other} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("unrelated file removed: %v", err)
		}
	}
	sweepSpools(filepath.Join(dir, "missing")) // no-op, no panic
}

// TestRefreshUnwritableCacheDirStillLoads: an unusable cache dir is non-fatal,
// the fresh feed still loads (spooled in the OS temp dir, snapshot skipped).
func TestRefreshUnwritableCacheDirStillLoads(t *testing.T) {
	var mu sync.Mutex
	body := zipOf(t, []byte(sampleCSV))
	srv := serveBody(t, &body, &mu)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// cachePath's parent is a regular file: MkdirAll fails.
	c := &Checker{key: "k", feedURL: srv.URL, client: srv.Client(), cachePath: filepath.Join(blocker, "sub", "mb.bin"),
		logf: func(string, ...any) {}, stop: make(chan struct{})}
	if err := c.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refresh with unusable cache dir: %v", err)
	}
	if n := len(c.set.Load().m); n != 2 {
		t.Fatalf("loaded %d hashes, want 2", n)
	}
	// Parent exists but is read-only: CreateTemp fails, same fallback.
	if os.Geteuid() != 0 {
		ro := filepath.Join(t.TempDir(), "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		c2 := &Checker{key: "k", feedURL: srv.URL, client: srv.Client(), cachePath: filepath.Join(ro, "mb.bin"),
			logf: func(string, ...any) {}, stop: make(chan struct{})}
		if err := c2.refreshOnce(context.Background()); err != nil || len(c2.set.Load().m) != 2 {
			t.Fatalf("read-only cache dir: err=%v", err)
		}
	}
}
